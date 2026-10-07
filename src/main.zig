///
const std = @import("std");

const backoff = @import("utils/backoff.zig");
const blocked_response = @import("dns/blocked_response.zig");
const cache_mod = @import("dns/cache.zig");
const Cache = cache_mod.Cache;
const CacheKey = cache_mod.CacheKey;
const Context = @import("utility.zig").Context;
const Refresher = @import("utility.zig").Refresher;
const Tcp = @import("utility.zig").Tcp;
const DomainBlockList = @import("blocklist/domain_blocklist.zig").DomainBlockList;
const Header = @import("dns/header.zig").Header;
const pending_table_mod = @import("utils/pending_table.zig");
const PendingTable = pending_table_mod.PendingTable;
const PendingQuery = pending_table_mod.PendingQuery;
const Policy = @import("blocklist/policy.zig").Policy;
const Snapshot = @import("blocklist/policy.zig").Snapshot;
const obs_log = @import("obs/log.zig");
const ResourceRecordIter = @import("dns/resource_record.zig").ResourceRecordIter;
const settings_mod = @import("settings.zig");
const Settings = settings_mod.Settings;
const SuffixBlockList = @import("blocklist/suffix_blocklist.zig").SuffixBlockList;
const Question = @import("dns/question.zig").Question;
const edns = @import("dns/edns.zig");
const ConnTable = @import("utils/conn_table.zig").ConnTable;

/// Every `std.log.*` call in the process — ours and the standard library's —
/// renders through [obs/log.zig](obs/log.zig).
///
/// `log_level` is deliberately wide open. `std.log.logEnabled` filters at
/// comptime, which cannot see a value that arrives from the environment at
/// startup, so the comptime gate has to pass everything through and `logFn`
/// applies the operator's real level at runtime.
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = obs_log.logFn,
};

/// Per-query verdicts, scoped so they can be filtered apart from operational
/// diagnostics. `debug` because this is one record per DNS query on the
/// network; P2.3's query log is what will carry these as real fields
/// (client, qtype, latency) on a level an operator can leave on.
const query_log = std.log.scoped(.query);

fn addrBind(io: std.Io, addr: *const std.Io.net.IpAddress, what: []const u8) !std.Io.net.Socket {
    return addr.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        logBindFailure(what, addr, err);
        return err;
    };
}

/// Names the address that could not be bound and, for the failures a first
/// deployment on port 53 actually hits (P2.6), the likely cause — the bare
/// error name says neither which socket failed nor what to do about it.
fn logBindFailure(what: []const u8, addr: *const std.Io.net.IpAddress, err: anyerror) void {
    const hint: []const u8 = switch (err) {
        error.AddressInUse => " (another process holds this port; on most systemd hosts that is " ++
            "systemd-resolved's stub listener, see README \"Running under systemd\")",
        // std 0.16's bind has no AccessDenied: EACCES arrives as Unexpected.
        error.Unexpected => if (addr.getPort() < 1024)
            " (ports below 1024 need CAP_NET_BIND_SERVICE, which the systemd unit grants)"
        else
            "",
        error.AddressUnavailable => " (no local interface has this address)",
        else => "",
    };
    std.log.err("cannot bind {s} to {f}: {s}{s}", .{ what, addr.*, @errorName(err), hint });
}

fn initIpAddress(host: []const u8, port: u16) !std.Io.net.IpAddress {
    return try std.Io.net.IpAddress.parse(host, port);
}

fn initSockets(io: std.Io, cfg: Settings) !struct {
    std.Io.net.Socket,
    std.Io.net.Socket,
} {
    const addr: std.Io.net.IpAddress = try initIpAddress(cfg.listen_host, cfg.listen_port);
    const client_socket: std.Io.net.Socket = try addrBind(io, &addr, "udp listener");

    const local_upstream_addr: std.Io.net.IpAddress = try std.Io.net.IpAddress.parse(
        cfg.upstream_bind_host,
        cfg.upstream_bind_port,
    );
    const upstream_socket: std.Io.net.Socket = try addrBind(io, &local_upstream_addr, "upstream socket");

    return .{
        client_socket,
        upstream_socket,
    };
}

/// How a query arrived, which decides how large a reply it can take: over UDP,
/// what its OPT advertises (512 without one); over TCP, a full 64 KiB.
const Transport = enum { udp, tcp };

/// What the datapath decided to do with one query. Shared by both transports,
/// which differ only in how they carry the bytes and how they forward.
const Outcome = union(enum) {
    /// Send nothing: a response (QR=1 — answering it would make us a
    /// reflector), or a question section too malformed to answer about.
    drop,
    /// Answered locally. A prefix of the caller's `out` buffer.
    reply: []u8,
    /// Needs upstream.
    forward: Forward,
};

const Forward = struct {
    client_id: u16,
    /// One past the question section, as `parseQuestion` returned it.
    q_end: usize,
    /// The requester's EDNS class — the cache partition its answer belongs to.
    class: edns.Class,
};

/// Validates a query and decides its fate: drop, answer locally, or forward.
///
/// Everything a query goes through before it needs a socket lives here, so
/// UDP and TCP cannot drift apart on what they block, cache or reject. The
/// order is load-bearing:
///
///   1. Header — QR=1 dropped; bad opcode or QDCOUNT answered header-only.
///   2. Question — unparseable is dropped.
///   3. OPT (P3.5) — malformed or duplicated is FORMERR; version > 0 is BADVERS.
///   4. Policy — a blocked name is answered here, with our OPT if it sent one.
///   5. Cache — **after** policy, never before: a name cached and then added to
///      a refreshed blocklist (P2.2) would otherwise keep resolving for up to a
///      TTL. The blocklist wins, always.
///
/// `data` is mutated only on the forward path, where the OPT's payload size is
/// clamped. Every reply is written into `out`.
fn decide(
    io: std.Io,
    ctx: *const Context,
    data: []u8,
    out: []u8,
    transport: Transport,
) std.Io.Cancelable!Outcome {
    if (data.len < 12) return .drop;

    var header = Header{};
    header.parseHeader(data[0..12]);

    const rejection = header.validateQuery();
    if (rejection != .none) {
        // `rcode()` decides drop-vs-reply. QR=1 is the silent case. The others
        // are real clients asking for something malformed or unimplemented, so
        // they get an answer — header-only, since their question section is
        // exactly what we could not trust.
        std.log.debug("rejecting query: {s}", .{@tagName(rejection)});
        const rcode = rejection.rcode() orelse return .drop;
        out[0..12].* = Header.headerOnlyReply(data, rcode);
        return .{ .reply = out[0..12] };
    }

    var question = Question{};
    const q_end = question.parseQuestion(data, 12) catch |err| {
        std.log.debug("dropping malformed query: {s}", .{@errorName(err)});
        return .drop;
    };

    // Borrows `question`'s inline buffer, so it stays valid for exactly as long
    // as `question` is in scope.
    const domain: []const u8 = question.qname.slice();

    const opt = edns.find(data, q_end, header) catch |err| {
        // RFC 6891 §6.1.1: more than one OPT is FORMERR, and so is one we cannot
        // locate with confidence. Header-only, like every other FORMERR.
        std.log.debug("FORMERR for {s}: {s}", .{ domain, @errorName(err) });
        out[0..12].* = Header.headerOnlyReply(data, .format_error);
        return .{ .reply = out[0..12] };
    };
    const our_opt: ?blocked_response.Opt = if (opt) |o|
        .{ .udp_size = ctx.edns_udp_size, .do_bit = o.do_bit }
    else
        null;

    if (opt) |o| if (o.version > 0) {
        // BADVERS: we speak version 0 only. Extended RCODE 16 is 1 in the OPT's
        // top byte with 0 in the header, and needs the OPT to be expressible.
        std.log.debug("BADVERS for {s}: version {d}", .{ domain, o.version });
        var badvers = our_opt.?;
        badvers.ext_rcode = 1;
        const reply = blocked_response.buildInto(out, data, q_end, .no_error, .{
            .soa = false,
            .opt = badvers,
        }) catch return .drop;
        return .{ .reply = reply };
    };

    switch (try ctx.policy.decide(io, domain)) {
        .allow => query_log.debug("verdict=allow qname={s}", .{domain}),
        .block => {
            query_log.debug("verdict=block qname={s}", .{domain});
            // NXDOMAIN + a synthetic SOA so the client can negatively cache the
            // block, and our OPT if the query carried one (RFC 6891 §7).
            const reply = blocked_response.buildInto(out, data, q_end, .name_error, .{
                .opt = our_opt,
            }) catch {
                std.log.warn("dropping blocked reply for {s}: reply buffer too small", .{domain});
                return .drop;
            };
            return .{ .reply = reply };
        },
        .pass => query_log.debug("verdict=pass qname={s}", .{domain}),
    }

    const class = edns.class(opt);

    if (ctx.cache) |cache| serve: {
        const now: i64 = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds);

        // The buffer handed to `get` is exactly as large as this client may
        // receive, and `get` treats an entry that does not fit as a miss. That
        // is the size check: an answer fetched over TCP, or for a client with a
        // larger EDNS buffer, is never squeezed down to — or silently cut to
        // fit — one that cannot take it.
        const limit = switch (transport) {
            .udp => @min(edns.replyLimit(opt), out.len),
            .tcp => out.len,
        };
        const hit = cache.get(CacheKey.fromQuestion(&question, class), now, out[0..limit]) orelse break :serve;

        // `get` handed back a copy, so this cannot reach the stored entry. The
        // client's own ID and question bytes go in: the entry was filled by
        // whoever asked first, in their casing.
        const served = out[0..hit.len];
        cache_mod.finalizeServed(served, data[12..q_end], header.id, hit.age_secs) catch |err| {
            // A cache that cannot render a hit is a slow cache, not a broken
            // resolver: fall through to upstream.
            std.log.warn("cache hit for {s} unusable: {s}", .{ domain, @errorName(err) });
            break :serve;
        };
        query_log.debug("verdict=hit qname={s} age={d}s", .{ domain, hit.age_secs });
        return .{ .reply = served };
    }

    // Upstream never sends a reply larger than the query advertises, so
    // clamping the advertisement is what keeps replies within what we relay
    // unfragmented (1232) — or, with no TCP listener, within our buffer.
    if (opt) |o| edns.clampInPlace(data, o, ctx.edns_udp_size);

    return .{ .forward = .{ .client_id = header.id, .q_end = q_end, .class = class } };
}

/// Per-datagram task: decide, then answer or hand the query to upstream.
fn handleQuery(
    io: std.Io,
    gpa: std.mem.Allocator,
    ctx: *const Context,
    incoming_addr: std.Io.net.IpAddress,
    data: []u8,
) std.Io.Cancelable!void {
    defer gpa.free(data);

    // On the task stack, like the ingress and dispatcher buffers. Bounded by
    // the handler count (`VORTEX_HANDLER_THREADS`), not by P1.5's pending cap —
    // a local answer never takes a pending slot.
    var out: [4096]u8 = undefined;

    switch (try decide(io, ctx, data, &out, .udp)) {
        .drop => {},
        .reply => |reply| ctx.client_socket.send(io, &incoming_addr, reply) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => std.log.warn("reply send to {f} failed: {s}", .{ incoming_addr, @errorName(err) }),
        },
        .forward => |f| try forwardUdp(io, ctx, incoming_addr, data, f),
    }
}

/// Sends a query upstream over the shared UDP socket; `dispatcherLoop` relays
/// the reply and the sweeper SERVFAILs it if none comes.
fn forwardUdp(
    io: std.Io,
    ctx: *const Context,
    incoming_addr: std.Io.net.IpAddress,
    data: []u8,
    f: Forward,
) std.Io.Cancelable!void {
    // q_end is one past the question section, so the question occupies
    // data[12..q_end]. parseQuestion already bounded it against data.len.
    const question_len: u16 = @intCast(f.q_end - 12);
    const question_hash = pending_table_mod.hashQuestion(ctx.question_seed, data, question_len).?;

    const proxy_id = ctx.pending_table.appendQuery(.{
        .client_id = f.client_id,
        .client_addr = incoming_addr,
        .question_hash = question_hash,
        .question_len = question_len,
        .edns = f.class,
        .expires_at = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds + 5 * std.time.ns_per_s),
    }) catch |err| switch (err) {
        // P1.5: at the cap, drop without a reply. Deliberately silent in both
        // directions — no log line per refusal (the sweeper reports a count),
        // and no SERVFAIL, because a flood's source addresses are often spoofed
        // and answering each packet reflects traffic at someone else, even
        // with no amplification. Local answers returned from `decide` before
        // this, so they are still given while the table is full.
        error.TableFull => return,
        else => {
            std.log.err("Failed to append query to Pending table: {s}", .{@errorName(err)});
            return;
        },
    };
    std.mem.writeInt(u16, data[0..2], proxy_id, .big);

    ctx.upstream_socket.send(io, &ctx.upstream_addr, data) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            _ = ctx.pending_table.complete(proxy_id);
            std.log.err("upstream send query failed: {s}", .{@errorName(err)});
        },
    };
}

/// Files a verified upstream reply in the cache, under the partition of the
/// requester it was fetched for. Shared by the UDP dispatcher and the TCP path.
///
/// Returns an error only when the reply's question does not parse, which the
/// UDP path has always treated as "do not relay".
fn storeReply(
    io: std.Io,
    ctx: *const Context,
    reply: []const u8,
    overflowed: bool,
    class: edns.Class,
) error{MalformedReply}!void {
    var reply_header = Header{};
    reply_header.parseHeader(reply[0..12]);

    var reply_question = Question{};
    const offset = reply_question.parseQuestion(reply, 12) catch |err| {
        std.log.warn("failed to parse reply question: {s}", .{@errorName(err)});
        return error.MalformedReply;
    };

    // Read-only walk: a parse failure abandons the walk and nothing else — the
    // reply is relayed verbatim whatever it finds, and is simply not cached.
    //
    // Two guards, which stopped being cosmetic when the walk's output started
    // deciding what gets *stored*:
    //
    //   * Overflowed — the records are known-incomplete.
    //   * QDCOUNT != 1 — records begin at `12 + question_len` only when there
    //     is exactly one question. Walking from the wrong offset is the silent
    //     desynchronization this design exists to avoid.
    const walkable = !overflowed and reply_header.question_count == 1;

    var min_ttl: ?u32 = null;
    if (walkable) walk: {
        min_ttl = cache_mod.replyTtlSeconds(reply, offset, reply_header) catch |err| {
            std.log.debug("record walk for {s}: {s}", .{ reply_question.qname.slice(), @errorName(err) });
            break :walk;
        };

        // The label is load-bearing: an unlabelled `break` in a `while`
        // condition binds to the nearest enclosing loop.
        var it = ResourceRecordIter.init(reply, offset, reply_header);
        walk_log: while (true) {
            const next = it.next() catch break :walk_log;
            const record = next orelse break :walk_log;
            query_log.debug("record name={s} type={d} ttl={d}", .{ record.name.slice(), record.type, record.ttl });
        }
    }

    const cache = ctx.cache orelse return;
    if (!cache_mod.isCacheable(reply_header, overflowed, min_ttl)) return;

    const now: i64 = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds);
    const ttl_ns = @as(i64, min_ttl.?) * std.time.ns_per_s;
    cache.put(CacheKey.fromQuestion(&reply_question, class), reply, now, now + ttl_ns) catch |err| {
        // A cache that cannot store is a slow cache. The reply goes out anyway.
        std.log.warn("cache put failed: {s}", .{@errorName(err)});
    };
}

fn dispatcherLoop(io: std.Io, ctx: *const Context) std.Io.Cancelable!void {
    var msg_buf: [4096]u8 = undefined;
    while (true) {
        const reply_msg = ctx.upstream_socket.receive(io, &msg_buf) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.warn("dispatcher receive: {s}", .{@errorName(err)});
                continue;
            },
        };
        if (reply_msg.data.len < 12) continue;
        if (!ctx.upstream_addr.eql(&reply_msg.from)) continue;

        const proxy_id = std.mem.readInt(u16, reply_msg.data[0..2], .big);

        // Peek first, and only consume the entry once the reply is proven to
        // answer it. Completing up front would mean a forged packet that merely
        // guessed the proxy ID could delete a live query as a side effect of
        // being rejected — the attacker fails to inject an answer but still
        // denies service, and the sweeper is left with nothing to SERVFAIL.
        const pending = ctx.pending_table.peek(proxy_id) orelse {
            std.log.debug("orphan response id={x}", .{proxy_id});
            continue;
        };

        // The upstream echoes the question verbatim, so a genuine reply carries
        // the same bytes at the same offset. On top of the random proxy ID and
        // the source-address check, an off-path attacker now has to guess the ID
        // *and* reproduce the exact question to land a forgery.
        const reply_hash = pending_table_mod.hashQuestion(
            ctx.question_seed,
            reply_msg.data,
            pending.question_len,
        );
        if (reply_hash == null or reply_hash.? != pending.question_hash) {
            // Entry deliberately left in place: the real reply may still be in
            // flight, and if it never comes the sweeper will SERVFAIL it.
            std.log.warn("discarding reply id={x}: question does not match the query", .{proxy_id});
            continue;
        }

        // Verified — now consume it. A concurrent sweep could have evicted the
        // entry since the peek, in which case the client has already been sent
        // a SERVFAIL and this reply is too late to matter.
        const entry = ctx.pending_table.complete(proxy_id) orelse {
            std.log.debug("reply id={x} arrived after its deadline", .{proxy_id});
            continue;
        };

        // Store before the transaction ID is rewritten, so the entry holds
        // upstream's bytes rather than one client's view of them.
        storeReply(io, ctx, reply_msg.data, reply_msg.flags.trunc, entry.edns) catch continue;

        std.mem.writeInt(u16, reply_msg.data[0..2], entry.client_id, .big);

        // The datagram was larger than `msg_buf` and the tail was discarded.
        // Since P3.5 the forwarded OPT is clamped, so a conforming upstream
        // cannot provoke this; one that ignores the advertised size still can.
        // Relaying the prefix as-is would hand the client a silently corrupt
        // message; TC=1 tells it to retry over TCP.
        if (reply_msg.flags.trunc) {
            std.log.warn("upstream reply for id={x} exceeded {d}-byte buffer; setting TC", .{
                proxy_id,
                msg_buf.len,
            });
            Header.markTruncated(reply_msg.data);
        }

        ctx.client_socket.send(io, &entry.client_addr, reply_msg.data) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.warn("client send failed: {s}", .{@errorName(err)});
                continue;
            },
        };
    }
}

// ── TCP (P3.6) ────────────────────────────────────────────────────────────

/// Largest DNS message over TCP: the 2-byte length prefix caps it.
const tcp_max_message = std.math.maxInt(u16);

/// How long a TCP connection may go without completing a message before the
/// sweeper cancels it. RFC 7766 §6.2.3 asks for a timeout "on the order of
/// seconds". Counted per *message*, so it also bounds a stalled upstream: a
/// forward that has not come back by then takes its connection with it.
const tcp_idle_ns: i64 = 10 * std.time.ns_per_s;

/// Accepts TCP connections and gives each its own task, up to the table's cap.
fn tcpAcceptLoop(io: std.Io, ctx: *const Context) std.Io.Cancelable!void {
    const tcp = ctx.tcp orelse return parkForever(io);
    while (true) {
        const stream = tcp.server.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                // Brief pause: an error like EMFILE would otherwise come back
                // immediately and spin this loop.
                std.log.warn("tcp accept: {s}", .{@errorName(err)});
                try io.sleep(std.Io.Duration.fromMilliseconds(50), std.Io.Clock.boot);
                continue;
            },
        };

        const slot = tcp.conns.claim(io) orelse {
            std.log.debug("refusing tcp connection: {d} already open (VORTEX_MAX_TCP_CONNS)", .{tcp.conns.slots.len});
            stream.close(io);
            continue;
        };
        // `concurrent`, never `async`: a connection lives as long as its client
        // keeps it open, and `async` may run it inline — right here, where it
        // would stop every other connection from being accepted until it ends.
        const future = io.concurrent(tcpConnection, .{ io, ctx, stream, slot }) catch |err| {
            std.log.warn("cannot start tcp connection task: {s}", .{@errorName(err)});
            tcp.conns.release(io, slot);
            stream.close(io);
            continue;
        };
        tcp.conns.attach(io, slot, future);
    }
}

/// Serves one TCP connection: length-prefixed queries in, answers out, in
/// order (RFC 7766 permits pipelining; answering in order is always correct).
fn tcpConnection(io: std.Io, ctx: *const Context, stream: std.Io.net.Stream, slot: *ConnTable.Slot) void {
    defer slot.finish();
    defer stream.close(io);

    // Two full-size message buffers per connection: 128 KiB, which is why the
    // connection count is capped. `reply_buf` keeps two bytes in front for
    // the length prefix, so a reply goes out in one write.
    const bufs = ctx.gpa.alloc(u8, 2 * (2 + tcp_max_message)) catch return;
    defer ctx.gpa.free(bufs);
    const query_buf = bufs[0 .. 2 + tcp_max_message];
    const reply_buf = bufs[2 + tcp_max_message ..];

    var read_buf: [512]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var writer = stream.writer(io, &.{});

    while (true) {
        // Any read or write failure ends the connection — including a
        // cancellation from the idle sweep, which surfaces here as a failed read.
        var len_bytes: [2]u8 = undefined;
        reader.interface.readSliceAll(&len_bytes) catch return;
        const len = std.mem.readInt(u16, &len_bytes, .big);
        if (len < 12) return;
        const query = query_buf[0..len];
        reader.interface.readSliceAll(query) catch return;
        slot.touch(io);

        const out = reply_buf[2..];
        const reply: []const u8 = switch (decide(io, ctx, query, out, .tcp) catch return) {
            // Over TCP a drop leaves the client waiting on a stream it owns, so
            // close it instead: that is an answer it can act on.
            .drop => return,
            .reply => |r| r,
            .forward => |f| tcpForward(io, ctx, query, out, f) catch |err| switch (err) {
                error.Canceled => return,
                else => blk: {
                    std.log.warn("tcp upstream: {s}", .{@errorName(err)});
                    out[0..12].* = Header.synthesizedReply(f.client_id, .server_failure);
                    break :blk out[0..12];
                },
            },
        };

        std.mem.writeInt(u16, reply_buf[0..2], @intCast(reply.len), .big);
        writer.interface.writeAll(reply_buf[0 .. 2 + reply.len]) catch return;
    }
}

/// Forwards one query to upstream over a fresh TCP connection and reads the
/// reply into `out`.
///
/// No `PendingTable`: the connection itself pairs the reply with the query,
/// and an off-path attacker cannot inject into an established TCP stream the
/// way they can race a UDP reply. The ID and question are still checked — a
/// confused upstream is not only an attacker's problem.
fn tcpForward(io: std.Io, ctx: *const Context, query: []const u8, out: []u8, f: Forward) ![]u8 {
    const upstream = try ctx.upstream_addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer upstream.close(io);

    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, @intCast(query.len), .big);
    var writer = upstream.writer(io, &.{});
    var parts = [_][]const u8{ &len_bytes, query };
    writer.interface.writeVecAll(&parts) catch return streamError(writer.err);

    var read_buf: [512]u8 = undefined;
    var reader = upstream.reader(io, &read_buf);
    reader.interface.readSliceAll(&len_bytes) catch return streamError(reader.err);
    const len = std.mem.readInt(u16, &len_bytes, .big);
    if (len < 12 or len > out.len) return error.BadUpstreamReply;
    const reply = out[0..len];
    reader.interface.readSliceAll(reply) catch return streamError(reader.err);

    const question_len: u16 = @intCast(f.q_end - 12);
    const asked = pending_table_mod.hashQuestion(ctx.question_seed, query, question_len).?;
    if (std.mem.readInt(u16, reply[0..2], .big) != f.client_id or
        pending_table_mod.hashQuestion(ctx.question_seed, reply, question_len) != asked)
    {
        return error.BadUpstreamReply;
    }

    storeReply(io, ctx, reply, false, f.class) catch return error.BadUpstreamReply;
    return reply;
}

/// A stream reader or writer reports failure as `ReadFailed`/`WriteFailed` and
/// keeps the cause on the side. A cancellation has to come back out as
/// `error.Canceled`: it is delivered to one cancellation point only, so a
/// caller that swallowed it would carry on — and the canceller, which waits
/// for this task to end, would wait forever.
fn streamError(cause: anytype) anyerror {
    if (cause) |err| return if (err == error.Canceled) error.Canceled else err;
    return error.EndOfStream;
}

fn sweeperLoop(io: std.Io, ctx: *const Context) std.Io.Cancelable!void {
    const gpa = ctx.gpa;
    // Reused across sweeps so the steady state allocates nothing: the common
    // case is an empty list once per second.
    var evicted: std.ArrayList(PendingQuery) = .empty;
    defer evicted.deinit(gpa);

    // The cache rides this loop rather than getting a coroutine of its own, but
    // not at the same cadence: pending queries need a 1 s tick because a client
    // is waiting on the SERVFAIL, whereas an expired cache entry is already
    // inert — `get` treats it as a miss — so sweeping it is only about
    // reclaiming memory. Every 30th tick keeps a full walk of a 10k-entry map
    // off the once-a-second path.
    const cache_sweep_ticks = 30;
    var tick: usize = 0;

    while (true) {
        // A relative sleep on the settable wall clock would stutter or race
        // ahead whenever NTP adjusts it; the sweep cadence should track the same
        // monotonic clock the deadlines are measured on.
        try io.sleep(std.Io.Duration.fromSeconds(1), std.Io.Clock.boot);

        tick +%= 1;
        if (tick % cache_sweep_ticks == 0) {
            if (ctx.cache) |cache| {
                const now: i64 = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds);
                const dropped = cache.sweepExpired(now);
                if (dropped > 0) std.log.debug("cache: swept {d} expired entries", .{dropped});
            }
        }

        // One line per tick, not per refusal: see `PendingTable.takeShed`.
        const shed = ctx.pending_table.takeShed();
        if (shed > 0) std.log.warn("shed {d} queries: pending table full (VORTEX_MAX_PENDING={d})", .{
            shed,
            ctx.pending_table.max_pending,
        });

        // TCP connections ride the same tick: a connection that has not
        // completed a message in `tcp_idle_ns` is cancelled, which is the only
        // way to end a blocked read — `std.Io` streams have no read timeout.
        if (ctx.tcp) |tcp| {
            const now: i64 = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds);
            const ended = tcp.conns.cancelIdle(io, now, tcp_idle_ns);
            if (ended > 0) std.log.debug("tcp: closed {d} idle connections", .{ended});
        }

        evicted.clearRetainingCapacity();
        ctx.pending_table.sweepExpiredQueries(&evicted);
        if (evicted.items.len == 0) continue;

        // The upstream never answered inside the deadline. Until now the client
        // got nothing at all and had to wait out its own timeout; SERVFAIL lets
        // it fail fast and move to its next configured resolver.
        std.log.debug("sweeping {d} timed-out queries", .{evicted.items.len});
        for (evicted.items) |entry| {
            const reply = Header.synthesizedReply(entry.client_id, .server_failure);
            ctx.client_socket.send(io, &entry.client_addr, &reply) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => std.log.warn("SERVFAIL send to {f} failed: {s}", .{
                    entry.client_addr,
                    @errorName(err),
                }),
            };
        }
    }
}

// ── Blocklist generations ─────────────────────────────────────────────────

/// Builds one blocklist generation from the configured sources.
///
/// Shared by startup and `refresherLoop`, so both get the same retries, the same
/// on-disk cache fallback and the same failure policy. The two paths differ only
/// in what they do with the result: startup installs it as the first generation,
/// a refresh swaps it in for the previous one.
///
/// Both lists are resolved concurrently, which halves the wait when both are
/// URLs — the common case, and the slow one at ~25 s for the real lists.
///
/// **Fail-open lives here**, and only for `error.BlocklistUnavailable`. Every
/// other failure is still fatal: a missing local path, a malformed URL, or an
/// allocation failure are all configuration or environment errors that a policy
/// about *network* resilience has no business swallowing.
fn buildSnapshot(
    gpa: std.mem.Allocator,
    io: std.Io,
    http_client: *std.http.Client,
    cfg: Settings,
) !*Snapshot {
    const snapshot = try Snapshot.create(gpa);
    errdefer snapshot.destroy();

    // An empty setting means "no on-disk cache", which `acquire` expresses as a
    // null rather than as an empty path it would then try to create.
    const cache_dir: ?[]const u8 = if (cfg.cache_dir.len == 0) null else cfg.cache_dir;

    var f_domain = io.async(DomainBlockList.load, .{
        &snapshot.domain_blocklist,
        gpa,
        io,
        http_client,
        cfg.blocklist_source,
        cache_dir,
    });
    var f_suffix = io.async(SuffixBlockList.load, .{
        &snapshot.suffix_blocklist,
        gpa,
        io,
        http_client,
        cfg.suffix_blocklist_source,
        cache_dir,
    });

    // Await both futures before propagating either error: a dropped future
    // would leave its coroutine running while the deferred deinits tear down
    // the resources it is still using.
    const r_domain = f_domain.await(io);
    const r_suffix = f_suffix.await(io);
    try applyFailurePolicy(r_domain, cfg.blocklist_on_failure, "blocklist");
    try applyFailurePolicy(r_suffix, cfg.blocklist_on_failure, "suffix blocklist");

    return snapshot;
}

/// Resolves one list's load result against the operator's failure policy.
///
/// A tolerated failure leaves that list's set empty, which the chain already
/// handles — an empty set simply blocks nothing.
fn applyFailurePolicy(
    result: anytype,
    policy: settings_mod.FailurePolicy,
    what: []const u8,
) !void {
    _ = result catch |err| switch (err) {
        error.BlocklistUnavailable => switch (policy) {
            .closed => {
                std.log.err("{s} unavailable and VORTEX_BLOCKLIST_ON_FAILURE=closed; refusing to start", .{what});
                return err;
            },
            .open => {
                std.log.err("{s} unavailable; continuing without it (VORTEX_BLOCKLIST_ON_FAILURE=open)", .{what});
                return;
            },
        },
        else => return err,
    };
}

/// Ceiling on the retry interval while running without a usable blocklist.
///
/// Five minutes rather than the configured interval, because the degraded state
/// is one where the resolver is filtering nothing — waiting a day to try again
/// would turn a transient outage at the list host into a day of unfiltered DNS.
const degraded_refresh_cap_s: i64 = 5 * 60;

/// Rebuilds both blocklists on a timer and swaps the result in.
///
/// Written to `LoopFn` so it goes through `supervise` like the other two loops,
/// which is what gives it crash-loop protection for free.
///
/// **Why a whole new generation rather than an update in place.** Readers are
/// live: a mutation of the running sets would be visible half-applied to a query
/// arriving mid-refresh, and the sets' keys are slices into a body this would be
/// reallocating underneath them. Building off to the side and swapping a pointer
/// makes the change atomic from a reader's point of view; see `Policy` for why
/// the swap needs a lock and not just an atomic store.
fn refresherLoop(io: std.Io, ctx: *const Context) std.Io.Cancelable!void {
    // Guarded at the spawn site — the loop is only started when refresh is
    // configured. Parking rather than returning covers the case where that
    // guard is ever dropped: a supervised loop that returns gets restarted, so
    // returning here would spin and log forever.
    const refresh = ctx.refresh orelse return parkForever(io);
    const cfg = refresh.cfg;

    var consecutive_failures: u32 = 0;

    while (true) {
        const live = try ctx.policy.entryCounts(io);
        const degraded = consecutive_failures > 0 or (live.domain + live.suffix) == 0;
        const configured: i64 = @intCast(cfg.blocklist_refresh_secs);

        // `+ 1` so the first degraded retry waits a second rather than firing
        // instantly: a fail-open startup has `consecutive_failures == 0` and an
        // empty list, and an immediate retry there would hammer a host that has
        // just failed. Never longer than the configured interval, so a short
        // interval is not silently overridden by the degraded ceiling.
        const delay_s = if (degraded)
            @min(backoff.seconds(consecutive_failures + 1, degraded_refresh_cap_s), configured)
        else
            configured;

        try io.sleep(std.Io.Duration.fromSeconds(delay_s), std.Io.Clock.boot);

        const before = try ctx.policy.entryCounts(io);
        const started = std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds;

        const fresh = buildSnapshot(ctx.gpa, io, refresh.http_client, cfg.*) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            consecutive_failures +|= 1;
            std.log.err("blocklist refresh failed: {s}; keeping {d} entries", .{
                @errorName(err),
                before.domain + before.suffix,
            });
            continue;
        };

        // The rule, and the reasoning behind it, live on `Snapshot.wouldDisarm`.
        const after = fresh.counts();
        if (Snapshot.wouldDisarm(before, after)) {
            fresh.destroy();
            consecutive_failures +|= 1;
            std.log.err(
                "blocklist refresh would empty a list ({d}/{d} -> {d}/{d} entries); keeping the current one",
                .{ before.domain, before.suffix, after.domain, after.suffix },
            );
            continue;
        }

        try ctx.policy.install(io, fresh);
        consecutive_failures = 0;

        const elapsed_ms = @divTrunc(
            std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds - started,
            std.time.ns_per_ms,
        );
        std.log.info("blocklist refreshed: {d}/{d} -> {d}/{d} entries in {d}ms", .{
            before.domain,
            before.suffix,
            after.domain,
            after.suffix,
            elapsed_ms,
        });
    }
}

/// Blocks until cancelled, without spinning.
///
/// For a supervised loop that has nothing to do: returning would be read as a
/// crash and restarted, so the only way to "stop" while staying under the
/// supervisor is to wait forever and honour cancellation.
fn parkForever(io: std.Io) std.Io.Cancelable!void {
    while (true) {
        try io.sleep(std.Io.Duration.fromSeconds(3600), std.Io.Clock.boot);
    }
}

/// Every background loop has this shape, which is what lets one supervisor
/// cover all of them.
const LoopFn = *const fn (std.Io, *const Context) std.Io.Cancelable!void;

/// Runs `loop` forever, restarting it if it ever returns for any reason other
/// than cancellation.
///
/// Today neither loop can return normally — every non-`Canceled` path
/// `continue`s — so this is defence against a future edit, not a live bug. It
/// earns its keep because the failure mode is total and silent: if
/// `dispatcherLoop` ever stops draining the table, ingress keeps accepting and
/// enqueuing queries that nobody will ever answer, and the only symptom is that
/// every lookup times out.
/// Longest a restart is ever delayed. Past this the loop is clearly broken and
/// retrying faster only burns CPU, but we keep retrying: an upstream socket that
/// is unusable now may be usable in a minute.
const restart_backoff_cap_s = 30;

/// A loop that stayed up this long was doing its job, so its next failure is
/// treated as a fresh incident rather than a continuation of a crash loop.
const healthy_run_ns = 60 * std.time.ns_per_s;

/// Delay before the *next* restart, given how many restarts have already
/// happened back to back. Doubles from 1s and saturates at
/// `restart_backoff_cap_s`; the very first restart is immediate, so a one-off
/// blip recovers with no added latency.
///
/// The schedule itself lives in [utils/backoff.zig](utils/backoff.zig), shared
/// with the blocklist fetch retry, which wants the same rule and a different
/// ceiling.
fn backoffSeconds(consecutive_restarts: u32) i64 {
    return backoff.seconds(consecutive_restarts, restart_backoff_cap_s);
}

/// Runs `loop` forever, restarting it if it ever returns for any reason other
/// than cancellation.
///
/// Today neither loop can return normally — every non-`Canceled` path
/// `continue`s — so this is defence against a future edit, not a live bug. It
/// earns its keep because the failure mode is total and silent: if
/// `dispatcherLoop` ever stops draining the table, ingress keeps accepting and
/// enqueuing queries that nobody will ever answer, and the only symptom is that
/// every lookup times out.
///
/// **Why the backoff.** The `while` here wraps a loop that itself blocks
/// forever, so in the healthy case this body never completes a single iteration
/// and costs nothing but a stack frame. The danger is the opposite case: a
/// `loop` that returns *immediately* would be restarted as fast as the CPU
/// allows, pinning a core and writing error logs in a tight spin. That is the
/// classic supervisor crash-loop, and the backoff is what bounds it.
///
/// Cancellation is honoured while backing off — `io.sleep` propagates
/// `error.Canceled` — so shutdown never waits out a 30-second delay.
fn supervise(io: std.Io, ctx: *const Context, name: []const u8, loop: LoopFn) std.Io.Cancelable!void {
    var consecutive_restarts: u32 = 0;

    while (true) {
        const started = std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds;

        loop(io, ctx) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
        };

        // A long clean run means this is a new failure, not a tight crash loop,
        // so the schedule starts over rather than inheriting an old delay.
        const ran_ns = std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds - started;
        if (ran_ns >= healthy_run_ns) consecutive_restarts = 0;

        const delay_s = backoffSeconds(consecutive_restarts);
        std.log.err("{s} loop returned unexpectedly after {d}ms; restart #{d} in {d}s", .{
            name,
            @divTrunc(ran_ns, std.time.ns_per_ms),
            consecutive_restarts + 1,
            delay_s,
        });

        if (delay_s > 0) try io.sleep(std.Io.Duration.fromSeconds(delay_s), std.Io.Clock.boot);
        consecutive_restarts +|= 1;
    }
}

/// Handler threads when `VORTEX_HANDLER_THREADS` is unset: `std.Io.Threaded`'s
/// own default of one less than the CPU count, so the ingress thread and the
/// handlers together fill the machine.
fn defaultHandlerThreads() usize {
    const cpus = std.Thread.getCpuCount() catch 1;
    return cpus -| 1;
}

/// The `async_limit` that leaves `handler_threads` slots for handlers once
/// `long_lived` concurrent tasks are running — the background loops, plus one
/// per TCP connection slot.
///
/// The addition is the point. `Io.Threaded` keeps one busy count for `async`
/// and `concurrent` tasks alike, and compares it against `async_limit` when an
/// `async` task arrives. A loop never returns, so without the extra slots every
/// loop permanently takes one away from the handlers — on a 4-CPU host the
/// three loops took all three, and every query ran inline on the ingress
/// thread. An open TCP connection holds its slot the same way.
fn asyncLimit(handler_threads: usize, long_lived: usize) std.Io.Limit {
    return .limited(handler_threads + long_lived);
}

/// Starts a supervised background loop on a thread of its own.
///
/// `concurrent`, never `async`. Once the async limit is reached, `async` does
/// not queue a task: it runs it **inline on the calling thread**. For a
/// per-query handler that is only a slowdown. For a loop that never returns it
/// means `main` never returns from the spawn — the ingress loop never starts,
/// and the process sits there bound and silent. That was a real startup hang on
/// any host with three or fewer CPUs (two slots for three loops, with the
/// default refresh interval). `concurrent` either gets a thread or fails, and a
/// failure here is fatal at startup rather than a hang nobody can diagnose.
fn spawnLoop(group: *std.Io.Group, io: std.Io, ctx: *const Context, name: []const u8, loop: LoopFn) !void {
    group.concurrent(io, supervise, .{ io, ctx, name, loop }) catch |err| {
        std.log.err("cannot start {s} loop on its own thread: {s}", .{ name, @errorName(err) });
        return err;
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    // Our own runtime rather than `init.io`, because the async limit has to be
    // raised by the number of background loops (see `asyncLimit`) and
    // `std.process.Init` exposes its `Threaded` only as a type-erased `Io`.
    // Declared first so it is torn down last: `deinit` joins the worker
    // threads, which must not happen while anything below still uses them.
    var threaded: std.Io.Threaded = .init(gpa, .{
        .argv0 = .init(init.minimal.args),
        .environ = init.minimal.environ,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Before anything that can log, so diagnostics share one stderr lock with
    // the rest of the process rather than interleaving with it.
    obs_log.init(io);
    // Handed back to `init.io` before `threaded` is torn down, because logging
    // outlives `main`: when `main` returns an error, `start.zig` logs it through
    // `logFn` *after* every defer here has run. Left pointing at `threaded`, that
    // record locks stderr through a runtime that no longer exists — found as a
    // hang in the fail-closed case, which is exactly the path that returns one.
    defer obs_log.init(init.io);

    // Resolve configuration before anything else, so a bad env file fails
    // before we have opened a socket. `environ_map` is not threadsafe; loading
    // here keeps every write to it on this thread, before any coroutine runs.
    // Borrowed strings live as long as the map, i.e. the process.
    const cfg = try Settings.load(io, gpa, init.environ_map);

    // Only now can logging honour the operator: everything above this line —
    // including `Settings.load`'s own diagnostics — used the bootstrap defaults.
    obs_log.configure(io, cfg.log_level, cfg.log_format);

    // Before the first `async` anywhere — `buildSnapshot` below is one — so no
    // task is ever admitted under the old limit. The refresher and the TCP
    // accept loop only exist when enabled, and the count has to agree with
    // what is spawned.
    const handler_threads = cfg.handler_threads orelse defaultHandlerThreads();
    const tcp_enabled = cfg.max_tcp_conns > 0;
    const loops: usize = 2 + @as(usize, @intFromBool(cfg.blocklist_refresh_secs != 0)) + @intFromBool(tcp_enabled);
    threaded.setAsyncLimit(asyncLimit(handler_threads, loops + cfg.max_tcp_conns));

    const client_socket, const upstream_socket = try initSockets(io, cfg);
    defer client_socket.close(io);
    defer upstream_socket.close(io);

    // TCP on the same address and port as UDP (RFC 7766: a resolver that
    // answers over UDP must also answer over TCP). Declared here so its
    // teardown runs after the group's: the accept loop and the sweeper both
    // reach it, and both are stopped by `group.cancel` below.
    const listen_addr = try initIpAddress(cfg.listen_host, cfg.listen_port);
    //
    // `reuse_address`, because without it a restart fails with AddressInUse
    // for as long as the previous process's TCP connections sit in TIME_WAIT —
    // up to a couple of minutes after every restart that had TCP clients. It
    // sets SO_REUSEPORT too, which on its own would let a second Vortex share
    // the port; that cannot happen here, because the UDP socket above binds
    // first and without reuse, so a second instance fails there.
    var tcp_server: ?std.Io.net.Server = if (tcp_enabled)
        listen_addr.listen(io, .{ .reuse_address = true }) catch |err| {
            logBindFailure("tcp listener", &listen_addr, err);
            return err;
        }
    else
        null;
    defer if (tcp_server) |*server| server.deinit(io);
    var tcp_conns: ?ConnTable = if (tcp_enabled) try ConnTable.init(gpa, cfg.max_tcp_conns) else null;
    defer if (tcp_conns) |*conns| conns.deinit();
    // Runs before `deinit` above: every connection task has to be gone first.
    defer if (tcp_conns) |*conns| conns.cancelAll(io);
    const tcp: ?Tcp = if (tcp_enabled) .{ .server = &tcp_server.?, .conns = &tcp_conns.? } else null;

    const upstream_addr = try initIpAddress(cfg.upstream_host, cfg.upstream_port);

    var http_client: std.http.Client = .{
        .io = io,
        .allocator = gpa,
    };
    defer http_client.deinit();

    const initial = try buildSnapshot(gpa, io, &http_client, cfg);

    var policy = Policy.init(initial);
    defer policy.deinit();

    if (initial.count() == 0) {
        // Only reachable under `.open`: `.closed` would have propagated out of
        // `buildSnapshot`. Logged at `.err` rather than `.warn` because the
        // resolver is running in a state where it filters nothing, and the
        // refresher will retry on the degraded interval until that changes.
        std.log.err(
            "running with an EMPTY blocklist: no list could be fetched or restored from cache",
            .{},
        );
    }

    var seed: u64 = undefined;
    io.random(std.mem.asBytes(&seed));
    var pending_table = PendingTable.init(gpa, io, seed, cfg.max_pending);
    defer pending_table.deinit();

    var question_seed: u64 = undefined;
    io.random(std.mem.asBytes(&question_seed));

    // Its own seed, not `question_seed`. Different threat: `hashQuestion`'s
    // seed stops an off-path attacker precomputing a colliding question, while
    // this one stops chosen qnames from being piled into one hash bucket.
    // Sharing one seed would tie two unrelated defences together for no gain.
    var cache_seed: u64 = undefined;
    io.random(std.mem.asBytes(&cache_seed));

    var cache = Cache.init(gpa, io, cache_seed, cfg.cache_max_entries);
    defer cache.deinit();

    // Zero entries means "no cache" rather than "a cache that instantly
    // refuses everything" — the null keeps the lookup out of the hot path
    // entirely instead of paying for a lock and a miss on every query.
    const cache_ptr: ?*Cache = if (cfg.cache_max_entries == 0) null else &cache;
    if (cache_ptr == null) std.log.info("response cache disabled (VORTEX_CACHE_MAX_ENTRIES=0)", .{});

    // process-wide bundle of shared, long-lived resources that every coroutine in the proxy needs.
    // Null disables the refresher entirely, and the loop below is then never
    // spawned — "no refresh" costs one absent coroutine rather than one that
    // wakes up forever to decide it has nothing to do.
    const refresher: ?Refresher = if (cfg.blocklist_refresh_secs == 0)
        null
    else
        .{ .http_client = &http_client, .cfg = &cfg };
    if (refresher == null) std.log.info("blocklist refresh disabled (VORTEX_BLOCKLIST_REFRESH_SECS=0)", .{});

    var ctx = Context.init(
        &client_socket,
        &upstream_socket,
        upstream_addr,
        &pending_table,
        &policy,
        cache_ptr,
        gpa,
        question_seed,
        if (refresher) |*r| r else null,
    );
    ctx.tcp = if (tcp) |*t| t else null;
    // 1232 only when there is a TCP listener to retry against; see
    // `Context.edns_udp_size`.
    ctx.edns_udp_size = if (tcp_enabled) edns.advertised_udp_size else edns.no_tcp_udp_size;

    // Tasks live in the group, not in discarded futures, so completions
    // always have live result storage. Per-task resources are released as
    // each task returns, so the group can accept tasks indefinitely.
    var group: std.Io.Group = std.Io.Group.init;
    defer group.cancel(io);

    try spawnLoop(&group, io, &ctx, "dispatcher", dispatcherLoop);
    try spawnLoop(&group, io, &ctx, "sweeper", sweeperLoop);
    if (ctx.refresh != null) try spawnLoop(&group, io, &ctx, "refresher", refresherLoop);
    if (ctx.tcp != null) try spawnLoop(&group, io, &ctx, "tcp accept", tcpAcceptLoop);

    // `{f}`, not host:port, so an IPv6 listener reads `[::]:53` rather than `:::53`.
    std.log.info("listening={f} upstream={f} handler_threads={d} tcp_conns={d} edns_udp_size={d}", .{
        listen_addr,
        upstream_addr,
        handler_threads,
        cfg.max_tcp_conns,
        ctx.edns_udp_size,
    });
    var buffer: [4096]u8 = undefined;
    while (true) {
        const incoming: std.Io.net.IncomingMessage = client_socket.receive(io, &buffer) catch |err| switch (err) {
            error.Canceled => return,
            else => {
                std.log.warn("ingress receive: {s}", .{@errorName(err)});
                continue;
            },
        };

        const incoming_addr: std.Io.net.IpAddress = incoming.from;

        // The query was larger than `buffer` and its tail is gone. Parsing the
        // prefix would mean acting on a question we only half received, so this
        // is refused before the dupe and the coroutine spawn — a flood of
        // oversized datagrams costs one 12-byte reply each and nothing more.
        // FORMERR is safe to send here: the reply is far smaller than the
        // query, so it carries no amplification value.
        if (incoming.flags.trunc) {
            std.log.warn("oversized query from {f} exceeded {d}-byte buffer", .{
                incoming_addr,
                buffer.len,
            });
            if (incoming.data.len >= 12) {
                const reply = Header.headerOnlyReply(incoming.data, .format_error);
                client_socket.send(io, &incoming_addr, &reply) catch |err| switch (err) {
                    error.Canceled => return,
                    else => {},
                };
            }
            continue;
        }

        // `buffer` is reused by the next receive, so the handler needs its own copy.
        // Ownership transfers to `handleQuery`, whose `defer gpa.free(data)` releases
        // it on every exit path — do not dupe again below, and do not free here.
        const data_owned: []u8 = gpa.dupe(u8, incoming.data) catch {
            std.log.warn("shedding datagram from {f}: out of memory", .{incoming.from});
            continue;
        };

        group.async(io, handleQuery, .{
            io,
            gpa,
            &ctx,
            incoming_addr,
            data_owned,
        });
    }
}

// Aggregate every module's tests into `zig build test`. A plain `@import` alias
// (as at the top of this file) does NOT pull an imported file's `test` blocks into
// the build — only an explicit `_ = @import(...)` reference does. A file missing from
// this list keeps every one of its tests, and simply never runs them.
//
// Note what this does *not* reach: the integration cases in `tests/`, which are a
// separate artifact with its own root and are pulled in by `build.zig`, not from here.
test {
    _ = @import("dns/authority.zig");
    _ = @import("dns/blocked_response.zig");
    _ = @import("dns/cache.zig");
    _ = @import("dns/edns.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/name_reader.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/resource_record.zig");
    _ = @import("utils/backoff.zig");
    _ = @import("blocklist/acquire.zig");
    _ = @import("blocklist/allowlist.zig");
    _ = @import("blocklist/domain_blocklist.zig");
    _ = @import("blocklist/suffix_blocklist.zig");
    _ = @import("blocklist/policy.zig");
    _ = @import("utils/pending_table.zig");
    _ = @import("utils/conn_table.zig");
    _ = @import("utility.zig");
    _ = @import("obs/log.zig");
    _ = @import("settings.zig");
}

// The aggregator above collects each module's `test` blocks; it does not
// reference their declarations. This does, for this file — and this file is the
// one where it buys the most.
//
// Referencing `main` forces analysis of everything reachable from it:
// `handleQuery`, `dispatcherLoop`, `sweeperLoop`, `supervise` and all the
// wiring in between. None of that sits inside a `test` block, so until now
// **`zig build test` did not type-check any of it** — the 2026-08-09 finding
// where `backoffSeconds` returned the wrong integer type and the suite reported
// 0 errors while `zig build` could not produce a binary at all.
//
// This makes the coroutine layer *compiled*, which is strictly weaker than
// tested and was previously not true either. What tests it is the integration
// harness in [tests/](../tests/), which landed 2026-09-12 and drives this file's
// three loops over real sockets — the two are complements, not substitutes: the
// guard catches code that cannot build, the harness catches code that builds and
// is wrong.
test "refAllDecls: reaching main type-checks the whole coroutine layer" {
    std.testing.refAllDecls(@This());
}

test "initialize sockets" {
    const test_socket = try initIpAddress("0.0.0.0", 5454);

    std.debug.assert(test_socket.getPort() == 5454);
}

test "asyncLimit reserves a slot per loop on top of the handlers" {
    const testing = std.testing;

    // Handlers keep exactly what they were given: the loops' slots come on top,
    // never out of the handlers' share.
    try testing.expectEqual(std.Io.Limit.limited(3 + 3), asyncLimit(3, 3));

    // 0 handler threads is legal — every query inline on the ingress thread —
    // and must still leave room for the loops.
    try testing.expectEqual(std.Io.Limit.limited(2), asyncLimit(0, 2));
}

test "backoffSeconds binds the supervisor's ceiling" {
    const testing = std.testing;

    // The schedule itself is tested in utils/backoff.zig. What is this
    // function's own is the pair it binds: the first restart is immediate, and
    // the delay saturates at *this* cap rather than the fetch retry's.
    try testing.expectEqual(@as(i64, 0), backoffSeconds(0));
    try testing.expectEqual(@as(i64, 1), backoffSeconds(1));

    // 1<<5 is 32, which `restart_backoff_cap_s` clamps to 30 — so this
    // assertion fails if the wrapper is ever pointed at a different ceiling.
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(6));
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(std.math.maxInt(u32)));
}
