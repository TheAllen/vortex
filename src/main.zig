///
const std = @import("std");

const blocked_response = @import("dns/blocked_response.zig");
const Context = @import("utility.zig").Context;
const DomainBlockList = @import("blocklist/domain_blocklist.zig").DomainBlockList;
const Header = @import("dns/header.zig").Header;
const pending_table_mod = @import("utils/pending_table.zig");
const PendingTable = pending_table_mod.PendingTable;
const PendingQuery = pending_table_mod.PendingQuery;
const Policy = @import("blocklist/policy.zig").Policy;
const obs_log = @import("obs/log.zig");
const ResourceRecordIter = @import("dns/resource_record.zig").ResourceRecordIter;
const Settings = @import("settings.zig").Settings;
const SuffixBlockList = @import("blocklist/suffix_blocklist.zig").SuffixBlockList;
const Question = @import("dns/question.zig").Question;

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

fn addrBind(io: std.Io, addr: *const std.Io.net.IpAddress) !std.Io.net.Socket {
    return addr.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        std.log.err("Error: failed to create socket...", .{});
        return err;
    };
}

fn initIpAddress(host: []const u8, port: u16) !std.Io.net.IpAddress {
    return try std.Io.net.IpAddress.parse(host, port);
}

fn initSockets(io: std.Io, cfg: Settings) !struct {
    std.Io.net.Socket,
    std.Io.net.Socket,
} {
    const addr: std.Io.net.IpAddress = try initIpAddress(cfg.listen_host, cfg.listen_port);
    const client_socket: std.Io.net.Socket = try addrBind(io, &addr);

    const local_upstream_addr: std.Io.net.IpAddress = try std.Io.net.IpAddress.parse(
        cfg.upstream_bind_host,
        cfg.upstream_bind_port,
    );
    const upstream_socket: std.Io.net.Socket = try addrBind(io, &local_upstream_addr);

    return .{
        client_socket,
        upstream_socket,
    };
}

/// Per-query coroutine that checks the QName of a DNS packet and decide if it belongs to the block-list
/// Workflow:
///   1. Check the QName in Question section of the packet
///   2a. Parse the ID if not in blocklist
///   2b. Craft Response section and send back to client (no need to parse header)
fn handleQuery(
    io: std.Io,
    gpa: std.mem.Allocator,
    ctx: *const Context,
    incoming_addr: std.Io.net.IpAddress,
    data: []u8,
) std.Io.Cancelable!void {
    defer gpa.free(data);

    if (data.len < 12) return;

    // Check against block list
    var header = Header{};
    header.parseHeader(data[0..12]);

    const rejection = header.validateQuery();
    if (rejection != .none) {
        // `rcode()` decides drop-vs-reply. QR=1 is the silent case: answering a
        // response would make us a reflector. The others are real clients
        // asking for something malformed or unimplemented, so they get an
        // answer — header-only, since their question section is exactly what we
        // could not trust.
        if (rejection.rcode()) |rcode| {
            const reply = Header.headerOnlyReply(data, rcode);
            ctx.client_socket.send(io, &incoming_addr, &reply) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {},
            };
        }
        std.log.debug("rejecting query from {f}: {s}", .{ incoming_addr, @tagName(rejection) });
        return;
    }

    var question = Question{};
    const q_end = question.parseQuestion(data, 12) catch |err| {
        std.log.debug("dropping malformed query from {f}: {s}", .{ incoming_addr, @errorName(err) });
        return;
    };

    // Borrows `question`'s inline buffer, so it stays valid for exactly as long
    // as `question` is in scope — through the policy decision and the send below.
    const domain: []const u8 = question.qname.slice();

    switch (ctx.policy.decide(domain)) {
        .allow => {
            query_log.debug("verdict=allow qname={s}", .{domain});
        },
        .block => {
            query_log.debug("verdict=block qname={s}", .{domain});

            // NXDOMAIN + a synthetic SOA so the client can negatively cache the
            // block. Built into a fresh buffer because `data` is a dupe sized to
            // the exact query length — see blocked_response.build.
            const reply = blocked_response.build(gpa, data, q_end, .name_error) catch {
                std.log.warn("dropping blocked reply for {s}: out of memory", .{domain});
                return;
            };
            defer gpa.free(reply);

            ctx.client_socket.send(io, &incoming_addr, reply) catch {};
            return;
        },
        .pass => {
            query_log.debug("verdict=pass qname={s}", .{domain});
        },
    }

    // q_end is one past the question section, so the question occupies
    // data[12..q_end]. parseQuestion already bounded it against data.len.
    const question_len: u16 = @intCast(q_end - 12);
    const question_hash = pending_table_mod.hashQuestion(ctx.question_seed, data, question_len).?;

    const proxy_id = ctx.pending_table.appendQuery(.{
        .client_id = header.id,
        .client_addr = incoming_addr,
        .question_hash = question_hash,
        .question_len = question_len,
        .expires_at = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds + 5 * std.time.ns_per_s),
    }) catch {
        std.log.err("Failed to append query to Pending table", .{});
        return;
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

        var reply_header = Header{};
        reply_header.parseHeader(reply_msg.data[0..12]);

        var reply_question = Question{};
        var offset: usize = 12;
        offset = reply_question.parseQuestion(reply_msg.data, offset) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.warn("failed to parse reply question: {s}", .{@errorName(err)});
                continue;
            },
        };

        // Parse resource records. Read-only: the datapath below relays upstream's
        // bytes verbatim whatever this finds, so a parse failure abandons the
        // walk and nothing else. A resolver that stopped resolving because it
        // disagreed with a record it was only logging would be a worse outcome
        // than any log line is worth.
        // The label is load-bearing: an unlabelled `break` in a `while`
        // *condition* binds to the enclosing loop — here the dispatcher's own
        // `while (true)` — which silently swallows the reply and drops out of
        // the loop entirely instead of just ending the walk.
        var resourceRecordIter = ResourceRecordIter.init(reply_msg.data, offset, reply_header);
        walk: while (true) {
            const next = resourceRecordIter.next() catch |err| {
                std.log.debug("record walk for id={x}: {s}", .{ proxy_id, @errorName(err) });
                break :walk;
            };
            const record = next orelse break :walk;
            std.log.info("name: {s}", .{record.name.slice()});
        }

        std.mem.writeInt(u16, reply_msg.data[0..2], entry.client_id, .big);

        // The datagram was larger than `msg_buf` and the tail was discarded. We
        // forward the client's OPT verbatim, so a client advertising an EDNS0
        // buffer above 4096 can legitimately provoke this. Relaying the prefix
        // as-is hands the client a silently corrupt message; TC=1 tells them it
        // is incomplete and to retry over TCP. (That retry has nowhere to land
        // until P3.6 adds a TCP listener — an honest failure rather than
        // silent corruption.)
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

fn sweeperLoop(io: std.Io, ctx: *const Context) std.Io.Cancelable!void {
    const gpa = ctx.gpa;
    // Reused across sweeps so the steady state allocates nothing: the common
    // case is an empty list once per second.
    var evicted: std.ArrayList(PendingQuery) = .empty;
    defer evicted.deinit(gpa);

    while (true) {
        // A relative sleep on the settable wall clock would stutter or race
        // ahead whenever NTP adjusts it; the sweep cadence should track the same
        // monotonic clock the deadlines are measured on.
        try io.sleep(std.Io.Duration.fromSeconds(1), std.Io.Clock.boot);

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
/// Pure, so the schedule is testable without spawning anything.
/// Returns `i64` because that is what `std.Io.Duration.fromSeconds` takes;
/// keeping the type match here avoids a cast at the call site.
fn backoffSeconds(consecutive_restarts: u32) i64 {
    if (consecutive_restarts == 0) return 0;
    const shift: u6 = @intCast(@min(consecutive_restarts - 1, 5));
    return @min(@as(i64, 1) << shift, restart_backoff_cap_s);
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

pub fn main(init: std.process.Init) !void {
    // A standard set of pre-initialized useful APIs
    const io = init.io;
    const gpa = init.gpa;

    // Before anything that can log, so diagnostics share one stderr lock with
    // the rest of the process rather than interleaving with it.
    obs_log.init(io);

    // Resolve configuration before anything else, so a bad env file fails
    // before we have opened a socket. `environ_map` is not threadsafe; loading
    // here keeps every write to it on this thread, before any coroutine runs.
    // Borrowed strings live as long as the map, i.e. the process.
    const cfg = try Settings.load(io, gpa, init.environ_map);

    // Only now can logging honour the operator: everything above this line —
    // including `Settings.load`'s own diagnostics — used the bootstrap defaults.
    obs_log.configure(io, cfg.log_level, cfg.log_format);

    const client_socket, const upstream_socket = try initSockets(io, cfg);
    defer client_socket.close(io);
    defer upstream_socket.close(io);

    const upstream_addr = try initIpAddress(cfg.upstream_host, cfg.upstream_port);

    var policy = Policy.init(gpa);
    defer policy.deinit(gpa);

    var http_client: std.http.Client = .{
        .io = io,
        .allocator = gpa,
    };
    defer http_client.deinit();

    var f_domain = io.async(DomainBlockList.constructBlockList, .{
        &policy.domain_blocklist,
        gpa,
        &http_client,
        cfg.blocklist_url,
    });
    var f_suffix = io.async(SuffixBlockList.constructSuffixBlockList, .{
        &policy.suffix_blocklist,
        gpa,
        &http_client,
        cfg.suffix_blocklist_url,
    });

    // Await both futures before propagating either error: a dropped future
    // would leave its coroutine running while the deferred deinits tear down
    // the resources it is still using.
    const r_domain = f_domain.await(io);
    const r_suffix = f_suffix.await(io);
    try r_domain;
    try r_suffix;

    var seed: u64 = undefined;
    io.random(std.mem.asBytes(&seed));
    var pending_table = PendingTable.init(gpa, io, seed);
    defer pending_table.deinit();

    var question_seed: u64 = undefined;
    io.random(std.mem.asBytes(&question_seed));

    // process-wide bundle of shared, long-lived resources that every coroutine in the proxy needs.
    const ctx = Context.init(
        &client_socket,
        &upstream_socket,
        upstream_addr,
        &pending_table,
        &policy,
        gpa,
        question_seed,
    );

    // Tasks live in the group, not in discarded futures, so completions
    // always have live result storage. Per-task resources are released as
    // each task returns, so the group can accept tasks indefinitely.
    var group: std.Io.Group = std.Io.Group.init;
    defer group.cancel(io);

    group.async(io, supervise, .{ io, &ctx, "dispatcher", dispatcherLoop });
    group.async(io, supervise, .{ io, &ctx, "sweeper", sweeperLoop });

    std.log.info("listening={s}:{d} upstream={s}:{d}", .{
        cfg.listen_host,
        cfg.listen_port,
        cfg.upstream_host,
        cfg.upstream_port,
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
// the build — only an explicit `_ = @import(...)` reference does. Without this block
// `zig build test` silently runs only root.zig's stub test. See next_steps.md P2.5.
test {
    _ = @import("dns/authority.zig");
    _ = @import("dns/blocked_response.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/name_reader.zig");
    _ = @import("dns/question.zig");
    _ = @import("dns/resource_record.zig");
    _ = @import("blocklist/allowlist.zig");
    _ = @import("blocklist/domain_blocklist.zig");
    _ = @import("blocklist/suffix_blocklist.zig");
    _ = @import("blocklist/policy.zig");
    _ = @import("utils/pending_table.zig");
    _ = @import("utility.zig");
    _ = @import("obs/log.zig");
    _ = @import("settings.zig");
}

test "initialize sockets" {
    const test_socket = try initIpAddress("0.0.0.0", 5454);

    std.debug.assert(test_socket.getPort() == 5454);
}

test "backoffSeconds doubles, caps, and lets the first restart be immediate" {
    const testing = std.testing;

    // First restart is free: a single spurious return should recover with no
    // added latency, since one blip is not a crash loop.
    try testing.expectEqual(@as(i64, 0), backoffSeconds(0));

    // Then double from one second.
    try testing.expectEqual(@as(i64, 1), backoffSeconds(1));
    try testing.expectEqual(@as(i64, 2), backoffSeconds(2));
    try testing.expectEqual(@as(i64, 4), backoffSeconds(3));
    try testing.expectEqual(@as(i64, 8), backoffSeconds(4));
    try testing.expectEqual(@as(i64, 16), backoffSeconds(5));

    // 1<<5 is 32, which the cap clamps to 30 — the doubling must not overshoot
    // the documented ceiling on its way there.
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(6));

    // And it stays clamped no matter how long the crash loop runs. This is the
    // property that matters: an unbounded shift would overflow the u6 and panic,
    // turning a recoverable crash loop into a hard crash.
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(7));
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(1000));
    try testing.expectEqual(@as(i64, restart_backoff_cap_s), backoffSeconds(std.math.maxInt(u32)));

    // Never decreases, so a longer crash loop is never retried more eagerly.
    var prev: i64 = 0;
    for (0..64) |i| {
        const cur = backoffSeconds(@intCast(i));
        try testing.expect(cur >= prev);
        prev = cur;
    }
}
