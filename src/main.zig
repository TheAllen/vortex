///
const std = @import("std");

const blocked_response = @import("dns/blocked_response.zig");
const Console = @import("console.zig").Console;
const Context = @import("utility.zig").Context;
const DomainBlockList = @import("blocklist/domain_blocklist.zig").DomainBlockList;
const Header = @import("dns/header.zig").Header;
const PendingTable = @import("utils/pending_table.zig").PendingTable;
const Policy = @import("blocklist/policy.zig").Policy;
const Settings = @import("settings.zig").Settings;
const SuffixBlockList = @import("blocklist/suffix_blocklist.zig").SuffixBlockList;
const Question = @import("dns/question.zig").Question;

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
    question.init(gpa) catch {
        std.log.err("Failed to init question", .{});
        return;
    };
    defer question.deinit(gpa);
    const q_end = question.parseQuestion(gpa, data) catch |err| {
        std.log.debug("dropping malformed query from {f}: {s}", .{ incoming_addr, @errorName(err) });
        return;
    };

    const domain: []const u8 = question.qname.name_list.items;

    switch (ctx.policy.decide(domain)) {
        .allow => {
            console.println("Allow", .{}) catch {};
        },
        .block => {
            console.println("{s} -> BLOCKED", .{domain}) catch {};

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
            console.println("PASS", .{}) catch {};
        },
    }

    const proxy_id = ctx.pending_table.appendQuery(.{
        .client_id = header.id,
        .client_addr = incoming_addr,
        .expires_at = @truncate(std.Io.Timestamp.now(io, std.Io.Clock.real).nanoseconds + 5 * std.time.ns_per_s),
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

        // The DNS query entry with the custom proxy_id
        const entry = ctx.pending_table.complete(proxy_id) orelse {
            std.log.debug("orphan response id={x}", .{proxy_id});
            continue;
        };

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
    while (true) {
        try io.sleep(std.Io.Duration.fromSeconds(1), std.Io.Clock.real);
        ctx.pending_table.sweepExpiredQueries();
    }
}

var console = Console{};

pub fn main(init: std.process.Init) !void {
    // A standard set of pre-initialized useful APIs
    const io = init.io;
    const gpa = init.gpa;

    // Console is a thread safe writer
    console.init(io);

    // Resolve configuration before anything else, so a bad env file fails
    // before we have opened a socket. `environ_map` is not threadsafe; loading
    // here keeps every write to it on this thread, before any coroutine runs.
    // Borrowed strings live as long as the map, i.e. the process.
    const cfg = try Settings.load(io, gpa, init.environ_map);

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

    const ctx = Context.init(
        &client_socket,
        &upstream_socket,
        upstream_addr,
        &pending_table,
        &policy,
    );

    // Tasks live in the group, not in discarded futures, so completions
    // always have live result storage. Per-task resources are released as
    // each task returns, so the group can accept tasks indefinitely.
    var group: std.Io.Group = std.Io.Group.init;
    defer group.cancel(io);

    group.async(io, dispatcherLoop, .{ io, &ctx }); // Dispatcher Coroutine
    group.async(io, sweeperLoop, .{ io, &ctx }); // Sweeper Coroutine

    try console.println("Vortex listening on {s}:{d}, forwarding to {s}:{d}", .{
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
    _ = @import("dns/domain_name.zig");
    _ = @import("dns/header.zig");
    _ = @import("dns/question.zig");
    _ = @import("blocklist/allowlist.zig");
    _ = @import("blocklist/domain_blocklist.zig");
    _ = @import("blocklist/suffix_blocklist.zig");
    _ = @import("blocklist/policy.zig");
    _ = @import("utils/pending_table.zig");
    _ = @import("utility.zig");
    _ = @import("console.zig");
    _ = @import("settings.zig");
}

test "initialize sockets" {
    const test_socket = try initIpAddress("0.0.0.0", 5454);

    std.debug.assert(test_socket.getPort() == 5454);
}
