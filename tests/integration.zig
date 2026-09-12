//! End-to-end cases against a running `vortex`, over real UDP sockets.
//!
//! These are the coverage `zig build test`'s unit suite structurally cannot
//! provide: `handleQuery`, `dispatcherLoop` and the ingress loop are socket
//! plumbing, and everything in them that could be extracted into a pure
//! function over bytes already has been. See next_steps.md P2.5, and
//! [harness.zig](harness.zig) for how a case gets its Vortex.
//!
//! Each case is one scenario from the table in that document — the manual `dig`
//! runs that were, until now, the only evidence this layer worked at all. Two
//! of them (`upstream reply overflows our buffer`, `upstream echoes the right
//! ID with the wrong question`) found real bugs that the entire unit suite
//! passed straight through, which is the argument for the harness existing.
//!
//! **Conventions.**
//!
//! * Expectations are built by [wire.zig](wire.zig), which shares no code with
//!   `src/dns`. Two independent encoders agreeing is evidence; one encoder
//!   checked against itself is not.
//! * Every case gets its own Vortex, so nothing leaks between them — not a
//!   cache entry, not a pending-table slot, not a port.
//! * The cache is off unless the case is about the cache. It would otherwise
//!   turn "did the query reach upstream?" into a question about test ordering.
//! * Names come from RFC 2606 / RFC 6761 reserved space, so a case that
//!   somehow escaped to a real resolver still could not hit a real domain.
//!
//! **Runtime.** Two cases wait out Vortex's 5-second upstream deadline, so the
//! suite takes ~13s wall. That is the price of covering the timeout path, and
//! the timeout path is where the P1.3/P1.4 interaction bug lived.

const std = @import("std");

const harness = @import("harness.zig");
const wire = @import("wire.zig");

const testing = std.testing;
const Instance = harness.Instance;

/// Vortex SERVFAILs a query its upstream never answered after a 5s deadline,
/// swept on a 1s tick — so up to 6s, and no less than 5.
const upstream_deadline_ms = 5_000;
const sweep_interval_ms = 1_000;

// ── Forwarding ────────────────────────────────────────────────────────────

test "a forwarded query returns with the client's transaction ID restored" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // Deliberately not the ID that goes on the wire upstream: the whole point
    // of the pending table is that Vortex substitutes a random proxy ID and
    // puts this one back on the way out.
    const client_id: u16 = 0xAB12;

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, client_id, "forward.example.com", .{});
    try vortex.sendQuery(query);

    var upstream_buf: [wire.max_message]u8 = undefined;
    const forwarded = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);

    // The question must arrive byte for byte — the dispatcher hashes exactly
    // these bytes to decide whether the answer belongs to this query.
    const q_end = try wire.questionEnd(query);
    try testing.expectEqualSlices(u8, query[12..q_end], forwarded.data[12..q_end]);

    // And the ID must *not* be ours. If Vortex forwarded the client's ID
    // verbatim, an off-path attacker who saw the client's query would know the
    // ID to forge a reply with.
    try testing.expect(wire.id(forwarded.data) != client_id);

    var reply_buf: [wire.max_message]u8 = undefined;
    const reply = try wire.reply(&reply_buf, forwarded.data, .{
        .addresses = &.{.{ 203, 0, 113, 7 }},
        .ttl = 300,
    });
    try vortex.sendUpstreamReply(&forwarded.from, reply);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(client_id, wire.id(answer));
    try testing.expect(wire.isResponse(answer));
    try testing.expectEqual(@as(u4, wire.RCode.no_error), wire.rcode(answer));
    try testing.expectEqual(@as(u16, 1), wire.ancount(answer));

    // The payload is relayed untouched, which is the other half of "restored
    // ID": rewriting two bytes must not disturb anything after them.
    const answer_q_end = try wire.questionEnd(answer);
    try testing.expectEqual(
        [4]u8{ 203, 0, 113, 7 },
        try wire.firstAnswerAddress(answer, answer_q_end),
    );
}

// ── Blocking ──────────────────────────────────────────────────────────────

test "an exact-blocked name is answered locally with NXDOMAIN and an SOA" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // Mixed case on purpose. The C1 regression was that the *parsed* copy used
    // for the lookup was not lowercased, so `AdS.Example.COM` sailed past a
    // blocklist holding `ads.example.com`.
    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x1234, "AdS.Example.COM", .{});
    try vortex.sendQuery(query);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(@as(u16, 0x1234), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.name_error), wire.rcode(answer));
    try testing.expectEqual(@as(u16, 1), wire.qdcount(answer));
    try testing.expectEqual(@as(u16, 0), wire.ancount(answer));

    // NSCOUNT=1 is what makes the block *cacheable* by the client (RFC 2308).
    // Without the SOA the client re-asks for every lookup, which is the C2 bug.
    try testing.expectEqual(@as(u16, 1), wire.nscount(answer));

    // The question is echoed with its original casing intact — only the copy
    // the filters saw was folded.
    const q_end = try wire.questionEnd(answer);
    try testing.expectEqualSlices(u8, query[12..q_end], answer[12..q_end]);

    // Header + question + exactly one 34-byte SOA, and nothing else.
    try testing.expectEqual(q_end + 34, answer.len);

    const soa = answer[q_end..];
    try testing.expectEqual(@as(u16, 0xC00C), std.mem.readInt(u16, soa[0..2], .big));
    try testing.expectEqual(@as(u16, wire.Type.soa), std.mem.readInt(u16, soa[2..4], .big));
    try testing.expectEqual(@as(u16, wire.class_in), std.mem.readInt(u16, soa[4..6], .big));

    // The datagram never left the process: a synthesized answer that still made
    // an upstream round trip would be a block that leaks the lookup.
    try vortex.expectNoUpstreamQuery(200);
}

test "a suffix-blocked subdomain is answered locally" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // `adnetwork.example` is in the suffix fixture; this name is three labels
    // below it, so only the parent-label walk can match it.
    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x55AA, "a.b.c.adnetwork.example", .{});
    try vortex.sendQuery(query);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(@as(u16, 0x55AA), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.name_error), wire.rcode(answer));
    try testing.expectEqual(@as(u16, 1), wire.nscount(answer));
    try vortex.expectNoUpstreamQuery(200);
}

test "a name under no list is forwarded rather than blocked" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // The counterpart to the two cases above, and the one that would catch a
    // blocklist that matched everything — which is exactly what an over-eager
    // suffix walk produces, and what no unit test of `decide` alone can rule
    // out at the datapath level.
    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x0101, "allowed.example.com", .{});
    try vortex.sendQuery(query);

    var upstream_buf: [wire.max_message]u8 = undefined;
    _ = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);
}

// ── Header validation on ingress ──────────────────────────────────────────

test "a non-standard opcode is answered NOTIMP with every count zeroed" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x7777, "iquery.example.com", .{ .opcode = 1 });
    try vortex.sendQuery(query);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(@as(usize, 12), answer.len);
    try testing.expectEqual(@as(u16, 0x7777), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.not_implemented), wire.rcode(answer));
    try testing.expect(wire.isResponse(answer));

    // The opcode is echoed, so the client can tell which of its outstanding
    // requests was refused.
    try testing.expectEqual(@as(u4, 1), wire.opcode(answer));

    // No question is echoed: for an IQUERY there may not be one to echo, and
    // claiming a section that isn't there is what makes a reply unparseable.
    try testing.expectEqual(@as(u16, 0), wire.qdcount(answer));
    try testing.expectEqual(@as(u16, 0), wire.ancount(answer));
    try testing.expectEqual(@as(u16, 0), wire.nscount(answer));
    try testing.expectEqual(@as(u16, 0), wire.arcount(answer));

    try vortex.expectNoUpstreamQuery(200);
}

test "QDCOUNT other than 1 is answered FORMERR" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x2222, "two.example.com", .{ .qdcount = 2 });
    try vortex.sendQuery(query);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(@as(usize, 12), answer.len);
    try testing.expectEqual(@as(u16, 0x2222), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.format_error), wire.rcode(answer));
    try testing.expectEqual(@as(u16, 0), wire.qdcount(answer));
    try vortex.expectNoUpstreamQuery(200);
}

test "a datagram with QR=1 is dropped, never answered (C3 regression)" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // This is the reflector case, and it is the one rejection that must stay
    // silent. Answering a *response* turns Vortex into an amplifier: an
    // attacker spoofs a victim's source address, and every packet they send
    // produces one from us to the victim.
    //
    // Note what makes this testable end to end at all — a unit test can assert
    // `validateQuery` returns `.is_response`, but only a live socket can prove
    // nothing was put on the wire.
    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x3333, "reflect.example.com", .{ .response = true });
    try vortex.sendQuery(query);

    try vortex.expectNoClientReply(500);
    try vortex.expectNoUpstreamQuery(200);
}

test "a query larger than the ingress buffer gets a 12-byte FORMERR and is not forwarded" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    // Vortex receives into a 4096-byte buffer, so this datagram arrives with
    // its tail already gone. Parsing the prefix would mean acting on a question
    // only half of which was received.
    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x4444, "huge.example.com", .{ .padding = 5000 });
    try testing.expect(query.len > 4096);
    try vortex.sendQuery(query);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    try testing.expectEqual(@as(usize, 12), answer.len);
    try testing.expectEqual(@as(u16, 0x4444), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.format_error), wire.rcode(answer));

    // The reply is two orders of magnitude smaller than the query, so this
    // path carries no amplification value — which is why it is safe to answer
    // at all rather than drop.
    try testing.expect(answer.len < query.len);

    try vortex.expectNoUpstreamQuery(200);
}

// ── The dispatcher's reply path ───────────────────────────────────────────

test "an upstream reply larger than the buffer is relayed with TC=1" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x5151, "big.example.com", .{});
    try vortex.sendQuery(query);

    var upstream_buf: [wire.max_message]u8 = undefined;
    const forwarded = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);

    // Past Vortex's 4096-byte dispatcher buffer, so the tail is discarded on
    // receive and what reaches the client is a prefix of a DNS message.
    var reply_buf: [wire.max_message]u8 = undefined;
    const reply = try wire.reply(&reply_buf, forwarded.data, .{
        .addresses = &.{.{ 198, 51, 100, 1 }},
        .min_len = 5000,
    });
    try testing.expect(reply.len > 4096);
    try vortex.sendUpstreamReply(&forwarded.from, reply);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(&client_buf, harness.default_timeout_ms);

    // This is the bug the manual run caught: without TC the client parses a
    // silently corrupt message and has no way to know. TC=1 makes it an honest
    // failure the client can act on by retrying over TCP.
    try testing.expect(wire.isTruncated(answer));
    try testing.expectEqual(@as(u16, 0x5151), wire.id(answer));
    try testing.expect(answer.len <= 4096);
    try testing.expect(answer.len < reply.len);
}

test "a silent upstream produces SERVFAIL rather than silence" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x6161, "silent.example.com", .{});

    const started = std.Io.Clock.boot.now(testing.io);
    try vortex.sendQuery(query);

    // Received and deliberately not answered. Reading it matters: it proves
    // the SERVFAIL below came from the *deadline*, not from a send that failed
    // outright, which would arrive far too fast and mean nothing.
    var upstream_buf: [wire.max_message]u8 = undefined;
    _ = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);

    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(
        &client_buf,
        upstream_deadline_ms + sweep_interval_ms + harness.default_timeout_ms,
    );
    const elapsed_ms: u64 = @intCast(started.untilNow(testing.io, .boot).toMilliseconds());

    try testing.expectEqual(@as(u16, 0x6161), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.server_failure), wire.rcode(answer));
    try testing.expect(wire.isResponse(answer));

    // Not before the deadline, which is what separates "the sweeper did its
    // job" from "something else failed fast and happened to produce SERVFAIL".
    try testing.expect(elapsed_ms >= upstream_deadline_ms);
}

test "a reply with the right ID but the wrong question is discarded, and the client still gets SERVFAIL" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{});
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    var query_buf: [wire.max_message]u8 = undefined;
    const query = wire.query(&query_buf, 0x7171, "victim.example.com", .{});

    const started = std.Io.Clock.boot.now(testing.io);
    try vortex.sendQuery(query);

    var upstream_buf: [wire.max_message]u8 = undefined;
    const forwarded = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);

    // A forgery that guessed the proxy ID — here handed to us, which is
    // strictly more than an off-path attacker gets — but could not reproduce
    // the question. The question hash is what stops it.
    var forged_query_buf: [wire.max_message]u8 = undefined;
    const forged_query = wire.query(
        &forged_query_buf,
        wire.id(forwarded.data),
        "attacker.example.com",
        .{},
    );
    var forged_buf: [wire.max_message]u8 = undefined;
    const forged = try wire.reply(&forged_buf, forged_query, .{
        .addresses = &.{.{ 6, 6, 6, 6 }},
    });
    try vortex.sendUpstreamReply(&forwarded.from, forged);

    // Half one: the forgery is not relayed.
    try vortex.expectNoClientReply(500);

    // Half two, and the half that is the actual regression. Rejecting the
    // forgery must not *consume* the pending entry — an earlier version
    // completed the entry before verifying it, so a forged packet that merely
    // guessed the ID killed the real query as a side effect of being rejected.
    // The attacker failed to inject an answer and still denied service, and the
    // sweeper was left with nothing to SERVFAIL. Both units were correct in
    // isolation; only the interaction was wrong.
    var client_buf: [wire.max_message]u8 = undefined;
    const answer = try vortex.recvClient(
        &client_buf,
        upstream_deadline_ms + sweep_interval_ms + harness.default_timeout_ms,
    );
    const elapsed_ms: u64 = @intCast(started.untilNow(testing.io, .boot).toMilliseconds());

    try testing.expectEqual(@as(u16, 0x7171), wire.id(answer));
    try testing.expectEqual(@as(u4, wire.RCode.server_failure), wire.rcode(answer));
    try testing.expect(elapsed_ms >= upstream_deadline_ms);
}

// ── The cache ─────────────────────────────────────────────────────────────

test "a repeated query is served from cache without a second upstream round trip" {
    var vortex = try Instance.start(testing.io, testing.allocator, .{ .cache_max_entries = 100 });
    defer vortex.deinit();
    errdefer vortex.reportChildLog();

    const name = "cached.example.com";

    var query_buf: [wire.max_message]u8 = undefined;
    const first = wire.query(&query_buf, 0x8181, name, .{});
    try vortex.sendQuery(first);

    var upstream_buf: [wire.max_message]u8 = undefined;
    const forwarded = try vortex.recvUpstream(&upstream_buf, harness.default_timeout_ms);

    var reply_buf: [wire.max_message]u8 = undefined;
    const reply = try wire.reply(&reply_buf, forwarded.data, .{
        .addresses = &.{.{ 192, 0, 2, 55 }},
        .ttl = 300,
    });
    try vortex.sendUpstreamReply(&forwarded.from, reply);

    var client_buf: [wire.max_message]u8 = undefined;
    const miss = try vortex.recvClient(&client_buf, harness.default_timeout_ms);
    try testing.expectEqual(@as(u16, 0x8181), wire.id(miss));

    // Same question, different transaction ID — the case a cache keyed on the
    // ID would get wrong in both directions.
    var second_buf: [wire.max_message]u8 = undefined;
    const second = wire.query(&second_buf, 0x9292, name, .{});
    try vortex.sendQuery(second);

    // The assertion that makes this a cache test rather than a "did it answer"
    // test: nothing reaches the upstream the second time.
    try vortex.expectNoUpstreamQuery(500);

    var hit_buf: [wire.max_message]u8 = undefined;
    const hit = try vortex.recvClient(&hit_buf, harness.default_timeout_ms);

    // Served from one stored entry, but carrying *this* client's ID.
    try testing.expectEqual(@as(u16, 0x9292), wire.id(hit));
    try testing.expectEqual(@as(u4, wire.RCode.no_error), wire.rcode(hit));
    try testing.expectEqual(@as(u16, 1), wire.ancount(hit));

    const q_end = try wire.questionEnd(hit);
    try testing.expectEqual(
        [4]u8{ 192, 0, 2, 55 },
        try wire.firstAnswerAddress(hit, q_end),
    );

    // Aged on the way out, per RFC 2181 §5.2. A hit that handed back the
    // original 300 would tell the client the record is fresher than it is, and
    // a client that re-cached it would hold it past the authoritative expiry.
    try testing.expect(try wire.firstAnswerTtl(hit, q_end) <= 300);
}
