//! One record per query, and counters across all of them (P2.3 phase 2).
//!
//! **The record** is a `debug` event in the `query` scope, with real logfmt
//! fields:
//!
//! ```
//! ts=… level=debug scope=query client="192.168.1.20:51734" transport=udp
//!   qname="ads.example.com" qtype=1 verdict=block rcode=0 latency_us=41
//! ```
//!
//! (one line in the log). It is written once a query's fate is known: by
//! `decide` for an answer given locally, and by whatever completes a forward
//! (the dispatcher, the sweeper's timeout, the TCP path).
//!
//! **It is `debug` on purpose.** It says which device asked for which site,
//! which is personal data. Under the shipped `VORTEX_LOG_LEVEL=info` it is
//! never written; an operator turns it on deliberately. Decided 2026-11-22.
//!
//! **The counters** carry no per-client data, so the sweeper logs them at
//! `info`, once a minute, as a `stats` event. A query shed at the pending cap
//! (P1.5) gets a count here and no record of its own: one record per refused
//! datagram is what that rule exists to avoid during a flood.

const std = @import("std");
const obs_log = @import("log.zig");

pub const Transport = enum { udp, tcp };

/// What happened to a query. One per record, and one counter each.
pub const Verdict = enum {
    /// Answered locally from the blocklist.
    block,
    /// Answered from the cache.
    hit,
    /// Forwarded, and upstream's reply relayed.
    forward,
    /// Refused locally: a bad opcode, QDCOUNT, OPT or EDNS version.
    reject,
    /// Forwarded, and no reply came before the deadline: SERVFAIL.
    timeout,
    /// Forwarded over TCP, and the upstream connection failed: SERVFAIL.
    servfail,
};

pub const Event = struct {
    client: std.Io.net.IpAddress,
    transport: Transport,
    /// Empty when the question was never parsed (a header-only rejection).
    qname: []const u8,
    qtype: u16,
    verdict: Verdict,
    rcode: u4,
    /// When the query was received, on the `boot` clock.
    started_ns: i96,
};

/// Counts one query and writes its record. Call exactly once per query.
pub fn emit(io: std.Io, e: Event) void {
    count(e.verdict);
    const now = std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds;
    obs_log.event(.debug, .query, .{
        .client = e.client,
        .transport = e.transport,
        .qname = e.qname,
        .qtype = e.qtype,
        .verdict = e.verdict,
        .rcode = e.rcode,
        .latency_us = latencyUs(e.started_ns, now),
    });
}

/// Microseconds between two `boot` timestamps, never negative.
fn latencyUs(started_ns: i96, now_ns: i96) i64 {
    if (now_ns <= started_ns) return 0;
    return @intCast(@divTrunc(now_ns - started_ns, std.time.ns_per_us));
}

/// The rcode in a reply's header.
pub fn rcodeOf(reply: []const u8) u4 {
    if (reply.len < 4) return 0;
    return @truncate(reply[3]);
}

// ── Counters ──────────────────────────────────────────────────────────────

/// Counts since the last `take`. Monotonic atomics: each is independent, and
/// a snapshot that is a few queries out of step with itself is fine for a
/// once-a-minute summary.
const Counters = struct {
    block: std.atomic.Value(u64) = .init(0),
    hit: std.atomic.Value(u64) = .init(0),
    forward: std.atomic.Value(u64) = .init(0),
    reject: std.atomic.Value(u64) = .init(0),
    timeout: std.atomic.Value(u64) = .init(0),
    servfail: std.atomic.Value(u64) = .init(0),
    /// Datagrams dropped without a reply and without a record: QR=1, or a
    /// question too malformed to parse. Not queries, but worth seeing.
    dropped: std.atomic.Value(u64) = .init(0),
    /// Forwards refused at the pending cap (P1.5).
    shed: std.atomic.Value(u64) = .init(0),
};

var counters: Counters = .{};

fn count(v: Verdict) void {
    const c = switch (v) {
        .block => &counters.block,
        .hit => &counters.hit,
        .forward => &counters.forward,
        .reject => &counters.reject,
        .timeout => &counters.timeout,
        .servfail => &counters.servfail,
    };
    _ = c.fetchAdd(1, .monotonic);
}

/// A datagram that got neither a reply nor a record.
pub fn countDropped() void {
    _ = counters.dropped.fetchAdd(1, .monotonic);
}

/// A forward refused at the pending cap.
pub fn countShed() void {
    _ = counters.shed.fetchAdd(1, .monotonic);
}

pub const Snapshot = struct {
    block: u64,
    hit: u64,
    forward: u64,
    reject: u64,
    timeout: u64,
    servfail: u64,
    dropped: u64,
    shed: u64,

    /// Queries that got a record: everything but `dropped` and `shed`.
    pub fn queries(self: Snapshot) u64 {
        return self.block + self.hit + self.forward + self.reject + self.timeout + self.servfail;
    }

    pub fn isEmpty(self: Snapshot) bool {
        return self.queries() + self.dropped + self.shed == 0;
    }
};

/// Returns the counts since the last call, and resets them.
pub fn take() Snapshot {
    return .{
        .block = counters.block.swap(0, .monotonic),
        .hit = counters.hit.swap(0, .monotonic),
        .forward = counters.forward.swap(0, .monotonic),
        .reject = counters.reject.swap(0, .monotonic),
        .timeout = counters.timeout.swap(0, .monotonic),
        .servfail = counters.servfail.swap(0, .monotonic),
        .dropped = counters.dropped.swap(0, .monotonic),
        .shed = counters.shed.swap(0, .monotonic),
    };
}

/// Writes `s` as one `info` event in the `stats` scope. Skipped when nothing
/// happened, so an idle resolver does not log a line of zeros every minute.
pub fn logSnapshot(s: Snapshot, window_s: u32) void {
    if (s.isEmpty()) return;
    obs_log.event(.info, .stats, .{
        .window_s = window_s,
        .queries = s.queries(),
        .block = s.block,
        .hit = s.hit,
        .forward = s.forward,
        .reject = s.reject,
        .timeout = s.timeout,
        .servfail = s.servfail,
        .dropped = s.dropped,
        .shed = s.shed,
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────

const testing = std.testing;

test "each verdict increments its own counter, and take resets them" {
    _ = take();
    count(.block);
    count(.block);
    count(.hit);
    count(.forward);
    count(.reject);
    count(.timeout);
    count(.servfail);
    countDropped();
    countShed();

    const s = take();
    try testing.expectEqual(@as(u64, 2), s.block);
    try testing.expectEqual(@as(u64, 1), s.hit);
    try testing.expectEqual(@as(u64, 1), s.forward);
    try testing.expectEqual(@as(u64, 1), s.reject);
    try testing.expectEqual(@as(u64, 1), s.timeout);
    try testing.expectEqual(@as(u64, 1), s.servfail);
    try testing.expectEqual(@as(u64, 1), s.dropped);
    try testing.expectEqual(@as(u64, 1), s.shed);
    // Dropped and shed datagrams are not queries.
    try testing.expectEqual(@as(u64, 7), s.queries());

    try testing.expect(take().isEmpty());
}

test "latency is microseconds and never negative" {
    try testing.expectEqual(@as(i64, 41), latencyUs(1_000_000, 1_041_999));
    try testing.expectEqual(@as(i64, 0), latencyUs(5, 5));
    try testing.expectEqual(@as(i64, 0), latencyUs(10, 3));
}

test "rcodeOf reads the low nibble of the flags" {
    try testing.expectEqual(@as(u4, 3), rcodeOf(&.{ 0x12, 0x34, 0x81, 0x83 }));
    try testing.expectEqual(@as(u4, 0), rcodeOf(&.{ 0x12, 0x34, 0x81, 0x80 }));
    try testing.expectEqual(@as(u4, 0), rcodeOf(&.{0x12}));
}

test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Snapshot);
}
