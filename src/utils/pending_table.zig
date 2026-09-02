const std = @import("std");

pub const PendingQuery = struct {
    client_id: u16,
    client_addr: std.Io.net.IpAddress,

    /// Seeded hash of the query's question section, and its length on the wire.
    ///
    /// Together these let the dispatcher confirm a reply answers *this* query
    /// before it is forwarded: the upstream echoes the question verbatim, so the
    /// bytes at the same offset in the reply must hash identically. Storing the
    /// length as well means the reply path never re-parses — it slices a known
    /// range and hashes it, so a malformed or hostile question in a forged reply
    /// gets no parser to attack.
    ///
    /// A hash rather than the bytes: 10 bytes per in-flight query instead of up
    /// to 259, and matching is all we need. See `hashQuestion` for why the seed
    /// is per-process.
    question_hash: u64,
    question_len: u16,
    /// Nanoseconds on the **`.boot` clock** (`std.Io.Timestamp.now(io, .boot)`),
    /// the same clock and unit `sweepExpiredQueries` compares against.
    ///
    /// Two things this must not be. Not milliseconds: a unit mismatch here is
    /// exactly what bug B1 was, and it meant nothing ever expired. And not the
    /// `.real` wall clock, which is settable — an NTP step backwards would let
    /// entries outlive their deadline, a step forwards would evict every
    /// in-flight query at once. `.boot` is monotonic and counts time the machine
    /// spends suspended, so a query outstanding across a laptop sleep is
    /// correctly treated as long dead.
    expires_at: i64,
};

/// Hashes a DNS message's question section — the `question_len` bytes starting
/// at offset 12 — returning null if the message is too short to hold them.
///
/// `seed` is drawn once per process rather than fixed at zero. An off-path
/// attacker forging a reply must already guess the 16-bit proxy ID and spoof the
/// upstream's source address; a fixed seed would additionally let them
/// precompute a colliding question offline, and a random one costs nothing.
pub fn hashQuestion(seed: u64, msg: []const u8, question_len: u16) ?u64 {
    const end = 12 + @as(usize, question_len);
    if (msg.len < end) return null;
    return std.hash.Wyhash.hash(seed, msg[12..end]);
}

/// PendingTable is responsible for holding DNS queries that have been sent to upstream resolver.
/// It serves as a source of truth for DNS queries inflight.
/// It serves for DNS packet spoofing.
pub const PendingTable = struct {
    map: std.AutoHashMap(u16, PendingQuery),
    mutex: std.Io.Mutex,
    rng: std.Random.DefaultPrng,
    gpa: std.mem.Allocator,
    io: std.Io,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, seed: u64) PendingTable {
        return PendingTable{
            .map = std.AutoHashMap(u16, PendingQuery).init(gpa),
            .mutex = std.Io.Mutex.init,
            .rng = std.Random.DefaultPrng.init(seed),
            .gpa = gpa,
            .io = io,
        };
    }

    pub fn deinit(self: *PendingTable) void {
        self.map.deinit();
    }

    /// Appends a query to the pending table and generate a random u16 integer value
    /// as the proxy_id. Provides mechanism to retry if deduping proxy_id.
    pub fn appendQuery(self: *PendingTable, pending_query: PendingQuery) !u16 {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        if (self.map.count() > std.math.maxInt(u16)) return error.IdSpaceExhausted;

        var attempts: u16 = 0;
        while (attempts < 16) : (attempts += 1) {
            const proxy_id: u16 = self.rng.random().int(u16);
            const entry = try self.map.getOrPut(proxy_id);
            if (!entry.found_existing) {
                entry.value_ptr.* = pending_query;
                return proxy_id;
            }
        }

        // Rare: keep scanning linearly
        const base = self.rng.random().int(u16);
        var id: u32 = 0;
        while (id <= std.math.maxInt(u16)) : (id += 1) {
            const proxy_id: u16 = base +% @as(u16, @truncate(id));
            const entry = try self.map.getOrPut(proxy_id);
            if (!entry.found_existing) {
                entry.value_ptr.* = pending_query;
                return proxy_id;
            }
        }

        return error.IdSpaceExhausted;
    }

    /// Looks up an entry **without** removing it.
    ///
    /// The dispatcher needs this to validate a reply before consuming the entry.
    /// If it used `complete` first, a forged packet that guessed the proxy ID
    /// would delete the pending query as a side effect of being rejected —
    /// denying service to the real reply that arrives moments later, and leaving
    /// nothing for the sweeper to SERVFAIL. Peek, verify, then complete.
    pub fn peek(self: *PendingTable, proxy_id: u16) ?PendingQuery {
        self.mutex.lock(self.io) catch {
            std.log.err("Failed to acquire lock while peeking pending query...", .{});
            return null;
        };
        defer self.mutex.unlock(self.io);

        return self.map.get(proxy_id);
    }

    /// Attempts to acquire a mutex then fetchRemove a entry by proxy_id
    pub fn complete(self: *PendingTable, proxy_id: u16) ?PendingQuery {
        self.mutex.lock(self.io) catch {
            std.log.err("Failed to acquire lock while completing pending query...", .{});
            return null;
        };
        defer self.mutex.unlock(self.io);

        if (self.map.fetchRemove(proxy_id)) |query| {
            return query.value;
        }

        return null;
    }

    /// Removes every entry past its deadline, appending each evicted
    /// `PendingQuery` to `evicted` so the caller can answer the clients whose
    /// queries were abandoned.
    ///
    /// The table deliberately does **not** send anything itself. It holds no
    /// socket, and keeping it that way is what lets the whole suite below run
    /// without a live one — the reporting/sending split is the same shape as
    /// pulling logic out of `handleQuery` to make it testable.
    ///
    /// `evicted` must use the same allocator the table was built with. It is
    /// appended to, never cleared, so the caller controls reuse:
    /// `clearRetainingCapacity` between sweeps avoids reallocating every second.
    pub fn sweepExpiredQueries(self: *PendingTable, evicted: *std.ArrayList(PendingQuery)) void {
        self.mutex.lock(self.io) catch {
            std.log.err("Failed to acquire lock on sweeper loop...", .{});
            return;
        };
        defer self.mutex.unlock(self.io);

        const now: i64 = @intCast(std.Io.Timestamp.now(self.io, std.Io.Clock.boot).nanoseconds);
        var dead_queries = std.ArrayList(u16).initCapacity(self.gpa, 64) catch {
            std.log.err("Failed to initialize dead query array list...", .{});
            return;
        };
        defer dead_queries.deinit(self.gpa);

        var pending_iter = self.map.iterator();
        while (pending_iter.next()) |entry| {
            if (entry.value_ptr.expires_at <= now) {
                dead_queries.append(self.gpa, entry.key_ptr.*) catch break;
            }
        }
        for (dead_queries.items) |id| {
            const kv = self.map.fetchRemove(id) orelse continue;
            // If the report can't be recorded the entry is still evicted.
            // Holding a slot open because we failed to allocate a notification
            // would turn a transient OOM into a permanently leaked proxy ID.
            evicted.append(self.gpa, kv.value) catch {};
        }
    }
};

const testing = std.testing;

/// A `PendingQuery` expiring `offset_ns` from now — negative for already-expired.
/// Deliberately reads the *same clock and unit* the sweeper does: if the two
/// ever drift apart — different unit (bug B1) or different clock — the sweep
/// tests below fail instead of the table quietly never expiring anything.
fn queryExpiringIn(io: std.Io, client_id: u16, offset_ns: i64) PendingQuery {
    const now: i64 = @intCast(std.Io.Timestamp.now(io, std.Io.Clock.boot).nanoseconds);
    return .{
        .client_id = client_id,
        .client_addr = std.Io.net.IpAddress.parse("127.0.0.1", 5354) catch unreachable,
        .question_hash = 0,
        .question_len = 0,
        .expires_at = now + offset_ns,
    };
}

/// A 12-byte header followed by `question` — the shape `hashQuestion` slices.
fn msgWithQuestion(comptime question: []const u8) [12 + question.len]u8 {
    var msg: [12 + question.len]u8 = @splat(0);
    @memcpy(msg[12..], question);
    return msg;
}

test "hashQuestion matches only on identical question bytes" {
    const a = msgWithQuestion("\x03ads\x07example\x03com\x00\x00\x01\x00\x01");
    const qlen: u16 = a.len - 12;

    // Same bytes, same seed -> same hash. This is the whole mechanism: the
    // upstream echoes our question, so a genuine reply hashes identically.
    try testing.expectEqual(
        hashQuestion(99, &a, qlen).?,
        hashQuestion(99, &a, qlen).?,
    );

    // A different question must not match — this is the forged-reply case.
    const b = msgWithQuestion("\x03ads\x07example\x03net\x00\x00\x01\x00\x01");
    try testing.expect(hashQuestion(99, &a, qlen).? != hashQuestion(99, &b, qlen).?);

    // Trailing answer records must not disturb the hash: only the question
    // range is covered, so a real reply (question + answers) still matches.
    var with_answers: [a.len + 32]u8 = @splat(0xAB);
    @memcpy(with_answers[0..a.len], &a);
    try testing.expectEqual(hashQuestion(99, &a, qlen).?, hashQuestion(99, &with_answers, qlen).?);

    // Per-process seed: the same question under a different seed differs, so a
    // collision cannot be precomputed offline.
    try testing.expect(hashQuestion(1, &a, qlen).? != hashQuestion(2, &a, qlen).?);

    // Too short to hold the claimed question -> null, never a bogus match. A
    // forged reply truncated mid-question hits this.
    try testing.expect(hashQuestion(99, &a, qlen + 1) == null);
    try testing.expect(hashQuestion(99, a[0..12], qlen) == null);
}

test "appendQuery then complete round trips, and complete is idempotent" {
    var table = PendingTable.init(testing.allocator, testing.io, 0x5EED);
    defer table.deinit();

    const proxy_id = try table.appendQuery(queryExpiringIn(testing.io, 0xABCD, std.time.ns_per_s));
    try testing.expectEqual(@as(u32, 1), table.map.count());

    // The proxy ID is what goes on the wire; the client ID is what must come
    // back out, or the dispatcher restores the wrong ID onto the reply.
    const entry = table.complete(proxy_id).?;
    try testing.expectEqual(@as(u16, 0xABCD), entry.client_id);
    try testing.expectEqual(@as(u32, 0), table.map.count());

    // Completing twice must not resurrect or double-report the entry: the
    // upstream can legitimately send a duplicate reply.
    try testing.expect(table.complete(proxy_id) == null);
    try testing.expect(table.complete(0xFFFF) == null);
}

test "sweep removes expired entries and leaves live ones (B1 regression)" {
    var table = PendingTable.init(testing.allocator, testing.io, 1);
    defer table.deinit();

    // One entry a second past its deadline, one a full hour out.
    const dead = try table.appendQuery(queryExpiringIn(testing.io, 1, -std.time.ns_per_s));
    const live = try table.appendQuery(queryExpiringIn(testing.io, 2, 3600 * std.time.ns_per_s));
    try testing.expectEqual(@as(u32, 2), table.map.count());

    var evicted: std.ArrayList(PendingQuery) = .empty;
    defer evicted.deinit(testing.allocator);
    table.sweepExpiredQueries(&evicted);

    // The sweeper must hand back what it evicted, or the caller cannot SERVFAIL
    // the abandoned client — the entry would vanish as silently as before.
    try testing.expectEqual(@as(usize, 1), evicted.items.len);
    try testing.expectEqual(@as(u16, 1), evicted.items[0].client_id);

    // This is the assertion B1 failed. The writer stored nanoseconds and the
    // sweeper compared milliseconds, so `expires_at <= now` was never true and
    // *nothing* was ever swept — the table just filled until every query
    // errored. If the two sides ever drift apart in unit again, `dead` survives
    // and this fails.
    try testing.expectEqual(@as(u32, 1), table.map.count());
    try testing.expect(table.complete(dead) == null);
    try testing.expect(table.complete(live) != null);
}

test "sweep is a no-op when nothing has expired" {
    var table = PendingTable.init(testing.allocator, testing.io, 2);
    defer table.deinit();

    for (0..8) |i| {
        _ = try table.appendQuery(queryExpiringIn(testing.io, @intCast(i), 3600 * std.time.ns_per_s));
    }
    var evicted: std.ArrayList(PendingQuery) = .empty;
    defer evicted.deinit(testing.allocator);
    table.sweepExpiredQueries(&evicted);

    try testing.expectEqual(@as(u32, 8), table.map.count());
    // Nothing expired, so nothing to notify: a spurious SERVFAIL to a client
    // whose query is still in flight would be worse than staying quiet.
    try testing.expectEqual(@as(usize, 0), evicted.items.len);
}

test "appendQuery hands out distinct proxy IDs" {
    var table = PendingTable.init(testing.allocator, testing.io, 0xC0FFEE);
    defer table.deinit();

    // A reused proxy ID would silently overwrite an in-flight query, so the
    // collision retry has to actually work. 4096 draws from a 16-bit space is
    // enough for the birthday problem to make repeats near-certain if the
    // retry were broken.
    var seen = std.AutoHashMap(u16, void).init(testing.allocator);
    defer seen.deinit();

    for (0..4096) |i| {
        const id = try table.appendQuery(queryExpiringIn(testing.io, @intCast(i), std.time.ns_per_s));
        try testing.expect(!seen.contains(id));
        try seen.put(id, {});
    }
    try testing.expectEqual(@as(u32, 4096), table.map.count());
}

test "appendQuery fails cleanly once the 16-bit ID space is full" {
    var table = PendingTable.init(testing.allocator, testing.io, 7);
    defer table.deinit();

    // Fill every one of the 65,536 possible proxy IDs. The tail of this loop
    // exercises the linear-scan fallback with only a handful of free slots left.
    const capacity = @as(usize, std.math.maxInt(u16)) + 1;
    for (0..capacity) |i| {
        _ = try table.appendQuery(queryExpiringIn(testing.io, @truncate(i), 3600 * std.time.ns_per_s));
    }
    try testing.expectEqual(@as(u32, capacity), table.map.count());

    // Full table must return an error rather than hang, spin, or overwrite a
    // live entry. Note this pins the *behavior*, not the guard: the old
    // `>= maxInt(u32)` guard (bug B5) also ended up here, just after a futile
    // 65k-entry scan under the mutex. What B5 cost was time, which a test
    // cannot assert on without being flaky.
    try testing.expectError(error.IdSpaceExhausted, table.appendQuery(
        queryExpiringIn(testing.io, 0, 3600 * std.time.ns_per_s),
    ));
    try testing.expectEqual(@as(u32, capacity), table.map.count());

    // And the table is still usable once something frees up.
    const freed = table.complete(0x1234);
    try testing.expect(freed != null);
    _ = try table.appendQuery(queryExpiringIn(testing.io, 0, 3600 * std.time.ns_per_s));
}

test "peek does not consume the entry" {
    var table = PendingTable.init(testing.allocator, testing.io, 3);
    defer table.deinit();

    const id = try table.appendQuery(queryExpiringIn(testing.io, 0x4242, std.time.ns_per_s));

    // Repeated peeks must all succeed. The dispatcher rejects a forged reply by
    // peeking and walking away; if that removed the entry, one guessed proxy ID
    // would be enough to kill a legitimate in-flight query.
    try testing.expectEqual(@as(u16, 0x4242), table.peek(id).?.client_id);
    try testing.expectEqual(@as(u16, 0x4242), table.peek(id).?.client_id);
    try testing.expectEqual(@as(u32, 1), table.map.count());

    // And the real reply can still complete it afterwards.
    try testing.expectEqual(@as(u16, 0x4242), table.complete(id).?.client_id);
    try testing.expect(table.peek(id) == null);
}
