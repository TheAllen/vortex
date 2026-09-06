//! TTL-aware response cache (P3.3): the key and entry types, plus the hashing
//! context the map needs.
//!
//! Pure so far: no allocator, no `Io`, no map. Everything here is a value or a
//! function over one, which is the same shape `header.zig`, `name_reader.zig`
//! and `resource_record.zig` were built in, and for the same reason — the parts
//! that decide can be tested exhaustively before the parts that do exist.

const std = @import("std");

const name_reader = @import("name_reader.zig");
const Name = name_reader.Name;
const Question = @import("question.zig").Question;
const Header = @import("header.zig").Header;
const resource_record = @import("resource_record.zig");

/// TYPE 41. Excluded from every TTL computation below, because OPT reuses the
/// TTL field for extended-RCODE, version and the DO bit (RFC 6891 §6.1.3) — it
/// is a bit-field, not a duration. Folding it into a minimum yields whatever
/// the flags happened to encode, and the common `ttl = 0` case would pin every
/// cache entry at zero.
const opt_type: u16 = 41;
const soa_type: u16 = 6;

/// RFC 2181 §8: the TTL is an unsigned 31-bit value; anything with the top bit
/// set must be treated as zero rather than as a ~68-year cache lifetime.
const max_ttl: u32 = std.math.maxInt(i32);

fn sanitizeTtl(ttl: u32) u32 {
    return if (ttl > max_ttl) 0 else ttl;
}

/// What a cached response is keyed on: RFC 1034 §3.7's triple.
///
/// **Not a tuple.** `qtype` and `qclass` are both `u16` and adjacent, so a
/// tuple's `key[1]`/`key[2]` lets a transposition compile, hash cleanly, and
/// simply never hit — the same shape of defect as a byte-reversed SERIAL, which
/// is why that one is pinned by literal-byte assertions elsewhere. Names cost
/// nothing and make the transposition unwriteable.
pub const CacheKey = struct {
    /// Inline, not a slice: the key owns its bytes, so there is no dupe on
    /// insert and nothing to free on evict. `Name`'s 253-byte cap is a hard
    /// protocol bound (`name_reader.max_text_len`), so this cannot grow, and
    /// the whole key stays a trivially copyable value.
    ///
    /// The cost is real and worth knowing: `std.HashMap` stores keys by value
    /// across `capacity` slots, not `len`, so **empty slots cost a full key
    /// each**. At 80% max load, 10k entries reserves 16,384 slots ≈ 4.1 MB
    /// whether or not the cache is full. Fine at home-sinkhole scale; revisit
    /// above ~50k entries, where it is the largest single allocation here.
    qname: Name,
    qtype: u16,
    qclass: u16,

    /// The one place a key is made, so canonicalization cannot diverge between
    /// the lookup in `handleQuery` and the insert in `dispatcherLoop`.
    ///
    /// Correctness rests on `parseQuestion` having lowercased the name:
    /// `name_reader` canonicalizes while decoding, so `Question.qname` is
    /// already the case-insensitive form RFC 4343 requires. If that ever
    /// regresses, the symptom is not a blocklist miss but a *cache* that gives
    /// `Ads.Example.COM` its own entry — pinned by a test below.
    pub fn fromQuestion(q: *const Question) CacheKey {
        return .{ .qname = q.qname, .qtype = q.qtype, .qclass = q.qclass };
    }

    /// Hashing and equality for `std.HashMap`.
    ///
    /// **`AutoContext` cannot be used here and the failure is silent.** `Name`
    /// is `buf: [253]u8 = undefined` plus `len`, so structural hashing walks
    /// all 253 bytes including the uninitialized tail past `len`. Two identical
    /// questions parsed from two different datagrams inherit different garbage
    /// and become different keys: a cache with a 0% hit rate that passes any
    /// test which stores and reads back the same `CacheKey` value. Hash
    /// `slice()`, never `buf`.
    ///
    /// Stateful, carrying a per-process seed. `hashQuestion` seeds for a
    /// different reason — there a collision forges a reply, so the seed blocks
    /// offline precomputation. Here keys are compared in full on `eql`, so a
    /// collision costs only a probe; the seed is against hash flooding, an
    /// attacker choosing qnames that pile into one bucket. Same mechanism,
    /// different threat, and worth not conflating.
    pub const Context = struct {
        seed: u64,

        pub fn hash(self: Context, k: CacheKey) u64 {
            var h = std.hash.Wyhash.init(self.seed);
            // Length first: without it "ab" + qtype could hash-alias a longer
            // name whose tail happens to match the type bytes. Only a probe
            // cost, since `eql` compares in full, but it is one byte to avoid.
            h.update(&[_]u8{k.qname.len});
            h.update(k.qname.slice());
            // Native endianness is fine — this never leaves the process.
            h.update(std.mem.asBytes(&k.qtype));
            h.update(std.mem.asBytes(&k.qclass));
            return h.final();
        }

        /// Integers first: two `u16` compares reject almost every non-match
        /// before the `memcmp` is reached.
        pub fn eql(_: Context, a: CacheKey, b: CacheKey) bool {
            return a.qtype == b.qtype and
                a.qclass == b.qclass and
                std.mem.eql(u8, a.qname.slice(), b.qname.slice());
        }
    };
};

/// A cached upstream response.
pub const CacheEntry = struct {
    /// The upstream datagram exactly as received, sized to its actual length.
    /// Owned by the cache; freed on evict, on expiry, and on being replaced by
    /// a fresher response.
    ///
    /// **Never mutated in place.** Serving a hit rewrites the transaction ID
    /// and ages every TTL, both of which are per-request; doing that here would
    /// corrupt the entry for the next reader and race two handlers on the
    /// thread-pool-backed `Io`. Copy into the handler's send buffer, then
    /// mutate the copy. `[]u8` rather than `[]const u8` only because the
    /// allocator needs it back.
    bytes: []u8,

    /// Nanoseconds on the **`.boot` clock**, the same clock and unit as
    /// `PendingQuery.inserted_at`'s sibling `expires_at`. Not milliseconds —
    /// that unit mismatch was bug B1, and it meant nothing ever expired. Not
    /// `.real`, which is settable: an NTP step would either strand entries past
    /// their TTL or evict the whole cache at once.
    inserted_at: i64,

    /// Also `.boot` nanoseconds. Derived at insert from the minimum TTL across
    /// the answer and authority records — **excluding OPT**, whose TTL field
    /// carries extended-RCODE/version/DO rather than a duration
    /// (`dns-message-format.md`). Negative answers take RFC 2308's rule
    /// instead: `min(SOA.TTL, SOA.MINIMUM)`.
    ///
    /// Not redundant with `inserted_at`: that one ages the TTLs *inside*
    /// `bytes` on the way out, this one decides whether the entry may be served
    /// at all. Both are needed, and they answer different questions.
    expires_at: i64,

    pub fn isExpired(self: *const CacheEntry, now_ns: i64) bool {
        return now_ns >= self.expires_at;
    }

    /// How long this entry has been held, in whole seconds — the amount every
    /// TTL in the served copy must be decremented by.
    ///
    /// Serving a reply with its TTLs untouched is the classic forwarder bug: a
    /// 300-second record handed back 250 seconds later gets cached by the
    /// client for a further 300, and every hit re-extends it (RFC 2181 §5.2).
    ///
    /// Saturates rather than wrapping. `.boot` is monotonic so the clamp at 0
    /// is unreachable, and an entry old enough to overflow a `u32` of seconds
    /// is long expired — but a cast that silently wrapped would turn "very old"
    /// into "brand new", which is the one direction that must not happen.
    pub fn ageSeconds(self: *const CacheEntry, now_ns: i64) u32 {
        const elapsed = now_ns - self.inserted_at;
        if (elapsed <= 0) return 0;
        const secs = @divFloor(elapsed, std.time.ns_per_s);
        return std.math.cast(u32, secs) orelse std.math.maxInt(u32);
    }
};

/// How long a reply may be cached, in seconds, or null if it may not be.
///
/// Two rules, because a positive and a negative answer are cached for different
/// reasons and by different fields:
///
///   * **Positive** — the minimum TTL across the answer and authority sections.
///     The minimum rather than the first: serving any record past its own TTL
///     is the thing a cache exists not to do.
///   * **Negative** (no answer records — NXDOMAIN or NODATA) — RFC 2308 §5's
///     rule instead: `min(SOA.TTL, SOA.MINIMUM)` from the authority section.
///     Without this branch a negative reply computes a minimum over an empty
///     set, and the obvious fallbacks are both wrong: caching forever, or not
///     caching the answers that most deserve it.
///
/// Null means "do not cache" — no usable record was found. A zero return is
/// different and deliberate: upstream said this answer is not to be reused, and
/// the caller should honour that rather than treat it as absent.
///
/// Pure: a byte slice and a parsed header in, a number out. Errors come from
/// the record walk and mean the reply was malformed, which is also a reason not
/// to cache it.
pub fn replyTtlSeconds(
    msg: []const u8,
    records_start: usize,
    header: Header,
) !?u32 {
    var it = resource_record.ResourceRecordIter.init(msg, records_start, header);

    var min_positive: ?u32 = null;
    var soa_ttl: ?u32 = null;

    while (try it.next()) |rec| {
        if (rec.type == opt_type) continue;

        switch (rec.section) {
            .answer, .authority => {
                const ttl = sanitizeTtl(rec.ttl);
                min_positive = if (min_positive) |m| @min(m, ttl) else ttl;
            },
            // Hints, not the answer. Their TTLs must not shorten the entry.
            .additional => {},
        }

        if (rec.section == .authority and rec.type == soa_type) {
            // MINIMUM is the last of five u32s, so it is the final four bytes
            // of RDATA whatever MNAME and RNAME cost — which is why this reads
            // from the end rather than parsing two names to find it.
            if (rec.rdata.len >= 20) {
                const minimum = std.mem.readInt(u32, rec.rdata[rec.rdata.len - 4 ..][0..4], .big);
                soa_ttl = @min(sanitizeTtl(rec.ttl), sanitizeTtl(minimum));
            }
        }
    }

    if (header.answer_count > 0) return min_positive;
    return soa_ttl;
}

/// Subtracts `age_secs` from every TTL in `msg`, saturating at zero.
///
/// **Call this on the copy handed to the client, never on the cached entry.**
/// Relaying a cached reply with its TTLs untouched means a record with a
/// 300-second TTL served 250 seconds later gets cached downstream for a further
/// 300 — and every hit re-extends it, so a popular name can outlive its TTL
/// indefinitely (RFC 2181 §5.2).
///
/// OPT is skipped: decrementing it would corrupt the extended-RCODE and DO bits
/// into whatever the subtraction produced.
pub fn ageTtlsInPlace(
    msg: []u8,
    records_start: usize,
    header: Header,
    age_secs: u32,
) !void {
    var it = resource_record.ResourceRecordIter.init(msg, records_start, header);
    while (try it.next()) |rec| {
        if (rec.type == opt_type) continue;
        const remaining = sanitizeTtl(rec.ttl) -| age_secs;
        std.mem.writeInt(u32, msg[rec.ttl_offset..][0..4], remaining, .big);
    }
}

/// Whether a reply may be stored at all.
///
/// One place, so `dispatcherLoop` carries a call rather than four conditions —
/// and so each rule can be pinned by a test that needs no socket.
///
///   * **TC=1** — the records are known-incomplete. Caching a truncated answer
///     pins a partial result for the whole TTL.
///   * **QDCOUNT != 1** — the record walk starts at `12 + question_len`, which
///     is only where records begin given exactly one question. Caching what a
///     walk from the wrong offset produced is the silent desynchronization the
///     P3.2 design exists to avoid. Cheap here, load-bearing now that the
///     walk's output decides what gets stored.
///   * **rcode** — only NOERROR and NXDOMAIN describe the name. SERVFAIL and
///     REFUSED describe the *server*, and caching them turns one upstream blip
///     into minutes of failure for a name that resolves fine.
///   * **ttl** — null means nothing usable was found; zero means upstream
///     explicitly said do not reuse this. Both are refusals.
pub fn isCacheable(header: Header, truncated: bool, ttl: ?u32) bool {
    if (truncated) return false;
    if (header.question_count != 1) return false;
    switch (header.rcode) {
        .no_error, .name_error => {},
        else => return false,
    }
    const secs = ttl orelse return false;
    return secs > 0;
}

/// Turns a copy of a cached reply into the datagram a client receives.
///
/// Operates **in place on the caller's copy**, which `Cache.get` has already
/// made. An earlier version took a source and a destination and copied again;
/// that is both a wasted memcpy on the hit path and, when a caller passes the
/// same buffer as both, an overlapping `@memcpy` — undefined behaviour that
/// happens to look fine in a test. Taking one mutable slice makes the aliasing
/// question impossible to get wrong.
///
/// Two edits: restore the client's transaction ID, then age every TTL by how
/// long the entry has been held. Neither can reach the stored entry, because
/// this never sees it.
pub fn finalizeServed(
    served: []u8,
    records_start: usize,
    client_id: u16,
    age_secs: u32,
) !void {
    if (served.len < 12) return error.Truncated;

    // The client is owed the ID it asked with, not the one the cache happens to
    // hold from whichever query first populated the entry.
    std.mem.writeInt(u16, served[0..2], client_id, .big);

    var header = Header{};
    header.parseHeader(served[0..12]);
    try ageTtlsInPlace(served, records_start, header, age_secs);
}

/// 80% by default. The dial behind the capacity arithmetic on `CacheKey.qname`:
/// lower wastes more slots at 258 bytes each, higher trades memory for probes.
const max_load = std.hash_map.default_max_load_percentage;

/// The map, its lock, and the two things an unmanaged map does not carry.
///
/// Same shape as `PendingTable` — and deliberately so, because it is the same
/// situation: mutated for the whole process lifetime by handler inserts and
/// sweeper evictions. The README's "blocklists need no mutex" argument does
/// **not** reach here; that one rests on a clean phase boundary (built before
/// any coroutine spawns, read-only after), which a cache never has.
///
/// The lock is not optional on a technicality: `std.process.Init` hands us a
/// `std.Io.Threaded` whose `async_limit` defaults to `cpu_count - 1`, so
/// handlers run on a real thread pool and two can be inside this map at the
/// same instant on different cores.
pub const Cache = struct {
    /// Unmanaged: every mutating method below already needs `gpa` in hand to
    /// free an entry's `bytes`, so a map that stored its own allocator would
    /// just be a second copy that can disagree with this one.
    map: std.HashMapUnmanaged(CacheKey, CacheEntry, CacheKey.Context, max_load),
    mutex: std.Io.Mutex,
    /// The seed lives here because an unmanaged map with a non-zero-sized
    /// context does not store one — hence the `*Context` call variants below.
    ctx: CacheKey.Context,
    gpa: std.mem.Allocator,
    io: std.Io,
    /// Hard cap on live entries. Without it this is an unbounded, network-fed
    /// allocation — the same class of exposure as P1.5, reached by a flood of
    /// distinct uncacheable names rather than by concurrent handlers.
    max_entries: usize,

    pub fn init(
        gpa: std.mem.Allocator,
        io: std.Io,
        seed: u64,
        max_entries: usize,
    ) Cache {
        return .{
            .map = .empty,
            .mutex = std.Io.Mutex.init,
            .ctx = .{ .seed = seed },
            .gpa = gpa,
            .io = io,
            .max_entries = max_entries,
        };
    }

    /// Frees every entry's `bytes` before the map's own storage.
    ///
    /// `map.deinit` alone releases the slot array and leaks every response in
    /// it — the one leak an unmanaged map makes easy to write, since the type
    /// gives no hint that the values own heap memory.
    pub fn deinit(self: *Cache) void {
        var it = self.map.valueIterator();
        while (it.next()) |entry| self.gpa.free(entry.bytes);
        self.map.deinit(self.gpa);
    }

    /// What a hit yields: how many bytes landed in `out`, and how stale they are.
    ///
    /// Both come back from one lock acquisition. Fetching the age in a second call
    /// would race the sweeper — the entry can be evicted between the two, leaving
    /// the caller to serve bytes it can no longer date.
    pub const Hit = struct {
        len: usize,
        age_secs: u32,
    };

    /// Copies a live response into `out`, returning its length and age.
    ///
    /// **A copy, not a borrow.** Returning `entry.bytes` would hand the caller a
    /// slice owned by the map, which the sweeper is free to evict and free the
    /// moment the lock is released. The caller then rewrites the transaction ID
    /// and ages the TTLs in what it was given — so a borrow would also be a
    /// write into the shared entry, corrupting it for every later reader.
    ///
    /// An expired entry reports a miss and is left for the sweeper: reclaiming
    /// it here would turn every lookup into a writer and serialize the read
    /// path for no gain.
    pub fn get(self: *Cache, key: CacheKey, now_ns: i64, out: []u8) ?Hit {
        self.mutex.lock(self.io) catch {
            std.log.err("cache: failed to acquire lock on get", .{});
            return null;
        };
        defer self.mutex.unlock(self.io);

        const entry = self.map.getContext(key, self.ctx) orelse return null;
        if (entry.isExpired(now_ns)) return null;
        // Treated as a miss rather than truncated: a short buffer is a caller
        // bug, and half a DNS message is worse than none.
        if (entry.bytes.len > out.len) return null;

        @memcpy(out[0..entry.bytes.len], entry.bytes);
        return .{ .len = entry.bytes.len, .age_secs = entry.ageSeconds(now_ns) };
    }

    /// Stores a copy of `bytes` under `key`, replacing any existing entry.
    ///
    /// Callers must not cache what they cannot serve: a reply with TC=1 (records
    /// are known-incomplete) or a locally synthesized blocked response (already
    /// free to build, and caching it would put a blocklist verdict behind a TTL
    /// that outlives a P2.2 refresh).
    pub fn put(
        self: *Cache,
        key: CacheKey,
        bytes: []const u8,
        inserted_at: i64,
        expires_at: i64,
    ) !void {
        // Duplicated before the lock: allocation is the slow part, and holding
        // the mutex across it would serialize every insert in the process.
        const owned = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(owned);

        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        const gop = try self.map.getOrPutContext(self.gpa, key, self.ctx);
        if (gop.found_existing) {
            // The old response is ours to release. Missing this is the leak the
            // unmanaged map invites: `value_ptr.*` is overwritten either way,
            // and nothing complains that the previous `bytes` is now orphaned.
            self.gpa.free(gop.value_ptr.bytes);
        } else if (self.map.count() > self.max_entries) {
            // Over cap, and this is a genuinely new key. Undo the insert rather
            // than evicting a live entry: with no recency data there is nothing
            // to justify a choice of victim, and refusing to cache is the
            // failure mode that cannot serve a stale answer. Revisit when
            // there is an eviction policy worth the name.
            _ = self.map.removeContext(key, self.ctx);
            self.gpa.free(owned);
            return;
        }

        gop.value_ptr.* = .{
            .bytes = owned,
            .inserted_at = inserted_at,
            .expires_at = expires_at,
        };
    }

    /// Removes and frees every entry past its deadline, returning the count.
    ///
    /// Reports a number rather than the evicted entries, unlike
    /// `sweepExpiredQueries`. That table hands back `PendingQuery` values so the
    /// caller can SERVFAIL the abandoned clients; here the only thing an evicted
    /// entry owns is a buffer this function just freed, so handing one back
    /// would be a use-after-free by construction.
    pub fn sweepExpired(self: *Cache, now_ns: i64) usize {
        self.mutex.lock(self.io) catch {
            std.log.err("cache: failed to acquire lock on sweep", .{});
            return 0;
        };
        defer self.mutex.unlock(self.io);

        // Two passes: removing during iteration invalidates the iterator. Keys
        // are 258 bytes each, so a sweep that finds 1,000 dead entries needs a
        // ~258 KB temporary — bounded by `max_entries`, and the reason the cap
        // is not merely about steady-state memory.
        var dead = std.ArrayList(CacheKey).initCapacity(self.gpa, 64) catch {
            std.log.err("cache: failed to allocate sweep list", .{});
            return 0;
        };
        defer dead.deinit(self.gpa);

        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired(now_ns)) {
                dead.append(self.gpa, entry.key_ptr.*) catch break;
            }
        }

        var removed: usize = 0;
        for (dead.items) |key| {
            const kv = self.map.fetchRemoveContext(key, self.ctx) orelse continue;
            self.gpa.free(kv.value.bytes);
            removed += 1;
        }
        return removed;
    }
};

const testing = std.testing;

/// Builds a key the way the datapath will: by parsing a real question section
/// rather than by assigning fields.
///
/// `tail` is then written over every byte of `Name.buf` past `len`, which is
/// the whole point. Those bytes are `undefined`, so what actually lands there
/// is whatever the stack held — and two calls from the same test reuse the same
/// stack slot, so left to itself the garbage is *identical* and any test
/// claiming to prove tail-independence proves nothing. Verified by mutation:
/// with `hash` reading `buf` instead of `slice()`, the tests below fail only
/// because this poisons deliberately rather than hoping.
fn keyFromWire(wire: []const u8, tail: u8) !CacheKey {
    var q = Question{};
    _ = try q.parseQuestion(wire, 12);
    var key = CacheKey.fromQuestion(&q);
    @memset(key.qname.buf[key.qname.len..], tail);
    return key;
}

/// `ads.example.com` A IN, with `fill` written over the whole buffer first so
/// each call leaves different garbage past `Name.len`.
fn questionWire(buf: []u8, fill: u8) []const u8 {
    @memset(buf, fill);
    // zig fmt: off
    const q = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // header
        3, 'a', 'd', 's',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0,    // root
        0, 1, // qtype = A
        0, 1, // qclass = IN
    };
    // zig fmt: on
    @memcpy(buf[0..q.len], &q);
    return buf[0..q.len];
}

test "two parses of the same question produce the same key" {
    // The regression that AutoHashMap would fail: identical names, different
    // uninitialized tails. Structural hashing walks all 253 bytes of `buf` and
    // makes these distinct keys — a cache that never hits, and never fails a
    // test that stores and reads back one value.
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    const a = try keyFromWire(questionWire(&buf_a, 0xAA), 0xAA);
    const b = try keyFromWire(questionWire(&buf_b, 0xBB), 0xBB);

    const ctx = CacheKey.Context{ .seed = 0x1234 };
    try testing.expect(ctx.eql(a, b));
    try testing.expectEqual(ctx.hash(a), ctx.hash(b));
}

test "qtype and qclass are not interchangeable" {
    // Pins the transposition a tuple would allow: same name, the two u16s
    // swapped. A and IN are both 1, so the values are built directly here —
    // `qtype=1, qclass=2` vs `qtype=2, qclass=1` is the discriminating pair.
    var buf: [64]u8 = undefined;
    var base = try keyFromWire(questionWire(&buf, 0), 0x11);

    base.qtype = 1;
    base.qclass = 2;
    var swapped = base;
    swapped.qtype = 2;
    swapped.qclass = 1;

    const ctx = CacheKey.Context{ .seed = 0 };
    try testing.expect(!ctx.eql(base, swapped));
    try testing.expect(ctx.hash(base) != ctx.hash(swapped));
}

test "qtype discriminates: same name, A vs AAAA are different entries" {
    var buf: [64]u8 = undefined;
    const a = try keyFromWire(questionWire(&buf, 0), 0x22);
    var aaaa = a;
    aaaa.qtype = 28;

    const ctx = CacheKey.Context{ .seed = 0 };
    try testing.expect(!ctx.eql(a, aaaa));
}

test "keys are case-insensitive, inherited from parseQuestion (C1)" {
    // Not a restatement of the C1 test: this asserts the *cache* consequence.
    // If lowercasing regresses, a mixed-case query gets its own cache entry
    // rather than merely missing the blocklist.
    // zig fmt: off
    const mixed = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, 'A', 'D', 'S',
        7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'C', 'O', 'M',
        0,
        0, 1,
        0, 1,
    };
    // zig fmt: on
    var buf: [64]u8 = undefined;
    const lower = try keyFromWire(questionWire(&buf, 0), 0x33);
    const upper = try keyFromWire(&mixed, 0xCC);

    const ctx = CacheKey.Context{ .seed = 0 };
    try testing.expectEqualStrings("ads.example.com", upper.qname.slice());
    try testing.expect(ctx.eql(lower, upper));
    try testing.expectEqual(ctx.hash(lower), ctx.hash(upper));
}

test "the seed actually reaches the hash" {
    // Cheap, but it is the only thing standing between a seeded context and one
    // that silently ignores its seed — which would look identical in every
    // other test here.
    var buf: [64]u8 = undefined;
    const k = try keyFromWire(questionWire(&buf, 0), 0x44);

    const a = CacheKey.Context{ .seed = 1 };
    const b = CacheKey.Context{ .seed = 2 };
    try testing.expect(a.hash(k) != b.hash(k));
}

test "the key survives a real HashMap round trip" {
    // Forces the context onto the actual map type. Without this the whole file
    // could be dead: an uncalled `pub fn` is never analysed, which is exactly
    // how `parseRdata` shipped without compiling.
    const load = std.hash_map.default_max_load_percentage;
    var map: std.HashMapUnmanaged(CacheKey, u32, CacheKey.Context, load) = .empty;
    defer map.deinit(testing.allocator);

    const ctx = CacheKey.Context{ .seed = 0xDEADBEEF };
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;

    try map.putContext(testing.allocator, try keyFromWire(questionWire(&buf_a, 0xAA), 0xAA), 7, ctx);
    // A *separately parsed* key must find it — the whole point of the context.
    const got = map.getContext(try keyFromWire(questionWire(&buf_b, 0xBB), 0xBB), ctx);

    try testing.expectEqual(@as(?u32, 7), got);
    try testing.expectEqual(@as(usize, 1), map.count());
}

test "isExpired is inclusive at the deadline" {
    const e = CacheEntry{ .bytes = &.{}, .inserted_at = 0, .expires_at = 1000 };
    try testing.expect(!e.isExpired(999));
    try testing.expect(e.isExpired(1000));
    try testing.expect(e.isExpired(1001));
}

test "ageSeconds floors, clamps at zero, and saturates instead of wrapping" {
    const e = CacheEntry{ .bytes = &.{}, .inserted_at = 0, .expires_at = 0 };

    try testing.expectEqual(@as(u32, 0), e.ageSeconds(0));
    // Floors: 1.9s of age is 1 whole second of TTL to subtract, not 2.
    try testing.expectEqual(@as(u32, 1), e.ageSeconds(1_900_000_000));
    try testing.expectEqual(@as(u32, 5), e.ageSeconds(5 * std.time.ns_per_s));
    // Unreachable on a monotonic clock, but must not underflow if it happens.
    try testing.expectEqual(@as(u32, 0), e.ageSeconds(-1));
    // Saturates rather than wrapping: "very old" must never become "brand new".
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), e.ageSeconds(std.math.maxInt(i64)));
}

// --- Cache: the map, the lock, and the allocations -------------------------
//
// Everything above is pure and needs no `Io`. Everything below does, because
// `std.Io.Mutex.lock` takes one — so these tests stand up a real
// `std.Io.Threaded`, the same implementation `std.process.Init` hands `main`.
//
// The assertions are only half of what these are for. They run under
// `testing.allocator`, which fails the test on a leak or a double free, and
// every ownership rule in `Cache` — dupe on insert, free the replaced entry,
// free the refused entry, free everything on deinit — is enforced by that and
// by nothing else in the type system.

/// A `Cache` on a real threaded `Io`. Caller must `deinit` both, cache first.
fn testCache(threaded: *std.Io.Threaded, max_entries: usize) Cache {
    threaded.* = std.Io.Threaded.init(testing.allocator, .{});
    return Cache.init(testing.allocator, threaded.io(), 0xC0FFEE, max_entries);
}

test "put then get returns the stored response" {
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x55);
    const reply = [_]u8{ 0xAB, 0xCD, 0x81, 0x80, 1, 2, 3 };

    try cache.put(key, &reply, 0, 1000);

    var out: [64]u8 = undefined;
    const hit = cache.get(key, 500, &out).?;
    try testing.expectEqual(reply.len, hit.len);
    try testing.expectEqualSlices(u8, &reply, out[0..hit.len]);
}

test "get is a copy, not a borrow" {
    // The property the datapath depends on: the caller rewrites the transaction
    // ID and ages TTLs in what it receives, so scribbling on `out` must not
    // reach the cached entry. A borrow would make the second get observe 0xFF.
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x55);
    const reply = [_]u8{ 0xAB, 0xCD, 0x81, 0x80 };
    try cache.put(key, &reply, 0, 1000);

    var out: [64]u8 = undefined;
    _ = cache.get(key, 0, &out).?;
    @memset(out[0..reply.len], 0xFF);

    var again: [64]u8 = undefined;
    _ = cache.get(key, 0, &again).?;
    try testing.expectEqualSlices(u8, &reply, again[0..reply.len]);
}

test "an expired entry reports a miss but is not reclaimed by get" {
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x55);
    try cache.put(key, &[_]u8{ 1, 2, 3 }, 0, 1000);

    var out: [64]u8 = undefined;
    try testing.expect(cache.get(key, 999, &out) != null);
    try testing.expect(cache.get(key, 1000, &out) == null);
    // Still resident: reclaiming on the read path is the sweeper's job.
    try testing.expectEqual(@as(usize, 1), cache.map.count());
}

test "get refuses to truncate into a short buffer" {
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x55);
    try cache.put(key, &[_]u8{ 1, 2, 3, 4, 5 }, 0, 1000);

    var too_small: [4]u8 = undefined;
    try testing.expect(cache.get(key, 0, &too_small) == null);
}

test "replacing an entry frees the response it displaced" {
    // Asserted by testing.allocator: without the free in `put`'s
    // found_existing branch this leaks the first reply and fails on deinit.
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x55);

    try cache.put(key, &[_]u8{ 1, 1, 1, 1 }, 0, 1000);
    try cache.put(key, &[_]u8{ 2, 2 }, 500, 2000);

    try testing.expectEqual(@as(usize, 1), cache.map.count());
    var out: [64]u8 = undefined;
    const hit = cache.get(key, 600, &out).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 2, 2 }, out[0..hit.len]);
}

test "max_entries refuses new keys and frees the response it refused" {
    // The other allocator-enforced path: the early return in `put` must free
    // `owned` before bailing, or every rejected insert leaks.
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 1);
    defer cache.deinit();
    defer threaded.deinit();

    var buf_a: [64]u8 = undefined;
    const first = try keyFromWire(questionWire(&buf_a, 0), 0x55);
    var second = first;
    second.qtype = 28; // same name, AAAA — a genuinely distinct key

    try cache.put(first, &[_]u8{ 1, 2, 3 }, 0, 1000);
    try cache.put(second, &[_]u8{ 4, 5, 6 }, 0, 1000);

    try testing.expectEqual(@as(usize, 1), cache.map.count());
    var out: [64]u8 = undefined;
    try testing.expect(cache.get(first, 0, &out) != null);
    try testing.expect(cache.get(second, 0, &out) == null);

    // An existing key is still updatable at the cap — the limit is on new
    // entries, not on refreshing what is already resident.
    try cache.put(first, &[_]u8{ 9, 9 }, 0, 2000);
    try testing.expectEqual(@as(usize, 2), cache.get(first, 0, &out).?.len);
}

test "sweepExpired removes exactly the dead entries and frees them" {
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const base = try keyFromWire(questionWire(&buf, 0), 0x55);

    var dead_a = base;
    dead_a.qtype = 1;
    var dead_b = base;
    dead_b.qtype = 2;
    var live = base;
    live.qtype = 28;

    try cache.put(dead_a, &[_]u8{ 1, 1 }, 0, 100);
    try cache.put(dead_b, &[_]u8{ 2, 2 }, 0, 200);
    try cache.put(live, &[_]u8{ 3, 3 }, 0, 5000);

    try testing.expectEqual(@as(usize, 2), cache.sweepExpired(1000));
    try testing.expectEqual(@as(usize, 1), cache.map.count());

    var out: [64]u8 = undefined;
    try testing.expect(cache.get(live, 1000, &out) != null);
    // Sweeping again finds nothing left to do.
    try testing.expectEqual(@as(usize, 0), cache.sweepExpired(1000));
}

test "deinit frees every resident response" {
    // No assertion to make beyond the allocator's: if `deinit` dropped the
    // value loop and only called `map.deinit`, this leaks three buffers.
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const base = try keyFromWire(questionWire(&buf, 0), 0x55);
    for ([_]u16{ 1, 2, 28 }) |qtype| {
        var k = base;
        k.qtype = qtype;
        try cache.put(k, &[_]u8{ 7, 7, 7, 7, 7, 7, 7, 7 }, 0, 1000);
    }
    cache.deinit();
}

test "refAllDecls: an uncalled pub decl is never analysed without this" {
    // Not ceremony. `parseRdata` in resource_record.zig shipped through four
    // merged PRs and CI without compiling, because nothing referenced it and
    // Zig analyses lazily — `zig build` does not catch it either. This is the
    // one line that turns that class of rot into a test-time compile error.
    testing.refAllDecls(@This());
    testing.refAllDecls(Cache);
    testing.refAllDecls(CacheKey);
    testing.refAllDecls(CacheEntry);
}

// --- TTL policy ------------------------------------------------------------
//
// Golden byte vectors, same reason as `blocked_response`'s: the input is a wire
// format, and a fixture built by calling the same helpers the code uses would
// agree with a byte-reversed field. These are written out by hand and the first
// test asserts the walk finds what the comments claim, so a miscounted offset
// fails loudly rather than quietly changing what the later tests mean.

/// `a.com A IN` -> two A records (TTL 300, then 100) and an EDNS0 OPT.
///
/// The OPT's TTL is **0**, which is what a plain EDNS0 reply carries (extended
/// rcode 0, version 0, DO clear). That is deliberate: it is below every real
/// TTL here, so a computation that forgets to exclude OPT returns 0 instead of
/// 100 and the test fails. An OPT with the DO bit set would be a large number
/// and would hide the bug.
// zig fmt: off
const positive_reply = [_]u8{
    0xAB, 0xCD,             // id
    0x81, 0x80,             // qr=1 rd=1 ra=1, rcode=0
    0, 1,                   // qdcount = 1
    0, 2,                   // ancount = 2
    0, 0,                   // nscount = 0
    0, 1,                   // arcount = 1  (the OPT)
    // question @12: "a.com" A IN
    1, 'a', 3, 'c', 'o', 'm', 0,
    0, 1,                   // qtype = A
    0, 1,                   // qclass = IN
    // answer 1 @23
    0xC0, 0x0C,             // name -> offset 12
    0, 1,                   // type = A
    0, 1,                   // class = IN
    0, 0, 1, 0x2C,          // ttl = 300
    0, 4,                   // rdlength
    1, 2, 3, 4,
    // answer 2 @39
    0xC0, 0x0C,
    0, 1,
    0, 1,
    0, 0, 0, 100,           // ttl = 100  <- the minimum
    0, 4,
    5, 6, 7, 8,
    // additional @55: OPT
    0,                      // root owner name
    0, 41,                  // type = OPT
    0x10, 0x00,             // class = 4096 udp payload size
    0, 0, 0, 0,             // "ttl" = extended rcode/version/flags, NOT a ttl
    0, 0,                   // rdlength = 0
};

/// `a.com A IN` -> NXDOMAIN with an SOA in authority. SOA TTL 7200, MINIMUM
/// 900, so `min(TTL, MINIMUM)` = 900 and picking the wrong one of the two is
/// visible.
const negative_reply = [_]u8{
    0xAB, 0xCD,
    0x81, 0x83,             // rcode = 3 (NXDOMAIN)
    0, 1,                   // qdcount
    0, 0,                   // ancount = 0  <- negative
    0, 1,                   // nscount = 1
    0, 0,                   // arcount
    1, 'a', 3, 'c', 'o', 'm', 0,
    0, 1,
    0, 1,
    // authority @23: SOA
    0xC0, 0x0C,
    0, 6,                   // type = SOA
    0, 1,                   // class = IN
    0, 0, 0x1C, 0x20,       // ttl = 7200
    0, 22,                  // rdlength
    0,                      // MNAME = root
    0,                      // RNAME = root
    0, 0, 0, 1,             // SERIAL
    0, 0, 0x0E, 0x10,       // REFRESH = 3600
    0, 0, 0x02, 0x58,       // RETRY   = 600
    0, 1, 0x51, 0x80,       // EXPIRE  = 86400
    0, 0, 0x03, 0x84,       // MINIMUM = 900  <- wins
};
// zig fmt: on

/// As `positive_reply`, but the OPT's TTL field carries the DO bit
/// (0x00008000) instead of zero.
///
/// Needed because `positive_reply`'s OPT TTL is 0, and `0 -| 60` is still 0 —
/// so a bug that decremented the OPT would be invisible there. This fixture is
/// the one that can tell.
// zig fmt: off
const positive_reply_do = blk: {
    var m = positive_reply;
    m[62] = 0x80; // OPT @55: name(1)+type(2)+class(2) => TTL at 60; DO is byte 62
    break :blk m;
};

/// An OPT record in the **authority** section, which is a protocol violation
/// (RFC 6891 §6.1.1 puts it in additional) and therefore exactly the hostile
/// shape the type guard exists for. Answer TTL 100, OPT "TTL" 0: without the
/// guard the minimum comes out 0 and every such reply is uncacheable.
const opt_in_authority = [_]u8{
    0xAB, 0xCD,
    0x81, 0x80,
    0, 1,                   // qdcount
    0, 1,                   // ancount = 1
    0, 1,                   // nscount = 1  <- the misplaced OPT
    0, 0,                   // arcount
    1, 'a', 3, 'c', 'o', 'm', 0,
    0, 1,
    0, 1,
    // answer @23
    0xC0, 0x0C,
    0, 1,
    0, 1,
    0, 0, 0, 100,           // ttl = 100
    0, 4,
    1, 2, 3, 4,
    // authority @39: an OPT where one may not be
    0,
    0, 41,
    0x10, 0x00,
    0, 0, 0, 0,             // not a duration
    0, 0,
};
// zig fmt: on

/// Answer TTL 100, plus a **non-OPT** glue A record in additional with TTL 10.
///
/// The only fixture that can tell whether the additional section is excluded:
/// everywhere else the sole additional record is an OPT, which the type guard
/// drops anyway. A hint's short TTL must not shorten the answer's lifetime.
// zig fmt: off
const glue_in_additional = [_]u8{
    0xAB, 0xCD,
    0x81, 0x80,
    0, 1,                   // qdcount
    0, 1,                   // ancount = 1
    0, 0,                   // nscount
    0, 1,                   // arcount = 1 (glue, not OPT)
    1, 'a', 3, 'c', 'o', 'm', 0,
    0, 1,
    0, 1,
    // answer @23
    0xC0, 0x0C,
    0, 1,
    0, 1,
    0, 0, 0, 100,           // ttl = 100  <- what governs the entry
    0, 4,
    1, 2, 3, 4,
    // additional @39: glue A record with a much shorter TTL
    0xC0, 0x0C,
    0, 1,
    0, 1,
    0, 0, 0, 10,            // ttl = 10   <- must NOT win
    0, 4,
    9, 9, 9, 9,
};
// zig fmt: on

/// Both fixtures put the question at 12 and it is 11 bytes wide, so the
/// record stream begins at 23. Named apart from the `records_start` parameter
/// above so the fixtures cannot shadow it.
const fixture_records = 23;

fn headerOf(msg: []const u8) Header {
    var h = Header{};
    h.parseHeader(msg[0..12]);
    return h;
}

test "the fixtures are shaped the way their comments claim" {
    // Guards every test below: a miscounted byte here would otherwise turn into
    // a confidently wrong assertion about TTL policy.
    var it = resource_record.ResourceRecordIter.init(
        &positive_reply,
        fixture_records,
        headerOf(&positive_reply),
    );
    const a1 = (try it.next()).?;
    const a2 = (try it.next()).?;
    const opt = (try it.next()).?;
    try testing.expectEqual(@as(?resource_record.ResourceRecord, null), try it.next());

    try testing.expectEqual(@as(u32, 300), a1.ttl);
    try testing.expectEqual(@as(u32, 100), a2.ttl);
    try testing.expectEqual(opt_type, opt.type);
    try testing.expectEqual(@as(u32, 0), opt.ttl);
    try testing.expectEqual(resource_record.Section.additional, opt.section);
    // The TTL offsets point at the bytes the comments say they do.
    try testing.expectEqual(@as(u32, 300), std.mem.readInt(u32, positive_reply[a1.ttl_offset..][0..4], .big));
    try testing.expectEqual(@as(u32, 100), std.mem.readInt(u32, positive_reply[a2.ttl_offset..][0..4], .big));
}

test "a positive reply caches for the minimum TTL" {
    const ttl = try replyTtlSeconds(&positive_reply, fixture_records, headerOf(&positive_reply));
    // 100, not 300: the minimum, not the first record.
    try testing.expectEqual(@as(?u32, 100), ttl);
}

test "an OPT in the authority section does not zero the TTL" {
    // What the `opt_type` guard in `replyTtlSeconds` is actually for. In a
    // well-formed reply the OPT sits in additional, which the section filter
    // already excludes — so this misplaced one is the only thing that can tell
    // whether the type guard exists. Verified by mutation: deleting the guard
    // fails here and nowhere else.
    const ttl = try replyTtlSeconds(&opt_in_authority, fixture_records, headerOf(&opt_in_authority));
    try testing.expectEqual(@as(?u32, 100), ttl);
}

test "a hint in the additional section does not shorten the entry" {
    // Additional records are hints, not the answer. Letting a 10-second glue
    // record govern a 100-second answer would evict useful entries early and
    // hand upstream a lever on our cache it should not have.
    const ttl = try replyTtlSeconds(&glue_in_additional, fixture_records, headerOf(&glue_in_additional));
    try testing.expectEqual(@as(?u32, 100), ttl);
}

test "a negative reply uses min(SOA.TTL, SOA.MINIMUM) per RFC 2308" {
    const ttl = try replyTtlSeconds(&negative_reply, fixture_records, headerOf(&negative_reply));
    // 900 (MINIMUM), not 7200 (the record TTL) and not null.
    try testing.expectEqual(@as(?u32, 900), ttl);
}

test "a reply with nothing to learn from is not cached" {
    // Header claims no records of any kind: no TTL, so no entry.
    var empty = [_]u8{ 0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0 } ++
        [_]u8{ 1, 'a', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1 };
    const ttl = try replyTtlSeconds(&empty, fixture_records, headerOf(&empty));
    try testing.expectEqual(@as(?u32, null), ttl);
}

test "a TTL with the top bit set is treated as zero, not as 68 years" {
    // RFC 2181 §8. The failure this prevents is the memorable direction:
    // 0x80000000 read as unsigned is ~68 years of cache lifetime.
    var msg = positive_reply;
    std.mem.writeInt(u32, msg[23 + 6 ..][0..4], 0x8000_0000, .big);
    const ttl = try replyTtlSeconds(&msg, fixture_records, headerOf(&msg));
    try testing.expectEqual(@as(?u32, 0), ttl);
}

test "ageTtlsInPlace decrements every record TTL but not the OPT" {
    var msg = positive_reply;
    try ageTtlsInPlace(&msg, fixture_records, headerOf(&msg), 60);

    var it = resource_record.ResourceRecordIter.init(&msg, fixture_records, headerOf(&msg));
    try testing.expectEqual(@as(u32, 240), (try it.next()).?.ttl); // 300 - 60
    try testing.expectEqual(@as(u32, 40), (try it.next()).?.ttl); // 100 - 60
    // Vacuous on this fixture — its OPT TTL is 0 and 0 -| 60 is still 0. The
    // next test is the one that can fail.
    try testing.expectEqual(@as(u32, 0), (try it.next()).?.ttl);
}

test "ageTtlsInPlace leaves a DO-bit OPT byte-for-byte alone" {
    // The OPT TTL field is extended-RCODE/version/flags, not a duration.
    // Decrementing it here would clear the DO bit and tell the client we
    // stripped DNSSEC — a wrong answer dressed as a fresh one.
    var msg = positive_reply_do;

    // Located by the parser, not by hand: an off-by-one here would silently
    // assert about the wrong four bytes. (It did, on the first attempt.)
    const opt_ttl_offset = blk: {
        var find = resource_record.ResourceRecordIter.init(&msg, fixture_records, headerOf(&msg));
        while (try find.next()) |rec| {
            if (rec.type == opt_type) break :blk rec.ttl_offset;
        }
        return error.TestFixtureHasNoOpt;
    };

    const before = std.mem.readInt(u32, msg[opt_ttl_offset..][0..4], .big);
    try testing.expectEqual(@as(u32, 0x0000_8000), before);

    try ageTtlsInPlace(&msg, fixture_records, headerOf(&msg), 60);

    const after = std.mem.readInt(u32, msg[opt_ttl_offset..][0..4], .big);
    try testing.expectEqual(before, after);
    // The real records still aged, so this is not passing by doing nothing.
    var it = resource_record.ResourceRecordIter.init(&msg, fixture_records, headerOf(&msg));
    try testing.expectEqual(@as(u32, 240), (try it.next()).?.ttl);
}

test "ageTtlsInPlace saturates at zero rather than wrapping" {
    // The direction that must never happen: an age past the TTL wrapping into
    // a near-4-billion-second lifetime on the client.
    var msg = positive_reply;
    try ageTtlsInPlace(&msg, fixture_records, headerOf(&msg), 100_000);

    var it = resource_record.ResourceRecordIter.init(&msg, fixture_records, headerOf(&msg));
    try testing.expectEqual(@as(u32, 0), (try it.next()).?.ttl);
    try testing.expectEqual(@as(u32, 0), (try it.next()).?.ttl);
}

test "aging is what makes a cached reply honest end to end" {
    // The whole point, in one test: store a reply, serve it 60s later, and the
    // client must be told 40s remain — not the 100s the cache holds.
    var threaded: std.Io.Threaded = undefined;
    var cache = testCache(&threaded, 16);
    defer cache.deinit();
    defer threaded.deinit();

    var buf: [64]u8 = undefined;
    const key = try keyFromWire(questionWire(&buf, 0), 0x66);

    const ttl = (try replyTtlSeconds(&positive_reply, fixture_records, headerOf(&positive_reply))).?;
    const inserted_at: i64 = 0;
    const expires_at = inserted_at + @as(i64, ttl) * std.time.ns_per_s;
    try cache.put(key, &positive_reply, inserted_at, expires_at);

    const now = 60 * std.time.ns_per_s;
    var out: [512]u8 = undefined;
    const hit = cache.get(key, now, &out).?;

    // The age comes back with the hit — no second lookup to race the sweeper.
    try testing.expectEqual(@as(u32, 60), hit.age_secs);
    try ageTtlsInPlace(out[0..hit.len], fixture_records, headerOf(out[0..hit.len]), hit.age_secs);

    const n = hit.len;
    var served = resource_record.ResourceRecordIter.init(out[0..n], fixture_records, headerOf(out[0..n]));
    try testing.expectEqual(@as(u32, 240), (try served.next()).?.ttl);
    try testing.expectEqual(@as(u32, 40), (try served.next()).?.ttl);

    // And the stored entry still reads 300/100 for the next client.
    var stored = resource_record.ResourceRecordIter.init(&positive_reply, fixture_records, headerOf(&positive_reply));
    try testing.expectEqual(@as(u32, 300), (try stored.next()).?.ttl);
    try testing.expectEqual(@as(u32, 100), (try stored.next()).?.ttl);
}

test "isCacheable refuses each disqualifying condition on its own" {
    const ok = headerOf(&positive_reply);
    try testing.expect(isCacheable(ok, false, 100));

    // Truncated: the records are incomplete, whatever the TTL says.
    try testing.expect(!isCacheable(ok, true, 100));

    // QDCOUNT != 1: records do not start where the walk assumed.
    var two_questions = ok;
    two_questions.question_count = 2;
    try testing.expect(!isCacheable(two_questions, false, 100));

    // SERVFAIL describes the server, not the name.
    var servfail = ok;
    servfail.rcode = .server_failure;
    try testing.expect(!isCacheable(servfail, false, 100));

    // NXDOMAIN does describe the name, and RFC 2308 says cache it.
    var nxdomain = ok;
    nxdomain.rcode = .name_error;
    try testing.expect(isCacheable(nxdomain, false, 900));

    // No usable TTL, and an explicit zero, are both refusals.
    try testing.expect(!isCacheable(ok, false, null));
    try testing.expect(!isCacheable(ok, false, 0));
}

test "finalizeServed restores the client's ID and ages the TTLs" {
    var served = positive_reply;
    try finalizeServed(&served, fixture_records, 0x1234, 60);

    // The client's ID, not the 0xABCD the fixture was stored with.
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, served[0..2], .big));

    var it = resource_record.ResourceRecordIter.init(&served, fixture_records, headerOf(&served));
    try testing.expectEqual(@as(u32, 240), (try it.next()).?.ttl);
    try testing.expectEqual(@as(u32, 40), (try it.next()).?.ttl);

    // The original is untouched — this is the property that lets one entry
    // serve many clients, and it holds because `served` is a copy.
    try testing.expectEqual(@as(u16, 0xABCD), std.mem.readInt(u16, positive_reply[0..2], .big));
    try testing.expectEqual(@as(u8, 0x2C), positive_reply[23 + 9]);
}

test "finalizeServed rejects a runt too short to hold a header" {
    var runt = [_]u8{ 1, 2, 3, 4 };
    try testing.expectError(error.Truncated, finalizeServed(&runt, 0, 1, 0));
}

test "finalizeServed at zero age moves nothing but the ID" {
    // The same instant it was stored. A good check that aging by 0 is not
    // quietly rewriting TTLs to something else.
    var served = positive_reply;
    try finalizeServed(&served, fixture_records, 0xABCD, 0);
    try testing.expectEqualSlices(u8, &positive_reply, &served);
}
