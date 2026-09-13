const std = @import("std");

const AllowList = @import("../blocklist/allowlist.zig").AllowList;
const DomainBlockList = @import("../blocklist/domain_blocklist.zig").DomainBlockList;
const SuffixBlockList = @import("../blocklist/suffix_blocklist.zig").SuffixBlockList;

pub const Verdict = enum {
    /// Explicitly permit; short-circuits later filters in a chain.
    allow,
    /// Explicitly block; caller synthesizes the NXDOMAIN response.
    block,
    /// No opinion; defer to the next filter (or default-allow if none left).
    pass,
};

/// One immutable build of both blocklists.
///
/// **Why the two lists are one object.** Each set's keys are slices *into* that
/// list's `file_body`, so a body may never be freed while its set is still
/// readable — and a refresh replaces both lists at once. Binding them together
/// makes "the bytes and the index that points into them" a single unit with a
/// single lifetime, which is what lets `Policy.install` free a whole generation
/// with one call instead of four correctly-ordered ones.
///
/// Heap-allocated (`create`, never a value) because the refresh mechanism is a
/// pointer store: `Policy` holds a `*Snapshot`, and installing a new generation
/// swaps that pointer rather than mutating the lists underneath live readers.
///
/// **Immutable once installed.** Nothing mutates a snapshot after it reaches
/// `Policy`; a refresh builds a *new* one. That is the property the whole
/// locking argument in `Policy` rests on, so `decide` takes a `*const Snapshot`
/// and there is deliberately no method that writes to one.
pub const Snapshot = struct {
    domain_blocklist: DomainBlockList,
    suffix_blocklist: SuffixBlockList,

    /// An empty snapshot with both bodies ready to be filled by `load`.
    ///
    /// Allocated rather than returned by value: the caller hands the two
    /// sub-lists' addresses to concurrent `load` calls, and those addresses have
    /// to stay put.
    pub fn create(gpa: std.mem.Allocator) !*Snapshot {
        const self = try gpa.create(Snapshot);
        self.* = .{
            .domain_blocklist = DomainBlockList.init(std.Io.Writer.Allocating.init(gpa)),
            .suffix_blocklist = SuffixBlockList.init(std.Io.Writer.Allocating.init(gpa)),
        };
        return self;
    }

    /// Pure: no `Io`, no lock, no allocation. Kept that way on purpose — it is
    /// what lets the chain be tested against string literals, and it keeps the
    /// locked region in `Policy.decide` down to two hash lookups.
    pub fn decide(self: *const Snapshot, domain: []const u8) Verdict {
        if (self.domain_blocklist.decide(domain) == .block) return .block;
        return self.suffix_blocklist.decide(domain); // block or pass
    }

    /// Total entries across both lists. For logging and for the "did we start
    /// with nothing?" check; `counts` is what decisions are made on.
    pub fn count(self: *const Snapshot) u32 {
        const c = self.counts();
        return c.domain + c.suffix;
    }

    /// Entries in each list, kept apart because the safety rule below is
    /// per-list and a sum hides exactly the case it exists to catch.
    pub fn counts(self: *const Snapshot) Counts {
        return .{
            .domain = self.domain_blocklist.blocklist_set.count(),
            .suffix = self.suffix_blocklist.suffix_blocklist.count(),
        };
    }

    pub const Counts = struct { domain: u32, suffix: u32 };

    /// Whether installing a generation with `fresh` counts over one with
    /// `current` counts would zero out a list that currently has entries.
    ///
    /// This is the guard that matters most in the whole refresh path. A 200 OK
    /// serving an error page, or a truncated download, parses perfectly well
    /// into a list with no entries — and installing it silently disarms every
    /// block while the process goes on looking healthy. Keeping the previous
    /// list is always the better answer, because the alternative to a stale
    /// blocklist is no blocklist.
    ///
    /// **Per list, not on the total.** The two lists come from two different
    /// hosts, and one of them serving an error page while the other is fine is
    /// the ordinary case, not the exotic one. A rule on the sum passes happily
    /// while one of the two lists is wiped out.
    ///
    /// A list that is *already* empty may be replaced by another empty one —
    /// that is a fail-open startup waiting for its first real list, and
    /// refusing it would mean never recovering.
    ///
    /// Pure, so the rule is checkable without a refresh, a socket or a clock.
    pub fn wouldDisarm(current: Counts, fresh: Counts) bool {
        if (current.domain > 0 and fresh.domain == 0) return true;
        if (current.suffix > 0 and fresh.suffix == 0) return true;
        return false;
    }

    /// Frees both sets and both bodies, then the snapshot itself. Only ever
    /// called on a generation no reader can still reach; see `Policy.install`.
    ///
    /// Takes no allocator: it recovers the one `create` was given from the body
    /// that holds the bytes. Two generations are alive at once during a swap, so
    /// an allocator parameter here is a chance to free one generation with the
    /// other's allocator — a mistake that costs nothing today, when there is one
    /// allocator in the process, and is silent the day there are two.
    pub fn destroy(self: *Snapshot) void {
        const gpa = self.domain_blocklist.file_body.allocator;
        self.domain_blocklist.deinit(gpa);
        self.suffix_blocklist.deinit(gpa);
        gpa.destroy(self);
    }
};

/// The filter chain — allowlist → exact blocklist → suffix blocklist — over a
/// blocklist generation that can be replaced while queries are in flight.
///
/// ## Why there is a lock here now
///
/// The blocklists used to need no synchronization: they were built before any
/// coroutine spawned and only ever read afterwards, a clean write-once phase
/// boundary. Periodic refresh (P2.2) ends that. `std.process.Init` hands us a
/// `std.Io.Threaded` whose async limit defaults to `cpu_count - 1`, so handlers
/// run on a real thread pool and a refresh can land while several are mid-lookup.
///
/// ## Why an RwLock and not an atomic pointer
///
/// Swapping the pointer is the easy half; *freeing the old generation* is the
/// hard one. A bare atomic swap gives no way to know when the last reader that
/// loaded the old pointer has finished with it, which leaves only bad options:
/// leak every generation (~4 MB a refresh, on a process meant to run for
/// months), or free after a grace period and rest correctness on a timing
/// argument that a descheduled thread can violate.
///
/// The read lock makes it provable instead. A reader can only reach a snapshot
/// while holding the lock shared, and `install` takes it exclusively — which
/// waits for every existing reader to drain and blocks new ones — before
/// swapping. Once the swap is done the old pointer is unreachable from `self`,
/// so no reader can newly acquire it, and no reader still holds it. The free
/// after the unlock therefore races with nothing.
///
/// The cost is a `lockShared`/`unlockShared` pair per query. Uncontended that is
/// a compare-exchange loop with no syscall, around two hash lookups of work —
/// noise beside the UDP round trip it precedes.
pub const Policy = struct {
    /// Zero-size and comptime, so it has no generation and nothing to swap.
    /// Checked *before* the lock is taken, which keeps the allow path lock-free.
    allow_list: AllowList = .{},

    lock: std.Io.RwLock = .init,

    /// The live generation. Only ever read under `lock` shared, only ever
    /// written by `install` under `lock` exclusive.
    current: *Snapshot,

    pub fn init(snapshot: *Snapshot) Policy {
        return .{ .current = snapshot };
    }

    pub fn decide(self: *Policy, io: std.Io, domain: []const u8) std.Io.Cancelable!Verdict {
        if (self.allow_list.decide(domain) == .allow) return .allow;

        try self.lock.lockShared(io);
        defer self.lock.unlockShared(io);
        return self.current.decide(domain);
    }

    /// Per-list entry counts of the live generation, read under the lock.
    ///
    /// Exists so the refresher can log "12040 → 12061", decide whether it is
    /// running degraded, and apply `Snapshot.wouldDisarm` without reaching past
    /// the lock to `current`. An unsynchronized peek would be a data race.
    pub fn entryCounts(self: *Policy, io: std.Io) std.Io.Cancelable!Snapshot.Counts {
        try self.lock.lockShared(io);
        defer self.lock.unlockShared(io);
        return self.current.counts();
    }

    /// Makes `fresh` the live generation and frees the one it replaces.
    ///
    /// Takes ownership of `fresh` unconditionally: on the cancellation path it
    /// is destroyed rather than leaked, because the caller has already dropped
    /// its own reference by handing it over.
    ///
    /// The free happens *after* the unlock, which is safe for the reason spelled
    /// out on this type: past the swap the old pointer is reachable from nothing,
    /// and every reader that could have held it has already drained. Doing it
    /// outside the exclusive region keeps the critical section to a pointer
    /// store, so a refresh never stalls the datapath for as long as it takes to
    /// free a few megabytes.
    pub fn install(self: *Policy, io: std.Io, fresh: *Snapshot) std.Io.Cancelable!void {
        self.lock.lock(io) catch |err| {
            fresh.destroy();
            return err;
        };
        const old = self.current;
        self.current = fresh;
        self.lock.unlock(io);

        old.destroy();
    }

    pub fn deinit(self: *Policy) void {
        self.current.destroy();
    }
};

const testing = std.testing;

/// A snapshot over caller-supplied literals, bypassing the load path.
///
/// `build` is documented as borrowing its body, so string literals — static
/// storage, outliving everything — are a legal body. The `file_body` writers are
/// still initialized because `destroy` frees them; they simply stay empty.
fn testSnapshot(gpa: std.mem.Allocator, hosts: []const u8, suffixes: []const u8) !*Snapshot {
    const snap = try Snapshot.create(gpa);
    errdefer snap.destroy();
    try snap.domain_blocklist.build(gpa, hosts);
    try snap.suffix_blocklist.build(gpa, suffixes);
    return snap;
}

test "the chain consults exact before suffix" {
    const gpa = testing.allocator;

    const snap = try testSnapshot(gpa, "0.0.0.0 exact.example.net", "example.com");
    defer snap.destroy();

    // Each list still decides what it decides, through the chain.
    try testing.expectEqual(Verdict.block, snap.decide("exact.example.net"));
    try testing.expectEqual(Verdict.block, snap.decide("ads.example.com"));
    try testing.expectEqual(Verdict.pass, snap.decide("sub.exact.example.net"));
    try testing.expectEqual(Verdict.pass, snap.decide("example.org"));
}

test "an allowlist entry overrides a block" {
    const gpa = testing.allocator;

    // `captive.apple.com` is a real allowlist entry, and here it is *also* on
    // both blocklists — which is the whole point. A chain that consulted the
    // blocklists first, or that dropped the allowlist short-circuit, blocks a
    // captive-portal check and puts "no internet" popups on a working network.
    const snap = try testSnapshot(gpa, "0.0.0.0 captive.apple.com", "apple.com");

    // No `defer snap.destroy()`: `Policy.init` takes ownership, and `deinit`
    // frees the live generation. Doing both double-frees.
    var policy = Policy.init(snap);
    defer policy.deinit();

    // Asserted on the *snapshot* to pin what the allowlist is overriding: this
    // name really is blocked by the lists underneath.
    try testing.expectEqual(Verdict.block, snap.decide("captive.apple.com"));

    const io = testing.io;
    try testing.expectEqual(Verdict.allow, try policy.decide(io, "captive.apple.com"));

    // A sibling under the same blocked zone, not on the allowlist, still blocks —
    // so the override is the entry, not the zone.
    try testing.expectEqual(Verdict.block, try policy.decide(io, "ads.apple.com"));
}

test "install swaps the live generation and frees the old one" {
    const gpa = testing.allocator;
    const io = testing.io;

    var policy = Policy.init(try testSnapshot(gpa, "0.0.0.0 old.example.com", ""));
    defer policy.deinit();

    try testing.expectEqual(Verdict.block, try policy.decide(io, "old.example.com"));
    try testing.expectEqual(Verdict.pass, try policy.decide(io, "new.example.com"));

    try policy.install(io, try testSnapshot(gpa, "0.0.0.0 new.example.com", ""));

    // Both directions, because only the second one catches a swap that added the
    // new list without dropping the old: `new` blocking proves the fresh
    // generation is live, `old` passing proves the previous one is gone rather
    // than merged. The testing allocator's leak check covers the free itself.
    try testing.expectEqual(Verdict.block, try policy.decide(io, "new.example.com"));
    try testing.expectEqual(Verdict.pass, try policy.decide(io, "old.example.com"));
}

test "wouldDisarm refuses to empty a list that has entries" {
    const both: Snapshot.Counts = .{ .domain = 10, .suffix = 20 };

    // The ordinary refresh: both lists still have entries, install it.
    try testing.expect(!Snapshot.wouldDisarm(both, .{ .domain = 11, .suffix = 19 }));

    // Everything gone — a total outage serving error pages.
    try testing.expect(Snapshot.wouldDisarm(both, .{ .domain = 0, .suffix = 0 }));

    // One list gone and the other fine, in both directions. This is the pair a
    // rule written on the *sum* gets wrong: 0+20 and 10+0 are both non-zero, so
    // a summing guard installs a generation with one list wiped out.
    try testing.expect(Snapshot.wouldDisarm(both, .{ .domain = 0, .suffix = 20 }));
    try testing.expect(Snapshot.wouldDisarm(both, .{ .domain = 10, .suffix = 0 }));

    // A list may shrink drastically without being emptied — upstream lists do
    // get pruned, and second-guessing that would need a threshold nobody can
    // pick correctly. Only zero is treated as evidence of breakage.
    try testing.expect(!Snapshot.wouldDisarm(both, .{ .domain = 1, .suffix = 1 }));
}

test "wouldDisarm lets an empty list be replaced by another empty one" {
    // A fail-open startup: nothing was obtained, and the refresher is retrying.
    // If this were refused, a resolver that came up with no lists could never
    // adopt one, because every candidate would be compared against a state it
    // is trying to leave.
    const nothing: Snapshot.Counts = .{ .domain = 0, .suffix = 0 };
    try testing.expect(!Snapshot.wouldDisarm(nothing, nothing));

    // And the recovery itself is obviously allowed.
    try testing.expect(!Snapshot.wouldDisarm(nothing, .{ .domain = 10, .suffix = 20 }));

    // Half-recovered: one list arrived, the other did not. Allowed, because
    // some filtering beats none and the next round retries the other.
    try testing.expect(!Snapshot.wouldDisarm(nothing, .{ .domain = 10, .suffix = 0 }));
}

test "count sums both lists" {
    const gpa = testing.allocator;

    // Two and one, not two and two: distinct totals per list are what catch a
    // `count` that doubles one side instead of adding both.
    const snap = try testSnapshot(
        gpa,
        "0.0.0.0 a.example.com\n0.0.0.0 b.example.com",
        "c.example.net",
    );
    defer snap.destroy();

    try testing.expectEqual(@as(u32, 3), snap.count());
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Verdict);
    testing.refAllDecls(Snapshot);
    testing.refAllDecls(Policy);
}
