//! Exponential backoff schedules, as a pure function of the attempt number.
//!
//! Two callers with the same shape and different ceilings: `supervise` in
//! [main.zig](../main.zig) delaying a crash-looping coroutine's restart, and
//! [blocklist/acquire.zig](../blocklist/acquire.zig) delaying a blocklist fetch
//! retry. Sharing one function keeps "the first attempt is immediate, then
//! double, then clamp" as one rule with one test rather than two that could
//! drift apart.
//!
//! Pure on purpose: the schedule is checkable without spawning anything or
//! waiting for real time to pass.

const std = @import("std");

/// Delay before attempt number `prior_failures + 1`, in seconds.
///
/// Zero for the first attempt — a one-off blip should recover with no added
/// latency — then 1, 2, 4, 8 … doubling until `cap_s` clamps it.
///
/// Returns `i64` because that is what `std.Io.Duration.fromSeconds` takes;
/// keeping the type match here avoids a cast at every call site.
///
/// The shift is clamped to 62 before it is applied. That bound is not cosmetic:
/// a `u6` shift of 63 or more on an `i64` is illegal behavior, so an unclamped
/// schedule would turn a long retry loop — exactly the situation backoff exists
/// to survive — into a panic. `cap_s` then does the real limiting; the clamp
/// only guarantees the shift itself is well-defined.
pub fn seconds(prior_failures: u32, cap_s: i64) i64 {
    if (prior_failures == 0) return 0;
    const shift: u6 = @intCast(@min(prior_failures - 1, 62));
    return @min(@as(i64, 1) << shift, cap_s);
}

const testing = std.testing;

test "backoff doubles, caps, and lets the first attempt be immediate" {
    // The supervisor's ceiling, which is where this schedule came from.
    const cap: i64 = 30;

    // First attempt is free: a single spurious return should recover with no
    // added latency, since one blip is not a crash loop.
    try testing.expectEqual(@as(i64, 0), seconds(0, cap));

    // Then double from one second.
    try testing.expectEqual(@as(i64, 1), seconds(1, cap));
    try testing.expectEqual(@as(i64, 2), seconds(2, cap));
    try testing.expectEqual(@as(i64, 4), seconds(3, cap));
    try testing.expectEqual(@as(i64, 8), seconds(4, cap));
    try testing.expectEqual(@as(i64, 16), seconds(5, cap));

    // 1<<5 is 32, which the cap clamps to 30 — the doubling must not overshoot
    // the documented ceiling on its way there.
    try testing.expectEqual(cap, seconds(6, cap));

    // And it stays clamped no matter how long the crash loop runs. This is the
    // property that matters: an unbounded shift would overflow the u6 and panic,
    // turning a recoverable crash loop into a hard crash.
    try testing.expectEqual(cap, seconds(7, cap));
    try testing.expectEqual(cap, seconds(1000, cap));
    try testing.expectEqual(cap, seconds(std.math.maxInt(u32), cap));

    // Never decreases, so a longer crash loop is never retried more eagerly.
    var prev: i64 = 0;
    for (0..64) |i| {
        const cur = seconds(@intCast(i), cap);
        try testing.expect(cur >= prev);
        prev = cur;
    }
}

test "the cap is a parameter, not a constant" {
    // The blocklist retry's ceiling. A cap that is not a power of two is the
    // case that catches a `seconds` which clamps the *shift* to fit the cap
    // instead of clamping the result: 1<<3 is 8, so a shift-clamping version
    // agrees here and then disagrees at 5.
    try testing.expectEqual(@as(i64, 4), seconds(3, 5));
    try testing.expectEqual(@as(i64, 5), seconds(4, 5));
    try testing.expectEqual(@as(i64, 5), seconds(9, 5));

    // A zero cap means "retry immediately, forever" rather than a negative or
    // panicking delay — worth pinning, since `io.sleep` on a negative duration
    // is not a schedule anyone intended.
    try testing.expectEqual(@as(i64, 0), seconds(4, 0));
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
}
