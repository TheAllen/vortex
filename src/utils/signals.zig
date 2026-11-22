//! SIGINT, SIGTERM and SIGHUP (P2.4).
//!
//! **The handler only stores to atomics.** A signal can arrive on any thread,
//! in the middle of anything, including a `std.Io` call that holds a lock. So
//! nothing that takes a lock or touches `Io` is safe to run inside it, which
//! rules out logging, `Io.Event.set` and cancellation alike. The handler records
//! what was asked for. The main thread polls `poll` and does the actual work:
//! for SIGTERM it returns from `main`, whose deferred cleanup cancels every loop
//! and frees everything. For SIGHUP it wakes the refresher.
//!
//! Polling, rather than `sigwait` or a self-pipe, because std has neither
//! `sigwait` nor a way to hand a raw fd to `std.Io`, and a 100 ms check costs
//! nothing measurable. It also means a signal's only latency is that interval.

const std = @import("std");
const posix = std.posix;

/// What the process has been asked to do, most urgent first.
pub const Request = enum(u8) {
    none,
    /// SIGHUP: refresh the blocklists now.
    reload,
    /// SIGINT or SIGTERM: shut down.
    stop,
};

/// The signal that asked for `.stop`, for the log line. Zero until then.
var stop_signal: std.atomic.Value(u8) = .init(0);
/// SIGHUPs not yet handed out by `poll`.
var pending_reloads: std.atomic.Value(u32) = .init(0);

fn handle(sig: posix.SIG, info: *const posix.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    _ = info;
    _ = ctx;
    switch (sig) {
        .HUP => _ = pending_reloads.fetchAdd(1, .monotonic),
        .INT => stop_signal.store(signal_int, .release),
        .TERM => stop_signal.store(signal_term, .release),
        else => {},
    }
}

const signal_int: u8 = 2;
const signal_term: u8 = 15;

/// Installs the handler for SIGINT, SIGTERM and SIGHUP. Called once, from
/// `main`, before any loop starts. Until then the defaults apply, and SIGHUP's
/// default is to terminate the process.
pub fn install() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handle },
        .mask = posix.sigemptyset(),
        // RESTART, so a signal landing mid-syscall on some other thread does
        // not surface there as a spurious EINTR.
        .flags = posix.SA.SIGINFO | posix.SA.RESTART,
    };
    posix.sigaction(.INT, &act, null);
    posix.sigaction(.TERM, &act, null);
    posix.sigaction(.HUP, &act, null);
}

/// The most urgent request since the last call. A `.reload` is consumed by
/// returning it. `.stop` is sticky, since there is no undoing a shutdown.
pub fn poll() Request {
    if (stop_signal.load(.acquire) != 0) return .stop;
    if (pending_reloads.swap(0, .monotonic) > 0) return .reload;
    return .none;
}

/// The name of the signal that requested `.stop`, or `"none"`.
pub fn stopSignalName() []const u8 {
    return switch (stop_signal.load(.acquire)) {
        signal_int => "INT",
        signal_term => "TERM",
        else => "none",
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// The handler is called directly rather than through `raise`: a real SIGINT or
// SIGTERM delivered to the test runner would be caught by this handler only
// after `install`, and a test that forgot to install first would kill the
// runner. The integration cases send real signals to a real child instead.

const testing = std.testing;

fn reset() void {
    stop_signal.store(0, .monotonic);
    pending_reloads.store(0, .monotonic);
}

fn deliver(sig: posix.SIG) void {
    handle(sig, undefined, null);
}

test "SIGHUP is a reload, handed out once" {
    reset();
    defer reset();
    try testing.expectEqual(Request.none, poll());
    deliver(.HUP);
    deliver(.HUP);
    // Two HUPs before a poll are one refresh, not two back to back.
    try testing.expectEqual(Request.reload, poll());
    try testing.expectEqual(Request.none, poll());
}

test "SIGTERM and SIGINT are a stop, which stays and outranks a reload" {
    reset();
    defer reset();
    deliver(.HUP);
    deliver(.TERM);
    try testing.expectEqual(Request.stop, poll());
    try testing.expectEqual(Request.stop, poll());
    try testing.expectEqualStrings("TERM", stopSignalName());

    reset();
    deliver(.INT);
    try testing.expectEqual(Request.stop, poll());
    try testing.expectEqualStrings("INT", stopSignalName());
}

test "refAllDecls" {
    testing.refAllDecls(@This());
}
