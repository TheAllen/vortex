//! A fixed set of slots for TCP connection tasks (P3.6).
//!
//! Each connection runs as its own `io.concurrent` task — never `async`,
//! because a connection lives as long as its client keeps it open, and an
//! `async` task that ran inline would hold the accept loop hostage for exactly
//! that long. `concurrent` has no limit of its own, so this table is the limit:
//! a connection that finds no free slot is closed on arrival.
//!
//! It is also how an idle connection is ended. `std.Io` offers no read timeout
//! on a stream, and setting SO_RCVTIMEO underneath it is not an option — the
//! runtime treats the resulting EAGAIN as a programmer bug and panics. So each
//! slot keeps the task's `Future`, and `cancelIdle` cancels the ones that have
//! gone quiet, which interrupts whatever read they are blocked in.

const std = @import("std");
const Io = std.Io;

pub const ConnTable = struct {
    mutex: Io.Mutex = .init,
    slots: []Slot,
    gpa: std.mem.Allocator,

    pub const Slot = struct {
        state: State = .free,
        /// Present once the task is attached. Awaited or cancelled exactly once,
        /// under the table's mutex, since `Future` is not threadsafe.
        future: ?Io.Future(void) = null,
        /// Set by the task as its last act, so a finished task can be reaped
        /// without anyone blocking on it.
        done: std.atomic.Value(bool) = .init(false),
        /// `.boot` nanoseconds of the last completed message. Bumped per whole
        /// message rather than per read, so a client trickling one byte at a
        /// time cannot hold a slot open forever (slowloris).
        last_active_ns: std.atomic.Value(i64) = .init(0),

        const State = enum { free, reserved, running };

        pub fn touch(slot: *Slot, io: Io) void {
            slot.last_active_ns.store(nowNs(io), .monotonic);
        }

        pub fn finish(slot: *Slot) void {
            slot.done.store(true, .release);
        }
    };

    pub fn init(gpa: std.mem.Allocator, capacity: usize) !ConnTable {
        const slots = try gpa.alloc(Slot, capacity);
        for (slots) |*s| s.* = .{};
        return .{ .slots = slots, .gpa = gpa };
    }

    /// Every task must already be gone — `cancelAll` first.
    pub fn deinit(self: *ConnTable) void {
        for (self.slots) |s| std.debug.assert(s.future == null);
        self.gpa.free(self.slots);
    }

    /// Reaps finished tasks, then reserves a free slot, or returns null when
    /// every slot holds a live connection.
    ///
    /// Reaping here, on the accept path, means a finished connection's slot is
    /// reclaimed exactly when a new one needs it, with no background pass.
    pub fn claim(self: *ConnTable, io: Io) ?*Slot {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var free: ?*Slot = null;
        for (self.slots) |*s| {
            if (s.state == .running and s.done.load(.acquire)) {
                s.future.?.await(io);
                s.* = .{};
            }
            if (free == null and s.state == .free) free = s;
        }
        const slot = free orelse return null;
        slot.* = .{ .state = .reserved };
        slot.touch(io);
        return slot;
    }

    /// Hands the reserved slot its task.
    pub fn attach(self: *ConnTable, io: Io, slot: *Slot, future: Io.Future(void)) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(slot.state == .reserved);
        slot.future = future;
        slot.state = .running;
    }

    /// Gives back a reserved slot whose task could not be started.
    pub fn release(self: *ConnTable, io: Io, slot: *Slot) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(slot.state == .reserved);
        slot.* = .{};
    }

    /// Cancels every running connection whose last message completed more
    /// than `idle_ns` ago, and frees its slot. Returns how many it ended.
    ///
    /// Holds the mutex across each `cancel`, which blocks until the task has
    /// returned. That cannot deadlock: a connection task never takes this
    /// mutex — it only stores to its slot's atomics.
    pub fn cancelIdle(self: *ConnTable, io: Io, now_ns: i64, idle_ns: i64) usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var ended: usize = 0;
        for (self.slots) |*s| {
            if (s.state != .running) continue;
            const finished = s.done.load(.acquire);
            if (!finished and now_ns - s.last_active_ns.load(.monotonic) < idle_ns) continue;
            if (finished) s.future.?.await(io) else {
                s.future.?.cancel(io);
                ended += 1;
            }
            s.* = .{};
        }
        return ended;
    }

    /// Cancels every connection. For shutdown.
    pub fn cancelAll(self: *ConnTable, io: Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        for (self.slots) |*s| {
            if (s.future) |*f| f.cancel(io);
            s.* = .{};
        }
    }

    /// Slots currently reserved or running.
    pub fn active(self: *ConnTable, io: Io) usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var n: usize = 0;
        for (self.slots) |s| n += @intFromBool(s.state != .free);
        return n;
    }
};

fn nowNs(io: Io) i64 {
    return @intCast(Io.Timestamp.now(io, Io.Clock.boot).nanoseconds);
}

const testing = std.testing;

/// Stands in for a connection: parks until cancelled, then marks its slot.
fn parkedConnection(io: Io, slot: *ConnTable.Slot) void {
    defer slot.finish();
    io.sleep(Io.Duration.fromSeconds(3600), Io.Clock.boot) catch {};
}

/// Stands in for a connection that has already hung up.
fn finishedConnection(io: Io, slot: *ConnTable.Slot) void {
    _ = io;
    slot.finish();
}

fn start(table: *ConnTable, io: Io, comptime func: anytype) !*ConnTable.Slot {
    const slot = table.claim(io) orelse return error.Full;
    table.attach(io, slot, try io.concurrent(func, .{ io, slot }));
    return slot;
}

test "claim refuses once every slot holds a live connection" {
    const io = testing.io;
    var table = try ConnTable.init(testing.allocator, 2);
    defer table.deinit();
    defer table.cancelAll(io);

    _ = try start(&table, io, parkedConnection);
    _ = try start(&table, io, parkedConnection);
    try testing.expectEqual(@as(?*ConnTable.Slot, null), table.claim(io));
    try testing.expectEqual(@as(usize, 2), table.active(io));
}

test "a finished connection's slot is reclaimed by the next claim" {
    const io = testing.io;
    var table = try ConnTable.init(testing.allocator, 1);
    defer table.deinit();
    defer table.cancelAll(io);

    const first = try start(&table, io, finishedConnection);
    // Wait for the task to report itself done — it runs on its own thread.
    while (!first.done.load(.acquire)) try io.sleep(Io.Duration.fromMilliseconds(1), Io.Clock.boot);

    // One slot, and it is the finished connection's: reclaimed, not refused.
    _ = try start(&table, io, parkedConnection);
    try testing.expectEqual(@as(usize, 1), table.active(io));
}

test "cancelIdle ends quiet connections and spares recent ones" {
    const io = testing.io;
    var table = try ConnTable.init(testing.allocator, 2);
    defer table.deinit();
    defer table.cancelAll(io);

    const quiet = try start(&table, io, parkedConnection);
    const busy = try start(&table, io, parkedConnection);

    // Backdate one connection's last message by a minute.
    const now = nowNs(io);
    quiet.last_active_ns.store(now - 60 * std.time.ns_per_s, .monotonic);
    busy.last_active_ns.store(now, .monotonic);

    try testing.expectEqual(@as(usize, 1), table.cancelIdle(io, now, 10 * std.time.ns_per_s));
    try testing.expectEqual(@as(usize, 1), table.active(io));
    // The survivor is the recent one, still parked.
    try testing.expect(!busy.done.load(.acquire));
}

test "release returns a reserved slot whose task never started" {
    const io = testing.io;
    var table = try ConnTable.init(testing.allocator, 1);
    defer table.deinit();

    const slot = table.claim(io).?;
    try testing.expectEqual(@as(?*ConnTable.Slot, null), table.claim(io));
    table.release(io, slot);
    try testing.expect(table.claim(io) != null);
}

test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(ConnTable);
    testing.refAllDecls(ConnTable.Slot);
}
