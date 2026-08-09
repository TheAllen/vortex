const std = @import("std");

pub const Console = struct {
    buf: [256]u8 = undefined,
    writer: std.Io.File.Writer = undefined,
    interface: *std.Io.Writer = undefined,
    io: std.Io = undefined,
    // Serializes print+flush so concurrent handlers don't interleave bytes
    // or trample the shared buffer/writer state. std.Io.Mutex (new in 0.16)
    // has no default field values, so use the `init` declaration instead of `.{}`.
    mutex: std.Io.Mutex = std.Io.Mutex.init,

    pub fn init(self: *Console, io: std.Io) void {
        self.io = io;
        self.writer = std.Io.File.stdout().writer(io, &self.buf);
        self.interface = &self.writer.interface;
    }

    pub fn print(self: *Console, comptime fmt: []const u8, args: anytype) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.interface.print(fmt, args);
        try self.interface.flush();
    }

    pub fn println(self: *Console, comptime fmt: []const u8, args: anytype) !void {
        try self.print(fmt ++ "\n", args);
    }
};
