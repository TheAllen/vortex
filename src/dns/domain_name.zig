const std = @import("std");

/// DomainName (label encode/decode)
pub const DomainName = struct {
    name_list: std.ArrayList(u8) = undefined,

    pub fn init(gpa: std.mem.Allocator) !DomainName {
        return DomainName{
            .name_list = try std.ArrayList(u8).initCapacity(gpa, 50),
        };
    }

    pub fn append(self: *DomainName, gpa: std.mem.Allocator, char: u8) !void {
        try self.name_list.append(gpa, char);
    }

    pub fn deinit(self: *DomainName, gpa: std.mem.Allocator) void {
        self.name_list.deinit(gpa);
    }
};

const testing = std.testing;

test "DomainName appends character" {
    // std.testing.allocator detects leaks: if you forget deinit, the test fails.
    var name = try DomainName.init(testing.allocator);
    defer name.deinit(testing.allocator);

    for ("example") |c| {
        try name.append(testing.allocator, c);
    }

    try testing.expectEqualStrings("example", name.name_list.items);
    try testing.expectEqual(@as(usize, 7), name.name_list.items.len);
}
