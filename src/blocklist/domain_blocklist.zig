const std = @import("std");

const Verdict = @import("policy.zig").Verdict;

pub const DomainBlockList = struct {
    LOCALHOST: []const u8 = "localhost",
    blocklist_set: std.StringHashMapUnmanaged(void) = .empty,
    file_body: std.Io.Writer.Allocating = undefined,

    pub fn init(file_body: std.Io.Writer.Allocating) DomainBlockList {
        return .{
            .file_body = file_body,
        };
    }

    fn parseDomain(self: *DomainBlockList, line: []const u8) ?[]const u8 {
        // tokenizeAny collapses runs of spaces/tabs and trims a trailing '\r'
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");

        const ip = fields.next() orelse return null;
        if (ip.len == 0 or ip[0] == '#') return null;
        const domain = fields.next() orelse return null;
        if (std.mem.eql(u8, domain, self.LOCALHOST)) return null;

        return domain;
    }

    /// `url` comes from `Settings.blocklist_url` and must outlive this call.
    pub fn constructBlockList(
        self: *DomainBlockList,
        gpa: std.mem.Allocator,
        http_client: *std.http.Client,
        url: []const u8,
    ) !void {
        const res = try http_client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &self.file_body.writer,
        });
        if (res.status != .ok) {
            std.log.err("failed to fetch blocklist '{s}': HTTP {d}", .{ url, @intFromEnum(res.status) });
            return error.BlocklistFetchFailed;
        }

        var hosts_iter = std.mem.splitScalar(u8, self.file_body.written(), '\n');
        while (hosts_iter.next()) |line| {
            // tokenizeAny collapses runs of the spaces/tabs and trims a trailing '\r'
            const domain = self.parseDomain(line) orelse continue;
            try self.blocklist_set.put(gpa, domain, {});
        }
    }

    pub fn decide(self: *const DomainBlockList, domain: []const u8) Verdict {
        return if (self.blocklist_set.contains(domain)) .block else .pass;
    }

    pub fn deinit(self: *DomainBlockList, gpa: std.mem.Allocator) void {
        self.file_body.deinit();
        self.blocklist_set.deinit(gpa);
    }
};
