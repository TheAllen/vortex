const std = @import("std");

const Verdict = @import("policy.zig").Verdict;

pub const SuffixBlockList = struct {
    suffix_blocklist: std.StringHashMapUnmanaged(void) = .empty,
    file_body: std.Io.Writer.Allocating = undefined,

    pub fn init(file_body: std.Io.Writer.Allocating) SuffixBlockList {
        return .{
            .file_body = file_body,
        };
    }

    fn parseSuffixDomain(_: *SuffixBlockList, line: []const u8) ?[]const u8 {
        // tokenizeAny collapses runs of spaces/tabs and trims a trailing '\r'
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");

        const domain: []const u8 = fields.next() orelse return null; // skip blank lines
        if (domain[0] == '#') return null; // skip comments
        return domain;
    }

    /// `url` comes from `Settings.suffix_blocklist_url` and must outlive this call.
    pub fn constructSuffixBlockList(
        self: *SuffixBlockList,
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
            std.log.err("failed to fetch suffix blocklist '{s}': HTTP {d}", .{ url, @intFromEnum(res.status) });
            return error.BlocklistFetchFailed;
        }

        var hosts_iter = std.mem.splitScalar(u8, self.file_body.written(), '\n');
        while (hosts_iter.next()) |line| {
            const domain = self.parseSuffixDomain(line) orelse continue;
            try self.suffix_blocklist.put(gpa, domain, {});
        }
    }

    pub fn decide(self: *const SuffixBlockList, domain: []const u8) Verdict {
        var rest: []const u8 = domain;
        while (true) {
            if (self.suffix_blocklist.contains(rest)) return .block;
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return .pass;
            rest = rest[dot + 1 ..];
        }
    }

    pub fn deinit(self: *SuffixBlockList, gpa: std.mem.Allocator) void {
        self.file_body.deinit();
        self.suffix_blocklist.deinit(gpa);
    }
};

const testing = std.testing;

test "suffix blocklist blocks a zone and its subdomains" {
    const gpa = testing.allocator;

    // Populate the set directly — decide() never touches file_body, so we skip the
    // HTTP fetch (and its undefined file_body) and free only the set.
    var sbl = SuffixBlockList{};
    defer sbl.suffix_blocklist.deinit(gpa);
    try sbl.suffix_blocklist.put(gpa, "example.com", {});

    // Names arrive already lowercased from parseQuestion (the C1 fix), so the filter
    // matches canonical input without re-normalizing. The parent-label walk means a
    // blocked zone also covers its subdomains.
    try testing.expectEqual(Verdict.block, sbl.decide("example.com")); // exact zone
    try testing.expectEqual(Verdict.block, sbl.decide("ads.example.com")); // subdomain
    try testing.expectEqual(Verdict.block, sbl.decide("a.b.example.com")); // deep subdomain
    try testing.expectEqual(Verdict.pass, sbl.decide("notexample.com")); // suffix ≠ label boundary
    try testing.expectEqual(Verdict.pass, sbl.decide("example.org")); // different zone
}
