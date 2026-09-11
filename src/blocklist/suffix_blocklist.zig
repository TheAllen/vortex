const std = @import("std");

const Source = @import("../settings.zig").Source;
const Verdict = @import("policy.zig").Verdict;
const readFileInto = @import("domain_blocklist.zig").readFileInto;

/// Diagnostics for the load path, scoped so an operator can filter a blocklist
/// failure apart from the datapath.
const log = std.log.scoped(.blocklist);

pub const SuffixBlockList = struct {
    suffix_blocklist: std.StringHashMapUnmanaged(void) = .empty,
    file_body: std.Io.Writer.Allocating = undefined,

    pub fn init(file_body: std.Io.Writer.Allocating) SuffixBlockList {
        return .{
            .file_body = file_body,
        };
    }

    fn parseSuffixDomain(line: []const u8) ?[]const u8 {
        // tokenizeAny collapses runs of spaces/tabs and trims a trailing '\r'
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");

        const domain: []const u8 = fields.next() orelse return null; // skip blank lines
        if (domain[0] == '#') return null; // skip comments
        return domain;
    }

    /// Builds the set from an already-acquired list body.
    ///
    /// Pure over the byte slice: no `Io`, no HTTP, no filesystem. `body` **must
    /// outlive `self`**; the keys put into the set are slices *into* it, never
    /// copies. `load` satisfies that by passing `self.file_body.written()`,
    /// which lives until `deinit`.
    pub fn build(self: *SuffixBlockList, gpa: std.mem.Allocator, body: []const u8) !void {
        var hosts_iter = std.mem.splitScalar(u8, body, '\n');
        while (hosts_iter.next()) |line| {
            const domain = parseSuffixDomain(line) orelse continue;
            try self.suffix_blocklist.put(gpa, domain, {});
        }
    }

    /// Acquires the list into `self.file_body`, then builds the set from it.
    ///
    /// `source` comes from `Settings.suffix_blocklist_source` and must outlive
    /// this call. A `.path` source is read from disk and never touches the
    /// network.
    pub fn load(
        self: *SuffixBlockList,
        gpa: std.mem.Allocator,
        io: std.Io,
        http_client: *std.http.Client,
        source: Source,
    ) !void {
        switch (source) {
            .url => |url| {
                const res = try http_client.fetch(.{
                    .location = .{ .url = url },
                    .method = .GET,
                    .response_writer = &self.file_body.writer,
                });
                if (res.status != .ok) {
                    log.err("failed to fetch suffix blocklist '{s}': HTTP {d}", .{ url, @intFromEnum(res.status) });
                    return error.BlocklistFetchFailed;
                }
            },
            .path => |path| try readFileInto(&self.file_body, io, gpa, path, "suffix blocklist"),
        }

        try self.build(gpa, self.file_body.written());
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

/// Builds a list from a literal body, borrowing the caller's bytes directly.
/// See the equivalent helper in domain_blocklist.zig.
fn testList(gpa: std.mem.Allocator, body: []const u8) !SuffixBlockList {
    var list = SuffixBlockList{};
    errdefer list.suffix_blocklist.deinit(gpa);
    try list.build(gpa, body);
    return list;
}

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

test "build reads bare domains and skips comments and blanks" {
    const gpa = testing.allocator;

    var list = try testList(gpa,
        \\# a full-line comment
        \\
        \\example.com
        \\  indented.example.org
        \\   # an indented comment
        \\trailing.example.net
    );
    defer list.suffix_blocklist.deinit(gpa);

    try testing.expectEqual(Verdict.block, list.decide("ads.example.com"));
    try testing.expectEqual(Verdict.block, list.decide("indented.example.org"));
    try testing.expectEqual(Verdict.block, list.decide("trailing.example.net"));

    // Three keys, not five: the comments must not become zones. A leaked `#`
    // key is invisible to decide() — nothing resolves a name starting with
    // `#` — so counting is the only assertion that catches it.
    try testing.expectEqual(@as(u32, 3), list.suffix_blocklist.count());
}

test "build tolerates CRLF" {
    const gpa = testing.allocator;

    // With '\r' left attached the key is `example.com\r`, which the parent-label
    // walk can never equal: the list would load clean and block nothing, which
    // is this file's documented worst-case failure.
    var list = try testList(gpa, "example.com\r\nexample.org\r\n");
    defer list.suffix_blocklist.deinit(gpa);

    try testing.expectEqual(Verdict.block, list.decide("ads.example.com"));
    try testing.expectEqual(Verdict.block, list.decide("example.org"));
}

test "a '*.'-prefixed entry is retained verbatim and blocks nothing" {
    const gpa = testing.allocator;

    // The footgun `.env`, README and Settings all warn about in prose, pinned
    // as a checked property: `domainswild` (with the `*.` prefix) parses without
    // complaint and then matches nothing, because `decide` walks parent labels
    // and never produces a label beginning with `*`. Use `domainswild2`.
    //
    // If a future change starts stripping the prefix, this test fails — which
    // is the correct outcome: the stripping would be a feature, and the warnings
    // in those three documents would all need to come out with it.
    var list = try testList(gpa, "*.example.com");
    defer list.suffix_blocklist.deinit(gpa);

    try testing.expectEqual(@as(u32, 1), list.suffix_blocklist.count());
    try testing.expectEqual(Verdict.pass, list.decide("example.com"));
    try testing.expectEqual(Verdict.pass, list.decide("ads.example.com"));
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(SuffixBlockList);
}
