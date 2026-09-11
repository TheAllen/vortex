const std = @import("std");

const Settings = @import("../settings.zig").Settings;
const Source = @import("../settings.zig").Source;
const Verdict = @import("policy.zig").Verdict;

/// Diagnostics for the load path, scoped so an operator can filter a blocklist
/// failure apart from the datapath.
const log = std.log.scoped(.blocklist);

pub const DomainBlockList = struct {
    blocklist_set: std.StringHashMapUnmanaged(void) = .empty,
    file_body: std.Io.Writer.Allocating = undefined,

    /// Hosts files point every blocked name at a loopback address and then
    /// include the loopback's *own* names in the same format. Blocking
    /// `localhost` would make the machine unable to resolve itself.
    const LOCALHOST = "localhost";

    pub fn init(file_body: std.Io.Writer.Allocating) DomainBlockList {
        return .{
            .file_body = file_body,
        };
    }

    fn parseDomain(line: []const u8) ?[]const u8 {
        // tokenizeAny collapses runs of spaces/tabs and trims a trailing '\r'
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");

        const ip = fields.next() orelse return null;
        if (ip.len == 0 or ip[0] == '#') return null;
        const domain = fields.next() orelse return null;
        if (std.mem.eql(u8, domain, LOCALHOST)) return null;

        return domain;
    }

    /// Builds the set from an already-acquired hosts body.
    ///
    /// Pure over the byte slice: no `Io`, no HTTP, no filesystem — which is what
    /// makes the whole grammar testable against literals. `body` **must outlive
    /// `self`**; the keys put into the set are slices *into* it, never copies.
    /// `load` satisfies that by passing `self.file_body.written()`, which lives
    /// until `deinit`.
    pub fn build(self: *DomainBlockList, gpa: std.mem.Allocator, body: []const u8) !void {
        var hosts_iter = std.mem.splitScalar(u8, body, '\n');
        while (hosts_iter.next()) |line| {
            const domain = parseDomain(line) orelse continue;
            try self.blocklist_set.put(gpa, domain, {});
        }
    }

    /// Acquires the list into `self.file_body`, then builds the set from it.
    ///
    /// `source` comes from `Settings.blocklist_source` and must outlive this
    /// call. A `.path` source is read from disk and never touches the network,
    /// which is what makes a startup against a fixture instant rather than the
    /// ~25 s an HTTP fetch of the real lists costs.
    pub fn load(
        self: *DomainBlockList,
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
                    log.err("failed to fetch blocklist '{s}': HTTP {d}", .{ url, @intFromEnum(res.status) });
                    return error.BlocklistFetchFailed;
                }
            },
            .path => |path| try readFileInto(&self.file_body, io, gpa, path, "blocklist"),
        }

        try self.build(gpa, self.file_body.written());
    }

    pub fn decide(self: *const DomainBlockList, domain: []const u8) Verdict {
        return if (self.blocklist_set.contains(domain)) .block else .pass;
    }

    pub fn deinit(self: *DomainBlockList, gpa: std.mem.Allocator) void {
        self.file_body.deinit();
        self.blocklist_set.deinit(gpa);
    }
};

/// Reads `path` into `file_body`, which retains the bytes for the process
/// lifetime because both lists' keys are slices into them.
///
/// Shared by both blocklists. Every failure is fatal and names the path: unlike
/// the optional `.env` file, an operator who named a blocklist asked for that
/// blocklist, and continuing with an empty set would be the silent fail-open
/// this project already rejected once.
///
/// The read allocates a temporary copy that is immediately appended and freed.
/// That costs one transient duplicate of the body (~3.5 MB for a full
/// StevenBlack list) in exchange for much plainer code than a `Reader.stream`
/// loop; revisit only if that ever shows up in a profile. Note that
/// `Writer.Allocating.initOwnedSlice` is *not* the zero-copy shortcut it looks
/// like — it leaves `writer.end` at 0, so `written()` comes back empty.
pub fn readFileInto(
    file_body: *std.Io.Writer.Allocating,
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    what: []const u8,
) !void {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(Settings.max_blocklist_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => {
            log.err("{s} '{s}' does not exist", .{ what, path });
            return err;
        },
        error.StreamTooLong => {
            log.err("{s} '{s}' exceeds {d} bytes", .{ what, path, Settings.max_blocklist_bytes });
            return err;
        },
        else => {
            log.err("cannot read {s} '{s}': {s}", .{ what, path, @errorName(err) });
            return err;
        },
    };
    defer gpa.free(bytes);

    try file_body.writer.writeAll(bytes);
}

const testing = std.testing;

/// Builds a list from a literal body, borrowing the caller's bytes directly.
///
/// `build` is documented as borrowing, so a test may hand it a string literal —
/// those live in static storage and outlive everything. `file_body` stays
/// `undefined` because nothing on this path touches it, so only the set is
/// freed.
fn testList(gpa: std.mem.Allocator, body: []const u8) !DomainBlockList {
    var list = DomainBlockList{};
    errdefer list.blocklist_set.deinit(gpa);
    try list.build(gpa, body);
    return list;
}

test "build reads the hosts grammar and skips what it must" {
    const gpa = testing.allocator;

    var list = try testList(gpa,
        \\# a full-line comment
        \\
        \\0.0.0.0 ads.example.com
        \\0.0.0.0    spaced.example.com
        \\127.0.0.1 localhost
        \\127.0.0.1 kept.example.com
        \\203.0.113.9
    );
    defer list.blocklist_set.deinit(gpa);

    // The ordinary case, and a run of spaces collapsing to one separator.
    try testing.expectEqual(Verdict.block, list.decide("ads.example.com"));
    try testing.expectEqual(Verdict.block, list.decide("spaced.example.com"));

    // `localhost` is dropped *by name*, not because of the address in front of
    // it — the line below it is identical in every other respect and survives.
    // Deleting the LOCALHOST check has to fail this test, and the `kept.` entry
    // is what makes it fail for the right reason.
    try testing.expectEqual(Verdict.pass, list.decide("localhost"));
    try testing.expectEqual(Verdict.block, list.decide("kept.example.com"));

    // A line with an address and no name yields nothing rather than indexing
    // past the end of the token stream.
    try testing.expectEqual(Verdict.pass, list.decide("203.0.113.9"));

    // Comment and blank lines contribute no keys at all. Counting is what
    // catches a comment leaking in as a key nobody thought to query for.
    try testing.expectEqual(@as(u32, 3), list.blocklist_set.count());
}

test "build tolerates tabs, CRLF, and an indented comment" {
    const gpa = testing.allocator;

    // A CRLF file must not leave '\r' glued to the last field: `example.com\r`
    // would be a key no lowercased qname can ever equal, so the entry would
    // load clean and block nothing. Tabs are the other separator hosts files
    // use in the wild, and can't appear in a multiline literal — hence the
    // escapes here rather than in the grammar test above.
    var list = try testList(
        gpa,
        "0.0.0.0\tcrlf.example.com\r\n  # indented comment\r\n0.0.0.0 \t second.example.com\r\n",
    );
    defer list.blocklist_set.deinit(gpa);

    try testing.expectEqual(Verdict.block, list.decide("crlf.example.com"));
    try testing.expectEqual(Verdict.block, list.decide("second.example.com"));
    try testing.expectEqual(@as(u32, 2), list.blocklist_set.count());
}

test "decide matches the exact name only" {
    const gpa = testing.allocator;

    var list = try testList(gpa, "0.0.0.0 example.com");
    defer list.blocklist_set.deinit(gpa);

    // Exact match, and nothing else — the parent-label walk belongs to
    // SuffixBlockList. A subdomain passing here is the whole reason both lists
    // exist.
    try testing.expectEqual(Verdict.block, list.decide("example.com"));
    try testing.expectEqual(Verdict.pass, list.decide("ads.example.com"));
    try testing.expectEqual(Verdict.pass, list.decide("notexample.com"));
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(DomainBlockList);
}
