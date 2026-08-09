const std = @import("std");
const DomainName = @import("domain_name.zig").DomainName;

/// Question Section
pub const Question = struct {
    // Domain name
    qname: DomainName = undefined,

    // Two octet code which specifies the type of the query
    qtype: u16 = undefined,

    // Two octet code which specifies the class of the query
    qclass: u16 = undefined,

    question_str_slice: []const u8 = undefined,

    pub fn parseQuestion(self: *Question, gpa: std.mem.Allocator, byte_slice: []const u8) !usize {
        var idx: usize = 12;
        while (true) {
            if (idx >= byte_slice.len) return error.TruncatedQuestion;
            const label_len: usize = @as(usize, byte_slice[idx]);
            if (label_len == 0) break;

            // Labels are capped at 63 octets; a length byte >= 0xC0 is a
            // compression pointer, which is never valid in a query's question
            // name. The 0x40/0x80 prefixes are reserved.
            if (label_len > 63) return error.UnsupportedLabel;

            idx += 1;
            if (idx + label_len > byte_slice.len) return error.TruncatedQuestion;

            // Add dot separator between labels
            if (self.qname.name_list.items.len > 0) {
                try self.qname.name_list.append(gpa, '.');
            }
            // Canonicalize to lowercase as we build: DNS names are case-insensitive
            // (RFC 1035 §2.3.3), so filters must match regardless of the case the client
            // (or a 0x20-randomizing upstream) sent. ASCII-only by design — IDNs arrive as
            // punycode (xn--) and DNS case-folding is defined only over A–Z. Only the
            // parsed copy is folded; the wire buffer (`data`) is forwarded unchanged.
            for (0..label_len) |i| {
                try self.qname.name_list.append(gpa, std.ascii.toLower(byte_slice[idx..][i]));
            }
            idx += label_len;

            // RFC 1035: a full name is at most 255 octets on the wire
            if (idx - 12 > 255) return error.NameTooLong;
        }

        // Skip the null terminator
        idx += 1;

        if (idx + 4 > byte_slice.len) return error.TruncatedQuestion;
        self.qtype = std.mem.readInt(u16, byte_slice[idx..][0..2], .big);
        self.qclass = std.mem.readInt(u16, byte_slice[idx + 2 ..][0..2], .big);
        idx += 4;

        return idx;
    }

    pub fn init(self: *Question, gpa: std.mem.Allocator) !void {
        self.qname = try DomainName.init(gpa);
    }

    pub fn deinit(self: *Question, gpa: std.mem.Allocator) void {
        self.qname.deinit(gpa);
    }
};

const testing = std.testing;

test "parseQuestion lowercases the qname (C1 regression)" {
    const gpa = testing.allocator;

    // 12-byte header (contents irrelevant to parseQuestion — it starts at idx 12)
    // followed by the question for "ADS.Example.COM" A IN. Labels carry mixed case
    // on the wire; the parsed name must come back canonical lowercase.
    // One label per line: the grouping is the documentation for a wire format,
    // so it is pinned against `zig fmt`'s column reflow.
    // zig fmt: off
    const wire = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // header
        3, 'A', 'D', 'S',
        7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'C', 'O', 'M',
        0,    // root label terminator
        0, 1, // qtype = A
        0, 1, // qclass = IN
    };
    // zig fmt: on

    var question = Question{};
    try question.init(gpa);
    defer question.deinit(gpa);

    const end = try question.parseQuestion(gpa, &wire);

    try testing.expectEqualStrings("ads.example.com", question.qname.name_list.items);
    try testing.expectEqual(@as(u16, 1), question.qtype);
    try testing.expectEqual(@as(u16, 1), question.qclass);
    // The whole question section was consumed.
    try testing.expectEqual(wire.len, end);
}
