const std = @import("std");
const name_reader = @import("name_reader.zig");

/// Question Section
pub const Question = struct {
    /// Decoded, lowercased QNAME. Inline storage — no allocator, nothing to
    /// free, and the slice stays valid exactly as long as this struct does.
    qname: name_reader.Name = .{},

    // Two octet code which specifies the type of the query
    qtype: u16 = undefined,

    // Two octet code which specifies the class of the query
    qclass: u16 = undefined,

    /// Parses one question starting at `name_start` and returns the offset one
    /// past it.
    ///
    /// `name_start` is a parameter rather than a hard-coded 12 because P3.2
    /// parses questions echoed inside *responses*, where the header is not the
    /// only thing in front of them.
    ///
    /// Compression is refused outright: a pointer in a query's question section
    /// is a protocol violation, and reading one would let a client aim the
    /// parser at bytes it did not send.
    pub fn parseQuestion(self: *Question, byte_slice: []const u8, name_start: usize) anyerror!usize {
        const read = try name_reader.readNameNoPointers(byte_slice, name_start);
        self.qname = read.name;

        const idx = read.next_offset;
        if (idx + 4 > byte_slice.len) return error.Truncated;
        self.qtype = std.mem.readInt(u16, byte_slice[idx..][0..2], .big);
        self.qclass = std.mem.readInt(u16, byte_slice[idx + 2 ..][0..2], .big);

        return idx + 4; // offset accounts for the qtype and qclass.
    }
};

const testing = std.testing;

test "parseQuestion lowercases the qname (C1 regression)" {
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

    const end = try question.parseQuestion(&wire, 12);

    try testing.expectEqualStrings("ads.example.com", question.qname.slice());
    try testing.expectEqual(@as(u16, 1), question.qtype);
    try testing.expectEqual(@as(u16, 1), question.qclass);
    // The whole question section was consumed.
    try testing.expectEqual(wire.len, end);
}

test "parseQuestion rejects a truncated question section" {
    // Name complete, but the four bytes of QTYPE/QCLASS are not all there.
    // zig fmt: off
    const wire = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        3, 'a', 'd', 's',
        0,
        0, 1, // qtype, then nothing
    };
    // zig fmt: on

    var question = Question{};
    try testing.expectError(error.Truncated, question.parseQuestion(&wire, 12));
}

test "parseQuestion rejects a compression pointer in the question" {
    // 0xC00C at offset 12 — a self-pointer, and in a query illegal regardless.
    var wire: [18]u8 = @splat(0);
    wire[12] = 0xC0;
    wire[13] = 0x0C;

    var question = Question{};
    try testing.expectError(
        error.UnexpectedCompressionInQuery,
        question.parseQuestion(&wire, 12),
    );
}

test "parseQuestion rejects a label with a reserved length prefix" {
    // zig fmt: off
    const wire = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x80, 'a', 'd', 's', // 10xxxxxx — reserved, never assigned
        0,
        0, 1, 0, 1,
    };
    // zig fmt: on

    var question = Question{};
    try testing.expectError(error.ReservedLabelType, question.parseQuestion(&wire, 12));
}
