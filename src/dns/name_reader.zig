//! Reads a domain name out of a DNS message, following RFC 1035 §4.1.4
//! compression pointers.
//!
//! Pure: bytes in, value out. No allocator, no `Io`, no state carried between
//! calls — the entire threat model of this file is hostile input, so it is
//! written to be exhaustively testable without a socket anywhere near it.
//!
//! Two entry points, because whether a pointer is legal is a property of *where
//! in the protocol you are*, not of the parser. In a query's question section a
//! pointer is malformed input (`readNameNoPointers`); in a reply's record
//! stream it is the normal case (`readName`). Encoding that in the function
//! name is what stops the query path from ever growing pointer-following by
//! accident.

const std = @import("std");

/// Maximum length of a name in the text form this module produces.
///
/// RFC 1035 §2.3.4 caps a name at 255 octets *on the wire*. Text form spends
/// each label's length byte on a '.' separator instead — except the last, which
/// has no successor to separate it from — and drops the root label's zero byte
/// entirely, so a W-octet wire name is exactly W-2 characters of text. 253 is
/// therefore the 255-octet wire cap restated in this module's units, not a
/// second and looser limit of its own.
pub const max_text_len = 253;

/// A decoded name, lowercased, dot-separated, without a trailing root dot.
///
/// Inline storage rather than an allocation: the cap above is a hard protocol
/// bound, so a fixed buffer is exactly sized, cannot leak, and keeps the
/// allocator off the response path — which starts to matter once P3.2 calls
/// this once per resource record and P3.3 once per cache lookup.
pub const Name = struct {
    buf: [max_text_len]u8 = undefined,
    len: u8 = 0,

    pub fn slice(self: *const Name) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const Read = struct {
    name: Name,

    /// Where the caller resumes parsing — which is **not** where the name's
    /// bytes ended. When a pointer is followed, the name continues at the
    /// target but the *message* continues 2 bytes past the pointer. Returning
    /// both in one struct is the whole reason this is not just a `[]const u8`:
    /// a record walk that resumes at the wrong one desynchronizes silently.
    next_offset: usize,
};

pub const NameError = error{
    /// Ran off the end of the message mid-name.
    Truncated,
    /// A `01`/`10` length-byte prefix: reserved by RFC 1035 §4.1.4, never assigned.
    ReservedLabelType,
    /// A pointer that does not go strictly backwards, or a chain that will not end.
    BadPointer,
    /// Decoding would exceed the 255-octet wire cap.
    NameTooLong,
    /// A compression pointer where the protocol does not permit one.
    UnexpectedCompressionInQuery,
};

/// The ordering rule below does most of the work, but it does **not** by itself
/// bound the loop: a label followed by a backwards pointer to that same label
/// (`63 'a'… 0xC0 0x00` read from the pointer) satisfies "strictly backwards"
/// on every hop and still cycles forever. Chains that emit bytes are stopped by
/// `max_text_len`; chains that emit none — pointer straight to pointer — are
/// stopped only here. Unreachable in any message a real compressor produces.
const max_jumps = 64;

/// Reads the name at `offset`, following compression pointers.
pub fn readName(msg: []const u8, offset: usize) NameError!Read {
    return read(msg, offset, true);
}

/// Query-path variant: a pointer is a protocol violation, not a hop.
pub fn readNameNoPointers(msg: []const u8, offset: usize) NameError!Read {
    return read(msg, offset, false);
}

fn read(msg: []const u8, offset: usize, comptime follow_pointers: bool) NameError!Read {
    var name: Name = .{};
    var pos = offset;
    // Set on the *first* pointer only: later hops move within the name, but the
    // message resumes after the pointer the caller's scan actually reached.
    var resume_at: ?usize = null;
    var jumps: usize = 0;

    while (true) {
        if (pos >= msg.len) return error.Truncated;
        const len_byte = msg[pos];

        // The top two bits of a length byte are the label type: 00 literal,
        // 11 pointer, 01 and 10 reserved.
        switch (len_byte & 0xC0) {
            0x00 => {
                // Root label: the name ends here, one byte wide.
                if (len_byte == 0) {
                    pos += 1;
                    break;
                }

                const label_len: usize = len_byte;
                const start = pos + 1;
                const end = start + label_len;
                if (end > msg.len) return error.Truncated;

                // Checked before copying, so the buffer cannot be overrun even
                // by a cyclic chain that keeps handing us more labels.
                const sep: usize = @intFromBool(name.len > 0);
                if (name.len + sep + label_len > name.buf.len) return error.NameTooLong;

                if (sep == 1) {
                    name.buf[name.len] = '.';
                    name.len += 1;
                }
                // Canonicalize to lowercase while decoding: DNS names are
                // case-insensitive (RFC 1035 §2.3.3), and both the filter
                // lookups and P3.3's cache key want the canonical form. ASCII
                // only by design — IDNs arrive as punycode (xn--) and DNS
                // case-folding is defined only over A-Z.
                for (msg[start..end]) |c| {
                    name.buf[name.len] = std.ascii.toLower(c);
                    name.len += 1;
                }
                pos = end;
            },
            0xC0 => {
                if (!follow_pointers) return error.UnexpectedCompressionInQuery;

                if (pos + 1 >= msg.len) return error.Truncated;
                const target = (@as(usize, len_byte & 0x3F) << 8) | msg[pos + 1];

                // Every pointer must target an offset strictly less than its
                // own. RFC 1035 compression *is* a backreference to a name
                // already emitted, so this costs nothing in compatibility and
                // kills self-reference, forward pointers, A->B->A ping-pong and
                // out-of-range targets under one rule — no visited set to
                // allocate, no arbitrary depth constant to justify.
                if (target >= pos) return error.BadPointer;

                jumps += 1;
                if (jumps > max_jumps) return error.BadPointer;

                if (resume_at == null) resume_at = pos + 2;
                pos = target;
            },
            else => return error.ReservedLabelType,
        }
    }

    return .{ .name = name, .next_offset = resume_at orelse pos };
}

const testing = std.testing;
const blocked_response = @import("blocked_response.zig");

/// One message exercising every well-formed shape at a known offset, so each
/// test below is a single call against a fixture whose layout is spelled out
/// here once. Offsets are load-bearing — the pointers encode them.
///
/// One label per line: the grouping is the documentation for a wire format, so
/// it is pinned against `zig fmt`'s column reflow.
// zig fmt: off
const fixture = [_]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //  0  header
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // 12  qname: example.com
    3, 'c', 'o', 'm',                     // 20
    0,                                    // 24  root label
    0x00, 0x01,                           // 25  qtype  = A
    0x00, 0x01,                           // 27  qclass = IN
    0xC0, 0x0C,                           // 29  whole name is a pointer -> 12
    3, 'W', 'w', 'W',                     // 31  partial: "www" + pointer -> 12
    0xC0, 0x0C,                           // 35
    0xC0, 0x1F,                           // 37  two hops: -> 31, which -> 12
    0,                                    // 39  root-only name
};
// zig fmt: on

test "readName decodes an uncompressed name and stops after the root byte" {
    const got = try readName(&fixture, 12);
    try testing.expectEqualStrings("example.com", got.name.slice());
    try testing.expectEqual(@as(usize, 25), got.next_offset);
}

test "readName follows a name that is nothing but a pointer" {
    const got = try readName(&fixture, 29);
    try testing.expectEqualStrings("example.com", got.name.slice());
    // 2 past the pointer — not 25, where the target's bytes ended.
    try testing.expectEqual(@as(usize, 31), got.next_offset);
}

test "readName follows partial compression, lowercasing as it goes" {
    // The case that actually shows up in real upstream replies: some labels
    // literal, the shared suffix behind a pointer.
    const got = try readName(&fixture, 31);
    try testing.expectEqualStrings("www.example.com", got.name.slice());
    try testing.expectEqual(@as(usize, 37), got.next_offset);
}

test "readName follows a two-hop chain" {
    const got = try readName(&fixture, 37);
    try testing.expectEqualStrings("www.example.com", got.name.slice());
    // Still 2 past the *first* pointer, however many hops followed it.
    try testing.expectEqual(@as(usize, 39), got.next_offset);
}

test "readName accepts a root-only name as empty" {
    const got = try readName(&fixture, 39);
    try testing.expectEqualStrings("", got.name.slice());
    try testing.expectEqual(@as(usize, 40), got.next_offset);
}

test "readName rejects a pointer to itself" {
    // 0xC00C sitting at offset 12 — the classic self-reference.
    var msg: [14]u8 = @splat(0);
    msg[12] = 0xC0;
    msg[13] = 0x0C;
    try testing.expectError(error.BadPointer, readName(&msg, 12));
}

test "readName rejects a forward pointer" {
    const msg = [_]u8{ 0xC0, 0x05, 0, 0, 0, 0, 0 };
    try testing.expectError(error.BadPointer, readName(&msg, 0));
}

test "readName rejects an A->B->A cycle" {
    // A at offset 4 points back to B at 2; B points forward to A, which is
    // where the ordering rule catches the loop — before it can ever run.
    const msg = [_]u8{ 0, 0, 0xC0, 0x04, 0xC0, 0x02 };
    try testing.expectError(error.BadPointer, readName(&msg, 4));
}

test "readName rejects a pointer past the end of the message" {
    // Subsumed by the ordering rule rather than needing a bounds check of its
    // own: a target beyond the message is necessarily ahead of the pointer.
    const msg = [_]u8{ 0xC0, 0xFF, 0, 0 };
    try testing.expectError(error.BadPointer, readName(&msg, 0));
}

test "readName rejects a pointer whose second byte is missing" {
    const msg = [_]u8{ 3, 'w', 'w', 'w', 0xC0 };
    try testing.expectError(error.Truncated, readName(&msg, 0));
}

test "readName rejects a label running past the end of the message" {
    const msg = [_]u8{ 7, 'e', 'x' };
    try testing.expectError(error.Truncated, readName(&msg, 0));
}

test "readName rejects the reserved label types" {
    for ([_]u8{ 0x40, 0x80 }) |len_byte| {
        const msg = [_]u8{ len_byte, 'x', 'x', 'x', 0 };
        try testing.expectError(error.ReservedLabelType, readName(&msg, 0));
    }
}

test "readName rejects chained compression that expands past the length cap" {
    // Four 63-octet labels reached through three backwards pointers. Each hop
    // is individually legal; only the accumulated length is not (63*4 + 3 dots
    // = 255 > 253), so this catches a reader that bounds hops but not output.
    var msg: [263]u8 = undefined;
    msg[0] = 63;
    @memset(msg[1..64], 'a');
    msg[64] = 0; // "aaa…" ends here
    msg[65] = 63;
    @memset(msg[66..129], 'b');
    msg[129] = 0xC0;
    msg[130] = 0; // "bbb….aaa…"
    msg[131] = 63;
    @memset(msg[132..195], 'c');
    msg[195] = 0xC0;
    msg[196] = 65; // "ccc….bbb….aaa…"
    msg[197] = 63;
    @memset(msg[198..261], 'd');
    msg[261] = 0xC0;
    msg[262] = 131; // "ddd….ccc….bbb….aaa…" — one label too far

    try testing.expectError(error.NameTooLong, readName(&msg, 197));

    // The same chain one label shorter is fine, which is what makes the failure
    // above a length verdict rather than an accident of the fixture.
    const ok = try readName(&msg, 131);
    try testing.expectEqual(@as(usize, 63 * 3 + 2), ok.name.slice().len);
}

test "readName round-trips the one pointer Vortex emits" {
    // blocked_response.build writes the SOA's owner name as 0xC00C. Reading it
    // back must yield the qname — the reader checked against our own writer
    // rather than against a fixture we also wrote by hand.
    const gpa = testing.allocator;

    // zig fmt: off
    const query = [_]u8{
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        3, 'A', 'd', 'S',
        7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'C', 'O', 'M',
        0,
        0x00, 0x01,
        0x00, 0x01,
    };
    // zig fmt: on
    const question_end = 33;

    const reply = try blocked_response.build(gpa, &query, question_end, .name_error);
    defer gpa.free(reply);

    const got = try readName(reply, question_end);
    try testing.expectEqualStrings("ads.example.com", got.name.slice());
    try testing.expectEqual(@as(usize, question_end + 2), got.next_offset);
}

test "readNameNoPointers accepts an uncompressed name" {
    const got = try readNameNoPointers(&fixture, 12);
    try testing.expectEqualStrings("example.com", got.name.slice());
    try testing.expectEqual(@as(usize, 25), got.next_offset);
}

test "readNameNoPointers rejects compression outright" {
    // Both the whole-name pointer and the partial one — a query may not carry
    // either, and the partial case is the one a hand-rolled label loop is most
    // likely to let through.
    try testing.expectError(error.UnexpectedCompressionInQuery, readNameNoPointers(&fixture, 29));
    try testing.expectError(error.UnexpectedCompressionInQuery, readNameNoPointers(&fixture, 31));
}

test "fuzz name reading against arbitrary bytes" {
    // The highest-value test in this file: the entire threat model of these
    // functions is hostile input, and under ReleaseSafe any out-of-bounds read
    // becomes a clean crash the fuzzer catches. The assertion is only that they
    // terminate and return — everything about *what* they return is pinned by
    // the golden vectors above.
    try testing.fuzz({}, fuzzReadName, .{});
}

fn fuzzReadName(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();

    var buf: [512]u8 = undefined;
    const msg = buf[0..smith.slice(&buf)];
    const offset = smith.index(msg.len + 1);

    if (readName(msg, offset)) |got| {
        // A success must be self-consistent, or a caller walking records with
        // it would run backwards or off the end.
        try testing.expect(got.name.len <= max_text_len);
        try testing.expect(got.next_offset <= msg.len);
        try testing.expect(got.next_offset > offset);
    } else |_| {}

    if (readNameNoPointers(msg, offset)) |got| {
        try testing.expect(got.name.len <= max_text_len);
        try testing.expect(got.next_offset <= msg.len);
    } else |_| {}
}
