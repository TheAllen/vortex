const std = @import("std");

const Authority = @import("authority.zig").Authority;
const Header = @import("header.zig").Header;

/// Builds the complete locally-synthesized reply to a query we are answering
/// ourselves: the original question echoed back, response flags set, and a
/// synthetic SOA in the Authority section so the client can negatively cache
/// the result (RFC 2308).
///
/// Pure: bytes in, bytes out. `query` is only read, so this is unit-testable
/// without an `Io`, a socket, or a `Context` — which is the whole reason it
/// lives here instead of inline in `handleQuery`. See next_steps.md P0.C2.
///
/// `question_end` is `parseQuestion`'s return value: the offset one past the
/// question section. Anything after it in `query` (an OPT record, most
/// commonly) is dropped — see next_steps.md P3.5.
///
/// `rcode` is a parameter rather than a hard-coded NXDOMAIN because the same
/// shape serves P4.1's NODATA path (RCODE=0) and P4.2's FORMERR/NOTIMP replies.
///
/// Returns a fresh buffer of exactly `question_end + Authority.WIRE_LEN` bytes,
/// owned by the caller. The incoming datagram cannot be extended in place: it
/// is a `dupe` sized to the exact query length (main.zig), with no room for the
/// 34 appended bytes.
pub fn build(
    gpa: std.mem.Allocator,
    query: []const u8,
    question_end: usize,
    rcode: Header.RCode,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(question_end >= 12);
    std.debug.assert(question_end <= query.len);

    // The Question end position plus the Authority wire length.
    const out = try gpa.alloc(u8, question_end + Authority.WIRE_LEN);
    errdefer gpa.free(out);

    // Copying only up to `question_end` is what truncates the message.
    @memcpy(out[0..question_end], query[0..question_end]);

    Header.writeResponseFlags(out, rcode);

    // Zero ANCOUNT / NSCOUNT / ARCOUNT (bytes 6..12), then claim the one
    // authority record we are about to append. QDCOUNT (4..6) stays as sent.
    @memset(out[6..12], 0);
    std.mem.writeInt(u16, out[8..10], 1, .big); // NSCOUNT = 1

    var authority = Authority{};
    const end = authority.write_authority_section(out, question_end);
    std.debug.assert(end == out.len);

    return out;
}

const testing = std.testing;

/// The exact 34 bytes `write_authority_section` must emit, spelled out rather
/// than recomputed from `Authority`'s fields: a test that reads the constants
/// back cannot catch a byte-reversed SERIAL/TTL/MINIMUM, which is the specific
/// regression this guards (native little-endian would write SERIAL 1 as
/// `01 00 00 00`).
const golden_soa = [Authority.WIRE_LEN]u8{
    0xC0, 0x0C, // NAME  — compression pointer to the QNAME at offset 12
    0x00, 0x06, // TYPE  — SOA
    0x00, 0x01, // CLASS — IN
    0x00, 0x00, 0x0E, 0x10, // TTL 3600
    0x00, 0x16, // RDLENGTH 22
    0x00, // MNAME — root label
    0x00, // RNAME — root label
    0x00, 0x00, 0x00, 0x01, // SERIAL 1
    0x00, 0x00, 0x0E, 0x10, // REFRESH 3600
    0x00, 0x00, 0x02, 0x58, // RETRY 600
    0x00, 0x01, 0x51, 0x80, // EXPIRE 86400
    0x00, 0x00, 0x0E, 0x10, // MINIMUM 3600 — the field RFC 2308 caches against
};

/// "AdS.Example.COM" A IN, preceded by a 12-byte header with id 0x1234 and
/// RD=1. Mixed case on purpose: the wire question must be echoed back byte for
/// byte, uppercase intact (C1 folds only the *parsed* copy used by the filters).
// One label per line: the grouping is the documentation for a wire format, so
// it is pinned against `zig fmt`'s column reflow.
// zig fmt: off
const query_ads_example_com = [_]u8{
    0x12, 0x34, // ID
    0x01, 0x00, // flags: RD=1, everything else clear
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
    3, 'A', 'd', 'S',
    7, 'E', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'C', 'O', 'M',
    0,          // root label
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
};
// zig fmt: on

/// Offset one past the question section of `query_ads_example_com`, i.e. what
/// `parseQuestion` returns for it: 12 header + 21 question.
const ads_question_end = 33;

test "build emits the exact blocked-response bytes (C2 regression)" {
    const gpa = testing.allocator;

    const reply = try build(gpa, &query_ads_example_com, ads_question_end, .name_error);
    defer gpa.free(reply);

    // Length: header + question + one 34-byte SOA, and nothing else.
    try testing.expectEqual(@as(usize, ads_question_end + Authority.WIRE_LEN), reply.len);
    try testing.expectEqual(@as(usize, 67), reply.len);

    // ID is echoed so the client can match the reply to its query.
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, reply[0..2], .big));

    // QR=1, OPCODE=0 (preserved), AA=0, TC=0, RD=1 (preserved), RA=1, Z=0,
    // RCODE=3. Asserting the whole word catches a stray bit either way.
    try testing.expectEqual(@as(u16, 0x8183), std.mem.readInt(u16, reply[2..4], .big));

    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[4..6], .big)); // QDCOUNT
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[6..8], .big)); // ANCOUNT
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[8..10], .big)); // NSCOUNT
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[10..12], .big)); // ARCOUNT

    // The question is echoed verbatim — including its original case, which is
    // the other half of C1: only the parsed copy is lowercased.
    try testing.expectEqualSlices(
        u8,
        query_ads_example_com[12..ads_question_end],
        reply[12..ads_question_end],
    );

    // And the SOA, byte for byte.
    try testing.expectEqualSlices(u8, &golden_soa, reply[ads_question_end..]);
}

test "build carries the requested rcode, not a hard-coded NXDOMAIN" {
    const gpa = testing.allocator;

    // NODATA (P4.1) and FORMERR/NOTIMP (P4.2) reuse this same shape; only the
    // low nibble of the flags word may differ.
    for ([_]Header.RCode{ .no_error, .format_error, .server_failure, .not_implemented }) |rcode| {
        const reply = try build(gpa, &query_ads_example_com, ads_question_end, rcode);
        defer gpa.free(reply);

        const flags = std.mem.readInt(u16, reply[2..4], .big);
        try testing.expectEqual(@as(u4, @intFromEnum(rcode)), @as(u4, @truncate(flags)));
        try testing.expectEqual(@as(u16, 0x8180), flags & 0xFFF0);
        try testing.expectEqualSlices(u8, &golden_soa, reply[ads_question_end..]);
    }
}

test "build drops a trailing OPT record and clears ARCOUNT" {
    const gpa = testing.allocator;

    // Same query, but EDNS0-aware: ARCOUNT=1 with a bare OPT record appended
    // after the question. Vortex currently discards it, which is a protocol
    // violation the client can notice (next_steps.md P3.5). This test pins the
    // *current* behavior so fixing P3.5 has to be a deliberate, visible change
    // rather than a silent one.
    var query: [ads_question_end + 11]u8 = undefined;
    @memcpy(query[0..ads_question_end], query_ads_example_com[0..ads_question_end]);
    std.mem.writeInt(u16, query[10..12], 1, .big); // ARCOUNT = 1
    @memcpy(query[ads_question_end..], &[_]u8{
        0x00, // NAME — root
        0x00, 0x29, // TYPE — OPT (41)
        0x10, 0x00, // CLASS — advertised UDP payload size 4096
        0x00, 0x00, 0x00, 0x00, // TTL — extended rcode + flags
        0x00, 0x00, // RDLENGTH — 0
    });

    const reply = try build(gpa, &query, ads_question_end, .name_error);
    defer gpa.free(reply);

    try testing.expectEqual(@as(usize, ads_question_end + Authority.WIRE_LEN), reply.len);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[10..12], .big));
    try testing.expectEqualSlices(u8, &golden_soa, reply[ads_question_end..]);
}
