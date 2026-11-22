const std = @import("std");

const Authority = @import("authority.zig").Authority;
const Header = @import("header.zig").Header;
const edns = @import("edns.zig");

/// Builds a locally-synthesized reply to a query we are answering ourselves:
/// the original question echoed back, response flags set, then optionally one
/// answer record (a null-IP block, P4.1), optionally a synthetic SOA in
/// Authority (so a negative block can be cached, RFC 2308) and optionally our
/// own OPT in Additional. `plan` decides which, for a blocked name.
///
/// Pure: bytes in, bytes out. `query` is only read, so this is unit-testable
/// without an `Io`, a socket, or a `Context` — which is the whole reason it
/// lives here instead of inline in `handleQuery`. See next_steps.md P0.C2.
///
/// `question_end` is `parseQuestion`'s return value: the offset one past the
/// question section. Anything after it in `query` is **not** copied — the
/// client's OPT least of all, since RFC 6891 §7 wants the *responder's* OPT in
/// a reply, not the requester's echoed back. `opts.opt` is how ours gets in.
///
/// `rcode` is a parameter rather than a hard-coded NXDOMAIN because the same
/// shape serves P4.1's NODATA path (RCODE=0) and BADVERS (RCODE 0 in the header,
/// extended RCODE 1 in the OPT).
///
/// Writes into `out` and returns the used prefix; `error.NoSpaceLeft` if `out`
/// is shorter than `wireLen`. The incoming datagram cannot be extended in
/// place: it is a `dupe` sized to the exact query length (main.zig).
pub fn buildInto(
    out: []u8,
    query: []const u8,
    question_end: usize,
    rcode: Header.RCode,
    opts: Options,
) error{NoSpaceLeft}![]u8 {
    std.debug.assert(question_end >= 12);
    std.debug.assert(question_end <= query.len);

    const len = wireLen(question_end, opts);
    if (out.len < len) return error.NoSpaceLeft;
    const reply = out[0..len];

    // Copying only up to `question_end` is what drops whatever followed.
    @memcpy(reply[0..question_end], query[0..question_end]);

    Header.writeResponseFlags(reply, rcode);

    // Zero ANCOUNT / NSCOUNT / ARCOUNT (bytes 6..12), then claim exactly the
    // records appended below. QDCOUNT (4..6) stays as sent.
    @memset(reply[6..12], 0);
    var at = question_end;

    // Answer, then Authority, then Additional: RFC 1035 §4.1's section order.
    if (opts.answer) |answer| {
        std.mem.writeInt(u16, reply[6..8], 1, .big); // ANCOUNT = 1
        at = answer.write(reply, at);
    }
    if (opts.soa) {
        std.mem.writeInt(u16, reply[8..10], 1, .big); // NSCOUNT = 1
        var authority = Authority{};
        at = authority.write_authority_section(reply, at);
    }
    if (opts.opt) |opt| {
        std.mem.writeInt(u16, reply[10..12], 1, .big); // ARCOUNT = 1
        edns.writeOpt(reply[at..][0..edns.opt_wire_len], opt.udp_size, opt.do_bit, opt.ext_rcode);
        at += edns.opt_wire_len;
    }
    std.debug.assert(at == reply.len);

    return reply;
}

pub const Options = struct {
    /// One answer record for the question, before everything else. Set for a
    /// null-IP block (P4.1); null for every negative answer.
    answer: ?Answer = null,
    /// Append the synthetic SOA. On for a negative blocked answer (NXDOMAIN or
    /// NODATA), off for a null-IP answer and for BADVERS.
    soa: bool = true,
    /// Append our OPT. Set exactly when the query carried one.
    opt: ?Opt = null,
};

/// TTL on a null-IP answer. Short on purpose: a device holds the block for
/// this long after the name is unblocked, and blocked names are answered
/// locally, so re-asking costs nothing upstream. Decided 2026-11-22.
pub const answer_ttl: u32 = 60;

/// The unroutable address a null-IP block answers with: `0.0.0.0` or `::`.
pub const Answer = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,

    pub const zero_a: Answer = .{ .a = @splat(0) };
    pub const zero_aaaa: Answer = .{ .aaaa = @splat(0) };

    /// NAME, TYPE, CLASS, TTL and RDLENGTH, before the address.
    const fixed_len = 12;

    pub fn wireLen(self: Answer) usize {
        return fixed_len + self.rdata().len;
    }

    fn rdata(self: *const Answer) []const u8 {
        return switch (self.*) {
            .a => |*b| b,
            .aaaa => |*b| b,
        };
    }

    fn rrType(self: Answer) u16 {
        return switch (self) {
            .a => qtype_a,
            .aaaa => qtype_aaaa,
        };
    }

    /// Writes the record at `at` and returns the offset one past it. The name
    /// is a compression pointer to the question's QNAME, which always starts
    /// at offset 12, so the answer is for exactly the name that was asked.
    fn write(self: Answer, out: []u8, at: usize) usize {
        const rec = out[at..][0..self.wireLen()];
        std.mem.writeInt(u16, rec[0..2], 0xC00C, .big); // NAME → offset 12
        std.mem.writeInt(u16, rec[2..4], self.rrType(), .big);
        std.mem.writeInt(u16, rec[4..6], class_in, .big);
        std.mem.writeInt(u32, rec[6..10], answer_ttl, .big);
        const data = self.rdata();
        std.mem.writeInt(u16, rec[10..12], @intCast(data.len), .big);
        @memcpy(rec[fixed_len..], data);
        return at + rec.len;
    }
};

const qtype_a: u16 = 1;
const qtype_aaaa: u16 = 28;
const class_in: u16 = 1;

/// How a blocked name is answered (P4.1): `VORTEX_BLOCK_RESPONSE`.
pub const Strategy = enum {
    /// `0.0.0.0` for A and `::` for AAAA, NODATA for every other type. The
    /// default: an app trying to connect fails at once (connection refused)
    /// instead of treating the name as missing and retrying. It is also what
    /// the hosts-format lists Vortex loads literally say (`0.0.0.0 ads.…`).
    null_ip,
    /// NOERROR with no answer and an SOA: "the name exists, but has no record
    /// of this type". Never hands out an address.
    nodata,
    /// NXDOMAIN with an SOA: "the name does not exist". Vortex's only answer
    /// before P4.1.
    nxdomain,

    pub fn parse(raw: []const u8) ?Strategy {
        return std.meta.stringToEnum(Strategy, raw);
    }
};

/// What a blocked reply carries, before the OPT, which is the caller's call.
pub const Plan = struct {
    rcode: Header.RCode,
    answer: ?Answer,
    soa: bool,
};

/// Picks the reply for a blocked question. Pure, so the whole
/// strategy × qtype table is unit-tested without building a message.
///
/// Only an A or AAAA question in class IN gets an address. Everything else
/// under `null_ip`, HTTPS (type 65) above all, gets NODATA: browsers send an
/// HTTPS query next to A and AAAA, and an address there would be malformed.
/// A null-IP answer carries no SOA, because it is a positive answer and the
/// SOA exists only so a negative one can be cached (RFC 2308).
pub fn plan(strategy: Strategy, qtype: u16, qclass: u16) Plan {
    const nodata: Plan = .{ .rcode = .no_error, .answer = null, .soa = true };
    return switch (strategy) {
        .nxdomain => .{ .rcode = .name_error, .answer = null, .soa = true },
        .nodata => nodata,
        .null_ip => if (qclass != class_in) nodata else switch (qtype) {
            qtype_a => .{ .rcode = .no_error, .answer = Answer.zero_a, .soa = false },
            qtype_aaaa => .{ .rcode = .no_error, .answer = Answer.zero_aaaa, .soa = false },
            else => nodata,
        },
    };
}

pub const Opt = struct {
    udp_size: u16,
    do_bit: bool,
    /// Upper 8 bits of a 12-bit RCODE. 1 with a header RCODE of 0 is BADVERS.
    ext_rcode: u8 = 0,
};

/// Bytes `buildInto` writes for this question and these options.
pub fn wireLen(question_end: usize, opts: Options) usize {
    return question_end +
        (if (opts.answer) |a| a.wireLen() else 0) +
        (if (opts.soa) @as(usize, Authority.WIRE_LEN) else 0) +
        (if (opts.opt != null) @as(usize, edns.opt_wire_len) else 0);
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
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_ads_example_com, ads_question_end, .name_error, .{});

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
    // NODATA (P4.1) and FORMERR/NOTIMP (P4.2) reuse this same shape; only the
    // low nibble of the flags word may differ.
    for ([_]Header.RCode{ .no_error, .format_error, .server_failure, .not_implemented }) |rcode| {
        var buf: [512]u8 = undefined;
        const reply = try buildInto(&buf, &query_ads_example_com, ads_question_end, rcode, .{});

        const flags = std.mem.readInt(u16, reply[2..4], .big);
        try testing.expectEqual(@as(u4, @intFromEnum(rcode)), @as(u4, @truncate(flags)));
        try testing.expectEqual(@as(u16, 0x8180), flags & 0xFFF0);
        try testing.expectEqualSlices(u8, &golden_soa, reply[ads_question_end..]);
    }
}

/// `query_ads_example_com` made EDNS0-aware: ARCOUNT=1 and a bare OPT
/// (payload 4096, DO set) after the question.
const query_with_opt = blk: {
    var q: [ads_question_end + 11]u8 = undefined;
    @memcpy(q[0..ads_question_end], query_ads_example_com[0..ads_question_end]);
    std.mem.writeInt(u16, q[10..12], 1, .big); // ARCOUNT = 1
    @memcpy(q[ads_question_end..], &[_]u8{
        0x00, // NAME — root
        0x00, 0x29, // TYPE — OPT (41)
        0x10, 0x00, // CLASS — advertised UDP payload size 4096
        0x00, 0x00, 0x80, 0x00, // TTL — ext rcode 0, version 0, DO
        0x00, 0x00, // RDLENGTH — 0
    });
    break :blk q;
};

test "build answers an OPT with our own OPT, after the SOA (P3.5)" {
    // This test used to be "build drops a trailing OPT record and clears
    // ARCOUNT", pinning the protocol violation so that fixing it had to be a
    // visible decision. This is that decision: RFC 6891 §7 — a query with an
    // OPT gets one back.
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_with_opt, ads_question_end, .name_error, .{
        .opt = .{ .udp_size = 1232, .do_bit = true },
    });

    try testing.expectEqual(@as(usize, ads_question_end + Authority.WIRE_LEN + 11), reply.len);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[8..10], .big)); // NSCOUNT
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[10..12], .big)); // ARCOUNT

    // SOA first, untouched...
    const soa_end = ads_question_end + Authority.WIRE_LEN;
    try testing.expectEqualSlices(u8, &golden_soa, reply[ads_question_end..soa_end]);
    // ...then *our* OPT: 1232, not the client's 4096; DO copied from the query.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0x29, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0 }, reply[soa_end..]);
}

test "build with no OPT requested still drops the client's and clears ARCOUNT" {
    // The client's OPT is never copied through. Whether one comes back is
    // `opts.opt`'s decision alone.
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_with_opt, ads_question_end, .name_error, .{});
    try testing.expectEqual(@as(usize, ads_question_end + Authority.WIRE_LEN), reply.len);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[10..12], .big));
}

test "build shapes a BADVERS reply: no SOA, RCODE 0, extended RCODE 1" {
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_with_opt, ads_question_end, .no_error, .{
        .soa = false,
        .opt = .{ .udp_size = 1232, .do_bit = false, .ext_rcode = 1 },
    });

    try testing.expectEqual(@as(usize, ads_question_end + 11), reply.len);
    try testing.expectEqual(@as(u16, 0x8180), std.mem.readInt(u16, reply[2..4], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[8..10], .big)); // no SOA
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[10..12], .big));
    try testing.expectEqual(@as(u8, 1), reply[ads_question_end + 5]); // ext rcode
}

test "build refuses a buffer too small for the reply" {
    var buf: [ads_question_end + Authority.WIRE_LEN - 1]u8 = undefined;
    try testing.expectError(
        error.NoSpaceLeft,
        buildInto(&buf, &query_ads_example_com, ads_question_end, .name_error, .{}),
    );
}

// ── P4.1: null-IP answers and the strategy table ─────────────────────────

/// `query_ads_example_com` asking for AAAA instead of A.
const query_ads_aaaa = blk: {
    var q = query_ads_example_com;
    std.mem.writeInt(u16, q[ads_question_end - 4 ..][0..2], 28, .big);
    break :blk q;
};

test "build emits the exact null-IP A answer, with no SOA" {
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_ads_example_com, ads_question_end, .no_error, .{
        .answer = Answer.zero_a,
        .soa = false,
    });

    try testing.expectEqual(@as(usize, ads_question_end + 16), reply.len);
    try testing.expectEqual(@as(u16, 0x8180), std.mem.readInt(u16, reply[2..4], .big)); // NOERROR
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[6..8], .big)); // ANCOUNT
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[8..10], .big)); // NSCOUNT
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, reply[10..12], .big)); // ARCOUNT

    try testing.expectEqualSlices(u8, &.{
        0xC0, 0x0C, // NAME — pointer to the QNAME at offset 12
        0x00, 0x01, // TYPE — A
        0x00, 0x01, // CLASS — IN
        0x00, 0x00, 0x00, 0x3C, // TTL 60
        0x00, 0x04, // RDLENGTH 4
        0, 0, 0, 0, // 0.0.0.0
    }, reply[ads_question_end..]);
}

test "build emits the exact null-IP AAAA answer, then our OPT" {
    var buf: [512]u8 = undefined;
    const reply = try buildInto(&buf, &query_ads_aaaa, ads_question_end, .no_error, .{
        .answer = Answer.zero_aaaa,
        .soa = false,
        .opt = .{ .udp_size = 1232, .do_bit = false },
    });

    const answer_end = ads_question_end + 28;
    try testing.expectEqual(@as(usize, answer_end + edns.opt_wire_len), reply.len);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[6..8], .big)); // ANCOUNT
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, reply[10..12], .big)); // ARCOUNT

    try testing.expectEqualSlices(u8, &[_]u8{
        0xC0, 0x0C, // NAME
        0x00, 0x1C, // TYPE — AAAA (28)
        0x00, 0x01, // CLASS — IN
        0x00, 0x00, 0x00, 0x3C, // TTL 60
        0x00, 0x10, // RDLENGTH 16
    } ++ @as([16]u8, @splat(0)), reply[ads_question_end..answer_end]); // ::
    // The OPT comes after the answer, not in place of it.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0x29, 0x04, 0xD0, 0, 0, 0, 0, 0, 0 }, reply[answer_end..]);
}

test "build refuses a buffer one byte short of an answer" {
    const opts: Options = .{ .answer = Answer.zero_aaaa, .soa = false };
    var buf: [ads_question_end + 27]u8 = undefined;
    try testing.expectEqual(@as(usize, buf.len + 1), wireLen(ads_question_end, opts));
    try testing.expectError(error.NoSpaceLeft, buildInto(&buf, &query_ads_aaaa, ads_question_end, .no_error, opts));
}

test "plan: every strategy against A, AAAA, HTTPS and a non-IN class" {
    const a = 1;
    const aaaa = 28;
    const https = 65;
    const in = 1;
    const chaos = 3;

    // null_ip: an address for A and AAAA only, NODATA for everything else.
    const pa = plan(.null_ip, a, in);
    try testing.expectEqual(Header.RCode.no_error, pa.rcode);
    try testing.expectEqualDeep(@as(?Answer, Answer.zero_a), pa.answer);
    try testing.expect(!pa.soa);

    const p6 = plan(.null_ip, aaaa, in);
    try testing.expectEqualDeep(@as(?Answer, Answer.zero_aaaa), p6.answer);
    try testing.expect(!p6.soa);

    for ([_][2]u16{ .{ https, in }, .{ 15, in }, .{ 255, in }, .{ a, chaos }, .{ aaaa, chaos } }) |q| {
        const p = plan(.null_ip, q[0], q[1]);
        try testing.expectEqual(Header.RCode.no_error, p.rcode);
        try testing.expectEqual(@as(?Answer, null), p.answer);
        try testing.expect(p.soa);
    }

    // nodata and nxdomain never hand out an address, whatever was asked.
    for ([_]u16{ a, aaaa, https }) |qtype| {
        const nd = plan(.nodata, qtype, in);
        try testing.expectEqual(Header.RCode.no_error, nd.rcode);
        try testing.expectEqual(@as(?Answer, null), nd.answer);
        try testing.expect(nd.soa);

        const nx = plan(.nxdomain, qtype, in);
        try testing.expectEqual(Header.RCode.name_error, nx.rcode);
        try testing.expectEqual(@as(?Answer, null), nx.answer);
        try testing.expect(nx.soa);
    }
}

test "Strategy.parse accepts exactly the three names" {
    try testing.expectEqual(@as(?Strategy, .null_ip), Strategy.parse("null_ip"));
    try testing.expectEqual(@as(?Strategy, .nodata), Strategy.parse("nodata"));
    try testing.expectEqual(@as(?Strategy, .nxdomain), Strategy.parse("nxdomain"));
    try testing.expectEqual(@as(?Strategy, null), Strategy.parse("null-ip"));
    try testing.expectEqual(@as(?Strategy, null), Strategy.parse("NXDOMAIN"));
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Options);
    testing.refAllDecls(Opt);
    testing.refAllDecls(Answer);
    testing.refAllDecls(Strategy);
    testing.refAllDecls(Plan);
}
