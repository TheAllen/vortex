const std = @import("std");
const name_reader = @import("name_reader.zig");

const Header = @import("header.zig").Header;

pub const Section = enum {
    answer,
    authority,
    additional,
};

pub const Type = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    HTTPS = 65,
    _, // open enum: unknown codes are stil representable
};

/// Slices borrow from the message buffer; it must outlive this.
pub const Rdata = union(enum) {
    a: *const [4]u8,
    aaaa: *const [16]u8,
    /// NS, CNAME, PTR: a single wire-format name.
    name: []const u8,
    mx: struct { preference: u16, exchange: []const u8 },
    srv: struct { priority: u16, weight: u16, port: u16, target: []const u8 },
    /// TXT: raw character-strings, still length-prefixed internally.
    txt: []const u8,
    /// RFC 3597: anything we don't model stays opaque.
    unknown: []const u8,
};

pub fn parseRdata(t: Type, rdata: []const u8) !Rdata {
    switch (t) {
        .A => .{ .a = std.mem.bytesAsValue([4]u8, rdata[0..4]) },
        .AAAA => .{ .aaaa = std.mem.bytesAsValue([16]u8, rdata[0..16]) },
        .NS, .CNAME, .PTR => .{ .name = rdata },
        .MX => blk: {
            if (rdata.len < 3) return error.MalformedRdata;
            break :blk .{ .mx = .{
                .preference = std.mem.readInt(u16, rdata[0..2], .big),
                .exchange = rdata[0..2],
            } };
        },
        .SRV => blk: {
            if (rdata.len < 7) return error.MalformedRdata;
            break :blk .{ .srv = .{
                .priority = std.mem.readInt(u16, rdata[0..2], .big),
                .weight = std.mem.readInt(u16, rdata[2..4], .big),
                .port = std.mem.readInt(u16, rdata[4..6], .big),
                .target = rdata[6..],
            } };
        },
        .TXT => .{ .txt = rdata },
        else => .{ .unknown = rdata },
    }
}

pub const ResourceRecord = struct {
    name: name_reader.Name = .{},
    type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []const u8,
    section: Section,
};

/// A parsed record plus where the walk resumes — the same shape, and for the
/// same reason, as `name_reader.Read`.
pub const Read = struct {
    record: ResourceRecord,
    next_offset: usize,
};

/// Parses one record at `idx_start`. A free function returning a whole record
/// rather than a method filling out `self`: every field is set in one
/// expression, so there is no window in which a `ResourceRecord` exists
/// half-built and no field needs an `undefined` default to make the caller
/// compile.
pub fn parseRecord(byte_slice: []const u8, idx_start: usize, section: Section) !Read {
    // `readName`, not the no-pointers variant: this is the reply path, where an
    // owner name compressed back to the qname at offset 12 is what every
    // upstream sends, not a protocol violation.
    const read = try name_reader.readName(byte_slice, idx_start);
    const idx = read.next_offset;

    // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) - checked as one block, before any read.
    if (idx + 10 > byte_slice.len) return error.Truncated;
    const rdlength = std.mem.readInt(u16, byte_slice[idx..][8..10], .big);

    const rdata_start = idx + 10;
    // RDLENGTH is upstream's claim about the message, not a fact about it.
    if (rdata_start + rdlength > byte_slice.len) return error.Truncated;

    return .{
        .record = .{
            .name = read.name,
            .type = std.mem.readInt(u16, byte_slice[idx..][0..2], .big),
            .class = std.mem.readInt(u16, byte_slice[idx..][2..4], .big),
            .ttl = std.mem.readInt(u32, byte_slice[idx..][4..8], .big),
            .rdlength = rdlength,
            .rdata = byte_slice[rdata_start..][0..rdlength],
            .section = section,
        },
        // The walk resumes past RData - never at a contained name's next_offset.
        .next_offset = rdata_start + rdlength,
    };
}

pub const ResourceRecordIter = struct {
    msg: []const u8,
    offset: usize,
    /// Records still owed per section, in wire order. Drained left to right.
    remaining: [3]u16,
    section_idx: usize = 0,

    pub fn init(msg: []const u8, offset: usize, header: Header) ResourceRecordIter {
        return .{
            .msg = msg,
            .offset = offset,
            .remaining = .{
                header.answer_count,
                header.authority_record_count,
                header.additional_record_count,
            },
        };
    }

    pub fn next(self: *ResourceRecordIter) !?ResourceRecord {
        // An empty section is normal, not an ending - a reply with ANCOUNT=0
        // and NSCOUNT=1 (NXDOMAIN with a SOA) is the common case, so skip forward
        // rather than stopping.
        while (self.section_idx < 3 and self.remaining[self.section_idx] == 0) {
            self.section_idx += 1;
        }

        if (self.section_idx == 3) {
            // Every declared record consumed. Bytes left over means the framing
            if (self.offset != self.msg.len) return error.CountMismatch;
            return null;
        }

        // Records still owned, no bytes left to pay with.
        if (self.offset >= self.msg.len) return error.CountMismatch;

        const read = try parseRecord(self.msg, self.offset, @enumFromInt(self.section_idx));
        self.offset = read.next_offset;
        self.remaining[self.section_idx] -= 1;
        return read.record;
    }
};

const testing = std.testing;
const blocked_response = @import("blocked_response.zig");

/// A reply shaped like the ones upstreams actually send: `www.example.com` A,
/// answered by a CNAME to `cdn.example.com` and then that name's A record, with
/// an EDNS0 OPT record in Additional. Every owner name is compressed, and the
/// CNAME's RDATA target is compressed too — the shape a hand-built fixture is
/// most likely to get wrong and a real resolver never does.
///
/// Offsets are load-bearing, since the pointers encode them. One field per line
/// so the wire layout stays readable; pinned against `zig fmt`'s column reflow.
// zig fmt: off
const reply_fixture = [_]u8{
    0x12, 0x34,             //  0  ID
    0x81, 0x80,             //  2  QR=1 RD=1 RA=1, NOERROR
    0x00, 0x01,             //  4  QDCOUNT = 1
    0x00, 0x02,             //  6  ANCOUNT = 2
    0x00, 0x00,             //  8  NSCOUNT = 0
    0x00, 0x01,             // 10  ARCOUNT = 1

    3, 'w', 'w', 'w',                     // 12  QNAME: www.example.com
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // 16
    3, 'c', 'o', 'm',                     // 24
    0,                                    // 28
    0x00, 0x01,                           // 29  QTYPE  = A
    0x00, 0x01,                           // 31  QCLASS = IN
                                          // 33  question ends

    // --- Answer 1: CNAME www.example.com -> cdn.example.com ---
    0xC0, 0x0C,             // 33  NAME -> 12 (www.example.com)
    0x00, 0x05,             // 35  TYPE  = CNAME
    0x00, 0x01,             // 37  CLASS = IN
    0x00, 0x00, 0x01, 0x2C, // 39  TTL   = 300
    0x00, 0x06,             // 43  RDLENGTH = 6
    3, 'c', 'd', 'n',       // 45  RDATA: "cdn" + pointer -> 16 (example.com)
    0xC0, 0x10,             // 49

    // --- Answer 2: A record, owner name points into Answer 1's RDATA ---
    0xC0, 0x2D,             // 51  NAME -> 45 (cdn.example.com)
    0x00, 0x01,             // 53  TYPE  = A
    0x00, 0x01,             // 55  CLASS = IN
    0x00, 0x00, 0x00, 0x3C, // 57  TTL   = 60
    0x00, 0x04,             // 61  RDLENGTH = 4
    93, 184, 216, 34,       // 63  RDATA: 93.184.216.34

    // --- Additional: EDNS0 OPT ---
    0,                      // 67  NAME — root label, the byte a walk must not
                            //     mistake for a terminator
    0x00, 0x29,             // 68  TYPE  = OPT (41)
    0x04, 0xD0,             // 70  CLASS — reused as UDP payload size (1232)
    0x00, 0x00, 0x00, 0x00, // 72  TTL   — reused as extended RCODE / flags
    0x00, 0x00,             // 76  RDLENGTH = 0
};                          // 78  message ends
// zig fmt: on

const reply_question_end = 33;

/// NXDOMAIN with an SOA in Authority: ANCOUNT=0, NSCOUNT=1, ARCOUNT=0.
///
/// The SOA is here for one reason — it is the record type where "resume past
/// RDATA" and "resume at the contained name's `next_offset`" give different
/// answers. MNAME is a 2-byte pointer, so a walk that resumed at its
/// `next_offset` would restart 22 bytes early, inside the numeric fields.
/// CNAME cannot catch that bug: its RDATA *is* the name, so both rules
/// coincide.
// zig fmt: off
const nxdomain_fixture = [_]u8{
    0x12, 0x34,             //  0  ID
    0x81, 0x83,             //  2  QR=1 RD=1 RA=1, NXDOMAIN
    0x00, 0x01,             //  4  QDCOUNT = 1
    0x00, 0x00,             //  6  ANCOUNT = 0 — Answer is empty, not the end
    0x00, 0x01,             //  8  NSCOUNT = 1
    0x00, 0x00,             // 10  ARCOUNT = 0

    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // 12  QNAME: example.com
    3, 'c', 'o', 'm',                     // 20
    0,                                    // 24
    0x00, 0x01,                           // 25  QTYPE  = A
    0x00, 0x01,                           // 27  QCLASS = IN
                                          // 29  question ends

    0xC0, 0x0C,             // 29  NAME -> 12 (example.com)
    0x00, 0x06,             // 31  TYPE  = SOA
    0x00, 0x01,             // 33  CLASS = IN
    0x00, 0x00, 0x0E, 0x10, // 35  TTL   = 3600
    0x00, 0x18,             // 39  RDLENGTH = 24
    0xC0, 0x0C,             // 41  MNAME -> 12; its next_offset is 43, but the
                            //     record does not end until 65
    0xC0, 0x0C,             // 43  RNAME -> 12
    0x00, 0x00, 0x00, 0x7B, // 45  SERIAL  = 123
    0x00, 0x00, 0x1C, 0x20, // 49  REFRESH = 7200
    0x00, 0x00, 0x0E, 0x10, // 53  RETRY   = 3600
    0x00, 0x09, 0x3A, 0x80, // 57  EXPIRE  = 604800
    0x00, 0x00, 0x01, 0x2C, // 61  MINIMUM = 300
};                          // 65  message ends
// zig fmt: on

const nxdomain_question_end = 29;

/// Parses `msg`'s header and returns an iterator positioned at the records.
fn walk(msg: []const u8, question_end: usize) ResourceRecordIter {
    var header = Header{};
    header.parseHeader(msg[0..12]);
    return ResourceRecordIter.init(msg, question_end, header);
}

test "the walk yields every declared record, in order, with its section" {
    var it = walk(&reply_fixture, reply_question_end);

    const cname = (try it.next()).?;
    try testing.expectEqualStrings("www.example.com", cname.name.slice());
    try testing.expectEqual(Section.answer, cname.section);
    try testing.expectEqual(@intFromEnum(Type.CNAME), cname.type);
    try testing.expectEqual(@as(u32, 300), cname.ttl);

    const a = (try it.next()).?;
    // Owner name points *into the previous record's RDATA* — legal, and the
    // reason the walk must read names against the whole message.
    try testing.expectEqualStrings("cdn.example.com", a.name.slice());
    try testing.expectEqual(Section.answer, a.section);
    try testing.expectEqual(@intFromEnum(Type.A), a.type);
    try testing.expectEqual(@as(u32, 60), a.ttl);
    try testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, a.rdata);

    const opt = (try it.next()).?;
    try testing.expectEqual(Section.additional, opt.section);

    // Exactly three records, and the walk landed precisely on the last byte.
    try testing.expect((try it.next()) == null);
    try testing.expectEqual(reply_fixture.len, it.offset);
}

test "an OPT record's root owner name does not end the walk" {
    // The bug this guards: RRs have no terminator, so a walk that stops at a
    // zero byte stops at the first OPT record — which sits in Additional in
    // essentially every modern reply, and is usually last, so the walk looks
    // like it works. Here it is reached only by consuming both answers first.
    var it = walk(&reply_fixture, reply_question_end);
    _ = try it.next();
    _ = try it.next();

    const opt = (try it.next()).?;
    try testing.expectEqualStrings("", opt.name.slice());
    try testing.expectEqual(@intFromEnum(Type.OPT), opt.type);
    try testing.expectEqual(@as(u16, 0), opt.rdlength);
    try testing.expectEqual(@as(usize, 0), opt.rdata.len);

    // CLASS and TTL carry EDNS0 fields here, not a class and a lifetime. The
    // walk surfaces them verbatim; recognizing that they mean something else is
    // the caller's job, and folding this TTL into a minimum would produce a
    // number with no meaning.
    try testing.expectEqual(@as(u16, 1232), opt.class);
    try testing.expectEqual(@as(u32, 0), opt.ttl);
}

test "an empty section is skipped, not treated as the end of the records" {
    // ANCOUNT=0 with NSCOUNT=1 — every NXDOMAIN. A walk that stopped on the
    // first exhausted section would return nothing at all here.
    var it = walk(&nxdomain_fixture, nxdomain_question_end);

    const soa = (try it.next()).?;
    try testing.expectEqual(Section.authority, soa.section);
    try testing.expectEqualStrings("example.com", soa.name.slice());
    try testing.expectEqual(@intFromEnum(Type.SOA), soa.type);

    try testing.expect((try it.next()) == null);
}

test "a name inside RDATA advances the walk by RDLENGTH, not by next_offset" {
    // The SOA's MNAME is a pointer at offset 41, so `readName` would report
    // next_offset 43. The record ends at 65. Resuming at 43 would land in the
    // middle of RNAME and desynchronize every record after it — silently, since
    // those bytes still parse as *something*.
    var it = walk(&nxdomain_fixture, nxdomain_question_end);
    const soa = (try it.next()).?;

    try testing.expectEqual(@as(u16, 24), soa.rdlength);
    try testing.expectEqual(@as(usize, 24), soa.rdata.len);

    // The whole RDATA was consumed: the last four bytes are MINIMUM, which is
    // only where it belongs if the walk spanned all 24 octets.
    try testing.expectEqual(@as(u32, 300), std.mem.readInt(u32, soa.rdata[20..24], .big));
    try testing.expectEqual(nxdomain_fixture.len, it.offset);
}

test "RDLENGTH running past the end of the message is Truncated" {
    // RDLENGTH is upstream's claim about the message, not a fact about it: the
    // record declares 512 octets of RDATA in a message that has 4 left.
    // zig fmt: off
    const msg = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // header
        0,                                  // NAME — root
        0x00, 0x01,                         // TYPE  = A
        0x00, 0x01,                         // CLASS = IN
        0x00, 0x00, 0x00, 0x3C,             // TTL
        0x02, 0x00,                         // RDLENGTH = 512
        1, 2, 3, 4,                         // ...and 4 bytes actually present
    };
    // zig fmt: on

    try testing.expectError(error.Truncated, parseRecord(&msg, 12, .answer));
}

test "fixed fields running past the end of the message is Truncated" {
    // The name parses, but TYPE/CLASS/TTL/RDLENGTH need 10 octets and only 3
    // remain. Checked as one block before any of the four is read.
    const msg = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00 };
    try testing.expectError(error.Truncated, parseRecord(&msg, 12, .answer));
}

test "a count larger than the records present is CountMismatch" {
    // ANCOUNT claims 9 answers in a message holding 3 records total. The byte
    // budget stops this, not the count: it must fail on running out of message,
    // not iterate 9 times.
    var msg = reply_fixture;
    std.mem.writeInt(u16, msg[6..8], 9, .big);

    var it = walk(&msg, reply_question_end);
    var yielded: usize = 0;
    while (true) {
        const record = it.next() catch |err| {
            try testing.expectEqual(error.CountMismatch, err);
            break;
        };
        if (record == null) return error.TestUnexpectedResult; // must not end cleanly
        yielded += 1;
        try testing.expect(yielded <= 9);
    }
}

test "bytes left over after the last declared record is CountMismatch" {
    // The counts were satisfied but the message did not end where they said it
    // would. Shrugging at this would mean silently ignoring appended bytes.
    const msg = reply_fixture ++ [_]u8{0xFF};

    var it = walk(&msg, reply_question_end);
    _ = try it.next();
    _ = try it.next();
    _ = try it.next();
    try testing.expectError(error.CountMismatch, it.next());
}

test "walking our own blocked response yields exactly the synthetic SOA" {
    // Reader checked against our own writer rather than against a fixture we
    // also wrote by hand — the same cross-check name_reader.zig ends on. It
    // exercises the RDLENGTH rule again for free: `blocked_response` emits
    // root-label MNAME and RNAME, so their next_offsets are 21 octets short of
    // where the record actually ends.
    const gpa = testing.allocator;

    // zig fmt: off
    const query = [_]u8{
        0x12, 0x34,
        0x01, 0x00, // RD=1
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        3, 'a', 'd', 's',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0,
        0x00, 0x01,
        0x00, 0x01,
    };
    // zig fmt: on
    const question_end = 33;

    const reply = try blocked_response.build(gpa, &query, question_end, .name_error);
    defer gpa.free(reply);

    var it = walk(reply, question_end);

    const soa = (try it.next()).?;
    try testing.expectEqual(Section.authority, soa.section);
    try testing.expectEqual(@intFromEnum(Type.SOA), soa.type);
    try testing.expectEqual(@as(u32, 3600), soa.ttl);
    try testing.expectEqual(@as(u16, 22), soa.rdlength);
    // The owner name is the 0xC00C pointer we wrote, resolving to the qname.
    try testing.expectEqualStrings("ads.example.com", soa.name.slice());

    try testing.expect((try it.next()) == null);
    try testing.expectEqual(reply.len, it.offset);
}

test "fuzz the record walk against arbitrary bytes" {
    // The highest-value test here, for the same reason it was in name_reader:
    // this parser's entire threat model is hostile input, and under ReleaseSafe
    // any out-of-bounds read becomes a crash the fuzzer catches. The assertions
    // are only that the walk terminates and that what it hands back borrows
    // from inside the message — everything about *what* it returns is pinned by
    // the golden vectors above.
    try testing.fuzz({}, fuzzWalk, .{});
}

fn fuzzWalk(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();

    var buf: [512]u8 = undefined;
    const msg = buf[0..smith.slice(&buf)];
    if (msg.len < 12) return;

    var header = Header{};
    header.parseHeader(msg[0..12]);

    var it = ResourceRecordIter.init(msg, smith.index(msg.len + 1), header);
    while (true) {
        const next = it.next() catch break;
        const record = next orelse break;

        // `rdata` must lie wholly inside `msg`, or a caller reading it walks off
        // the datagram.
        try testing.expectEqual(@as(usize, record.rdlength), record.rdata.len);
        const start = @intFromPtr(record.rdata.ptr) - @intFromPtr(msg.ptr);
        try testing.expect(start + record.rdata.len <= msg.len);

        try testing.expect(record.name.len <= name_reader.max_text_len);
        try testing.expect(it.offset <= msg.len);
    }
}
