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
