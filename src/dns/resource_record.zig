const std = @import("std");
const name_reader = @import("name_reader.zig");

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

    pub fn parseRecord(self: *ResourceRecord, byte_slice: []const u8, idx_start: usize) !usize {
        const read = try name_reader.readNameNoPointers(byte_slice, idx_start);
        self.name = read.name;

        var idx = read.next_offset;

        self.type = std.mem.readInt(u16, byte_slice[idx..][0..2], .big);
        self.class = std.mem.readInt(u16, byte_slice[idx..][2..4], .big);
        self.ttl = std.mem.readInt(u32, byte_slice[idx..][4..8], .big);
        self.rdlength = std.mem.readInt(u16, byte_slice[idx..][8..10], .big);
        idx += 10;

        return idx;
    }
};
