//! EDNS0 (RFC 6891): finding a query's OPT pseudo-record, and writing ours.
//!
//! Pure, like the rest of `dns/`: byte slices in, values out, no `Io`. The
//! datapath calls `find` once per query and then decides three things from the
//! result — whether the query is acceptable at all (a malformed or duplicate OPT
//! is FORMERR, an unknown version is BADVERS), how large a UDP reply the client
//! can take, and which cache partition its answer belongs to.

const std = @import("std");

const Header = @import("header.zig").Header;
const resource_record = @import("resource_record.zig");

/// TYPE 41.
pub const opt_type: u16 = @intFromEnum(resource_record.Type.OPT);

/// The UDP payload size Vortex advertises, and the most it lets a forwarded
/// query advertise on a client's behalf when TCP is available.
///
/// 1232 is the DNS Flag Day 2020 value: the largest payload that fits a
/// 1280-byte IPv6 minimum MTU after headers, so a reply of this size is never
/// IP-fragmented. Fragmented UDP is both lossy and a known cache-poisoning
/// vector. The price is more TC=1 replies, which is only honest because the
/// TCP listener exists for clients to retry against.
pub const advertised_udp_size: u16 = 1232;

/// The size to clamp to when TCP is disabled: our receive buffer. Clamping any
/// lower would produce TC=1 replies that no client can retry.
pub const no_tcp_udp_size: u16 = 4096;

/// RFC 6891 §6.2.3: a requester's payload size below 512 is treated as 512.
pub const min_udp_size: u16 = 512;

/// Bytes in the OPT record `writeOpt` emits: root name, TYPE, CLASS, TTL,
/// RDLENGTH — and no options.
pub const opt_wire_len = 11;

/// What a query's OPT record says, plus where its payload size sits so the
/// forwarded copy can be clamped in place.
pub const Opt = struct {
    udp_size: u16,
    version: u8,
    /// DO — DNSSEC OK (RFC 3225). The top bit of the TTL's flags half.
    do_bit: bool,
    /// Offset of the CLASS field, which is where OPT carries the payload size.
    class_offset: usize,
};

/// The cache partition a query's answer belongs to.
///
/// An answer is shaped by what its requester advertised: a client with no OPT
/// gets no OPT back and at most 512 bytes; a DO client gets RRSIGs. Serving one
/// requester's answer to another would hand a plain client an OPT record it
/// never asked for, or DNSSEC records to one that did not want them.
pub const Class = enum(u8) {
    none,
    plain,
    dnssec,
};

pub fn class(opt: ?Opt) Class {
    const o = opt orelse return .none;
    return if (o.do_bit) .dnssec else .plain;
}

/// The largest UDP reply this client can take.
pub fn replyLimit(opt: ?Opt) usize {
    const o = opt orelse return min_udp_size;
    return @max(o.udp_size, min_udp_size);
}

pub const Error = error{
    /// The records after the question do not parse, or their counts disagree
    /// with the header. The OPT, if any, cannot be located with confidence.
    MalformedRecords,
    /// More than one OPT (RFC 6891 §6.1.1: FORMERR).
    DuplicateOpt,
    /// An OPT outside the additional section, or with a non-root owner name.
    MalformedOpt,
};

/// Finds the query's OPT record, if it has one.
///
/// `records_start` is `parseQuestion`'s return value. Every record after the
/// question is walked, not just the first additional one: a second OPT is only
/// detectable by looking, and a query whose counts do not add up is not one
/// whose OPT we can trust.
pub fn find(msg: []const u8, records_start: usize, header: Header) Error!?Opt {
    var it = resource_record.ResourceRecordIter.init(msg, records_start, header);
    var found: ?Opt = null;

    while (it.next() catch return error.MalformedRecords) |rec| {
        if (rec.type != opt_type) continue;
        if (rec.section != .additional or rec.name.len != 0) return error.MalformedOpt;
        if (found != null) return error.DuplicateOpt;

        // TTL, repurposed: extended RCODE (8) | VERSION (8) | DO (1) | Z (15).
        found = .{
            .udp_size = rec.class,
            .version = @truncate(rec.ttl >> 16),
            .do_bit = (rec.ttl & 0x8000) != 0,
            .class_offset = rec.ttl_offset - 2,
        };
    }
    return found;
}

/// Rewrites the query's advertised payload size to at most `ceiling`, and at
/// least 512, so upstream never sends a reply larger than we are willing to
/// relay over UDP.
pub fn clampInPlace(msg: []u8, opt: Opt, ceiling: u16) void {
    const size = std.math.clamp(opt.udp_size, min_udp_size, ceiling);
    std.mem.writeInt(u16, msg[opt.class_offset..][0..2], size, .big);
}

/// Writes our own OPT record into `out[0..opt_wire_len]`.
///
/// RFC 6891 §7: a responder includes an OPT in its reply exactly when the
/// request had one, and it is *our* OPT — our payload size — not the client's
/// echoed back. DO is copied from the request (RFC 3225 §3). `ext_rcode` is
/// the upper 8 bits of a 12-bit RCODE; nonzero only for BADVERS.
pub fn writeOpt(out: []u8, udp_size: u16, do_bit: bool, ext_rcode: u8) void {
    out[0] = 0; // root owner name
    std.mem.writeInt(u16, out[1..3], opt_type, .big);
    std.mem.writeInt(u16, out[3..5], udp_size, .big);
    out[5] = ext_rcode;
    out[6] = 0; // VERSION 0
    std.mem.writeInt(u16, out[7..9], if (do_bit) 0x8000 else 0, .big);
    std.mem.writeInt(u16, out[9..11], 0, .big); // RDLENGTH: no options
}

const testing = std.testing;

fn headerOf(msg: []const u8) Header {
    var h = Header{};
    h.parseHeader(msg[0..12]);
    return h;
}

// zig fmt: off
/// `a.com A IN` with an EDNS0 OPT: payload 4096, version 0, DO set.
const query_with_opt = [_]u8{
    0x12, 0x34, 0x01, 0x00,
    0, 1, 0, 0, 0, 0, 0, 1,             // QD=1 AR=1
    1, 'a', 3, 'c', 'o', 'm', 0,        // question @12
    0, 1, 0, 1,
    0,                                  // OPT @23: root name
    0, 41,                              // TYPE = OPT
    0x10, 0x00,                         // CLASS = 4096   <- @26
    0x00, 0x00, 0x80, 0x00,             // ext-rcode 0, version 0, DO
    0, 0,                               // RDLENGTH
};
// zig fmt: on
const fixture_records = 23;

test "find reads payload size, version and DO, and locates the size field" {
    const opt = (try find(&query_with_opt, fixture_records, headerOf(&query_with_opt))).?;
    try testing.expectEqual(@as(u16, 4096), opt.udp_size);
    try testing.expectEqual(@as(u8, 0), opt.version);
    try testing.expect(opt.do_bit);
    try testing.expectEqual(@as(usize, 26), opt.class_offset);
    try testing.expectEqual(Class.dnssec, class(opt));
}

test "find returns null for a query without an OPT" {
    const plain = query_with_opt[0..fixture_records].*;
    var msg = plain;
    msg[11] = 0; // ARCOUNT = 0
    try testing.expectEqual(@as(?Opt, null), try find(&msg, fixture_records, headerOf(&msg)));
    try testing.expectEqual(Class.none, class(null));
    try testing.expectEqual(@as(usize, 512), replyLimit(null));
}

test "find reads a nonzero version rather than rejecting it" {
    // BADVERS needs the version to answer with, so `find` reports it and the
    // caller decides. Byte 29 is the VERSION octet.
    var msg = query_with_opt;
    msg[29] = 1;
    const opt = (try find(&msg, fixture_records, headerOf(&msg))).?;
    try testing.expectEqual(@as(u8, 1), opt.version);
}

test "find refuses a second OPT" {
    const opt_rr = query_with_opt[fixture_records..];
    var msg: [query_with_opt.len + opt_rr.len]u8 = undefined;
    @memcpy(msg[0..query_with_opt.len], &query_with_opt);
    @memcpy(msg[query_with_opt.len..], opt_rr);
    msg[11] = 2; // ARCOUNT = 2
    try testing.expectError(error.DuplicateOpt, find(&msg, fixture_records, headerOf(&msg)));
}

test "find refuses an OPT outside the additional section, or with an owner name" {
    // Same bytes, counted as an answer record instead.
    var in_answer = query_with_opt;
    in_answer[7] = 1; // ANCOUNT = 1
    in_answer[11] = 0; // ARCOUNT = 0
    try testing.expectError(error.MalformedOpt, find(&in_answer, fixture_records, headerOf(&in_answer)));

    // An owner name that is not the root: a pointer back to "a.com".
    // zig fmt: off
    const named = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1,
        1, 'a', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
        0xC0, 0x0C, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0,
    };
    // zig fmt: on
    try testing.expectError(error.MalformedOpt, find(&named, fixture_records, headerOf(&named)));
}

test "find refuses records that do not match the header's counts" {
    var msg = query_with_opt;
    msg[11] = 2; // claims two additional records, carries one
    try testing.expectError(error.MalformedRecords, find(&msg, fixture_records, headerOf(&msg)));
}

test "replyLimit floors a tiny advertised size at 512" {
    var opt = (try find(&query_with_opt, fixture_records, headerOf(&query_with_opt))).?;
    try testing.expectEqual(@as(usize, 4096), replyLimit(opt));
    opt.udp_size = 100;
    try testing.expectEqual(@as(usize, 512), replyLimit(opt));
}

test "clampInPlace caps the size at the ceiling and floors it at 512" {
    var msg = query_with_opt;
    const opt = (try find(&msg, fixture_records, headerOf(&msg))).?;

    clampInPlace(&msg, opt, advertised_udp_size);
    try testing.expectEqualSlices(u8, &.{ 0x04, 0xD0 }, msg[26..28]); // 1232

    // Nothing but the two size bytes moved.
    try testing.expectEqualSlices(u8, query_with_opt[0..26], msg[0..26]);
    try testing.expectEqualSlices(u8, query_with_opt[28..], msg[28..]);

    var tiny = opt;
    tiny.udp_size = 100;
    clampInPlace(&msg, tiny, advertised_udp_size);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00 }, msg[26..28]); // 512
}

test "writeOpt emits the exact 11 bytes" {
    var out: [opt_wire_len]u8 = undefined;

    writeOpt(&out, 1232, true, 0);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0 }, &out);

    // BADVERS: extended RCODE 1 in the TTL's top byte, DO clear.
    writeOpt(&out, 1232, false, 1);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 41, 0x04, 0xD0, 1, 0, 0, 0, 0, 0 }, &out);
}

test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Opt);
}
