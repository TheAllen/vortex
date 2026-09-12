//! Minimal DNS wire encoding and decoding, for the integration harness only.
//!
//! **Deliberately does not import anything from `src/`.** The point of these
//! tests is to check what Vortex puts on the wire, and a harness that built its
//! expectations with `Header.writeResponseFlags` would agree with a byte-swapped
//! implementation of `Header.writeResponseFlags`. Two independent encoders that
//! agree is evidence; one encoder checked against itself is not.
//!
//! That also means this file is allowed to be dumb. It handles exactly the
//! shapes the cases need — one question, uncompressed names, A records — and
//! nothing else. When a case needs more, add it here rather than reaching into
//! `src/dns`.

const std = @import("std");

/// Largest DNS message any case builds or receives. Matches the 4096-byte
//  buffers on both of Vortex's sockets, plus room to exceed them on purpose.
pub const max_message = 8192;

// ── Header field accessors ────────────────────────────────────────────────
//
// Offsets are spelled out rather than named, because RFC 1035 §4.1.1 numbers
// them and a reader checking this against the RFC wants the numbers.

pub fn id(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[0..2], .big);
}

pub fn flags(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[2..4], .big);
}

pub fn qdcount(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[4..6], .big);
}

pub fn ancount(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[6..8], .big);
}

pub fn nscount(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[8..10], .big);
}

pub fn arcount(msg: []const u8) u16 {
    return std.mem.readInt(u16, msg[10..12], .big);
}

pub fn isResponse(msg: []const u8) bool {
    return flags(msg) & 0x8000 != 0;
}

pub fn opcode(msg: []const u8) u4 {
    return @truncate(flags(msg) >> 11);
}

pub fn isTruncated(msg: []const u8) bool {
    return flags(msg) & (1 << 9) != 0;
}

pub fn isRecursionDesired(msg: []const u8) bool {
    return flags(msg) & (1 << 8) != 0;
}

pub fn rcode(msg: []const u8) u4 {
    return @truncate(flags(msg));
}

/// RCODEs the cases assert on. Values from RFC 1035 §4.1.1.
pub const RCode = struct {
    pub const no_error: u4 = 0;
    pub const format_error: u4 = 1;
    pub const server_failure: u4 = 2;
    pub const name_error: u4 = 3;
    pub const not_implemented: u4 = 4;
};

/// QTYPEs the cases use.
pub const Type = struct {
    pub const a: u16 = 1;
    pub const soa: u16 = 6;
    pub const aaaa: u16 = 28;
};

pub const class_in: u16 = 1;

// ── Building queries ──────────────────────────────────────────────────────

pub const QueryOptions = struct {
    qtype: u16 = Type.a,
    qclass: u16 = class_in,
    /// RD. Set on every real stub query, so it is the default here too.
    recursion_desired: bool = true,
    /// QR. Only the "we must never answer a response" case sets this.
    response: bool = false,
    /// OPCODE. Only the IQUERY case sets this.
    opcode: u4 = 0,
    /// QDCOUNT as *written into the header*, which the FORMERR case needs to
    /// disagree with the one question actually encoded below it.
    qdcount: u16 = 1,
    /// Bytes appended after the question. Used to push a datagram past
    /// Vortex's 4096-byte ingress buffer without inventing a record format.
    padding: usize = 0,
};

/// Writes a query into `buf` and returns the slice actually used.
///
/// `name` is in presentation form ("ads.example.com"); the trailing root label
/// is added here.
pub fn query(buf: []u8, msg_id: u16, name: []const u8, opts: QueryOptions) []u8 {
    var flag_word: u16 = 0;
    if (opts.response) flag_word |= 0x8000;
    flag_word |= @as(u16, opts.opcode) << 11;
    if (opts.recursion_desired) flag_word |= 1 << 8;

    std.mem.writeInt(u16, buf[0..2], msg_id, .big);
    std.mem.writeInt(u16, buf[2..4], flag_word, .big);
    std.mem.writeInt(u16, buf[4..6], opts.qdcount, .big);
    @memset(buf[6..12], 0);

    var end: usize = 12;
    end = writeName(buf, end, name);
    std.mem.writeInt(u16, buf[end..][0..2], opts.qtype, .big);
    std.mem.writeInt(u16, buf[end + 2 ..][0..2], opts.qclass, .big);
    end += 4;

    // 'P' rather than 0, so a harness bug that sends the padding where a
    // question is expected shows up as garbage labels instead of a plausible
    // root label.
    @memset(buf[end..][0..opts.padding], 'P');
    end += opts.padding;

    return buf[0..end];
}

/// Encodes `name` as length-prefixed labels at `offset`, terminated by the root
/// label. Returns the offset one past the terminator.
///
/// No compression: a query never contains a pointer, and Vortex's query-path
/// name reader refuses one outright.
pub fn writeName(buf: []u8, offset: usize, name: []const u8) usize {
    var end = offset;
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue; // tolerate a trailing dot
        std.debug.assert(label.len <= 63);
        buf[end] = @intCast(label.len);
        @memcpy(buf[end + 1 ..][0..label.len], label);
        end += 1 + label.len;
    }
    buf[end] = 0;
    return end + 1;
}

// ── Reading the question back ─────────────────────────────────────────────

pub const ParseError = error{
    /// Ran off the end of the message, or hit a compression pointer where an
    /// uncompressed name was required.
    Malformed,
};

/// Offset one past the question section — i.e. what `parseQuestion` returns.
/// Rejects compression pointers, since none of these messages contain one in
/// the question.
pub fn questionEnd(msg: []const u8) ParseError!usize {
    var offset: usize = 12;
    while (true) {
        if (offset >= msg.len) return error.Malformed;
        const len = msg[offset];
        if (len & 0xC0 != 0) return error.Malformed;
        offset += 1 + len;
        if (len == 0) break;
    }
    if (offset + 4 > msg.len) return error.Malformed;
    return offset + 4;
}

/// The question's QNAME in presentation form, written into `out`.
pub fn questionName(msg: []const u8, out: []u8) ParseError![]u8 {
    var offset: usize = 12;
    var written: usize = 0;
    while (true) {
        if (offset >= msg.len) return error.Malformed;
        const len = msg[offset];
        if (len == 0) break;
        if (len & 0xC0 != 0) return error.Malformed;
        if (offset + 1 + len > msg.len) return error.Malformed;
        if (written != 0) {
            out[written] = '.';
            written += 1;
        }
        @memcpy(out[written..][0..len], msg[offset + 1 ..][0..len]);
        written += len;
        offset += 1 + len;
    }
    return out[0..written];
}

// ── Building upstream replies ─────────────────────────────────────────────

pub const ReplyOptions = struct {
    /// TTL on every answer record. The cache case leans on this.
    ttl: u32 = 300,
    rcode: u4 = RCode.no_error,
    /// Answer payload, one A record per address.
    addresses: []const [4]u8 = &.{},
    /// Pad the message out to at least this many bytes with a trailing filler
    /// record, to drive the "upstream reply overflowed our buffer" case.
    /// The filler is a TXT-shaped record whose RDATA is `X` repeated; Vortex
    /// only ever counts bytes here, never interprets them.
    min_len: usize = 0,
};

/// Builds the reply an obedient upstream would send for `q`: the question
/// echoed byte for byte, QR/RA set, and one A record per requested address.
///
/// Echoing the question verbatim is load-bearing, not cosmetic — the dispatcher
/// hashes those exact bytes to decide whether a reply answers its query. The
/// "wrong question" case is precisely this function with the name changed.
pub fn reply(buf: []u8, q: []const u8, opts: ReplyOptions) ParseError![]u8 {
    const q_end = try questionEnd(q);

    @memcpy(buf[0..q_end], q[0..q_end]);

    // QR=1, RD copied from the query, RA=1, plus the RCODE.
    var flag_word: u16 = 0x8000 | (1 << 7) | @as(u16, opts.rcode);
    if (isRecursionDesired(q)) flag_word |= 1 << 8;
    std.mem.writeInt(u16, buf[2..4], flag_word, .big);

    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, buf[6..8], @intCast(opts.addresses.len), .big); // ANCOUNT
    @memset(buf[8..12], 0); // NSCOUNT, ARCOUNT

    var end = q_end;
    for (opts.addresses) |addr| {
        std.mem.writeInt(u16, buf[end..][0..2], 0xC00C, .big); // NAME -> QNAME
        std.mem.writeInt(u16, buf[end + 2 ..][0..2], Type.a, .big);
        std.mem.writeInt(u16, buf[end + 4 ..][0..2], class_in, .big);
        std.mem.writeInt(u32, buf[end + 6 ..][0..4], opts.ttl, .big);
        std.mem.writeInt(u16, buf[end + 10 ..][0..2], 4, .big); // RDLENGTH
        @memcpy(buf[end + 12 ..][0..4], &addr);
        end += 16;
    }

    if (end < opts.min_len) {
        // 12 bytes of record header, so the RDATA carries the rest.
        const rdlen: u16 = @intCast(opts.min_len - end - 12);
        std.mem.writeInt(u16, buf[end..][0..2], 0xC00C, .big);
        std.mem.writeInt(u16, buf[end + 2 ..][0..2], 16, .big); // TXT
        std.mem.writeInt(u16, buf[end + 4 ..][0..2], class_in, .big);
        std.mem.writeInt(u32, buf[end + 6 ..][0..4], opts.ttl, .big);
        std.mem.writeInt(u16, buf[end + 10 ..][0..2], rdlen, .big);
        @memset(buf[end + 12 ..][0..rdlen], 'X');
        end += 12 + rdlen;

        // The filler is an Additional-section record, not an Answer: it is not
        // a well-formed TXT record and nothing should treat it as an answer.
        std.mem.writeInt(u16, buf[10..12], 1, .big); // ARCOUNT
    }

    return buf[0..end];
}

/// The A record's address, read out of the first answer at `offset`.
///
/// Assumes the shape `reply` writes — a two-byte compression pointer for NAME —
/// because that is the only shape a case ever asks about.
pub fn firstAnswerAddress(msg: []const u8, records_start: usize) ParseError![4]u8 {
    if (records_start + 16 > msg.len) return error.Malformed;
    if (std.mem.readInt(u16, msg[records_start..][0..2], .big) != 0xC00C) return error.Malformed;
    if (std.mem.readInt(u16, msg[records_start + 10 ..][0..2], .big) != 4) return error.Malformed;
    return msg[records_start + 12 ..][0..4].*;
}

/// The A record's TTL, read out of the first answer at `records_start`.
pub fn firstAnswerTtl(msg: []const u8, records_start: usize) ParseError!u32 {
    if (records_start + 16 > msg.len) return error.Malformed;
    return std.mem.readInt(u32, msg[records_start + 6 ..][0..4], .big);
}
