const std = @import("std");

/// The Header section is a fixed 12 bytes header present in every DNS message.
/// Contains a transaction ID, flags controlling query behavior, and counts
/// for each subsequent section.
pub const Header = packed struct(u96) {
    /// Arbitrary Header ID
    id: u16 = undefined,

    // ===== Flags section =====
    /// Query or Response flag
    qr: u1 = undefined,

    /// A four bit field that specifies kind of query in this message
    opcode: OpCode = undefined,

    /// Authorization Answer
    aa: u1 = undefined,

    /// Truncated - retry over TCP
    tc: u1 = undefined,

    /// Recursion Desired (Client sets this)
    rd: u1 = undefined,

    /// Recursion Available (Server sets this)
    ra: u1 = undefined,

    /// Reserved (Zero)
    z: u3 = 0,

    /// Response Code - this 4 bit field is set as part of responses
    rcode: RCode = undefined,

    /// QCOUNT
    question_count: u16 = undefined,

    /// ANCOUNT
    answer_count: u16 = undefined,

    /// NSCOUNT
    authority_record_count: u16 = undefined,

    /// ARCOUNT
    additional_record_count: u16 = undefined,

    /// OPCODE - This value is set by the originator of a query and copied into the response
    pub const OpCode = enum(u4) {
        // A standard query (QUERY)
        standard_query = 0,

        // An inverse query (IQUERY)
        inverse_query = 1,

        // A server status request (STATUS)
        status_request = 2,

        // Reserved for future use
        _,
    };

    /// Response code - this 4 bit field is set as part of responses.
    pub const RCode = enum(u4) {
        // No error condition.
        no_error = 0,

        // Format error - The name server was unable to interpret the query.
        format_error = 1,

        // Server failure - The name server was unable to process this query.
        server_failure = 2,

        // Name Error - Meaningful only for responses from an authoritative name server.
        name_error = 3,

        // Not implemented - The name server does not support the requested kind of query.
        not_implemented = 4,

        // Refused - The name server refuses to perform the specified operation for policy reasons.
        refused = 5,

        // 6-15 - Reserved for future use.
        _,
    };

    /// Why an inbound datagram is not something we should act on as a query.
    /// One guard for the whole "validate the header before acting on it" family,
    /// so the checks stay together instead of scattering `if`s through `handleQuery`.
    pub const Rejection = enum {
        /// Header is a well-formed query; proceed.
        none,

        /// QR=1 — this is a *response*, not a query. Drop it silently: a server
        /// must never answer a response, and forwarding one upstream would make
        /// us a reflector and burn a PendingTable slot per injected packet.
        is_response,

        /// OPCODE is something other than a standard query (IQUERY, STATUS,
        /// or reserved). Answer NOTIMP — this is a real client asking for
        /// something we don't do, not an attack.
        bad_opcode,

        /// QDCOUNT != 1. `parseQuestion` always reads one question at offset
        /// 12, so anything else means we'd be parsing bytes that aren't a
        /// question. Answer FORMERR.
        bad_qdcount,

        /// Whether this rejection should produce a reply, and with what RCODE.
        /// `null` means drop silently.
        pub fn rcode(self: Rejection) ?RCode {
            return switch (self) {
                .none => null,
                // A server must never answer a response — replying would make
                // us usable as a reflector amplifier.
                .is_response => null,
                .bad_opcode => .not_implemented,
                .bad_qdcount => .format_error,
            };
        }
    };

    /// Header-level validation, run before the question is parsed or any policy
    /// is applied. Pure: inspects the parsed header only, so it is unit-testable
    /// without an `Io` or a socket.
    ///
    /// Order matters. QR is checked first because it is the only rejection that
    /// must **not** generate a reply: a spoofed response with a bogus QDCOUNT
    /// has to stay silent, or we hand an attacker a reflector.
    pub fn validateQuery(self: *const Header) Rejection {
        if (self.qr == 1) return .is_response;
        if (self.opcode != .standard_query) return .bad_opcode;
        if (self.question_count != 1) return .bad_qdcount;
        return .none;
    }

    /// Sets TC=1 on an existing message in place, leaving every other bit alone.
    ///
    /// Separate from `writeResponseFlags` (which clears TC) because this is used
    /// on a message we are *relaying*, not synthesizing: a reply from upstream
    /// that overflowed our receive buffer. TC=1 is the only way to tell the
    /// client "what you're holding is incomplete, ask again over TCP" — without
    /// it they parse a silently corrupt message.
    pub fn markTruncated(msg: []u8) void {
        std.debug.assert(msg.len >= 12);

        var flags = std.mem.readInt(u16, msg[2..4], .big);
        flags |= 1 << 9; // TC=1
        std.mem.writeInt(u16, msg[2..4], flags, .big);
    }

    /// A 12-byte reply built from an ID alone, for when the query bytes are
    /// gone: the sweeper timing out an entry that retains only `client_id` and
    /// `client_addr`.
    ///
    /// Sets QR=1, RD=1, RA=1, the given RCODE, and zero counts. RD is *assumed*
    /// rather than echoed — anything that reached the pending table is a query
    /// we forwarded upstream, which only happens for recursive queries.
    ///
    /// Caveat worth knowing: with QDCOUNT=0 there is no question to match
    /// against, and a strict stub resolver may ignore the reply and fall back to
    /// its own timeout. That is exactly today's behaviour, so this is never
    /// worse — but it can be made strictly correct by storing the question in
    /// `PendingQuery` and echoing it, which is what P1.3's question
    /// verification will put there anyway.
    pub fn synthesizedReply(id: u16, rcode: RCode) [12]u8 {
        var out: [12]u8 = @splat(0);
        std.mem.writeInt(u16, out[0..2], id, .big);
        // QR=1, RD=1, RA=1 (0x8180) plus the RCODE in the low nibble.
        std.mem.writeInt(u16, out[2..4], 0x8180 | @as(u16, @intFromEnum(rcode)), .big);
        return out;
    }

    /// A 12-byte reply carrying nothing but the header: the query's ID, response
    /// flags with `rcode`, and **all four section counts zeroed**.
    ///
    /// Used where the question section cannot be echoed. RFC 1035 §4.1.2 says a
    /// reply should repeat the question, but for `bad_qdcount` whether a
    /// parseable question exists at all is precisely what is in doubt, and for
    /// `bad_opcode` (IQUERY, STATUS) there may be no question section at
    /// all. Zeroing QDCOUNT and sending only the header is what BIND does in the
    /// same spot, and it is the only self-consistent message we can produce.
    ///
    /// Contrast `blocked_response.build`, which *does* echo the question — there
    /// the question is known good, because we parsed it to make the decision.
    pub fn headerOnlyReply(query: []const u8, rcode: RCode) [12]u8 {
        std.debug.assert(query.len >= 12);

        var out: [12]u8 = undefined;
        @memcpy(&out, query[0..12]);
        writeResponseFlags(&out, rcode);

        // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT — no sections follow.
        @memset(out[4..12], 0);
        return out;
    }

    /// Deserialize Header section to little-endian format
    pub fn parseHeader(self: *Header, header_slice: *const [12]u8) void {
        // Read in the Header ID in wire format
        self.*.id = std.mem.readInt(u16, header_slice[0..2], .big);

        // ===== Flags Section =====
        const flags = std.mem.readInt(u16, header_slice[2..4], .big);

        // bit shift 15 to get the first bit then truncate
        self.*.qr = @truncate(flags >> 15);

        // use @enumFromInt to convert the u4 to the OpCode enum
        self.*.opcode = @enumFromInt(@as(u4, @truncate(flags >> 11)));
        self.*.aa = @truncate(flags >> 10);
        self.*.tc = @truncate(flags >> 9);
        self.*.rd = @truncate(flags >> 8);
        self.*.ra = @truncate(flags >> 7);
        self.*.z = @truncate(flags >> 4);

        // use the @enumFromInt to convert u4 type to the RCode enum
        self.*.rcode = @enumFromInt(@as(u4, @truncate(flags)));

        self.*.question_count = std.mem.readInt(u16, header_slice[4..6], .big);
        self.*.answer_count = std.mem.readInt(u16, header_slice[6..8], .big);
        self.*.authority_record_count = std.mem.readInt(u16, header_slice[8..10], .big);
        self.*.additional_record_count = std.mem.readInt(u16, header_slice[10..], .big);
    }

    /// Turns the 12-byte header at the front of `msg` from a query into a
    /// response, in place: QR=1, AA=0, TC=0, RA=1, Z=0, and the given RCODE.
    /// OPCODE and RD are echoed back from the query, as RFC 1035 requires.
    ///
    /// Flags only — the RR counts (bytes 4..12) are the caller's business,
    /// because they differ per reply shape: a blocked answer sets NSCOUNT=1 for
    /// its SOA, while a FORMERR for a bad QDCOUNT can't echo a question section
    /// at all. `blocked_response.build` is the caller for the former.
    pub fn writeResponseFlags(msg: []u8, rcode: RCode) void {
        std.debug.assert(msg.len >= 12);

        var flags = std.mem.readInt(u16, msg[2..4], .big);
        flags |= 1 << 15; // QR=1
        flags &= ~@as(u16, 1 << 10); // AA=0
        flags &= ~@as(u16, 1 << 9); // TC=0
        flags |= 1 << 7; // RA=1
        flags &= ~@as(u16, 0x7 << 4); // Z=0
        flags = (flags & ~@as(u16, 0xF)) | @intFromEnum(rcode);
        std.mem.writeInt(u16, msg[2..4], flags, .big);
    }
};

const testing = std.testing;

/// Builds a 12-byte header on the wire. `flags` is the raw 16-bit flags word so
/// each test can state exactly which bits it is exercising.
fn wireHeader(id: u16, flags: u16, qdcount: u16) [12]u8 {
    var wire: [12]u8 = @splat(0);
    std.mem.writeInt(u16, wire[0..2], id, .big);
    std.mem.writeInt(u16, wire[2..4], flags, .big);
    std.mem.writeInt(u16, wire[4..6], qdcount, .big);
    return wire;
}

test "validateQuery rejects a response (C3 regression)" {
    // QR=1, RD=1, RA=1 — the shape of a real upstream reply arriving at the
    // listen port, either spoofed or via an upstream that loops back to us.
    // QDCOUNT=1 and a well-formed question would follow: the point of this test
    // is that a datagram which parses perfectly as a query is still refused
    // purely on QR. Before this guard existed it was given a proxy ID and
    // forwarded upstream, making Vortex a reflector (next_steps.md P0.C3).
    var wire = wireHeader(0x1234, 0x8180, 1);

    var header = Header{};
    header.parseHeader(&wire);

    try testing.expectEqual(@as(u1, 1), header.qr);
    try testing.expectEqual(Header.Rejection.is_response, header.validateQuery());
}

test "validateQuery accepts an ordinary query" {
    // QR=0, RD=1 — a standard recursive query from a stub resolver.
    var wire = wireHeader(0x1234, 0x0100, 1);

    var header = Header{};
    header.parseHeader(&wire);

    try testing.expectEqual(@as(u1, 0), header.qr);
    try testing.expectEqual(Header.OpCode.standard_query, header.opcode);
    try testing.expectEqual(Header.Rejection.none, header.validateQuery());
}

test "validateQuery keys on QR alone, not the other flags" {
    // A response with every other flag cleared (QR=1 and nothing else) must still
    // be refused; conversely an unusual-looking query (TC=1, AA=1, RCODE!=0) is
    // not this guard's business — QDCOUNT/opcode policing is P4.2.
    var response = wireHeader(0, 0x8000, 0);
    var header = Header{};
    header.parseHeader(&response);
    try testing.expectEqual(Header.Rejection.is_response, header.validateQuery());

    var odd_query = wireHeader(0, 0x0603, 1); // AA=1, TC=1, RCODE=3, QR=0
    header.parseHeader(&odd_query);
    try testing.expectEqual(Header.Rejection.none, header.validateQuery());
}

test "validateQuery rejects non-standard opcodes (P4.2)" {
    var header = Header{};

    // OPCODE occupies bits 11-14. IQUERY (1) and STATUS (2) are real opcodes we
    // don't implement; 15 is reserved. All three earn NOTIMP rather than being
    // parsed as if they carried a standard question.
    for ([_]u16{ 1, 2, 15 }) |opcode| {
        var wire = wireHeader(0, opcode << 11, 1);
        header.parseHeader(&wire);
        try testing.expectEqual(Header.Rejection.bad_opcode, header.validateQuery());
        try testing.expectEqual(Header.RCode.not_implemented, header.validateQuery().rcode().?);
    }

    // Opcode 0 with an otherwise identical header is still fine.
    var standard = wireHeader(0, 0, 1);
    header.parseHeader(&standard);
    try testing.expectEqual(Header.Rejection.none, header.validateQuery());
}

test "validateQuery rejects QDCOUNT != 1 (P4.2)" {
    var header = Header{};

    // parseQuestion unconditionally reads one question at offset 12. QDCOUNT=0
    // means there is nothing there; QDCOUNT>1 means we would silently ignore
    // the rest. Either way we would be acting on bytes we did not validate.
    for ([_]u16{ 0, 2, 65535 }) |qdcount| {
        var wire = wireHeader(0, 0x0100, qdcount);
        header.parseHeader(&wire);
        try testing.expectEqual(Header.Rejection.bad_qdcount, header.validateQuery());
        try testing.expectEqual(Header.RCode.format_error, header.validateQuery().rcode().?);
    }
}

test "validateQuery checks QR before anything that would generate a reply" {
    // The ordering is load-bearing, not incidental. A spoofed *response* that
    // also has a bogus QDCOUNT must be dropped silently — if it came back as
    // `bad_qdcount` we would send a FORMERR to whatever address the attacker
    // forged, which is exactly the reflector P0.C3 closed.
    var wire = wireHeader(0, 0x8000 | (2 << 11), 7); // QR=1, opcode=2, QDCOUNT=7
    var header = Header{};
    header.parseHeader(&wire);

    try testing.expectEqual(Header.Rejection.is_response, header.validateQuery());
    try testing.expect(header.validateQuery().rcode() == null);
}

test "headerOnlyReply echoes the ID and zeroes every section count" {
    // A FORMERR for a query claiming QDCOUNT=3, with a question section that we
    // must not echo because we never validated it.
    var wire = wireHeader(0xBEEF, 0x0100, 3); // RD=1
    const reply = Header.headerOnlyReply(&wire, .format_error);

    try testing.expectEqual(@as(usize, 12), reply.len);
    try testing.expectEqual(@as(u16, 0xBEEF), std.mem.readInt(u16, reply[0..2], .big));

    // QR=1, opcode=0 preserved, AA=0, TC=0, RD=1 preserved, RA=1, Z=0, RCODE=1.
    try testing.expectEqual(@as(u16, 0x8181), std.mem.readInt(u16, reply[2..4], .big));

    // Every count zero — including QDCOUNT, since no question follows.
    try testing.expectEqualSlices(u8, &[_]u8{0} ** 8, reply[4..12]);
}

test "markTruncated sets TC and touches nothing else" {
    // A relayed upstream reply: QR=1, RD=1, RA=1, RCODE=0 — plus real section
    // counts, which must survive since the client needs them to parse what did
    // arrive.
    var wire = wireHeader(0x0A0B, 0x8180, 1);
    std.mem.writeInt(u16, wire[6..8], 9, .big); // ANCOUNT = 9

    Header.markTruncated(&wire);

    // 0x8180 | TC(bit 9) == 0x8380. Asserting the whole word catches a flag
    // clobbered on the way through.
    try testing.expectEqual(@as(u16, 0x8380), std.mem.readInt(u16, wire[2..4], .big));
    try testing.expectEqual(@as(u16, 0x0A0B), std.mem.readInt(u16, wire[0..2], .big));
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, wire[4..6], .big));
    try testing.expectEqual(@as(u16, 9), std.mem.readInt(u16, wire[6..8], .big));

    // Idempotent — a reply that already had TC set stays valid.
    Header.markTruncated(&wire);
    try testing.expectEqual(@as(u16, 0x8380), std.mem.readInt(u16, wire[2..4], .big));
}

test "synthesizedReply builds a reply from an ID alone" {
    // What the sweeper sends when a query times out: it kept the client's ID
    // and address, but the query bytes were freed when handleQuery returned.
    const reply = Header.synthesizedReply(0x1357, .server_failure);

    try testing.expectEqual(@as(usize, 12), reply.len);
    try testing.expectEqual(@as(u16, 0x1357), std.mem.readInt(u16, reply[0..2], .big));

    // QR=1, opcode=0, AA=0, TC=0, RD=1 (assumed), RA=1, Z=0, RCODE=2.
    try testing.expectEqual(@as(u16, 0x8182), std.mem.readInt(u16, reply[2..4], .big));

    // No sections at all — there is no question to echo.
    try testing.expectEqualSlices(u8, &[_]u8{0} ** 8, reply[4..12]);

    // The RCODE is the only thing that varies.
    try testing.expectEqual(
        @as(u16, 0x8180),
        std.mem.readInt(u16, Header.synthesizedReply(0, .no_error)[2..4], .big),
    );
}
