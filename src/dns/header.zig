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

    question_count: u16 = undefined,
    answer_count: u16 = undefined,
    authority_record_count: u16 = undefined,
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

        // P4.2 extends this: `bad_qdcount` (QDCOUNT != 1) and `bad_opcode`
        // (non-standard OPCODE). Unlike `is_response` those are real queries
        // from a real client, so they warrant a FORMERR/NOTIMP reply rather
        // than a silent drop — see next_steps.md P4.2.
    };

    /// Header-level validation, run before the question is parsed or any policy
    /// is applied. Pure: inspects the parsed header only, so it is unit-testable
    /// without an `Io` or a socket.
    pub fn validateQuery(self: *const Header) Rejection {
        if (self.qr == 1) return .is_response;
        return .none;
    }

    /// Deserialize Header section to little-endian format
    pub fn parseHeader(self: *Header, header_slice: *[12]u8) void {
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
