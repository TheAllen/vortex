# DNS Message Format

Wire-format reference for the question and answer sections, plus the blocked-path response we synthesize. Pairs with [src/dns/header.zig](../src/dns/header.zig) (the header is already implemented) and roadmap items #1, #2, #3, and #8 in [next_steps.md](next_steps.md).

## Overall packet layout (RFC 1035 §4.1)

A DNS message has a fixed 12-byte header followed by four variable-length sections, in this order:

| Section | Count in header | Notes |
|---|---|---|
| Header | — | 12 bytes, parsed by [src/dns/header.zig](../src/dns/header.zig) |
| Question | `QDCOUNT` (`question_count`) | What's being asked |
| Answer | `ANCOUNT` (`answer_count`) | RRs that answer the question |
| Authority | `NSCOUNT` (`authority_record_count`) | RRs pointing toward an authority |
| Additional | `ARCOUNT` (`additional_record_count`) | "Glue" RRs (often OPT records for EDNS0) |

For a client *query*: `QDCOUNT=1`, the answer/authority counts are 0, and `ARCOUNT` is 0 or 1 (the latter when the client advertises EDNS0 via an OPT record). The blocklist filter only needs to read the question section to make its decision.

## Question section

### Wire layout

A single question is three fields, back to back, no padding:

```
+----------------------------+--------+--------+
| QNAME (variable,            | QTYPE  | QCLASS|
| length-prefixed labels,     | 16-bit | 16-bit|
| ending in a 0x00 byte)      |        |       |
+----------------------------+--------+--------+
```

`QDCOUNT` in the header says how many of these are packed together (always 1 in practice — see "What we ignore" below).

### QNAME — length-prefixed labels

QNAME is *not* a null-terminated C string. Each label is prefixed with a single length byte, and the sequence ends with a length byte of `0`:

```
www.example.com  encodes as:
  03 'w' 'w' 'w'   07 'e' 'x' 'a' 'm' 'p' 'l' 'e'   03 'c' 'o' 'm'   00
  ↑                ↑                                ↑                ↑
  3-byte label    7-byte label                      3-byte label    root
```

Rules:
- Each label length is 1–63 bytes (`0x01`–`0x3F`).
- The top two bits `11` (`0xC0`–`0xFF`) mean **this is a compression pointer**, not a label length — see [next_steps.md item #2](next_steps.md). Queries from clients almost never use compression in QNAME, but responses from upstream do, so the parser must reject pointers in queries and follow them in responses.
- Max total wire length 255 bytes (RFC 1035 §2.3.4).
- Case-insensitive per RFC 1035 §2.3.3 — lowercase before comparing against the blocklist (the StevenBlack hosts list is all lowercase).

### Implementation sketch

The skeleton in [src/dns/question.zig](../src/dns/question.zig) is a stub. The parsing loop already drafted in [next_steps.md item #1](next_steps.md) is the right shape, expanded with bounds checks and the QTYPE / QCLASS tail:

```zig
pub const Question = struct {
    qname: std.ArrayListUnmanaged(u8) = .empty,
    qtype: QType = undefined,
    qclass: QClass = undefined,

    /// Returns the byte offset *after* the question section so the caller can
    /// continue parsing answer / authority / additional sections.
    pub fn parse(
        self: *Question,
        gpa: std.mem.Allocator,
        data: []const u8,
        start: usize,
    ) !usize {
        var idx: usize = start;

        // QNAME — read labels until 0x00 root terminator.
        while (true) {
            if (idx >= data.len) return error.MalformedPacket;
            const len_byte = data[idx];

            if (len_byte == 0) { idx += 1; break; }
            if (len_byte & 0xC0 != 0) return error.UnexpectedCompressionInQuery;
            if (len_byte > 63)        return error.LabelTooLong;
            if (idx + 1 + len_byte > data.len) return error.MalformedPacket;

            if (self.qname.items.len > 0)
                try self.qname.append(gpa, '.');
            for (0..len_byte) |i|
                try self.qname.append(gpa, std.ascii.toLower(data[idx + 1 + i]));
            idx += 1 + len_byte;

            if (self.qname.items.len > 255) return error.QnameTooLong;
        }

        if (idx + 4 > data.len) return error.MalformedPacket;
        self.qtype  = @enumFromInt(std.mem.readInt(u16, data[idx..][0..2], .big));
        self.qclass = @enumFromInt(std.mem.readInt(u16, data[idx + 2..][0..2], .big));
        return idx + 4;
    }
};
```

### Fields we care about

| Field | What we read | Why |
|---|---|---|
| **QNAME** | Yes — full string, lowercased | Sole input to the blocklist lookup. |
| **QTYPE** | Yes — read but don't *gate* on it | Logged; future caching key is `(qname, qtype, qclass)`. The block decision is QNAME-only because filtering A but not AAAA leaks the same domain over IPv6. |
| **QCLASS** | Yes — sanity check only | If not `IN` (1), we still forward but don't bother matching the blocklist — non-IN classes don't carry hostnames in any deployment we care about. |

### Fields and cases we ignore

| Field / case | Behavior |
|---|---|
| `QDCOUNT > 1` | Reject with `RCODE=1` (Format Error). No real client sends multi-question packets; the RFC technically allows it but no resolver implements it correctly. Defensive. |
| `QDCOUNT == 0` | Reject with Format Error. Nothing to do. |
| Compression pointers inside a query's QNAME | Reject with Format Error. Clients don't compress queries (the question section is the first variable-length thing in the message — there's nothing earlier to point at). |
| Trailing bytes after the question section | Allowed — either an OPT record (EDNS0, item #5) or ignored. |
| Unknown QTYPE values | Forwarded as-is. The block decision still runs on QNAME. |

## Answer section (for blocked responses)

A full RR-section parser is roadmap [item #3](next_steps.md) — we don't need it to *block*, only to *forward* normal responses, which today is byte-for-byte relay. This section covers only what we synthesize when a query *is* blocked: the `craftBlockedResponse` function referenced throughout [next_steps.md](next_steps.md) and [async-migration.md](async-migration.md).

### Which sections `craftBlockedResponse` modifies

The whole transformation is a header-only rewrite plus a truncation — no section is built from scratch:

| Section | Modified? | What happens |
|---|---|---|
| **Header** | **Yes — the only section rewritten** | Flags flipped (`QR=1`, `AA=0`, `TC=0`, `RA=1`, `RCODE=3`); `ANCOUNT`/`NSCOUNT`/`ARCOUNT` zeroed. `ID` and `QDCOUNT` are left as-is from the request. |
| **Question** | No — echoed verbatim | RFC 1035 §4.1.1 requires the response to repeat the original question. Not a single byte changes. |
| **Answer** | Not present | NXDOMAIN means "no such name" — there are no answer RRs to add, which is the point of choosing RCODE=3 over an `A 0.0.0.0` sinkhole. |
| **Authority** | Not present | We deliberately skip the RFC 2308 `SOA` record — see the negative-caching caveat below. |
| **Additional** | Dropped | Any client OPT record (EDNS0) is truncated away, matching the zeroed `ARCOUNT`. |

### Strategy: NXDOMAIN

When the QNAME matches the blocklist we respond with `RCODE=3` (Name Error / NXDOMAIN) and *no* answer RRs. The client sees "this name does not exist" and fails fast.

Why NXDOMAIN over `A 0.0.0.0` sinkhole or `REFUSED`:

| Option | Problem |
|---|---|
| `A 0.0.0.0` / `AAAA ::` | NOERROR + null IP. Some clients keep the result in their negative cache *and* keep trying to connect, producing TCP resets instead of clean failures. We'd also need to mint two RRs (one A, one AAAA) and pick a TTL. |
| `REFUSED` (RCODE=5) | Most clients interpret this as "ask a different resolver" and fall back to a secondary in their stack — the block leaks. |
| **NXDOMAIN (RCODE=3)** | Clean "no such name", cached negatively by the client, no further connection attempts. What pi-hole and unbound both do for filtered names. |

### Where retries actually happen

"Won't NXDOMAIN cause retries?" is really three different retry loops. Separating them clarifies why NXDOMAIN wins:

| Retry loop | NXDOMAIN | `A 0.0.0.0` sinkhole | `REFUSED` |
|---|---|---|---|
| **DNS resolver fallback** (client tries a different DNS server) | No — RCODE=3 is definitive | No — RCODE=0 is definitive | **Yes** — clients fall back to a secondary, block leaks |
| **DNS re-query** (client asks us again soon) | Negatively cached per RFC 2308 — see caveat below | Governed by the synthesized A record's TTL | N/A |
| **App-level connect retry** (TCP reconnects to the resolved IP) | No — app sees "host not found" and gives up | **Yes** — app connects to 0.0.0.0, gets RST/timeout, often retries with backoff (browsers, mobile SDKs) | N/A |

Only `REFUSED` triggers resolver-layer fallback, and that's the case where the block actually leaks. Sinkhole's retry pressure is at the *application* layer — annoying for the user, doesn't compromise the filter, but means a misbehaving app can hammer us with re-resolves on every failed connect.

### Negative-caching caveat

RFC 2308 says NXDOMAIN cache duration is governed by the `MINIMUM` field of an `SOA` record in the authority section. `craftBlockedResponse` doesn't add one, so strict resolvers may skip negative caching and re-query us on every connection attempt. Fine for a local filter — we're cheap to re-query, and pi-hole omits the SOA too. If this ever runs as a public/upstream resolver, synthesize a stub SOA pointing at ourselves with a small `MINIMUM` (e.g. 300s) so downstream caches hold the answer.

### Wire-format steps to build the response

Given the request bytes `query` and `Header` already parsed, the response is built **in place** by mutating bytes 0..12 and truncating the buffer to `header + question` (we don't add any RRs). The question section is echoed verbatim — RFC 1035 §4.1.1 requires the response to repeat the original question.

```
Request                 →  Response (NXDOMAIN)
┌──────────────────┐       ┌──────────────────┐
│ Header (12B)     │       │ Header (12B)     │  flip flags + RCODE
│   QR=0           │       │   QR=1           │
│   RD=1           │       │   RD=1 (echoed)  │
│   RA=0           │       │   RA=1           │
│   RCODE=0        │       │   RCODE=3        │
│   QDCOUNT=1      │       │   QDCOUNT=1      │
│   ANCOUNT=0      │       │   ANCOUNT=0      │
│   NSCOUNT=0      │       │   NSCOUNT=0      │
│   ARCOUNT=0/1    │       │   ARCOUNT=0      │
├──────────────────┤       ├──────────────────┤
│ Question         │       │ Question         │  echoed unchanged
│   QNAME/TYPE/    │       │   QNAME/TYPE/    │
│   CLASS          │       │   CLASS          │
├──────────────────┤       └──────────────────┘
│ (optional OPT)   │           ← truncated; no RRs
└──────────────────┘
```

Concretely, the flag bits to flip in the 16-bit flags word at bytes 2..4:

| Bit(s) | Position | Set to |
|---|---|---|
| `QR` | bit 15 | `1` (this is a response) |
| `AA` | bit 10 | `0` (we are not authoritative) |
| `TC` | bit 9 | `0` (not truncated; response fits in UDP) |
| `RD` | bit 8 | echo client's value |
| `RA` | bit 7 | `1` (we offer recursion) |
| `Z`  | bits 4–6 | `0` (reserved, must be zero) |
| `RCODE` | bits 0–3 | `3` (Name Error) |

The transaction `ID` is already correct from the request, and `QDCOUNT` stays at 1. `ANCOUNT`/`NSCOUNT`/`ARCOUNT` get zeroed — leaving the request's `ARCOUNT=1` (EDNS0) in place would lie to the client about an OPT record we're not echoing.

### Implementation sketch

```zig
/// Returns the length of the response (always ≤ query.len). Mutates `query`
/// in place: flips the response flags, sets RCODE=3, and zeros the RR counts.
/// Buffer ownership stays with the caller; send `query[0..len]`.
pub fn craftBlockedResponse(query: []u8, question_end: usize) usize {
    var flags = std.mem.readInt(u16, query[2..4], .big);
    flags |= 1 << 15;                     // QR=1
    flags &= ~@as(u16, 1 << 10);          // AA=0
    flags &= ~@as(u16, 1 << 9);           // TC=0
    flags |= 1 << 7;                      // RA=1
    flags &= ~@as(u16, 0x7 << 4);         // Z=0
    flags = (flags & ~@as(u16, 0xF)) | 3; // RCODE=3 (NXDOMAIN)
    std.mem.writeInt(u16, query[2..4], flags, .big);

    // Zero ANCOUNT / NSCOUNT / ARCOUNT (bytes 6..12). QDCOUNT (4..6) stays.
    @memset(query[6..12], 0);

    // Truncate: header (12) + question section. Drops any OPT record.
    return question_end;
}
```

`question_end` is the offset returned by `Question.parse` above. The handler then sends `query[0..len]` to the client.

### Why mutate in place

The buffer arrived via `gpa.dupe(u8, msg.data)` in `main.zig` (see [async-migration.md](async-migration.md) Pattern 1), so the handler already owns it. Allocating a second buffer for the response would double allocations on the hot path. Truncating the length on `send` is cheap and the leftover bytes never travel.

### Where this slots into the handler

In `handleQuery` (Shape A in [async-migration.md](async-migration.md) Pattern 2):

```zig
var question: Question = .{};
defer question.qname.deinit(gpa);
const q_end = question.parse(gpa, query, 12) catch return;

if (ctx.blocklist.contains(question.qname.items)) {
    const len = craftBlockedResponse(query, q_end);
    ctx.client_sock.send(io, &client_addr, query[0..len]) catch {};
    return;
}
// ... forward path ...
```

## Error handling

Every read past `data.len` is `error.MalformedPacket`. The handler logs and drops — never panic, never echo back a half-built reply. This is the contract roadmap [item #8](next_steps.md) asks for.

| Condition | Outcome |
|---|---|
| Header < 12 bytes | Drop silently — there's no valid ID to respond against. |
| QNAME length byte points past `data.len` | `error.MalformedPacket`, drop. |
| Compression pointer in a query QNAME | `error.UnexpectedCompressionInQuery`, drop. |
| Label length > 63 | `error.LabelTooLong`, drop. |
| QNAME total length > 255 | `error.QnameTooLong`, drop. |
| `QDCOUNT != 1` | Respond with `RCODE=1` (Format Error), same flag-flip pattern as the NXDOMAIN path. |
| Trailing bytes after the question section | Allowed — leave them alone on forward, truncate them on synthesized response. |

## Cross-references

- [src/dns/header.zig](../src/dns/header.zig) — header parser (done)
- [src/dns/question.zig](../src/dns/question.zig) — question parser (stub; this doc specifies it)
- [next_steps.md item #1](next_steps.md) — multi-label QNAME parsing
- [next_steps.md item #2](next_steps.md) — compression pointer handling (responses only)
- [next_steps.md item #3](next_steps.md) — answer-section parser (needed for caching, not blocking)
- [next_steps.md item #8](next_steps.md) — defensive bounds-checking on parsing
- [async-migration.md](async-migration.md) — where `craftBlockedResponse` slots into the blocked path (Pattern 2)
- [upstream-design.md](upstream-design.md) — what happens to non-blocked queries
