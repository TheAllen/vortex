# DNS Message Format

Wire-format reference for the question, compression, and resource-record formats, plus the blocked-path response we synthesize. The header ([src/dns/header.zig](../src/dns/header.zig)), the question parser ([question.zig](../src/dns/question.zig)), the name reader ([name_reader.zig](../src/dns/name_reader.zig), P3.1) and the blocked response ([blocked_response.zig](../src/dns/blocked_response.zig)) are implemented; the resource-record walk is [P3.2](next_steps.md#p32-in-detail--parsing-upstream-response-records) and is not.

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
- The top two bits `11` (`0xC0`–`0xFF`) mean **this is a compression pointer**, not a label length — see [Compression pointers](#compression-pointers-rfc-1035-414) below. Queries from clients almost never use compression in QNAME, but responses from upstream do, so the parser rejects pointers in queries and follows them in responses.
- Max total wire length 255 bytes (RFC 1035 §2.3.4).
- Case-insensitive per RFC 1035 §2.3.3 — lowercase before comparing against the blocklist (the StevenBlack hosts list is all lowercase).

## Compression pointers (RFC 1035 §4.1.4)

Implemented in [src/dns/name_reader.zig](../src/dns/name_reader.zig) (P3.1, landed
2026-08-13). Reading a name is its own concern, shared by the question parser and — from
P3.2 onwards — the resource-record walk, so it lives in one module rather than inside
either caller.

A pointer is two bytes: `11` in the top two bits, then a 14-bit offset from the **start of
the message**. It means "the rest of this name is the name at that offset."

```
0xC0 0x0C  →  11 000000 00001100  →  offset 12
   ↑              ↑        ↑
   type bits      high 6   low 8
```

So every length byte is one of three things, decided by its top two bits:

| Top 2 bits | Meaning | Action |
|---|---|---|
| `00` | label, length 0–63 (`0` = root) | copy the bytes; `0` ends the name |
| `11` | compression pointer | jump to the target offset |
| `01` / `10` | reserved, never assigned | `error.ReservedLabelType` |

### `next_offset` is not where the name ended

This is the whole subtlety of the format. When a pointer is followed, the *name* continues
at the target, but the *message* continues **2 bytes past the pointer**. `readName` returns
both in one struct so a caller cannot conflate them.

Take a message whose question name `example.com` sits at offset 12, with a later record
naming `www.example.com` via partial compression:

```
12: 07 'e''x''a''m''p''l''e'   20: 03 'c''o''m'   24: 00   25: qtype   27: qclass
31: 03 'w''w''w'               35: C0 0C          37: <the next field starts here>
```

`readName(msg, 31)`:

| pos | byte | what happens | name so far |
|---|---|---|---|
| 31 | `03` | label `www` | `www` |
| 35 | `C0 0C` | target 12 < 35 ✓ → **`next_offset = 37`**, jump | `www` |
| 12 | `07` | label `example` | `www.example` |
| 20 | `03` | label `com` | `www.example.com` |
| 24 | `00` | root; name ends | `www.example.com` |

The name's bytes ended at 25 — inside the question section, which is *not* where the record
stream resumes. A walk that resumed there would desynchronize silently.

### Termination: strictly backwards, plus a jump cap

Every pointer must target an offset **strictly less than the pointer's own offset**. RFC
1035 compression *is* a backreference to a name already emitted, so this costs nothing in
compatibility, and it kills self-reference (`0xC00C` at offset 12), forward pointers,
A→B→A ping-pong, and out-of-range targets under a single O(1) rule — no visited set to
allocate, no arbitrary depth constant to justify.

That rule alone does **not** bound the loop, which is worth stating because it is easy to
assume otherwise: `63 'a'… 0xC0 0x00` read from the pointer goes strictly backwards on
every hop and still cycles forever. Chains that emit bytes are stopped by the 255-octet
length cap; chains that emit none — pointer straight to pointer — are stopped by
`max_jumps = 64`. Both bounds are load-bearing.

### Two entry points

Whether a pointer is legal is a property of *where in the protocol you are*, not of the
parser:

| Function | Used by | On a pointer |
|---|---|---|
| `readNameNoPointers` | `Question.parseQuestion` — the client's query | `error.UnexpectedCompressionInQuery` |
| `readName` | [P3.2's record walk](#resource-records-rfc-1035-43) — upstream's reply | follow it |

### Storage

`Name` is a fixed 253-byte inline buffer, no allocator. 255 octets is the wire cap; text
form spends each label's length byte on a `.` separator instead — except the last — and
drops the root byte, so a W-octet wire name is exactly W−2 characters of text. 253 is the
wire cap restated, not a second limit.

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

## Resource records (RFC 1035 §4.3)

The Answer, Authority and Additional sections are all the same thing: a flat stream of
resource records, `ANCOUNT + NSCOUNT + ARCOUNT` of them, back to back with no framing
between sections. You know which section a record is in only by counting.

Parsing them is **P3.2** ([plan](next_steps.md#p32-in-detail--parsing-upstream-response-records)) —
not needed to *block*, needed to read TTLs, log answers, and eventually cache. Today
`dispatcherLoop` relays these bytes without looking at them.

### Wire layout

```
+--------------------+--------+--------+--------+----------+---------------+
| NAME (variable,    | TYPE   | CLASS  | TTL    | RDLENGTH | RDATA         |
| labels or pointer) | 16-bit | 16-bit | 32-bit | 16-bit   | RDLENGTH bytes|
+--------------------+--------+--------+--------+----------+---------------+
```

The name is both the **first** field and the **variable-length** one, which is why nothing
in a record — not the TYPE, not the TTL, not the step to the next record — is reachable
without a name reader. A record is at least 11 octets: a root-label name (1) plus the ten
bytes of fixed fields.

### Walking the stream

| Step | Rule |
|---|---|
| Where it starts | One past the question section. In a reply Vortex forwards, that offset is already known and verified — see [P3.2's plan](next_steps.md#p32-in-detail--parsing-upstream-response-records) |
| Read the owner name | `readName` — pointers are the normal case here, not an error |
| Advance past the name | `readName`'s `next_offset` |
| Read the fixed fields | TYPE, CLASS, TTL, RDLENGTH at `next_offset`, big-endian |
| **Advance past RDATA** | `rdata_start + RDLENGTH` — **never** the `next_offset` of a name read inside RDATA |
| When to stop | After the declared record count, which must land exactly on the end of the message |

### The RDATA-name trap

A CNAME, NS, PTR or MX target inside RDATA is a name, and usually a compressed one. It is
read against the **whole message** — a pointer in RDATA may target any earlier offset,
which the strictly-backwards rule accommodates — but the *record walk* resumes at
`rdata_start + RDLENGTH`, not where that name's `next_offset` says. Both values are
legitimate; using the wrong one desynchronizes the stream on every compressed RDATA and
produces garbage records rather than an error. This is the same `next_offset` subtlety as
[above](#next_offset-is-not-where-the-name-ended), in the one place `Read` cannot disambiguate
for the caller.

### OPT is not a normal record (RFC 6891)

An EDNS0 OPT record is a resource record structurally and a header extension semantically.
It reuses two fields for entirely different purposes:

| Field | In a normal RR | In OPT (TYPE 41) |
|---|---|---|
| NAME | The owner name | Always root (`0x00`) |
| CLASS | `IN` (1) | The requestor's UDP payload size (e.g. 4096) |
| TTL | Seconds the record may be cached | Extended RCODE, EDNS version, and the DO bit |
| RDATA | Type-specific data | `{code, length, data}` option triples |

So an OPT record must be recognized by type and excluded from any TTL aggregate — folding
its TTL field into a minimum yields whatever those flag bits happened to encode. This
applies from the first line of P3.2, not from P3.5: replies carrying an OPT record arrive
today.

### TTL semantics

| Case | Which TTL governs |
|---|---|
| Positive answer | The minimum TTL across the records actually answering the question |
| Negative answer (NXDOMAIN/NODATA) | `min(SOA.MINIMUM, the SOA record's own TTL)` — RFC 2308 §5 |
| OPT | None. Not a cacheable record |

### Types worth decoding first

| TYPE | Name | RDATA | Why |
|---|---|---|---|
| 1 | `A` | 4 bytes, IPv4 | The answer, for logging |
| 28 | `AAAA` | 16 bytes, IPv6 | Same, and the reason blocking is QNAME-only rather than per-qtype |
| 5 | `CNAME` | one name | The alias chain — and the vector for CNAME-cloaked trackers |
| 6 | `SOA` | 2 names + 5 × 32-bit | `MINIMUM` governs negative caching; we already *write* one ([authority.zig](../src/dns/authority.zig)) |
| 41 | `OPT` | option triples | Must be identified so it can be excluded, even before EDNS0 is implemented |

Everything else is walked past by RDLENGTH without being interpreted.

## Answer section (for blocked responses)

A full RR-section parser is **P3.2** ([above](#resource-records-rfc-1035-43)) — we don't need it to *block*, only to *forward* normal responses, which today is byte-for-byte relay. This section covers only what we synthesize when a query *is* blocked: the `craftBlockedResponse` function referenced throughout [next_steps.md](next_steps.md) and [async-migration.md](async-migration.md).

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

Every malformed name is an error value. The handler logs and drops — never panic, never echo
back a half-built reply. This is the contract roadmap [item #8](next_steps.md) asks for.

Name errors are `name_reader.NameError`, raised identically on both paths; the rest are the
question parser's own.

| Condition | Outcome |
|---|---|
| Header < 12 bytes | Drop silently — there's no valid ID to respond against. |
| QNAME length byte or label body runs past `data.len` | `error.Truncated`, drop. |
| Compression pointer in a query QNAME | `error.UnexpectedCompressionInQuery`, drop. |
| Length byte with a `01`/`10` prefix | `error.ReservedLabelType`, drop. |
| Pointer that is not strictly backwards, or a chain over 64 hops | `error.BadPointer`, drop. |
| QNAME total wire length > 255 | `error.NameTooLong`, drop. |
| QTYPE/QCLASS not fully present after the name | `error.Truncated`, drop. |
| `QDCOUNT != 1` | Respond with `RCODE=1` (Format Error), same flag-flip pattern as the NXDOMAIN path. |
| Trailing bytes after the question section | Allowed — leave them alone on forward, truncate them on synthesized response. |

A label length above 63 is not a separate error: the top two bits make it either a pointer
or a reserved type, so it is already covered by the two rows above.

### Record-walk errors are different: log, then relay anyway

The table above is about *queries*, where a parse failure means the request is unusable and
dropping is the only honest answer. A malformed **reply** is not the same situation: the
client asked a question, upstream answered it, and the answer has already passed the
anti-spoofing checks. P3.2 parses those records to *observe* them, so a failure there is
logged and the reply is relayed byte-for-byte regardless.

| Condition | Outcome |
|---|---|
| Reply's records are truncated (TC / oversized datagram) | Skip the walk — the records are known-incomplete. Relay, with TC set |
| Reply's `QDCOUNT != 1` | Skip the walk — the record stream is not where we computed it to be. Relay |
| RR fixed fields or RDATA run past the message | `error.Truncated`, log, relay |
| Declared record count does not match the bytes present | `error.CountMismatch`, log, relay |
| Any `NameError` reading an owner name or an RDATA name | Log, relay |

That changes once records are *stored* rather than logged: a reply that cannot be parsed
cannot be cached (P3.3), and one whose records are out of bailiwick must not be.

## Cross-references

- [src/dns/header.zig](../src/dns/header.zig) — header parser (done)
- [src/dns/question.zig](../src/dns/question.zig) — question parser (done)
- [src/dns/name_reader.zig](../src/dns/name_reader.zig) — name reader with compression pointer following (done, P3.1)
- [next_steps.md P3.2 in detail](next_steps.md#p32-in-detail--parsing-upstream-response-records) — resource-record walk: the plan, the decisions, and what is deliberately out of scope (`resource_record.zig` / `resource_data.zig` do not exist yet)
- [next_steps.md item #8](next_steps.md) — defensive bounds-checking on parsing
- [async-migration.md](async-migration.md) — where `craftBlockedResponse` slots into the blocked path (Pattern 2)
- [upstream-design.md](upstream-design.md) — what happens to non-blocked queries
