# Changelog — what landed, and why it is shaped that way

Split out of [next_steps.md](next_steps.md) on 2026-08-19, which had grown to the point
where the history crowded out the board. **Nothing here is a to-do.** Entries are kept in
full because each records *why* a fix is shaped the way it is and what now keeps it that
way — the reasoning is the reason these are worth keeping, not the fact that they happened.

Newest first. Open work lives in [next_steps.md](next_steps.md).

---

## Landed 2026-08-13 — P3.1 compression pointer following

Planned 2026-08-11, built 2026-08-13. The plan is kept below as written, with a
[what actually shipped](#what-actually-shipped) note at the end recording the three places
reality diverged from it. Everything else landed as specified. The rationale is retained
in full because **P3.2 and P3.3 both build directly on its decisions.**

### Why this matters

*(Written before the build.)* Today Vortex only ever *writes* a pointer —
`Authority.NAME = 0xC00C` ([authority.zig:5](../src/dns/authority.zig#L5)) — and *rejects*
them on read, since `parseQuestion`'s `label_len > 63` check catches `0xC0` on the way past.
Nothing in the process can follow one.

**This is a reading capability, not a writing one, and it pays for nothing we do today.**
Blocked responses carry no answer section at all — that is the point of NXDOMAIN over a
`0.0.0.0` sinkhole — and on the forward path `dispatcherLoop` relays upstream's bytes
verbatim, rewriting only the transaction ID and TC on overflow. Upstream already did the
compressing. Land P3.1 on its own and **every existing behavior is byte-for-byte
identical**; the value is entirely in what it unblocks:

- **Caching (P3.3), the real prize.** Correct caching needs the TTL, and the TTL lives
  inside each RR behind a name: `NAME (variable) │ TYPE 2 │ CLASS 2 │ TTL 4 │ RDLENGTH 2 │
  RDATA`. The name is both the *first* field and the *variable-length* one, so every read of
  a TTL — and every step to the next record — begins by getting past a name. The dodge is
  caching the whole datagram under a fixed TTL, which breaks DNS-based failover and
  round-robin load balancing in ways that are miserable to diagnose from the client side.
- **CNAME cloaking — a real blocking gap, not just plumbing.** Trackers defeat QNAME-only
  blocklists by pointing `metrics.example.com` at `tracker.adnetwork.net` via CNAME.
  `Policy` decides on the question name alone, so Vortex forwards the query and hands the
  client the tracker's address. Closing that means reading the CNAME target out of the
  answer's RDATA, and that target is itself a name — usually a compressed one.
- **Per-query logs that name the answer.** Resolved IPs and the CNAME chain are the half of
  P2.3 that makes the query log usable for debugging rather than just for auditing.
- **Not poisoning our own cache.** The moment responses are cached, answer RRs have to be
  checked as in-bailiwick instead of stored because upstream volunteered them. That check
  compares names, which means resolving them.

**One distinction the rest of this section leans on.** *Recognizing* a pointer is enough to
**skip** a name — see `0xC0`, add 2, move on — and that alone walks the record stream to
TYPE/TTL/RDLENGTH. *Following* one is what yields the name's **value**, needed for CNAME
targets, bailiwick checks, and logging. So P3.2 could technically reach TTLs on recognition
alone; following is what makes the records mean anything. Both are the same sixty lines of
reader, so splitting them would be false economy — but "prerequisite for parsing the answer
section" is a slight overstatement of the dependency, and worth knowing which half you are
relying on when P3.2 gets written.

**New file: `src/dns/name_reader.zig`.** Not `domain_name.zig` — that is a growable byte
buffer, a different job — and not `resource_record.zig`, which does not exist and is P3.2's
file. Reading a name out of a message is its own concern, and it is the piece both P3.2 and
P3.3 sit on.

### API

```zig
pub const Name = struct {
    buf: [255]u8 = undefined,
    len: u8 = 0,
    pub fn slice(self: *const Name) []const u8;
};

pub const Read = struct { name: Name, next_offset: usize };

/// Reads a name at `offset`, following compression pointers.
pub fn readName(msg: []const u8, offset: usize) NameError!Read;

/// Query-path variant: a pointer is a protocol violation, not a hop.
pub fn readNameNoPointers(msg: []const u8, offset: usize) NameError!Read;
```

Two decisions worth pinning here, because they are the expensive-to-reverse ones:

**No allocator.** A name is at most 255 octets (RFC 1035 §2.3.4), so a fixed inline buffer
is exactly sized, cannot leak, and keeps the allocator off the response path — which starts
to matter at P3.2 (once per RR) and P3.3 (once per cache lookup). `Question` currently owns
an `ArrayList` through `DomainName`; the refactor below drops it.

**`next_offset` is not "where the name ended."** This is the whole subtlety of the format:
when a pointer is followed, parsing resumes **2 bytes past the pointer**, not past the
target name. Returning both in one struct is what makes it impossible for a caller to get
that wrong — the reason the signature is not just `[]const u8`.

### Loop protection: strictly-backwards, not a depth counter

Every pointer must target an offset **strictly less than the offset of the pointer itself**.
That one invariant makes termination provable with O(1) state — no visited set to allocate,
no arbitrary depth constant to justify — and costs nothing in compatibility, because RFC
1035 compression *is* a backreference to a name already emitted. It kills self-reference
(`0xC00C` sitting at offset 12), forward pointers, and A→B→A ping-pong under a single rule.

On top of it, `max_jumps = 64`. A pointer-to-pointer chain emits no bytes, so it is not
bounded by the 255-octet cap the way a chain of partial names is; the ordering rule alone
bounds it only by message length. Unreachable in any real message — it exists so the loop
bound does not rest solely on the ordering argument.

### Validation, in reading order

| Condition | Error |
|---|---|
| `offset >= msg.len` at any step | `Truncated` |
| Length byte `& 0xC0` is `0x40` or `0x80` | `ReservedLabelType` |
| Label body runs past `msg.len` | `Truncated` |
| Pointer's second byte missing | `Truncated` |
| Pointer target `>=` the pointer's own offset | `BadPointer` (covers self, forward, cycle) |
| Jumps exceed 64 | `BadPointer` |
| Decoded wire length exceeds 255 | `NameTooLong` |
| Any pointer at all, in the no-pointer variant | `UnexpectedCompressionInQuery` |

Lowercase while decoding, for the reason already given at
[question.zig](../src/dns/question.zig) — filter lookups and the future cache key both want
the canonical form.

### Refactor `question.zig` onto it

`parseQuestion` becomes `readNameNoPointers(msg, 12)` followed by QTYPE/QCLASS at
`next_offset`, deleting the hand-rolled label loop and the `DomainName` field. Two things
fall out of that: the hard-coded start offset of 12 becomes a parameter (P3.2 needs to parse
questions inside *responses*), and the `idx - 12 > 255` length check moves inside the reader,
where it is measured against the right origin rather than against a constant that happens to
be the header size.

The existing case-normalization test should pass **unchanged** — that is the signal the
refactor preserved behavior. `error.UnsupportedLabel` and `error.TruncatedQuestion` are
named in `main.zig`'s drop path, so either keep the names or update both sites in the same
commit.

### Tests

The format is bytes, so these are golden byte vectors. Not one table-driven test — each of
these fails differently, and the point is to know which one broke:

- Uncompressed name → text plus `next_offset` past the root byte
- Pure pointer (`0xC00C` as the whole name) → the target's name, `next_offset` = pointer + 2
- **Partial compression** — `3 'w' 'w' 'w' 0xC0 0x0C` → `www.example.com`. The case that
  actually shows up in real upstream replies
- Two-hop chain → resolves
- Self-pointer at its own offset → `BadPointer`
- Forward pointer → `BadPointer`
- A→B, B→A → `BadPointer`
- Target past `msg.len` → `BadPointer`
- Bare `0xC0` as the final byte → `Truncated`
- `0x40` / `0x80` length byte → `ReservedLabelType`
- Root-only name (`0x00`) → empty, `next_offset` = offset + 1
- Chained partial compression expanding past 255 → `NameTooLong`
- **Round trip against our own writer** — run `readName` over a message built by
  `blocked_response.build` and assert the SOA's owner name comes back as the qname. Checks
  the reader against the one pointer Vortex already emits

Then a fuzz target (`std.testing.fuzz`) over arbitrary bytes, asserting only that it
terminates and returns. That is the highest-value test in the list: the entire threat model
of this function is hostile input, and under ReleaseSafe any out-of-bounds read becomes a
clean crash the fuzzer catches. It also lands in the one place this project's testing lesson
applies cleanly — a pure function over a byte slice, no `Io` anywhere near it.

### Explicitly out of scope

- **Writing** compression. We synthesize exactly one pointer, by hand, and it is correct. A
  general compressor only earns its keep if local records (P4.1) start emitting multi-RR
  answers.
- **Wiring into `dispatcherLoop`.** P3.1 ships as a tested pure module with no caller. The
  datapath change belongs to P3.2, and mixing the two makes both harder to review.

### What actually shipped

`zig build test` → **59/59 pass**, `zig build` green. Three divergences from the plan above,
each because building it made something visible that planning it did not:

1. **The strictly-backwards rule does not bound the loop on its own.** The plan claimed it
   "makes termination provable with O(1) state" and cast `max_jumps = 64` as belt-and-braces
   for pointer-to-pointer chains. It is not: `63 'a'… 0xC0 0x00`, read starting at the
   pointer, goes strictly backwards on every hop and cycles forever, emitting a label each
   time. Termination rests on **two** bounds — the length cap stops chains that emit bytes,
   `max_jumps` stops chains that do not — and `max_jumps` is load-bearing, not decorative.
   Recorded in a comment at its definition so the next reader does not re-derive it.
2. **The buffer is 253 bytes, not 255.** The 255-octet cap is a *wire* length; text form
   spends each label's length byte on a `.` except the last, and drops the root byte, so a
   W-octet wire name is exactly W−2 characters. 253 is that cap restated in the module's own
   units, which makes the bound checkable against the buffer directly instead of maintaining
   a second wire-length counter alongside it.
3. **No error-name coordination was needed.** The plan warned that `error.UnsupportedLabel`
   and `error.TruncatedQuestion` were "named in `main.zig`'s drop path". They were not —
   `main.zig` only formats `@errorName(err)`, so no site outside `question.zig` referenced
   either. The whole error set is now `NameError`, and the drop log gained more precise names
   for free (`ReservedLabelType`, `BadPointer`) rather than the catch-all `UnsupportedLabel`.

Also worth recording: the "target past `msg.len`" row in the validation table is
**unreachable as its own case**. A target beyond the message is necessarily ahead of the
pointer, so the ordering rule catches it first. The test for it is kept, because what it
pins is that the ordering rule subsumes the bounds check — not that a separate check exists.

The plan's own test list was followed as written and all of it earned its keep; the
`next_offset` assertion in the pure-pointer test was verified to discriminate (mutating it
to the target's end offset fails the suite), which is the one assertion in the file that
could have been vacuous.

---

## Landed 2026-08-10 — P2.3 structured logging (phase 1)

`console.zig` is gone; [obs/log.zig](../src/obs/log.zig) is installed as
`std.options.logFn`, so every `std.log.*` call in the process — ours and the standard
library's — renders as one **logfmt** record:

```
ts=2026-08-10T14:03:11.482Z level=warn scope=default msg="discarding reply id=a3f2"
```

- **The message body is whatever the call site formatted**, wrapped in a quoted `msg`
  field. Deliberate: the 16 existing `std.log` call sites needed no edits to become
  parseable, and **no call site can break the record format**, because everything passes
  through `EscapingWriter` on the way out.
- **The escaping is not optional.** `parseQuestion` lowercases label bytes but does not
  validate them, so a qname reaching a log call site can contain any byte, newlines
  included. Interpolating that raw would let anyone who can send us a query forge log
  records. Pinned by a test ("an attacker-controlled qname cannot forge a second record").
- **Level and format are runtime settings** — `VORTEX_LOG_LEVEL` and `VORTEX_LOG_FORMAT`,
  resolved by [settings.zig](../src/settings.zig) and applied through `configure`. That
  closes one of the four P2.1 knobs whose consumer could not previously take a runtime
  value.
- **One `Io`, one stderr mutex.** Logging goes through the *same* `Io` instance as every
  other stderr writer: `std.Io.lockStderr` takes a mutex living on the `Io` implementation,
  and `std.Options.debug_io` is a separate statically-initialized singleton — so mixing
  `std.debug.lockStderr` with `io.lockStderr` acquires two different mutexes and lets
  records interleave mid-line.
- **Eight tests** — level/format parsing in both spellings and any case, the threshold
  semantics of `enables`, the logfmt envelope, short level names and default scope, the
  forged-record attempt, escaping across quotes/backslashes/controls/high bytes, and
  timestamp rendering across leap years and a pre-epoch clock.

Still open under P2.3: the per-query event carrying client, qtype, latency and verdict as
real fields, and counters.

---

## Landed 2026-08-09 (second pass) — core query datapath closed out

Six items, worked in dependency order. Two of them were **not previously on the board** —
they came out of re-reading the datapath rather than from the existing list.

**New findings, now fixed:**

- **Oversized datagrams were silently truncated, and the dispatcher forwarded corrupt
  replies.** `IncomingMessage.flags.trunc` — "the trailing portion of a datagram was
  discarded because it was larger than the buffer supplied" — was never checked on either
  socket. The dispatcher case was a genuine correctness bug: we forward the client's OPT
  verbatim, so a client advertising an EDNS0 buffer above 4096 lets upstream legitimately
  reply with more than `msg_buf` holds. We truncated it, rewrote the ID, and forwarded a
  **malformed message with TC unset** — the client had no way to know. Now
  `Header.markTruncated` sets TC=1 before relaying; the client retries over TCP, which fails
  honestly until **P3.6** rather than corrupting silently. On ingress an oversized query gets
  FORMERR and is dropped **before** the dupe and coroutine spawn, so a flood costs one
  12-byte reply each. FORMERR is safe to send there precisely because the reply is far
  smaller than the query.
  *Verified with a fake upstream returning 5000 bytes (flags word `0x8380` on the wire) and a
  5000-byte query (12-byte FORMERR back).*
- **Timeouts ran on the settable wall clock.** `expires_at` and the sweeper both used
  `Clock.real`, which std documents as "affected by discontinuous jumps... and by frequency
  adjustments performed by NTP": a step backwards let entries outlive their deadline, a step
  forwards evicted every in-flight query at once. Both now use **`Clock.boot`** — monotonic,
  and unlike `.awake` it counts time the machine spends suspended, so a query outstanding
  across a laptop sleep is correctly treated as long dead. The sweep cadence moved too: a
  relative sleep on a settable clock stutters whenever NTP adjusts. All three sites also went
  `@truncate` → `@intCast`, which closes the half of [memory-review.md](memory-review.md) #4
  that was never adopted.

**Board items, now done:**

- **P4.2 — QDCOUNT/opcode validation.** `Rejection` gained `bad_opcode` and `bad_qdcount`
  plus an `rcode()` method that puts drop-vs-reply in one place instead of at the call site.
  New `Header.headerOnlyReply` zeroes **all four** counts including QDCOUNT — for
  `bad_qdcount` the existence of a parseable question is exactly what is in doubt.
  *Ordering is load-bearing:* QR is checked first, because a spoofed response with a bogus
  QDCOUNT must stay silent or we FORMERR a forged address and reopen the C3 reflector.
  Mutation-verified.
- **P1.1 — `PendingTable` unit tests.** Eight tests: round trip, idempotent complete, the
  **B1 expiry regression**, sweep-is-a-no-op, 4096 distinct proxy IDs, ID-space exhaustion
  (fills all 65,536), `peek` non-consumption, and `hashQuestion`. The trick that made them
  cheap is that none control time — a helper builds deadlines off the same clock the sweeper
  reads, so "already expired" is a negative offset. Mutation-verified five ways, including
  reintroducing B1 verbatim.
- **P1.2 — supervisor (the coroutine half).** One `supervise(io, ctx, name, loop)` covers
  both loops, which now share a `fn (Io, *const Context)` shape (`sweeperLoop` takes its
  allocator from `Context`). Neither loop can currently return, so this guards a future edit
  — it earns its place because the failure is total and silent.

  **With exponential backoff.** The supervisor is a `while` wrapping a loop that itself
  blocks forever, so in the healthy case its body never completes an iteration and costs
  nothing but a stack frame. The hazard is the opposite case: a `loop` that returns
  *immediately* would be restarted as fast as the CPU allows, pinning a core and writing
  error logs in a tight spin — the classic supervisor crash loop. The schedule is
  `0s → 1s → 2s → 4s → 8s → 16s → 30s` (capped), with two deliberate properties:
  - **The first restart is immediate**, so a single spurious return recovers with no added
    latency. Only repeated failures back off.
  - **A clean run of 60s resets the schedule**, so a process up for a month does not inherit
    a 30s penalty from an unrelated hiccup at startup.

  `io.sleep` propagates `error.Canceled`, so shutdown never waits out a 30s delay.
  `backoffSeconds` is pure and separately tested — including saturation, because an
  unbounded shift would overflow the `u6` and panic, turning a recoverable crash loop into a
  hard crash. *Verified live by temporarily making `sweeperLoop` return immediately: 8
  restarts in 75 seconds, against millions without the backoff.*
- **P1.3 — question verification (the second half).** `PendingQuery` carries a seeded
  `question_hash` plus `question_len`. Storing the length means the reply path **never
  re-parses**: it slices a known range and hashes it, so a hostile question in a forged reply
  gets no parser to attack. The seed is per-process from `io.random`, so a colliding question
  cannot be precomputed offline.
- **P1.4 — SERVFAIL on sweep.** `sweepExpiredQueries` now *reports* what it evicted into a
  caller-owned list and `sweeperLoop` does the sending, so the table still holds no socket —
  which is what keeps its suite runnable without one. Reused across sweeps, so the steady
  state (an empty sweep per second) allocates nothing. A failed report still evicts: holding
  a slot open because we could not allocate a *notification* would turn transient OOM into a
  permanently leaked proxy ID.

  Measured latency is ~5.4 s (the 5 s deadline plus up to 1 s of sweep granularity).
  **Two follow-ups:** the reply carries QDCOUNT=0 because the sweeper has no question bytes
  — `dig` accepts it, matching on ID, but a stricter stub resolver may ignore it and fall
  back to its own timeout (never worse than the old silence). Echoing the question would
  mean storing the bytes rather than the hash, which is a real memory trade, not a free
  upgrade. And the 5 s deadline plus 1 s cadence are still hard-coded — newly unblocked for
  **P2.1** now that their consumer takes runtime values, and arguably too long for a
  forwarder (2–3 s is typical).

**One design bug found by testing, worth recording.** The first cut of P1.3 called
`complete()` (which removes) *before* the hash check. A forged packet that merely guessed the
proxy ID would therefore **delete the legitimate pending query as a side effect of being
rejected** — no injected answer, but a successful denial of service, and nothing left for the
sweeper to SERVFAIL. A live test against an upstream that echoed the right ID with the wrong
question produced silence instead of SERVFAIL, which is how it surfaced. Fixed by adding
`PendingTable.peek` and ordering it **peek → verify → complete**. P1.3 and P1.4 each looked
correct alone; the defect was in their interaction.

---

## Landed 2026-08-09 (first pass) — P2.1 configuration (mechanism)

`settings.zig` went from a block of `pub const` compile-time constants to a runtime
`Settings` struct resolved once at startup. **Precedence: defaults < `.env` file < process
environment** — the usual dotenv contract, so `VORTEX_LISTEN_PORT=5355 ./vortex` overrides
the file without editing it.

- **The file is merged *into* `init.environ_map` rather than kept beside it.** One lookup
  path, and precedence is enforced by construction: a key that already exists is never
  overwritten, so the process environment wins automatically and no comparison logic can get
  it backwards. It also means **`Settings` owns nothing** — its string fields point either at
  literals (defaults) or into the map, which lives for the whole process. No `deinit`, no
  arena, no ownership question. The one constraint is documented at the type: it must not
  outlive that map.
- **Parser is pure over a byte slice**, split from the file read, so the whole grammar is
  testable without an `Io` or a filesystem — the same move that made C2 and C3 testable.
  Handles blank lines, `#` comments, `export ` prefixes, whitespace around `=`, single and
  double quotes, CRLF, and a UTF-8 BOM. A `#` inside a URL survives (an inline comment must
  be preceded by whitespace). Malformed lines warn and are skipped rather than aborting the
  load. No backslash escapes or multi-line values — deliberately.
- **Failure policy is deliberate, not incidental:** a missing default `.env` is silent (no
  config file is a supported mode), but a file named explicitly via `VORTEX_ENV_FILE` that
  doesn't exist is fatal, and so is an unparseable port. The asymmetry is the point — in the
  latter two cases the operator asked for a config that couldn't be delivered.
- **`constructBlockList` / `constructSuffixBlockList` now take the URL as a parameter**
  instead of importing a constant, and their fetch-failure logs name the URL and HTTP status
  rather than saying `Failed to fetch BLOCKLIST_URL...`.
- **`.env` migrated** to the `VORTEX_`-prefixed names and expanded into the documented
  reference for every knob. The old keys were `PORT` and `LOCALHOST`, both of which are bad
  neighbours in a real process environment (`PORT` in particular is set by many platforms).
  All three of its previous values equalled the defaults, so nothing was lost.
- **Four tests** — the module logs through a scoped logger that is silenced under
  `builtin.is_test`: the port tests deliberately feed bad values, and Zig's test runner
  fails any test that logs at `.err`. Only logging is suppressed; the returned errors are
  what the tests assert on.
- **Verified end to end**, not just by unit test: with a scratch env file using `export `,
  an inline comment, and single quotes, the server came up on the configured port and
  upstream, resolved `example.com` through it, and returned NXDOMAIN + SOA for
  `doubleclick.net`. `dig` rendered the authority record as
  `doubleclick.net. 3600 IN SOA . . 1 3600 600 86400 3600` — which independently confirms
  the C2 golden bytes, since `dig` had to follow the `0xC00C` compression pointer to print
  that owner name.

---

## Landed 2026-08-08 (second pass) — P0 closed out and fully pinned

- **The blocked-response assembly is now a pure function**
  ([blocked_response.zig](../src/dns/blocked_response.zig)). `build(gpa, query,
  question_end, rcode)` takes bytes and returns a fresh owned buffer of exactly
  `question_end + Authority.WIRE_LEN`. `handleQuery`'s blocked branch went from ~18 lines of
  inline buffer juggling to three.

  This was the precondition for testing C2 at all. A golden-bytes test on
  `write_authority_section` alone would have missed the part that was actually bug-prone:
  the NSCOUNT=1 write, the fresh-buffer sizing, the copy, and the append offset were all
  inline in `handleQuery`, which needs an `Io` and two live sockets to reach. Same move as
  the `validateQuery` extraction, same payoff.

- **`craftBlockedResponse` → `Header.writeResponseFlags(msg, rcode)`.** Three changes: the
  RCODE is a parameter instead of a hard-coded `3`, the RR-count zeroing moved out to the
  caller, and the vestigial `_: *Header` receiver is gone. Splitting flags from counts is
  what lets **P4.2** reuse it — a FORMERR for a bad QDCOUNT can't echo a question section, so
  it needs the same flag flip with different counts. **P4.1**'s NODATA path takes
  `rcode = .no_error` through the same door.

- **Three golden-bytes tests** ([blocked_response.zig](../src/dns/blocked_response.zig)):
  - *Exact bytes* — asserts all 67 bytes for a known query: length, echoed ID, the full
    flags word `0x8183` (QR=1, opcode+RD preserved, AA/TC/Z=0, RA=1, RCODE=3), all four
    counts, the question echoed **verbatim including its original mixed case** (which pins
    C1's other half — only the *parsed* copy is folded), and the 34-byte SOA against a
    literal array. The SOA is spelled out as literal bytes rather than recomputed from
    `Authority`'s fields *on purpose*: a test that reads the constants back cannot catch a
    byte-reversed SERIAL/TTL/MINIMUM, which is the one regression most worth guarding.
  - *RCODE is carried, not hard-coded* — loops over four RCODEs, asserts the low nibble
    changes and the upper twelve bits don't. Guards the P4.1/P4.2 reuse path.
  - *OPT is dropped, ARCOUNT cleared* — pins the **current** P3.5 violation so fixing it has
    to be a deliberate, visible change rather than a silent one.
  - Verified non-vacuous by mutation: writing SERIAL or MINIMUM little-endian fails all
    three; clearing RA fails two on the flags word; and re-hard-coding `| 3` doesn't compile
    (unused parameter) — the same accidental safety net the C3 guard has.

- **Bounds asserts in `write_authority_section`** ([authority.zig](../src/dns/authority.zig))
  — the 34 bytes were written unchecked. Added `byte_slice.len >= start_idx + WIRE_LEN` and
  `start_idx >= 12` (the `0xC00C` owner pointer is only meaningful if the QNAME really is at
  offset 12). Both hold today; they exist so the `WIRE_LEN` footgun trips a panic instead of
  corrupting a neighbouring allocation.

- **Stale `expires_at` comment corrected** — it claimed "ns since boot,
  `std.time.nanoTimestamp()`"; both writer and sweeper use ns-since-epoch from
  `std.Io.Timestamp.now(io, .real)`. No behavior change; this was the comment that invited
  reintroducing **B1**.

- **Correction to the previous entry:** the 08-08 morning pass's "Suggested order" claimed
  "C1 and C2 are not [pinned]". C1 *was* pinned, by [question.zig](../src/dns/question.zig)
  since 07-27 — the doc contradicted its own P2.5 test inventory. Only C2 was unpinned.

---

## Landed 2026-08-08 (first pass) — C3 gets a test, P1.2 closed

- **P1.2 fixed** — the ingress loop no longer propagates out of `main`. `receive` now mirrors
  `dispatcherLoop`'s shape (`error.Canceled => return` for clean shutdown, log + `continue`
  otherwise), and a failed `gpa.dupe` sheds the datagram instead of terminating the server. A
  transient receive error or one failed allocation is no longer fatal. The `dupe` site is the
  natural hook for the **P1.5** concurrency cap when that lands.
- **`Header.validateQuery` extracted** — the QR check moved out of `handleQuery` into a pure
  method returning a `Header.Rejection` (`none` / `is_response`). `handleQuery` switches on
  it; behavior is unchanged. Two reasons:
  - **It made the C3 fix testable.** `handleQuery` needs an `Io` and a `Context` holding
    two live sockets, so "assert nothing is forwarded" was an integration test. The
    extracted method is bytes-in/enum-out.
  - **It gives P4.2 a home.** `Rejection` is where `bad_qdcount` and `bad_opcode` go, so
    the header-validation family stays in one guard instead of scattering `if`s.
- **Three tests added** — QR=1 rejected, ordinary query accepted, and QR-in-isolation (QR=1
  with all other flags clear is still refused; a query with odd AA/TC/RCODE bits is still
  accepted, since that's P4.2's business, not this guard's). First movement in the coverage
  number since 2026-07-27.
  - Verified non-vacuous by mutation: inverting the guard to `if (self.qr == 0)` fails all
    three. (Deleting the guard outright doesn't compile — Zig rejects the then-unused
    `self` — which is its own small safety net.)

**Still open from this pass:** the `parseQuestion` malformed-input tests (P2.5) and the
`PendingTable` suite (P1.1). *(The C2 SOA golden-bytes test, also listed here at the time,
landed in the second 08-08 pass above.)*

---

## Landed 2026-08-07 — P0.C3 fixed

- **P0.C3 fixed** — `handleQuery` gained a QR-bit check immediately after `parseHeader` and
  before `Policy.decide`, exactly where the spec called for it:

  ```zig
  if (header.qr == 1) {
      std.log.debug("dropping response-as-query from {f}", .{incoming_addr});
      return;
  }
  ```

  It drops silently (a server must not answer a response), logs at `debug` so an injection
  flood can't be used to fill the log, and returns before a `PendingTable` slot is taken —
  so all three consequences listed under C3 (reflection, upstream loop, ID-space pollution)
  are closed at once. Vortex no longer ships a reflector when **P2.6** binds off localhost.
  (The 2026-08-08 pass moved this check verbatim into `Header.validateQuery`; the behavior
  above is unchanged, only its address is.)

The rest of this entry records observations about `main.zig` that earlier passes hadn't,
rather than changes made on that date — this repo wasn't under version control at the time,
so "when they landed" isn't recoverable, only that they were true then:

- **Malformed questions drop instead of propagating** — `parseQuestion`'s error union
  (`TruncatedQuestion` / `UnsupportedLabel` / `NameTooLong`) is caught in `handleQuery` and
  turned into a debug log + drop, so a truncated or compression-pointer question can't take a
  query path down. All three error paths are still untested (P2.5).
- **The test aggregator covers every module** — the `test { _ = @import(…) }` block pulls in
  all 10 source files, including `header.zig`, `policy.zig`, `pending_table.zig`,
  `utility.zig`, and `console.zig`. At the time, those five contained **zero `test` blocks**,
  so the wiring bought nothing: `zig build test` was `7/7`, really 4, unchanged since
  2026-07-27. The 2026-08-08 pass finally cashed it in — `header.zig`'s three new tests run
  *because* this aggregator entry already existed.

---

## 2026-08-05 — review only, no code changes

This pass read the source rather than adding to it. Net effect on the board: **+1 P0**
(C3, QR bit unchecked on ingress), **+1 P1** (ingress-loop error recovery, folded into
P1.2), and a corrected P2.5 coverage count (`7/7` passing is **4** real tests, not 7).
Everything the 2026-07-30 entry below claims as landed was verified still present and
correct in the source — including the 34-byte SOA math in
[authority.zig](../src/dns/authority.zig) and the fresh-buffer blocked path.

---

## Landed 2026-07-30

- **P0.C2 fixed** — blocked NXDOMAIN responses now carry a synthetic SOA, so clients can
  negatively cache the block instead of re-querying on every reference:
  - New [authority.zig](../src/dns/authority.zig) emits the fixed 34-byte SOA — `0xC00C`
    owner-name pointer to the QNAME, SOA/IN, TTL 3600, RDLENGTH 22, root-label
    MNAME/RNAME, and the 20-byte numeric tail — all serialized with big-endian
    `std.mem.writeInt` (no `@bitCast`, so the endianness footgun is avoided). `WIRE_LEN = 34`
    is a named constant with the "only fixed because of the pointer + root-label choices"
    caveat documented at its definition.
  - The blocked branch in `handleQuery` takes the "fresh buffer" path: `craftBlockedResponse`
    truncates + flips flags on the exact-sized dupe, the caller sets **NSCOUNT=1**, then
    copies `data[0..question_len]` into a `question_len + WIRE_LEN` buffer and appends the
    SOA there — so the exact-length query dupe is never overrun.
- **Remaining C2 follow-ups (not blockers)** *as recorded on 07-30:* no golden-bytes test
  yet (tracked in P2.5); the negative-cache TTL is hard-coded to 3600 in `Authority` (make
  it configurable in P2.1); the blocked path is still NXDOMAIN-only regardless of qtype
  (P4.1) and still drops a client OPT (P3.5).
  *Status as of 08-08:* the golden-bytes test landed; the other three are still open. The
  `craftBlockedResponse` named here is now `Header.writeResponseFlags` plus
  `blocked_response.build`.

- **P0.B1–B6** — all six pending-table bugs fixed: sweeper now compares ns to ns;
  `dead_queries` is `defer`-freed; the proxy ID is reclaimed on upstream send failure; the
  bogus `main.zig` import is gone; the capacity guard is `> maxInt(u16)`;
  `pending_table.deinit()` is deferred.
- **P1.3 (partial)** — dispatcher now drops responses whose source address isn't the
  upstream. The optional question-hash verification landed 08-09.
- **P3.4** — suffix/wildcard blocking implemented, plus a curated allowlist that
  overrides blocks, composed through `Policy.decide`. This is the first concrete slice
  of the [filter-design.md](filter-design.md) `Filter`/`Chain` design.

---

## Landed 2026-07-27

- **P0.C1 fixed** — `parseQuestion` now lowercases each label as it builds the name, so every
  filter matches on a canonical QName. The wire buffer is untouched, so forwarded queries
  keep their original case. Regression test added (`parseQuestion lowercases the qname`).
- **Test harness fixed (half of P2.5)** — `zig build test` was silently running **only**
  the `root.zig` `add(3,7)` stub: a plain `@import` alias doesn't pull an imported file's
  `test` blocks into the build. Added a `test { _ = @import(...) }` aggregator to
  [main.zig](../src/main.zig) so all module tests now run (`6/6` and counting). This is the
  precondition for the rest of P2.5 to mean anything.
- **New tests** — `parseQuestion` case-normalization (above) and `SuffixBlockList.decide`
  parent-label walk ([suffix_blocklist.zig](../src/blocklist/suffix_blocklist.zig)).

---

# Reference — the three closed P0s in detail

Retained as **reference for the behavior now shipped**, not as to-dos. Each records why the
fix is shaped the way it is and what now keeps it that way.

| Bug | Fixed | Pinned by |
|-----|-------|-----------|
| C1 — QName never lowercased | 2026-07-27 | [question.zig](../src/dns/question.zig) `parseQuestion lowercases the qname (C1 regression)`, plus the verbatim-question assertion in the C2 golden test (the wire-case half) |
| C2 — blocked NXDOMAIN carries no SOA | 2026-07-30 | [blocked_response.zig](../src/dns/blocked_response.zig) — three golden-bytes tests, 2026-08-08 |
| C3 — QR bit never checked on ingress | 2026-08-07 | [header.zig](../src/dns/header.zig) — `validateQuery` tests, 2026-08-08 |

## C3. QR bit is never checked on ingress — fixed 2026-08-07

Background: `handleQuery` parsed the header and read `id`, `opcode`, and the counts, but
**never looked at `header.qr`**. Any datagram ≥ 12 bytes that parsed as a question was
treated as a query: run through `Policy`, given a fresh proxy ID, and sent to the upstream
resolver.

Why it mattered — a DNS *response* delivered to the listen port became a *new outbound
query*:

- **Reflection/amplification.** An attacker spoofing the source address of a third party
  could make Vortex emit upstream traffic on their behalf — the reflector half of the
  amplification exposure tracked in **P2.7**. Rate limiting alone would not have fixed it,
  because the packet should never have been forwarded at all.
- **Loop risk.** Point the upstream at an address that routes back to the listen socket
  (misconfiguration, or `UPSTREAM_HOST` set to Vortex itself) and each response re-entered
  as a query — an unbounded packet loop that also burned a `PendingTable` slot per hop.
- **`PendingTable` pollution.** Every injected response consumed a proxy ID for the full
  5 s sweeper window, a cheap path to `error.IdSpaceExhausted` against the 16-bit ID space.

Localhost-only binding was the *only* thing containing this, which meant it would have gone
live the moment P2.6 binds anything else — same trigger as P1.5.

**How it was fixed:** `Header.validateQuery` returns `.is_response` for QR=1, and
`handleQuery` switches on it between `parseHeader` and `Policy.decide` — before the
`PendingTable` allocation, and silent, since a server must not answer a response.

**Pinned by three tests**: QR=1 rejected, ordinary query accepted, and QR-in-isolation. All
three fail if the guard is inverted (verified by mutation), so this fix can't silently
regress the way it silently arrived.

## C2. Blocked NXDOMAIN carries no SOA — fixed 2026-07-30

Background: a negative answer with an empty authority section carries **no TTL to cache
against** — RFC 2308 says a resolver takes the negative-cache lifetime from the SOA in the
Authority section (the smaller of the SOA's record TTL and its MINIMUM field). No SOA ⇒ the
client can't cache the "doesn't exist" ⇒ it re-queries on *every* reference. The fix
appends one synthetic SOA and sets NSCOUNT=1; clients don't validate MNAME/RNAME for a
sinkhole, so those are root-label placeholders and only the negative-cache TTL matters.

### Wire layout emitted (after the question section)

An SOA resource record, owner-name given as a compression pointer back to the QNAME:

| Bytes | Field | Value |
|------:|-------|-------|
| 2 | NAME | `0xC0 0x0C` — pointer to QNAME at offset 12 (avoids repeating the name) |
| 2 | TYPE | `0x00 0x06` — SOA |
| 2 | CLASS | `0x00 0x01` — IN |
| 4 | TTL | negative-cache TTL, e.g. `3600` |
| 2 | RDLENGTH | `22` (length of the RDATA below) |
| 1 | MNAME | `0x00` — root label (placeholder primary NS) |
| 1 | RNAME | `0x00` — root label (placeholder admin mailbox) |
| 4 | SERIAL | `1` |
| 4 | REFRESH | e.g. `3600` |
| 4 | RETRY | e.g. `600` |
| 4 | EXPIRE | e.g. `86400` |
| 4 | MINIMUM | **negative-cache TTL — the field that matters**, keep == record TTL |

That's **34 bytes** total (2+2+2+4+2 header of the RR + 22 RDATA). Header edits: keep QR=1
and RCODE=3, keep AN/ARCOUNT=0, set **NSCOUNT=1**. Response length becomes
`question_end + 34`. Set the record TTL and MINIMUM to the same value so RFC 2308's
`min(TTL, MINIMUM)` is unambiguous; 60–3600 s is the usual range (Pi-hole uses ~2 s).

**Why 34 is fixed here — and only here.** SOA is *not* a fixed-size record in general. Its
RDATA is `MNAME + RNAME + 20 bytes` of five 32-bit fields (SERIAL, REFRESH, RETRY, EXPIRE,
MINIMUM), and MNAME/RNAME are variable-length domain names — a real SOA like
`ns.example.com. admin.example.com. …` runs well past 34. We land on exactly 34 because we
make **two deliberate encoding choices**, both valid for a sinkhole:

1. **Owner NAME is a 2-byte compression pointer** (`0xC00C`) instead of a spelled-out name.
2. **MNAME and RNAME are each a single root label** (`0x00`) — placeholders, since no
   resolver validates them for a synthetic negative answer.

Change either choice and the size changes. `Authority.WIRE_LEN = 34` is safe to hard-code
*only because `write_authority_section` always emits this exact shape* — a comment at the
constant records the caveat so nobody later swaps in a real MNAME and overruns the math.

### How it was implemented

- **[authority.zig](../src/dns/authority.zig)** — `write_authority_section` serializes
  every multi-byte field with `std.mem.writeInt(…, .big)`, sidestepping the
  `packed struct` + `@bitCast` endianness trap (native little-endian would have written
  SERIAL `1` as `01 00 00 00`). The owner NAME pointer and root MNAME/RNAME go out as
  literal bytes. Two `assert`s (added 08-08) check the caller left room for all 34 bytes and
  that the QNAME really is at offset 12, since `0xC00C` is meaningless otherwise.
- **The buffer gotcha** — the handler buffer is `gpa.dupe(u8, incoming.data)`, sized to the
  *exact* query length, so the blocked branch can't extend it in place.
  `blocked_response.build` allocates a fresh `question_end + WIRE_LEN` buffer, copies the
  question in (the copy length is what truncates the message), flips the flags and counts
  *in the output*, and appends the SOA there. `query` is only ever read.
- **Assembly lives in one pure function** (08-08) —
  [blocked_response.zig](../src/dns/blocked_response.zig). Previously it was ~18 inline
  lines in `handleQuery`, reachable only with an `Io` and two live sockets, which is why C2
  went four weeks without a test.

### Follow-ups spun out of C2

Still open, tracked on the board: **NODATA vs NXDOMAIN per qtype** (P4.1 — the `rcode`
parameter on `build` is the door in), **OPT still dropped** (P3.5 — pinned by a test, so
fixing it means deliberately rewriting that test), and **TTL hard-coded to 3600** (P2.1 —
also un-`comptime`s `Authority`'s fields and turns the golden test's literal SOA array into
a function of the configured TTL).

## C1. QName is never lowercased — fixed 2026-07-27

See the 2026-07-27 entry above. `parseQuestion` lowercases each label as it builds the name;
the wire buffer is untouched so forwarded queries keep their original case, which the C2
golden test pins from the other side by asserting the echoed question is byte-for-byte the
original including its mixed case.

---

# Reference — closed board items

## P1.1–P1.4 (all landed 2026-08-09)

1. **Unit tests for `PendingTable`** — eight tests, mutation-verified, including the B1
   expiry regression. *Was:* zero tests, and this is exactly where the P0.B-series bugs hid.
2. **Supervisor for dispatcher/sweeper death** — `supervise` wraps both loops and restarts on
   any non-`Canceled` return, with exponential backoff (`0s → 1s → … → 30s`, reset after a
   60s clean run) so a fast-returning loop cannot become a spin. The ingress-loop half landed
   2026-08-08.
   - *Ownership note for whoever touches this next:* the duped datagram is owned by
     `handleQuery`, whose `defer gpa.free(data)` covers **every** exit path including the
     early QR and malformed-question returns. Do not add a `free` in those branches (double
     free) and do not free at the call site after `group.async` (use-after-free). The
     08-08 pass briefly had a second `gpa.dupe` at the call site, which leaked one copy per
     query and left the fatal `try` in place — worth not reintroducing.
   - `Group.async` returns `void` and cannot fail (`std/Io.zig:1240`), so the spawn itself is
     not a failure point — only the task body is.
3. **Question-hash verification** — seeded `question_hash` + `question_len` in
   `PendingQuery`, checked by the dispatcher **before** the entry is consumed (`peek` →
   verify → `complete`; see the 08-09 entry for why that ordering is load-bearing). The reply
   path never re-parses.
4. **SERVFAIL on sweep** — `sweepExpiredQueries` reports evicted entries to the caller;
   `sweeperLoop` sends `Header.synthesizedReply(id, .server_failure)`. Two follow-ups
   recorded in the 08-09 entry (QDCOUNT=0 replies; hard-coded 5 s / 1 s).

## P4.2 — QDCOUNT / opcode validation (landed 2026-08-09)

*Was:* `parseQuestion` always reads exactly one question at offset 12 regardless of QDCOUNT,
and opcode is parsed but unused. Reject QDCOUNT≠1 and non-standard opcodes with
FORMERR/NOTIMP instead of parsing whatever is at offset 12. Same root cause as **P0.C3**.
The spec, followed as written:

```zig
pub const Rejection = enum { none, is_response, bad_opcode, bad_qdcount };

pub fn validateQuery(self: *const Header) Rejection {
    if (self.qr == 1) return .is_response;                  // silent drop
    if (self.opcode != .standard_query) return .bad_opcode;  // NOTIMP  (4)
    if (self.question_count != 1) return .bad_qdcount;       // FORMERR (1)
    return .none;
}
```

Order matters — QR is checked first because it is the only one that must *not* generate a
reply. The reply shape is *not* the blocked-response shape: `blocked_response.build` echoes
the question and appends an SOA, but for `bad_qdcount` you cannot echo a question (whether
one parses is precisely what is in doubt) and for `bad_opcode` there may not be a question
section at all. Hence `Header.headerOnlyReply` — a 12-byte reply with QDCOUNT=0.

## P3.4 — wildcard / suffix blocking (landed 2026-07-30)

`SuffixBlockList` walks parent labels; `Policy` composes it after the exact blocklist, with
the allowlist overriding both. Remaining polish is still open on the board (fold `Policy`
into the comptime `Filter`/`Chain`, add a suffix-*allow* matcher).

## Housekeeping items closed

- **Stale comment on `PendingQuery.expires_at`** — ✅ fixed 2026-08-08. It claimed "ns since
  boot, `std.time.nanoTimestamp()`"; both the writer and the sweeper use ns-since-epoch from
  `std.Io.Timestamp.now(io, .real)`. There was never a bug, but this was the comment that
  invited reintroducing **B1** (the fixed ns/ms mismatch); it now names the clock and says
  why the unit matters. *(Both sites moved to `Clock.boot` later the same week — see the
  08-09 second-pass entry.)*
- **`.env` exists at the repo root but nothing reads it** — ✅ wired up 2026-08-09 (P2.1).
  It is now the documented reference for every knob. Two follow-ups: there is no `.gitignore`
  (moot while this repo is not under version control, but `.env` is conventionally ignored,
  and this one is safe to commit only because it holds no secrets); and if a future knob ever
  *is* a secret, revisit that before adding it.
- **Empty `src/server.zig`** — deleted 2026-08-09.
- **`console.zig`** — replaced by [obs/log.zig](../src/obs/log.zig), 2026-08-10.
