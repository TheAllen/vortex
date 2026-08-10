# Next Steps — Road to Production-Ready

Reviewed **2026-08-09** against the current source (Zig 0.16.0, `zig build test` →
**31/31 pass, exit 0**, Debug and ReleaseSafe). **No open P0s, and no open P1 bugs.** As of the second 08-08 pass,
**every P0 fix is now pinned by a regression test** — C1 (07-27), C3 (08-08 morning), and
C2 (08-08, this pass). That closes the P0 section for good: the three bugs that shipped
silently can no longer regress silently.

**P2.1 configuration** landed on 08-09 (Vortex is no longer configured by recompiling it),
and later the same day the **core query datapath was closed out**: six items, of which two
were bugs nobody had recorded. **P1.1, P1.2, P1.3, P1.4 and P4.2 are all done**, leaving
**P1.5 as the only open P1**.

Testing has changed shape rather than gone away. **28 real tests, up from 4** on 08-08
morning, and `PendingTable` — where the entire P0.B series hid — went from zero coverage to
eight tests. The remaining gap is no longer "write more unit tests": it is that
`handleQuery`, `dispatcherLoop` and the ingress loop have **no automated coverage at all**,
and cannot get any by extracting another pure function, because what is untested is the
socket plumbing itself. That needs an integration harness (**P2.5**), which in turn needs a
local-file blocklist source (**P2.1**) so startup does not cost 25 seconds per case.

What exists today:

- Ingress loop + per-query `handleQuery` coroutines via `std.Io.Group` ([main.zig](../src/main.zig))
- Header validation on ingress via `Header.validateQuery`
  ([header.zig:115–127](../src/dns/header.zig#L115)) — QR=1 datagrams are dropped
  ([main.zig:67–83](../src/main.zig#L67)); a malformed question section is logged and
  dropped rather than acted on ([main.zig:91–94](../src/main.zig#L91))
- An ingress loop that survives transient errors: `receive` failures are logged and retried,
  and a datagram is shed when its buffer can't be allocated ([main.zig:366–411](../src/main.zig#L366))
- Shared upstream socket with `dispatcherLoop` demuxing by proxy transaction ID, with a
  source-address check (`upstream_addr.eql(reply.from)`) on every response ([main.zig:159](../src/main.zig#L159))
- Runtime configuration from defaults < `.env` < process environment
  ([settings.zig](../src/settings.zig))
- `PendingTable` with random proxy IDs, mutex, and a sweeper coroutine ([pending_table.zig](../src/utils/pending_table.zig))
- Multi-label QName parsing with bounds checks, lowercased in place ([question.zig](../src/dns/question.zig))
- A `Policy` filter chain — allowlist → exact blocklist → suffix blocklist — with a
  three-valued `Verdict` (`allow`/`block`/`pass`) ([policy.zig](../src/blocklist/policy.zig))
  - Exact-match blocklist fetched over HTTP ([domain_blocklist.zig](../src/blocklist/domain_blocklist.zig))
  - Suffix/wildcard blocklist walking parent labels ([suffix_blocklist.zig](../src/blocklist/suffix_blocklist.zig))
  - Comptime allowlist that overrides a block, validated lowercase at build time ([allowlist.zig](../src/blocklist/allowlist.zig))
- NXDOMAIN synthesis for blocked names, assembled in one pure function
  ([blocked_response.zig](../src/dns/blocked_response.zig)) from `Header.writeResponseFlags`
  plus a cacheable SOA ([authority.zig](../src/dns/authority.zig))

---

## ✅ Done since the last review

### Landed 2026-08-09 (second pass) — core query datapath closed out

Six items, worked in dependency order. Two of them were **not previously on this board** —
they came out of re-reading the datapath rather than from the existing list.

**New findings, now fixed:**

- **Oversized datagrams were silently truncated, and the dispatcher forwarded corrupt
  replies.** `IncomingMessage.flags.trunc` — "the trailing portion of a datagram was
  discarded because it was larger than the buffer supplied" — was never checked on either
  socket. The dispatcher case was a genuine correctness bug: we forward the client's OPT
  verbatim, so a client advertising an EDNS0 buffer above 4096 lets upstream legitimately
  reply with more than `msg_buf` holds. We truncated it, rewrote the ID, and forwarded a
  **malformed message with TC unset** — the client had no way to know. Now
  `Header.markTruncated` ([header.zig:136](../src/dns/header.zig#L136)) sets TC=1 before
  relaying ([main.zig:206](../src/main.zig#L206)); the client retries over TCP, which fails
  honestly until **P3.6** rather than corrupting silently. On ingress
  ([main.zig:383](../src/main.zig#L383)) an oversized query gets FORMERR and is dropped
  **before** the dupe and coroutine spawn, so a flood costs one 12-byte reply each. FORMERR
  is safe to send there precisely because the reply is far smaller than the query.
  *Verified with a fake upstream returning 5000 bytes (flags word `0x8380` on the wire) and a
  5000-byte query (12-byte FORMERR back).*
- **Timeouts ran on the settable wall clock.** `expires_at` and the sweeper both used
  `Clock.real`, which std documents as "affected by discontinuous jumps... and by frequency
  adjustments performed by NTP": a step backwards let entries outlive their deadline, a step
  forwards evicted every in-flight query at once. Both now use **`Clock.boot`** — monotonic,
  and unlike `.awake` it counts time the machine spends suspended, so a query outstanding
  across a laptop sleep is correctly treated as long dead. The sweep cadence
  ([main.zig:224](../src/main.zig#L224)) moved too: a relative sleep on a settable clock
  stutters whenever NTP adjusts. All three sites also went `@truncate` → `@intCast`, which
  closes the half of [memory-review.md](memory-review.md) #4 that was never adopted.

**Board items, now done:**

- **P4.2 — QDCOUNT/opcode validation.** `Rejection` gained `bad_opcode` and `bad_qdcount`
  plus an `rcode()` method that puts drop-vs-reply in one place instead of at the call site.
  New `Header.headerOnlyReply` ([header.zig:178](../src/dns/header.zig#L178)) zeroes **all
  four** counts including QDCOUNT — for `bad_qdcount` the existence of a parseable question
  is exactly what is in doubt. *Ordering is load-bearing:* QR is checked first, because a
  spoofed response with a bogus QDCOUNT must stay silent or we FORMERR a forged address and
  reopen the C3 reflector. Mutation-verified.
- **P1.1 — `PendingTable` unit tests.** Eight tests: round trip, idempotent complete, the
  **B1 expiry regression**, sweep-is-a-no-op, 4096 distinct proxy IDs, ID-space exhaustion
  (fills all 65,536), `peek` non-consumption, and `hashQuestion`. The trick that made them
  cheap is that none control time — a helper builds deadlines off the same clock the sweeper
  reads, so "already expired" is a negative offset. Mutation-verified five ways, including
  reintroducing B1 verbatim.
- **P1.2 — supervisor (the coroutine half).** One `supervise(io, ctx, name, loop)`
  ([main.zig:313](../src/main.zig#L313)) covers both loops, which now share a
  `fn (Io, *const Context)` shape (`sweeperLoop` takes its allocator from `Context`). Neither
  loop can currently return, so this guards a future edit — it earns its place because the
  failure is total and silent.

  **With exponential backoff** ([main.zig:288](../src/main.zig#L288)). The supervisor is a
  `while` wrapping a loop that itself blocks forever, so in the healthy case its body never
  completes an iteration and costs nothing but a stack frame. The hazard is the opposite
  case: a `loop` that returns *immediately* would be restarted as fast as the CPU allows,
  pinning a core and writing error logs in a tight spin — the classic supervisor crash loop.
  The schedule is `0s → 1s → 2s → 4s → 8s → 16s → 30s` (capped), with two deliberate
  properties:
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

**One design bug found by testing, worth recording.** The first cut of P1.3 called
`complete()` (which removes) *before* the hash check. A forged packet that merely guessed the
proxy ID would therefore **delete the legitimate pending query as a side effect of being
rejected** — no injected answer, but a successful denial of service, and nothing left for the
sweeper to SERVFAIL. A live test against an upstream that echoed the right ID with the wrong
question produced silence instead of SERVFAIL, which is how it surfaced. Fixed by adding
`PendingTable.peek` ([pending_table.zig:109](../src/utils/pending_table.zig#L109)) and
ordering it **peek → verify → complete**. P1.3 and P1.4 each looked correct alone; the defect
was in their interaction.

### Landed 2026-08-09 (first pass) — P2.1 configuration (mechanism)

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
- **Four tests** ([settings.zig](../src/settings.zig)) — **`zig build test` → 17/17, real
  count 10 → 14.** Note the module logs through a scoped logger that is silenced under
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

### Landed 2026-08-08 (second pass) — P0 closed out and fully pinned

- **The blocked-response assembly is now a pure function**
  ([blocked_response.zig](../src/dns/blocked_response.zig)). `build(gpa, query,
  question_end, rcode)` takes bytes and returns a fresh owned buffer of exactly
  `question_end + Authority.WIRE_LEN`. `handleQuery`'s blocked branch went from ~18 lines of
  inline buffer juggling to three ([main.zig:102–115](../src/main.zig#L102)).

  This was the precondition for testing C2 at all. A golden-bytes test on
  `write_authority_section` alone would have missed the part that was actually bug-prone:
  the NSCOUNT=1 write, the fresh-buffer sizing, the copy, and the append offset were all
  inline in `handleQuery`, which needs an `Io` and two live sockets to reach. Same move as
  the `validateQuery` extraction, same payoff.

- **`craftBlockedResponse` → `Header.writeResponseFlags(msg, rcode)`**
  ([header.zig:218–239](../src/dns/header.zig#L218)). Three changes: the RCODE is a
  parameter instead of a hard-coded `3`, the RR-count zeroing moved out to the caller, and
  the vestigial `_: *Header` receiver is gone. Splitting flags from counts is what lets
  **P4.2** reuse it — a FORMERR for a bad QDCOUNT can't echo a question section, so it needs
  the same flag flip with different counts. **P4.1**'s NODATA path takes `rcode = .no_error`
  through the same door.

- **Three golden-bytes tests** ([blocked_response.zig](../src/dns/blocked_response.zig)) —
  **`zig build test` → 13/13, real count 7 → 10.**
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

- **Bounds asserts in `write_authority_section`** ([authority.zig:39–43](../src/dns/authority.zig#L39))
  — the 34 bytes were written unchecked. Added `byte_slice.len >= start_idx + WIRE_LEN` and
  `start_idx >= 12` (the `0xC00C` owner pointer is only meaningful if the QNAME really is at
  offset 12). Both hold today; they exist so the `WIRE_LEN` footgun trips a panic instead of
  corrupting a neighbouring allocation.

- **Stale `expires_at` comment corrected**
  ([pending_table.zig:21](../src/utils/pending_table.zig#L21)) — it claimed "ns since boot,
  `std.time.nanoTimestamp()`"; both writer and sweeper use ns-since-epoch from
  `std.Io.Timestamp.now(io, .real)`. No behavior change; this was the comment that invited
  reintroducing **B1**.

- **Correction to the previous entry:** the 08-08 morning pass's "Suggested order" claimed
  "C1 and C2 are not [pinned]". C1 *was* pinned, by
  [question.zig:72](../src/dns/question.zig#L72) since 07-27 — the doc contradicted its own
  P2.5 test inventory. Only C2 was unpinned.

### Landed 2026-08-08 (first pass) — C3 gets a test, P1.2 closed
- **P1.2 fixed** — the ingress loop no longer propagates out of `main`
  ([main.zig:366–411](../src/main.zig#L366)). `receive` now mirrors `dispatcherLoop`'s
  shape (`error.Canceled => return` for clean shutdown, log + `continue` otherwise), and a
  failed `gpa.dupe` sheds the datagram instead of terminating the server. A transient
  receive error or one failed allocation is no longer fatal. The `dupe` site is the
  natural hook for the **P1.5** concurrency cap when that lands.
- **`Header.validateQuery` extracted** ([header.zig:115–127](../src/dns/header.zig#L115)) —
  the QR check moved out of `handleQuery` into a pure method returning a
  `Header.Rejection` (`none` / `is_response`). `handleQuery` switches on it
  ([main.zig:67–83](../src/main.zig#L67)); behavior is unchanged. Two reasons:
  - **It made the C3 fix testable.** `handleQuery` needs an `Io` and a `Context` holding
    two live sockets, so "assert nothing is forwarded" was an integration test. The
    extracted method is bytes-in/enum-out.
  - **It gives P4.2 a home.** `Rejection` is where `bad_qdcount` and `bad_opcode` go, so
    the header-validation family stays in one guard instead of scattering `if`s.
- **Three tests added** ([header.zig:252+](../src/dns/header.zig#L252)) — QR=1 rejected,
  ordinary query accepted, and QR-in-isolation (QR=1 with all other flags clear is still
  refused; a query with odd AA/TC/RCODE bits is still accepted, since that's P4.2's
  business, not this guard's). **`zig build test` → 10/10, and the real count moved 4 → 7.**
  First movement in the coverage number since 2026-07-27.
  - Verified non-vacuous by mutation: inverting the guard to `if (self.qr == 0)` fails all
    three. (Deleting the guard outright doesn't compile — Zig rejects the then-unused
    `self` — which is its own small safety net.)

**Still open from this pass:** the `parseQuestion` malformed-input tests (P2.5) and the
`PendingTable` suite (P1.1). *(The C2 SOA golden-bytes test, also listed here at the time,
landed in the second 08-08 pass above.)*

### Landed 2026-08-07 — P0.C3 fixed

- **P0.C3 fixed** — `handleQuery` gained a QR-bit check immediately after `parseHeader` and
  before `Policy.decide`, exactly where the spec below called for it:

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
rather than changes made on that date — this repo isn't under version control, so "when
they landed" isn't recoverable, only that they were true then:

- **Malformed questions drop instead of propagating** — `parseQuestion`'s error union
  (`TruncatedQuestion` / `UnsupportedLabel` / `NameTooLong`) is caught in `handleQuery` and
  turned into a debug log + drop ([main.zig:91–94](../src/main.zig#L91)), so a truncated or
  compression-pointer question can't take a query path down. All three error paths are
  still untested (P2.5).
- **The test aggregator covers every module** — the `test { _ = @import(…) }` block pulls in
  all 10 source files, including `header.zig`, `policy.zig`, `pending_table.zig`,
  `utility.zig`, and `console.zig`. At the time, those five contained **zero `test` blocks**,
  so the wiring bought nothing: `zig build test` was `7/7`, really 4, unchanged since
  2026-07-27. The 2026-08-08 pass finally cashed it in — `header.zig`'s three new tests run
  *because* this aggregator entry already existed.

> Note on line numbers: several `main.zig:NN` refs in the older entries below had drifted out
> of sync with the source (the 2026-08-05 pass carried some forward without re-checking).
> Every `main.zig` reference in this document was re-verified against the current file on
> 2026-08-07.

### 2026-08-05 — review only, no code changes

This pass read the source rather than adding to it. Net effect on the board: **+1 P0**
(C3, QR bit unchecked on ingress), **+1 P1** (ingress-loop error recovery, folded into
P1.2), and a corrected P2.5 coverage count (`7/7` passing is **4** real tests, not 7).
Everything the 2026-07-30 entry below claims as landed was verified still present and
correct in the source — including the 34-byte SOA math in
[authority.zig](../src/dns/authority.zig) and the fresh-buffer blocked path in
[main.zig:102–115](../src/main.zig#L102).

### Landed 2026-07-30 (previous session)

- **P0.C2 fixed** — blocked NXDOMAIN responses now carry a synthetic SOA, so clients can
  negatively cache the block instead of re-querying on every reference. Implemented exactly
  to the spec below:
  - New [authority.zig](../src/dns/authority.zig) emits the fixed 34-byte SOA — `0xC00C`
    owner-name pointer to the QNAME, SOA/IN, TTL 3600, RDLENGTH 22, root-label
    MNAME/RNAME, and the 20-byte numeric tail — all serialized with big-endian
    `std.mem.writeInt` (no `@bitCast`, so the endianness footgun is avoided). `WIRE_LEN = 34`
    is a named constant with the "only fixed because of the pointer + root-label choices"
    caveat documented at its definition.
  - The blocked branch in `handleQuery` ([main.zig:102–115](../src/main.zig#L102)) takes the
    "fresh buffer" path: `craftBlockedResponse` truncates + flips flags on the exact-sized
    dupe, the caller sets **NSCOUNT=1**, then copies `data[0..question_len]` into a
    `question_len + WIRE_LEN` buffer and appends the SOA there — so the exact-length query
    dupe is never overrun.
- **Remaining C2 follow-ups (not blockers)** *as recorded on 07-30:* no golden-bytes test
  yet (tracked in P2.5); the negative-cache TTL is hard-coded to 3600 in `Authority` (make
  it configurable in P2.1); the blocked path is still NXDOMAIN-only regardless of qtype
  (P4.1) and still drops a client OPT (P3.5).
  *Status as of 08-08:* the golden-bytes test landed; the other three are still open. The
  `craftBlockedResponse` named here is now `Header.writeResponseFlags` plus
  `blocked_response.build`.



- **P0.B1–B6** — all six pending-table bugs fixed: sweeper now compares ns to ns
  ([pending_table.zig:153](../src/utils/pending_table.zig#L153)); `dead_queries` is
  `defer`-freed ([:91](../src/utils/pending_table.zig#L91)); the proxy ID is reclaimed on
  upstream send failure ([main.zig:143](../src/main.zig#L143)); the bogus `main.zig` import
  is gone; the capacity guard is `> maxInt(u16)`
  ([:37](../src/utils/pending_table.zig#L37)); `pending_table.deinit()` is deferred
  ([main.zig:396](../src/main.zig#L396)).
- **P1.3 (partial)** — dispatcher now drops responses whose source address isn't the
  upstream. The optional question-hash verification is still open (see P1 below).
- **P3.4** — suffix/wildcard blocking implemented, plus a curated allowlist that
  overrides blocks, composed through `Policy.decide`. This is the first concrete slice
  of the [filter-design.md](filter-design.md) `Filter`/`Chain` design.

### Landed 2026-07-27 (earlier session)

- **P0.C1 fixed** — `parseQuestion` now lowercases each label as it builds the name
  ([question.zig:41–43](../src/dns/question.zig#L41)), so every filter matches on a canonical
  QName. The wire buffer is untouched, so forwarded queries keep their original case.
  Regression test added ([question.zig](../src/dns/question.zig), `parseQuestion lowercases
  the qname`).
- **Test harness fixed (half of P2.5)** — `zig build test` was silently running **only**
  the `root.zig` `add(3,7)` stub: a plain `@import` alias doesn't pull an imported file's
  `test` blocks into the build. Added a `test { _ = @import(...) }` aggregator to
  [main.zig](../src/main.zig) so all module tests now run (`6/6` and counting). This is the
  precondition for the rest of P2.5 to mean anything.
- **New tests** — `parseQuestion` case-normalization (above) and `SuffixBlockList.decide`
  parent-label walk ([suffix_blocklist.zig](../src/blocklist/suffix_blocklist.zig)).

---

## P0 — Correctness bugs

**None open, and all three are pinned by tests.** C1 (QName lowercasing), C2 (cacheable
SOA), and C3 (QR bit on ingress) are fixed *and* each has a named regression test that fails
under mutation:

| Bug | Fixed | Pinned by |
|-----|-------|-----------|
| C1 — QName never lowercased | 2026-07-27 | [question.zig:72](../src/dns/question.zig#L72), plus the verbatim-question assertion in the C2 golden test (the wire-case half) |
| C2 — blocked NXDOMAIN carries no SOA | 2026-07-30 | [blocked_response.zig](../src/dns/blocked_response.zig) — three golden-bytes tests, 2026-08-08 |
| C3 — QR bit never checked on ingress | 2026-08-07 | [header.zig:252+](../src/dns/header.zig#L252) — three `validateQuery` tests, 2026-08-08 |

The subsections below are retained as **reference for the behavior now shipped**, not as
to-dos; each records why the fix is shaped the way it is and what now keeps it that way.
Each also lists the follow-ups that were deliberately spun out into lower priorities — those
are the live work, not the P0s themselves.

### ~~C1. QName is never lowercased~~ — ✅ fixed 2026-07-27

### ~~C3. QR bit is never checked on ingress~~ — ✅ fixed 2026-08-07

Background: `handleQuery` parsed the header ([main.zig:71–72](../src/main.zig#L71)) and read
`id`, `opcode`, and the counts, but **never looked at `header.qr`**. Any datagram ≥ 12 bytes
that parsed as a question was treated as a query: run through `Policy`, given a fresh proxy
ID, and sent to the upstream resolver.

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

**How it was fixed:** `Header.validateQuery` returns `.is_response` for QR=1
([header.zig:115–127](../src/dns/header.zig#L115)), and `handleQuery` switches on it between
`parseHeader` and `Policy.decide` ([main.zig:67–83](../src/main.zig#L67)) — before the
`PendingTable` allocation, and silent, since a server must not answer a response.

**Pinned by three tests** ([header.zig:252+](../src/dns/header.zig#L252)): QR=1 rejected,
ordinary query accepted, and QR-in-isolation. All three fail if the guard is inverted
(verified by mutation), so this fix can't silently regress the way it silently arrived.

**Remaining follow-up:** the rest of the "validate the header before acting on it" family
(QDCOUNT≠1, non-standard opcodes) is still open in **P4.2** — extend `Rejection` and
`validateQuery` rather than adding a second scattered `if`. Its other prerequisite also
landed on 08-08: `Header.writeResponseFlags(msg, rcode)` now takes the RCODE as a parameter,
so a FORMERR/NOTIMP reply reuses the flag flip directly.

### ~~C2. Blocked NXDOMAIN carries no SOA~~ — ✅ fixed 2026-07-30

Background: a negative answer with an empty authority section carries **no TTL to cache
against** — RFC 2308 says a resolver takes the negative-cache lifetime from the SOA in the
Authority section (the smaller of the SOA's record TTL and its MINIMUM field). No SOA ⇒ the
client can't cache the "doesn't exist" ⇒ it re-queries on *every* reference. The fix
appends one synthetic SOA and sets NSCOUNT=1; clients don't validate MNAME/RNAME for a
sinkhole, so those are root-label placeholders and only the negative-cache TTL matters.

#### Wire layout emitted (after the question section)

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

#### How it was implemented

- **[authority.zig](../src/dns/authority.zig)** — `write_authority_section` serializes
  every multi-byte field with `std.mem.writeInt(…, .big)`, sidestepping the
  `packed struct` + `@bitCast` endianness trap (native little-endian would have written
  SERIAL `1` as `01 00 00 00`). The owner NAME pointer and root MNAME/RNAME go out as
  literal bytes. Two `assert`s (added 08-08) check the caller left room for all 34 bytes and
  that the QNAME really is at offset 12, since `0xC00C` is meaningless otherwise.
- **The buffer gotcha** — the handler buffer is `gpa.dupe(u8, incoming.data)`
  ([main.zig:401](../src/main.zig#L401)), sized to the *exact* query length, so the blocked
  branch can't extend it in place. `blocked_response.build` allocates a fresh
  `question_end + WIRE_LEN` buffer, copies the question in (the copy length is what
  truncates the message), flips the flags and counts *in the output*, and appends the SOA
  there. `query` is only ever read.
- **Assembly lives in one pure function** (08-08) —
  [blocked_response.zig](../src/dns/blocked_response.zig). Previously it was ~18 inline
  lines in `handleQuery`, reachable only with an `Io` and two live sockets, which is why C2
  went four weeks without a test.

#### Remaining follow-ups (moved to their own priorities)

- ~~**No golden-bytes test yet.**~~ ✅ **Landed 2026-08-08** — three tests in
  [blocked_response.zig](../src/dns/blocked_response.zig) assert the exact 67 output bytes,
  the full flags word, all four counts, the verbatim question, and the 34-byte SOA against a
  literal array. Byte-reversing SERIAL or MINIMUM fails all three.
- **Still NXDOMAIN, not NODATA.** Per-qtype response strategy (NODATA for AAAA, `0.0.0.0`
  sinkhole for A) is **P4.1**. The `rcode` parameter on `build` is the door in — a NODATA
  reply is this exact shape with `rcode = .no_error`.
- **OPT still dropped.** The response is truncated at `question_end`, discarding any client
  OPT; echoing EDNS is **P3.5**. The current behavior is *pinned by a test*, so fixing P3.5
  means updating that test deliberately.
- **TTL hard-coded to 3600.** Make the negative-cache TTL configurable in **P2.1**. Note
  this also un-`comptime`s `Authority`'s fields (see Housekeeping) and turns the golden
  test's literal SOA array into a function of the configured TTL.

---

## P1 — Hardening the dispatcher path

**Only P1.5 remains open.** P1.1–P1.4 all landed 2026-08-09; entries kept below as a record
of what each was and how it was resolved.

1. ~~**Unit tests for `PendingTable`.**~~ ✅ **Done 2026-08-09** — eight tests, mutation-verified,
   including the B1 expiry regression. Original note follows.
   **Was:** Still *zero* tests, and this is exactly where the
   P0.B-series bugs hid. The list stands: allocate/complete round trip, expiry,
   sweep-only-expired, collision retry, ID-space exhaustion, idempotent complete. B1
   would have been caught by the first expiry test.
2. ~~**Supervisor for dispatcher/sweeper death.**~~ ✅ **Done 2026-08-09** — `supervise`
   ([main.zig:313](../src/main.zig#L313)) wraps both loops and restarts on any non-`Canceled`
   return, with exponential backoff (`0s → 1s → … → 30s`, reset after a 60s clean run) so a
   fast-returning loop cannot become a spin. Original note follows.
   **Was:** ~~Ingress-loop error recovery~~ — ✅ **fixed
   2026-08-08**: `receive` now propagates only `error.Canceled` (clean shutdown) and logs +
   `continue`s otherwise, and a failed `gpa.dupe` sheds the datagram
   ([main.zig:366–411](../src/main.zig#L366)), matching the shape `dispatcherLoop` uses
   ([main.zig:150–157](../src/main.zig#L150)). What remains is the *coroutine* half: if
   `dispatcherLoop` ever returns, every future forwarded query hangs silently — the ingress
   loop keeps enqueuing to a table nobody drains. Have `main` watch the group (or wrap each
   loop body in a catch-all + respawn) instead of fire-and-forget `group.async`. Note that
   `Group.async` returns `void` and cannot fail (`std/Io.zig:1240`), so the spawn itself is
   not a failure point — only the task body is.
   - *Ownership note for whoever touches this next:* the duped datagram is owned by
     `handleQuery`, whose `defer gpa.free(data)` covers **every** exit path including the
     early QR and malformed-question returns. Do not add a `free` in those branches (double
     free) and do not free at the call site after `group.async` (use-after-free). The
     08-08 pass briefly had a second `gpa.dupe` at the call site, which leaked one copy per
     query and left the fatal `try` in place — worth not reintroducing.
3. ~~**Question-hash verification.**~~ ✅ **Done 2026-08-09** — seeded `question_hash` +
   `question_len` in `PendingQuery`, checked by the dispatcher **before** the entry is
   consumed (`peek` → verify → `complete`; see the landed entry for why that ordering is
   load-bearing). The reply path never re-parses.
4. ~~**SERVFAIL on sweep.**~~ ✅ **Done 2026-08-09** — `sweepExpiredQueries` reports evicted
   entries to the caller; `sweeperLoop` sends `Header.synthesizedReply(id, .server_failure)`.
   Measured latency is ~5.4 s (the 5 s deadline plus up to 1 s of sweep granularity).
   **Two follow-ups:** the reply carries QDCOUNT=0 because the sweeper has no question bytes
   — `dig` accepts it, matching on ID, but a stricter stub resolver may ignore it and fall
   back to its own timeout (never worse than the old silence). Echoing the question would
   mean storing the bytes rather than the hash, which is a real memory trade, not a free
   upgrade. And the 5 s deadline plus 1 s cadence are still hard-coded — newly unblocked for
   **P2.1** now that their consumer takes runtime values, and arguably too long for a
   forwarder (2–3 s is typical).
5. **Bounded in-flight concurrency / backpressure.** The ingress loop does an unbounded
   `group.async(handleQuery, …)` plus a `gpa.dupe` **per received datagram**
   ([main.zig:366–411](../src/main.zig#L366)). The P1.2 fix put a `catch` on that `dupe`, so
   an allocation failure now sheds one datagram instead of killing the server — but that is
   a backstop, not a bound: nothing caps how many handlers are in flight before the
   allocator starts failing. A UDP flood still spawns unbounded coroutines and
   unbounded heap — a trivial memory-exhaustion DoS the moment this leaves localhost.
   Cap concurrent handlers (semaphore / fixed worker pool / bounded queue) and shed load
   past the cap. Distinct from per-client rate limiting (P2.7): this protects the process
   itself.

---

## P2 — Production operability (still mostly unbuilt)

1. **Configuration — mechanism done 2026-08-09, fields partly.**
   [settings.zig](../src/settings.zig) is now a runtime `Settings` struct resolved at
   startup from **defaults < `.env` file < process environment**, replacing the compile-time
   `pub const` block. `.env` at the repo root is finally read (it previously existed and
   nothing looked at it).
   - **Done:** listen host+port, upstream host+port, upstream bind host+port, both blocklist
     URLs. All eight are `VORTEX_`-prefixed env vars; `VORTEX_ENV_FILE` picks a different
     file. A missing default `.env` is fine; a file named explicitly that isn't there is
     fatal, as is a malformed port — silently listening on 5354 because someone typed
     `535e` is the config bug that costs an hour.
   - **Still to do:** `std.process.args` for CLI flags (highest precedence, above process
     env), multiple upstreams (P4.3), **local file paths as a blocklist source alongside
     URLs — now a blocker for the P2.5 integration harness, since a 25s HTTP fetch at
     startup makes per-case integration tests unusable**,
     and the four knobs whose *consumers* can't take a runtime value yet — **timeouts**,
     **log level** (needs P2.3), **negative-cache TTL** (needs `Authority`'s comptime fields
     un-`comptime`d, see Housekeeping), and **fail-open vs fail-closed** (needs P2.2). Each
     is one struct field plus one line in `fromEnviron` once its consumer is ready.
   - Four tests, all pure over a byte slice plus an `Environ.Map` — the dotenv grammar,
     the precedence rule, malformed-line recovery (CRLF/BOM/bad keys), and default fallback
     plus port rejection.
2. **Blocklist resilience.** Both lists are fetched concurrently at startup; a non-OK
   status or network error now returns `error.BlocklistFetchFailed`, which `main`
   propagates — so the server **fails closed: no blocklist means no DNS at all**. That's
   the opposite of the old silent fail-open, and arguably worse for a resolver (a
   transient GitHub blip takes your whole network's DNS down). Needed: a deliberate,
   configurable fail-open-vs-closed policy, a local cache file written on success and
   loaded on fetch failure, retry with backoff, and **periodic refresh**. Refresh then
   requires the read-mostly swap strategy from [README.md](../README.md) — build a fresh set
   off to the side and atomically swap the pointer; don't mutate the live set under the
   readers in `handleQuery`.
3. **Structured logging + metrics.** Logging is human-readable `console.println`
   (`"Allow"`, `"PASS"`, `"{s} -> BLOCKED"`) with no client, qtype, latency, or verdict
   fields, and there are no counters. Add a structured per-query line (ts, client, qname,
   qtype, verdict, rcode, latency) and counters: total / blocked / forwarded / orphan
   responses / sweep evictions / upstream latency. The choke points already exist:
   `Policy.decide`, `appendQuery`/`complete`, the orphan branch in `dispatcherLoop`.
4. **Graceful shutdown.** No signal handling; the only exit is a crash or Ctrl-C
   mid-write. Catch SIGINT/SIGTERM, `group.cancel`, flush the console, run the deferred
   deinits.
5. **Test coverage + CI.** The harness bug is fixed and **CI exists** (`.github/workflows/ci.yml`
   — `zig fmt --check`, build, test, plus a ReleaseSafe job). **`31/31`, of which 28 are real**;
   the count has moved four times over 08-08/08-09 after stalling since 2026-07-27.
   - **28 real behavior tests** — `DomainName` append, allowlist hit/miss, `parseQuestion`
     case normalization, `SuffixBlockList.decide` parent-walk, **nine** `Header` tests
     (P0.C3 QR validation, P4.2 opcode/QDCOUNT, `headerOnlyReply`, `markTruncated`,
     `synthesizedReply`), **three** `blocked_response.build` golden-bytes tests (P0.C2),
     **four** `settings` env-file/precedence tests (P2.1), **eight** `PendingTable`
     tests (P1.1) covering round trip, idempotent complete, the B1 expiry regression,
     no-op sweep, distinct proxy IDs, ID-space exhaustion, `peek` non-consumption and
     `hashQuestion`, and the `backoffSeconds` schedule test (P1.2).
   - **3 that assert nothing about Vortex** — `root.zig`'s `add(3, 7) == 10` stub;
     `main.zig`'s "initialize sockets", which only checks a std-library assertion; and the
     `test { _ = @import(…) }` aggregator, which the runner counts as a passing test.

   **The lesson, now confirmed four times.** C3 became testable when the check moved into
   pure `Header.validateQuery`; C2 when assembly moved into pure `blocked_response.build`;
   P2.1 when the dotenv parser split from the file read; P1.1 when
   `sweepExpiredQueries` was changed to *report* evictions instead of sending them.
   Every one of those is the same move: **separate deciding from doing, and the test needs
   no `Io`.**

   Three more worth keeping:
   - **Assert against literal bytes**, not values recomputed from the same constants the
     code uses — that is what catches a byte-reversed SERIAL/TTL/MINIMUM.
   - **Test the interaction, not just the units.** P1.3 and P1.4 were each correct in
     isolation; the defect was that verifying a reply consumed the entry, so a rejected
     forgery killed the real query. Only an end-to-end run against a hostile upstream
     showed it.
   - **`zig build test` does not type-check `main`.** Discovered 2026-08-09 while adding the
     supervisor backoff: `backoffSeconds` returned `u64` where `Io.Duration.fromSeconds`
     takes `i64`, and for several minutes **`zig build test` reported 0 errors while
     `zig build` failed to produce a binary at all.**

     The cause is Zig's lazy analysis. In a test build the root is `main.zig`, but the test
     runner supplies its own entry point, so `pub fn main` is never referenced and never
     analysed — and neither is anything reachable only from it. That covers a lot of this
     project: the ingress loop, `supervise`, and all the wiring in `main` sit outside any
     `test` block.

     **Consequence: a green test suite is not evidence that Vortex compiles.** Always run
     `zig build` too. CI already does — `zig build` and `zig build test` are separate steps,
     plus a ReleaseSafe pair — which was belt-and-braces when it was written and now has a
     concrete justification. Anything you want the compiler to check must be reachable from
     a `test`, or you must build the exe.

   Still missing:
   - **An integration harness for the coroutine-bound code — now the largest gap.**
     The 31 tests are almost entirely over pure functions. `handleQuery`, `dispatcherLoop`
     and the ingress loop have **no automated coverage of any kind** — not runtime, and (per
     the third lesson above) not even compile-time from `zig build test`. Everything proven
     about them on 2026-08-09 was proven by hand with `dig` and throwaway Python.

     That is a different shape of gap from the rest of this list: it cannot be closed by
     extracting another pure function, because what is untested *is* the socket plumbing.
     It needs a harness that spawns the binary against a scratch config, drives it with
     crafted UDP, and asserts on the replies.

     The manual runs that would become its first cases, and what each one caught:

     | Scenario | Asserts | Caught |
     |---|---|---|
     | Normal forward | reply relayed, ID restored | — |
     | Blocked name | NXDOMAIN + 34-byte SOA, `0xC00C` resolves | — |
     | `+opcode=IQUERY` | NOTIMP, `QUERY: 0` | — |
     | 5000-byte query | 12-byte FORMERR, no coroutine spawned | — |
     | Upstream returns 5000 bytes | TC=1 set on the relayed prefix | the silent-corruption bug |
     | Upstream never answers | SERVFAIL at ~5.4s, not silence | — |
     | Upstream echoes right ID, wrong question | reply dropped **and** client still gets SERVFAIL | the peek-vs-complete DoS |
     | Supervised loop returns immediately | backoff `0→1→2→4→8→16→30`, not a spin | — |

     Two of those found real bugs that every unit test passed straight through, which is the
     argument for building it.

     **P2.1 is what makes this feasible** — pointing the binary at a fake upstream on a
     scratch port is now a config file, not a recompile.

     **But there is a hard prerequisite:** startup blocks on fetching two blocklists over
     HTTP, which took ~25s in every manual run. At 25s per case this is unusable in CI. The
     harness needs the **local-file blocklist source** already listed under P2.1's "still to
     do" — or an injection seam for the lists. Do that first; the harness is cheap
     afterwards and near-impossible before.
   - **`Question.parseQuestion` malformed-input tests** — the error paths
     (`TruncatedQuestion`, `UnsupportedLabel`, `NameTooLong`) all exist in
     [question.zig](../src/dns/question.zig) and are all unexercised.
   - `parseDomain`/`parseSuffixDomain` parsing tests. `policy.zig` and `console.zig` are now
     the only files carrying logic with **no `test` blocks at all**.
   - **CI has never actually run.** Every step passes locally, but the workflow, the
     `mlugg/setup-zig` action and the Ubuntu runner are unexercised until the first push.
     Note its `zig build` step is load-bearing, not decorative — see the third lesson above.
   Housekeeping: `root.zig` is still the template stub and the module root of the second
   test artifact — fold it into the aggregator or delete it.
6. **Deployment surface.** `127.0.0.1:5354` is dev-only. Real use means `0.0.0.0:53`
   (privileged port → capability / launchd / systemd unit), an IPv6 listener, and a
   service definition. Pick the target platform and add the unit files.
7. **Rate limiting / abuse controls.** Any resolver reachable beyond localhost needs
   per-client rate limiting (and ideally Response Rate Limiting) so it can't be conscripted
   into DNS amplification. Pairs with, but is separate from, the process-level backpressure
   in P1.5.

---

## P3 — Protocol completeness

Priority order unchanged: **compression → response parsing → caching**, each depending on
the previous. (P3.4 wildcard blocking is now **done** — see the top of this doc.)

1. **DNS message compression (pointer following).** Prerequisite for parsing any answer
   section. `0xC0`-prefixed length byte = pointer; follow with a depth/visited-offset
   limit against malicious loops. (`resource_record.zig`/`resource_data.zig` do not exist
   yet — create them fresh.)
2. **Parse upstream response records.** Decode Answer/Authority/Additional RRs to log
   resolved IPs/CNAMEs and extract TTLs — prerequisite for caching.
3. **TTL-aware response caching.** Keyed on `(qname, qtype, qclass)`; store response
   bytes + expiry; on hit rewrite txid and reply without touching upstream. Plugs in
   cleanly: check in `handleQuery` before `appendQuery`, populate in `dispatcherLoop`
   before forwarding to the client.
4. ~~**Wildcard / suffix blocking.**~~ **Done** — `SuffixBlockList` walks parent labels;
   `Policy` composes it after the exact blocklist, with the allowlist overriding both.
   Remaining polish: fold the hand-rolled `Policy` into the comptime duck-typed
   `Filter`/`Chain` from [filter-design.md](filter-design.md), and add a suffix-*allow*
   matcher for the entries parked in the allowlist's "NEEDS SUFFIX-ALLOW" comment
   ([allowlist.zig:56](../src/blocklist/allowlist.zig#L56)).
5. **EDNS0 (RFC 6891).** 4096-byte buffers are in place on both sockets; still missing:
   parse the client's OPT record, attach our own OPT on upstream queries to advertise the
   4096 capacity, and **preserve/echo the client OPT on blocked responses** —
   `blocked_response.build` truncates the message at `question_end`, dropping any OPT, which
   is a protocol violation if the client sent one. As of 08-08 that behavior is **pinned by
   a test** ("build drops a trailing OPT record and clears ARCOUNT"), so fixing this means
   deliberately rewriting that test — which is the point: the drop stops being an
   unexamined default and becomes a decision. Echoing an OPT also changes the response-size
   arithmetic `WIRE_LEN` currently makes trivial.
6. **TCP fallback.** On TC=1 from upstream, retry over TCP with 2-byte length framing
   (RFC 1035 §4.2.2). The dispatcher detects TC=1 and hands off to a TCP path.
   **Newly concrete as of 08-09:** we now *set* TC=1 ourselves when an upstream reply
   overflows the 4096-byte buffer, so a conforming client will retry over TCP and find
   nothing listening. That is a deliberate, honest failure rather than the silent corruption
   it replaced — but it means this item now has a reachable trigger, not just a theoretical
   one. A TCP listener would also remove the ingress-side FORMERR for oversized queries.
7. **Multiple upstreams / DoT / DoH.** Future arcs the dispatcher architecture was chosen
   to accommodate (a connection pool replaces `upstream_socket`, same `PendingTable`
   pattern). See the evolution table in [upstream-design.md](upstream-design.md).

---

## P4 — Missing for a *production-grade DNS blackhole* (new)

Gaps beyond raw protocol/operability that separate a forwarder-with-a-blocklist from a
real sinkhole (the Pi-hole / AdGuard Home / Unbound-`local-zone` feature class):

1. **Blocked-response strategy per qtype.** Today every block is NXDOMAIN regardless of
   query type. That is one legitimate strategy, but it has real downsides and a
   production sinkhole makes this a *choice*:
   - **NXDOMAIN** — "domain doesn't exist." Simple, but some apps interpret it as a hard
     failure and retry aggressively; it also lies about non-A records.
   - **NODATA (NOERROR + empty answer + SOA)** — "domain exists, no record of this type."
     Gentler; the common default for AAAA so clients don't stall waiting on a bogus A6/AAAA.
   - **Null-IP sinkhole (`0.0.0.0` / `::`)** — return an unroutable address in the answer
     section. Fastest client failure (connection refused vs. resolution retry), and what
     the StevenBlack `hosts` format literally encodes. Needs an actual A/AAAA answer RR,
     not just flipped header flags.
   Decide a default, make it configurable, and branch on `qtype` (A vs AAAA vs everything
   else). This subsumes C2 (the SOA is required for the NODATA/NXDOMAIN caching paths).
2. ~~**QDCOUNT / opcode validation.**~~ ✅ **Done 2026-08-09** — see the landed entry above. Original spec follows.
   **Was:** `parseQuestion` always reads exactly one question at
   offset 12 regardless of QDCOUNT, and opcode is parsed but unused. Reject QDCOUNT≠1 and
   non-standard opcodes with FORMERR/NOTIMP instead of parsing whatever is at offset 12.
   Same root cause as **P0.C3**, which is now fixed — so both prerequisites already exist
   and have names. **This is now the cheapest item on the board**; it is fully specified:

   ```zig
   pub const Rejection = enum { none, is_response, bad_opcode, bad_qdcount };

   pub fn validateQuery(self: *const Header) Rejection {
       if (self.qr == 1) return .is_response;                  // silent drop
       if (self.opcode != .standard_query) return .bad_opcode;  // NOTIMP  (4)
       if (self.question_count != 1) return .bad_qdcount;       // FORMERR (1)
       return .none;
   }
   ```

   Order matters — QR is checked first because it is the only one that must *not* generate
   a reply. Then handle the two new variants in `handleQuery`'s switch
   ([main.zig:67–83](../src/main.zig#L67)); the compiler will point at it for you. A
   placeholder comment marks the spot in `Rejection`. Flag-flipping is already
   rcode-parameterized: `Header.writeResponseFlags(msg, .format_error)`.

   **One design decision to make before writing the handler arm.** The reply shape is *not*
   the blocked-response shape. `blocked_response.build` echoes the question section and
   appends an SOA — but for `bad_qdcount` you cannot echo a question, because whether one
   parses is precisely what is in doubt, and for `bad_opcode` (e.g. IQUERY) there may not be
   a question section at all. So these need a **header-only 12-byte reply with QDCOUNT=0**,
   not a call into `build`. Decide that explicitly; the tests are then the same three lines
   as the QR ones.
3. **Upstream timeout & failover.** A single upstream with no explicit per-query timeout
   (the sweeper's 5 s is the only bound) and no secondary. Production forwarders round-robin
   or fail over to a second upstream on timeout/SERVFAIL, and surface upstream health.
4. **Local custom records / conditional forwarding.** The staple sinkhole features beyond
   blocking: local A/PTR records (name your LAN devices), CNAME/host overrides, and
   split-horizon / conditional forwarding (send `*.internal` to a different upstream).
   These slot in ahead of the blocklist as another `Filter`/resolver stage.
5. **Blocklist normalization & footprint.** The two lists (StevenBlack hosts + hagezi
   wildcards) overlap heavily and the raw HTTP bodies are retained for the process
   lifetime via `Writer.Allocating` inside each list (`file_body` is never freed until
   `deinit`, and the `StringHashMap` keys are slices *into* that body). Document/decide
   this ownership model, dedupe exact entries already covered by a suffix, and consider
   freeing the source body after building if you switch to owned keys — matters once both
   lists are ~100k+ entries.
6. **Observability surface for a sinkhole.** Beyond raw counters (P2.3): top blocked
   domains, per-client query/block ratios, and a query log with a retention/privacy
   policy (DNS query logs are PII). This is the dashboard half of what makes Pi-hole
   Pi-hole; scope it once structured logging exists.
7. **DNSSEC posture.** Decide and document: we're a non-authoritative forwarder, so
   blocked synthetic answers can't be signed — a validating client with DO set that
   queries a blocked name will get a bogus/unsigned answer. Confirm we pass the DO bit and
   RRSIGs through untouched on the *forwarded* path, and document that blocking is
   incompatible with strict downstream validation of the blocked names (every sinkhole has
   this caveat).

---

## Housekeeping

- Delete or repurpose the remaining template leftovers (empty `src/server.zig` was deleted
  2026-08-09): the
  stub [src/root.zig](../src/root.zig) (`add`/`printAnotherMessage`) which is also the
  misleading module root, `copy.zig` at the repo root, and the boilerplate comment walls
  in [build.zig](../build.zig).
- `Question.question_str_slice` ([question.zig:15](../src/dns/question.zig#L15)) is declared
  but never assigned or read — drop it or wire it up.
- **Three sibling docs still name `craftBlockedResponse`** (renamed 2026-08-08):
  [dns-message-format.md](dns-message-format.md) (§"Which sections … modifies", plus a code
  listing), [async-migration.md](async-migration.md) (three snippets and an explanatory
  note), and [filter-design.md](filter-design.md) (two snippets and the `block`-verdict
  discussion). Their *descriptions* of the wire behavior are still accurate — only the
  function name and call shape moved. Worth a sweep, and note that
  [dns-message-format.md:159](dns-message-format.md) additionally still claims "we don't add
  an SOA", which C2 made false back on 07-30.
- ~~**Stale comment on `PendingQuery.expires_at`**~~ — ✅ **fixed 2026-08-08.** It claimed
  "ns since boot, `std.time.nanoTimestamp()`"; both the writer
  ([main.zig:132](../src/main.zig#L132)) and the sweeper
  ([pending_table.zig:153](../src/utils/pending_table.zig#L153)) use ns-since-epoch from
  `std.Io.Timestamp.now(io, .real)`. There was never a bug, but this was the comment that
  invited reintroducing **B1** (the fixed ns/ms mismatch); it now names the clock and says
  why the unit matters.
- ~~`.env` exists at the repo root but nothing reads it~~ — ✅ **wired up 2026-08-09** (P2.1).
  It is now the documented reference for every knob. Two follow-ups: there is no `.gitignore`
  (moot while this repo is not under version control, but `.env` is conventionally ignored,
  and this one is safe to commit only because it holds no secrets); and if a future knob ever
  *is* a secret, revisit that before adding it.
- `Authority` ([authority.zig](../src/dns/authority.zig)) models the SOA as a struct of
  `comptime` fields with a runtime `write_authority_section` method. It works, but every
  field is a fixed constant — a namespaced `const` block (or plain named byte constants)
  would say the same thing without the `var authority = Authority{};` instance dance, which
  now lives in `blocked_response.build` rather than `handleQuery`. Revisit if/when the
  negative-cache TTL becomes configurable (P2.1), since that field then stops being comptime
  anyway — and note the golden-bytes test's literal SOA array has to become TTL-dependent at
  the same time.

---

## Suggested order

**All three P0s are now pinned**, so the regression risk that drove the last two passes is
retired. What follows is ordered by cost-to-value, cheapest first.

**1. P4.2 (QDCOUNT/opcode) — do this next.** It has jumped the queue twice and is now
almost free: `Header.validateQuery`, `Rejection`, and the rcode-parameterized
`writeResponseFlags` all exist. Two enum variants, two `if`s, two switch arms, and three
tests in the shape already established. It closes out header validation entirely, and the
P4.2 entry above spells out the one open decision (header-only FORMERR replies).

**2. Finish the tests (P2.5 + P1.1).** Write the **`parseQuestion` malformed-input tests**
first — pure, over byte slices, no `Io`, same shape as everything added on 08-08. Then the
**`PendingTable` suite**, which is now the single largest gap on the board: still zero
tests, and where the entire P0.B series hid. It needs an `Io`, so budget more for it than
for the byte-slice tests. Add the **CI workflow** in the same pass so the count can't
quietly stall for six weeks again — `.github/` still does not exist.

**Then P2.1 config + P2.3 structured logging** — makes everything after observable, and
P2.1 unblocks the configurable negative-cache TTL that C2 hard-coded.

**Then branch:** **P4.1 blocked-response strategy** if the goal is "a real blackhole," or
the **P3 compression → parsing → caching** track if the goal is "keep learning DNS."
P1.4 and the coroutine-supervisor half of P1.2 are small and can be sprinkled in anytime;
**P1.5 and P2.7 both jump the queue the moment you bind anything other than localhost** —
C3 removed the reflector and P1.2 stopped OOM from being fatal, but nothing yet *bounds*
the number of in-flight handlers a flood can create.

For the view from above — how far along the whole project is, which of these bands is worth
the most per unit of effort, and why "no open P0s" does **not** mean "safe to deploy" — see
[progress.md](progress.md).

Reference docs, still accurate: [dns-message-format.md](dns-message-format.md) (wire
format + error table), [upstream-design.md](upstream-design.md) (architecture rationale),
[async-migration.md](async-migration.md) (async patterns),
[filter-design.md](filter-design.md) (the `Filter`/`Chain` design the `Policy` chain is
converging toward).
