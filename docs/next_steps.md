# Next Steps — Road to Production-Ready

Reviewed **2026-08-19** against the current source (Zig 0.16.0, `zig build test` →
**59/59 pass**, of which 56 are real behavior tests). **No open P0s, and no open P1 bugs** —
all three P0s are pinned by regression tests that fail under mutation.

**History lives in [changelog.md](changelog.md)** — dated entries for everything that landed,
the three closed P0s in detail, and the shipped P3.1 plan. This file is the board: open work
only.

The single largest remaining gap is that `handleQuery`, `dispatcherLoop` and the ingress loop
have **no automated coverage at all**, and cannot get any by extracting another pure
function, because what is untested is the socket plumbing itself. That needs an integration
harness (**P2.5**), which in turn needs a local-file blocklist source (**P2.1**) so startup
does not cost 25 seconds per case.

## What exists today

- Ingress loop + per-query `handleQuery` coroutines via `std.Io.Group` ([main.zig](../src/main.zig)),
  both long-lived loops wrapped in `supervise` with exponential backoff
- Header validation on ingress via `Header.validateQuery` ([header.zig](../src/dns/header.zig))
  — QR=1 datagrams are dropped, non-standard opcodes get NOTIMP, QDCOUNT≠1 gets FORMERR; a
  malformed question section is logged and dropped rather than acted on
- An ingress loop that survives transient errors: `receive` failures are logged and retried,
  a datagram is shed when its buffer can't be allocated, and an oversized query gets FORMERR
  before the dupe and coroutine spawn
- Shared upstream socket with `dispatcherLoop` demuxing by proxy transaction ID, with a
  source-address check and a seeded question-hash check on every response, ordered
  `peek → verify → complete`
- `PendingTable` with random proxy IDs, mutex, monotonic (`Clock.boot`) deadlines, and a
  sweeper coroutine that SERVFAILs what it evicts ([pending_table.zig](../src/utils/pending_table.zig))
- Runtime configuration from defaults < `.env` < process environment ([settings.zig](../src/settings.zig))
- Structured logfmt logging installed as `std.options.logFn`, with escaping that no call site
  can bypass, and runtime level/format knobs ([obs/log.zig](../src/obs/log.zig))
- Multi-label QName parsing with bounds checks, lowercased in place ([question.zig](../src/dns/question.zig)),
  on top of an allocator-free name reader that follows compression pointers on the response
  path and refuses them on the query path ([name_reader.zig](../src/dns/name_reader.zig))
- A `Policy` filter chain — allowlist → exact blocklist → suffix blocklist — with a
  three-valued `Verdict` (`allow`/`block`/`pass`) ([policy.zig](../src/blocklist/policy.zig))
  - Exact-match blocklist fetched over HTTP ([domain_blocklist.zig](../src/blocklist/domain_blocklist.zig))
  - Suffix/wildcard blocklist walking parent labels ([suffix_blocklist.zig](../src/blocklist/suffix_blocklist.zig))
  - Comptime allowlist that overrides a block, validated lowercase at build time ([allowlist.zig](../src/blocklist/allowlist.zig))
- NXDOMAIN synthesis for blocked names, assembled in one pure function
  ([blocked_response.zig](../src/dns/blocked_response.zig)) from `Header.writeResponseFlags`
  plus a cacheable SOA ([authority.zig](../src/dns/authority.zig))
- CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) — `zig fmt --check`, build,
  test, plus a ReleaseSafe job

---

## P0 — Correctness bugs

**None open, and all three are pinned by tests.** C1 (QName lowercasing), C2 (cacheable SOA),
and C3 (QR bit on ingress) are fixed *and* each has a named regression test that fails under
mutation. Full detail — what each bug was, why the fix is shaped that way, and what keeps it
that way — is in [changelog.md](changelog.md#reference--the-three-closed-p0s-in-detail).

---

## P1 — Hardening the dispatcher path

**Only P1.5 remains open.** P1.1–P1.4 landed 2026-08-09; see
[changelog.md](changelog.md#p11p14-all-landed-2026-08-09).

**P1.5 — bounded in-flight concurrency / backpressure.** The ingress loop does an unbounded
`group.async(handleQuery, …)` plus a `gpa.dupe` **per received datagram**. The P1.2 fix put
a `catch` on that `dupe`, so an allocation failure now sheds one datagram instead of killing
the server — but that is a backstop, not a bound: nothing caps how many handlers are in
flight before the allocator starts failing. A UDP flood still spawns unbounded coroutines and
unbounded heap — a trivial memory-exhaustion DoS the moment this leaves localhost. Cap
concurrent handlers (semaphore / fixed worker pool / bounded queue) and shed load past the
cap. Distinct from per-client rate limiting (P2.7): this protects the process itself.

---

## P2 — Production operability

1. **Configuration — mechanism done 2026-08-09, fields partly.**
   [settings.zig](../src/settings.zig) resolves a runtime `Settings` struct at startup from
   **defaults < `.env` file < process environment**.
   - **Done:** listen host+port, upstream host+port, upstream bind host+port, both blocklist
     URLs, log level and log format. All `VORTEX_`-prefixed; `VORTEX_ENV_FILE` picks a
     different file. A missing default `.env` is fine; a file named explicitly that isn't
     there is fatal, as is a malformed port — silently listening on 5354 because someone
     typed `535e` is the config bug that costs an hour.
   - **Still to do:** `std.process.args` for CLI flags (highest precedence, above process
     env), multiple upstreams (P4.3), **local file paths as a blocklist source alongside
     URLs — now a blocker for the P2.5 integration harness, since a 25s HTTP fetch at
     startup makes per-case integration tests unusable**, and the three remaining knobs whose
     *consumers* can't take a runtime value yet — **timeouts** (the 5 s deadline and 1 s sweep
     cadence, now unblocked), **negative-cache TTL** (needs `Authority`'s comptime fields
     un-`comptime`d, see Housekeeping), and **fail-open vs fail-closed** (needs P2.2). Each
     is one struct field plus one line in `fromEnviron` once its consumer is ready.
2. **Blocklist resilience.** Both lists are fetched concurrently at startup; a non-OK
   status or network error returns `error.BlocklistFetchFailed`, which `main` propagates —
   so the server **fails closed: no blocklist means no DNS at all**. That's the opposite of
   the old silent fail-open, and arguably worse for a resolver (a transient GitHub blip takes
   your whole network's DNS down). Needed: a deliberate, configurable fail-open-vs-closed
   policy, a local cache file written on success and loaded on fetch failure, retry with
   backoff, and **periodic refresh**. Refresh then requires the read-mostly swap strategy
   from [README.md](../README.md) — build a fresh set off to the side and atomically swap the
   pointer; don't mutate the live set under the readers in `handleQuery`.
3. **Structured logging + metrics — phase 1 landed 2026-08-10.** Every `std.log` call now
   renders as a logfmt record with escaping that no call site can bypass, and level/format
   are runtime knobs ([obs/log.zig](../src/obs/log.zig); see
   [changelog.md](changelog.md#landed-2026-08-10--p23-structured-logging-phase-1)).
   **Still open:** the per-query event carrying ts, client, qname, qtype, verdict, rcode and
   latency as *real fields* rather than a formatted `msg` body, and counters — total /
   blocked / forwarded / orphan responses / sweep evictions / upstream latency. The choke
   points already exist: `Policy.decide`, `appendQuery`/`complete`, the orphan branch in
   `dispatcherLoop`.
4. **Graceful shutdown.** No signal handling; the only exit is a crash or Ctrl-C mid-write.
   Catch SIGINT/SIGTERM, `group.cancel`, flush the log, run the deferred deinits.
5. **Test coverage.** `zig build test` → **59/59, of which 56 are real**: 17 `name_reader`
   (including the fuzz target), 9 `Header`, 8 `obs/log`, 7 `PendingTable`, 5 `settings`,
   4 `parseQuestion`, 3 `blocked_response` golden-bytes, `backoffSeconds`, allowlist
   hit/miss, and `SuffixBlockList.decide`. The 3 that assert nothing about Vortex are
   `root.zig`'s `add(3, 7)` stub, `main.zig`'s "initialize sockets", and the
   `test { _ = @import(…) }` aggregator, which the runner counts as a passing test.

   **The lesson, now confirmed five times.** C3 became testable when the check moved into
   pure `Header.validateQuery`; C2 when assembly moved into pure `blocked_response.build`;
   P2.1 when the dotenv parser split from the file read; P1.1 when `sweepExpiredQueries` was
   changed to *report* evictions instead of sending them; P3.1 when name reading became a
   pure function over a byte slice. Every one is the same move: **separate deciding from
   doing, and the test needs no `Io`.**

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
     plus a ReleaseSafe pair. Anything you want the compiler to check must be reachable from
     a `test`, or you must build the exe.

   Still missing:
   - **An integration harness for the coroutine-bound code — now the largest gap.**
     The 59 tests are almost entirely over pure functions. `handleQuery`, `dispatcherLoop`
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
   - `parseDomain`/`parseSuffixDomain` parsing tests. [policy.zig](../src/blocklist/policy.zig),
     [domain_blocklist.zig](../src/blocklist/domain_blocklist.zig) and
     [utility.zig](../src/utility.zig) are the only files carrying logic with **no `test`
     blocks at all**.
   - Housekeeping: `root.zig` is still the template stub and the module root of the second
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
the previous.

1. ~~**DNS message compression (pointer following).**~~ **Done 2026-08-13** —
   [name_reader.zig](../src/dns/name_reader.zig) reads names with pointer following, bounded
   by a strictly-backwards rule plus a 64-jump cap; `question.zig` is refactored onto its
   no-pointer variant and `DomainName` is deleted. Ships with no datapath caller by design.
   The full rationale is retained in
   [changelog.md](changelog.md#landed-2026-08-13--p31-compression-pointer-following),
   because P3.2 and P3.3 both build directly on its decisions.
2. **Parse upstream response records.** Decode Answer/Authority/Additional RRs to log
   resolved IPs/CNAMEs and extract TTLs — prerequisite for caching.
   (`resource_record.zig`/`resource_data.zig` do not exist yet — create them fresh, on top
   of the name reader from P3.1.) **This is where the reader gets its first datapath
   caller**: `dispatcherLoop` after `upstream_socket.receive`. See
   [P3.2 in detail](#p32-in-detail--parsing-upstream-response-records) below.
3. **TTL-aware response caching.** Keyed on `(qname, qtype, qclass)`; store response
   bytes + expiry; on hit rewrite txid and reply without touching upstream. Plugs in
   cleanly: check in `handleQuery` before `appendQuery`, populate in `dispatcherLoop`
   before forwarding to the client.
4. ~~**Wildcard / suffix blocking.**~~ **Done 2026-07-30.** Remaining polish: fold the
   hand-rolled `Policy` into the comptime duck-typed `Filter`/`Chain` from
   [filter-design.md](filter-design.md), and add a suffix-*allow* matcher for the entries
   parked in the allowlist's "NEEDS SUFFIX-ALLOW" comment
   ([allowlist.zig](../src/blocklist/allowlist.zig)).
5. **EDNS0 (RFC 6891).** 4096-byte buffers are in place on both sockets; still missing:
   parse the client's OPT record, attach our own OPT on upstream queries to advertise the
   4096 capacity, and **preserve/echo the client OPT on blocked responses** —
   `blocked_response.build` truncates the message at `question_end`, dropping any OPT, which
   is a protocol violation if the client sent one. That behavior is **pinned by a test**
   ("build drops a trailing OPT record and clears ARCOUNT"), so fixing this means
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

### P3.2 in detail — parsing upstream response records

Planned 2026-08-16. Not built. The wire-format half of this lives in
[dns-message-format.md § Resource records](dns-message-format.md#resource-records-rfc-1035-43);
what follows is the plan, the decisions, and the two questions still open.

#### Three things that are already in place

Worth stating first, because the plan reads shorter once they are accounted for:

1. **The record stream's start offset is already known — and already verified.** The plan in
   P3.1 said this walk begins "from `q_end`", which implies re-parsing the question out of
   the reply. It does not have to. `PendingQuery.question_len` is stored at send time, and by
   the time `dispatcherLoop` reaches the forwarding path,
   [`hashQuestion`](../src/utils/pending_table.zig) has already checked that the reply's
   bytes `[12..12+question_len]` hash-match the query's. So records start at
   `12 + pending.question_len`, established by a field lookup against bytes that have already
   been proven to be our own question echoed back — not by trusting the reply's framing.
2. **The insertion point is unambiguous**: in `dispatcherLoop`, between
   `pending_table.complete` and the transaction-ID rewrite. Everything above that line is
   anti-spoofing and must stay first; everything below it is the client's copy of the packet.
3. **The section counts are already decoded.** `answer_count`, `authority_record_count` and
   `additional_record_count` are live fields on [`Header`](../src/dns/header.zig).
   `dispatcherLoop` never builds a `Header` for a reply today — it reads the ID raw — so this
   costs one `parseHeader` call.

#### Scope: a read-only observer, and nothing else

**The datapath keeps relaying upstream's bytes verbatim, whatever the walk finds.** A parse
error logs at debug and changes nothing about what the client receives; there is no path
from a record-parsing verdict to a dropped or rewritten reply in this item. That preserves
the property P3.1 shipped under — no existing behavior changes — and it matters more here
than it did there, because this is the first time a hostile-input parser sits on the live
response path. A resolver that stops resolving because it disagreed with an RR it was only
logging is a worse outcome than any log line is worth.

Two guards fall out of that stance, both cheap:

- **Skip the walk when `reply_msg.flags.trunc`.** Those records are known-incomplete —
  `dispatcherLoop` already handles that case by setting TC — so parsing them yields errors
  that mean nothing.
- **Skip the walk unless the reply's QDCOUNT is 1.** `12 + question_len` is where records
  start *given one question*. An upstream that echoes a second question puts the record
  stream somewhere else, and walking from the wrong offset is exactly the silent
  desynchronization the rest of this design is built to avoid.

#### API — an iterator, not an eager parse

```zig
pub const Record = struct {
    name: name_reader.Name,
    rtype: u16,
    class: u16,
    ttl: u32,
    /// Borrows `msg`. Valid exactly as long as the datagram buffer is.
    rdata: []const u8,
    /// Which section this record came from, so a caller can tell an answer
    /// from a hint without counting.
    section: Section,
};

pub const RecordIter = struct {
    pub fn init(msg: []const u8, offset: usize, header: Header) RecordIter;
    pub fn next(self: *RecordIter) RecordError!?Record;
};
```

Pull-based because the counts are upstream-controlled `u16`s: an eager parse into a slice
needs either an allocation or an arbitrary cap on how many records it will hold, and the
iterator needs neither. `rdata` is a subslice rather than a copy, which keeps the allocator
off the response path for the same reason `Name` is inline storage — the borrow is
lifetime-obvious because the datagram outlives the walk by construction.

#### The two mistakes worth writing comments about

Both are silent-corruption bugs rather than crashes, which is what makes them worth pinning
in the source rather than only here.

**OPT is not a TTL.** An OPT record (TYPE 41, RFC 6891) reuses the CLASS field to carry the
requestor's UDP payload size and the TTL field to carry extended-RCODE, version, and the DO
bit. Folding it into a minimum-TTL computation produces a number with no meaning — it is
whatever the flags happened to encode. It has to be recognized by type and excluded, and
that is live from day one, not a P3.5 concern: replies with an OPT record arrive today.

**Names inside RDATA advance by RDLENGTH, never by `next_offset`.** A CNAME/NS/PTR target is
read with `readName` against the whole message — a pointer in RDATA may legally target any
earlier offset, which the strictly-backwards rule accommodates — but the *walk* resumes at
`rdata_start + rdlength`. Using the name's `next_offset` to continue the record stream
desynchronizes on every compressed RDATA. This is precisely the confusion `Read` was shaped
to prevent, in the one place where the struct cannot prevent it for you: both values are
legitimate, and the caller has to pick the right one.

#### Bounding the walk

Both bounds are load-bearing, in the same way `max_jumps` turned out to be for the name
reader:

- **Counts.** Stop after `ANCOUNT + NSCOUNT + ARCOUNT` records. A reply claiming
  `ANCOUNT=65535` in a 40-byte datagram must fail on the second record, not iterate.
- **Bytes.** Every record consumes at least 11 octets — a root-label name (1) plus TYPE (2),
  CLASS (2), TTL (4), RDLENGTH (2) — so the byte budget bounds the loop independently of
  what the header claims. Reaching the end of the message with records still owed, or
  finishing the declared records with bytes left over, is a `CountMismatch`, not a shrug.
- **RDLENGTH is a claim, not a fact.** `rdata_start + rdlength > msg.len` is `Truncated`.

#### Errors

`RecordError` is its own set that includes `NameError`, so a caller can switch on the
precise cause without the record walk having to rename the name reader's errors:

| Condition | Error |
|---|---|
| RR fixed fields (TYPE/CLASS/TTL/RDLENGTH) run past `msg.len` | `Truncated` |
| RDATA runs past `msg.len` | `Truncated` |
| Declared record count not satisfied by the bytes present | `CountMismatch` |
| Anything the name reader raises while reading an owner name or RDATA name | `NameError` |

#### Tests

Golden byte vectors again, and for the same reason — the format is bytes, and each of these
fails differently:

- A real-shaped reply: question, then `CNAME` → `A`, with the owner names compressed back to
  offset 12. The case every upstream actually sends
- Walking that reply yields exactly `ANCOUNT + NSCOUNT + ARCOUNT` records and lands precisely
  on `msg.len`
- A CNAME whose RDATA target is itself compressed — the RDLENGTH-vs-`next_offset` trap, with
  the assertion on the *next* record's name rather than on this one's
- RDLENGTH that overruns the message → `Truncated`
- ANCOUNT larger than the records present → `CountMismatch`
- Trailing bytes after the last declared record → `CountMismatch`
- An OPT record in Additional → surfaced as a record, excluded from any TTL aggregate
- Round trip against `blocked_response.build`: walking our own NXDOMAIN reply yields exactly
  one authority record, the synthetic SOA, with its owner name resolving to the qname. The
  same writer-vs-reader check P3.1 ended on
- Fuzz over arbitrary bytes at an arbitrary offset, asserting only termination and that
  every yielded record's `rdata` lies inside `msg`. Highest-value test here, same as it was
  for the name reader

#### Explicitly out of scope

- **CNAME-cloak blocking.** The most interesting item in P3.1's rationale, and a genuine
  behavior change: it turns the walk into a decision rather than an observation. It needs its
  own entry, with its own answer to what happens to a reply whose CNAME chain is blocked
  (synthesize NXDOMAIN? drop? relay and log?) — questions that have nothing to do with
  parsing and would swallow the review of the parser if bundled.
- **Bailiwick checking.** Only matters once records are stored (P3.3). An observer that logs
  an out-of-bailiwick record is not poisoned by it.
- **Typed RDATA decode beyond A / AAAA / CNAME.** Enough to log an answer. `resource_data.zig`
  exists to be extended, not to be exhaustive on the first pass.
- **The per-query structured event log.** Emitting these as real fields (client, qtype,
  rcode, answer, latency) is P2.3's remaining phase. P3.2 hands it the data.

#### Sequencing

1. `resource_record.zig` — `RecordIter` plus golden vectors and the fuzz target,
   self-contained, no callers, reviewable on its own
2. `resource_data.zig` — A / AAAA / CNAME decoding over `Record.rdata`
3. Wire into `dispatcherLoop` behind the two guards above, logging under the `query` scope;
   confirm a normal lookup is still byte-identical end to end
4. Add the file to `main.zig`'s test aggregation block, and run `zig build` as well as
   `zig build test` — the P2.5 lesson: a green suite is not evidence the exe still compiles

#### Open decisions

1. **Observer-only, as written above — or is CNAME-cloak blocking the point?** The plan above
   assumes the former. If the answer is the latter, the parser is unchanged and one more
   entry gets written; nothing here is wasted either way.
2. **Where the walk's output goes in this pass.** Simplest is a `query`-scoped debug line
   naming the answer. The alternative is holding P3.2's caller until P2.3's per-query event
   is defined, so the answer arrives as fields in that record rather than as a second line
   beside it.

---

## P4 — Missing for a *production-grade DNS blackhole*

Gaps beyond raw protocol/operability that separate a forwarder-with-a-blocklist from a
real sinkhole (the Pi-hole / AdGuard Home / Unbound-`local-zone` feature class).
**P4.2 (QDCOUNT/opcode validation) landed 2026-08-09** — see
[changelog.md](changelog.md#p42--qdcount--opcode-validation-landed-2026-08-09).

- **P4.1 — blocked-response strategy per qtype.** Today every block is NXDOMAIN regardless of
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
  else). The `rcode` parameter on `blocked_response.build` is the door in.
- **P4.3 — upstream timeout & failover.** A single upstream with no explicit per-query timeout
  (the sweeper's 5 s is the only bound) and no secondary. Production forwarders round-robin
  or fail over to a second upstream on timeout/SERVFAIL, and surface upstream health.
- **P4.4 — local custom records / conditional forwarding.** The staple sinkhole features beyond
  blocking: local A/PTR records (name your LAN devices), CNAME/host overrides, and
  split-horizon / conditional forwarding (send `*.internal` to a different upstream).
  These slot in ahead of the blocklist as another `Filter`/resolver stage.
- **P4.5 — blocklist normalization & footprint.** The two lists (StevenBlack hosts + hagezi
  wildcards) overlap heavily and the raw HTTP bodies are retained for the process
  lifetime via `Writer.Allocating` inside each list (`file_body` is never freed until
  `deinit`, and the `StringHashMap` keys are slices *into* that body). Document/decide
  this ownership model, dedupe exact entries already covered by a suffix, and consider
  freeing the source body after building if you switch to owned keys — matters once both
  lists are ~100k+ entries.
- **P4.6 — observability surface for a sinkhole.** Beyond raw counters (P2.3): top blocked
  domains, per-client query/block ratios, and a query log with a retention/privacy
  policy (DNS query logs are PII). This is the dashboard half of what makes Pi-hole
  Pi-hole; scope it once the per-query event exists.
- **P4.7 — DNSSEC posture.** Decide and document: we're a non-authoritative forwarder, so
  blocked synthetic answers can't be signed — a validating client with DO set that
  queries a blocked name will get a bogus/unsigned answer. Confirm we pass the DO bit and
  RRSIGs through untouched on the *forwarded* path, and document that blocking is
  incompatible with strict downstream validation of the blocked names (every sinkhole has
  this caveat).

---

## Housekeeping

- Delete or repurpose the remaining template leftovers: the stub
  [src/root.zig](../src/root.zig) (`add`/`printAnotherMessage`), which is also the misleading
  module root, and the boilerplate comment walls in [build.zig](../build.zig). (`copy.zig`
  at the repo root and the empty `src/server.zig` are both already gone.)
- `Question.question_str_slice` ([question.zig](../src/dns/question.zig)) is declared but
  never assigned or read — drop it or wire it up.
- **Three sibling docs still name `craftBlockedResponse`** (renamed 2026-08-08):
  [dns-message-format.md](dns-message-format.md) (§"Which sections … modifies", plus a code
  listing), [async-migration.md](async-migration.md) (three snippets and an explanatory
  note), and [filter-design.md](filter-design.md) (two snippets and the `block`-verdict
  discussion). Their *descriptions* of the wire behavior are still accurate — only the
  function name and call shape moved. Worth a sweep, and note that
  [dns-message-format.md](dns-message-format.md) additionally still claims "we don't add
  an SOA", which C2 made false back on 07-30.
- `Authority` ([authority.zig](../src/dns/authority.zig)) models the SOA as a struct of
  `comptime` fields with a runtime `write_authority_section` method. It works, but every
  field is a fixed constant — a namespaced `const` block (or plain named byte constants)
  would say the same thing without the `var authority = Authority{};` instance dance, which
  now lives in `blocked_response.build` rather than `handleQuery`. Revisit if/when the
  negative-cache TTL becomes configurable (P2.1), since that field then stops being comptime
  anyway — and note the golden-bytes test's literal SOA array has to become TTL-dependent at
  the same time.
- **Line-number anchors were dropped from this document on 2026-08-19.** `main.zig` has grown
  by ~120 lines since the refs were last verified (2026-08-07) and every one of them had
  drifted. Links now point at files, not lines.

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

> ⚠️ **This section is stale** and was left verbatim on 2026-08-19 by request. Items 1 and 2
> are done (P4.2 landed 08-09, both test suites landed 08-09, CI exists), and P2.1/P2.3 both
> shipped. Rewriting it against what is actually open — P1.5, P2.1's local-file blocklist
> source → P2.5's harness, P2.2, P2.3's per-query event, then P3.2 or P4.1 — is a separate
> pass.

For the view from above — how far along the whole project is, which of these bands is worth
the most per unit of effort, and why "no open P0s" does **not** mean "safe to deploy" — see
[progress.md](progress.md).

Reference docs, still accurate: [dns-message-format.md](dns-message-format.md) (wire
format + error table), [upstream-design.md](upstream-design.md) (architecture rationale),
[async-migration.md](async-migration.md) (async patterns),
[filter-design.md](filter-design.md) (the `Filter`/`Chain` design the `Policy` chain is
converging toward). History: [changelog.md](changelog.md).
