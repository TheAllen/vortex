# Next Steps — Road to Production-Ready

Reviewed **2026-09-15** against the current source (Zig 0.16.0, `zig build test` →
**163/163 pass** — 147 unit tests, of which 127 are real behavior tests, plus **16
integration cases**). *Updated 2026-09-27: 166/166 — 149 unit, 17 integration.*

**2026-09-27: background loops now get threads of their own.** Spawning them with
`group.async` made Vortex hang at startup on any host with ≤ 3 CPUs, and serialized every
handler on a 4-CPU one; see
[changelog.md](changelog.md#landed-2026-09-27--background-loops-get-threads-of-their-own).
This was a prerequisite for P1.5 and P2.4, both of which reason about what the runtime does
at its limits.

**2026-09-28: P1.5 landed** — `PendingTable` is capped by `VORTEX_MAX_PENDING` and drops past
it; see [changelog.md](changelog.md#landed-2026-09-28--p15-pending-table-cap).

**2026-09-28: cache fixes landed** — TC=1 replies are no longer cached, and hits echo the
asking client's question casing; see
[changelog.md](changelog.md#landed-2026-09-28--cache-tc1-is-never-stored-and-hits-echo-the-clients-casing).
Phase 1 of the protocol plan under [P3](#p3--protocol-completeness).

**2026-09-28: EDNS0 and TCP landed** (P3.5 + P3.6, phases 2 and 3 of that plan, combined) —
see [changelog.md](changelog.md#landed-2026-09-28--p35p36-edns0-and-tcp).
*206/206 — 173 unit, 33 integration.* What stands between Vortex and a bind off localhost is now P2.6 and P2.7. **No open P0s, and no open P1 bugs** — all three P0s are pinned by
regression tests that fail under mutation.

**P2.2 blocklist resilience landed 2026-09-13**, and with it the last of the two
deployability blockers that were not about load. A failed fetch is retried, falls back to an
on-disk copy, and — if even that is missing — resolves against a configurable
fail-open/fail-closed policy instead of killing the process. Both lists are rebuilt on a
timer and swapped in as whole generations behind an `Io.RwLock`. **"No blocklist means no DNS
at all" is retired**, as is "the list is whatever was fetched the day the process started" —
see [changelog.md](changelog.md#landed-2026-09-13--p22-blocklist-resilience).

**P3.3 response caching landed 2026-09-05**, closing the compression → parsing → caching
chain. The P3 band is now the EDNS0/TCP remainder rather than the main event.

**The integration harness landed 2026-09-12**, closing P2.5 and with it the largest gap on
this board. `handleQuery`, `dispatcherLoop` and the ingress loop now have automated
coverage: [tests/](../tests/) spawns the real binary against a scratch config, drives it
with crafted UDP from a fake upstream it owns both ends of, and asserts on the replies. All
16 cases are mutation-checked (12 then, 4 added by P2.2). **The "everything ever proven about this layer was proven by
hand with `dig`" caveat is retired** — see
[changelog.md](changelog.md#landed-2026-09-12--p25-integration-harness).

**The local-file blocklist source landed 2026-09-11**, which is what made that affordable:
either list may be a path instead of a URL, so a case costs milliseconds of startup rather
than ~25 s of HTTP. The same pass split acquisition from parsing in both blocklists, which
gave the two files their first tests; see
[changelog.md](changelog.md#landed-2026-09-11--p21-local-file-blocklist-source).

**The housekeeping sweep landed 2026-09-08** and closed the whole Housekeeping backlog:
`parseRdata` is fixed and tested, every module carries the `refAllDecls` guard, and the
`root.zig` template stub and its module are deleted. Two of those are worth carrying forward
as facts rather than chores:

- **`zig build test` now type-checks `main`.** The guard on [main.zig](../src/main.zig)
  reaches `handleQuery`, `dispatcherLoop`, `sweeperLoop` and `supervise` — none of which sit
  in a `test` block — so the long-standing "a green test suite is not evidence that Vortex
  compiles" caveat is retired. That layer is now *compiled*, still not *tested*.
- **The guard works.** It caught `parseRdata` on its first run, exactly the class of rot it
  was proposed for. See [Housekeeping](#housekeeping).

**History lives in [changelog.md](changelog.md)** — dated entries for everything that landed,
the three closed P0s in detail, and the shipped P3.1 and P3.2 plans. This file is the board:
open work only.

The single largest remaining gap is now **deployability**, not coverage. What is left is
almost entirely P2: bounded concurrency (P1.5), the per-query event (P2.3), and the
deployment surface (P2.6). **P1.5 is now the top of the board** — it is the one thing
standing between Vortex and a bind off localhost that is not also rate limiting. The harness
is where its cap gets asserted once there is one: it is still the only thing in the tree that
can create load.

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
- A resource-record walk over upstream replies ([resource_record.zig](../src/dns/resource_record.zig)),
  wired into `dispatcherLoop` behind two guards (skip on TC=1, skip unless QDCOUNT is 1). It
  began as a read-only observer; its output now also decides what may be cached
- A TTL-aware response cache ([cache.zig](../src/dns/cache.zig)) keyed on
  `(qname, qtype, qclass)`, checked in `handleQuery` **after** the policy verdict so a
  refreshed blocklist is never shadowed by a stale entry, and filled in `dispatcherLoop`.
  Serves a copy with the client's transaction ID restored and every TTL aged by the entry's
  age; RFC 2308 negative caching. An expired entry is reclaimed by the `get` that finds it,
  with the 30 s sweep as the backstop for keys nobody asks for again.
  `VORTEX_CACHE_MAX_ENTRIES=0` disables it
- A `Policy` filter chain — allowlist → exact blocklist → suffix blocklist — with a
  three-valued `Verdict` (`allow`/`block`/`pass`) ([policy.zig](../src/blocklist/policy.zig)),
  over an immutable `Snapshot` held behind an `Io.RwLock` so a refresh can replace both lists
  as one generation while queries are in flight. The allowlist is checked before the lock is
  taken, so the allow path stays lock-free
  - Exact-match blocklist ([domain_blocklist.zig](../src/blocklist/domain_blocklist.zig))
  - Suffix/wildcard blocklist walking parent labels ([suffix_blocklist.zig](../src/blocklist/suffix_blocklist.zig))
  - Both resolve from a URL **or** a local file path, chosen by the value's scheme
    (`Settings.Source`), with acquisition split from parsing so the line grammar of each
    is tested over literals
  - Acquisition is retried, cached on disk and fail-open by default
    ([acquire.zig](../src/blocklist/acquire.zig)); both lists are rebuilt on a timer by
    `refresherLoop`, and a refresh that would empty a populated list is refused
  - Comptime allowlist that overrides a block, validated lowercase at build time ([allowlist.zig](../src/blocklist/allowlist.zig))
- NXDOMAIN synthesis for blocked names, assembled in one pure function
  ([blocked_response.zig](../src/dns/blocked_response.zig)) from `Header.writeResponseFlags`
  plus a cacheable SOA ([authority.zig](../src/dns/authority.zig))
- An integration harness ([tests/](../tests/)) that spawns the real binary against a scratch
  config and a fake upstream, covering the ingress loop, `handleQuery` and `dispatcherLoop`
  end to end over UDP. `zig build test-integration` runs it alone;
  `-Dtest-filter=<substr>` narrows to one case
- CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) — `zig fmt --check`, build,
  test, plus a ReleaseSafe job. `zig build test` covers both suites, so the harness runs in
  both jobs

---

## P0 — Correctness bugs

**None open, and all three are pinned by tests.** C1 (QName lowercasing), C2 (cacheable SOA),
and C3 (QR bit on ingress) are fixed *and* each has a named regression test that fails under
mutation. Full detail — what each bug was, why the fix is shaped that way, and what keeps it
that way — is in [changelog.md](changelog.md#reference--the-three-closed-p0s-in-detail).

---

## P1 — Hardening the dispatcher path

**None open.** P1.1–P1.4 landed 2026-08-09; see
[changelog.md](changelog.md#p11p14-all-landed-2026-08-09). **P1.5 landed 2026-09-28**
([changelog.md](changelog.md#landed-2026-09-28--p15-pending-table-cap)) — the entry below is
kept as the reasoning that shaped it. One divergence: the check sits in `appendQuery`, not at
ingress, so blocked names and cache hits are still answered while the table is full.

**P1.5 — bounded in-flight work / backpressure.** The ingress loop does an unbounded
`group.async(handleQuery, …)` plus a `gpa.dupe` **per received datagram**. The P1.2 fix put
a `catch` on that `dupe`, so an allocation failure now sheds one datagram instead of killing
the server — but that is a backstop, not a bound. Still the last code-level gate on a bind
off localhost, and still distinct from per-client rate limiting (P2.7): this protects the
process itself.

> **Premise corrected 2026-09-19 — the cap belongs somewhere else than this entry said.**
> This item read *"a UDP flood still spawns unbounded coroutines and unbounded heap — a
> trivial memory-exhaustion DoS"* and prescribed *"cap concurrent handlers (semaphore /
> fixed worker pool / bounded queue)"*. Both halves are wrong about the runtime we actually
> get: `std.process.Init` hands us a `std.Io.Threaded` (`std/start.zig:724`), and read
> against the 0.16.0 source —
>
> - **`Io.Threaded` already caps the handlers.** `async_limit` defaults to `cpu_count - 1`
>   (since 2026-09-27: `VORTEX_HANDLER_THREADS` plus one slot per background loop)
>   (`std/Io/Threaded.zig:1639`), and `groupAsync` does **not** queue past it: at the limit
>   it destroys the task and calls `groupAsyncEager` → `start(context)` **inline on the
>   calling thread** (`std/Io/Threaded.zig:2197`). Same inline fallback on
>   `builtin.single_threaded`, on task-allocation OOM, and on `Thread.spawn` failure.
>   `busy_count` is decremented only when a task *returns* (`std/Io/Threaded.zig:1799`), so
>   a handler blocked in a syscall holds its thread for the duration.
> - **The `dupe` heap is bounded by the same mechanism.** Past the limit handlers run inline
>   and free on return, so roughly `cpu_count` dupes are live at once — not a flood's worth.
>
> **What a flood actually does**, in two parts, neither fixed by a semaphore around the spawn:
>
> 1. **The ingress loop goes serial.** Past `async_limit`, `group.async` is a blocking call
>    *inside the loop*, so it stops calling `receive` while it runs a policy lookup and an
>    upstream send. Throughput collapses to serial and the kernel's UDP receive buffer
>    overflows — the drops happen in the kernel, where Vortex cannot see or count them.
> 2. **`PendingTable` grows without bound, and it is the real vector.** `handleQuery`
>    inserts an entry and returns immediately after the upstream send
>    ([main.zig](../src/main.zig), `appendQuery` then `send`) — it never awaits the reply,
>    `dispatcherLoop` does. Entries live until answered or swept at 5 s, so occupancy is
>    arrival-rate × 5 s and nothing else bounds it.
>
> **So: cap in-flight pending queries, not spawned handlers.** Shed the datagram when
> `PendingTable` is at capacity, before the `dupe` and the spawn — the same position the
> oversized-query FORMERR already occupies. A handler semaphore mostly re-implements what
> the runtime is already doing.
>
> **Do not lean on the inline degradation as the backpressure mechanism.** `async` is
> explicitly *permitted* to run inline — that is why it may return a null future, and why
> `io.concurrent` exists separately to demand parallelism and fail with
> `error.ConcurrencyUnavailable`. What is written above is the 0.16.0 implementation, not a
> contract it promises to keep. Note also that `Group.concurrent` uses `concurrent_limit`,
> which defaults to `.unlimited`: moving handlers onto it would make this entry's original
> unbounded-spawn premise true.
>
> **The side benefit is testability.** A cap on `PendingTable` is asserted against a number
> Vortex owns and can report, rather than against a coroutine count the harness has no way
> to observe from outside the process.

---

## P2 — Production operability

1. **Configuration — mechanism done 2026-08-09, fields partly.**
   [settings.zig](../src/settings.zig) resolves a runtime `Settings` struct at startup from
   **defaults < `.env` file < process environment**.
   - **Done:** listen host+port, upstream host+port, upstream bind host+port, both blocklist
     sources, log level and log format, `VORTEX_CACHE_MAX_ENTRIES` (0 disables the cache),
     and P2.2's three — `VORTEX_BLOCKLIST_ON_FAILURE`, `VORTEX_CACHE_DIR` (empty disables
     the on-disk list cache) and `VORTEX_BLOCKLIST_REFRESH_SECS` (0 disables refresh). All
     `VORTEX_`-prefixed; `VORTEX_ENV_FILE` picks a
     different file. A missing default `.env` is fine; a file named explicitly that isn't
     there is fatal, as is a malformed port — silently listening on 5354 because someone
     typed `535e` is the config bug that costs an hour.

     `VORTEX_CACHE_DIR` is the one string setting where an explicitly empty value means the
     empty string rather than "unset" (`envStrAllowEmpty`). An empty host or port says
     nothing; an empty *directory* says "nowhere", and without the distinction the setting
     would have had no off switch.
   - ~~**Local file paths as a blocklist source alongside URLs**~~ **Done 2026-09-11.**
     `VORTEX_BLOCKLIST_SOURCE` / `VORTEX_SUFFIX_BLOCKLIST_SOURCE` take a URL or a path,
     decided by the value's scheme. This was P2.5's hard prerequisite; P2.5 is now
     unblocked. The old `_URL` names are a fatal error naming the replacement rather than a
     silent fall back to the default list.
   - **Still to do:** `std.process.args` for CLI flags (highest precedence, above process
     env), multiple upstreams (P4.3), and the two remaining knobs whose
     *consumers* can't take a runtime value yet — **timeouts** (the 5 s deadline and 1 s sweep
     cadence, now unblocked) and **negative-cache TTL** (needs `Authority`'s comptime fields
     un-`comptime`d, see Housekeeping). Each is one struct field plus one line in
     `fromEnviron` once its consumer is ready. *(Fail-open vs fail-closed was the third; P2.2
     built the consumer and it shipped 2026-09-13.)*
2. ~~**Blocklist resilience.**~~ **Done 2026-09-13.** A failed fetch is retried (three
   attempts, only the transient statuses), then falls back to an on-disk copy written on the
   last success and stamped with the source it came from; if even that is missing,
   `VORTEX_BLOCKLIST_ON_FAILURE` decides between starting unfiltered-and-loud and refusing to
   start. Both lists are rebuilt on a timer by `refresherLoop` and installed as a whole
   `Snapshot` behind an `Io.RwLock`, and a refresh that would empty a list which currently
   has entries is refused. See
   [changelog.md](changelog.md#landed-2026-09-13--p22-blocklist-resilience).

   **Two things this left open**, both small and both deliberately out of that pass:
   - **SIGHUP-triggered refresh.** Needs the signal handling P2.4 will add; the refresh
     mechanism itself is already a function call away.
   - **Retry counts, the degraded interval and the attempt schedule are constants**, not
     settings. They are one `Settings` field each if an operator ever needs them; nobody has.
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
5. **Test coverage — the harness landed 2026-09-12; what is left is listed below.**
   `zig build test` → **163/163**: the 147-test unit suite plus **16 integration cases**
   ([tests/](../tests/), see
   [changelog.md](changelog.md#landed-2026-09-12--p25-integration-harness)).

   The unit suite is **147/147, of which 145 are real**: 32 `cache`,
   17 `resource_record` (10 walk tests including a fuzz target, plus 7 `parseRdata`
   tests from 09-08), 17 `name_reader` (including a fuzz target), 9 `Header`, 8 `obs/log`,
   8 `settings`, 7 `PendingTable`, **6 `Policy`** and **5 `acquire`** (all new on 09-13),
   4 `parseQuestion`, 3 `DomainBlockList`, 4 `SuffixBlockList`, 3 `blocked_response`
   golden-bytes, **2 `backoff`**, `backoffSeconds`'s ceiling, allowlist hit/miss, and
   **18 `refAllDecls` guards** — one per module, which assert nothing at runtime and
   everything at compile time.
   Only 2 now assert nothing about Vortex: `main.zig`'s "initialize sockets" and the
   `test { _ = @import(…) }` aggregator, which the runner counts as a passing test.
   (`root.zig`'s `add(3, 7)` stub was the third; it is deleted.)

   Counted exactly, so the headline number is not mistaken for behavior coverage:
   **147 = 127 behavior tests + 18 guards + 1 aggregator + 1 no-op.** The guard count tracks
   the module count exactly; it went 16 → 18 on 09-13 with `acquire.zig` and
   `utils/backoff.zig`.

   **A third testing lesson, learned the hard way on 2026-09-05.** Mutation-testing the
   cache found **four assertions that could not fail**, each because the fixture was built
   to be *realistic* rather than to *discriminate*. The clearest: the OPT record's TTL was
   set to 0 — exactly what a plain EDNS0 reply carries — so "aging skips the OPT" passed
   whether or not it did, since `0 -| 60` is still 0. Realism is what hid the bug.
   **Write the fixture that fails when the rule is broken, then confirm it does by breaking
   the rule.** Alongside "assert against literal bytes" and "test the interaction".

   **The lesson, now confirmed six times.** C3 became testable when the check moved into
   pure `Header.validateQuery`; C2 when assembly moved into pure `blocked_response.build`;
   P2.1 when the dotenv parser split from the file read; P1.1 when `sweepExpiredQueries` was
   changed to *report* evictions instead of sending them; P3.1 when name reading became a
   pure function over a byte slice; P3.2 when the record walk was built as an iterator over
   that slice, testable against golden bytes before it had a caller. Every one is the same
   move: **separate deciding from doing, and the test needs no `Io`.**

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

     **Worse than recorded, found 2026-09-05.** This is not limited to `main`. `parseRdata`
     in [resource_record.zig](../src/dns/resource_record.zig) has no callers anywhere, so it
     was never analysed and **did not compile** — while `zig build` *and* `zig build test`
     both stayed green, in both optimization modes. Adding the file to the aggregator does not
     help: `_ = @import("dns/resource_record.zig")` collects that file's `test` blocks; it
     does not reference its declarations. So the rule was stronger than "build the exe too":
     **an uncalled `pub fn` is unchecked no matter what you run.**

     **Resolved 2026-09-08 — this entry is kept as the reasoning, not as a live caveat.**
     Every module now carries a `refAllDecls` guard, `main.zig` included, so both halves of
     the failure mode are closed: the uncalled `pub fn` (caught immediately — `parseRdata`
     failed on the guard's first run) and the `main`-only reachable code. Reintroducing the
     original `backoffSeconds` `u64` regression now fails `zig build test` at `main.zig:489`,
     inside `supervise`. Two corrections to the fix as it was written above: it is **not** one
     line per file, because 0.16.0 ships only the shallow `refAllDecls` and struct methods
     need their container named explicitly; and `std.meta.declarations` yields only `pub`
     declarations, so file-private types must be named directly. Details in
     [Housekeeping](#housekeeping).

     **What has not changed:** keep `zig build` and `zig build test` as separate CI steps.
     The guard forces analysis of declarations, which is not the same as linking an
     executable, and the ReleaseSafe pair still catches what Debug lets through.

   Still missing:
   - ~~**An integration harness for the coroutine-bound code — the largest gap.**~~
     **Done 2026-09-12.** [tests/](../tests/) spawns the binary against a scratch config and
     a fake upstream and asserts on the replies. All eight scenarios from the table that used
     to live here are cases, plus four more (suffix block, the not-blocked counterpart,
     QDCOUNT≠1, and a cache hit); the one row that did not survive is the supervisor backoff,
     which cannot be provoked from outside the process and which `backoffSeconds` already
     covers as a pure function. Every case is mutation-checked. Full detail, including the
     deadlock the mutation run found *in the harness*, is in
     [changelog.md](changelog.md#landed-2026-09-12--p25-integration-harness).

     **What the harness still does not cover**, and these are the live items:
     - **Concurrency.** Every case is one query at a time. Nothing exercises many in-flight
       handlers — which is P1.5's whole subject, and the harness is where a concurrency cap
       gets asserted once there is one. It is currently the only thing in the tree that can
       generate load at all.

       P2.2 made this gap sharper rather than smaller. The `Io.RwLock` in `Policy` exists to
       make freeing a replaced blocklist generation safe *while readers are running*, and no
       case runs two queries at once — so the property the lock is for is the one thing the
       suite cannot observe. It was checked by hand (130 live swaps under six concurrent
       query streams, ReleaseSafe, no errors), which is exactly the kind of evidence P2.5
       existed to stop relying on.
     - **The supervisor.** A loop that returns immediately cannot be provoked from outside.
       Closing this needs a fault-injection hook in the binary, which is a real design
       decision (a test-only code path in a resolver) and not obviously worth it.
     - **Vortex does not report its bound listen port.** The harness therefore picks one by
       binding port 0 and releasing it, which is a race it cannot close from the outside. The
       fake upstream has no such problem — it stays bound and reads `Socket.address`. Having
       the binary log or write its resolved port would remove the last non-determinism in
       startup, and is worth doing alongside P2.6.
   - ~~`parseDomain`/`parseSuffixDomain` parsing tests.~~ **Done 2026-09-11**, as a
     by-product of splitting `build` (pure, over a byte slice) out of `load` in both
     blocklists. ~~[policy.zig](../src/blocklist/policy.zig) and~~
     [utility.zig](../src/utility.zig) is now the only file carrying logic with **no
     `test` blocks at all** — and it carries very little. `policy.zig` got its first six on
     2026-09-13.
6. **Deployment surface.** `127.0.0.1:5354` is dev-only. Real use means `0.0.0.0:53`
   (privileged port → capability / launchd / systemd unit), an IPv6 listener, and a
   service definition. Pick the target platform and add the unit files.
7. **Rate limiting / abuse controls.** Any resolver reachable beyond localhost needs
   per-client rate limiting (and ideally Response Rate Limiting) so it can't be conscripted
   into DNS amplification. Pairs with, but is separate from, the process-level backpressure
   in P1.5.

---

## P3 — Protocol completeness

The **compression → response parsing → caching** chain is complete as of 2026-09-05.
**EDNS0 and TCP are done as of 2026-09-28.** What remains in this band is the multi-upstream
arc (P3.7) and the residue listed under P3.5 and P3.6 below.

**Plan, agreed 2026-09-28** — three phases; 2 and 3 were combined into one branch, which
let the 1232 clamp land in the same change as the TCP listener:

1. ~~**Cache correctness**~~ ✅ 2026-09-28 — TC=1 never cached; hits echo the client's casing.
2. ~~**EDNS0 (P3.5)**~~ ✅ 2026-09-28 — a pure OPT parser (`dns/edns.zig`) with FORMERR for malformed/duplicate
   OPTs and BADVERS for version > 0; our own OPT on blocked replies; the forwarded OPT's
   payload size clamped to our buffer; the cache keyed by EDNS/DO with a size check on hits;
   the DNSSEC posture (P4.7) written down.
3. ~~**TCP (P3.6)**~~ ✅ 2026-09-28 — a client-facing listener (accept loop via `concurrent`; connection handlers
   via `concurrent` under `VORTEX_MAX_TCP_CONNS`, since a connection lives as long as its
   client keeps it open), the validate → policy → cache step shared with UDP, TCP to upstream
   for TCP clients. **The advertised/clamped EDNS size drops to 1232** (DNS Flag Day 2020) in
   this phase, not phase 2: 1232 produces more TC=1, and TC=1 is only honest once there is a
   TCP listener to retry against.

Multi-upstream and DoT (P3.7) are planned after phase 3, together with P4.3 failover.

1. ~~**DNS message compression (pointer following).**~~ **Done 2026-08-13** —
   [name_reader.zig](../src/dns/name_reader.zig) reads names with pointer following, bounded
   by a strictly-backwards rule plus a 64-jump cap; `question.zig` is refactored onto its
   no-pointer variant and `DomainName` is deleted. Ships with no datapath caller by design.
   The full rationale is retained in
   [changelog.md](changelog.md#landed-2026-08-13--p31-compression-pointer-following),
   because P3.2 and P3.3 both build directly on its decisions.
2. ~~**Parse upstream response records.**~~ **Done 2026-08-30** —
   [resource_record.zig](../src/dns/resource_record.zig) walks Answer/Authority/Additional
   with a pull-based `ResourceRecordIter`, and `dispatcherLoop` is the name reader's first
   datapath caller. Ships as a read-only observer: the datapath relays upstream's bytes
   whatever the walk finds. The plan, the decisions, and **four divergences from it** are in
   [changelog.md](changelog.md#landed-2026-08-30--p32-upstream-response-record-parsing).
   **Residue — all but one closed by P3.3 on 2026-09-05:**
   - ~~The two planned guards~~ ✅ landed with P3.3, where they stopped being cosmetic:
     while the walk only logged, a wrong offset cost one bad log line; it now decides what
     gets cached
   - ~~TTL extraction, excluding OPT~~ ✅ `replyTtlSeconds` in
     [cache.zig](../src/dns/cache.zig)
   - ~~The placeholder `std.log.info("name: …")`~~ ✅ now a `query`-scoped debug record
     carrying name, type and TTL. Still a line per record rather than fields on P2.3's
     per-query event, which is where it belongs
   - ~~**`parseRdata` is broken and dead**~~ ✅ **fixed 2026-09-08** with 7 tests and the
     `refAllDecls` guard that keeps it compiling. Still has no datapath caller — it is
     capability for the EDNS0/P4.1 work, in the same "ships before its caller" shape as
     P3.1. See [Housekeeping](#housekeeping)
3. ~~**TTL-aware response caching.**~~ **Done 2026-09-05** —
   [cache.zig](../src/dns/cache.zig). Keyed on `(qname, qtype, qclass)` with a hand-written
   hash context (`AutoHashMap` silently cannot work here — see the changelog), entries
   holding the datagram plus `.boot` insert and expiry timestamps. TTLs are aged on the way
   out per RFC 2181 §5.2, OPT is excluded from every TTL computation, and negative answers
   use RFC 2308's `min(SOA.TTL, SOA.MINIMUM)`. Full rationale, the two bugs caught during
   the build, and the four vacuous tests found by mutation are in
   [changelog.md](changelog.md#landed-2026-09-05--p33-ttl-aware-response-caching).
   **Deliberately out of scope, each worth its own item:**
   - **Request coalescing** — N clients missing the same name during one upstream round
     trip all forward. Wasteful, not wrong; needs an in-flight set
   - **An eviction policy** — at `max_entries` the cache refuses new keys rather than
     choosing a victim, because there is no recency data to justify one
   - ~~**The question-section casing echo**~~ **Fixed 2026-09-28** — a hit now carries the
     asking client's question bytes. Found alongside it: TC=1 replies were being cached;
     also fixed
4. ~~**Wildcard / suffix blocking.**~~ **Done 2026-07-30.** Remaining polish: fold the
   hand-rolled `Policy` into the comptime duck-typed `Filter`/`Chain` from
   [filter-design.md](filter-design.md), and add a suffix-*allow* matcher for the entries
   parked in the allowlist's "NEEDS SUFFIX-ALLOW" comment
   ([allowlist.zig](../src/blocklist/allowlist.zig)).
5. ~~**EDNS0 (RFC 6891).**~~ **Done 2026-09-28** — [edns.zig](../src/dns/edns.zig). The
   pinned test "build drops a trailing OPT record" was rewritten as planned, into "build
   answers an OPT with our own OPT". **Residue, each small and deliberately out of scope:**
   - **Header-only replies carry no OPT** — the FORMERR/NOTIMP for a bad header, and the
     sweeper's SERVFAIL (which no longer has the query to read an OPT from). RFC 6891 wants
     one whenever the query had one; clients cope, and the sweeper case needs the class
     stored on `PendingQuery` plus the DO bit to fix.
   - **Forwarded replies relay upstream's OPT verbatim**, so the payload size a client sees
     on a forwarded answer is upstream's, not ours. A strict forwarder rewrites it.
   - **EDNS options (cookies, ECS, padding) are passed through untouched**, never parsed.
6. ~~**TCP fallback.**~~ **Done 2026-09-28** — a client-facing listener on the listen
   address, with each connection a `concurrent` task in a [ConnTable](../src/utils/conn_table.zig)
   slot (`VORTEX_MAX_TCP_CONNS`, default 64), idle ones cancelled by the sweeper after 10 s,
   and TCP queries forwarded over TCP. The TC=1 we set on an oversized upstream reply now has
   somewhere to land. **Residue:**
   - **One upstream TCP connection per forwarded query.** No pooling or reuse. Fine for a
     fallback path; the first thing to change if TCP ever carries real volume, and the
     groundwork for DoT (P3.7).
   - **The upstream TCP connection ignores `VORTEX_UPSTREAM_BIND_*`**; it connects from
     wherever the kernel picks.
   - **The oversized-UDP-query FORMERR stays.** A query over 4096 bytes over UDP is still
     malformed; the difference is that TCP now exists for one that genuinely needs the room.
7. **Multiple upstreams / DoT / DoH.** Future arcs the dispatcher architecture was chosen
   to accommodate (a connection pool replaces `upstream_socket`, same `PendingTable`
   pattern). See the evolution table in [upstream-design.md](upstream-design.md).

### P3.2 in detail — shipped

The plan that was written here on 2026-08-16 built out on 2026-08-30 and moved to
[changelog.md](changelog.md#landed-2026-08-30--p32-upstream-response-record-parsing),
following the convention P3.1 set: a plan stops being board material the day it ships, but
the reasoning is kept because P3.3 builds directly on it. What is still open from that work
is listed under P3.2 above, not here.

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
  wildcards) overlap heavily and the raw bodies are retained for the process
  lifetime via `Writer.Allocating` inside each list (`file_body` is never freed until
  `deinit`, and the `StringHashMap` keys are slices *into* that body). Document/decide
  this ownership model, dedupe exact entries already covered by a suffix, and consider
  freeing the source body after building if you switch to owned keys — matters once both
  lists are ~100k+ entries.
- **P4.6 — observability surface for a sinkhole.** Beyond raw counters (P2.3): top blocked
  domains, per-client query/block ratios, and a query log with a retention/privacy
  policy (DNS query logs are PII). This is the dashboard half of what makes Pi-hole
  Pi-hole; scope it once the per-query event exists.
- ~~**P4.7 — DNSSEC posture.**~~ **Decided and documented 2026-09-28**, with P3.5:
  - **Forwarded path: transparent.** The client's OPT — DO bit included — goes upstream
    with only its payload size clamped, and the reply, RRSIGs and all, comes back verbatim.
    Verified live against 1.1.1.1 (`dig +dnssec cloudflare.com` returns the RRSIG).
  - **Cache: partitioned by DO**, so an answer carrying RRSIGs is never served to a client
    that did not ask for them, and one without is never served to a client that did.
  - **Blocked names: unsigned, by nature.** The synthesized NXDOMAIN cannot be signed, so a
    validating client with DO set gets a bogus answer for a blocked name. That is the
    caveat every sinkhole carries, and it is only about the *blocked* names: everything
    forwarded validates as it would without Vortex in the path.

---

## Housekeeping

- ~~**`parseRdata` does not compile**~~ **Fixed 2026-09-08**, along with the two silent
  defects behind the compile error (`.MX` sliced the *preference* as the exchange name; `.A`
  and `.AAAA` indexed a fixed width with no length check, so a well-framed record with short
  RDATA was an out-of-bounds read). It now has **seven tests**, and all three defects were
  mutation-checked — the missing width check reproduces as a real
  `index out of bounds: index 4, len 3` panic when removed. See
  [changelog.md](changelog.md#landed-2026-09-08--housekeeping-sweep).
- ~~**Add `std.testing.refAllDecls(@This())` to each module's test block.**~~
  **Done 2026-09-08 — every module now carries it**, and it caught `parseRdata` on the very
  first run.

  Two things were learned applying it that the original entry got wrong:
  - **It is not one line per file.** 0.16.0's `std.testing` has only the *shallow*
    `refAllDecls`; there is no `refAllDeclsRecursive` (that is a later-Zig API). Shallow
    means referencing a container type without analysing what is inside it, and most of this
    codebase's logic lives in struct *methods*. So every container has to be named
    explicitly — which is what [cache.zig](../src/dns/cache.zig) was already doing on
    2026-09-05, and the reason why was not recorded at the time.
  - **`std.meta.declarations` reports only `pub` declarations.** A file-private type is never
    reached by `@This()` and must be named directly — see `EscapingWriter` in
    [obs/log.zig](../src/obs/log.zig).

  **The largest single win was [main.zig](../src/main.zig)**, and it is worth stating
  separately because it retires a documented limitation rather than a bug: referencing `main`
  forces analysis of everything reachable from it — `handleQuery`, `dispatcherLoop`,
  `sweeperLoop`, `supervise` and all the wiring — none of which sits in a `test` block.
  **"`zig build test` does not type-check `main`" is no longer true.** Verified by
  reintroducing the exact 2026-08-09 `backoffSeconds` regression (`i64` → `u64`), which now
  fails `zig build test` at `main.zig:489`, inside `supervise`. Note this makes that layer
  *compiled*, not *tested* — a strictly weaker claim. P2.5's harness, landed 2026-09-12,
  is what closed the rest.
- ~~Delete or repurpose the remaining template leftovers~~ **Done 2026-09-08.** `src/root.zig`
  is deleted and the `addModule("vortex")` that rooted it is gone from
  [build.zig](../build.zig) along with the boilerplate walls around it. Nothing imported that
  module, its only test asserted `add(3, 7) == 10`, and it was the first module a reader met
  — so it read as the project's public surface while being template residue. It also cost a
  second test artifact: `zig build test` ran two binaries, one of which existed to run that
  one stub. **`zig build test` was a single artifact from then until 2026-09-12, 122 tests,
  120 of them real.** It runs two again now — the second is the integration harness, which
  needs its own root because it must *not* link `main`, and which earns the artifact the
  `root.zig` stub never did.
- ~~`Question.question_str_slice`~~ Already gone from
  [question.zig](../src/dns/question.zig); only this entry still referenced it. Removed
  2026-09-08.
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

> ⚠️ **This section is stale** and is kept verbatim by request; only this note is maintained.
> As of 2026-09-13: items 1 and 2 are done (P4.2 landed 08-09, both test suites landed 08-09,
> CI exists), P2.1/P2.3 both shipped, and the P3 track it offers as a *branch* has now been
> walked end to end — compression 08-13, record parsing 08-30, caching 09-05. **P2.5's harness
> landed 09-12 and came off this list**, as P2.1's local-file blocklist source did on 09-11
> and **P2.2's cache + refresh did on 09-13**.
> The real order is now **P1.5, P2.3's per-query event, then P4.1** — with P2.6 and P2.7
> alongside P1.5 if the goal is a bind off localhost, since none of the three is sufficient
> on its own. Rewriting this section against that is a separate pass, and the case for doing
> so keeps strengthening: every item it names is done, what is left is entirely the
> deployability block, and the list is now down to three.
>
> **2026-09-19:** the verbatim text above ends on *"nothing yet bounds the number of in-flight
> handlers a flood can create"* — which is no longer the right way to state the gap. The
> runtime bounds the handlers; what is unbounded is `PendingTable`. The order is unchanged,
> P1.5 is still first, and only its shape moved. See P1.5 above.

For the view from above — how far along the whole project is, which of these bands is worth
the most per unit of effort, and why "no open P0s" does **not** mean "safe to deploy" — see
[progress.md](progress.md).

Reference docs, still accurate: [dns-message-format.md](dns-message-format.md) (wire
format + error table), [upstream-design.md](upstream-design.md) (architecture rationale),
[async-migration.md](async-migration.md) (async patterns),
[filter-design.md](filter-design.md) (the `Filter`/`Chain` design the `Policy` chain is
converging toward). History: [changelog.md](changelog.md).
