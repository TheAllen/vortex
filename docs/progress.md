# Progress — Where Vortex Actually Stands

A periodic completion assessment. [next_steps.md](next_steps.md) tracks *what is left*, item
by item; this file tracks *how far along the whole thing is* and — more usefully — **what
would actually move the needle**.

Percentages here are **judgment, not measurement**. They come from weighting five areas by
how much of a production DNS sinkhole each represents, then estimating completion within
each. Someone who weights caching over operability would land somewhere else. The weights
are stated explicitly below so the number can be argued with rather than just quoted.

---

## Snapshot — 2026-09-12

> **≈ 60.0% complete** (58.8 → 60.0). One area moved, and it is the one that had been named
> the largest gap for six straight snapshots.
>
> Source: 5,902 lines of Zig across 16 files in `src/` (+7, all comment), plus **1,130 lines
> across 3 new files in `tests/`**.
> `zig build test` → **143/143 pass** under both Debug and ReleaseSafe — the 131-test unit
> suite plus **12 integration cases**.
>
> Moved by P2.5's integration harness: **Tests + CI ~80% → ~92%** (+1.2). Nothing else moved,
> because nothing else changed: not one line of `src/` behavior was edited this pass.
>
> **What changed is what the suite is evidence *of*.** Every previous snapshot could say the
> datapath was tested and mean "the pure functions under it are tested." `handleQuery`,
> `dispatcherLoop` and the ingress loop had no runtime coverage of any kind, and both of this
> project's last two real bugs lived there and were found by hand. That sentence is now gone.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | Unchanged, and deliberately: the code did not change. What changed is confidence in it, which this column does not measure |
| Operability | 25% | ~33% | 8.25 | Unchanged. Per-query event log, metrics, graceful shutdown, deployment, blocklist refresh all still unbuilt |
| Protocol completeness | 20% | ~62% | 12.4 | Unchanged. EDNS0, TCP fallback, multi-upstream |
| Sinkhole feature set | 15% | ~5% | 0.75 | Unchanged |
| Tests + CI | 10% | ~92% | 9.2 | **+12.** The coroutine layer has coverage for the first time: 12 end-to-end cases, all mutation-checked. Not 100% — concurrency and the supervisor are still unreachable |
| **Total** | **100%** | | **≈ 60.0** | |

### Why +12 on one area and nothing anywhere else

The harness adds no capability. It cannot make Vortex answer a query it could not answer
yesterday. Scoring it anywhere but Tests + CI would be double-counting work that already
scored when the datapath was built.

**What it buys is that the other four columns can now be trusted.** Six snapshots running,
this file has recorded a variant of *"131 passing tests and zero of them start the binary."*
Both of the last two real bugs — the silent-corruption bug on an oversized upstream reply,
and the peek-vs-complete DoS where rejecting a forgery killed the live query — were found by
driving sockets by hand, and every unit test passed straight through both. Those two runs are
now cases 9 and 11.

The remaining 8% is specific, not a rounding allowance:

- **Concurrency is untested.** Every case is one query at a time. This is the same gap P1.5
  names, and the harness is where a cap gets asserted once one exists — it is now the only
  thing in the tree that can generate load.
- **The supervisor is unreachable from outside.** A loop that returns immediately cannot be
  provoked across a process boundary. Closing it means a fault-injection path in the binary,
  which is a real design decision rather than a chore.
- **Vortex does not report its bound listen port**, so the harness picks one by binding port 0
  and releasing it. That race cannot be closed from the outside; having the binary report its
  resolved port would remove the last non-determinism in startup, and belongs with P2.6.

### The finding worth keeping

The mutation run — 12 mutations, one per case, each confirming the case fails when the rule
is broken — did not find a bug in `src/`. All 12 were caught. **It found a deadlock in the
harness itself**: the diagnostic path drained the child's stderr while the child was still
alive, and reading a pipe whose write end is open blocks until EOF, which a server that never
exits never produces. Every deliberately-broken build hung for the full timeout instead of
reporting a failure.

Two things follow. First, **a diagnostic path that deadlocks is worse than no diagnostics**,
because the symptom reads as a slow test rather than a broken one. Second, and more
uncomfortable: the harness is now load-bearing test infrastructure with **no harness of its
own**, and the only thing that exercised its failure path was deliberately breaking the code
under test. Mutation testing earned its keep twice this pass — once as intended, and once by
catching the tool.

---

## Snapshot — 2026-09-11

> **≈ 58.8% complete** (57.9 → 58.8). Roughly one point for a 424-line feature, which
> undersells it: **the number is not what changed this pass — the shape of the board is.**
>
> Source: 5,895 lines of Zig across 16 files. `zig build test` → **131/131 pass** under both
> Debug and ReleaseSafe.
>
> Moved by P2.1's local-file blocklist source: **Operability ~30% → ~33%** (+0.75) and
> **Tests + CI ~78% → ~80%** (+0.2). Nothing else moved.
>
> **The headline is not the percentage.** P2.5 — the integration harness, and the largest
> gap on this board for five straight snapshots — went from *blocked* to *buildable*. It is
> the first time since 08-09 that the biggest open item has had nothing in front of it.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | Unchanged. Still the 5 s deadline, the 1 s sweep cadence and the QDCOUNT=0 SERVFAIL |
| Operability | 25% | ~33% | 8.25 | **+3.** P2.1 config is now all but closed — only CLI flags and three consumer-blocked knobs remain. Per-query event log, metrics, graceful shutdown, deployment, blocklist refresh all still unbuilt |
| Protocol completeness | 20% | ~62% | 12.4 | Unchanged. EDNS0, TCP fallback, multi-upstream |
| Sinkhole feature set | 15% | ~5% | 0.75 | Unchanged |
| Tests + CI | 10% | ~80% | 8.0 | **+2.** 113 behavior tests (up from 104), and two of the three zero-coverage logic files closed. Still no integration harness — but nothing blocks one now |
| **Total** | **100%** | | **≈ 58.8** | |

### Why a small feature earns the pass

The change itself is modest: a `Source` union that reads a value's scheme, a file-read
branch beside the HTTP one, and a rename guard. Full detail in
[changelog.md](changelog.md#landed-2026-09-11--p21-local-file-blocklist-source).

**What it actually bought is the removal of a precondition.** Every snapshot since 09-05 has
named the integration harness the largest gap, and every one has also named the reason it
could not be built: startup blocked on two HTTP fetches costing ~25 s, and a harness that
spawns the binary per case cannot pay that per case. That sentence is now gone. Startup
against [testdata/](../testdata/) is instant and touches no network at all.

This is the inverse of the 09-08 sweep. That pass touched every file and moved half a point
because it bought *analysis* where testing was needed. This one touches four files and moves
just under a point because it bought *permission to test the thing that has never been
tested*. Neither number reflects what changed; in both cases the sentence after the number is
the finding.

**The credit is deliberately not larger.** The harness is unblocked, not built. `handleQuery`
and `dispatcherLoop` still have zero runtime coverage, exactly as they did on 09-08, and this
project has already learned once this month that crediting a guard rail in advance is not the
same as verifying it — see the CI correction under
[what moves the number](#-40-finish-header-validation-and-the-test-floor--done-2026-08-09).
The points here are for the nine tests that exist, not the harness that does not.

### The counting, stated exactly

**131 = 113 behavior tests + 16 `refAllDecls` guards + 1 aggregator + 1 no-op.**

Worth writing out, because the guard count has been recorded as 14 since 09-08 and is
actually 16 — one per module, as the sweep intended; three are simply named something other
than `test "refAllDecls"`, and a `grep` for the exact name undercounted them. Nothing is
wrong with the code; the *record* of it was wrong for three days. That is a small instance of
this file's own closing question, and it was found by regenerating the table from `wc -l` and
`grep` instead of hand-editing it, which is the practice the 08-13 snapshot's stale table
prompted.

Two of the three files carrying logic with no behavior tests are now closed —
`domain_blocklist.zig` (0 → 4) and `suffix_blocklist.zig` (1 → 5). **`policy.zig` remains,
still 40 lines, still the chain that decides whether a domain is blocked, still zero
behavior tests.** It has now survived every pass since 08-08 on that list. `authority.zig`
and `utility.zig` join it, carrying less.

### The finding: documentation is not verification

The last three passes each delivered a finding of the form *something assumed to be checked
that was not*. This one continues the run, in a milder form.

The suffix list's `*.`-prefix footgun — a list whose entries carry `*.` parses without
complaint and then matches **zero domains** — was "handled" in the sense that it is warned
about in three places: [.env](../.env), the [README](../README.md), and `Settings`'
doc-comment. It retired a real outage on 08-10 and has been treated as closed ever since.
But prose in three files does not fail a build. It is now a test asserting that
`*.example.com` is retained verbatim as a key and blocks nothing — so if a future change
starts stripping the prefix, the suite fails and points at the three documents that would
need to change with it.

A second one, caught by reading rather than by running: **`Writer.Allocating.initOwnedSlice`
is not the zero-copy shortcut it appears to be.** It installs the slice as `buffer` but
leaves `writer.end` at 0, so `written()` comes back empty. Using it for the file read would
have produced a blocklist that loads clean and blocks nothing — the identical failure
signature as the `*.` prefix and the hagezi 404, arrived at by a third independent route.
**That failure mode has now shown up three times in this project from three unrelated
causes**, which is enough to call it the characteristic way this codebase breaks, and an
argument for P2.2 to carry a startup assertion on non-zero blocklist size rather than
trusting each load path to be right.

### What did not move, and why

The datapath, protocol and sinkhole bands are untouched — correctly, since nothing in this
pass changed what a client receives. The [localhost cliff](#the-counterweight-the-localhost-cliff)
is unchanged and unretired: P1.5 and P2.7 are both still open, and localhost binding is
still load-bearing as a security control.

One thing did get quietly worse in proportion: `settings.zig` is now 681 lines and the
third-largest file in the project, having grown 183 lines in one pass. Roughly the same
comment-to-code ratio as before, so this is not yet the `cache.zig` conversation — but
`Source` is the first thing in that file that is not a scalar knob, and if a second such type
arrives it should take both with it into its own module.

---

## Snapshot — 2026-09-08

> **≈ 57.9% complete** (57.4 → 57.9). A deliberately small move for a sweep that
> touched every file in the project, and the size is the point.
>
> Source: 5,471 lines of Zig across 16 files (`root.zig` deleted). `zig build test` →
> **122/122 pass** under both Debug and ReleaseSafe, of which **120 are real**, from one test
> artifact instead of two.
>
> Moved by the housekeeping sweep: **Tests + CI from ~73% to ~78%** (+0.5 weighted). Nothing
> else moved.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | Unchanged. Still the 5 s deadline, the 1 s sweep cadence and the QDCOUNT=0 SERVFAIL |
| Operability | 25% | ~30% | 7.5 | Unchanged. Per-query event log, metrics, graceful shutdown, deployment, blocklist refresh all still unbuilt |
| Protocol completeness | 20% | ~62% | 12.4 | Unchanged by choice — `parseRdata` compiles and is tested but has no datapath caller yet; see below |
| Sinkhole feature set | 15% | ~5% | 0.75 | Unchanged |
| Tests + CI | 10% | ~78% | 7.8 | **+5.** 120 real tests, two fuzz targets, `refAllDecls` on all 16 modules, one test artifact. The suite now type-checks `main`. Still no integration harness |
| **Total** | **100%** | | **≈ 57.9** | |

### What changed, and why it is worth only half a point

The sweep closed the entire Housekeeping backlog — `parseRdata` fixed and given 7 tests,
`refAllDecls` guards on all 16 modules, the `root.zig` template stub and its module deleted.
Full detail in [changelog.md](changelog.md#landed-2026-09-08--housekeeping-sweep).

**It bought one genuinely new property:** `zig build test` now type-checks `main` and
everything reachable from it. Since 2026-08-09 the board had carried "a green test suite is
not evidence that Vortex compiles" as a standing caveat; that is now false, verified by
reintroducing the original `backoffSeconds` regression and watching the suite fail at
`main.zig:489` inside `supervise`. It also caught a real bug the day it landed — `parseRdata`
failed on the guard's first run, which is the difference between a guard and a ritual.

**It did not move the number much, because compiling is not testing.** The coroutine layer
went from *unanalysed* to *analysed*. It is still *unexercised*: `handleQuery` and
`dispatcherLoop` have no runtime coverage, and the two most recent real bugs in this project
were both found by driving sockets against a hostile upstream, where no amount of semantic
analysis would have helped. The integration harness (P2.5) remains the single largest gap on
the board and the sweep did not touch it.

**Why the protocol band did not move at all.** `parseRdata` works now, but it has no datapath
caller — it is capability for EDNS0 and P4.1. P3.1 was credited for exactly this shape of
work, so an argument for +1 exists; it is not taken here because P3.1's pure capability had a
committed consumer two items later on the board, and this does not yet.

**The counting caveat, once more.** 122 is a better number than 101, but 15 of the 22 new
tests are guards and unit tests over one dead function. The shape of the gap is unchanged
from the 09-05 snapshot: everything is still over pure functions.

---

## Snapshot — 2026-09-05 (pm)

> **≈ 57.4% complete** against the yardstick in
> [next_steps.md](next_steps.md): *"production-ready DNS sinkhole for a home network."*
>
> Source: 5,215 lines of Zig across 17 files. `zig build test` → 101/101 pass under both
> Debug and ReleaseSafe, of which **98 are real behavior tests**.
>
> Moved by P3.3 (TTL-aware response caching): the protocol band from ~32% to ~62%, and tests
> from 69 to 101. **The largest single feature left on the board is now done**, and this is
> the first P3 item that changes what a client receives — a repeat query is answered in
> 0 ms from memory, with its TTLs correctly counted down.
>
> The compression → parsing → caching chain is complete: P3.1 on 08-13, P3.2 on 08-30,
> P3.3 today. The two earlier items bought no behavior at all by design; this one spends
> everything they built.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | **Closed out 08-09.** Header validation complete, no silent-failure modes left, replies verified against their query, every query lifecycle has a defined answer including timeout |
| Operability | 25% | ~30% | 7.5 | P2.1 config done and grown a cache knob; P2.3 logging **phases 1 and 2 of 3**. The per-query event log, metrics, graceful shutdown, deployment, blocklist refresh still unbuilt |
| Protocol completeness | 20% | ~62% | 12.4 | Wildcard blocking, compression (08-13), record parsing (08-30) and **caching (09-05)** all done. EDNS0, TCP fallback and multi-upstream remain — real work, but none of it is the centrepiece caching was |
| Sinkhole feature set | 15% | ~5% | 0.75 | Per-qtype strategy, local records, dashboards, DNSSEC posture — all open |
| Tests + CI | 10% | ~73% | 7.3 | 98 real tests, two fuzz targets, and the first module carrying `refAllDecls`. Still no integration harness, which is now unambiguously the largest gap on the board |
| **Total** | **100%** | | **≈ 57.4** | |

*What "98%" on the datapath means:* the remaining 2% is the hard-coded 5 s deadline and 1 s
sweep cadence (newly unblocked for P2.1) and the QDCOUNT=0 SERVFAIL. Both are known, both are
documented, neither is a correctness defect.

*What P3.3 bought:* the biggest single jump this project has recorded, and the first one an
operator would *feel*. A warm query is answered from memory in 0 ms instead of a round trip,
and the answer is honest about its age — TTLs are aged on the way out, so a client cannot be
told 300 seconds remain on a record the cache has held for 250. That last part is the whole
difference between a cache and a correctness bug, and it is why `inserted_at` sits beside
`expires_at` rather than being derivable from it.

*What it did not buy:* three named exclusions, each of which should be read as scope rather
than oversight. There is **no request coalescing** — N clients missing the same name inside
one upstream round trip all forward, which is wasteful but never wrong. There is **no
eviction policy** — at the cap the cache refuses new keys rather than choosing a victim,
because there is no recency data to justify a choice and refusing cannot serve a stale
answer. And a hit echoes **the first requester's qname casing**, which is invisible to
ordinary clients and wrong for one doing 0x20 verification.

*The counting caveat, restated:* 98 real tests is a better number than 66, but the shape of
the gap has not changed. All of them are over pure functions. `handleQuery` and
`dispatcherLoop` — which P3.3 just made materially more complex, with a lookup, an insert,
two new guards and a serve path — still have **no automated coverage of any kind**. P3.3 was
verified with `dig` against a live upstream, and that verification found nothing, but the two
most recent real bugs in this project were both found exactly there and by nothing else.

*What P3.2 bought, and what it did not* (written at the 09-05 am snapshot, kept because the
prediction is worth grading): the protocol band moved 12 points for a walk that changed
nothing a client could observe — the correct shape, since P3.1 and P3.2 are both pure
capability and the payoff is P3.3. The band was credited at ~32% rather than ~35% because
**the two guards the plan specified were not built** (skip on TC=1, and unless QDCOUNT is 1),
with the note that both would get cheaper to add before P3.3 gave the walk consequences.

**Graded: they landed with P3.3 the same day, and the reasoning held.** They stopped being
cosmetic exactly where predicted — a wrong offset used to cost one bad log line and now
decides what gets stored. The ~3 points are collected in this snapshot's ~62%.

*The counting problem the 09-05 am snapshot exposed:* **69 passing tests is a weaker signal than 59
was.** `parseRdata` shipped, was reviewed, was merged, and does not compile — nothing calls
it, so Zig never analysed it, and `zig build` plus `zig build test` are both green in both
optimization modes. The suite grew by ten while the *guarantee* the suite offers shrank,
because the project now contains a demonstrated instance of unanalysed code. This is the
second time lazy analysis has hidden a compile error here (the first was `backoffSeconds` on
08-09, caught in minutes by hand); the difference is that this one survived four merged PRs
and CI. The one-line fix — `std.testing.refAllDecls(@This())` per module — is on the board
under Housekeeping and should land before the next feature, not after.

*What the two logging passes bought (+2.5 across the day):* every record in the process is
now one structured logfmt line with a timestamp, level, and scope, and an operator can set
`VORTEX_LOG_LEVEL` and `VORTEX_LOG_FORMAT` without a rebuild. Both are small slices of a
25%-weight band — deliberately so. **Do not read this as "logging is done."** The per-query
event log (client, qtype, verdict, rcode, latency as real fields) is still open, and *all* of
metrics is, which is the half that turns logs into an answer to "is it working right now?"
A log tells you what happened; a counter tells you what is happening.

*A knock-on worth noting:* P2.1 shrank as a side effect. Its deferred list named **log level**
as one of four fields blocked on their consumers being ready. That consumer now exists, and
`log_level` plus `log_format` are live `VORTEX_`-prefixed variables with the same fail-loud
contract as a typo'd port. Three deferred fields remain — timeouts, negative-cache TTL, and
fail-open-vs-closed — and each is still one struct field plus one line once its consumer can
take a runtime value.

*One thing the number does not capture:* the logging work closed a **log-injection
vulnerability** that had been live. `Question.parseQuestion` never validated label bytes, so
a qname could carry a newline and forge log records — an attacker could write whatever they
liked into the operator's log. Escaping now happens in the one place every record passes
through. It is a security fix, not a feature, so it moves no percentage; it is recorded here
because it would otherwise be invisible.

*And one privacy control that arrived early:* `VORTEX_LOG_LEVEL=off`. Per-query records name
every domain every client on the network resolves, which is why `Level` is a local enum
rather than `std.log.Level` — the standard one cannot express "off". P4.6 still owes a real
retention and privacy policy for the query log, but the blunt instrument exists now rather
than after the data has been written.

### Two other yardsticks, for calibration

- **"Have the hard problems been solved?" → ~82%.** Of the two substantial features named at
  the last snapshot, **response caching is done** and only **bounded concurrency** (P1.5)
  remains. The expensive-to-reverse decisions were already made — the shared upstream socket
  with `PendingTable` demux, the `std.Io.Group` coroutine structure, the three-valued filter
  chain — and the cache's own irreversible choices (inline keys, a hand-written hash context,
  aging on the way out) are now made too. What is left is overwhelmingly *volume* of
  well-understood work — arg parsing, signal handlers, a service unit, counters — plus one
  genuinely unsolved problem that is not a feature at all: an integration harness for the
  socket-bound code.
- **"Pi-hole competitor?" → ~28%.** Caching is the first thing on this axis a user would
  actually notice, and it moves this number more than its weight suggests, because "is it
  fast?" is the question people put to a resolver. But the whole P4 band — per-qtype
  strategy, local records, observability dashboard, DNSSEC posture — is still untouched, and
  that band remains the difference between a forwarder-with-a-blocklist and the thing people
  install.

---

## The counterweight: the localhost cliff

The headline number smooths over a discontinuity that matters more than any percentage.

**You cannot safely point a router at Vortex today** — and as of 08-09 that is a *policy*
statement rather than a mechanical one, which makes it more dangerous, not less. Before P2.1
the compile-time `127.0.0.1` was an accidental safety interlock. Now
`VORTEX_LISTEN_HOST=0.0.0.0` is one line in a file, and two open items become live exposure
the moment anyone writes it:

- **P1.5** — the ingress loop does an unbounded `group.async` + `gpa.dupe` per datagram.
  A UDP flood spawns unbounded coroutines and unbounded heap. Memory-exhaustion DoS.
  **As of 08-09 this is the only open P1 and the last code-level gate.**
- **P2.7** — no per-client rate limiting, so it can be conscripted into amplification.

The 08-09 datapath work removed several *other* reasons not to expose this — replies are now
verified against their query, oversized datagrams can't corrupt a client, and every rejection
path answers or drops deliberately rather than by accident. That makes it more tempting to
flip the listen address, and the two items above are still not done.

**Localhost binding is currently load-bearing as a security control.** That is worth stating
plainly, because it is easy to read "no open P0s" as "safe to deploy." It is not. The P0
board being clear means the *logic* is correct, not that the *deployment* is safe.

Making config runtime therefore *raised* the urgency of P1.5 and P2.7 rather than lowering
it: the guard rail that used to require a recompile to remove is now a text edit. The warning
in [.env](../.env) next to `VORTEX_LISTEN_HOST` is the only thing standing there, and a
comment is not a control. **P1.5 and P2.7 should land before anything else in the
deployability block.**

This is also why P0.C3 (QR bit unchecked on ingress) mattered so much more than its size
suggested: it was the reflector half of the same exposure, and it would have gone live on
the same trigger.

---

## The counterweight that retired: the default config boots again

Found 2026-08-10 while smoke-testing the logging change, not by any test; **fixed 08-10 and
verified still fixed on 09-05.** Kept because the finding outlived the bug.

`VORTEX_SUFFIX_BLOCKLIST_URL` defaulted to hagezi's `wildcard/light-onlydomains.txt`, which
began returning HTTP 404. Because blocklist fetch fails closed, a clean checkout with no
`.env` **exited at startup**. The default is now `https://small.oisd.nl/domainswild2`, and
the reason the replacement is that specific path is itself a trap worth keeping: it must be
`domainswild2`, not `domainswild`, because the `2` variant omits the `*.` prefix and the
parser does not strip one — a `*.`-prefixed list loads with no error at all and then matches
**zero domains**. A silent fail-open wearing the costume of a successful startup.

Two findings came out of it, and the second has not been fixed:

1. ~~The URL needs updating~~ — done 08-10. What made it worse than a typo: the hagezi
   *account* disappeared, not just the file, so there was no successor URL to point at. An
   upstream you do not control can vanish entirely.
2. **P2.2 was theoretical and is now real, and still is.** [next_steps.md](next_steps.md)
   P2.2 describes fail-closed as a hypothetical: *"a transient GitHub blip takes your whole
   network's DNS down."* It is not hypothetical. The blip already happened, it was not
   transient, and the only reason it cost nothing is that nobody is running this yet. A local
   cache file written on success and loaded on fetch failure would have made it a warning
   instead of a hard stop. **Swapping one hard-coded URL for another did not fix the class
   of problem** — it re-armed it against a different host, and oisd.nl additionally
   rate-limits by IP with HTTP 503, so a handful of quick restarts can still leave Vortex
   unable to start.

P2.2 therefore stays at the top of the deployability block, above P2.6 and P2.4.

It was also a comment on the test suite: **131 passing tests and zero of them start the
binary.** That is no longer true as of 2026-09-12 — the harness starts the binary 12 times
per run, and would have caught the 404 on the first one. Its blocker, *local file paths as a
blocklist source*, landed 2026-09-11. Both of those halves are done; the cache-file half of
P2.2 is not, and the prediction that "one change closes both"
turned out to be half right. The file-reading machinery a cache file needs now exists
(`readFileInto`, shared by both lists), so P2.2's remaining work is the write-on-success side
and a refresh strategy, not the plumbing.

---

## What moves the number

Ordered by return on effort, not by priority band.

### ~~→ ~40%: finish header validation and the test floor~~ ✅ done 2026-08-09
P4.2, the `PendingTable` suite, and CI all landed. What is left from this tier keeps
shrinking: `console.zig` is gone (08-10) and its replacement shipped with tests,
`parseQuestion`'s error paths now have four tests, and **CI has run** — four PRs merged
through it between 08-13 and 08-31. The residue is `policy.zig` coverage, still zero on the
40 lines that decide whether a domain is blocked.

**And a correction, because the previous entry got it wrong.** Every pass from 08-10 onward
recorded "CI has never run" as the outstanding guard rail against the lazy-analysis class of
bug, on the reasoning that `ci.yml` runs `zig build` before `zig build test` in both
optimization modes and so "would have caught it on the first push." CI has since run, many
times, and it **did not catch `parseRdata`** — because an uncalled `pub fn` is not analysed
by `zig build` either. The guard rail was switched on and the bug walked past it. What was
actually needed is `refAllDecls`, which no amount of running the existing workflow supplies.
Worth keeping as a reminder that a guard rail credited in advance is not a guard rail
verified.

### → ~55%: make it deployable — the highest-value block on the board
Six items, and together they're the difference between a toy and a tool. **One is now done:**

| Item | Why it's on the critical path |
|---|---|
| ~~P2.1 config~~ ✅ 08-09, local-file source ✅ 09-11 | Was the gate on all of these; listen address is now runtime, and either blocklist can be a path |
| ~~P1.1 / P1.2 / P1.3 / P1.4 / P4.2~~ ✅ 08-09 | Datapath closed out; P1.5 is the only P1 left |
| ~~**P2.5 integration harness**~~ ✅ 09-12 | Topped this list for one pass and came off it. 12 end-to-end cases, all mutation-checked. It was here because both of the last two real bugs were found only by driving sockets; everything below now ships with it in place, which was the point |
| **P2.2 blocklist cache + refresh** | The 404 that proved it was fixed by swapping in another hard-coded URL, which re-armed the same trap against a different host — one that rate-limits. Its file-reading half now exists; see [the counterweight that retired](#the-counterweight-that-retired-the-default-config-boots-again) |
| P1.5 concurrency cap | Gate for leaving localhost |
| P2.7 rate limiting | Gate for leaving localhost |
| P2.6 bind + service unit | `0.0.0.0:53`, privileged port, launchd/systemd |
| P2.4 graceful shutdown | Currently the only exit is a crash or Ctrl-C mid-write |

Note the shape of this: it moves completion by ~20 points but moves **utility from zero to
most of the way there**. It is the single most underweighted block if you judge by the
percentage alone.

### ~~→ ~70%: caching~~ ✅ done 2026-09-05
~~P3.1~~ ✅ 08-13 → ~~P3.2~~ ✅ 08-30 → ~~P3.3~~ ✅ 09-05. The chain is complete, and it
landed close to the ~70% this tier predicted for the protocol band alone (~62%). The walk
also stopped being an observer exactly where this entry said it would: a parse error used to
change nothing precisely *because* nothing depended on it, and P3.2's two skipped guards
became load-bearing the moment a record's TTL started deciding how long an answer is served.

**The remaining tiers are now the whole board.** With the largest feature gone, what is left
is the deployability block below plus the sinkhole band — which is a better position than the
percentage suggests, because that block moves *utility* far more than it moves this number.

### → beyond: the sinkhole band
P4.1 (per-qtype strategy), P4.4 (local records / conditional forwarding), P4.6 (observability
surface). Optional depending on whether the goal is "a real blackhole" or "keep learning
DNS" — the branch [next_steps.md](next_steps.md) flags at the end of its Suggested order.

---

## Where the code actually is

Regenerated from `wc -l` on 2026-09-12. Test counts exclude each file's `refAllDecls`
guard, so this column is **behavior tests only** and will not sum to the 131 the unit runner
reports.

```
src/ — 5,902 lines of Zig, 16 files

src/dns/cache.zig                1215  key + context, entry, map, TTL policy         31 tests
src/main.zig                      737  ingress, handleQuery, dispatcher, supervisor   1 test   <- +1 no-op, +1 aggregator
src/settings.zig                  682  runtime config: .env parse, precedence, Source 8 tests
src/dns/resource_record.zig       624  RR walk, iterator, rdata types                17 tests
src/obs/log.zig                   494  logfmt logFn, escaping writer, level + format  8 tests
src/dns/header.zig                412  parse, validateQuery, reply builders           9 tests
src/dns/name_reader.zig           378  name reading, pointer following               17 tests
src/utils/pending_table.zig       370  proxy-ID table, sweeper, question hashing      7 tests
src/blocklist/domain_blocklist.zig 228 exact-match list, URL or file + shared read    3 tests
src/dns/blocked_response.zig      187  pure NXDOMAIN+SOA assembly                     3 tests
src/blocklist/suffix_blocklist.zig 181 parent-label walk, URL or file                 4 tests
src/dns/question.zig              119  QName parse, lowercasing                       4 tests
src/blocklist/allowlist.zig        99  comptime allowlist                             1 test
src/dns/authority.zig              69  34-byte synthetic SOA                          0 tests
src/utility.zig                    57  Context                                        0 tests
src/blocklist/policy.zig           50  allow -> exact -> suffix chain                 0 tests  <- logic, no tests

tests/ — 1,130 lines of Zig, 3 files                                            <- new 09-12

tests/integration.zig             455  the 12 end-to-end cases                       12 tests
tests/harness.zig                 395  child process, fake upstream, scratch config   0 tests
tests/wire.zig                    280  independent DNS encode/decode for assertions   0 tests
```

`tests/` is a second artifact with its own root, and it must be: it deliberately does **not**
link `main`. `wire.zig` shares no code with `src/dns` for the same reason the golden-bytes
tests spell their expectations out as literals — an assertion built with the encoder it is
checking would agree with a byte-swapped encoder. `harness.zig` carries no tests of its own,
which is noted in the snapshot above as a real risk rather than an oversight.

`cache.zig` arrives as the largest file in the project at 1,215 lines, which deserves the
same raised eyebrow `obs/log.zig` got at 478. Roughly half is comment and a further third is
tests, so the executable core is on the order of 300 lines — but it is carrying four distinct
things (the key and its hash context, the entry, the TTL policy, and the map wrapper), and
the first natural split if it grows again is the TTL policy, which is pure message
arithmetic with no relationship to storage.

*(The 08-13 snapshot's copy of this table was stale on arrival — it carried a 2,951-line
total that contradicted its own header, and still listed `src/dns/domain_name.zig`, which
P3.1 deleted in the very pass that snapshot was recording. Regenerate it from `wc -l`, don't
hand-edit it.)*

The distribution has changed shape twice over. `pending_table.zig` was the largest untested
risk in the project and is now among the best covered — seven tests, mutation-verified,
including the one that would have caught B1. **`policy.zig` remains the only file carrying
*logic* with zero behavior tests**, and it is still 50 lines; `authority.zig` and
`utility.zig` join it on that list but carry less. `domain_blocklist.zig` left it on
2026-09-11 — not by having tests bolted on, but the way `console.zig` and `cache.zig` did it:
the line loop was split out as `build(gpa, body)`, pure over a byte slice, and the tests
followed for free.

`console.zig` left that list the way things should: not by having tests bolted on, but by
being deleted. Its replacement is the fifth file written pure-first, and it arrived with
tests because the format renders into a `*std.Io.Writer` and the level and format parsers are
plain functions over a string — none of it needs an `Io` to exercise.

The two DNS-reading files added since 08-13 are now 845 lines between them — `name_reader.zig`
plus `resource_record.zig`, 27 tests, two fuzz targets, and until 08-30 zero callers. That is
the pure-first pattern working exactly as intended. It is also where the `parseRdata` rot hid:
**pure and well-tested is not the same as reachable**, and this project has now proven that a
file can be both the best-tested in its band and contain a function that does not compile.

The best-tested files are also the ones deliberately built or restructured to be pure:
`header.zig`, `blocked_response.zig`, `settings.zig`, `pending_table.zig`, `obs/log.zig`,
`name_reader.zig`, `resource_record.zig`, and now `cache.zig`. That is not a coincidence —
see the lesson in [next_steps.md](next_steps.md) P2.5. It has now held eight times, and the
last four were files where it was applied *before* the code existed rather than as a rescue.

`cache.zig` is the clearest instance yet, and also the one that shows the limit of the
pattern. Its pure half — the key, the hash context, the TTL rules, the serve-path
arithmetic — is exhaustively tested and was **mutation-verified rule by rule**. Its impure
half is four call sites in `handleQuery` and `dispatcherLoop`, and those remain untested,
because separating deciding from doing shrinks the untestable surface without ever
eliminating it. Both bugs caught during the build (the overlapping `@memcpy`, the get/age
race) were in the seam between the two halves, not in either half — which is exactly where
P2.5's harness would look.

---

## History

| Date | Estimate | What moved |
|---|---:|---|
| 2026-08-08 | ~33% | First assessment. Same-day: P1.2 closed, C3 pinned, C2 pinned + extracted to a pure function; tests 7/7 (4 real) → 13/13 (10 real) |
| 2026-08-09 | ~37% | P2.1 configuration mechanism: runtime `Settings` from defaults < `.env` < process env; tests → 17/17 (14 real). Also raised the priority of P1.5/P2.7 — see the localhost cliff |
| 2026-08-09 (pm) | ~42% | Core datapath closed out: P1.1–P1.4 + P4.2, plus two unrecorded bugs (silent datagram truncation, wall-clock timeouts). Tests → 31/31 (28 real); `PendingTable` 0 → 8. Supervisor backoff. Repo prepped for GitHub with CI |
| 2026-08-10 | ~43.5% | P2.3 phase 1: `Console` deleted, custom `std.options.logFn` emitting logfmt records, escaping writer closing a live **log-injection hole**. Tests → 36/36 (33 real). Smallest move yet, and correctly so — logging is one third done and metrics untouched. The pass's real value was a *finding*, not a feature: the default suffix blocklist 404s and **the binary does not start on its defaults** |
| 2026-08-10 (pm) | ~44.5% | P2.3 phase 2: `VORTEX_LOG_LEVEL` (incl. `off`) and `VORTEX_LOG_FORMAT` (`auto`/`logfmt`/`text`), both fail-loud on a bad value; closed P2.1's deferred `log level` field. Tests → 40/40 (37 real). Also a process finding: `zig build test` **passed while `zig build` failed** — lazy analysis never reached code only `main` calls, so the test step alone does not prove the binary compiles |
| 2026-08-13 | ~47.1% | P3.1 compression pointer following: [name_reader.zig](../src/dns/name_reader.zig) with a strictly-backwards rule *plus* a 64-jump cap (the cap turned out to be load-bearing, not decorative), the project's first fuzz target, and `DomainName` deleted along with its allocator. Tests → 59/59 (58 real). Shipped with no datapath caller by design |
| 2026-09-05 (pm) | ~57.4% | **P3.3 TTL-aware response caching** — [cache.zig](../src/dns/cache.zig), keyed on `(qname, qtype, qclass)` with a hand-written hash context, TTLs aged on the way out per RFC 2181 §5.2, RFC 2308 negative caching, OPT excluded throughout. Tests → 101/101 (98 real), 69 → 101. Closes the compression → parsing → caching chain and the largest single feature on the board. Two bugs caught during the build (an overlapping `@memcpy`, a get/age race), and **four vacuous tests found by mutation** — each because the fixture was built to be realistic rather than to discriminate. First module to carry `refAllDecls` |
| 2026-09-12 | ~60.0% | **P2.5 integration harness.** [tests/](../tests/) spawns the real binary against a scratch `.env` and a fake upstream it owns both ends of, and drives it over UDP: 12 cases covering forwarding, exact and suffix blocking, all three ingress rejections, both oversize paths, the upstream timeout, a forged reply, and a cache hit. `zig build test` → 143/143; `-Dtest-filter` narrows to one case in ~0.4 s. **No `src/` behavior changed** — the pass adds evidence, not capability, which is why only Tests + CI moved. All 12 cases mutation-checked, and the one mutation that failed to *compile* was rewritten rather than counted. Findings: the mutation run caught no bug in `src/` and one deadlock in the harness's own diagnostic path — `Child.kill` closes and nulls `child.stderr`, so a drain must detach the pipe *before* the kill and read it *after* |
| 2026-09-11 | ~58.8% | **P2.1 local-file blocklist source.** `VORTEX_BLOCKLIST_SOURCE` / `VORTEX_SUFFIX_BLOCKLIST_SOURCE` take a URL *or* a path, resolved by scheme through a new `Source` union; the old `_URL` names are a fatal error naming the replacement, not a silent fall back to the default list. Acquisition split from parsing in both blocklists (`load` / `build`), which gave two zero-coverage logic files their first tests. Tests → 131/131, 104 → 113 behavior tests, four mutation-checked. **The point of the pass is a precondition removed, not a feature added:** P2.5's harness has been the largest gap for five snapshots and was blocked on exactly this. Findings: the `*.`-prefix footgun was documented in three files and verified in none (now a test), and `Writer.Allocating.initOwnedSlice` silently yields an empty `written()` — a third independent route to "loads clean, blocks nothing" |
| 2026-09-08 | ~57.9% | Housekeeping sweep: `parseRdata` fixed + 7 tests, `refAllDecls` guards on all 16 modules, `root.zig` and its module deleted. Tests → 122/122. Bought one new property — `zig build test` now type-checks `main` — and correctly moved the number very little, because compiling is not testing |
| 2026-09-05 | ~50.2% | P3.2 upstream record parsing: [resource_record.zig](../src/dns/resource_record.zig), a pull-based iterator wired into `dispatcherLoop` as a read-only observer — the name reader's first datapath caller. Tests → 69/69 (66 real), second fuzz target. **Two guards from the plan were not built** (TC=1 and QDCOUNT≠1 skips). The pass's real value was again a *finding*: **`parseRdata` does not compile** and four merged PRs plus CI never noticed, because nothing calls it. Lazy analysis, round two — and this time `zig build` does not catch it either |

*Add a row per review pass. If the number doesn't move, that is itself the finding — the
coverage count sat still from 2026-07-27 to 2026-08-08 and nobody noticed until it was
written down.*

*Four passes in a row (08-10, 09-05, 09-05 pm, 09-11) delivered a finding at least as
valuable as the feature, and all four were the same shape: **something assumed to be checked
that was not.** First the default config nobody had booted; then `parseRdata`, which the
compiler was assumed to be checking; then four cache tests that were assumed to be asserting;
then the `*.`-prefix footgun, warned about in three documents and verified by none. The
pattern is now well enough established to act on rather than note — the question to open the
next pass with is not "what is left to build" but "what do we believe is verified, and what
actually verifies it?"*

*Asked of the current board, that question has an uncomfortable answer: **the entire
coroutine layer.** `handleQuery`, `dispatcherLoop`, the ingress loop and `supervise` are
believed correct on the strength of hand-driven `dig` runs from 08-09, and nothing since has
re-checked them — while P3.3 added four call sites to two of them. That is the same bet the
four findings above all lost. It is also precisely what P2.5 verifies, which is the argument
for building it next rather than after the next feature.*
