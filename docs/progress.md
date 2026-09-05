# Progress — Where Vortex Actually Stands

A periodic completion assessment. [next_steps.md](next_steps.md) tracks *what is left*, item
by item; this file tracks *how far along the whole thing is* and — more usefully — **what
would actually move the needle**.

Percentages here are **judgment, not measurement**. They come from weighting five areas by
how much of a production DNS sinkhole each represents, then estimating completion within
each. Someone who weights caching over operability would land somewhere else. The weights
are stated explicitly below so the number can be argued with rather than just quoted.

---

## Snapshot — 2026-09-05

> **≈ 50.2% complete** against the yardstick in
> [next_steps.md](next_steps.md): *"production-ready DNS sinkhole for a home network."*
>
> Source: 3,820 lines of Zig across 16 files. `zig build test` → 69/69 pass under both
> Debug and ReleaseSafe, of which **66 are real behavior tests**.
>
> Moved by P3.2 (upstream response record parsing): the protocol band from ~20% to ~32%, and
> tests from 59 to 69. The datapath is again unchanged in what the client receives — the walk
> is a read-only observer — so this buys the *capability* caching needs, not caching.
>
> Also closed since the last snapshot: the default suffix blocklist URL that 404'd, which
> had made the software unusable on its own defaults. See
> [the counterweight that retired](#the-counterweight-that-retired-the-default-config-boots-again).

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | **Closed out 08-09.** Header validation complete, no silent-failure modes left, replies verified against their query, every query lifecycle has a defined answer including timeout |
| Operability | 25% | ~28% | 7.0 | P2.1 config done; P2.3 structured logging **phases 1 and 2 of 3** done. +1 point of band for the suffix-URL fix — it boots on defaults again. The per-query event log, metrics, graceful shutdown, deployment, blocklist refresh still unbuilt |
| Protocol completeness | 20% | ~32% | 6.4 | Wildcard blocking, **P3.1 compression 08-13**, and **P3.2 record parsing 08-30** all done. Caching — the big one — plus EDNS0 and TCP fallback still open |
| Sinkhole feature set | 15% | ~5% | 0.75 | Per-qtype strategy, local records, dashboards, DNSSEC posture — all open |
| Tests + CI | 10% | ~66% | 6.6 | 66 real tests, and a second fuzz target with `resource_record.zig`. Still no integration harness, which is the largest gap. **And the suite is weaker than the count suggests — see below** |
| **Total** | **100%** | | **≈ 50.2** | |

*What "98%" on the datapath means:* the remaining 2% is the hard-coded 5 s deadline and 1 s
sweep cadence (newly unblocked for P2.1) and the QDCOUNT=0 SERVFAIL. Both are known, both are
documented, neither is a correctness defect.

*What P3.2 bought, and what it did not:* the protocol band moved 12 points for a walk that
changes nothing a client can observe. That is the correct shape — P3.1 and P3.2 are both
pure capability, and the payoff is P3.3. What is worth noticing is that **the two guards the
plan specified were not built** (skip the walk on TC=1, and unless QDCOUNT is 1), so the
band is credited at ~32% rather than the ~35% a complete P3.2 would earn. Neither is
reachable as a bug today, because a parse error changes nothing; both get cheaper to add now
than after P3.3 gives the walk consequences.

*The counting problem this snapshot exposes:* **69 passing tests is a weaker signal than 59
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

- **"Have the hard problems been solved?" → ~68%.** Percentage-complete *understates*
  Vortex, because the expensive-to-reverse decisions are the ones already made: the shared
  upstream socket with `PendingTable` demux, the `std.Io.Group` coroutine structure, and the
  three-valued filter chain. What remains is mostly *volume* of well-understood work
  (arg parsing, log lines, signal handlers, a service unit) plus exactly two substantial
  features — **response caching** (P3.3) and **bounded concurrency** (P1.5). This moved 6
  points because caching's two prerequisites are now both done: P3.3 no longer needs anything
  built before it can start, which is a different kind of progress than a percentage shows.
- **"Pi-hole competitor?" → ~20%.** The whole P4 band (per-qtype strategy, local records,
  observability dashboard, DNSSEC posture) is untouched, and that band *is* the difference
  between a forwarder-with-a-blocklist and the thing people actually install.

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

It is also a comment on the test suite: **69 passing tests and zero of them start the
binary.** P2.5's integration harness would have caught the 404 on the first run — and the
blocker for that harness is *local file paths as a blocklist source*, which is the same fix
as the cache file above. One change closes both.

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
| ~~P2.1 config~~ ✅ 08-09 | Was the gate on all of these; listen address is now runtime |
| ~~P1.1 / P1.2 / P1.3 / P1.4 / P4.2~~ ✅ 08-09 | Datapath closed out; P1.5 is the only P1 left |
| **P2.2 blocklist cache + refresh** | **Still the top of this list.** The 404 that proved it was fixed by swapping in another hard-coded URL, which re-armed the same trap against a different host — one that rate-limits. See [the counterweight that retired](#the-counterweight-that-retired-the-default-config-boots-again) |
| P1.5 concurrency cap | Gate for leaving localhost |
| P2.7 rate limiting | Gate for leaving localhost |
| P2.6 bind + service unit | `0.0.0.0:53`, privileged port, launchd/systemd |
| P2.4 graceful shutdown | Currently the only exit is a crash or Ctrl-C mid-write |

Note the shape of this: it moves completion by ~20 points but moves **utility from zero to
most of the way there**. It is the single most underweighted block if you judge by the
percentage alone.

### → ~70%: caching
~~P3.1~~ ✅ 08-13 → ~~P3.2~~ ✅ 08-30 → **P3.3 is now unblocked.** Both prerequisites are
done: compression pointer following, then the record walk that needs it. What is left is the
feature itself — a table keyed on `(qname, qtype, qclass)` holding response bytes plus an
expiry, checked in `handleQuery` before `appendQuery` and populated in `dispatcherLoop`
before the reply goes out. This is the largest single feature left and the one that most
changes how the thing *feels* to use.

Two things P3.2 owes it before that starts, both small: **TTL extraction excluding OPT**
(TYPE 41 reuses the TTL field for extended-RCODE/version/DO, so folding it into a minimum-TTL
computation yields a meaningless number), and the two skipped guards. Caching is also the
point where the walk stops being an observer — a parse error currently changes nothing
precisely *because* nothing depends on it, and that stops being true the moment a record's
TTL decides how long an answer is served.

### → beyond: the sinkhole band
P4.1 (per-qtype strategy), P4.4 (local records / conditional forwarding), P4.6 (observability
surface). Optional depending on whether the goal is "a real blackhole" or "keep learning
DNS" — the branch [next_steps.md](next_steps.md) flags at the end of its Suggested order.

---

## Where the code actually is

```
3,820 lines of Zig, 16 files

src/main.zig                    588   ingress, handleQuery, dispatcher, sweeper, supervisor  3 tests
src/dns/resource_record.zig     481   RR walk, iterator, rdata types                 10 tests
src/obs/log.zig                 478   logfmt logFn, escaping writer, level + format   8 tests
src/settings.zig                465   runtime config: .env parse, precedence          5 tests
src/dns/header.zig              403   parse, validateQuery, reply builders            9 tests
src/dns/name_reader.zig         364   name reading, pointer following                17 tests
src/utils/pending_table.zig     360   proxy-ID table, sweeper, question hashing       7 tests
src/dns/blocked_response.zig    179   pure NXDOMAIN+SOA assembly                      3 tests
src/dns/question.zig            110   QName parse, lowercasing                        4 tests
src/blocklist/allowlist.zig      90   comptime allowlist                              1 test
src/blocklist/suffix_blocklist.zig 82 parent-label walk                               1 test
src/blocklist/domain_blocklist.zig 61 exact-match list over HTTP                      0 tests
src/dns/authority.zig            60   34-byte synthetic SOA                           0 tests
src/utility.zig                  41   Context                                         0 tests
src/blocklist/policy.zig         40   allow -> exact -> suffix chain                  0 tests  <- logic, no tests
src/root.zig                     18   template stub -- delete (Housekeeping)
```

*(The 08-13 snapshot's copy of this table was stale on arrival — it carried a 2,951-line
total that contradicted its own header, and still listed `src/dns/domain_name.zig`, which
P3.1 deleted in the very pass that snapshot was recording. Regenerate it from `wc -l`, don't
hand-edit it.)*

The distribution has changed shape twice over. `pending_table.zig` was the largest untested
risk in the project and is now among the best covered — seven tests, mutation-verified,
including the one that would have caught B1. **`policy.zig` remains the only file carrying
logic with zero tests**, and it is still 40 lines; `domain_blocklist.zig` and `utility.zig`
join it on the zero-test list but carry less.

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
`name_reader.zig`, and now `resource_record.zig`. That is not a coincidence — see the lesson
in [next_steps.md](next_steps.md) P2.5. It has now held seven times, and the last three were
files where it was applied *before* the code existed rather than as a rescue.

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
| 2026-09-05 | ~50.2% | P3.2 upstream record parsing: [resource_record.zig](../src/dns/resource_record.zig), a pull-based iterator wired into `dispatcherLoop` as a read-only observer — the name reader's first datapath caller. Tests → 69/69 (66 real), second fuzz target. **Two guards from the plan were not built** (TC=1 and QDCOUNT≠1 skips). The pass's real value was again a *finding*: **`parseRdata` does not compile** and four merged PRs plus CI never noticed, because nothing calls it. Lazy analysis, round two — and this time `zig build` does not catch it either |

*Add a row per review pass. If the number doesn't move, that is itself the finding — the
coverage count sat still from 2026-07-27 to 2026-08-08 and nobody noticed until it was
written down.*

*Two passes in a row (08-10, 09-05) delivered more value as a finding than as a feature, and
both findings were the same shape: **something the tooling was assumed to be checking, and
was not.** Worth asking at the top of the next pass what else is assumed rather than
verified.*
