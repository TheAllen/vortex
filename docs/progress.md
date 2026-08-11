# Progress — Where Vortex Actually Stands

A periodic completion assessment. [next_steps.md](next_steps.md) tracks *what is left*, item
by item; this file tracks *how far along the whole thing is* and — more usefully — **what
would actually move the needle**.

Percentages here are **judgment, not measurement**. They come from weighting five areas by
how much of a production DNS sinkhole each represents, then estimating completion within
each. Someone who weights caching over operability would land somewhere else. The weights
are stated explicitly below so the number can be argued with rather than just quoted.

---

## Snapshot — 2026-08-10 (end of day)

> **≈ 44.5% complete** against the yardstick in
> [next_steps.md](next_steps.md): *"production-ready DNS sinkhole for a home network."*
>
> Source: 2,951 lines of Zig across 15 files. `zig build test` → 40/40 pass under both
> Debug and ReleaseSafe, of which **37 are real behavior tests**.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | **Closed out 08-09.** Header validation complete, no silent-failure modes left, replies verified against their query, every query lifecycle has a defined answer including timeout |
| Operability | 25% | ~27% | 6.75 | P2.1 config done; P2.3 structured logging **phases 1 and 2 of 3** done — records are structured, level and format are runtime. The per-query event log, metrics, graceful shutdown, deployment, blocklist refresh still unbuilt |
| Protocol completeness | 20% | ~10% | 2.0 | Wildcard blocking done; compression, response parsing, caching, EDNS0, TCP fallback all open |
| Sinkhole feature set | 15% | ~5% | 0.8 | Per-qtype strategy, local records, dashboards, DNSSEC posture — all open |
| Tests + CI | 10% | ~56% | 5.6 | 37 real tests; CI exists but **has still never run**; `obs/log.zig` shipped with 8 tests including an adversarial one |
| **Total** | **100%** | | **≈ 44.5** | |

*What "98%" on the datapath means:* the remaining 2% is the hard-coded 5 s deadline and 1 s
sweep cadence (newly unblocked for P2.1) and the QDCOUNT=0 SERVFAIL. Both are known, both are
documented, neither is a correctness defect.

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

- **"Have the hard problems been solved?" → ~62%.** Percentage-complete *understates*
  Vortex, because the expensive-to-reverse decisions are the ones already made: the shared
  upstream socket with `PendingTable` demux, the `std.Io.Group` coroutine structure, and the
  three-valued filter chain. What remains is mostly *volume* of well-understood work
  (arg parsing, log lines, signal handlers, a service unit) plus exactly two substantial
  features — **response caching** (P3.3, which needs compression + RR parsing first) and
  **bounded concurrency** (P1.5).
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

## The second counterweight: the default config no longer boots

Found 2026-08-10 while smoke-testing the logging change, not by any test:

**`VORTEX_SUFFIX_BLOCKLIST_URL`'s default now returns HTTP 404.** The hagezi
`wildcard/light-onlydomains.txt` path has moved. Because blocklist fetch fails closed, a
clean checkout run with no `.env` **exits at startup**:

```
level=error msg="failed to fetch suffix blocklist '...light-onlydomains.txt': HTTP 404"
level=error msg="BlocklistFetchFailed"
```

Two separate findings, and the second is the important one:

1. The URL needs updating — a one-line fix.
2. **P2.2 was theoretical and is now real.** [next_steps.md](next_steps.md) P2.2 describes
   fail-closed as a hypothetical: *"a transient GitHub blip takes your whole network's DNS
   down."* It is not hypothetical. The blip already happened, it was not transient, and the
   only reason it cost nothing is that nobody is running this yet. A local cache file written
   on success and loaded on fetch failure would have made this a warning instead of a
   hard stop.

This should move P2.2 up the deployability block, above P2.6 and P2.4. It is the only open
item that makes the software *unusable on its defaults* rather than merely unfinished.

It is also a comment on the test suite: 36 passing tests and zero of them start the binary.
P2.5's integration harness would have caught this on the first run — and note that the same
doc already identifies the blocker for that harness as *local file paths as a blocklist
source*, which is the same fix as the cache file above.

---

## What moves the number

Ordered by return on effort, not by priority band.

### ~~→ ~40%: finish header validation and the test floor~~ ✅ done 2026-08-09
P4.2, the `PendingTable` suite, and CI all landed. What is left from this tier keeps
shrinking: `console.zig` is gone (08-10) and its replacement shipped with tests, so what
remains is `parseQuestion`'s three error paths, `policy.zig` coverage, and **actually running
CI once** — every step passes locally but the workflow itself is still unexercised, now
across five review passes.

That last item stopped being a formality on 08-10. A phase-2 edit compiled clean under
`zig build test` and **failed under `zig build`**: Zig analyses lazily, and the broken
declaration was only reachable from `main`, which a test binary never calls. `ci.yml` already
runs `zig build` before `zig build test` in both optimization modes, so the workflow would
have caught it on the first push. The one guard rail written for exactly this class of
mistake is the one nobody has switched on.

### → ~55%: make it deployable — the highest-value block on the board
Six items, and together they're the difference between a toy and a tool. **One is now done:**

| Item | Why it's on the critical path |
|---|---|
| ~~P2.1 config~~ ✅ 08-09 | Was the gate on all of these; listen address is now runtime |
| ~~P1.1 / P1.2 / P1.3 / P1.4 / P4.2~~ ✅ 08-09 | Datapath closed out; P1.5 is the only P1 left |
| **P2.2 blocklist cache + refresh** | **Now the top of this list.** Not "a blip *would* mean no DNS" — the default suffix URL 404s today and the binary does not start. See the second counterweight |
| P1.5 concurrency cap | Gate for leaving localhost |
| P2.7 rate limiting | Gate for leaving localhost |
| P2.6 bind + service unit | `0.0.0.0:53`, privileged port, launchd/systemd |
| P2.4 graceful shutdown | Currently the only exit is a crash or Ctrl-C mid-write |

Note the shape of this: it moves completion by ~20 points but moves **utility from zero to
most of the way there**. It is the single most underweighted block if you judge by the
percentage alone.

### → ~70%: caching
**P3.1 → P3.2 → P3.3** in that order (compression is a hard prerequisite for parsing answer
sections; parsing is a prerequisite for extracting TTLs). This is the largest single feature
left and the one that most changes how the thing *feels* to use.

### → beyond: the sinkhole band
P4.1 (per-qtype strategy), P4.4 (local records / conditional forwarding), P4.6 (observability
surface). Optional depending on whether the goal is "a real blackhole" or "keep learning
DNS" — the branch [next_steps.md](next_steps.md) flags at the end of its Suggested order.

---

## Where the code actually is

```
2,951 lines of Zig, 15 files

src/main.zig                    556   ingress, handleQuery, dispatcher, sweeper, supervisor  2 tests
src/obs/log.zig                 478   logfmt logFn, escaping writer, level + format   8 tests
src/settings.zig                455   runtime config: .env parse, precedence          5 tests
src/dns/header.zig              396   parse, validateQuery, reply builders            9 tests
src/utils/pending_table.zig     358   proxy-ID table, sweeper, question hashing       7 tests
src/dns/blocked_response.zig    178   pure NXDOMAIN+SOA assembly                      3 tests
src/dns/question.zig            103   QName parse, lowercasing                        1 test
src/blocklist/allowlist.zig      90   comptime allowlist                              1 test
src/blocklist/suffix_blocklist.zig 82 parent-label walk                               1 test
src/blocklist/domain_blocklist.zig 61 exact-match list over HTTP                      0 tests
src/dns/authority.zig            60   34-byte synthetic SOA                           0 tests
src/utility.zig                  41   Context                                         0 tests
src/blocklist/policy.zig         40   allow -> exact -> suffix chain                  0 tests  <- logic, no tests
src/dns/domain_name.zig          35   name accumulator                                1 test
src/root.zig                     18   template stub -- delete (Housekeeping)
```

The distribution has changed shape. `pending_table.zig` was the largest untested risk in the
project and is now among the best covered — seven tests, mutation-verified, including the one
that would have caught B1. (Earlier passes recorded this as eight; the count is seven, since
`peek` non-consumption and `hashQuestion` share a test.) **`policy.zig` is now the only file
carrying logic with zero tests**, and it is 40 lines.

`console.zig` left that list the way things should: not by having tests bolted on, but by
being deleted. Its replacement is the fifth file written pure-first, and it arrived with
tests because the format renders into a `*std.Io.Writer` and the level and format parsers are
plain functions over a string — none of it needs an `Io` to exercise.

`obs/log.zig` is now the second-largest file in the project, which is worth a raised eyebrow:
478 lines to emit log records. Roughly half is comment, and the tests are a third of the
remainder, but if it grows again during phase 3 the escaping writer and the record format
should split from the level/format configuration.

The five best-tested files are also the five that were deliberately built or restructured to
be pure: `header.zig`, `blocked_response.zig`, `settings.zig`, `pending_table.zig`, and now
`obs/log.zig`. That is not a coincidence — see the lesson in
[next_steps.md](next_steps.md) P2.5. The lesson has now held five times, and `obs/log.zig` is
the first file where it was applied *before* the code existed rather than as a rescue.

---

## History

| Date | Estimate | What moved |
|---|---:|---|
| 2026-08-08 | ~33% | First assessment. Same-day: P1.2 closed, C3 pinned, C2 pinned + extracted to a pure function; tests 7/7 (4 real) → 13/13 (10 real) |
| 2026-08-09 | ~37% | P2.1 configuration mechanism: runtime `Settings` from defaults < `.env` < process env; tests → 17/17 (14 real). Also raised the priority of P1.5/P2.7 — see the localhost cliff |
| 2026-08-09 (pm) | ~42% | Core datapath closed out: P1.1–P1.4 + P4.2, plus two unrecorded bugs (silent datagram truncation, wall-clock timeouts). Tests → 31/31 (28 real); `PendingTable` 0 → 8. Supervisor backoff. Repo prepped for GitHub with CI |
| 2026-08-10 | ~43.5% | P2.3 phase 1: `Console` deleted, custom `std.options.logFn` emitting logfmt records, escaping writer closing a live **log-injection hole**. Tests → 36/36 (33 real). Smallest move yet, and correctly so — logging is one third done and metrics untouched. The pass's real value was a *finding*, not a feature: the default suffix blocklist 404s and **the binary does not start on its defaults** |
| 2026-08-10 (pm) | ~44.5% | P2.3 phase 2: `VORTEX_LOG_LEVEL` (incl. `off`) and `VORTEX_LOG_FORMAT` (`auto`/`logfmt`/`text`), both fail-loud on a bad value; closed P2.1's deferred `log level` field. Tests → 40/40 (37 real). Also a process finding: `zig build test` **passed while `zig build` failed** — lazy analysis never reached code only `main` calls, so the test step alone does not prove the binary compiles |

*Add a row per review pass. If the number doesn't move, that is itself the finding — the
coverage count sat still from 2026-07-27 to 2026-08-08 and nobody noticed until it was
written down.*
