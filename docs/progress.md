# Progress — Where Vortex Actually Stands

A periodic completion assessment. [next_steps.md](next_steps.md) tracks *what is left*, item
by item; this file tracks *how far along the whole thing is* and — more usefully — **what
would actually move the needle**.

Percentages here are **judgment, not measurement**. They come from weighting five areas by
how much of a production DNS sinkhole each represents, then estimating completion within
each. Someone who weights caching over operability would land somewhere else. The weights
are stated explicitly below so the number can be argued with rather than just quoted.

---

## Snapshot — 2026-08-09 (end of day)

> **≈ 42% complete** against the yardstick in
> [next_steps.md](next_steps.md): *"production-ready DNS sinkhole for a home network."*
>
> Source: 2,290 lines of Zig across 15 files. `zig build test` → 30/30 pass under both
> Debug and ReleaseSafe, of which **27 are real behavior tests**.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~98% | 29.4 | **Closed out 08-09.** Header validation complete, no silent-failure modes left, replies verified against their query, every query lifecycle has a defined answer including timeout |
| Operability | 25% | ~20% | 5.0 | P2.1 config done. Structured logging, metrics, graceful shutdown, deployment, blocklist refresh still unbuilt |
| Protocol completeness | 20% | ~10% | 2.0 | Wildcard blocking done; compression, response parsing, caching, EDNS0, TCP fallback all open |
| Sinkhole feature set | 15% | ~5% | 0.8 | Per-qtype strategy, local records, dashboards, DNSSEC posture — all open |
| Tests + CI | 10% | ~48% | 4.8 | 27 real tests; CI exists but has never run; `PendingTable` went 0 → 8 tests |
| **Total** | **100%** | | **≈ 42** | |

*What "98%" on the datapath means:* the remaining 2% is the hard-coded 5 s deadline and 1 s
sweep cadence (newly unblocked for P2.1) and the QDCOUNT=0 SERVFAIL. Both are known, both are
documented, neither is a correctness defect.

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

## What moves the number

Ordered by return on effort, not by priority band.

### ~~→ ~40%: finish header validation and the test floor~~ ✅ done 2026-08-09
P4.2, the `PendingTable` suite, and CI all landed. What is left from this tier is small:
`parseQuestion`'s three error paths, `policy.zig`/`console.zig` coverage, and **actually
running CI once** — every step passes locally but the workflow itself is unexercised.

### → ~55%: make it deployable — the highest-value block on the board
Six items, and together they're the difference between a toy and a tool. **One is now done:**

| Item | Why it's on the critical path |
|---|---|
| ~~P2.1 config~~ ✅ 08-09 | Was the gate on all of these; listen address is now runtime |
| ~~P1.1 / P1.2 / P1.3 / P1.4 / P4.2~~ ✅ 08-09 | Datapath closed out; P1.5 is the only P1 left |
| P2.2 blocklist cache + refresh | Today a transient GitHub blip means **no DNS at all** (fails closed) |
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
2,290 lines of Zig, 15 files

src/main.zig                    440   ingress, handleQuery, dispatcher, sweeper, supervisor
src/dns/header.zig              396   parse, validateQuery, reply builders            9 tests
src/settings.zig                359   runtime config: .env parse, precedence          4 tests
src/utils/pending_table.zig     358   proxy-ID table, sweeper, question hashing       8 tests
src/dns/blocked_response.zig    178   pure NXDOMAIN+SOA assembly                      3 tests
src/dns/question.zig            103   QName parse, lowercasing                        1 test
src/blocklist/allowlist.zig      90   comptime allowlist                              1 test
src/blocklist/suffix_blocklist.zig 82 parent-label walk                               1 test
src/blocklist/domain_blocklist.zig 61 exact-match list over HTTP                      0 tests
src/dns/authority.zig            60   34-byte synthetic SOA
src/utility.zig                  41   Context                                         0 tests
src/blocklist/policy.zig         40   allow -> exact -> suffix chain                  0 tests  <- logic, no tests
src/dns/domain_name.zig          35   name accumulator                                1 test
src/console.zig                  29   thread-safe writer                              0 tests  <- logic, no tests
src/root.zig                     18   template stub -- delete (Housekeeping)
```

The distribution has changed shape. `pending_table.zig` was the largest untested risk in the
project and is now the second-best covered file — eight tests, mutation-verified, including
the one that would have caught B1. **`policy.zig` and `console.zig` are now the only files
carrying logic with zero tests**, and both are small.

The four best-tested files are also the four that were deliberately restructured to be pure:
`header.zig`, `blocked_response.zig`, `settings.zig`, `pending_table.zig`. That is not a
coincidence — see the lesson in [next_steps.md](next_steps.md) P2.5.

---

## History

| Date | Estimate | What moved |
|---|---:|---|
| 2026-08-08 | ~33% | First assessment. Same-day: P1.2 closed, C3 pinned, C2 pinned + extracted to a pure function; tests 7/7 (4 real) → 13/13 (10 real) |
| 2026-08-09 | ~37% | P2.1 configuration mechanism: runtime `Settings` from defaults < `.env` < process env; tests → 17/17 (14 real). Also raised the priority of P1.5/P2.7 — see the localhost cliff |
| 2026-08-09 (pm) | ~42% | Core datapath closed out: P1.1–P1.4 + P4.2, plus two unrecorded bugs (silent datagram truncation, wall-clock timeouts). Tests → 30/30 (27 real); `PendingTable` 0 → 8. Repo prepped for GitHub with CI |

*Add a row per review pass. If the number doesn't move, that is itself the finding — the
coverage count sat still from 2026-07-27 to 2026-08-08 and nobody noticed until it was
written down.*
