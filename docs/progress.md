# Progress — Where Vortex Actually Stands

A periodic completion assessment. [next_steps.md](next_steps.md) tracks *what is left*, item
by item; this file tracks *how far along the whole thing is* and — more usefully — **what
would actually move the needle**.

Percentages here are **judgment, not measurement**. They come from weighting five areas by
how much of a production DNS sinkhole each represents, then estimating completion within
each. Someone who weights caching over operability would land somewhere else. The weights
are stated explicitly below so the number can be argued with rather than just quoted.

---

## Snapshot — 2026-08-09

> **≈ 37% complete** against the yardstick in
> [next_steps.md](next_steps.md): *"production-ready DNS sinkhole for a home network."*
>
> Source: 1,692 lines of Zig across 15 files. `zig build test` → 17/17 pass, of which
> **14 are real behavior tests**.

### Breakdown

| Area | Weight | Done | Contribution | Notes |
|---|---:|---:|---:|---|
| Core query datapath | 30% | ~90% | 27.0 | Parse → filter → forward → demux → reply works end to end; all three P0s closed *and* pinned by regression tests |
| Operability | 25% | ~18% | 4.5 | **P2.1 config landed 08-09** — no longer configured by recompiling. Structured logging, metrics, graceful shutdown, deployment, blocklist refresh still unbuilt |
| Protocol completeness | 20% | ~10% | 2.0 | Wildcard blocking done; compression, response parsing, caching, EDNS0, TCP fallback all open |
| Sinkhole feature set | 15% | ~5% | 0.8 | Per-qtype response strategy, local records, dashboards, DNSSEC posture — all open |
| Tests + CI | 10% | ~30% | 3.0 | 14 real tests; `PendingTable` still zero; no `.github/` |
| **Total** | **100%** | | **≈ 37** | |

*Why config counts for ~13 points of the operability bucket on its own:* it is the item every
other deployment task sits behind. Nothing else in P2 can be exercised while the listen
address is a compile-time constant, so its completion unblocks more than its size suggests.
The *mechanism* is finished; four declared knobs (timeouts, log level, negative-cache TTL,
fail-open) are still pending because their **consumers** can't take a runtime value yet.

### Two other yardsticks, for calibration

- **"Have the hard problems been solved?" → ~55%.** Percentage-complete *understates*
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
- **P2.7** — no per-client rate limiting, so it can be conscripted into amplification.

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

### → ~40%: finish header validation and the test floor
**P4.2** (QDCOUNT/opcode) is nearly free now — `validateQuery`, `Rejection`, and the
rcode-parameterized `writeResponseFlags` all exist. Then the `parseQuestion` error-path
tests, the **`PendingTable` suite** (the largest remaining test gap, and where the whole
P0.B series hid), and a **CI workflow**. Cheap, and it stops the coverage number stalling
for six weeks the way it did between 07-27 and 08-08.

### → ~55%: make it deployable — the highest-value block on the board
Six items, and together they're the difference between a toy and a tool. **One is now done:**

| Item | Why it's on the critical path |
|---|---|
| ~~P2.1 config~~ ✅ 08-09 | Was the gate on all of these; listen address is now runtime |
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
1,692 lines of Zig, 15 files

src/settings.zig                359   runtime config: .env parse, precedence, defaults  4 tests
src/main.zig                    302   ingress loop, handleQuery, dispatcher, sweeper
src/dns/header.zig              207   header parse, validateQuery, writeResponseFlags   3 tests
src/dns/blocked_response.zig    175   pure NXDOMAIN+SOA assembly                        3 tests
src/utils/pending_table.zig     106   proxy-ID table, mutex, sweeper                    0 tests  <- largest gap
src/dns/question.zig             99   QName parse, lowercasing                          1 test
src/blocklist/allowlist.zig      90   comptime allowlist                                1 test
src/blocklist/suffix_blocklist.zig 82 parent-label walk                                 1 test
src/blocklist/domain_blocklist.zig 61 exact-match list over HTTP                        0 tests
src/dns/authority.zig            60   34-byte synthetic SOA
src/blocklist/policy.zig         40   allow -> exact -> suffix chain                    0 tests
src/dns/domain_name.zig          35   name accumulator                                  1 test
src/utility.zig                  29   Context                                           0 tests
src/console.zig                  29   thread-safe writer                                0 tests
src/root.zig                     18   template stub -- delete (Housekeeping)
```

The distribution is worth noting: **`pending_table.zig` and `policy.zig` remain the two
files carrying real logic with zero tests**, and the former is where six bugs already hid
once. `settings.zig` is now the largest file in the project — about half of it is doc
comments and tests, which is the right ratio for the module that decides how everything
else is wired.

---

## History

| Date | Estimate | What moved |
|---|---:|---|
| 2026-08-08 | ~33% | First assessment. Same-day: P1.2 closed, C3 pinned, C2 pinned + extracted to a pure function; tests 7/7 (4 real) → 13/13 (10 real) |
| 2026-08-09 | ~37% | P2.1 configuration mechanism: runtime `Settings` from defaults < `.env` < process env; tests → 17/17 (14 real). Also raised the priority of P1.5/P2.7 — see the localhost cliff |

*Add a row per review pass. If the number doesn't move, that is itself the finding — the
coverage count sat still from 2026-07-27 to 2026-08-08 and nobody noticed until it was
written down.*
