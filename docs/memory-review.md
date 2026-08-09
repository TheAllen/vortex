# Memory Bug Review — 2026-07-12

Findings from a one-off review of `src/` for memory bugs, ordered by severity.

> **Status as of 2026-08-09: 7 of 9 resolved.** Each was re-verified against the
> current source rather than taken on trust. The two that remain are tracked on
> the live board in [next_steps.md](next_steps.md) — **#5** (blocklist key
> lifetime) is **P4.5**, and **#6** (unbounded in-flight handlers) is **P1.5**,
> one of the two gates on binding off localhost.
>
> **#4 is now fully resolved** (2026-08-09). Its secondary recommendation —
> `@intCast` instead of `@truncate` when narrowing the timestamp — was adopted
> along with a move off the settable wall clock. See the note under that finding.
>
> **On line numbers:** the `Where:` lines record where things were on 2026-07-12
> and have since drifted. Resolution notes and the *Verified sound* section cite
> current locations and were re-checked on 2026-08-09.
>
> This file is a closed record of one review — what was found, and how each item
> was resolved. New findings belong on the live board in
> [next_steps.md](next_steps.md), not here.

---

## Critical

### 1. [x] `blocklist_set` is never initialized — undefined behavior

> **Fixed.** The field now defaults to `.empty` (`domain_blocklist.zig:7`).

- **Where:** `src/blocklist/domain_blocklist.zig:5`, `src/main.zig:150`
- **What:** The field defaults to `undefined`, and `main.zig` constructs the
  struct setting only `.file_body`:

  ```zig
  var domain_blocklist = DomainBlockList{
      .file_body = std.Io.Writer.Allocating.init(gpa),
  };
  ```

  `constructBlockList` then calls `contains`/`put` on a hashmap whose header
  (pointer, size, capacity) is garbage memory — anything from a crash to
  silent corruption. The stale `copy.zig` at the repo root had
  `.blocklist_set = .empty` (line 67); the initializer was lost when the code
  moved to `src/main.zig`.
- **Fix:** Change the field default to `blocklist_set: std.StringHashMapUnmanaged(void) = .empty`.

### 2. [x] Discarded `io.async` futures — dangling result storage

> **Fixed.** Tasks live in a long-lived `std.Io.Group` in `main`
> (`main.zig:353-357`), so every completion has live result storage. Both loops
> now go through a supervisor that restarts them (P1.2, 08-09). The two startup
> blocklist fetches keep their futures and `await` both before propagating
> either error (`main.zig:311-330`).

- **Where:** `src/main.zig:188`, `src/main.zig:189`, `src/main.zig:198`
- **What:** `_ = io.async(...)` discards the returned `Future`. In the 0.16
  `std.Io` API the future owns the task's result storage and must be kept
  alive and `await`ed (or canceled). As a discarded temporary it dies at the
  end of the statement — under a threaded/event-loop Io implementation the
  still-running coroutine can later write its completion state into reclaimed
  stack memory. Happens on **every packet** for the `handleQuery` spawn. Also
  silently drops errors and allows unbounded concurrency (no backpressure).
- **Fix:** Use an `std.Io.Group` (or store the futures) so completions have a
  live home; consider bounding in-flight handlers.
- **Note:** The "bound in-flight handlers" half of the fix was **not** covered by
  the `Group` change and is tracked separately as finding #6 (P1.5).

### 3. [x] Memory leak in the sweeper — every second

> **Fixed.** `defer dead_queries.deinit(self.gpa)` (`pending_table.zig:158`). Was P0.B2.

- **Where:** `src/utils/pending_table.zig:86`
- **What:** `sweepExpiredQueries` allocates `dead_queries` with
  `initCapacity(self.gpa, 64)` and never frees it. The sweeper runs once per
  second (`src/main.zig:130`), so this leaks continuously.
- **Fix:** Add `defer dead_queries.deinit(self.gpa);` right after the init.

### 4. [x] Expiry units mismatch — entries never expire

> **Fixed — the units half.** Writer and sweeper both use nanoseconds from the
> same clock (`main.zig:132`, `pending_table.zig:153`), and the comment on
> `PendingQuery.expires_at` now names the clock and unit so the mismatch is
> harder to reintroduce. Was P0.B1.
>
> **Also fixed (2026-08-09) — the `@intCast` half.** Both sites now `@intCast`,
> so narrowing `Io.Timestamp.nanoseconds` (an **i96**) to `i64` traps instead of
> silently wrapping.
>
> **And a third problem this finding did not spot.** Both sides were reading
> `Clock.real`, the *settable* wall clock — std documents it as subject to NTP
> steps and manual adjustment. A step backwards would let entries outlive their
> deadline; a step forwards would evict every in-flight query at once. Both now
> use `Clock.boot`: monotonic, and unlike `.awake` it counts time the machine
> spends suspended, so a query outstanding across a laptop sleep is correctly
> treated as long dead. The sweep cadence moved to the same clock.
>
> **Now pinned by tests.** `PendingTable` went from zero coverage to eight tests
> (P1.1, done 2026-08-09). The expiry test reintroduces B1 exactly under mutation
> and fails — and because its helper reads the same clock the sweeper does, it
> also catches a *clock* mismatch between the two sides, not just a unit one.

- **Where:** `src/main.zig:92` (stores **nanoseconds**) vs.
  `src/utils/pending_table.zig:85` (compares **milliseconds**)
- **What:** A nanosecond epoch value (~10^18) is never ≤ a millisecond value
  (~10^12), so the sweep removes nothing. Entries are only removed when the
  upstream replies; every dropped upstream response accumulates. Memory is
  capped (u16 keys → 65,536 entries), but once the table fills,
  `appendQuery` degenerates into a 65k-iteration scan while holding the mutex
  and then fails every query — a slow self-DoS.
- **Fix:** Use the same unit (ns is fine) on both sides. Also prefer
  `@intCast` over `@truncate` when narrowing the timestamp to `i64` — it
  traps on real overflow instead of silently wrapping.

---

## Design fragility

### 5. [ ] Blocklist keys borrow from `file_body` — lifetime coupling

> **Still open** — tracked as **P4.5**. Correct today (the body outlives the
> keys), but undocumented coupling that matters once the lists grow. Now applies
> to **both** lists: `SuffixBlockList` was added after this review and borrows
> from its own `file_body` the same way
> (`domain_blocklist.zig:49`, `suffix_blocklist.zig:44`). Each body is freed only
> in its own `deinit` (`domain_blocklist.zig:58`, `suffix_blocklist.zig:58`).

- **Where:** `src/blocklist/domain_blocklist.zig:26` *(2026-07-12; now :49)*
- **What:** The map keys are slices pointing directly into `file_body`'s
  buffer (the downloaded hosts file). Safe today only because `file_body`
  lives for the program's lifetime and is never mutated after
  `constructBlockList`. Refreshing the blocklist at runtime, or freeing
  `file_body` before the set, would dangle every key.
- **Fix:** Dupe the keys into the map and free `file_body` after
  construction — also saves memory, since the whole ~10 MB hosts file is
  currently kept resident just to back the keys. (Or document the invariant
  loudly if the coupling is intentional.)

### 6. [ ] Unbounded in-flight `handleQuery` tasks — no backpressure

> **Still open** — tracked as **P1.5**, and one of the two gates on binding off
> localhost (the other is per-client rate limiting, P2.7). A failed `dupe` now
> sheds one datagram instead of killing the server (P1.2, fixed 08-08), but that
> is a backstop, not a bound: nothing caps how many handlers are in flight before
> the allocator starts failing.
>
> This got **more** urgent on 08-09, not less. Before P2.1 the listen address was
> a compile-time constant, so reaching this bug required a recompile; now
> `VORTEX_LISTEN_HOST=0.0.0.0` is one line in a config file.

- **Where:** `src/main.zig:203` *(2026-07-12)* — now `src/main.zig:406`, the
  `group.async(io, handleQuery, ...)` spawn; the `gpa.dupe` at `:401` is the
  natural place to acquire a semaphore.
- **What:** Split out from finding #2. The `std.Io.Group` fix gives every
  task's completion live result storage, but the main loop still spawns one
  task per incoming packet with no limit on how many run concurrently. Each
  task carries a duped packet buffer and a `Question` allocation, so a burst
  (or a flood) of queries grows memory and task count without bound until the
  upstream catches up.
- **Fix:** Bound in-flight handlers, e.g. a counting semaphore acquired
  before `group.async` and released as `handleQuery` returns — or drop/refuse
  queries past a threshold, which is acceptable for UDP DNS since clients
  retry.

---

## Minor

### 7. [x] Ineffective full-table guard in `appendQuery`

> **Fixed.** Guard is `> maxInt(u16)` (`pending_table.zig:40`). Was P0.B5.

- **Where:** `src/utils/pending_table.zig:38`
- **What:** `count() >= std.math.maxInt(u32)` can never fire — a u16-keyed
  map caps at 65,536 entries. Presumably meant `maxInt(u16)`. As written, the
  full-table case falls through to the expensive linear scan instead of
  failing fast.

### 8. [x] Dead import that references a nonexistent decl

> **Fixed.** `pending_table.zig` imports only `std`. Was P0.B4.

- **Where:** `src/utils/pending_table.zig:2`
- **What:** `@import("../../src/main.zig").Console` doesn't exist (`Console`
  lives in `console.zig` and isn't `pub` in `main.zig`). It only compiles
  because the constant is unused and Zig analyzes lazily. Delete it.

### 9. [x] Stale `copy.zig` at repo root

> **Fixed.** The file is gone.

- **Where:** `copy.zig`
- **What:** An older copy of main. Misleading during review (it already
  obscured finding #1). Delete it.

---

## Verified sound

Checked and found no issues. **Re-verified 2026-08-09** against a `main.zig` that
has changed substantially since — all four still hold, at these locations:

- `handleQuery`'s `defer gpa.free(data)` covers all exit paths
  (`src/main.zig:59`). It now covers several *more* early returns than it did in
  July — the QR-bit drop, the P4.2 opcode/QDCOUNT rejections, the
  malformed-question drop, and the blocked-response path — which is why
  `main.zig` carries an ownership note at the call site (`:397-400`): do not free
  in those branches, and do not free after `group.async`.
- `parseQuestion`'s bounds checks are correct (`src/dns/question.zig`). Still
  correct, still **untested** — all three error paths are unexercised (P2.5).
- The dispatcher sends synchronously from `msg_buf` before the next receive, so
  there is no buffer-reuse race (`src/main.zig:148-222`).
- The main loop's `gpa.dupe` happens before the receive buffer is reused
  (`src/main.zig:401`). An oversized datagram is now refused *before* this point,
  so a truncated query never reaches a handler at all (08-09).

Two further properties established after this review, both memory-relevant and
worth recording here so they are not re-litigated:

- **The blocked-response path never overruns the exact-sized dupe.** The incoming
  datagram is duped to the exact query length, so the 34-byte SOA cannot be
  appended in place. `blocked_response.build` allocates a fresh
  `question_end + 34` buffer and reads `query` only
  (`src/dns/blocked_response.zig`). Asserts in `write_authority_section` catch a
  future caller that sizes it wrong.
- **`Settings` owns no memory.** Its string fields point at either string
  literals or the process-wide `Environ.Map`, so there is no `deinit` and no
  ownership question — only the documented constraint that it must not outlive
  that map (`src/settings.zig`).
