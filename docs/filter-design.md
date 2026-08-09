# Filter Design — Comptime Duck-Typed Blocking Policy

Written 2026-07-20. Design-only; nothing here is implemented yet. This documents the
refactor from the hard-wired exact-match block check into a composable *filter*
abstraction built on Zig's compile-time duck typing. It is the vehicle for
[next_steps.md](next_steps.md) P3.4 (wildcard/suffix blocking) and the allowlist/regex
features that follow from it.

---

## 1. Current state

The block decision is a single concrete call inlined into `handleQuery`
([main.zig:80](../src/main.zig#L80)):

```zig
const domain: []const u8 = question.qname.name_list.items;
if (ctx.domain_block_list.blocklist_set.contains(domain)) {
    console.println("{s} -> BLOCKED", .{domain}) catch {};
    const len = header.craftBlockedResponse(data, q_end);
    ctx.client_socket.send(io, &incoming_addr, data[0..len]) catch {};
    return;
}
```

One concrete type (`DomainBlockList`), one algorithm (exact hash-set membership), one
outcome (NXDOMAIN). There is no seam to add a second matcher (suffix/wildcard), an
allowlist that *overrides* a block, or a different response for allow vs block. Adding
any of those today means editing `handleQuery` and growing an `if/else` ladder inside
the hot path.

## 2. The pattern: compile-time duck typing

Zig has no `interface` keyword. The idiomatic static-dispatch equivalent is a function
(or generic struct) that takes `anytype` and simply *uses* the members it needs — if
the type structurally has them, it compiles; if not, you get a compile error at the
call site. There is **zero runtime cost**: no vtable, no pointer indirection, every
call is monomorphized and inlinable.

You already rely on this exactly once — `Console.print(comptime fmt, args: anytype)`
([console.zig:19](../src/console.zig#L19)) accepts any argument tuple that the format
string can consume. The Filter refactor applies the same idea to policy instead of
formatting.

> **Contrast with the runtime pattern.** `std.mem.Allocator` / `std.Io` / `std.Io.Writer`
> use a `*anyopaque` + vtable so the concrete type can vary *at runtime*. We do **not**
> need that here — the set of filters is known at compile time (it's a config decision,
> not per-query data). Section 8 covers when that calculus flips.

## 3. The Filter contract

A **Filter** is any type with one method:

```zig
/// Returns the verdict for `domain`. `domain` is the already-parsed, dotted,
/// lowercase-normalized QName (e.g. "ads.example.com"). Must not allocate and
/// must be safe to call concurrently from many handleQuery coroutines — filters
/// are read-only over their configured state (same invariant DomainBlockList
/// already documents in README.md).
///
/// Normalization is a load-time (or, for the comptime allowlist, build-time)
/// invariant, not a per-query one: because `domain` arrives lowercased, every
/// filter's configured entries (the comptime `allow_set`, SuffixBlockList.zones,
/// the blocklist set) MUST be lowercased, or a mixed-case entry silently never
/// matches. The allowlist enforces this with a `comptime` @compileError (§4c); the
/// loaded lists lowercase in their parse pass (§4d).
pub fn decide(self: @This(), domain: []const u8) Verdict;
```

The verdict is a small enum rather than a `bool`, so the policy layer — not
`handleQuery` — owns the allow/block/abstain distinction. This is what makes allowlists
composable (see §5):

```zig
pub const Verdict = enum {
    /// Explicitly permit; short-circuits later filters in a chain.
    allow,
    /// Explicitly block; caller synthesizes the NXDOMAIN response.
    block,
    /// No opinion; defer to the next filter (or default-allow if none left).
    pass,
};
```

Keeping `Verdict` transport-agnostic (it says *what*, not *how*) means the response
crafting stays in `handleQuery`/`Header` where it already lives. If you later want a
filter to dictate the response shape (e.g. sinkhole to `0.0.0.0` instead of NXDOMAIN),
promote `block` to a tagged union — see §9, "designing toward answers."

## 4. Concrete filters

### 4a. `ExactBlockList` — refactor of what exists

`DomainBlockList` grows one method and satisfies the contract; its storage
(`blocklist_set: std.StringHashMapUnmanaged(void)`) is unchanged:

```zig
// in domain_blocklist.zig
pub fn decide(self: DomainBlockList, domain: []const u8) Verdict {
    return if (self.blocklist_set.contains(domain)) .block else .pass;
}
```

Note it returns `.pass`, not `.allow`, on a miss — "not on my list" is an abstention,
not a permission. That is the whole reason `Verdict` has three states.

### 4b. `SuffixBlockList` — the wildcard feature (P3.4)

Exact match can't express `*.doubleclick.net`. A suffix filter walks parent labels
against a set of blocked zones:

```zig
pub const SuffixBlockList = struct {
    zones: std.StringHashMapUnmanaged(void), // "doubleclick.net", "ads.example.com"

    pub fn decide(self: SuffixBlockList, domain: []const u8) Verdict {
        var rest: []const u8 = domain;
        while (true) {
            if (self.zones.contains(rest)) return .block;
            const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return .pass;
            rest = rest[dot + 1 ..]; // "a.b.c" -> "b.c" -> "c"
        }
    }
};
```

It's a *different type* with the *same shape*, so it drops into any chain that accepts
a Filter — no change to the call site.

#### The `*` is a rule, never a query

A crucial framing point: **`*.doubleclick.net` never appears in a DNS packet.** The
QName in a query is always a *concrete* name the client wants resolved —
`ads.doubleclick.net`, `static.doubleclick.net` — never a pattern. A resolver client
has no "wildcard question" to ask. (DNS wildcards exist only in *authoritative zone
data*, RFC 1034 §4.3.3 / RFC 4592, where a server synthesizes answers from a stored
`*.example.com` record; even then the querying client sends the concrete name. Pedantic
footnote: the byte `0x2A` = `*` is legal in a label on the wire, but no normal client
emits it for lookup.)

So `SuffixBlockList` never compares against a literal `*`. The `*` lives entirely on
*our* side, as blocklist-author notation. The loader strips the `*.` prefix and stores
the bare zone — the matcher only ever sees concrete names on both sides:

```zig
// when ingesting a rule line, before inserting into `zones`
fn normalizeZone(rule: []const u8) []const u8 {
    // "*.doubleclick.net" -> "doubleclick.net"; "doubleclick.net" -> unchanged
    if (std.mem.startsWith(u8, rule, "*.")) return rule[2..];
    return rule;
}
```

This is why `zones` holds `"doubleclick.net"`, not `"*.doubleclick.net"`, in the field
comment above.

#### Worked traces

Given `zones = { "doubleclick.net", "ads.example.com" }`, here is what `decide` does
label-by-label. `rest` is the slice reused each iteration; `→` is one loop turn:

| Incoming QName (concrete)   | Walk (`rest` each turn)                                   | Result   |
|-----------------------------|----------------------------------------------------------|----------|
| `ads.doubleclick.net`       | `ads.doubleclick.net` → `doubleclick.net` ✅              | `.block` |
| `doubleclick.net` (apex)    | `doubleclick.net` ✅                                       | `.block` |
| `a.b.ads.example.com`       | `a.b.ads.example.com` → `b.ads.example.com` → `ads.example.com` ✅ | `.block` |
| `notdoubleclick.net`        | `notdoubleclick.net` → `net` → (no dot) ✗                 | `.pass`  |
| `example.org`               | `example.org` → `org` → (no dot) ✗                        | `.pass`  |
| `net` (single label)        | `net` → (no dot) ✗                                        | `.pass`  |

Two correctness properties the trace demonstrates:

1. **Label-boundary safety.** `notdoubleclick.net` does **not** match zone
   `doubleclick.net`, even though the zone is a literal substring-suffix of the name.
   The walk only ever tests whole-label boundaries (it advances *past* a `.`), so it
   can never split inside the `notdoubleclick` label. A naive
   `std.mem.endsWith(u8, domain, zone)` would wrongly block it — this is *the* classic
   suffix-match bug, and the reason we walk labels instead of comparing tails.
2. **Termination.** Every iteration either returns or strips at least one label, and
   `indexOfScalar` returns `null` once no `.` remains, so a single-label input
   (`"net"`, or a root-ish `""`) terminates after one probe with `.pass`.

Note the apex row: zone `doubleclick.net` blocks *both* `doubleclick.net` itself and any
subdomain. That matches how ad-block lists intend `*.doubleclick.net` — the apex is
almost always meant too. If you ever want subdomains-only (block `ads.doubleclick.net`
but *not* the apex), that's a different rule type, not this one.

### 4c. `AllowList` — override capability (comptime, baked into the binary)

The allowlist is different *in kind* from the two blocklists, and that difference decides
its storage. The blocklists are large (44k–100k+), externally maintained, and fetched at
startup; the allowlist is small, developer-curated, and rarely changed. That makes it
genuine *compile-time* data (§2, §8) — it changes when you edit-and-rebuild, not per-run —
so it lives in the binary as a `std.StaticStringMap`, not a loaded `StringHashMap`:

```zig
// allowlist.zig
const allow_set = std.StaticStringMap(void).initComptime(.{
    .{"captive.apple.com"}, .{"login.live.com"}, .{"mtalk.google.com"},
    // ...the curated list
});

pub const AllowList = struct {
    pub fn decide(_: AllowList, domain: []const u8) Verdict {
        return if (allow_set.has(domain)) .allow else .pass;
    }
};
```

What the comptime storage buys — note that *lookup speed is not on the list*. The QName is
runtime data, so you still probe at request time, and per §6a the filter cost is noise next
to the network I/O regardless. The wins are about the *load path* and *robustness*:

- **Zero load path.** No fetch, no parse, no allocation, no retained buffer — the set is in
  `.rodata` at process start. `AllowList` is a **zero-size type**: nothing to `deinit`,
  nothing to thread through `Context`/`main` construction (§6, §7).
- **No runtime failure mode** for the one list that most needs to be bulletproof — it's the
  safety override that keeps logins and push working, and it can't be missing or malformed.
- **Build-time invariant enforcement.** The §3 lowercase rule is checked in a `comptime`
  block that `@compileError`s on any uppercase byte, so a mixed-case entry is a *build*
  failure, not a silently-never-matching key.

The one cost: editing the list means recompiling — the right trade for a list the developer
owns (it forces the change through the build). If a non-developer operator ever needs to
edit without rebuilding, keep this comptime set as the always-present baseline and
*additionally* read a runtime file that extends it (`decide` checks the static set, then the
loaded one) — the same "add it the day it becomes data" rule as §7a. Don't build the overlay
first.

Two framing points that carry over from the block matchers:

- **The storage swap is invisible to the Filter contract (§3).** `decide` is still
  `[]const u8 -> Verdict`; comptime-vs-runtime is a detail behind the seam, which is exactly
  why the same `Verdict` and the same `Policy` wiring apply unchanged.
- **Exact match only** (like §4a, unlike §4b): an entry covers that FQDN, not its
  subdomains. Domains that vary by subdomain (Apple push couriers, Google's rotating CDNs)
  can't be exact entries — they wait on a suffix-allow matcher (a mirror of §4b over an
  allow `allow_set`) and sit commented in `allowlist.zig` until then.

`AllowList` is useless on its own (it never blocks) — its value is entirely in
*composition* (§5).

### 4d. Loading from source lists — which source feeds which matcher

A matcher is only as good as what you load into it, and the two block matchers want
*different-shaped* source data. Getting this mapping wrong is the easy mistake, so it's
worth stating outright.

#### The StevenBlack hosts file is an *exact* source, not a suffix source

`ExactBlockList` is fed from [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts)
(`BLOCKLIST_URL`). That file is a standard hosts file: every blockable entry is a
`0.0.0.0 <domain>` data line naming **one fully-qualified, concrete domain**. It has **no
wildcards** — it can't express `*.adblade.com`; instead it enumerates each subdomain on
its own line:

```
# [adblade.com]                  ← comment / section label — SKIP (starts with '#')
0.0.0.0 adblade.com              ← data: one concrete domain
0.0.0.0 dmp.adblade.com          ← data: one concrete domain
0.0.0.0 pixel.adblade.com        ← data: one concrete domain
0.0.0.0 static-cdn.adblade.com   ← data
```

**The `# [adblade.com]` line is a comment, not data.** It's cosmetic grouping the
maintainer inserts; it starts with `#`, so it is dropped like any other comment. Note that
`adblade.com` *also* appears as a real `0.0.0.0 adblade.com` entry directly below — the
header carries no information the data lines don't already have. Do **not** promote these
section headers into suffix zones: it's reverse-engineering intent the format doesn't
guarantee (sections don't reliably contain only strict subdomains of the header), and it
silently changes semantics from "block exactly what's listed" to "block `*.header`
including names never listed". That may be a policy you want — but it's *your* decision,
not something the hosts file encodes.

Because every entry is a concrete name, the hosts file maps **1:1 onto `ExactBlockList`**
(flat set membership, §4a). It does **not** feed `SuffixBlockList`.

#### The parse rules (what `constructBlockList` does)

For each line, in order:

1. Skip blank lines and comment lines (first non-space field starts with `#`).
2. Whitespace-tokenize; expect `["0.0.0.0", "<domain>"]` and take field `[1]`.
3. Skip preamble/alias junk: `localhost`, and — cheapest catch-all — **any field with no
   dot** (`0.0.0.0`, `broadcasthost`, `local`, `localhost.localdomain`'s bare forms). A
   real blockable FQDN always contains a `.`.
4. **Lowercase at load time** — this is the §3 loader invariant, not optional. QNames
   arrive already lowercased, so a mixed-case hosts entry would silently *never* match.
   Since the set keys are zero-copy slices into the retained `file_body` buffer, the clean
   implementation is a single in-place `std.ascii.lowerString` pass over the owned buffer
   before iterating (ASCII-only; touching the comment/IP bytes we discard is harmless).

> **Known gap:** the current `constructBlockList` (`src/blocklist/domain_blocklist.zig`)
> does not yet perform step 4. StevenBlack entries are almost all lowercase already, so it
> works in practice, but the invariant is unenforced — close it when the §10 refactor
> lands.

#### What `SuffixBlockList` needs instead

The suffix matcher wants *zones* — a bare domain that stands for the apex **and** every
subdomain (§4b). The hosts file can't express that, so `SuffixBlockList.zones` stays
**empty** from that source and fills from a list whose maintainer *declares* wildcard
intent as data.

**Chosen source: [HaGeZi's DNS blocklists](https://github.com/hagezi/dns-blocklists),
`wildcard/…-onlydomains.txt`.** Each data line is one bare, lowercase domain that HaGeZi
has already declared a wildcard zone — the header literally reads `# Syntax: Domains
(without subdomains)`, i.e. subdomains are omitted *on purpose* because the wildcard
covers them. That is `SuffixBlockList` semantics expressed as data, not derived by
guessing (contrast the "don't promote `# [section]` headers" warning above).

Default tier for vortex is **`light`** (~44k zones, minimal false positives, low
resource — fits the lightweight/learning goal); step up to `multi` or `pro` for more
coverage:

```
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt
```

Loader delta vs the hosts parser: skip `#`/blank lines, then each remaining line *is* the
whole zone — no whitespace split, no `0.0.0.0` prefix. `normalizeZone` (§4b) strips a
leading `*.` and is a **no-op** on HaGeZi's onlydomains (they carry none), but keep it so
the same loader also accepts `*.zone` lists. Lowercase per the §3 invariant. Then
`try zones.put(gpa, domain, {})`. The label-walk in `decide` is why ~44k zones stand in
for millions of enumerated names.

#### The two sources, side by side

The final split — both fetched at startup, both populate-then-freeze before any coroutine
spawns, so the README's no-mutex argument holds for each:

| Matcher            | Source URL                                                                                          | Shape / match          |
|--------------------|-----------------------------------------------------------------------------------------------------|------------------------|
| `ExactBlockList`   | `raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts`                               | concrete FQDNs, O(1) set membership |
| `SuffixBlockList`  | `raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt`               | declared zones, label-walk (apex + all subdomains) |

Two operational notes now that it's two lists:

- **Overlap is expected and harmless.** HaGeZi `light` and StevenBlack share many domains.
  A name on both hits `exact` first (§5 precedence) and short-circuits — no dedup across
  lists is needed; each list populates its own structure independently.
- **Two fetches, two retained buffers.** `main` currently fetches one `BLOCKLIST_URL` into
  `domain_blocklist.file_body`; the suffix list needs a *second* fetch into a *second*
  buffer whose lifetime backs `zones`' zero-copy keys — same populate-then-freeze rule as
  the exact list (§7).

#### The allowlist has no *source* — it's comptime, not loaded

The table above is the two *loaded* lists. `AllowList` (§4c) deliberately has **no source
URL and no loader**: it's a `std.StaticStringMap` baked into the binary. This is the mirror
image of the sourcing logic above, not an exception to it. The block matchers want large,
externally maintained data that must be *fetched* to stay current — so which source feeds
which matcher is a real question, and getting the source *shape* right (exact FQDNs vs.
declared zones) is the easy mistake to avoid. The allowlist wants the opposite: a small,
curated, developer-owned override that should ship *with* the binary and never fail to load.
Opposite data nature → opposite storage strategy, behind the same `decide` seam (§3). So for
the allowlist there is no "which source feeds it" — the developer feeds it, at compile time,
and the §3 lowercase invariant it shares with the loaded lists is enforced at build time
rather than in a parse pass.

## 5. Composition: a concrete `Policy` struct

The precedence between allow / exact / suffix is *fixed policy* — it never varies at
runtime, and it never varies at comptime either (changing it means editing code). So it
doesn't need a generic combinator; it needs one hand-written function that reads
top-to-bottom exactly as the precedence rule reads:

```zig
// in filter.zig
pub const Policy = struct {
    allow: AllowList,
    exact: ExactBlockList,   // == the existing DomainBlockList
    suffix: SuffixBlockList,

    /// Allow wins, then exact block, then suffix block; default-.pass if all abstain.
    pub fn decide(self: Policy, domain: []const u8) Verdict {
        if (self.allow.decide(domain) == .allow) return .allow;
        if (self.exact.decide(domain) == .block) return .block;
        return self.suffix.decide(domain); // .block or .pass
    }
};
```

Each matcher is still an independent `[]const u8 -> Verdict` function (§4), so each is
unit-tested in isolation; `Policy.decide` is the *one* place precedence lives, and it's
three lines you can read without unrolling anything. Codegen is identical to an
`inline for` chain — three inlined calls, no loop, no allocation, no indirection — but
there is no `comptime Filters: type`, no `std.meta.fields`, and nothing generic to
propagate into `Context`.

### Verdict flow

The three matchers form a short-circuit ladder. A domain falls straight through until a
matcher has an opinion; the first non-`pass` wins and the rest are never consulted. The
two terminal `allow`/`pass` outcomes are indistinguishable to `handleQuery` (both forward
upstream, §6) — the distinction only governs short-circuiting *inside* `decide`:

```
                     domain: "ads.example.com"
                              │
                              ▼
                   ┌──────────────────────┐
                   │ allow.decide(domain) │
                   └──────────┬───────────┘
                     .allow   │   .pass
                  ┌───────────┴───────────┐
                  ▼                        ▼
            ┌───────────┐        ┌──────────────────────┐
            │   ALLOW   │        │ exact.decide(domain) │
            └───────────┘        └──────────┬───────────┘
             short-circuit         .block   │   .pass
             forward upstream    ┌──────────┴───────────┐
                                 ▼                       ▼
                           ┌───────────┐      ┌───────────────────────┐
                           │   BLOCK   │      │ suffix.decide(domain) │
                           └───────────┘      └───────────┬───────────┘
                            NXDOMAIN            .block     │     .pass
                            (craftBlocked-    ┌────────────┴──────────┐
                             Response)        ▼                       ▼
                                        ┌───────────┐          ┌───────────┐
                                        │   BLOCK   │          │   PASS    │
                                        └───────────┘          └───────────┘
                                         NXDOMAIN               default-allow
                                                                forward upstream
```

Precedence reads top-to-bottom exactly as `Policy.decide`'s three statements do: `allow`
gates first (so it can override a later block), then `exact`, then `suffix`, and if all
three abstain the ladder falls out the bottom as `.pass`.

### Worked composition trace

Config:

```zig
Policy{
    .allow  = .{}, // zero-size; assume comptime allow_set ⊇ { "ads.internal.corp" } here
    .exact  = .{ .blocklist_set = <{ "tracker.example.com" }> },
    .suffix = .{ .zones = <{ "doubleclick.net", "example.com" }> },
}
```

(`<{ ... }>` denotes an already-populated `StringHashMapUnmanaged` — these aren't
brace-initializable; shown for illustration.)

`decide` runs the three matchers top-to-bottom and returns on the **first** non-`pass`.
The ✋ marks the check that returns; matchers after it are never consulted:

| QName                                     | `allow` | `exact` | `suffix` | Result   | Why                                          |
|-------------------------------------------|---------|---------|----------|----------|----------------------------------------------|
| `ads.internal.corp`                       | allow ✋| —       | —        | **allow**| allowlist checked first                      |
| `tracker.example.com`                     | pass    | block ✋| —        | **block**| exact hit; suffix never consulted            |
| `ads.doubleclick.net`                     | pass    | pass    | block ✋ | **block**| only the suffix zone matches                 |
| `foo.example.com`                         | pass    | pass    | block ✋ | **block**| suffix zone `example.com` (subdomain)        |
| `ads.internal.corp` *and* on a blocklist  | allow ✋| (block) | (block)  | **allow**| **order is the feature** — allow precedes    |
| `www.wikipedia.org`                       | pass    | pass    | pass     | **pass** | nobody objects → `handleQuery` forwards it   |

The fifth row is the whole reason `Verdict` has three states instead of a `bool`: an
allowlisted domain that *also* appears on a blocklist resolves to `.allow` purely because
`Policy.decide` consults `allow` first. Precedence is expressed by statement order, in one
readable function.

The last row shows `.pass` propagating all the way out: no matcher blocked and no matcher
allowed, so `decide` returns `.pass`, which `handleQuery` treats as "forward upstream"
(default-allow). `.allow` and `.pass` are indistinguishable to `handleQuery` today — the
difference only matters *inside* `decide`, where `.allow` short-circuits and `.pass`
doesn't.

## 6. Wiring into `Context` and `handleQuery`

`Context` stays **non-generic**. Swap one field
([utility.zig:11](../src/utility.zig#L11)):

```zig
pub const Context = struct {
    // ...
    policy: *const Policy = undefined, // was: domain_block_list: *DomainBlockList
};
```

`init` takes `policy: *const Policy` in place of `domain_block_list`; nothing else in
`Context` changes, and no caller of `Context` (server.zig, etc.) needs a generic
signature. The hot-path check becomes:

```zig
const domain: []const u8 = question.qname.name_list.items;
switch (ctx.policy.decide(domain)) {
    .block => {
        console.println("{s} -> BLOCKED", .{domain}) catch {};
        const len = header.craftBlockedResponse(data, q_end);
        ctx.client_socket.send(io, &incoming_addr, data[0..len]) catch {};
        return;
    },
    .allow, .pass => {}, // fall through to upstream forwarding
}
```

Everything below this line (proxy-ID allocation, upstream send) is untouched.

## 6a. Per-query cost — does adding suffix search slow resolution down?

A natural worry once the chain grows from one matcher to three: every query now runs
`allow` → `exact` → `suffix` instead of a single `contains`. Does that tax the hot path?
**No, not measurably** — and the reasoning is worth writing down because it also tells you
*where* the real cost of resolution lives (and thus what's actually worth optimizing).

### The chain's cost is a tiny fixed constant, independent of list size

Walk the three matchers by their per-query work:

| Matcher            | Per-query work                                              | Cost                          |
|--------------------|-------------------------------------------------------------|-------------------------------|
| `AllowList`        | one `contains(domain)`                                      | 1 hash + 1 compare — O(1)     |
| `ExactBlockList`   | one `contains(domain)`                                      | 1 hash + 1 compare — O(1)     |
| `SuffixBlockList`  | one `contains` **per label of the query**, until a hit/miss | O(labels), *not* O(zones)     |

The point that dissolves the worry: the suffix walk (§4b) loops over the **labels of the
incoming query**, not over the blocklist. `ads.doubleclick.net` probes at most
`ads.doubleclick.net` → `doubleclick.net` → `net` — three lookups — then stops. Real
domains carry ~2–4 labels, so the whole `Policy.decide` is bounded at roughly **2 + 4 ≈ 6
hashmap probes**, worst case, per query. That bound does **not** grow with the blocklists:
44k zones or 44 zones, the label count of the *query* is the same. Every probe is an O(1)
`StringHashMap.contains` with no allocation (the §3 contract forbids allocating in
`decide`). No loop over entries, no indirection (§2 — all calls monomorphize and inline).

### That constant is dwarfed by the network I/O a *pass* already pays

The comparison that matters is filter cost vs. the cost of what happens *next*:

```
 ~6 in-memory hashmap probes         upstream resolver round-trip
 ≈ tens of nanoseconds        vs.    ≈ 1–50 milliseconds
 └──────────────── ~6 orders of magnitude apart ────────────────┘
```

A query that isn't blocked gets forwarded upstream and waits milliseconds on the network
(see [upstream-design.md](upstream-design.md)). The filtering that decided to forward it
cost nanoseconds. The chain is lost in the noise of the I/O it gates — you could make it
ten matchers and not move the needle on end-to-end resolution latency.

### The asymmetry favors blocking

Note *which* queries pay the full chain. A **block short-circuits** (§5): the first
non-`pass` verdict returns, `handleQuery` synthesizes NXDOMAIN, and the upstream query
**never happens** (§6). So a blocked name pays a fraction of the chain and then *skips* the
millisecond-scale network cost entirely — blocking is strictly *faster* than passing, not
slower. Only a full `.pass` (nobody objected) runs all three matchers, and that query was
about to spend milliseconds upstream anyway.

### Ordering is already optimal for cost

The §5 precedence (`allow` → `exact` → `suffix`) also happens to be cheapest-first: the two
O(1) matchers gate before the O(labels) walk, and any earlier hit short-circuits the walk
away. Precedence was chosen for *correctness* (allow must override block), but it costs
nothing extra — the two goals align.

### If profiling ever says otherwise (it won't at this scale)

Reach for these only with a measurement in hand — all are premature today:

- **A qname→verdict cache in front of `Policy.decide`.** You likely want a DNS answer
  cache anyway; once it exists, repeat queries skip both the filter chain *and* the
  upstream round-trip. This is the high-value lever, and it's about caching *answers*, not
  speeding up filtering.
- **Collapse `exact`+`suffix` into the single label walk** — two set-probes per label
  instead of a separate full-name `exact` probe. Saves ~1 probe; not worth the loss of the
  clean per-matcher `decide` seam (§4, §11) at this scale.

The takeaway for P3.4: build the three-matcher chain as designed. The added suffix search
is a fixed ~2–5 extra hashmap lookups per query, independent of blocklist size, and
invisible next to the network I/O that DNS resolution already pays.

## 7. Construction in `main`

`main` builds the policy once, after the blocklist HTTP fetch
([main.zig:176](../src/main.zig#L176)), before spawning coroutines — the same
populate-then-freeze lifecycle the README's no-mutex argument depends on:

```zig
const policy = Policy{
    .allow  = .{},              // comptime StaticStringMap — nothing to construct or fetch
    .exact  = domain_blocklist, // the existing DomainBlockList
    .suffix = suffix_list,
};
```

Then pass `&policy` into `Context`. Stack-allocated, immutable after construction, and
shared by `const` pointer across every coroutine — no synchronization, consistent with
`DomainBlockList` today.

## 7a. What this deliberately drops (and when to add it back)

- **A generic `Chain(comptime Filters: type)` combinator** — it buys "reorder the tuple
  to change precedence," but precedence here is fixed policy, so the flexibility is never
  exercised. `Policy.decide` gives identical codegen and reads more directly. Reach for a
  generic chain only if the *number* or *order* of filters becomes configuration (many
  named lists, user-orderable rules) — then the tuple pays for itself.
- **Generic `Context(comptime Policy: type)`** — only needed to thread a comptime chain
  type through; with a concrete `Policy` there's nothing to parameterize.
- **Runtime vtable (§8) and tagged-union `Verdict` (§9)** — still deferred, still additive
  when they arrive. The `Verdict` contract is what carries forward, and it's identical here.

The rule of thumb: `Verdict` (the 3-state precedence type) and per-matcher `decide` are
the load-bearing ideas and stay. The combinator is machinery for a variability this
program doesn't yet have — add it the day filters become data, not before.

## 8. Why comptime here, and when to switch to a vtable

**Use comptime duck typing (this design) because** the filter set is a startup
configuration decision, fixed for the process lifetime. Comptime gives full inlining and
zero per-query overhead on the hottest path in the program.

**Switch to a runtime `Filter` vtable** (the `std.mem.Allocator` shape:
`ptr: *anyopaque, vtable: *const struct { decide: *const fn(...) Verdict }`) **only if**
one day you need the filter *list itself* to change at runtime — e.g. an admin API that
adds/removes filters live, or filters loaded from a plugin. At that point the set is
runtime data and comptime can't express it. That is a real but distant requirement;
don't pay the indirection now. The `Verdict` contract is identical in both worlds, so
the migration is mechanical if it ever comes.

## 9. Designing toward answers (forward-compat note)

Today `block` implies exactly one response: NXDOMAIN via `craftBlockedResponse`. When
P3 adds record synthesis, promote the verdict so a filter can pick the sinkhole:

```zig
pub const Verdict = union(enum) {
    allow,
    pass,
    block: BlockAction, // nxdomain | { sinkhole_a: [4]u8 } | refused
};
```

`handleQuery`'s `switch` gains arms per `BlockAction`; the filter *contract* and
`Policy.decide` are unchanged. This is the tagged-union sum-type pattern noted in the
review — premature to build now (only one response shape exists), but the enum-first
`Verdict` is deliberately shaped so the union upgrade is additive.

## 10. Migration steps

Small, each independently testable — do them in order:

1. Add `Verdict` (enum form) in a new `src/blocklist/filter.zig`.
2. Add `ExactBlockList.decide` to `DomainBlockList` — pure addition, existing code path
   still calls `contains` directly, so nothing breaks yet.
3. Add the concrete `Policy` struct in `filter.zig` (with just `.exact` wired for now).
4. Switch `handleQuery` from the inline `contains` to `ctx.policy.decide`, and swap the
   `Context` field. Behavior is *identical* — `Policy` wraps only `ExactBlockList`.
5. Add `SuffixBlockList` (P3.4) and `AllowList` (the comptime `StaticStringMap`, §4c — a
   zero-size field, nothing to fetch or construct); add the two fields to `Policy` and the
   two lines to `Policy.decide`. No `handleQuery` change, no `Context` change.

Steps 1–4 are a pure refactor with no behavior change — land and verify them before
step 5 adds features.

## 11. Testing

Each filter is a pure `[]const u8 -> Verdict` function — trivially unit-testable with no
IO, no allocator gymnastics, no coroutines (contrast the PendingTable suite in
next_steps.md P1.1):

- `ExactBlockList`: hit → `.block`, miss → `.pass`, `localhost` skipped (existing
  `parseDomain` rule).
- `SuffixBlockList`: `ads.doubleclick.net` blocked by zone `doubleclick.net`;
  `notdoubleclick.net` **not** blocked (label-boundary correctness — the classic
  suffix-match bug); apex `doubleclick.net` blocked; single-label input terminates.
- `AllowList`: hit → `.allow`, miss → `.pass`, and a subdomain of a listed name → `.pass`
  (exact-match, §4c). The lowercase invariant is a *compile-time* `@compileError`, so it
  needs no runtime test — a bad entry fails the build.
- `Policy.decide` precedence: allowlisted domain that is also in the blocklist → `.allow`
  (allow-checked-first is the whole feature); all-abstain → `.pass`.

---

Reference: this abstraction is the seam P3.4 and the allow/regex follow-ons plug into;
the runtime-vtable alternative in §8 mirrors the upstream-transport interface sketched in
[upstream-design.md](upstream-design.md).
