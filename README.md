# Vortex

A DNS forwarder with blocklist filtering, written in Zig 0.16 on the new `std.Io`
async runtime. Point a resolver at it and ad/tracker domains come back NXDOMAIN;
everything else is forwarded upstream.

**Status: works, but it is a learning project, not a product.** The query path is
complete and tested; the operational surface around it (config reload, metrics,
rate limiting, service units) largely is not. See
[Where it actually stands](#where-it-actually-stands) before deploying it anywhere.

---

## Quick start

Requires **Zig 0.16.0** (the `std.Io` APIs used here do not exist in 0.15 and are
not stable across versions).

```sh
git clone <your-repo-url> && cd vortex
zig build

cp .env.example .env      # optional — it runs on defaults with no .env at all
./zig-out/bin/vortex
```

By default it listens on `127.0.0.1:5354` and forwards to `192.168.1.1:53`.

```sh
# forwarded
dig @127.0.0.1 -p 5354 example.com A +short

# blocked — NXDOMAIN with a cacheable SOA in the authority section
dig @127.0.0.1 -p 5354 doubleclick.net A
```

```
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 55996
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0

;; AUTHORITY SECTION:
doubleclick.net.  3600  IN  SOA  . . 1 3600 600 86400 3600
```

Run the tests with `zig build test --summary all`.

## Configuration

Resolved once at startup from three sources, **later wins**:

```
built-in defaults  <  .env file  <  process environment
```

So `VORTEX_LISTEN_PORT=5355 ./vortex` overrides the file without editing it.
Every knob is documented in [`.env.example`](.env.example); copy it to `.env`
and edit. Running with no `.env` at all is a supported mode.

| Variable | Default |
|---|---|
| `VORTEX_LISTEN_HOST` / `VORTEX_LISTEN_PORT` | `127.0.0.1` / `5354` |
| `VORTEX_UPSTREAM_HOST` / `VORTEX_UPSTREAM_PORT` | `192.168.1.1` / `53` |
| `VORTEX_UPSTREAM_BIND_HOST` / `VORTEX_UPSTREAM_BIND_PORT` | `0.0.0.0` / `0` (ephemeral) |
| `VORTEX_BLOCKLIST_SOURCE` | StevenBlack `hosts` (URL or local path) |
| `VORTEX_SUFFIX_BLOCKLIST_SOURCE` | oisd `small.oisd.nl/domainswild2` (URL or local path) |
| `VORTEX_CACHE_MAX_ENTRIES` | `10000` (`0` disables the cache) |
| `VORTEX_ENV_FILE` | `.env` |

A missing `.env` is fine; a file named explicitly via `VORTEX_ENV_FILE` that
doesn't exist is fatal, and so is a malformed port. Silently listening on the
default port because someone typed `535e` is the config bug that costs an hour.

Either blocklist may be a **URL or a local file path**, decided by the value's
scheme: `http://` and `https://` are fetched, `file://` is read from disk with
the scheme stripped, and anything else is read as a path. Pointing both at the
checked-in fixtures starts the server in milliseconds instead of the ~25 s two
HTTP fetches cost, and without touching the network at all:

```
VORTEX_BLOCKLIST_SOURCE=./testdata/blocklist.hosts \
VORTEX_SUFFIX_BLOCKLIST_SOURCE=./testdata/suffix.txt \
zig build run
```

If you change the suffix list, it must be a **bare-domain** list —
`domainswild2`, not `domainswild`. The parser does not strip a leading `*.`, so
a `*.`-prefixed list loads without any error and then matches nothing. Both
lists are resolved at startup and a failure is currently fatal (P2.2) — a named
file that doesn't exist included, because an operator who named a blocklist
asked for that blocklist.

These two were called `VORTEX_BLOCKLIST_URL` / `VORTEX_SUFFIX_BLOCKLIST_URL`
before they learned to take a path. Setting a stale name is a startup error
naming its replacement rather than a silent fall back to the default list.

## How it works

```
                    ┌──────────────────────────────────────────┐
   client ──UDP──▶  │  ingress loop            (main.zig)      │
                    │    ├─ validateQuery      (header.zig)    │  QR=1 → drop
                    │    ├─ parseQuestion      (question.zig)  │  malformed → drop
                    │    └─ Policy.decide      (policy.zig)    │
                    │         allow → forward                  │
                    │         block → NXDOMAIN + SOA ──────────┼──▶ client
                    │         pass  → forward                  │
                    │                    │                     │
                    │              PendingTable                │
                    │         (random proxy ID, 5s sweep)      │
                    │                    │                     │
                    │              upstream socket ────────────┼──▶ resolver
                    │                                          │
                    │  dispatcher loop ◀───────────────────────┼──── reply
                    │    ├─ demux by proxy ID, verify question │
                    │    ├─ walk RRs   (resource_record.zig)   │
                    │    ├─ store      (cache.zig)             │
                    │    └─ restore client ID ─────────────────┼──▶ client
                    └──────────────────────────────────────────┘

A cache hit never reaches the upstream socket at all: `handleQuery` checks
`cache.zig` **after** the policy verdict — so a refreshed blocklist is never
shadowed by a stale entry — and answers from memory with the client's
transaction ID restored and every TTL aged by how long the entry has been held.
```

One coroutine per query via `std.Io.Group`, plus two long-lived loops (dispatcher
and sweeper). A **single shared upstream socket** is multiplexed by rewriting each
query's transaction ID to a random proxy ID, so replies are demuxed by table
lookup rather than by socket. Every reply is checked against the upstream source
address before it is forwarded on.

Filtering is a three-stage chain — **allowlist → exact blocklist → suffix
blocklist** — with a three-valued verdict (`allow` / `block` / `pass`) so an
allowlist entry can override a block.

**Why the blocklists need no mutex:** they are write-once, read-many with a clean
phase boundary. The lists are fully built before any coroutine spawns, and the
only later access is a pure read. `PendingTable` and the response cache *do* need
one — both are mutated for the whole process lifetime by inserts, removes, and a
sweeper's iterate-and-remove. That is not a formality: `std.process.Init` hands
us a `std.Io.Threaded` whose async limit defaults to `cpu_count - 1`, so handlers
run on a real thread pool and two can be inside the same map at the same instant.
This changes the day blocklist refresh (P2.2) lands: build a fresh set off to the
side and swap the pointer rather than mutating under live readers.

## Where it actually stands

Roughly **57%** of the way to "production-ready home sinkhole," with the caveat
that the expensive-to-reverse architectural decisions are the ones already made.
[`docs/progress.md`](docs/progress.md) has the weighted breakdown and what would
actually move it.

**The query datapath is complete and tested.** Header validation (QR, opcode,
QDCOUNT), QName case normalization, cacheable SOA on blocked answers, replies
verified against the question that provoked them, SERVFAIL on upstream timeout,
and TC=1 rather than silent corruption when a reply overflows the receive buffer.
Every one of those is now asserted end to end against the running binary, not just
against the pure function behind it. `zig build test` runs **143 tests** — 131 unit
tests plus 12 integration cases — under both Debug and ReleaseSafe.

**Responses are cached, with honest TTLs.** The compression → parsing → caching
chain is complete: pointer following (P3.1), the record walk (P3.2), and a
TTL-aware cache (P3.3) keyed on `(qname, qtype, qclass)`. A repeat query is
answered from memory in ~0 ms, and its TTLs are counted down by the entry's age
rather than replayed at full value — so a client is never told 300 seconds
remain on a record held for 250 (RFC 2181 §5.2). Negative answers are cached
per RFC 2308, and OPT is excluded from every TTL computation, since TYPE 41
reuses that field for flags rather than a duration.

> [!WARNING]
> **Do not bind this off localhost yet.** There is no cap on in-flight handlers —
> a UDP flood spawns unbounded coroutines and heap — and no per-client rate
> limiting. The localhost default is load-bearing as a security control, not a dev
> convenience. Since configuration became runtime, removing that guard rail is a
> one-line edit rather than a recompile, so this matters more than it used to.

The gap is everything around the datapath: EDNS0, TCP fallback, graceful
shutdown, metrics, and blocklist refresh with an on-disk cache — today a failed
fetch at startup is fatal. [`docs/next_steps.md`](docs/next_steps.md) is the
full prioritized board.

The testing gap that used to sit here is closed. The 131 unit tests are all over
pure functions, which left `handleQuery`, `dispatcherLoop` and the ingress loop
with no runtime coverage at all — the two functions where this project's last two
real bugs lived. As of 2026-09-12 [`tests/`](tests/) spawns the real binary
against a scratch config and a fake upstream and drives it over UDP: 12 cases,
every one confirmed to fail when the behavior it covers is deliberately broken.

`zig build test` runs both suites (143 tests); `zig build test-integration` runs
just the harness, and `-Dtest-filter=<substr>` narrows it to a single case.

What is *not* covered there is concurrency — every case is one query at a time —
which is the same gap P1.5 names above, and the harness is where a cap on
in-flight handlers would get asserted once one exists.

## Documentation

| Doc | What's in it |
|---|---|
| [next_steps.md](docs/next_steps.md) | The prioritized board: every open item, why it matters, and how it should be shaped |
| [changelog.md](docs/changelog.md) | Dated entries for everything that landed, and why it is shaped that way |
| [progress.md](docs/progress.md) | Completion assessment and what moves the number |
| [dns-message-format.md](docs/dns-message-format.md) | Wire format reference and error table |
| [upstream-design.md](docs/upstream-design.md) | Why the shared-socket + `PendingTable` architecture |
| [async-migration.md](docs/async-migration.md) | `std.Io` async patterns used here |
| [filter-design.md](docs/filter-design.md) | The `Filter`/`Chain` design the policy chain is converging on |
| [memory-review.md](docs/memory-review.md) | Closed record of one memory-bug review; 7 of 9 resolved |

## License

MIT — see [LICENSE](LICENSE).
