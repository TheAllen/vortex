# Upstream Forwarding Under Async

Design notes for migrating to Zig 0.16's `IO.async` and resolving the cross-talk race when multiple client queries are in flight against a shared upstream resolver.

## The race

With the current shared upstream socket and async coroutines:

```
Client A query → coroutine A → sendto(upstream) → recvfrom(upstream) ──┐
Client B query → coroutine B → sendto(upstream) → recvfrom(upstream) ──┤
                                                                       ▼
                            UDP socket queue: [response for B][response for A]
```

`recvfrom` returns whatever packet arrives next — UDP gives you no per-query demultiplexing. Coroutine A might pull B's response off the socket and forward B's QNAME/IP to client A.

There are two distinct failure modes:

1. **Wrong-coroutine delivery.** A reads B's bytes off the socket.
2. **Transaction-id collision between clients.** Two unrelated clients independently pick the same 16-bit query ID. Even with correct routing-by-ID, you can't tell their responses apart.

## Three options

### Option 1: ephemeral upstream socket per query (Ephemeral Socket)

Each query coroutine opens its own UDP socket, sends, recvs *its own* response, closes.

```
coroutine per query:
    sock = posix.socket(...)
    sendto(sock, ...)
    recvfrom(sock, ...)   // only this query's response arrives here
    close(sock)
```

The OS gives each socket a unique ephemeral source port, which demultiplexes responses. Zero shared state. Cost: a syscall pair per query — negligible at home-network scale.

### Option 2: shared upstream socket + dispatcher

One coroutine owns the upstream socket and loops on `recvfrom`. A `HashMap(u16, Channel)` maps transaction-id → the per-query coroutine waiting for it. The dispatcher reads each response, parses the ID, looks up the channel, hands off the bytes.

This is what `unbound`/`dnsmasq` do. Saves syscalls but requires synchronization, timeout handling, and orphan cleanup. Does **not** solve transaction-id collisions on its own — needs Option 3 layered on top.

### Option 3: rewrite transaction IDs at the proxy (Production-grade)

Maintain `proxy_id → (client_id, client_addr)`. On forward: pick a fresh proxy-side ID, rewrite bytes [0..2] of the query, send. On response: look up by proxy ID, rewrite bytes [0..2] back to the client's original ID, send to the right client.

The only safe way to share an upstream socket across clients. Bonus: proxy-controlled IDs are harder to spoof.

## Which is most "elegant"?

**If "elegant" = smallest correct solution that fits the problem:** Option 1. It delegates demultiplexing to the kernel instead of rebuilding it in userspace. Zero shared state, no map, no cleanup, no ID exhaustion.

**If "elegant" = thorough, production-grade, what real systems do:** Option 3. Every serious resolver rewrites IDs because at scale you need spoof resistance, syscall efficiency, and a single connection point to layer caching/rate-limiting on.

**Easy to miss:** Option 1 quietly gets Option 3's *security* benefit for free. The kernel hands each socket a randomized ephemeral source port, so two clients with colliding transaction IDs are still demultiplexed by `(src_port, dst_port, ip)`. Option 1 isn't a worse-but-simpler version of Option 3 — it's a different decomposition that pushes the same job to a layer better suited to do it.

**Verdict for this project:** Option 1. Pick Option 3 only if the project is meant to look like a real resolver.

## Stage separation (recommended regardless of option)

```
┌─────────────────────┐
│ ingress loop        │  recvfrom(client_socket) in a tight loop
│ (one coroutine)     │  → spawn handleQuery(buf, src_addr) and continue
└─────────────────────┘
            │
            ▼
┌─────────────────────┐
│ handleQuery         │  parse header + question
│ (one per query)     │  → blocked? craft response, send, exit
│                     │  → not blocked? forward + await + send
└─────────────────────┘
            │
            ▼
┌─────────────────────┐
│ forwardToUpstream   │  Option 1: own socket, sendto, recvfrom, return bytes
│ (called by handler) │  Option 3: register in dispatcher map, await delivery
└─────────────────────┘
```

The ingress loop should never block on anything but `recvfrom(client_socket)`. Everything else happens in a spawned coroutine so a slow upstream for client A doesn't stall client B.

## LOC estimate for Option 3

Assumes "Variant B": dispatcher sends responses directly to clients based on stored address, so per-query coroutines exit after forwarding. No channel/future needed.

| Component | Approx LOC | Notes |
|---|---|---|
| `PendingQuery` struct | 8-10 | `{ client_id, client_addr, addr_len, expires_at }` |
| `PendingTable` wrapper | 15-20 | HashMap + Mutex + Rng + `init`/`deinit` |
| `allocate(client_id, addr) !u16` | 15-20 | Random ID, retry on collision, abort if full |
| `complete(proxy_id) ?PendingQuery` | 8-10 | Lookup + remove under lock |
| `sweepExpired()` | 10-15 | Walk map, remove past `expires_at` |
| Dispatcher coroutine | 25-35 | Loop on `recvfrom`, parse ID, lookup, rewrite, `sendto` client |
| Sweep coroutine / timer | 10-15 | Periodic `sweepExpired` |
| Forward-path changes in `handleQuery` | +10 / −15 | Allocate proxy ID, rewrite bytes [0..2]. Delete inline `recvfrom`. |
| `main()` wiring | 8-12 | Init table, spawn dispatcher + sweeper |
| Timeout / orphan path | 8-12 | Mostly logging |
| Imports, error sets, helpers | 5-10 | |

**Net total: ~130-150 lines.** With docstrings, defensive logging, and graceful shutdown drain: ~170-200.

### Compared against Option 1

| | Option 1 | Option 3 (Variant B) |
|---|---|---|
| Net new lines | ~20-30 | ~130-150 |
| New files (recommended) | 0 | 1 (`src/upstream.zig`) |
| New shared state | none | hashmap + mutex + rng |
| New coroutines | 0 | 2 (dispatcher, sweeper) |
| New failure modes | socket-open fails (1 query dies) | ID exhaustion, orphaned entries, dispatcher death = total outage |
| Test surface | ~3 cases | ~10 cases |

### Where the cost actually lives

The line count is misleading on its own. Cognitive cost concentrates in three places:

1. **Synchronization on the table.** Every `allocate`/`complete`/`sweep` has to be lock-correct.
2. **Lifetime of the table entry.** Sweep can race with a slow upstream response. Decide: drop late responses or log them.
3. **Dispatcher death.** If the dispatcher panics or returns, every in-flight query hangs forever. Needs a supervisor or `defer` that signals all pending entries.

Those three things are maybe 40 LOC but ~70% of the bugs you'd hit.

### Hidden assumptions

- Zig 0.16's `IO.async` provides a usable mutex/lock equivalent for coroutine context. If you have to roll your own async-aware lock, add 30-50 LOC.
- A sleep/timer primitive is available for the sweeper. If not, add 10-20 LOC.
- Tests not included. A reasonable test pass (allocate/complete/expire/exhaustion) adds ~80 LOC.
- Logging/metrics not included. Counters for in-flight, expired, exhausted, late-arriving add ~30 LOC.

A fully-finished Option 3 with tests and observability is realistically a **250-300 LOC delta**, vs **30-50 LOC** for Option 1 — roughly a **6-8× cost** for the same functional outcome on a home network.

### Option 1 vs Option 3
A home network with all devices on it — laptops, phones, smart TVs, smart-home gear — peaks at maybe 50-100 queries per second during heavy use, more like 1-10 qps average. Option 1 handles that without noticing. Linux/BSD chew through 10,000+ ephemeral ports per second routinely. The threshold where Option 1 actually starts hurting is closer to thousands of qps, multi-tenant security requirements, or port-exhaustion territory. A home network of any plausible size doesn't approach it.

So if your reasoning is "more devices means I need Option 3", that's not quite right — Option 1 would still serve you fine.

That said, there are legitimate reasons to pick Option 3 anyway:

1. You want to learn how a real resolver works. This is the best one. Option 3 forces you to deal with ID allocation, dispatcher coroutines, table lifetimes, and supervisor patterns — all transferable concepts. Option 1 mostly teaches you "the kernel is good at sockets."
2. You want to add caching, rate limiting, or per-upstream pooling later. These compose more naturally on a single shared upstream socket than on per-query ephemeral ones.
3. Spoof resistance via proxy-controlled IDs (though you'd want both proxy IDs and port randomization for full RFC 5452 compliance — Option 1 gives you the latter, Option 3 gives you the former, real resolvers do both).
4. You like the project as a serious build rather than a minimum viable thing.
Any of those is a fine reason to commit. "I have more devices" alone isn't.

If you're in for the right reasons, the rough plan would be:

1. Stage separation first (ingress loop / per-query handler / forwardToUpstream) on the current sync code — that refactor is valid for any option and gets the codebase into the right shape.
2. Migrate to 0.16 + IO.async, port the stages to coroutines.
3. Build PendingTable + dispatcher coroutine + sweeper.
4. Wire ID rewriting on send/recv.
5. Add tests for the table (collision, expiry, exhaustion, late-arrival-after-sweep).
6. Add the supervisor/dispatcher-death path last, since it's only meaningful once the rest works.

## Option 3: stage flow in detail

Expanding the "Stage separation" sketch above into the full Option 3 architecture, including where upstream responses go (and where they don't).

### Do upstream responses go through the ingress loop?

**No.** The ingress loop's `client_sock.receive(io, &buf)` listens on the **client-facing port** (5354). Upstream responses arrive on the **upstream-facing socket** bound to an ephemeral port. They're literally two different file descriptors. There is no path that could route an upstream response through the ingress loop.

But you might be asking a deeper question: *should the architecture treat client queries and upstream responses uniformly — one ingress, one loop, one demux?* The answer is still no, and the reason is informative.

### Why client and upstream live on separate loops

| | Client socket | Upstream socket |
|---|---|---|
| Bound to | `127.0.0.1:5354` (well-known) | `0.0.0.0:<ephemeral>` (kernel-picked) |
| Sender semantics | unknown clients, addresses we've never seen | exactly one peer (`192.168.1.1:53`) |
| Demux key | new connection / new query | proxy_id in payload bytes [0..2] |
| Lifetime | server uptime | server uptime (shared in Option 3) |
| Action on receive | spawn handler, register pending entry | look up entry, send to stored client_addr |

These are different jobs. Forcing them into one loop means an `if/else` on which socket the packet came from, which buys you nothing and clutters the demux logic. **Two loops, two responsibilities, both running concurrently as separate coroutines.**

### The Option 3 stage diagram

```
                                  ┌────────────────────────┐
                                  │  PendingTable          │
                                  │  proxy_id → {          │
                                  │    client_id,          │
                                  │    client_addr,        │
                                  │    expires_at          │
                                  │  }                     │
                                  └────┬───────────────┬───┘
                                       │ allocate()    │ complete()
                                       │               │
┌─────────────────────┐                │               │
│ ingress loop        │                │               │
│ (1 coroutine)       │                ▼               │
│                     │      ┌─────────────────────┐   │
│ client_sock         │      │ handleQuery         │   │
│   .receive(io)      │ ────►│ (1 per query,       │   │
│ owned = dupe(data)  │ spawn│  short-lived)       │   │
│ io.async(           │      │                     │   │
│   handleQuery,      │      │ blocked? craft +    │   │
│   {ctx, from,       │      │   send to client    │   │
│    owned})          │      │   exit              │   │
│                     │      │                     │   │
│ (loop forever,      │      │ forward?            │   │
│  never blocks       │      │   read client_id    │   │
│  on upstream)       │      │   proxy_id =        │   │
└─────────────────────┘      │     pending         │   │
                             │     .allocate(...)  │───┘
                             │   rewrite [0..2]    │
                             │   up_sock.send(io)  │
                             │   EXIT              │
                             └─────────┬───────────┘
                                       │
                                       │ packet on the wire
                                       │ (kernel network stack)
                                       ▼
                             ┌─────────────────────┐
                             │ upstream resolver   │
                             │ 192.168.1.1:53      │
                             └─────────┬───────────┘
                                       │ response
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────┐
│ dispatcher coroutine (long-lived, 1 total)              │
│                                                          │
│ loop:                                                    │
│   msg = up_sock.receive(io, &buf)                        │
│   proxy_id = readInt(msg.data[0..2], .big)               │
│   entry = pending.complete(proxy_id) orelse continue ────┼──► drop (orphan / late)
│   writeInt(msg.data[0..2], entry.client_id, .big)        │
│   client_sock.send(io, entry.client_addr, msg.data) ─────┼──► back to original client
└──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ sweeper coroutine (long-lived, 1 total)                  │
│                                                          │
│ loop:                                                    │
│   io.sleep(1s)                                           │
│   pending.sweepExpired()  ──► remove entries past timeout │
└──────────────────────────────────────────────────────────┘
```

### The lifecycle of one forwarded query

Walking the timeline so the role of each stage is unambiguous:

```
T=0ms    Client sends query (txid=0xAB12) to 127.0.0.1:5354
T=0      Ingress: client_sock.receive returns {from=client, data=...}
T=0      Ingress: gpa.dupe(data) → owned slice
T=0      Ingress: io.async(handleQuery, {ctx, client_addr, owned})
T=0      Ingress: loops back, calls receive again (suspends)

T=0+ε    handleQuery starts running (own coroutine)
T=0+ε    parse qname, not blocked
T=0+ε    client_id = 0xAB12 (read from owned[0..2])
T=0+ε    proxy_id = pending.allocate(0xAB12, client_addr, ttl=5s)
                  → returns 0x73F1, table now has {0x73F1 → {0xAB12, client_addr, expires}}
T=0+ε    rewrite owned[0..2] = 0x73F1
T=0+ε    up_sock.send(io, upstream_addr, owned) → suspends briefly
T=0+δ    send completes
T=0+δ    handleQuery returns, coroutine ends, owned slice freed by defer

T=0..50ms  (handler is gone. The pending table is the only memory of this query.)

T=50ms   Upstream replies on the wire
T=50     Dispatcher's up_sock.receive resumes, returns {from=upstream, data=resp}
T=50     proxy_id = readInt(resp.data[0..2]) = 0x73F1
T=50     entry = pending.complete(0x73F1) → returns {0xAB12, client_addr}, removes from map
T=50     writeInt(resp.data[0..2], 0xAB12)  ← restore client's original ID
T=50     client_sock.send(io, client_addr, resp.data) → suspends
T=50+ε   Send completes; client gets a response with its own txid
T=50+ε   Dispatcher loops back to receive
```

The handler is **gone** by T=δ. Only the pending table entry persists. The dispatcher resurrects the routing information when the response comes back. That decoupling is the whole point — handlers are short-lived, the table is the memory, the dispatcher is the rendezvous.

### Why this layering matters

1. **Ingress never blocks on upstream.** A slow or dead upstream makes the dispatcher's `receive` slow, but the ingress loop keeps accepting client queries and spawning handlers (which return immediately after `up_sock.send`).
2. **Handlers are O(short).** They allocate, rewrite, send, exit. No wait state. This bounds memory: even a flood of queries doesn't keep thousands of handler coroutines alive — only their pending entries.
3. **The dispatcher is the *only* code that touches the upstream socket's recv side.** No race over who reads the next packet. Single owner.
4. **Demux is explicit.** The proxy_id is the only routing key. No socket lookup, no address matching, no per-coroutine channels.
5. **Failure isolation per stage.**
   - Ingress dies → server is dead (acceptable, this is the entry point).
   - Handler dies → that query is dropped, table entry expires via sweeper.
   - Dispatcher dies → all in-flight queries hang until expiry. **Add a supervisor.**
   - Sweeper dies → table grows unbounded over hours. Lower priority but worth a supervisor too.

### What goes through the ingress loop, restated

| Packet | Path |
|---|---|
| Client → 5354 (query) | ingress → handleQuery |
| Upstream → ephemeral port (response) | dispatcher only |
| Client → 5354 (response) | dispatcher emits this, ingress never sees it |

Three traffic flows, two receive coroutines, one send-to-client point (the dispatcher for forwards, the handler for blocked replies).

### Optional refinement: a single send-to-client seam

If you want one place for everything that gets sent back to clients (useful for adding metrics, rate limiting, or testing), introduce a small helper:

```zig
fn sendToClient(io: std.Io, sock: *const Socket, addr: IpAddress, data: []const u8) void {
    // central place to add: latency timing, byte counters, error logging
    sock.send(io, addr, data) catch |err| {
        std.log.warn("client send: {s}", .{@errorName(err)});
    };
}
```

Both `handleQuery` (blocked path) and `dispatcher` (forward path) call this. It's not a coroutine — just a function — but it keeps "what we send to clients" as one identifiable seam.

### Do the two receive loops live in the same `while (true)`?

**No — they're two separate coroutines, each with its own `while (true)` loop**, running concurrently. (Plus the sweeper, which is a third.)

#### What "same loop" would mean (and why it's wrong)

If both `receive` calls were in one loop, you'd have to choose which to call first:

```zig
while (true) {
    const client_msg = try client_sock.receive(io, &buf1); // BLOCKS here
    // ...never gets to the upstream side until a client query arrives
    const up_msg = try up_sock.receive(io, &buf2);         // BLOCKS here
    // ...never gets back to client side until upstream replies
}
```

Even though `receive` is cooperative (suspends on the runtime, doesn't pin a thread), the **code path** is sequential. Client queries can only be received between upstream responses, and vice versa. That's not concurrency, that's interleaving with bad ratios.

#### What you actually do

Two independent coroutines, spawned from `main`, each spinning on its own socket:

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    // ... bind sockets, init pending table, build ctx ...

    _ = io.async(dispatcherLoop, .{ io, &ctx });          // coroutine #2
    _ = io.async(sweeperLoop, .{ io, &ctx.pending });     // coroutine #3

    // coroutine #1 — the ingress loop runs in main's frame
    while (true) {
        var buf: [512]u8 = undefined;
        const msg = try ctx.client_sock.receive(io, &buf);
        const owned = try gpa.dupe(u8, msg.data);
        _ = io.async(handleQuery, .{ io, gpa, &ctx, msg.from, owned });
    }
}

fn dispatcherLoop(io: std.Io, ctx: *Context) void {
    var buf: [512]u8 = undefined;
    while (true) {                                        // its OWN loop
        const msg = ctx.up_sock.receive(io, &buf) catch continue;
        if (msg.data.len < 12) continue;

        const proxy_id = std.mem.readInt(u16, msg.data[0..2], .big);
        const entry = ctx.pending.complete(proxy_id) orelse continue;

        std.mem.writeInt(u16, msg.data[0..2], entry.client_id, .big);
        ctx.client_sock.send(io, entry.client_addr, msg.data) catch {};
    }
}

fn sweeperLoop(io: std.Io, pending: *PendingTable) void {
    while (true) {                                        // its OWN loop
        io.sleep(1 * std.time.ns_per_s) catch return;
        pending.sweepExpired();
    }
}
```

Three concurrent loops:
- **Loop 1** in `main`: suspends on `client_sock.receive`. Wakes only when a client packet arrives.
- **Loop 2** in `dispatcherLoop`: suspends on `up_sock.receive`. Wakes only when upstream replies.
- **Loop 3** in `sweeperLoop`: suspends on `io.sleep`. Wakes once per second.

The runtime multiplexes their suspensions. When client traffic and upstream traffic both arrive, both loops make progress in interleaved fashion — that's the actual concurrency.

#### Visualizing it

```
main()                          dispatcherLoop                    sweeperLoop
─────                          ──────────────                    ───────────
while (true):                  while (true):                     while (true):
  receive(client_sock) ⏸         receive(up_sock) ⏸                sleep(1s) ⏸
    │                              │                                 │
    │ packet from client            │ packet from upstream            │ 1s elapses
    ▼                              ▼                                 ▼
  spawn handleQuery              pending.complete                  sweepExpired
  loop back                      send to client                    loop back
                                 loop back
```

Three `⏸` suspension points, three loops. They share the `PendingTable` (under its mutex) and the `client_sock` (only the dispatcher and handler send through it; nobody contends on `client_sock.send`).

#### Why separate loops, not one

- **Independent suspension.** Each loop suspends on a different fd. The runtime wakes whichever has data without the other being involved.
- **No head-of-line blocking.** A 50ms upstream RTT doesn't delay accepting the next client query.
- **Single-owner per fd.** Only the dispatcher reads `up_sock`; only the ingress reads `client_sock`. No race over who pulls the next packet.
- **Spawn cost is one-time.** Two `io.async` calls at startup, then they run for the life of the server. The cost lives in the runtime's scheduler, not in your code.

## Summary

- Upstream responses **never** go through the ingress loop. They go through a dedicated **dispatcher coroutine** that owns the upstream socket's recv side.
- The flow is three stages: **ingress** (spawn handlers), **handler** (allocate proxy_id, send upstream, exit), **dispatcher** (receive response, complete table entry, send to original client). Plus a **sweeper** for expired entries.
- The pending table is the bridge between handler (which exits) and dispatcher (which arrives later). The handler is *not* alive when its response comes back — the table is.
- Pairs with [async-migration.md](async-migration.md) Pattern 4 (concrete code) and [next_steps.md](next_steps.md) item #11 (migration plan from the current per-query-socket implementation).
