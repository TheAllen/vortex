# Migrating recv/send to Zig 0.16 `std.Io`

How `recvfrom` / `sendto` reshape under the new `std.Io` async model, applied to this DNS blackhole. Pairs with [upstream-design.md](upstream-design.md) — this doc is the *mechanical* port; that doc is the *architectural* choice.

## Mental model

| Classic POSIX | Zig 0.16 `std.Io` |
|---|---|
| `recvfrom(fd, buf, &src_addr)` | `socket.receive(io, buf) -> IncomingMessage` |
| `sendto(fd, buf, &dst_addr)` | `socket.send(io, dst_addr, buf)` |
| `socket(...)` + `bind(...)` | `addr.bind(io, .{...}) -> Socket` |
| `close(fd)` | `socket.close(io)` |
| `select` / `epoll` / threads | `io.async(fn, args) -> Future` + `future.await(io)` |

**Key shift:** `receive` and `send` are *already* cooperative. They suspend the current coroutine when the kernel isn't ready and resume when it is. You do **not** need `io.async` around them just to "make them async." Reach for `io.async` when you want **another coroutine to make progress in parallel** — per-query handlers, timeout races, dispatcher loops.

### API call-shape note

In Zig 0.16's stdlib, the actual concrete call shapes used by working code in this project are:

| Operation | Call shape |
|---|---|
| Spawn a coroutine | `std.Io.async(io, fn, args_tuple)` |
| Send a UDP packet | `socket.send(io, &addr, data)` (addr by **pointer**) |
| Receive a UDP packet | `socket.receive(io, &buf)` |
| Bind a socket | `local_addr.bind(io, .{ .mode = .dgram, .protocol = .udp })` |
| Allocator from `Init` | `init.gpa` (not `init.allocator`) |

In prose below, `io.async(...)` is used as shorthand. The literal call in code is `std.Io.async(io, ...)`. The address-by-pointer rule on `send` is load-bearing — `socket.send(io, addr, data)` will not compile.

## Anti-pattern: wrapping a single call

```zig
// Don't do this — it allocates a future, defers a cancel, and gains zero concurrency.
var incoming = io.async(recvPacket, .{ io, &socket, buf_slice });
defer _ = incoming.cancel(io) catch {};
const incoming_result = try incoming.await(io);
```

The synchronous-shape call is enough:

```zig
const incoming = try socket.receive(io, &buf);
```

## Two distinct uses of "async"

Before the patterns, get this straight:

1. **`io.async(fn, args)`** — *spawns* a concurrent coroutine. The "fork a worker" primitive.
2. **`socket.send(io, ...)` / `socket.receive(io, ...)`** — already cooperative. Suspend when the kernel isn't ready, resume when it is. Calling them **is not "using async"** — they're plain function calls that happen to yield.

So `io.async` wraps the **coroutine boundary** (per-query handler, dispatcher, timeout race), never individual sends or receives. A reply-to-client `send` is always just `try sock.send(io, addr, data)`.

## Pattern 1: ingress loop

The ingress coroutine has exactly one job: pull packets off the listening socket and hand each one off. It never blocks on anything but `receive`. There are two reasonable shapes.

### Shape A — always spawn (recommended starting point)

Every query goes through `io.async(handleQuery, ...)`, blocked or not. Simplest mental model, one code path.

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const addr = try std.Io.net.IpAddress.parse(LOCALHOST, PORT);
    const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    var buf: [4096]u8 = undefined; // EDNS0-sized; ingress reuses across iterations
    while (true) {
        const msg = try socket.receive(io, &buf);

        // Copy out — ingress overwrites `buf` on the next iteration. Dupe transfers
        // ownership to the spawned handler.
        const owned = try gpa.dupe(u8, msg.data);

        // Spawn and forget. Handler owns `owned` and frees it.
        _ = std.Io.async(io, handleQuery, .{ io, gpa, &socket, msg.from, owned });
    }
}
```

### Shape B — inline blocked, spawn forward

The blocked path is fast (no network wait), so handle it inline and only spawn for forwards.

```zig
var buf: [4096]u8 = undefined;
while (true) {
    const msg = try socket.receive(io, &buf);

    const qname, const q_end = parseQname(msg.data) catch continue;
    if (blocklist.contains(qname)) {
        // Inline. Just call send — it suspends cooperatively if needed.
        const len = craftBlockedResponse(msg.data, q_end);
        try socket.send(io, &msg.from, msg.data[0..len]);
        continue;
    }

    // Forward path needs its own coroutine — upstream recv could take 100ms.
    const owned = try gpa.dupe(u8, msg.data);
    _ = std.Io.async(io, forwardToUpstream, .{ io, gpa, &socket, msg.from, owned });
}
```

> **What `craftBlockedResponse` does** — specified byte-by-byte in [dns-message-format.md](dns-message-format.md) ("Answer section (for blocked responses)"). It rewrites the request into an NXDOMAIN response **in place**, so only the **header** section is modified: flags flipped to `QR=1`, `AA=0`, `TC=0`, `RA=1`, `RCODE=3`, and `ANCOUNT`/`NSCOUNT`/`ARCOUNT` zeroed (`ID` and `QDCOUNT` stay). The **question** section is echoed verbatim per RFC 1035 §4.1.1, and **no answer RRs are added** — the buffer is truncated right after the question, which also drops any client OPT record. It returns the response length; `q_end` is the offset past the question section that the parser returns. No allocation, so nothing to free.

### Picking between them

| | Shape A | Shape B |
|---|---|---|
| Code paths | one | two |
| Spawn cost on blocked queries | one future per query | zero |
| Risk if `send` to client suspends | none — handler is its own coroutine | ingress stalls until kernel drains |
| When to pick | default | only if profiling shows spawn cost matters |

Both rely on fire-and-forget: never `await` the spawned handler from the ingress loop, or you've serialized everything again.

Why fire-and-forget: if you `await` the handler here, the ingress loop is single-threaded again — client B waits for client A's upstream round-trip. The whole point of the async model is to decouple them.

## Pattern 2: per-query handler (Option 1 from upstream-design)

Each handler owns its own ephemeral upstream socket. The kernel handles demultiplexing via the unique source port. No shared state, no dispatcher, no ID rewrite.

Notice every `send`/`receive` is a **plain call**, not wrapped in `io.async`. The handler itself is the coroutine; the calls inside it just suspend.

### For Shape A — combined handler

```zig
fn handleQuery(
    io: std.Io,
    gpa: std.mem.Allocator,
    client_sock: *const std.Io.net.Socket,
    client_addr: std.Io.net.IpAddress,
    query: []u8,
) void {
    defer gpa.free(query);

    if (query.len < 12) return;
    const qname, const q_end = parseQname(query) catch return;

    if (blocklist.contains(qname)) {
        // Header-only rewrite in place (QR=1, RCODE=3, RR counts zeroed);
        // question echoed; no answer RRs. See dns-message-format.md.
        const len = craftBlockedResponse(query, q_end);
        client_sock.send(io, &client_addr, query[0..len]) catch {}; // plain call
        return;
    }

    forwardToUpstream(io, gpa, client_sock, client_addr, query);
}
```

### For Shape B — forward-only handler

When the ingress loop already handles blocked queries inline, the spawned handler only deals with the forward path. **Important:** for an outgoing UDP client, you bind a *local* address (e.g. `0.0.0.0:0` so the kernel picks an ephemeral port). You do **not** bind the upstream's address — that's the *destination* you send to.

```zig
fn forwardToUpstream(
    io: std.Io,
    gpa: std.mem.Allocator,
    client_sock: *const std.Io.net.Socket,
    client_addr: std.Io.net.IpAddress,
    query: []u8,
) void {
    defer gpa.free(query);

    const upstream_addr = std.Io.net.IpAddress.parse(UPSTREAM_HOST, UPSTREAM_PORT)
        catch return;
    // Local bind: 0.0.0.0:0 → kernel picks any iface, ephemeral port.
    const local_addr = std.Io.net.IpAddress.parse("0.0.0.0", 0) catch return;
    const up_sock = local_addr.bind(io, .{ .mode = .dgram, .protocol = .udp })
        catch return;
    defer up_sock.close(io);

    up_sock.send(io, &upstream_addr, query) catch return;         // plain call, suspends

    var up_buf: [4096]u8 = undefined;
    const up_msg = up_sock.receive(io, &up_buf) catch return;     // plain call, suspends

    client_sock.send(io, &client_addr, up_msg.data) catch {};     // plain call, suspends
}
```

Note: handlers return `void`, not `!void`. Fire-and-forget coroutines have nowhere to propagate errors — swallow at the boundary or log.

## Pattern 3: timeout race on upstream

Concrete case where `io.async` does earn its keep. You want to give up on a slow upstream rather than leak coroutines.

```zig
var recv_fut = std.Io.async(io, upstreamReceive, .{ io, &up_sock, &up_buf });
var timer_fut = std.Io.async(io, io.sleep, .{ 2 * std.time.ns_per_s });

// Race them. Exact API for "first to complete" depends on stdlib version —
// could be io.select, a Group, or manual polling. Sketch:
const winner = io.race(.{ &recv_fut, &timer_fut });
switch (winner) {
    .recv => {
        _ = timer_fut.cancel(io) catch {};
        const up_msg = try recv_fut.await(io);
        // ... forward up_msg.data to client
    },
    .timeout => {
        _ = recv_fut.cancel(io) catch {};
        return; // drop the query
    },
}
```

**Important:** verify the exact `select`/`race` primitive in the stdlib you're building against — this part of `std.Io` is the most volatile surface area.

## Pattern 4: dispatcher + pending table (Option 3, production-grade)

Patterns 1–3 implement Option 1 from [upstream-design.md](upstream-design.md): ephemeral socket per query, kernel demultiplexes via source port. Correct, simple, fine for home-network scale.

Pattern 4 implements **Option 3**: one shared upstream socket, proxy-controlled transaction IDs, a dispatcher coroutine that demultiplexes responses back to the right client. This is what `unbound`, `dnsmasq`, and `knot-resolver` do. Pick it if you want spoof resistance, syscall efficiency, and a single seam to add caching/rate-limiting on later — not because home-network scale demands it (it doesn't).

### The four moving parts

```
┌─────────────────────┐
│ ingress loop        │  socket.receive(io, &buf)
│ (1 coroutine)       │  → io.async(handleQuery, ...)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ handleQuery         │  parse → blocked? send + exit
│ (per query)         │         → forward? table.allocate, rewrite ID,
│                     │                    up_sock.send, EXIT (no await)
└─────────────────────┘

┌─────────────────────┐
│ dispatcher          │  loop: up_sock.receive → parse proxy_id
│ (1 coroutine)       │        → table.complete → restore client_id
│                     │        → client_sock.send to entry.client_addr
└─────────────────────┘

┌─────────────────────┐
│ sweeper             │  loop: io.sleep(1s); table.sweepExpired
│ (1 coroutine)       │
└─────────────────────┘
```

Critically: `handleQuery` does **not** await the upstream response. It registers in the pending table and exits. The dispatcher delivers to the client directly. (This is "Variant B" from the design doc — fewer coroutines in flight, no per-query channel/future.)

### PendingTable

```zig
const PendingQuery = struct {
    client_id: u16,
    client_addr: std.Io.net.IpAddress,
    expires_at: i64, // ns since boot, std.time.nanoTimestamp()
};

const PendingTable = struct {
    map: std.AutoHashMap(u16, PendingQuery),
    mutex: std.Thread.Mutex,
    rng: std.Random.DefaultPrng,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, seed: u64) PendingTable {
        return .{
            .map = .init(gpa),
            .mutex = .{},
            .rng = .init(seed),
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *PendingTable) void {
        self.map.deinit();
    }

    /// Pick a fresh proxy ID, retry on collision. Returns error.IdSpaceExhausted
    /// if 65k slots are full (defensive — real workloads never hit this).
    pub fn allocate(
        self: *PendingTable,
        client_id: u16,
        client_addr: std.Io.net.IpAddress,
        timeout_ns: i64,
    ) !u16 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.map.count() >= std.math.maxInt(u16)) return error.IdSpaceExhausted;

        var attempts: u32 = 0;
        while (attempts < 16) : (attempts += 1) {
            const proxy_id = self.rng.random().int(u16);
            const gop = try self.map.getOrPut(proxy_id);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .client_id = client_id,
                    .client_addr = client_addr,
                    .expires_at = std.time.nanoTimestamp() + timeout_ns,
                };
                return proxy_id;
            }
        }
        // Rare: keep scanning linearly.
        var i: u32 = 0;
        while (i < std.math.maxInt(u16)) : (i += 1) {
            const proxy_id: u16 = @truncate(self.rng.random().int(u16) +% i);
            const gop = try self.map.getOrPut(proxy_id);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .client_id = client_id,
                    .client_addr = client_addr,
                    .expires_at = std.time.nanoTimestamp() + timeout_ns,
                };
                return proxy_id;
            }
        }
        return error.IdSpaceExhausted;
    }

    pub fn complete(self: *PendingTable, proxy_id: u16) ?PendingQuery {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.fetchRemove(proxy_id)) |kv| return kv.value;
        return null;
    }

    pub fn sweepExpired(self: *PendingTable) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now = std.time.nanoTimestamp();
        var it = self.map.iterator();
        var dead: std.BoundedArray(u16, 64) = .{};
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at <= now) {
                dead.append(entry.key_ptr.*) catch break; // batch in 64s
            }
        }
        for (dead.constSlice()) |id| _ = self.map.remove(id);
    }
};
```

### handleQuery (Option 3 forward path)

```zig
fn handleQuery(
    io: std.Io,
    gpa: std.mem.Allocator,
    ctx: *Context, // holds client_sock, up_sock, pending, blocklist
    client_addr: std.Io.net.IpAddress,
    query: []u8,
) void {
    defer gpa.free(query);

    if (query.len < 12) return;
    const qname, const q_end = parseQname(query) catch return;

    if (ctx.blocklist.contains(qname)) {
        // Header-only rewrite in place (QR=1, RCODE=3, RR counts zeroed);
        // question echoed; no answer RRs. See dns-message-format.md.
        const len = craftBlockedResponse(query, q_end);
        ctx.client_sock.send(io, &client_addr, query[0..len]) catch {};
        return;
    }

    // Forward path: rewrite ID, register, send. Do NOT await response here —
    // the dispatcher will deliver it.
    const client_id = std.mem.readInt(u16, query[0..2], .big);
    const proxy_id = ctx.pending.allocate(client_id, client_addr, 5 * std.time.ns_per_s)
        catch return;

    std.mem.writeInt(u16, query[0..2], proxy_id, .big);
    ctx.up_sock.send(io, &ctx.upstream_addr, query) catch {
        // Send failed — reclaim the slot so we don't leak it until sweep.
        _ = ctx.pending.complete(proxy_id);
        return;
    };
    // handleQuery exits here. Dispatcher takes over.
}
```

### Dispatcher coroutine

```zig
fn dispatcher(io: std.Io, ctx: *Context) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const msg = ctx.up_sock.receive(io, &buf) catch |err| {
            // Log and continue — don't let one bad packet kill the dispatcher.
            std.log.warn("dispatcher receive: {s}", .{@errorName(err)});
            continue;
        };
        if (msg.data.len < 12) continue;

        const proxy_id = std.mem.readInt(u16, msg.data[0..2], .big);
        const entry = ctx.pending.complete(proxy_id) orelse {
            // Late or spoofed — sweep already evicted it, or it was never ours.
            std.log.debug("dispatcher: orphan response id={x}", .{proxy_id});
            continue;
        };

        // Restore client's original transaction ID.
        std.mem.writeInt(u16, msg.data[0..2], entry.client_id, .big);
        ctx.client_sock.send(io, &entry.client_addr, msg.data) catch |err| {
            std.log.warn("dispatcher client send: {s}", .{@errorName(err)});
        };
    }
}
```

### Sweeper coroutine

```zig
fn sweeper(io: std.Io, pending: *PendingTable) void {
    while (true) {
        io.sleep(1 * std.time.ns_per_s) catch return;
        pending.sweepExpired();
    }
}
```

### Wiring in `main`

```zig
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    const client_addr = try std.Io.net.IpAddress.parse(LOCALHOST, PORT);
    const client_sock = try client_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer client_sock.close(io);

    const upstream_addr = try std.Io.net.IpAddress.parse(UPSTREAM_HOST, UPSTREAM_PORT);
    // Bind on a wildcard local addr; kernel picks ephemeral port. Shared for all queries.
    const up_local = try std.Io.net.IpAddress.parse("0.0.0.0", 0);
    const up_sock = try up_local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer up_sock.close(io);

    var pending: PendingTable = .init(gpa, @intCast(std.time.nanoTimestamp()));
    defer pending.deinit();

    var ctx: Context = .{
        .client_sock = &client_sock,
        .up_sock = &up_sock,
        .upstream_addr = upstream_addr,
        .pending = &pending,
        .blocklist = &blocklist,
    };

    _ = std.Io.async(io, dispatcher, .{ io, &ctx });
    _ = std.Io.async(io, sweeper, .{ io, &pending });

    var buf: [4096]u8 = undefined;
    while (true) {
        const msg = try client_sock.receive(io, &buf);
        const owned = try gpa.dupe(u8, msg.data);
        _ = std.Io.async(io, handleQuery, .{ io, gpa, &ctx, msg.from, owned });
    }
}
```

### Where the bugs hide

Per the design doc's warning, ~70% of bugs concentrate in three places:

1. **Lock correctness** on `allocate` / `complete` / `sweep`. The mutex above covers it because allocate-then-write happens in one critical section.
2. **Sweep racing a slow response.** A response arrives *after* sweep evicted the entry → dispatcher's `complete` returns null → drop. That's the right behavior; just log it as `orphan response`.
3. **Dispatcher death.** If `dispatcher` panics or returns, every future query hangs forever. Add a supervisor coroutine that restarts it, or wrap the loop body in a catch-all and never return.

### What's still missing for *true* production-grade

- **Caching** layer in front of the forward path (the whole reason Option 3 pays off).
- **Rate limiting** per client_addr.
- **EDNS0** handling (proxies generally need to preserve OPT records).
- **Multiple upstreams** with health checking and fallback.
- **Metrics** (in-flight gauge, expired counter, orphan counter, latency histogram).
- **Graceful shutdown** that drains pending entries instead of dropping them.

Pattern 4 gets you the *architecture* a production resolver uses. The list above is what you'd layer on top.

## Pattern 5: cancellation lifetime

`io.async` returns a `Future` that must be either `await`ed or `cancel`ed before its frame goes out of scope. For fire-and-forget handlers, the runtime owns the lifetime — there's no `Future` you have to clean up because you discarded it (`_ = io.async(...)`). For futures you keep, the rule is:

```zig
var fut = std.Io.async(io, work, .{ io });
defer _ = fut.cancel(io) catch {}; // belt-and-braces; no-op if already awaited

const result = try fut.await(io);
```

## Migration checklist for `src/main.zig`

> **Status as of current code:** Steps 1–8 are **complete**. The code is on Option 1 with Shape A. Steps 9 (timeout) and 10 (Option 3) are remaining work — see [next_steps.md](next_steps.md) item #11 for the Option 3 migration plan.

1. ✅ **Remove the `recvPacket` wrapper.** Inlined.
2. ✅ **Drop the `io.async` + `await` around receive.** Direct `try socket.receive(io, &buf)`.
3. ✅ **Remove the `break;` from the ingress loop.** Runs forever.
4. ✅ **Pick a shape.** Shape A in use — every query spawns `handleQuery`.
5. ✅ **Extract `handleQuery`** taking `(io, gpa, socket, upstream_addr, client_addr, query)` ([main.zig:39-46](../src/main.zig#L39-L46)).
6. ✅ **`gpa.dupe` before spawning** ([main.zig:103](../src/main.zig#L103)).
7. ✅ **Fire-and-forget spawn** via `_ = std.Io.async(io, handleQuery, .{...})` ([main.zig:104-111](../src/main.zig#L104-L111)).
8. ✅ **Per-query upstream socket** bound on `0.0.0.0:0`, sends + receives directly, no nested `io.async` ([main.zig:52-80](../src/main.zig#L52-L80)).
9. ⏳ **Add timeout** (Pattern 3) — drop slow upstream queries instead of leaking coroutines.
10. ⏳ **(Optional, Option 3)** Replace the per-query upstream socket with a shared socket + `PendingTable` + dispatcher + sweeper (Pattern 4). Documented as a future-exploration migration in [next_steps.md](next_steps.md) item #11.

## End-state shape

### Option 1 (Patterns 1–3)

```
main()
 └─ socket.receive(io, buf)      ← suspends cooperatively
     └─ io.async(handleQuery)    ← spawn, don't await
         ├─ up_sock.send(io)     ← suspends
         ├─ up_sock.receive(io)  ← suspends (or races a timeout)
         └─ client_sock.send(io) ← suspends
```

Three suspension points per query, one spawn per query, zero shared mutable state. The whole point of Option 1 under the new IO model.

### Option 3 (Pattern 4)

```
main()
 ├─ io.async(dispatcher)         ← long-lived, owns up_sock recv loop
 ├─ io.async(sweeper)            ← long-lived, evicts expired entries
 └─ loop:
     client_sock.receive(io)     ← suspends
     └─ io.async(handleQuery)    ← spawn, exits after registering+sending
                                    (does NOT await response)

dispatcher:
     up_sock.receive(io)         ← suspends
     pending.complete(proxy_id)
     client_sock.send(io)        ← suspends
```

Two long-lived coroutines (dispatcher, sweeper) plus one short-lived coroutine per query. Shared state: the `PendingTable`. The architecture real resolvers use — and roughly 6–8× the code of Option 1 for a home-network workload that doesn't need it.
