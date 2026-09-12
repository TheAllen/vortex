//! Runs a real `vortex` process and gives a test three handles on it: a client
//! socket that queries it, a fake upstream socket it forwards to, and the
//! child's captured stderr.
//!
//! ## Why a child process rather than calling into `src/`
//!
//! What P2.5 exists to cover is the socket plumbing — the ingress loop's
//! receive/dupe/spawn, `handleQuery`'s sends, `dispatcherLoop`'s demux. None of
//! that can be reached by importing a function, because none of it *is* a
//! function over bytes; the parts that were have already been extracted and
//! unit-tested. So the harness talks to the binary the same way a stub resolver
//! does, and asserts on what comes back.
//!
//! ## Why it is cheap now
//!
//! Startup used to block on two HTTP fetches (~25 s). Since the local-file
//! blocklist source landed, `Instance.start` points the child at the fixtures in
//! `testdata/` and startup is milliseconds — which is what makes one instance
//! per case affordable, and one instance per case is what keeps the cache and
//! the pending table from leaking state between them.
//!
//! ## Hermeticity
//!
//! The child gets an environment containing exactly one variable,
//! `VORTEX_ENV_FILE`, pointing at a scratch file this harness writes. It does
//! **not** inherit the developer's environment, and it never reads the repo's
//! own `.env`. A `VORTEX_*` variable exported in the shell therefore cannot
//! change what these tests exercise.

const std = @import("std");
const build_options = @import("build_options");

const wire = @import("wire.zig");

const testing = std.testing;
const Io = std.Io;

/// How long a case waits for a datagram that should already be on its way.
/// Generous for loopback — this is a "something is wrong" bound, not a timing
/// assertion. The one case that *is* about timing states its own.
pub const default_timeout_ms = 2_000;

/// Ceiling on how long `start` waits for the child to bind and load its
/// blocklists. Local-file fixtures make the real figure single-digit
/// milliseconds; this only has to beat a loaded CI runner.
const ready_timeout_ms = 10_000;

/// How often the readiness probe is repeated while waiting.
const probe_interval_ms = 20;

/// Verbosity the child runs at.
///
/// `warn` rather than `debug` on purpose: the child's stderr is a pipe that
/// nothing drains until teardown, so a case that logged per-query at debug
/// could in principle fill the pipe buffer and block the process it is
/// testing. Raise this by hand when diagnosing a failure — the captured output
/// is printed on every failed assertion — and put it back.
const child_log_level = "warn";

pub const Options = struct {
    /// Entries the response cache may hold. 0 disables it, which is what every
    /// case that is not *about* the cache wants: a cached reply would otherwise
    /// make a second identical query skip the upstream and quietly invalidate
    /// the assertion.
    cache_max_entries: usize = 0,
};

pub const Instance = struct {
    io: Io,
    gpa: std.mem.Allocator,

    child: std.process.Child,
    /// Everything the child wrote to stderr, read at `deinit`. Empty until then.
    child_stderr: std.ArrayList(u8),

    /// The socket a case queries Vortex from. Bound to an ephemeral port, so
    /// replies come back here and nowhere else.
    client: Io.net.Socket,
    /// Where Vortex thinks its upstream resolver is. A case owns both ends of
    /// this: nothing answers unless the case answers.
    upstream: Io.net.Socket,

    /// Vortex's listening address — where `sendQuery` sends.
    listen_addr: Io.net.IpAddress,

    tmp: testing.TmpDir,

    /// Spawns a Vortex configured against the checked-in blocklist fixtures and
    /// a fake upstream this harness owns, then waits until it answers.
    pub fn start(io: Io, gpa: std.mem.Allocator, opts: Options) !Instance {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        // Bound before the child is spawned, so its port is known and settled
        // by the time the child is told to forward there. Port 0 means the OS
        // picks; `Socket.address` carries what it picked.
        const upstream_bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const upstream = try upstream_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer upstream.close(io);

        const client_bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const client = try client_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer client.close(io);

        // Vortex's own listen port cannot be discovered the same way — it binds
        // it itself, and does not report the resolved port anywhere a test
        // could read. So the port is picked here, by binding and immediately
        // releasing, and handed over in the config. That is a race in
        // principle; in practice the kernel does not hand the same ephemeral
        // port out twice in the microseconds before the child claims it, and a
        // loss shows up as a clean "child exited" rather than a wrong answer.
        const listen_port = try reserveEphemeralPort(io);
        const listen_addr: Io.net.IpAddress = .{ .ip4 = .loopback(listen_port) };

        // Absolute, so the child's cwd is irrelevant — and so is the build
        // runner's, since these paths come from `b.path` via build options.
        const env_path = try writeEnvFile(io, gpa, &tmp, .{
            .listen_port = listen_port,
            .upstream_port = upstream.address.getPort(),
            .cache_max_entries = opts.cache_max_entries,
        });
        defer gpa.free(env_path);

        var environ: std.process.Environ.Map = .init(gpa);
        defer environ.deinit();
        try environ.put("VORTEX_ENV_FILE", env_path);

        var child = try std.process.spawn(io, .{
            .argv = &.{build_options.vortex_exe},
            .environ_map = &environ,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .pipe,
        });
        errdefer child.kill(io);

        var instance: Instance = .{
            .io = io,
            .gpa = gpa,
            .child = child,
            .child_stderr = .empty,
            .client = client,
            .upstream = upstream,
            .listen_addr = listen_addr,
            .tmp = tmp,
        };

        try instance.waitUntilReady();
        return instance;
    }

    pub fn deinit(self: *Instance) void {
        self.stopChild();
        self.client.close(self.io);
        self.upstream.close(self.io);
        self.child_stderr.deinit(self.gpa);
        self.tmp.cleanup();
        self.* = undefined;
    }

    // ── Talking to Vortex ─────────────────────────────────────────────────

    /// Sends `msg` to Vortex's listening socket, as a client would.
    pub fn sendQuery(self: *Instance, msg: []const u8) !void {
        try self.client.send(self.io, &self.listen_addr, msg);
    }

    /// Waits for Vortex to reply to the client, up to `timeout_ms`.
    pub fn recvClient(self: *Instance, buf: []u8, timeout_ms: u64) ![]u8 {
        const msg = try self.client.receiveTimeout(self.io, buf, durationTimeout(timeout_ms));
        return msg.data;
    }

    /// Waits for Vortex to forward a query to the fake upstream, up to
    /// `timeout_ms`. The returned `Forwarded` carries the address to answer
    /// from — which must be the address Vortex sent to, or the dispatcher's
    /// source check discards the reply.
    pub fn recvUpstream(self: *Instance, buf: []u8, timeout_ms: u64) !Forwarded {
        const msg = try self.upstream.receiveTimeout(self.io, buf, durationTimeout(timeout_ms));
        return .{ .data = msg.data, .from = msg.from };
    }

    /// Asserts that nothing reaches the fake upstream within `timeout_ms`.
    /// This is the assertion that distinguishes a cache hit from a fast miss,
    /// and a shed datagram from a forwarded one.
    pub fn expectNoUpstreamQuery(self: *Instance, timeout_ms: u64) !void {
        var buf: [wire.max_message]u8 = undefined;
        const got = self.recvUpstream(&buf, timeout_ms) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        std.debug.print(
            "expected no upstream query, got {d} bytes\n",
            .{got.data.len},
        );
        return error.UnexpectedUpstreamQuery;
    }

    /// Asserts that Vortex sends the client nothing within `timeout_ms`.
    pub fn expectNoClientReply(self: *Instance, timeout_ms: u64) !void {
        var buf: [wire.max_message]u8 = undefined;
        const got = self.recvClient(&buf, timeout_ms) catch |err| switch (err) {
            error.Timeout => return,
            else => return err,
        };
        std.debug.print("expected no reply, got {d} bytes\n", .{got.len});
        return error.UnexpectedClientReply;
    }

    /// Answers a forwarded query from the address it was sent to.
    pub fn sendUpstreamReply(self: *Instance, to: *const Io.net.IpAddress, msg: []const u8) !void {
        try self.upstream.send(self.io, to, msg);
    }

    pub const Forwarded = struct {
        data: []u8,
        from: Io.net.IpAddress,
    };

    // ── Diagnostics ───────────────────────────────────────────────────────

    /// Prints whatever the child logged. Call this when an assertion fails:
    /// the child's own warnings usually name the cause directly, and they are
    /// otherwise invisible because its stderr is a pipe.
    pub fn reportChildLog(self: *Instance) void {
        self.stopChild();
        if (self.child_stderr.items.len == 0) {
            std.debug.print("--- vortex stderr: (empty) ---\n", .{});
            return;
        }
        std.debug.print("--- vortex stderr ---\n{s}\n---------------------\n", .{
            self.child_stderr.items,
        });
    }

    /// Kills the child and collects everything it logged. Idempotent, because
    /// a failing case calls `reportChildLog` from an `errdefer` and `deinit`
    /// from a `defer`, in that order.
    ///
    /// **The ordering here is the whole function, and getting it wrong hangs
    /// the test process.** Reading a pipe whose write end is still open blocks
    /// until EOF, and the child is a server that never exits on its own — so
    /// the drain has to happen *after* the kill. But `Child.kill` closes and
    /// nulls `child.stderr` as part of its cleanup, so draining after it finds
    /// nothing to read. Neither order works on its own; the file has to be
    /// taken out of the child first, then the child killed, then the detached
    /// handle read to the EOF the child's death produced.
    ///
    /// Found by the first mutation run, where every deliberately-broken build
    /// hung for the full five-minute timeout instead of reporting a failure.
    /// A harness whose diagnostic path deadlocks is worse than one with no
    /// diagnostics at all, because the symptom looks like a slow test.
    fn stopChild(self: *Instance) void {
        const stderr_file = self.child.stderr;
        self.child.stderr = null;

        self.child.kill(self.io);

        if (stderr_file) |file| {
            defer file.close(self.io);
            var chunk: [4096]u8 = undefined;
            while (true) {
                const n = file.readStreaming(self.io, &.{&chunk}) catch break;
                if (n == 0) break;
                self.child_stderr.appendSlice(self.gpa, chunk[0..n]) catch break;
            }
        }
    }

    // ── Startup ───────────────────────────────────────────────────────────

    /// Blocks until the child answers a query, or gives up.
    ///
    /// Readiness is probed through the datapath rather than by matching the
    /// "listening=" log line: a log line says a socket is bound, whereas a
    /// reply says the blocklists finished loading and the ingress loop is
    /// actually running — which is the condition every case depends on.
    ///
    /// The probe asks for a name the *fixtures block*, so the answer is
    /// synthesized locally and the fake upstream never sees it. A probe that
    /// had to be forwarded would leave entries in the pending table for the
    /// case to trip over.
    fn waitUntilReady(self: *Instance) !void {
        // Its own socket, so that a late probe reply — one that arrives after
        // readiness was already established — lands here and is discarded with
        // the socket, rather than sitting in the case's client socket waiting
        // to be mistaken for the reply it is asserting on.
        const probe_bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const probe = try probe_bind.bind(self.io, .{ .mode = .dgram, .protocol = .udp });
        defer probe.close(self.io);

        var out: [wire.max_message]u8 = undefined;
        const msg = wire.query(&out, 0x0BEE, ready_probe_name, .{});

        var in: [wire.max_message]u8 = undefined;
        var waited_ms: u64 = 0;
        while (waited_ms < ready_timeout_ms) : (waited_ms += probe_interval_ms) {
            // A datagram sent before the child bound its port is simply lost —
            // there is nothing listening yet, and UDP does not report that. So
            // the probe is *resent* each round rather than sent once and waited
            // on, which is also why this loop cannot be replaced by one long
            // receive.
            probe.send(self.io, &self.listen_addr, msg) catch {};

            const got = probe.receiveTimeout(self.io, &in, durationTimeout(probe_interval_ms)) catch |err| switch (err) {
                error.Timeout => continue,
                // Nothing is bound on that port yet and the kernel bounced the
                // datagram with an ICMP port-unreachable. Expected on the first
                // round or two; a child that never comes up times out below.
                error.PortUnreachable => continue,
                else => return err,
            };
            if (got.data.len >= 12 and wire.id(got.data) == 0x0BEE) return;
        }

        std.debug.print(
            "vortex did not answer on 127.0.0.1:{d} within {d}ms\n",
            .{ self.listen_addr.getPort(), ready_timeout_ms },
        );
        self.reportChildLog();
        return error.VortexDidNotStart;
    }
};

/// Blocked by `testdata/blocklist.hosts`, so the reply is synthesized and no
/// upstream round trip is involved. Under `.test`, which RFC 6761 reserves.
const ready_probe_name = "blocked.test";

const EnvFields = struct {
    listen_port: u16,
    upstream_port: u16,
    cache_max_entries: usize,
};

/// Writes the scratch `.env` and returns its absolute path, caller-owned.
///
/// Sentinel-terminated because that is what `realPathFileAlloc` hands back, and
/// the terminator is part of the allocation — freeing it as a plain `[]u8`
/// returns one byte fewer than was taken, which `DebugAllocator` reports as a
/// size mismatch.
///
/// Config goes through the file rather than the child's environment so that the
/// dotenv path in `Settings.load` is exercised too — it is the path an operator
/// actually uses, and it had no end-to-end coverage before this.
fn writeEnvFile(io: Io, gpa: std.mem.Allocator, tmp: *testing.TmpDir, fields: EnvFields) ![:0]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);

    try body.print(gpa,
        \\VORTEX_LISTEN_HOST=127.0.0.1
        \\VORTEX_LISTEN_PORT={d}
        \\VORTEX_UPSTREAM_HOST=127.0.0.1
        \\VORTEX_UPSTREAM_PORT={d}
        \\VORTEX_UPSTREAM_BIND_HOST=127.0.0.1
        \\VORTEX_UPSTREAM_BIND_PORT=0
        \\VORTEX_BLOCKLIST_SOURCE={s}
        \\VORTEX_SUFFIX_BLOCKLIST_SOURCE={s}
        \\VORTEX_LOG_LEVEL={s}
        \\VORTEX_LOG_FORMAT=logfmt
        \\VORTEX_CACHE_MAX_ENTRIES={d}
        \\
    , .{
        fields.listen_port,
        fields.upstream_port,
        build_options.blocklist_path,
        build_options.suffix_blocklist_path,
        child_log_level,
        fields.cache_max_entries,
    });

    try tmp.dir.writeFile(io, .{ .sub_path = "vortex.env", .data = body.items });
    return tmp.dir.realPathFileAlloc(io, "vortex.env", gpa);
}

/// Binds UDP port 0, notes what the OS picked, and releases it.
///
/// See the comment at the call site for why this is acceptable here and not in
/// production code.
fn reserveEphemeralPort(io: Io) !u16 {
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    return socket.address.getPort();
}

fn durationTimeout(ms: u64) Io.Timeout {
    return .{
        .duration = .{
            .raw = .fromMilliseconds(@intCast(ms)),
            // The same monotonic clock Vortex measures its own deadlines on, so a
            // wall-clock adjustment mid-run cannot turn a pass into a failure.
            .clock = .boot,
        },
    };
}
