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

    /// Blocklist sources. Default to the checked-in fixtures; a P2.2 case
    /// overrides one to point at a scratch file it rewrites mid-test, or at a
    /// URL nothing is listening on.
    blocklist_source: ?[]const u8 = null,
    suffix_blocklist_source: ?[]const u8 = null,

    /// `VORTEX_BLOCKLIST_ON_FAILURE`. Null leaves it unset, so the case
    /// exercises the shipped default rather than a value the harness chose.
    on_failure: ?[]const u8 = null,

    /// Seconds between blocklist refreshes. 0 — the harness default, not the
    /// binary's — because a case that is not about refresh should not have a
    /// coroutine rebuilding lists underneath it.
    refresh_secs: usize = 0,

    /// On-disk blocklist cache directory. Empty disables it, which is the
    /// default here: a case that fell back to a cache left by a *previous* case
    /// would pass for the wrong reason. Cases about the cache set it to a path
    /// inside their own scratch directory.
    cache_dir: []const u8 = "",

    /// `VORTEX_HANDLER_THREADS`. Null leaves it unset, so the child sizes its
    /// handler pool from the CPU count like a real deployment does.
    handler_threads: ?usize = null,

    /// How `start` decides the child is up. See `Readiness`.
    readiness: Readiness = .blocked_probe,
};

/// How to tell that a child is ready to serve.
///
/// The default probe asks for a name the fixtures block and waits for the
/// locally synthesized answer. That is the strongest signal available — it
/// proves the blocklists loaded *and* the ingress loop is running — but it
/// assumes a loaded blocklist, which is exactly what a fail-open case does not
/// have. Such a case forwards everything instead, so it needs the other probe.
pub const Readiness = enum {
    /// Query a blocked name; ready when the synthesized reply comes back.
    blocked_probe,
    /// Query any name; ready when it shows up at the fake upstream. For a child
    /// running with an empty blocklist, where nothing is answered locally.
    forwarded_probe,
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
            .opts = opts,
        });
        defer gpa.free(env_path);

        var environ: std.process.Environ.Map = .init(gpa);
        defer environ.deinit();
        try environ.put("VORTEX_ENV_FILE", env_path);

        // Spawned straight into the instance, with the errdefer on the
        // instance's copy. `Child` is a value: an errdefer on a local that was
        // then copied in would kill a stale duplicate, whose id is still set
        // after `reportChildLog` has killed and reaped the real one — and the
        // second kill of a reaped pid panics with SRCH, burying the "did not
        // start" diagnostic under a harness crash.
        var instance: Instance = .{
            .io = io,
            .gpa = gpa,
            .child = try std.process.spawn(io, .{
                .argv = &.{build_options.vortex_exe},
                .environ_map = &environ,
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .pipe,
            }),
            .child_stderr = .empty,
            .client = client,
            .upstream = upstream,
            .listen_addr = listen_addr,
            .tmp = tmp,
        };
        errdefer {
            instance.stopChild();
            instance.child_stderr.deinit(gpa);
        }

        try instance.waitUntilReady(opts.readiness);
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

    /// Answers and discards everything already queued at the fake upstream.
    ///
    /// Used to clear readiness-probe traffic before a case starts asserting.
    /// Each datagram is answered rather than dropped so nothing is left in the
    /// child's pending table to be swept — and swept entries produce SERVFAILs
    /// that would arrive at the client socket mid-case.
    pub fn drainUpstream(self: *Instance) void {
        var buf: [wire.max_message]u8 = undefined;
        while (self.recvUpstream(&buf, 50)) |stale| {
            var reply_buf: [wire.max_message]u8 = undefined;
            const reply = wire.reply(&reply_buf, stale.data, .{}) catch continue;
            self.upstream.send(self.io, &stale.from, reply) catch {};
        } else |_| {}
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
    fn waitUntilReady(self: *Instance, readiness: Readiness) !void {
        // Its own socket, so that a late probe reply — one that arrives after
        // readiness was already established — lands here and is discarded with
        // the socket, rather than sitting in the case's client socket waiting
        // to be mistaken for the reply it is asserting on.
        const probe_bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const probe = try probe_bind.bind(self.io, .{ .mode = .dgram, .protocol = .udp });
        defer probe.close(self.io);

        var out: [wire.max_message]u8 = undefined;
        const name = switch (readiness) {
            .blocked_probe => ready_probe_name,
            .forwarded_probe => forwarded_probe_name,
        };
        const msg = wire.query(&out, 0x0BEE, name, .{});

        var in: [wire.max_message]u8 = undefined;
        var waited_ms: u64 = 0;
        while (waited_ms < ready_timeout_ms) : (waited_ms += probe_interval_ms) {
            // A datagram sent before the child bound its port is simply lost —
            // there is nothing listening yet, and UDP does not report that. So
            // the probe is *resent* each round rather than sent once and waited
            // on, which is also why this loop cannot be replaced by one long
            // receive.
            probe.send(self.io, &self.listen_addr, msg) catch {};

            switch (readiness) {
                .blocked_probe => {
                    const got = probe.receiveTimeout(self.io, &in, durationTimeout(probe_interval_ms)) catch |err| switch (err) {
                        error.Timeout => continue,
                        // Nothing is bound on that port yet and the kernel bounced the
                        // datagram with an ICMP port-unreachable. Expected on the first
                        // round or two; a child that never comes up times out below.
                        error.PortUnreachable => continue,
                        else => return err,
                    };
                    if (got.data.len >= 12 and wire.id(got.data) == 0x0BEE) return;
                },
                .forwarded_probe => {
                    // Ready when the probe reaches the fake upstream — which is
                    // the only signal available to a child whose blocklist is
                    // empty, since it answers nothing locally.
                    const got = self.upstream.receiveTimeout(self.io, &in, durationTimeout(probe_interval_ms)) catch |err| switch (err) {
                        error.Timeout => continue,
                        error.PortUnreachable => continue,
                        else => return err,
                    };

                    // Answered rather than dropped, so the probe does not leave
                    // an entry in the pending table for the case to trip over
                    // when it sweeps five seconds later.
                    var reply_buf: [wire.max_message]u8 = undefined;
                    const reply = wire.reply(&reply_buf, got.data, .{}) catch return;
                    self.upstream.send(self.io, &got.from, reply) catch {};

                    // The probe is resent every round, and every round's copy
                    // that was sent *before* the child came up may still be in
                    // flight behind this one. Left queued, the case's first
                    // `recvUpstream` would hand back a probe instead of the
                    // query it just sent, and it would then answer the wrong
                    // question — a failure that looks like a lost reply and is
                    // maddening to read. So drain the backlog before returning.
                    self.drainUpstream();
                    return;
                },
            }
        }

        std.debug.print(
            "vortex did not answer on 127.0.0.1:{d} within {d}ms\n",
            .{ self.listen_addr.getPort(), ready_timeout_ms },
        );
        self.reportChildLog();
        return error.VortexDidNotStart;
    }
};

/// Spawns a Vortex that is expected to fail at startup, and reports how it went.
///
/// The counterpart to `Instance.start`, for the one case that is about *not*
/// coming up: fail-closed. `start` would sit in its readiness loop for ten
/// seconds and then report a timeout, which is a much weaker assertion than
/// "exited, with this status, saying this".
///
/// The caller owns `stderr`.
pub fn runUntilExit(io: Io, gpa: std.mem.Allocator, opts: Options) !ExitResult {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // A child that is meant to die during blocklist loading never binds either
    // port, but the config still has to name them — and naming a port nothing
    // reserved keeps this from stealing one a live case is using.
    const env_path = try writeEnvFile(io, gpa, &tmp, .{
        .listen_port = try reserveEphemeralPort(io),
        .upstream_port = try reserveEphemeralPort(io),
        .opts = opts,
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

    // Drained before the wait, not after. The child's stderr is a pipe, and
    // waiting on a process that is still writing into a pipe nobody is reading
    // deadlocks once the buffer fills — the same trap `stopChild` documents,
    // arrived at from the other direction. This drain also *is* the exit
    // signal: the read hits EOF when the child's last stderr handle closes.
    var stderr: std.ArrayList(u8) = .empty;
    errdefer stderr.deinit(gpa);
    if (child.stderr) |file| {
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = file.readStreaming(io, &.{&chunk}) catch break;
            if (n == 0) break;
            try stderr.appendSlice(gpa, chunk[0..n]);
        }
    }

    return .{
        .term = try waitBounded(io, &child),
        .stderr = try stderr.toOwnedSlice(gpa),
    };
}

/// Longest `runUntilExit` waits for a child that is supposed to be dying.
///
/// Generous against the real figure — a fail-closed child gives up after three
/// connection-refused attempts, about three seconds — because this is a "something
/// is wrong" bound, not a timing assertion.
const exit_timeout_ms = 15_000;

/// `Child.wait`, but it cannot hang forever.
///
/// A plain `wait` on a child that never exits blocks the test process until the
/// build runner's own timeout, and the symptom is a slow suite rather than a
/// failure — which is exactly the trap documented on `stopChild`, met from the
/// other side. It matters most during a mutation run: a mutation that breaks
/// fail-closed makes the child *keep running*, and a case that hangs instead of
/// failing cannot confirm anything about the rule it was written for.
///
/// So the wait races a timer. If the timer wins, the child is killed — which
/// unblocks the wait — and the resulting `.signal` term is reported honestly,
/// where `ExitResult.failed` reads it as "did not exit on its own".
fn waitBounded(io: Io, child: *std.process.Child) !std.process.Child.Term {
    const Outcome = union(enum) {
        waited: std.process.Child.WaitError!std.process.Child.Term,
        expired: void,
    };

    // Captured before the wait task starts, because `Child.wait` nulls this
    // field when it reaps. The timeout path below needs the pid and must not
    // read it out of `child` while another task is writing it.
    const pid = child.id orelse return error.ChildAlreadyReaped;

    var buffer: [2]Outcome = undefined;
    var select: Io.Select(Outcome) = .init(io, &buffer);

    // Concurrent, not async: `wait` blocks in a syscall, so it needs a unit of
    // concurrency of its own or the timer below never gets to run.
    try select.concurrent(.waited, std.process.Child.wait, .{ child, io });
    select.async(.expired, sleepIgnoringCancel, .{ io, exit_timeout_ms });

    switch (try select.await()) {
        .waited => |result| {
            select.cancelDiscard();
            return result;
        },
        .expired => {
            // Signalled by pid rather than through `Child.kill`, which would
            // reap the process itself and race the `wait` already in flight on
            // it — two reapers, one of which finds the child gone. This way the
            // wait task stays the only reaper: the signal simply unblocks it,
            // and it reports the `.signal` term on its own.
            std.posix.kill(pid, std.posix.SIG.KILL) catch {};

            const reaped = try select.await();
            select.cancelDiscard();
            return switch (reaped) {
                .waited => |result| result,
                .expired => unreachable, // the timer already fired
            };
        },
    }
}

fn sleepIgnoringCancel(io: Io, ms: u64) void {
    io.sleep(Io.Duration.fromMilliseconds(@intCast(ms)), Io.Clock.boot) catch {};
}

pub const ExitResult = struct {
    term: std.process.Child.Term,
    stderr: []u8,

    pub fn deinit(self: *ExitResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stderr);
        self.* = undefined;
    }

    /// True when the child exited on its own with a failure status — which is
    /// what "refused to start" looks like from out here, as distinct from a
    /// crash (a signal) or a clean exit.
    pub fn failed(self: ExitResult) bool {
        return switch (self.term) {
            .exited => |code| code != 0,
            else => false,
        };
    }
};

/// Blocked by `testdata/blocklist.hosts`, so the reply is synthesized and no
/// upstream round trip is involved. Under `.test`, which RFC 6761 reserves.
const ready_probe_name = "blocked.test";

/// Deliberately *not* on either fixture list, so it is forwarded even by a
/// child whose blocklist loaded normally — the probe means the same thing
/// whether or not the case is a fail-open one.
const forwarded_probe_name = "ready-probe.example.com";

const EnvFields = struct {
    listen_port: u16,
    upstream_port: u16,
    opts: Options,
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
        \\VORTEX_CACHE_DIR={s}
        \\VORTEX_BLOCKLIST_REFRESH_SECS={d}
        \\
    , .{
        fields.listen_port,
        fields.upstream_port,
        fields.opts.blocklist_source orelse build_options.blocklist_path,
        fields.opts.suffix_blocklist_source orelse build_options.suffix_blocklist_path,
        child_log_level,
        fields.opts.cache_max_entries,
        fields.opts.cache_dir,
        fields.opts.refresh_secs,
    });

    // Appended only when the case asks for it, so the unset case exercises the
    // binary's own default rather than one the harness picked for it.
    if (fields.opts.on_failure) |policy| {
        try body.print(gpa, "VORTEX_BLOCKLIST_ON_FAILURE={s}\n", .{policy});
    }
    if (fields.opts.handler_threads) |n| {
        try body.print(gpa, "VORTEX_HANDLER_THREADS={d}\n", .{n});
    }

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
