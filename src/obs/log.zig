//! Structured diagnostic logging.
//!
//! Installed as `std.options.logFn` from [main.zig](../main.zig), so every
//! `std.log.*` call in the process renders as one **logfmt** record:
//!
//! ```
//! ts=2026-08-10T14:03:11.482Z level=warn scope=default msg="discarding reply id=a3f2"
//! ```
//!
//! The message body is whatever the call site formatted, wrapped in a quoted
//! `msg` field. That is deliberate: it means the 16 existing `std.log` call
//! sites needed no edits to become parseable, and — more importantly — it means
//! **no call site can break the record format**, because everything it emits
//! passes through `EscapingWriter` on the way out.
//!
//! **Why the escaping is not optional.** `Question.parseQuestion` lowercases
//! label bytes but does not validate them, so a qname reaching a log call site
//! can contain any byte, newlines included. Interpolating that raw would let
//! anyone who can send us a query forge log records. Escaping happens in the
//! one place every record must pass through, rather than being a rule call
//! sites are trusted to remember.
//!
//! Level and output format are both runtime settings — `VORTEX_LOG_LEVEL` and
//! `VORTEX_LOG_FORMAT` — resolved by [settings.zig](../settings.zig) and applied
//! through `configure`.
//!
//! Not yet here (see next_steps.md P2.3): the per-query event log carrying
//! client, qtype and latency as real fields, and counters.

const std = @import("std");

/// The application's `Io`, captured at startup by `init`.
///
/// Logging must go through the *same* `Io` instance as every other stderr
/// writer in the process. `std.Io.lockStderr` takes a mutex that lives on the
/// `Io` implementation (`Io.Threaded.stderr_mutex`), and `std.Options.debug_io`
/// is a separate statically-initialized singleton — so mixing
/// `std.debug.lockStderr` with `io.lockStderr` acquires two different mutexes
/// and lets records interleave mid-line.
///
/// Going through the application's `Io` also means a write that would block
/// (stderr piped to a slow reader) suspends the calling coroutine instead of
/// stalling the event-loop thread.
///
/// Written once during startup, before any coroutine is spawned; thread
/// creation is a synchronization point, so the plain `var` needs no atomics.
/// Null until then, and `logFn` falls back to `debug_io` so that anything
/// logging before `init` — or under `zig build test`, which never calls it —
/// still reaches stderr.
var app_io: ?std.Io = null;

/// How much to log. Ordered loosest-last, so `@intFromEnum` *is* the threshold.
///
/// Distinct from `std.log.Level` because it has an `off`, which that enum
/// cannot express — and "log nothing" is a real thing to ask a resolver for,
/// given the per-query records are personally identifying.
pub const Level = enum(u8) {
    off,
    err,
    warn,
    info,
    debug,

    /// Case-insensitive, and accepts both the short and long spelling of the
    /// two levels people disagree about. `VORTEX_LOG_LEVEL=WARNING` doing
    /// nothing would be a maddening ten minutes.
    pub fn parse(text: []const u8) ?Level {
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(text, "off") or eq(text, "none")) return .off;
        if (eq(text, "err") or eq(text, "error")) return .err;
        if (eq(text, "warn") or eq(text, "warning")) return .warn;
        if (eq(text, "info")) return .info;
        if (eq(text, "debug")) return .debug;
        return null;
    }

    /// Bootstrap default, used for anything logged before `configure` runs —
    /// which includes every diagnostic `Settings.load` itself emits. Follows
    /// `std.log`'s build-mode default so this changes nothing until an operator
    /// asks it to.
    pub fn fromStd(message_level: std.log.Level) Level {
        return switch (message_level) {
            .err => .err,
            .warn => .warn,
            .info => .info,
            .debug => .debug,
        };
    }

    fn enables(self: Level, message_level: std.log.Level) bool {
        return @intFromEnum(self) >= @intFromEnum(fromStd(message_level));
    }
};

/// Wire format for records.
///
/// `auto` is a configuration value only: `configure` resolves it against stderr
/// and the atomic below never holds it.
pub const Format = enum(u8) {
    /// `text` when stderr is a terminal, `logfmt` when it is a pipe or a file.
    /// Someone watching the server run wants to read it; something collecting
    /// its output wants to parse it.
    auto,
    /// One `key=value` record per line. See the module doc comment.
    logfmt,
    /// `std.log`'s own colored `level(scope): message`. No timestamp — the
    /// terminal in front of you supplies the context that field carries.
    text,

    /// Case-insensitive, to match `Level.parse`. Two config variables that
    /// disagree about whether `TEXT` counts would be its own small betrayal.
    pub fn parse(text: []const u8) ?Format {
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(text, "auto")) return .auto;
        if (eq(text, "logfmt")) return .logfmt;
        if (eq(text, "text")) return .text;
        return null;
    }

    fn resolve(self: Format, io: std.Io) Format {
        if (self != .auto) return self;
        const tty = std.Io.File.stderr().isTty(io) catch false;
        return if (tty) .text else .logfmt;
    }
};

/// Read on every log call from any thread, written twice during startup.
/// Relaxed ordering throughout: these guard a diagnostic, not a data
/// dependency, and a record either side of a level change is equally correct.
var current_level: std.atomic.Value(Level) = .init(Level.fromStd(std.log.default_level));
var current_format: std.atomic.Value(Format) = .init(.logfmt);

/// Points logging at the application's `Io`. Call once, early in `main`, before
/// anything that can log.
pub fn init(io: std.Io) void {
    app_io = io;
}

/// Applies the operator's `VORTEX_LOG_LEVEL` and `VORTEX_LOG_FORMAT`.
///
/// Separate from `init` because configuration cannot be read without logging:
/// `Settings.load` reports its own parse failures, so logging has to work
/// before the settings that govern it exist. Records emitted in that window use
/// the bootstrap defaults.
pub fn configure(io: std.Io, log_level: Level, log_format: Format) void {
    current_level.store(log_level, .monotonic);
    current_format.store(log_format.resolve(io), .monotonic);
}

pub fn logFn(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    // `fmt`, not `format`, so it does not shadow the module-level format state.
    comptime fmt: []const u8,
    args: anytype,
) void {
    // Before the clock, the lock, and any formatting: on a filtered-out record
    // this load and compare is the entire cost. `std.options.log_level` is
    // `.debug` so that the comptime gate in `std.log` passes everything through
    // to here — which is the only place a *runtime* level can be applied.
    if (!current_level.load(.monotonic).enables(message_level)) return;

    const io = app_io orelse std.Options.debug_io;

    // Logging is not a cancelation point. A coroutine being torn down still
    // gets to say why, and `lockStderr` below cannot then fail.
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    // `.real` rather than the `.boot` clock used for deadlines: a log timestamp
    // is for correlating against other systems' logs, which is exactly the job
    // wall time does and monotonic time cannot.
    const now = std.Io.Timestamp.now(io, .real);

    var buffer: [512]u8 = undefined;
    const locked = io.lockStderr(&buffer, null) catch |err| switch (err) {
        error.Canceled => unreachable, // Cancel protection enabled above.
    };
    defer io.unlockStderr();

    // A record we cannot write is a record we cannot report, so there is
    // nothing to do with the error but drop it.
    switch (current_format.load(.monotonic)) {
        .logfmt => writeRecord(
            &locked.file_writer.interface,
            now.nanoseconds,
            message_level,
            scope,
            fmt,
            args,
        ) catch {},
        .text => std.log.defaultLogFileTerminal(
            message_level,
            scope,
            fmt,
            args,
            locked.terminal(),
        ) catch {},
        .auto => unreachable, // `configure` resolves it; the atomic never holds it.
    }
}

/// Renders one complete record, newline included.
///
/// Pure over `out` and `epoch_ns` — no `Io`, no clock, no lock — which is what
/// makes the format testable.
fn writeRecord(
    out: *std.Io.Writer,
    epoch_ns: i96,
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) std.Io.Writer.Error!void {
    try out.writeAll("ts=");
    try writeTimestamp(out, epoch_ns);
    try out.print(" level={s} scope={t} msg=\"", .{ levelText(message_level), scope });

    // Unbuffered, so every byte reaches `out` escaped before this returns and
    // there is nothing left to flush.
    var escaping = EscapingWriter.init(out);
    try escaping.interface.print(format, args);

    try out.writeAll("\"\n");
}

/// `warn` rather than `std.log.Level.asText`'s `warning`: log processors and
/// everyone's grep habits expect the four-level short form.
fn levelText(comptime level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "error",
        .warn => "warn",
        .info => "info",
        .debug => "debug",
    };
}

/// Writes `epoch_ns` as RFC 3339 UTC with millisecond precision.
///
/// Milliseconds, not nanoseconds: the field exists to order records and line
/// them up against other systems, and nobody has ever needed nanosecond
/// precision to do that.
fn writeTimestamp(out: *std.Io.Writer, epoch_ns: i96) std.Io.Writer.Error!void {
    // Pre-epoch timestamps would underflow the unsigned `EpochSeconds` math.
    // A clock that far wrong is a broken machine, not a case to render
    // faithfully, so it clamps rather than trapping inside the logger.
    const total_ms: u64 = if (epoch_ns <= 0) 0 else @intCast(@divFloor(epoch_ns, std.time.ns_per_ms));

    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = total_ms / std.time.ms_per_s };
    const year_day = epoch_secs.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();

    try out.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        month_day.month.numeric(),
        // `day_index` is 0-based; calendars are not.
        @as(u16, month_day.day_index) + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
        total_ms % std.time.ms_per_s,
    });
}

/// A `std.Io.Writer` that escapes everything written through it into the
/// double-quoted logfmt value it is wrapping.
///
/// Output is restricted to printable ASCII: the quote and backslash are
/// escaped so a value cannot close its own field, the common whitespace
/// controls get their short forms, and **everything else — control bytes and
/// all of 0x7f-0xff — becomes `\xHH`**. Escaping high bytes rather than passing
/// them through keeps a record byte-for-byte greppable even when a qname
/// carries arbitrary binary; legitimate names are ASCII anyway, since IDNs
/// arrive as punycode.
///
/// Unbuffered (`buffer` is empty), so `drain` sees every byte and there is
/// never buffered state to flush. The escaped bytes land in `out`, which is
/// where the real buffering happens.
const EscapingWriter = struct {
    out: *std.Io.Writer,
    interface: std.Io.Writer,

    fn init(out: *std.Io.Writer) EscapingWriter {
        return .{
            .out = out,
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = &.{},
            },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *EscapingWriter = @alignCast(@fieldParentPtr("interface", w));

        const head = data[0 .. data.len - 1];
        const pattern = data[head.len];

        var written: usize = 0;
        for (head) |bytes| {
            try self.escape(bytes);
            written += bytes.len;
        }
        // The last slice is repeated `splat` times, which may be zero.
        for (0..splat) |_| try self.escape(pattern);
        written += pattern.len * splat;

        return written;
    }

    fn escape(self: *EscapingWriter, bytes: []const u8) std.Io.Writer.Error!void {
        for (bytes) |c| switch (c) {
            '"' => try self.out.writeAll("\\\""),
            '\\' => try self.out.writeAll("\\\\"),
            '\n' => try self.out.writeAll("\\n"),
            '\r' => try self.out.writeAll("\\r"),
            '\t' => try self.out.writeAll("\\t"),
            // Printable ASCII, minus the two bytes handled above.
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try self.out.writeByte(c),
            else => try self.out.print("\\x{x:0>2}", .{c}),
        };
    }
};

const testing = std.testing;

test "Level.parse takes both spellings, any case, and rejects the rest" {
    try testing.expectEqual(Level.off, Level.parse("off").?);
    try testing.expectEqual(Level.off, Level.parse("none").?);
    try testing.expectEqual(Level.err, Level.parse("err").?);
    try testing.expectEqual(Level.err, Level.parse("error").?);
    try testing.expectEqual(Level.warn, Level.parse("warn").?);
    try testing.expectEqual(Level.warn, Level.parse("warning").?);
    try testing.expectEqual(Level.info, Level.parse("info").?);
    try testing.expectEqual(Level.debug, Level.parse("debug").?);

    try testing.expectEqual(Level.warn, Level.parse("WARNING").?);
    try testing.expectEqual(Level.debug, Level.parse("Debug").?);

    // Near misses are rejected rather than coerced. Guessing that `verbose`
    // means `debug` is how you end up logging every query on a box you thought
    // was quiet.
    try testing.expect(Level.parse("verbose") == null);
    try testing.expect(Level.parse("warnings") == null);
    try testing.expect(Level.parse("") == null);
    try testing.expect(Level.parse("1") == null);
}

test "Level.enables is a threshold, and off silences everything" {
    // Each level admits itself and everything more severe, nothing less.
    try testing.expect(Level.warn.enables(.err));
    try testing.expect(Level.warn.enables(.warn));
    try testing.expect(!Level.warn.enables(.info));
    try testing.expect(!Level.warn.enables(.debug));

    try testing.expect(Level.debug.enables(.debug));
    try testing.expect(Level.err.enables(.err));
    try testing.expect(!Level.err.enables(.warn));

    // `off` is the point of having our own enum rather than `std.log.Level`:
    // a resolver's per-query records are PII, so "log nothing" has to be
    // expressible.
    inline for (.{ .err, .warn, .info, .debug }) |message_level| {
        try testing.expect(!Level.off.enables(message_level));
    }
}

test "Format.parse matches Level.parse's case-insensitivity" {
    try testing.expectEqual(Format.auto, Format.parse("auto").?);
    try testing.expectEqual(Format.logfmt, Format.parse("logfmt").?);
    try testing.expectEqual(Format.text, Format.parse("text").?);
    try testing.expectEqual(Format.text, Format.parse("TEXT").?);

    try testing.expect(Format.parse("json") == null);
    try testing.expect(Format.parse("") == null);
}

/// Renders one record into an owned buffer. Callers free the result.
fn renderForTest(
    epoch_ns: i96,
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) ![]u8 {
    var allocating = std.Io.Writer.Allocating.init(testing.allocator);
    errdefer allocating.deinit();
    try writeRecord(&allocating.writer, epoch_ns, level, scope, format, args);
    return allocating.toOwnedSlice();
}

test "writeRecord renders the logfmt envelope" {
    // 2026-08-10T14:03:11.482Z
    const ts: i96 = 1786370591_482_000_000;

    const line = try renderForTest(ts, .warn, .dispatcher, "id={x}", .{@as(u16, 0xa3f2)});
    defer testing.allocator.free(line);

    try testing.expectEqualStrings(
        "ts=2026-08-10T14:03:11.482Z level=warn scope=dispatcher msg=\"id=a3f2\"\n",
        line,
    );
}

test "writeRecord uses the short level names and the default scope" {
    const line = try renderForTest(0, .err, .default, "boom", .{});
    defer testing.allocator.free(line);

    // Epoch zero renders as the epoch, not as garbage.
    try testing.expectEqualStrings(
        "ts=1970-01-01T00:00:00.000Z level=error scope=default msg=\"boom\"\n",
        line,
    );
}

test "an attacker-controlled qname cannot forge a second record" {
    // The whole point of the escaping writer. `parseQuestion` lowercases label
    // bytes without validating them, so this is a name a client can really send:
    // a newline plus a well-formed-looking envelope of its own.
    const hostile = "evil\n" ++
        "ts=1970-01-01T00:00:00.000Z level=error scope=default msg=\"authorized\"";

    const line = try renderForTest(0, .debug, .query, "qname={s}", .{hostile});
    defer testing.allocator.free(line);

    // Exactly one record: the only newline is the terminator.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
    try testing.expect(std.mem.endsWith(u8, line, "\"\n"));

    // ...and the injected quotes are inert, so the forged `msg` never opens a
    // field of its own.
    try testing.expectEqualStrings(
        "ts=1970-01-01T00:00:00.000Z level=debug scope=query msg=\"qname=evil\\n" ++
            "ts=1970-01-01T00:00:00.000Z level=error scope=default msg=\\\"authorized\\\"\"\n",
        line,
    );
}

test "escaping covers quotes, backslashes, controls, and high bytes" {
    const line = try renderForTest(
        0,
        .info,
        .default,
        "{s}",
        .{"a\"b\\c\td\re\x00f\x7fg\xffh"},
    );
    defer testing.allocator.free(line);

    const open = std.mem.indexOf(u8, line, "msg=\"").? + "msg=\"".len;
    const body = line[open .. line.len - 2]; // strip the closing quote and newline

    try testing.expectEqualStrings(
        "a\\\"b\\\\c\\td\\re\\x00f\\x7fg\\xffh",
        body,
    );
}

test "writeTimestamp handles leap years and clamps a pre-epoch clock" {
    var buf: [64]u8 = undefined;

    // 2024-02-29T23:59:59.999Z — a leap day, and the last millisecond of it, so
    // both the year/month walk and the day-seconds split are exercised at their
    // boundaries.
    {
        var w = std.Io.Writer.fixed(&buf);
        try writeTimestamp(&w, 1709251199_999_000_000);
        try testing.expectEqualStrings("2024-02-29T23:59:59.999Z", w.buffered());
    }

    // A clock set before 1970 would underflow the unsigned epoch math; it
    // clamps instead of trapping inside the logger.
    {
        var w = std.Io.Writer.fixed(&buf);
        try writeTimestamp(&w, -1_000_000_000);
        try testing.expectEqualStrings("1970-01-01T00:00:00.000Z", w.buffered());
    }
}
