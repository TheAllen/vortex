//! Runtime configuration, resolved once at startup.
//!
//! Values are resolved from three sources, **later sources win**:
//!
//!   1. the built-in `defaults` below,
//!   2. an environment file (`.env` by default, or `$VORTEX_ENV_FILE`),
//!   3. the real process environment.
//!
//! That ordering is the usual dotenv contract: the file supplies values for
//! things not already set, so `VORTEX_LISTEN_PORT=5355 ./vortex` overrides the
//! file without editing it. The file is loaded *into* the process environ map
//! rather than kept alongside it, so there is exactly one lookup path and the
//! precedence rule is enforced by construction — a key that already exists is
//! never overwritten. (Within the file itself that also means the first
//! occurrence of a duplicated key wins.)
//!
//! **Lifetime:** a `Settings`'s string fields either point at string literals
//! (defaults) or into the `Environ.Map` owned by `std.process.Init`, which
//! lives for the whole process. `Settings` therefore owns nothing and has no
//! `deinit` — but it must not outlive the map it was loaded from.
//!
//! Not yet covered here (see next_steps.md P2.1): CLI flags, multiple upstreams,
//! timeouts, negative-cache TTL, and fail-open-vs-closed. Each is one field plus
//! one line in `fromEnviron` once the code it configures can accept a runtime
//! value.

const builtin = @import("builtin");
const std = @import("std");

const obs_log = @import("obs/log.zig");

const Environ = std.process.Environ;

/// Config diagnostics, scoped so an operator can filter them apart from the
/// datapath — and silenced under `zig build test`, because the validation tests
/// deliberately feed in bad values and Zig's test runner fails any test that
/// logs at `.err`. Only the logging is suppressed: the returned errors are
/// identical either way, and those are what the tests actually assert on.
///
/// P2.3 landed a runtime level, so `VORTEX_LOG_LEVEL=off` could in principle do
/// this job instead. It deliberately does not: that is one process-wide global,
/// and a test that set it would silence every *other* test running after it in
/// the same binary. A comptime swap of this one namespace is scoped to the file
/// that needs it and cannot leak.
const log = if (builtin.is_test) struct {
    fn err(comptime _: []const u8, _: anytype) void {}
    fn warn(comptime _: []const u8, _: anytype) void {}
    fn debug(comptime _: []const u8, _: anytype) void {}
} else std.log.scoped(.settings);

/// Where a blocklist's bytes come from: over the network, or off the disk.
///
/// Resolved from the variable's scheme rather than from a second variable, so
/// there is still exactly one setting per list and no "both set" case to define
/// a precedence rule for.
pub const Source = union(enum) {
    url: []const u8,
    path: []const u8,

    const file_scheme = "file://";

    /// `http://` or `https://` (case-insensitive) is a URL. `file://` is a path
    /// with the scheme stripped, so `file:///etc/hosts` is `/etc/hosts`.
    /// Everything else is a path.
    ///
    /// Deliberately total — there is no "invalid source" error. A typo'd
    /// `htps://example.com/hosts` becomes a path, and then fails at open time
    /// with that exact string in the message, which names the offending value
    /// just as loudly as a dedicated parse error would while keeping every
    /// unadorned relative path working.
    pub fn parse(raw: []const u8) Source {
        if (std.ascii.startsWithIgnoreCase(raw, "http://") or
            std.ascii.startsWithIgnoreCase(raw, "https://"))
        {
            return .{ .url = raw };
        }
        if (std.ascii.startsWithIgnoreCase(raw, file_scheme)) {
            return .{ .path = raw[file_scheme.len..] };
        }
        return .{ .path = raw };
    }
};

pub const Settings = struct {
    /// Address and port the resolver listens on for client queries.
    listen_host: []const u8,
    listen_port: u16,

    /// Upstream resolver queries are forwarded to.
    upstream_host: []const u8,
    upstream_port: u16,

    /// Local address the shared upstream socket binds to. Port 0 means "let the
    /// OS pick an ephemeral port", which is what you want unless you are
    /// pinning a source port through a firewall rule.
    upstream_bind_host: []const u8,
    upstream_bind_port: u16,

    /// Exact-match blocklist (hosts format) and suffix/wildcard blocklist.
    /// Either may be a URL or a local file path; see `Source`.
    ///
    /// The suffix list must be **bare domains, one per line** — the format
    /// `SuffixBlockList.parseSuffixDomain` reads and `decide`'s parent-label
    /// walk matches against. A list whose entries carry a `*.` prefix parses
    /// without complaint and then matches nothing at all, which is the worst
    /// possible failure: a blocklist that loads clean and blocks zero domains.
    blocklist_source: Source,
    suffix_blocklist_source: Source,

    /// Diagnostic verbosity, and whether records render for a human or a
    /// parser. Applied by `obs_log.configure`; see [obs/log.zig](obs/log.zig).
    log_level: obs_log.Level,
    log_format: obs_log.Format,

    /// Hard cap on resident response-cache entries.
    ///
    /// A bound, not a tuning hint: without one the cache is an unbounded,
    /// network-fed allocation, since a flood of distinct names would grow it
    /// until the allocator failed. Keys are 258 bytes and `std.HashMap`
    /// reserves capacity in powers of two at 80% load, so 10k entries costs
    /// ~4.1 MB of key array whether or not it is full. Zero disables caching.
    cache_max_entries: usize,

    pub const defaults: Settings = .{
        .listen_host = "127.0.0.1",
        .listen_port = 5354,

        .upstream_host = "192.168.1.1",
        .upstream_port = 53,

        .upstream_bind_host = "0.0.0.0",
        .upstream_bind_port = 0,

        .blocklist_source = .{ .url = "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts" },
        // `domainswild2`, not `domainswild`: the `2` variant omits the `*.`
        // prefix, which is the only form this codebase can match. Replaced the
        // hagezi light list on 2026-08-10 after that entire GitHub *account*
        // disappeared — not just the file — leaving no successor to point at.
        .suffix_blocklist_source = .{ .url = "https://small.oisd.nl/domainswild2" },

        // Tracks `std.log`'s build-mode default — debug under `Debug`, info
        // under the release modes — so adding this knob changes nothing for
        // anyone who does not set it.
        .log_level = obs_log.Level.fromStd(std.log.default_level),
        .log_format = .auto,

        // ~4.1 MB of key array at 80% load. Comfortable for a home network,
        // and well under the ~50k mark where the inline-key representation
        // stops being obviously the right trade.
        .cache_max_entries = 10_000,
    };

    /// Environment file consulted when `VORTEX_ENV_FILE` is unset. Missing is
    /// not an error — running with no config file at all is a supported mode.
    pub const default_env_file = ".env";

    /// A config file this large is a mistake, not a config file.
    pub const max_env_file_bytes = 64 * 1024;

    /// Ceiling on a blocklist read from disk. Generous on purpose — the full
    /// StevenBlack `hosts` is ~3.5 MB — but the read has to be bounded, because
    /// the bytes are retained for the process lifetime (the set's keys are
    /// slices into them) and an unbounded read of whatever path an operator
    /// typed is an easy way to lose the machine to a fat-fingered `/dev/zero`.
    pub const max_blocklist_bytes = 32 * 1024 * 1024;

    pub const ParseError = error{
        /// A port variable was set to something that isn't a u16.
        InvalidPort,
        /// `VORTEX_LOG_LEVEL` was set to something that isn't a level.
        InvalidLogLevel,
        /// `VORTEX_LOG_FORMAT` was set to something that isn't a format.
        InvalidLogFormat,
        /// `VORTEX_CACHE_MAX_ENTRIES` was set to something that isn't a count.
        InvalidCacheSize,
        /// A variable that no longer exists under that name is still set. See
        /// `renamed`.
        RenamedSetting,
    };

    /// Variables that were renamed, and what to say when one turns up.
    ///
    /// Ignoring a stale name would mean silently resolving the *default* while
    /// an operator's `.env` sits there plainly stating otherwise — the same
    /// class of failure as quietly listening on 5354 after a typo'd port, and
    /// worse here, because the value that gets ignored is a blocklist.
    const renamed = [_]struct { old: []const u8, new: []const u8 }{
        .{ .old = "VORTEX_BLOCKLIST_URL", .new = "VORTEX_BLOCKLIST_SOURCE" },
        .{ .old = "VORTEX_SUFFIX_BLOCKLIST_URL", .new = "VORTEX_SUFFIX_BLOCKLIST_SOURCE" },
    };

    /// Reads the environment file into `environ`, then resolves every field.
    ///
    /// `environ` is mutated (that is how precedence is enforced) and must be
    /// the process-wide map from `std.process.Init`. It is not threadsafe, so
    /// this has to run during startup, before any coroutine is spawned.
    pub fn load(io: std.Io, gpa: std.mem.Allocator, environ: *Environ.Map) !Settings {
        try loadEnvFile(io, gpa, environ);
        return fromEnviron(environ);
    }

    /// Pure: resolves fields from an already-populated map. Split out from
    /// `load` so it is testable without an `Io` or a file on disk.
    pub fn fromEnviron(environ: *const Environ.Map) ParseError!Settings {
        try checkRenamed(environ);
        return .{
            .listen_host = envStr(environ, "VORTEX_LISTEN_HOST", defaults.listen_host),
            .listen_port = try envPort(environ, "VORTEX_LISTEN_PORT", defaults.listen_port),

            .upstream_host = envStr(environ, "VORTEX_UPSTREAM_HOST", defaults.upstream_host),
            .upstream_port = try envPort(environ, "VORTEX_UPSTREAM_PORT", defaults.upstream_port),

            .upstream_bind_host = envStr(environ, "VORTEX_UPSTREAM_BIND_HOST", defaults.upstream_bind_host),
            .upstream_bind_port = try envPort(environ, "VORTEX_UPSTREAM_BIND_PORT", defaults.upstream_bind_port),

            .blocklist_source = envSource(environ, "VORTEX_BLOCKLIST_SOURCE", defaults.blocklist_source),
            .suffix_blocklist_source = envSource(environ, "VORTEX_SUFFIX_BLOCKLIST_SOURCE", defaults.suffix_blocklist_source),

            .log_level = try envEnum(
                obs_log.Level,
                environ,
                "VORTEX_LOG_LEVEL",
                defaults.log_level,
                error.InvalidLogLevel,
                "off, error, warn, info, or debug",
            ),
            .log_format = try envEnum(
                obs_log.Format,
                environ,
                "VORTEX_LOG_FORMAT",
                defaults.log_format,
                error.InvalidLogFormat,
                "auto, logfmt, or text",
            ),
            .cache_max_entries = try envCount(
                environ,
                "VORTEX_CACHE_MAX_ENTRIES",
                defaults.cache_max_entries,
            ),
        };
    }

    /// Same fail-loud contract as `envPort`: silently falling back to the
    /// default because someone typed `10_000` is the config bug that costs an
    /// hour of wondering why memory looks wrong.
    fn envCount(environ: *const Environ.Map, key: []const u8, fallback: usize) ParseError!usize {
        const raw = environ.get(key) orelse return fallback;
        if (raw.len == 0) return fallback;
        return std.fmt.parseInt(usize, raw, 10) catch {
            log.err("{s}: '{s}' is not a whole number of entries", .{ key, raw });
            return error.InvalidCacheSize;
        };
    }

    /// Rejects a variable that is set under a name this build no longer reads.
    ///
    /// Runs from `fromEnviron` rather than `load` so it sits inside the pure,
    /// `Io`-free surface the tests already cover. An explicitly empty value is
    /// "unset" here, exactly as it is everywhere else in this file — it would
    /// have configured nothing under the old name either.
    fn checkRenamed(environ: *const Environ.Map) ParseError!void {
        for (renamed) |r| {
            const raw = environ.get(r.old) orelse continue;
            if (raw.len == 0) continue;
            log.err(
                "{s} was renamed to {s}, which also accepts a local file path; rename it and restart",
                .{ r.old, r.new },
            );
            return error.RenamedSetting;
        }
    }

    fn envSource(environ: *const Environ.Map, key: []const u8, fallback: Source) Source {
        const raw = environ.get(key) orelse return fallback;
        if (raw.len == 0) return fallback;
        return Source.parse(raw);
    }

    fn envStr(environ: *const Environ.Map, key: []const u8, fallback: []const u8) []const u8 {
        const raw = environ.get(key) orelse return fallback;
        // An explicitly empty value means "unset", not "the empty string" —
        // otherwise `VORTEX_LISTEN_HOST=` produces a parse failure three call
        // frames away from the thing that caused it.
        if (raw.len == 0) return fallback;
        return raw;
    }

    /// A malformed port is fatal rather than silently falling back. Quietly
    /// listening on 5354 because someone typo'd `VORTEX_LISTEN_PORT=535e` is
    /// the kind of config bug that costs an hour to find.
    fn envPort(environ: *const Environ.Map, key: []const u8, fallback: u16) ParseError!u16 {
        const raw = environ.get(key) orelse return fallback;
        if (raw.len == 0) return fallback;
        return std.fmt.parseInt(u16, raw, 10) catch {
            log.err("{s}: '{s}' is not a port number (expected 0-65535)", .{ key, raw });
            return error.InvalidPort;
        };
    }

    /// Same fail-loud contract as `envPort`, for the enum-valued variables.
    ///
    /// `T` supplies its own `parse` rather than getting `std.meta.stringToEnum`
    /// applied here, so a type can accept aliases its tag names do not cover —
    /// `Level` takes both `warn` and `warning`.
    fn envEnum(
        comptime T: type,
        environ: *const Environ.Map,
        key: []const u8,
        fallback: T,
        comptime invalid: ParseError,
        comptime expected: []const u8,
    ) ParseError!T {
        const raw = environ.get(key) orelse return fallback;
        if (raw.len == 0) return fallback;
        return T.parse(raw) orelse {
            log.err("{s}: '{s}' is not valid (expected {s})", .{ key, raw, expected });
            return invalid;
        };
    }
};

/// Reads the env file and merges it into `environ`.
///
/// A missing *default* file is fine and silent. Anything else — an unreadable
/// file, or a missing file that was named explicitly via `VORTEX_ENV_FILE` — is
/// an error, because in those cases the operator asked for a config that could
/// not be delivered and starting with silent defaults would be worse.
fn loadEnvFile(io: std.Io, gpa: std.mem.Allocator, environ: *Environ.Map) !void {
    const explicit = environ.get("VORTEX_ENV_FILE");
    const path = explicit orelse Settings.default_env_file;

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(Settings.max_env_file_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => {
            if (explicit != null) {
                log.err("VORTEX_ENV_FILE='{s}' does not exist", .{path});
                return err;
            }
            log.debug("no '{s}'; using process environment and defaults", .{path});
            return;
        },
        error.StreamTooLong => {
            log.err("'{s}' exceeds {d} bytes", .{ path, Settings.max_env_file_bytes });
            return err;
        },
        else => {
            log.err("cannot read '{s}': {s}", .{ path, @errorName(err) });
            return err;
        },
    };
    defer gpa.free(bytes);

    try parseEnvInto(environ, bytes, path);
}

/// Parses dotenv-style `KEY=value` lines and inserts those not already set.
///
/// Pure over the byte slice (plus the map it fills), so the whole grammar is
/// testable without touching a filesystem. Supported: blank lines, `#`
/// comments, an optional `export ` prefix, whitespace around `=`, and values
/// wrapped in matching single or double quotes. An unquoted value may carry a
/// trailing comment, which must be preceded by whitespace so that a `#` inside
/// a URL is not mistaken for one.
///
/// Deliberately *not* supported: backslash escapes and multi-line values. A
/// quoted value is taken literally. `path` is used only for diagnostics.
fn parseEnvInto(environ: *Environ.Map, bytes: []const u8, path: []const u8) !void {
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, bytes, '\n');

    while (lines.next()) |raw_line| {
        line_no += 1;
        var line = raw_line;

        // Tolerate CRLF files and a UTF-8 BOM on the first line; both are what
        // you get when a config is edited on Windows or exported from an editor
        // that helpfully adds one.
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (line_no == 1 and std.mem.startsWith(u8, line, "\xEF\xBB\xBF")) line = line[3..];

        line = std.mem.trim(u8, line, " \t");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.startsWith(u8, line, "export ")) {
            line = std.mem.trimStart(u8, line["export ".len..], " \t");
        }

        const eq = std.mem.findScalar(u8, line, '=') orelse {
            log.warn("{s}:{d}: no '=' in '{s}', ignoring", .{ path, line_no, line });
            continue;
        };

        const key = std.mem.trim(u8, line[0..eq], " \t");
        if (!isValidKey(key)) {
            log.warn("{s}:{d}: '{s}' is not a valid variable name, ignoring", .{ path, line_no, key });
            continue;
        }

        const value = unquote(std.mem.trim(u8, line[eq + 1 ..], " \t"));

        // Already set — by the real environment, or by an earlier line. Leave
        // it: this is where the precedence rule is actually enforced.
        if (environ.get(key) != null) {
            log.debug("{s}:{d}: {s} already set, keeping existing value", .{ path, line_no, key });
            continue;
        }

        try environ.put(key, value);
    }
}

/// Env-var-shaped: a leading letter or underscore, then letters, digits, or
/// underscores. Stricter than `Environ.Map.validateKeyForPut` (which only bars
/// NUL and `=`) so that a mangled line is reported instead of silently
/// becoming a variable nothing will ever read.
fn isValidKey(key: []const u8) bool {
    if (key.len == 0) return false;
    if (!std.ascii.isAlphabetic(key[0]) and key[0] != '_') return false;
    for (key[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    }
    return true;
}

/// Strips matching surrounding quotes, or a whitespace-preceded trailing
/// comment from an unquoted value.
fn unquote(raw: []const u8) []const u8 {
    if (raw.len >= 2) {
        const quote = raw[0];
        if ((quote == '"' or quote == '\'') and raw[raw.len - 1] == quote) {
            return raw[1 .. raw.len - 1];
        }
    }

    // Unquoted: ` #` or `\t#` begins a comment. Requiring the whitespace keeps
    // `...#fragment` inside a bare URL intact.
    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        if (raw[i] == '#' and (raw[i - 1] == ' ' or raw[i - 1] == '\t')) {
            return std.mem.trimEnd(u8, raw[0..i], " \t");
        }
    }
    return raw;
}

const testing = std.testing;

/// Builds an empty map, parses `src` into it, and hands both back to the test.
fn testMap(src: []const u8) !Environ.Map {
    var map = Environ.Map.init(testing.allocator);
    errdefer map.deinit();
    try parseEnvInto(&map, src, "test.env");
    return map;
}

test "parseEnvInto handles the dotenv grammar" {
    var map = try testMap(
        \\# a full-line comment
        \\
        \\VORTEX_LISTEN_HOST = "127.0.0.1"
        \\VORTEX_LISTEN_PORT=5354
        \\  export VORTEX_UPSTREAM_HOST='1.1.1.1'
        \\VORTEX_UPSTREAM_PORT = 53   # trailing comment
        \\VORTEX_BLOCKLIST_URL=https://example.com/hosts#fragment
    );
    defer map.deinit();

    // Quoted, unquoted, single-quoted, and `export `-prefixed all land the same.
    try testing.expectEqualStrings("127.0.0.1", map.get("VORTEX_LISTEN_HOST").?);
    try testing.expectEqualStrings("5354", map.get("VORTEX_LISTEN_PORT").?);
    try testing.expectEqualStrings("1.1.1.1", map.get("VORTEX_UPSTREAM_HOST").?);

    // A whitespace-preceded `#` is a comment...
    try testing.expectEqualStrings("53", map.get("VORTEX_UPSTREAM_PORT").?);
    // ...but one inside a URL is not.
    try testing.expectEqualStrings(
        "https://example.com/hosts#fragment",
        map.get("VORTEX_BLOCKLIST_URL").?,
    );
}

test "parseEnvInto never overwrites an existing value" {
    // The precedence rule: the real process environment wins over the file.
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();
    try map.put("VORTEX_LISTEN_PORT", "9999");

    try parseEnvInto(&map,
        \\VORTEX_LISTEN_PORT=5354
        \\VORTEX_UPSTREAM_PORT=53
        \\VORTEX_UPSTREAM_PORT=5300
    , "test.env");

    try testing.expectEqualStrings("9999", map.get("VORTEX_LISTEN_PORT").?);
    // Same rule applied within the file: first occurrence wins.
    try testing.expectEqualStrings("53", map.get("VORTEX_UPSTREAM_PORT").?);
}

test "parseEnvInto skips malformed lines and survives CRLF and a BOM" {
    var map = try testMap("\xEF\xBB\xBFVORTEX_LISTEN_PORT=5354\r\nnot a config line\r\n9BAD=x\r\n=novalue\r\nVORTEX_UPSTREAM_PORT=53\r\n");
    defer map.deinit();

    // The BOM must not end up glued to the first key.
    try testing.expectEqualStrings("5354", map.get("VORTEX_LISTEN_PORT").?);
    // A line with no `=`, a key starting with a digit, and an empty key are all
    // dropped rather than aborting the load...
    try testing.expect(map.get("9BAD") == null);
    // ...and parsing continues past them.
    try testing.expectEqualStrings("53", map.get("VORTEX_UPSTREAM_PORT").?);
}

test "fromEnviron falls back to defaults and rejects a bad port" {
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();

    // Empty map → every default, verbatim.
    try testing.expectEqualDeep(Settings.defaults, try Settings.fromEnviron(&map));

    // An explicitly empty value is treated as unset, not as an empty host.
    try map.put("VORTEX_LISTEN_HOST", "");
    try testing.expectEqualStrings(
        Settings.defaults.listen_host,
        (try Settings.fromEnviron(&map)).listen_host,
    );

    try map.put("VORTEX_LISTEN_HOST", "0.0.0.0");
    try map.put("VORTEX_LISTEN_PORT", "53");
    const cfg = try Settings.fromEnviron(&map);
    try testing.expectEqualStrings("0.0.0.0", cfg.listen_host);
    try testing.expectEqual(@as(u16, 53), cfg.listen_port);
    // Untouched keys still come from defaults.
    try testing.expectEqualStrings(Settings.defaults.upstream_host, cfg.upstream_host);

    // A typo'd port is fatal, not silently defaulted.
    try map.put("VORTEX_LISTEN_PORT", "535e");
    try testing.expectError(error.InvalidPort, Settings.fromEnviron(&map));

    try map.put("VORTEX_LISTEN_PORT", "70000"); // > maxInt(u16)
    try testing.expectError(error.InvalidPort, Settings.fromEnviron(&map));
}

test "fromEnviron resolves the logging knobs and rejects bad values" {
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();

    // Unset means the bootstrap default, which tracks the build mode — so
    // adding these variables changed nothing for anyone who ignores them.
    const unset = try Settings.fromEnviron(&map);
    try testing.expectEqual(obs_log.Level.fromStd(std.log.default_level), unset.log_level);
    try testing.expectEqual(obs_log.Format.auto, unset.log_format);

    try map.put("VORTEX_LOG_LEVEL", "warning");
    try map.put("VORTEX_LOG_FORMAT", "logfmt");
    const cfg = try Settings.fromEnviron(&map);
    try testing.expectEqual(obs_log.Level.warn, cfg.log_level);
    try testing.expectEqual(obs_log.Format.logfmt, cfg.log_format);

    // Empty is "unset", consistent with every other variable here.
    try map.put("VORTEX_LOG_LEVEL", "");
    try testing.expectEqual(
        obs_log.Level.fromStd(std.log.default_level),
        (try Settings.fromEnviron(&map)).log_level,
    );

    // Same fail-loud contract as a typo'd port: starting up at a level nobody
    // asked for is exactly as silent a failure as listening on the wrong port,
    // and here it could mean an operator believes they disabled query logging
    // when they did not.
    try map.put("VORTEX_LOG_LEVEL", "verbose");
    try testing.expectError(error.InvalidLogLevel, Settings.fromEnviron(&map));

    try map.put("VORTEX_LOG_LEVEL", "info");
    try map.put("VORTEX_LOG_FORMAT", "json");
    try testing.expectError(error.InvalidLogFormat, Settings.fromEnviron(&map));
}

test "Source.parse separates a URL from a path" {
    // Both schemes we actually fetch over, and the value is passed through
    // whole — a truncated URL would still be a `.url`, so assert the payload.
    try testing.expectEqualDeep(
        Source{ .url = "https://example.com/hosts" },
        Source.parse("https://example.com/hosts"),
    );
    try testing.expectEqualDeep(
        Source{ .url = "http://example.com/hosts" },
        Source.parse("http://example.com/hosts"),
    );
    // A scheme is case-insensitive per RFC 3986 §3.1, and an operator who
    // pastes one from a document that capitalized it should not silently get a
    // filesystem read of the string "HTTPS://...".
    try testing.expectEqualDeep(
        Source{ .url = "HTTPS://example.com/hosts" },
        Source.parse("HTTPS://example.com/hosts"),
    );

    // `file://` is stripped, so the third slash of `file:///abs` is the leading
    // slash of the absolute path — off by one here means opening `/abs`'s
    // parent, or nothing at all.
    try testing.expectEqualDeep(
        Source{ .path = "/etc/vortex/hosts" },
        Source.parse("file:///etc/vortex/hosts"),
    );

    // Bare paths, relative and absolute, need no scheme at all.
    try testing.expectEqualDeep(
        Source{ .path = "./testdata/blocklist.hosts" },
        Source.parse("./testdata/blocklist.hosts"),
    );
    try testing.expectEqualDeep(
        Source{ .path = "/etc/vortex/hosts" },
        Source.parse("/etc/vortex/hosts"),
    );

    // A typo'd scheme is a path, not an error — and fails at open time naming
    // the whole string, which is the point of not adding a parse error here.
    try testing.expectEqualDeep(
        Source{ .path = "htps://example.com/hosts" },
        Source.parse("htps://example.com/hosts"),
    );
}

test "fromEnviron resolves both blocklist sources" {
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();

    // Unset means the built-in URLs, unchanged by this feature.
    const unset = try Settings.fromEnviron(&map);
    try testing.expectEqualDeep(Settings.defaults.blocklist_source, unset.blocklist_source);
    try testing.expectEqualDeep(Settings.defaults.suffix_blocklist_source, unset.suffix_blocklist_source);

    // The two lists resolve independently: one off disk, one over the network,
    // which is a combination the P2.5 harness will actually use.
    try map.put("VORTEX_BLOCKLIST_SOURCE", "./testdata/blocklist.hosts");
    try map.put("VORTEX_SUFFIX_BLOCKLIST_SOURCE", "https://example.com/wild");
    const cfg = try Settings.fromEnviron(&map);
    try testing.expectEqualDeep(Source{ .path = "./testdata/blocklist.hosts" }, cfg.blocklist_source);
    try testing.expectEqualDeep(Source{ .url = "https://example.com/wild" }, cfg.suffix_blocklist_source);

    // Empty is "unset", consistent with every other variable here.
    try map.put("VORTEX_BLOCKLIST_SOURCE", "");
    try testing.expectEqualDeep(
        Settings.defaults.blocklist_source,
        (try Settings.fromEnviron(&map)).blocklist_source,
    );
}

test "fromEnviron rejects the pre-rename blocklist variables" {
    var map = Environ.Map.init(testing.allocator);
    defer map.deinit();

    // A `.env` written before the rename would otherwise resolve to the default
    // URL while stating something else on the page — so this is fatal, not a
    // warning. Each name is checked separately: a loop that returned after the
    // first would leave the second unguarded.
    try map.put("VORTEX_BLOCKLIST_URL", "https://example.com/hosts");
    try testing.expectError(error.RenamedSetting, Settings.fromEnviron(&map));

    try map.put("VORTEX_BLOCKLIST_URL", "");
    try map.put("VORTEX_SUFFIX_BLOCKLIST_URL", "https://example.com/wild");
    try testing.expectError(error.RenamedSetting, Settings.fromEnviron(&map));

    // An explicitly empty stale name configured nothing under the old name
    // either, so it is "unset" rather than a migration failure — and with both
    // empty the load succeeds.
    try map.put("VORTEX_SUFFIX_BLOCKLIST_URL", "");
    _ = try Settings.fromEnviron(&map);
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Settings);
    testing.refAllDecls(Source);
}
