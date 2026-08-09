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
//! Not yet covered here (see next_steps.md P2.1): timeouts, log level,
//! negative-cache TTL, and fail-open-vs-closed. Each is one field plus one line
//! in `fromEnviron` once the code it configures can accept a runtime value.

const builtin = @import("builtin");
const std = @import("std");

const Environ = std.process.Environ;

/// Config diagnostics, scoped so they can be filtered once P2.3 lands a real
/// log level — and silenced under `zig build test`, because the validation
/// tests deliberately feed in bad values and Zig's test runner fails any test
/// that logs at `.err`. Only the logging is suppressed: the returned errors are
/// identical either way, and those are what the tests actually assert on.
const log = if (builtin.is_test) struct {
    fn err(comptime _: []const u8, _: anytype) void {}
    fn warn(comptime _: []const u8, _: anytype) void {}
    fn debug(comptime _: []const u8, _: anytype) void {}
} else std.log.scoped(.settings);

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
    blocklist_url: []const u8,
    suffix_blocklist_url: []const u8,

    pub const defaults: Settings = .{
        .listen_host = "127.0.0.1",
        .listen_port = 5354,

        .upstream_host = "192.168.1.1",
        .upstream_port = 53,

        .upstream_bind_host = "0.0.0.0",
        .upstream_bind_port = 0,

        .blocklist_url = "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
        .suffix_blocklist_url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
    };

    /// Environment file consulted when `VORTEX_ENV_FILE` is unset. Missing is
    /// not an error — running with no config file at all is a supported mode.
    pub const default_env_file = ".env";

    /// A config file this large is a mistake, not a config file.
    pub const max_env_file_bytes = 64 * 1024;

    pub const ParseError = error{
        /// A port variable was set to something that isn't a u16.
        InvalidPort,
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
        return .{
            .listen_host = envStr(environ, "VORTEX_LISTEN_HOST", defaults.listen_host),
            .listen_port = try envPort(environ, "VORTEX_LISTEN_PORT", defaults.listen_port),

            .upstream_host = envStr(environ, "VORTEX_UPSTREAM_HOST", defaults.upstream_host),
            .upstream_port = try envPort(environ, "VORTEX_UPSTREAM_PORT", defaults.upstream_port),

            .upstream_bind_host = envStr(environ, "VORTEX_UPSTREAM_BIND_HOST", defaults.upstream_bind_host),
            .upstream_bind_port = try envPort(environ, "VORTEX_UPSTREAM_BIND_PORT", defaults.upstream_bind_port),

            .blocklist_url = envStr(environ, "VORTEX_BLOCKLIST_URL", defaults.blocklist_url),
            .suffix_blocklist_url = envStr(environ, "VORTEX_SUFFIX_BLOCKLIST_URL", defaults.suffix_blocklist_url),
        };
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
