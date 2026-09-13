//! Getting a blocklist's bytes, and surviving the day that fails.
//!
//! Both blocklists route their acquisition through here. Before P2.2 each one
//! fetched its URL once and propagated any failure to `main`, which meant a
//! transient blip at the upstream list host — a GitHub outage, or oisd.nl's
//! per-IP rate limit answering 503 after a few quick restarts — took the whole
//! network's DNS down. Three mechanisms replace that:
//!
//!   1. **Retry**, but only what is worth retrying. A 503 is a bad minute; a 404
//!      is a bad URL, and retrying it three times only delays the diagnosis.
//!   2. **An on-disk cache**, written on every success and read when the network
//!      cannot be reached. A yesterday-old blocklist is enormously better than
//!      no blocklist.
//!   3. **`error.BlocklistUnavailable`** when even that fails, which the caller
//!      resolves against the operator's fail-open/fail-closed choice. This file
//!      does not make that decision — it reports.
//!
//! **A `.path` source is exempt from all three.** An operator who named a local
//! file asked for that file: a missing path is a configuration error, not a
//! transient network condition, so it stays fatal and says so. Retrying a
//! filename that is wrong will not make it right, and quietly serving a cached
//! copy of a file the operator has since edited would be worse than stopping.

const std = @import("std");

const backoff = @import("../utils/backoff.zig");
const readFileInto = @import("domain_blocklist.zig").readFileInto;
const Settings = @import("../settings.zig").Settings;
const Source = @import("../settings.zig").Source;

/// Diagnostics for the load path, scoped so an operator can filter a blocklist
/// failure apart from the datapath. Silenced under `zig build test` for the same
/// reason `settings.zig` silences its own: the tests here deliberately drive
/// failure paths, and Zig's test runner fails any test that logs at `.err`.
const log = if (@import("builtin").is_test) struct {
    fn err(comptime _: []const u8, _: anytype) void {}
    fn warn(comptime _: []const u8, _: anytype) void {}
    fn info(comptime _: []const u8, _: anytype) void {}
} else std.log.scoped(.blocklist);

/// How the bytes were obtained. Carried back to the caller so startup can say
/// which of the three states it is in rather than logging one line for all of
/// them — "loaded from cache" is the one an operator most needs to see.
pub const Outcome = enum {
    /// Fetched from the network (or read from a local path) this run.
    fresh,
    /// The fetch failed and the on-disk cache supplied the bytes.
    cached,
};

pub const Error = error{
    /// Every acquisition route failed: the fetch did not succeed and there was
    /// no usable cache. The caller applies the fail-open/fail-closed policy.
    BlocklistUnavailable,
    /// The configured source is a URL that cannot be parsed. Never retried and
    /// never resolved from cache — this one is a typo, and saying so beats
    /// silently serving yesterday's list.
    InvalidBlocklistUrl,
};

/// Attempts made before falling back to the cache, counting the first.
///
/// Three, not more: past a couple of tries the cache is a better answer than a
/// longer wait, because startup is blocked the whole time. With the schedule
/// below the worst case adds ~3 s before the fallback, which is invisible next
/// to the ~25 s two real list fetches cost anyway.
const max_attempts: u32 = 3;

/// Ceiling on the delay between fetch attempts. Far below the supervisor's 30 s
/// because this runs on the startup path, where the whole process is waiting.
const retry_cap_s: i64 = 8;

pub const Options = struct {
    source: Source,
    /// Directory holding the on-disk cache, or null to disable it. Created on
    /// demand — an operator should not have to `mkdir` before first run.
    cache_dir: ?[]const u8,
    /// This list's filename inside `cache_dir`. Distinct per list, since both
    /// share the directory.
    cache_name: []const u8,
    /// What to call this list in diagnostics: "blocklist", "suffix blocklist".
    what: []const u8,
};

/// Fills `body` with the list's bytes, by whatever route works.
///
/// `body` is left holding exactly what the parser should see. On the cached
/// route that includes the provenance header, which is deliberate: it is a `#`
/// comment, both list grammars already skip those, and keeping it means the
/// cache file on disk is a valid list rather than a format only this file reads.
pub fn acquire(
    gpa: std.mem.Allocator,
    io: std.Io,
    http_client: *std.http.Client,
    opts: Options,
    body: *std.Io.Writer.Allocating,
) !Outcome {
    const url = switch (opts.source) {
        // Local files bypass the network, the retries and the cache entirely.
        // `readFileInto` already carries the fail-loud contract and the
        // diagnostics this case wants.
        .path => |path| {
            try readFileInto(body, io, gpa, path, opts.what);
            return .fresh;
        },
        .url => |url| url,
    };

    // Parsed once, up front, so a typo'd URL fails immediately and by name
    // instead of being retried three times on its way to a fallback. This is
    // the one fetch failure that is definitely not transient.
    _ = std.Uri.parse(url) catch {
        log.err("{s} source '{s}' is not a valid URL", .{ opts.what, url });
        return error.InvalidBlocklistUrl;
    };

    if (try fetchWithRetry(io, http_client, url, opts, body)) {
        // Best-effort: a list we cannot cache is still a list we can serve, so a
        // read-only or full disk degrades the *next* startup, not this one.
        writeCache(io, opts, url, body.written()) catch |err| {
            log.warn("could not cache {s}: {s}", .{ opts.what, @errorName(err) });
        };
        return .fresh;
    }

    // Every attempt failed. A partially-written body from the last one would
    // otherwise be parsed as a truncated list — a blocklist that loads clean and
    // blocks a random prefix of what it should.
    body.clearRetainingCapacity();

    if (try readCache(gpa, io, opts, url, body)) |age_s| {
        log.warn("{s}: fetch failed, using cached copy from {d}h ago", .{
            opts.what,
            @divTrunc(age_s, std.time.s_per_hour),
        });
        return .cached;
    }

    log.err("{s} '{s}' could not be fetched and no usable cache exists", .{ opts.what, url });
    return error.BlocklistUnavailable;
}

/// Returns true if some attempt succeeded, leaving the body filled.
///
/// Never returns a hard error for a failed fetch: the caller has a fallback, and
/// deciding between "retry", "fall back" and "give up" is this function's whole
/// job. It only propagates cancellation, from the sleep between attempts.
fn fetchWithRetry(
    io: std.Io,
    http_client: *std.http.Client,
    url: []const u8,
    opts: Options,
    body: *std.Io.Writer.Allocating,
) std.Io.Cancelable!bool {
    var attempt: u32 = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        const delay_s = backoff.seconds(attempt, retry_cap_s);
        if (delay_s > 0) try io.sleep(std.Io.Duration.fromSeconds(delay_s), std.Io.Clock.boot);

        // Each attempt starts from an empty body. A retry that appended to a
        // half-received response would concatenate two partial lists into one
        // corrupt one — and it would parse, which is what makes it dangerous.
        body.clearRetainingCapacity();

        const res = http_client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &body.writer,
        }) catch |err| {
            // Every non-URL failure here is a network condition — connection
            // refused, TLS handshake, a truncated read — and every one of those
            // is worth another try. The URL itself was validated before the loop.
            log.warn("{s} fetch of '{s}' failed (attempt {d}/{d}): {s}", .{
                opts.what, url, attempt + 1, max_attempts, @errorName(err),
            });
            continue;
        };

        if (res.status == .ok) return true;

        if (!retryableStatus(res.status)) {
            log.err("{s} fetch of '{s}': HTTP {d}, not retrying", .{
                opts.what, url, @intFromEnum(res.status),
            });
            return false;
        }

        log.warn("{s} fetch of '{s}': HTTP {d} (attempt {d}/{d})", .{
            opts.what, url, @intFromEnum(res.status), attempt + 1, max_attempts,
        });
    }
    return false;
}

/// Whether another attempt could plausibly succeed.
///
/// Server errors are the transient case by definition. 429 is the one client
/// error worth retrying and the reason this distinction exists at all: oisd.nl
/// rate-limits per IP, so a handful of quick restarts used to leave Vortex
/// unable to start. Everything else in the 4xx range — 404 for a list that
/// moved, 403 for one that now needs auth — is a configuration problem that a
/// retry cannot fix and a *cache* can, which is where the caller takes it next.
pub fn retryableStatus(status: std.http.Status) bool {
    if (status == .too_many_requests) return true;
    return status.class() == .server_error;
}

// ── On-disk cache ─────────────────────────────────────────────────────────

/// Marks a file as ours and records what it is a copy of.
///
/// It is a `#` comment because both list grammars skip those, so the header
/// costs nothing on the read path and the cache file stays a valid blocklist —
/// one an operator can point `VORTEX_BLOCKLIST_SOURCE` straight at.
const header_prefix = "# vortex-cache v1 ";

/// A cache whose recorded source does not match the configured one is ignored.
///
/// This is the case that would otherwise be silent and wrong: an operator
/// switches to a different list, the new URL is down on the next restart, and a
/// cache keyed only by filename hands back the *old provider's* list while the
/// config plainly says otherwise. Recording the source makes that a miss.
const CacheHeader = struct {
    source: []const u8,
    fetched_unix_s: i64,

    /// Parses the first line of a cache file. Pure over a byte slice, which is
    /// what lets the format be tested against literals with no file involved.
    fn parse(first_line: []const u8) ?CacheHeader {
        const line = std.mem.trimEnd(u8, first_line, "\r");
        if (!std.mem.startsWith(u8, line, header_prefix)) return null;

        var fields = std.mem.tokenizeScalar(u8, line[header_prefix.len..], ' ');

        const source_field = fields.next() orelse return null;
        if (!std.mem.startsWith(u8, source_field, "source=")) return null;

        const fetched_field = fields.next() orelse return null;
        if (!std.mem.startsWith(u8, fetched_field, "fetched=")) return null;

        const fetched = std.fmt.parseInt(i64, fetched_field["fetched=".len..], 10) catch return null;

        return .{
            .source = source_field["source=".len..],
            .fetched_unix_s = fetched,
        };
    }
};

/// Renders the header line, without its newline.
///
/// A URL containing a space would produce a header that parses back with a
/// truncated source and therefore never matches — a cache that is written and
/// never read. Spaces are not legal in a URL, and `Uri.parse` has already
/// rejected the value by the time this runs, so the case cannot arise; the
/// assertion is here so that stays true if the caller order ever changes.
fn formatHeader(buf: []u8, source: []const u8, fetched_unix_s: i64) ![]u8 {
    std.debug.assert(std.mem.indexOfScalar(u8, source, ' ') == null);
    return std.fmt.bufPrint(buf, header_prefix ++ "source={s} fetched={d}", .{
        source,
        fetched_unix_s,
    });
}

/// Writes `contents` to the cache, header first, replacing any previous copy.
///
/// Written through `createFileAtomic`/`replace` rather than a plain create, so a
/// process killed mid-write leaves the previous cache intact instead of a
/// truncated file that would load clean and block a random prefix of the list.
fn writeCache(
    io: std.Io,
    opts: Options,
    url: []const u8,
    contents: []const u8,
) !void {
    const dir_path = opts.cache_dir orelse return;

    var header_buf: [2048]u8 = undefined;
    const header = try formatHeader(&header_buf, url, nowUnixSeconds(io));

    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, dir_path, .{});
    defer dir.close(io);

    var atomic = try dir.createFileAtomic(io, opts.cache_name, .{ .replace = true });
    defer atomic.deinit(io);

    var write_buf: [4096]u8 = undefined;
    var writer = atomic.file.writer(io, &write_buf);
    try writer.interface.writeAll(header);
    try writer.interface.writeAll("\n");
    try writer.interface.writeAll(contents);
    try writer.interface.flush();

    try atomic.replace(io);
}

/// Appends the cached copy to `body` and returns its age in seconds, or null if
/// there is no usable cache.
///
/// "Usable" means present, readable, and recorded against `url`. A stale cache
/// is still usable: there is deliberately no maximum age, because the
/// alternative to a month-old blocklist is no blocklist, and the age is logged
/// so an operator can see which they are getting.
fn readCache(
    gpa: std.mem.Allocator,
    io: std.Io,
    opts: Options,
    url: []const u8,
    body: *std.Io.Writer.Allocating,
) !?i64 {
    const dir_path = opts.cache_dir orelse return null;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, opts.cache_name }) catch
        return null;

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(Settings.max_blocklist_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => {
            log.warn("cannot read cached {s} '{s}': {s}", .{ opts.what, path, @errorName(err) });
            return null;
        },
    };
    defer gpa.free(bytes);

    const newline = std.mem.indexOfScalar(u8, bytes, '\n') orelse bytes.len;
    const header = CacheHeader.parse(bytes[0..newline]) orelse {
        log.warn("cached {s} '{s}' is not a vortex cache file; ignoring", .{ opts.what, path });
        return null;
    };

    if (!std.mem.eql(u8, header.source, url)) {
        log.warn(
            "cached {s} '{s}' was fetched from '{s}', not '{s}'; ignoring",
            .{ opts.what, path, header.source, url },
        );
        return null;
    }

    try body.writer.writeAll(bytes);
    return @max(0, nowUnixSeconds(io) - header.fetched_unix_s);
}

/// Wall-clock seconds since the Unix epoch.
///
/// `.real`, not the `.boot` clock the datapath measures deadlines on: this
/// number is written to disk and read back by a *later process*, so it has to
/// mean the same thing across restarts, which a monotonic clock does not.
fn nowUnixSeconds(io: std.Io) i64 {
    const ns = std.Io.Timestamp.now(io, std.Io.Clock.real).nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_s));
}

const testing = std.testing;

test "a written header parses back" {
    var buf: [256]u8 = undefined;
    const line = try formatHeader(&buf, "https://example.com/hosts", 1_757_000_000);

    // Against the literal bytes, not against a recomputed format string: that
    // is what catches a header whose writer and reader agree with each other
    // and with nothing else.
    try testing.expectEqualStrings(
        "# vortex-cache v1 source=https://example.com/hosts fetched=1757000000",
        line,
    );

    const parsed = CacheHeader.parse(line) orelse return error.HeaderDidNotParse;
    try testing.expectEqualStrings("https://example.com/hosts", parsed.source);
    try testing.expectEqual(@as(i64, 1_757_000_000), parsed.fetched_unix_s);
}

test "the header survives a CRLF round trip" {
    // A cache file edited on Windows, or copied through something that rewrites
    // line endings, must not become unreadable — the failure would be a silent
    // "no usable cache" on exactly the day the network is down.
    const parsed = CacheHeader.parse(
        "# vortex-cache v1 source=https://example.com/hosts fetched=42\r",
    ) orelse return error.HeaderDidNotParse;

    try testing.expectEqualStrings("https://example.com/hosts", parsed.source);
    try testing.expectEqual(@as(i64, 42), parsed.fetched_unix_s);
}

test "a header that is not ours does not parse" {
    // An ordinary hosts file, which is what a cache directory would contain if
    // someone pointed the setting at the wrong directory.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse("0.0.0.0 ads.example.com"));

    // A plain comment: has the '#', has none of the rest.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse("# just a comment"));

    // Ours, but a future version. Refusing to parse is the right failure: a v2
    // that changed the field order would otherwise be misread as v1.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse(
        "# vortex-cache v2 source=https://example.com/hosts fetched=42",
    ));
}

test "a malformed header does not parse" {
    // Fields present but transposed — the reader must not accept fields by
    // position alone.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse(
        "# vortex-cache v1 fetched=42 source=https://example.com/hosts",
    ));

    // Truncated: header and source, no timestamp. This is what a cache file
    // killed mid-write would look like if the write were not atomic.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse(
        "# vortex-cache v1 source=https://example.com/hosts",
    ));

    // A timestamp that is not a number, which would otherwise become a wildly
    // wrong age in the log line an operator uses to judge the cache.
    try testing.expectEqual(@as(?CacheHeader, null), CacheHeader.parse(
        "# vortex-cache v1 source=https://example.com/hosts fetched=yesterday",
    ));
}

test "retryable statuses are the transient ones" {
    // The case this whole distinction exists for: oisd.nl rate-limits per IP,
    // and a handful of quick restarts used to leave Vortex unable to start.
    try testing.expect(retryableStatus(.too_many_requests));

    try testing.expect(retryableStatus(.internal_server_error));
    try testing.expect(retryableStatus(.bad_gateway));
    try testing.expect(retryableStatus(.service_unavailable));
    try testing.expect(retryableStatus(.gateway_timeout));

    // A list that moved or now needs auth. Retrying cannot fix either, and the
    // cache is the right next step — so these must NOT be retryable, or startup
    // spends the backoff schedule on a certainty before falling back.
    try testing.expect(!retryableStatus(.not_found));
    try testing.expect(!retryableStatus(.forbidden));
    try testing.expect(!retryableStatus(.unauthorized));

    // 429 is retryable and its neighbours are not, which pins that the rule is
    // that one status rather than a range around it.
    try testing.expect(!retryableStatus(.too_early));
    try testing.expect(!retryableStatus(.request_header_fields_too_large));
}

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Outcome);
    testing.refAllDecls(Options);
    testing.refAllDecls(CacheHeader);
}
