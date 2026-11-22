//! Which client addresses Vortex answers (P2.7): `VORTEX_ALLOW_CLIENTS`.
//!
//! Vortex is meant for a home network. Behind a home router's NAT, nothing on
//! the internet can reach it over IPv4. Over IPv6 the host usually has a
//! globally routable address, so whether port 53 is reachable from outside
//! depends only on the router's IPv6 firewall. This list makes "home network
//! only" something Vortex enforces itself.
//!
//! **One address space.** Every range is stored as an IPv6 prefix, with IPv4
//! ranges held as IPv4-mapped (`::ffff:a.b.c.d`, prefix + 96). An IPv4 client
//! is mapped the same way before matching. That is what makes a dual-stack
//! `::` listener work: it sees IPv4 clients as `::ffff:a.b.c.d` already, and
//! those match the IPv4 ranges with no special case.
//!
//! Not to be confused with [blocklist/allowlist.zig](../blocklist/allowlist.zig),
//! which is about *domain names* that are never blocked.

const std = @import("std");

const IpAddress = std.Io.net.IpAddress;

/// One prefix in the unified IPv6 address space.
pub const Range = struct {
    /// Network address, with every bit past `prefix_len` zeroed.
    bytes: [16]u8,
    /// 0..128.
    prefix_len: u8,

    pub fn contains(self: Range, addr: [16]u8) bool {
        const full = self.prefix_len / 8;
        if (!std.mem.eql(u8, self.bytes[0..full], addr[0..full])) return false;
        const rem: u3 = @intCast(self.prefix_len % 8);
        if (rem == 0) return true;
        const mask: u8 = @as(u8, 0xFF) << @intCast(8 - @as(u4, rem));
        return (addr[full] & mask) == self.bytes[full];
    }

    /// Builds a range with its host bits cleared, so `192.168.1.7/24` is
    /// stored, and matches, exactly like `192.168.1.0/24`.
    fn init(bytes: [16]u8, prefix_len: u8) Range {
        var masked = bytes;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const bit_start = i * 8;
            if (bit_start >= prefix_len) {
                masked[i] = 0;
            } else if (bit_start + 8 > prefix_len) {
                const keep: u4 = @intCast(prefix_len - bit_start);
                masked[i] &= @as(u8, 0xFF) << @intCast(8 - keep);
            }
        }
        return .{ .bytes = masked, .prefix_len = prefix_len };
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) Range {
        return init(mapped(.{ a, b, c, d }), prefix_len + 96);
    }

    fn v6(bytes: [16]u8, prefix_len: u8) Range {
        return init(bytes, prefix_len);
    }
};

/// `::ffff:a.b.c.d`.
fn mapped(v4: [4]u8) [16]u8 {
    return [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF } ++ v4;
}

/// A client address in the unified space. Port, flow and scope are irrelevant
/// to whether an address is ours, so only the bytes are kept.
pub fn unified(addr: IpAddress) [16]u8 {
    return switch (addr) {
        .ip4 => |a| mapped(a.bytes),
        .ip6 => |a| a.bytes,
    };
}

pub const AllowedClients = struct {
    ranges: [max_ranges]Range = undefined,
    len: usize = 0,
    /// `any` was in the list: every client is allowed and `ranges` is unused.
    any: bool = false,

    /// Enough for `local` plus a generous number of the operator's own. A cap
    /// rather than an allocation, so `Settings` can stay a plain value that
    /// owns nothing.
    pub const max_ranges = 32;

    /// What `local` expands to: everything a home network's clients can be,
    /// and nothing the internet can.
    pub const local_ranges = [_]Range{
        Range.v4(127, 0, 0, 0, 8), // loopback
        Range.v4(10, 0, 0, 0, 8), // RFC 1918
        Range.v4(172, 16, 0, 0, 12), // RFC 1918
        Range.v4(192, 168, 0, 0, 16), // RFC 1918
        Range.v4(169, 254, 0, 0, 16), // link-local
        Range.v4(100, 64, 0, 0, 10), // CGNAT (RFC 6598), e.g. behind a carrier or a VPN overlay
        Range.v6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 128), // ::1
        Range.v6(.{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 10), // fe80::/10 link-local
        Range.v6(.{ 0xFC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 7), // fc00::/7 ULA
    };

    /// The default: `VORTEX_ALLOW_CLIENTS=local`.
    pub const local: AllowedClients = blk: {
        var self: AllowedClients = .{};
        for (local_ranges) |r| {
            self.ranges[self.len] = r;
            self.len += 1;
        }
        break :blk self;
    };

    pub const ParseError = error{
        /// An item that is not `local`, `any`, an address, or `address/len`.
        InvalidRange,
        /// More than `max_ranges` ranges after `local` is expanded.
        TooManyRanges,
        /// Nothing but separators. Would deny every client, which is a typo,
        /// not a configuration.
        EmptyList,
    };

    /// Parses a comma-separated list. Each item is `local`, `any`, an address
    /// (one host), or `address/prefix-length`. Whitespace around items is
    /// ignored, and so are empty items.
    ///
    /// On error, `bad` (when given) is set to the offending item, so the
    /// caller can name it rather than repeating the whole value back.
    pub fn parse(raw: []const u8, bad: ?*[]const u8) ParseError!AllowedClients {
        var self: AllowedClients = .{};
        var saw_item = false;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |item_raw| {
            const item = std.mem.trim(u8, item_raw, " \t");
            if (item.len == 0) continue;
            saw_item = true;
            errdefer if (bad) |b| {
                b.* = item;
            };

            if (std.ascii.eqlIgnoreCase(item, "any")) {
                self.any = true;
            } else if (std.ascii.eqlIgnoreCase(item, "local")) {
                for (local_ranges) |r| try self.append(r);
            } else {
                try self.append(try parseRange(item));
            }
        }
        if (!saw_item) return error.EmptyList;
        return self;
    }

    fn append(self: *AllowedClients, r: Range) ParseError!void {
        if (self.len == max_ranges) return error.TooManyRanges;
        self.ranges[self.len] = r;
        self.len += 1;
    }

    pub fn allows(self: *const AllowedClients, addr: IpAddress) bool {
        if (self.any) return true;
        const bytes = unified(addr);
        for (self.ranges[0..self.len]) |r| {
            if (r.contains(bytes)) return true;
        }
        return false;
    }
};

fn parseRange(item: []const u8) AllowedClients.ParseError!Range {
    const slash = std.mem.findScalar(u8, item, '/');
    const addr_text = if (slash) |i| item[0..i] else item;

    // `IpAddress.parse` tries IPv4 first, then IPv6, and refuses an IPv6 scope
    // (`%eth0`), which has no meaning in a range.
    const addr = IpAddress.parse(addr_text, 0) catch return error.InvalidRange;
    const max_len: u8 = switch (addr) {
        .ip4 => 32,
        .ip6 => 128,
    };
    const len: u8 = if (slash) |i|
        std.fmt.parseInt(u8, item[i + 1 ..], 10) catch return error.InvalidRange
    else
        max_len;
    if (len > max_len) return error.InvalidRange;

    return switch (addr) {
        .ip4 => |a| Range.init(mapped(a.bytes), len + 96),
        .ip6 => |a| Range.init(a.bytes, len),
    };
}

/// The allowlist, plus a record of who it turned away.
///
/// Shared by the UDP ingress loop and the TCP accept loop. Drops are not
/// logged one by one, which would spend stderr at whatever rate a scanner
/// sends. The sweeper calls `takeDenied` once a second instead, and the last
/// address is kept so that line can say who was dropped. That is what an
/// operator needs to spot a LAN client the list misses, such as one querying
/// from a global IPv6 address.
pub const Gate = struct {
    allowed: AllowedClients,
    mutex: std.Io.Mutex = .init,
    /// Guarded by `mutex`. Only touched on the denied path, so an allowed
    /// query never takes the lock.
    denied: u64 = 0,
    last_denied: ?IpAddress = null,

    pub const Denied = struct {
        count: u64,
        last: ?IpAddress,
    };

    pub fn init(allowed: AllowedClients) Gate {
        return .{ .allowed = allowed };
    }

    /// True when `from` may be answered. A denial is counted.
    pub fn admit(self: *Gate, io: std.Io, from: IpAddress) bool {
        if (self.allowed.allows(from)) return true;
        // A cancelled lock still denies: the count is a diagnostic, the
        // decision is not.
        self.mutex.lock(io) catch return false;
        defer self.mutex.unlock(io);
        self.denied += 1;
        self.last_denied = from;
        return false;
    }

    /// Returns what was denied since the last call, and resets it.
    pub fn takeDenied(self: *Gate, io: std.Io) Denied {
        self.mutex.lock(io) catch return .{ .count = 0, .last = null };
        defer self.mutex.unlock(io);
        const out: Denied = .{ .count = self.denied, .last = self.last_denied };
        self.denied = 0;
        self.last_denied = null;
        return out;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────────

const testing = std.testing;

fn ip(text: []const u8) IpAddress {
    return IpAddress.parse(text, 0) catch unreachable;
}

test "local allows every home-network range and nothing public" {
    const l = AllowedClients.local;

    // One address inside each local range, including both edges of the
    // smaller ones, so a range one bit too narrow fails here.
    for ([_][]const u8{
        "127.0.0.1",       "127.255.255.255", "10.1.2.3",
        "172.16.0.1",      "172.31.255.255",  "192.168.1.20",
        "169.254.10.10",   "100.64.0.1",      "100.127.255.255",
        "::1",             "fe80::1",         "febf:ffff::1",
        "fd12:3456::1",    "fc00::1",
    }) |text| {
        if (!l.allows(ip(text))) {
            std.debug.print("expected {s} to be local\n", .{text});
            return error.TestExpectedEqual;
        }
    }

    // Just outside each range's edge, plus ordinary public addresses in both
    // families. `2600:...` is the shape of a home client's global IPv6 address,
    // which `local` deliberately does not cover.
    for ([_][]const u8{
        "172.15.255.255", "172.32.0.0",  "192.169.0.1",
        "100.63.255.255", "100.128.0.0", "1.1.1.1",
        "8.8.8.8",        "::2",         "fec0::1",
        "fe00::1",        "fe7f::1",     "2600:4040:912f:bb00::1",
        "::",
    }) |text| {
        if (l.allows(ip(text))) {
            std.debug.print("expected {s} not to be local\n", .{text});
            return error.TestExpectedEqual;
        }
    }
}

test "an IPv4 client on a dual-stack listener matches the IPv4 ranges" {
    // What a `::` listener hands us for an IPv4 client.
    const l = AllowedClients.local;
    try testing.expect(l.allows(ip("::ffff:192.168.1.20")));
    try testing.expect(l.allows(ip("::ffff:127.0.0.1")));
    try testing.expect(!l.allows(ip("::ffff:8.8.8.8")));

    // And the other way round: a plain IPv4 range must match its mapped form
    // and its plain form identically.
    const custom = try AllowedClients.parse("203.0.113.0/24", null);
    try testing.expect(custom.allows(ip("203.0.113.9")));
    try testing.expect(custom.allows(ip("::ffff:203.0.113.9")));
    try testing.expect(!custom.allows(ip("203.0.114.9")));
}

test "parse expands local, adds ranges after it, and masks host bits" {
    const a = try AllowedClients.parse(" local , 2600:4040:912f:bb00::/56,192.0.2.7/24 ", null);
    try testing.expectEqual(AllowedClients.local_ranges.len + 2, a.len);
    try testing.expect(a.allows(ip("127.0.0.1")));
    try testing.expect(a.allows(ip("2600:4040:912f:bbff::1")));
    try testing.expect(!a.allows(ip("2600:4040:912f:bc00::1")));
    // `192.0.2.7/24` is stored as `192.0.2.0/24`.
    try testing.expect(a.allows(ip("192.0.2.200")));
    try testing.expect(!a.allows(ip("192.0.3.1")));
}

test "a bare address is one host, and a prefix that is not a byte boundary still works" {
    const host = try AllowedClients.parse("192.0.2.1", null);
    try testing.expect(host.allows(ip("192.0.2.1")));
    try testing.expect(!host.allows(ip("192.0.2.2")));

    // /20: the boundary falls inside the third byte.
    const net = try AllowedClients.parse("198.51.96.0/20", null);
    try testing.expect(net.allows(ip("198.51.111.255")));
    try testing.expect(!net.allows(ip("198.51.112.0")));
    try testing.expect(!net.allows(ip("198.51.95.255")));
}

test "a list without local does not allow loopback" {
    // Pins that `local` is only the *default*: an operator who names their own
    // ranges gets exactly those.
    const only = try AllowedClients.parse("10.0.0.0/8", null);
    try testing.expect(!only.allows(ip("127.0.0.1")));
    try testing.expect(!only.allows(ip("::1")));
    try testing.expect(only.allows(ip("10.9.9.9")));
}

test "any allows everything, whatever else is listed" {
    const a = try AllowedClients.parse("10.0.0.0/8, ANY", null);
    try testing.expect(a.allows(ip("8.8.8.8")));
    try testing.expect(a.allows(ip("2001:db8::1")));
}

test "parse rejects malformed items and names the one it rejected" {
    var bad: []const u8 = "";
    try testing.expectError(error.InvalidRange, AllowedClients.parse("local, 10.0.0.0/33", &bad));
    try testing.expectEqualStrings("10.0.0.0/33", bad);

    try testing.expectError(error.InvalidRange, AllowedClients.parse("::/129", &bad));
    try testing.expectError(error.InvalidRange, AllowedClients.parse("lan", &bad));
    try testing.expectEqualStrings("lan", bad);
    try testing.expectError(error.InvalidRange, AllowedClients.parse("10.0.0.0/", &bad));
    try testing.expectError(error.InvalidRange, AllowedClients.parse("10.0.0.0/x", &bad));
    try testing.expectError(error.InvalidRange, AllowedClients.parse("fe80::1%en0", &bad));
    try testing.expectError(error.EmptyList, AllowedClients.parse(" , ,", &bad));
}

test "parse refuses more ranges than it can hold" {
    // `local` four times is 36 ranges against a cap of 32.
    try testing.expectError(error.TooManyRanges, AllowedClients.parse("local,local,local,local", null));
}

test "Gate counts denials, keeps the last address, and resets on take" {
    var gate = Gate.init(try AllowedClients.parse("10.0.0.0/8", null));
    const io = testing.io;

    try testing.expect(gate.admit(io, ip("10.0.0.1")));
    try testing.expect(!gate.admit(io, ip("192.0.2.1")));
    try testing.expect(!gate.admit(io, ip("2001:db8::5")));
    // An allowed client is not counted.
    try testing.expect(gate.admit(io, ip("10.0.0.2")));

    const first = gate.takeDenied(io);
    try testing.expectEqual(@as(u64, 2), first.count);
    try testing.expectEqualSlices(u8, &unified(ip("2001:db8::5")), &unified(first.last.?));

    const second = gate.takeDenied(io);
    try testing.expectEqual(@as(u64, 0), second.count);
    try testing.expect(second.last == null);
}

test "refAllDecls" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Range);
    testing.refAllDecls(AllowedClients);
    testing.refAllDecls(Gate);
}
