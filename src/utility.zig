const std = @import("std");

const DomainBlockList = @import("blocklist/domain_blocklist.zig").DomainBlockList;
const PendingTable = @import("utils/pending_table.zig").PendingTable;
const Policy = @import("blocklist/policy.zig").Policy;
const Cache = @import("dns/cache.zig").Cache;
const Settings = @import("settings.zig").Settings;
const ConnTable = @import("utils/conn_table.zig").ConnTable;
const edns = @import("dns/edns.zig");

/// The TCP listener and its connection table (P3.6), or absent when
/// `VORTEX_MAX_TCP_CONNS=0`.
pub const Tcp = struct {
    server: *std.Io.net.Server,
    conns: *ConnTable,
};

/// Everything `refresherLoop` needs that the datapath does not.
///
/// Bundled behind one pointer rather than spread across five `Context` fields:
/// only one loop reads any of it, and `LoopFn` is a fixed signature, so the
/// alternative is widening the struct every coroutine shares for the benefit of
/// the one that refreshes lists.
///
/// Both members outlive the loop — the client sits on `main`'s frame with a
/// deferred `deinit`, and `Settings` borrows the process environment map, which
/// is never torn down.
pub const Refresher = struct {
    /// `std.http.Client.fetch` documents itself as threadsafe, which is what
    /// lets the refresher share the client startup already built rather than
    /// standing up a second one.
    http_client: *std.http.Client,
    cfg: *const Settings,
};

pub const Context = struct {
    client_socket: *const std.Io.net.Socket = undefined,
    upstream_socket: *const std.Io.net.Socket = undefined,
    upstream_addr: std.Io.net.IpAddress = undefined,
    pending_table: *PendingTable = undefined,
    policy: *Policy = undefined,
    /// TTL-aware response cache (P3.3). Null when caching is disabled, which is
    /// an option rather than an edge case: it is the first thing to turn off
    /// when diagnosing a stale-answer complaint.
    cache: ?*Cache = null,

    /// Long-lived allocator. Carried here so every background loop has the same
    /// `fn (Io, *const Context)` shape and can go through one supervisor.
    gpa: std.mem.Allocator = undefined,

    /// Per-process seed for `hashQuestion`. Drawn from `io.random` at startup so
    /// a colliding question cannot be precomputed offline against a fixed seed.
    question_seed: u64 = 0,

    /// What `refresherLoop` needs, or null when periodic refresh is disabled
    /// (`VORTEX_BLOCKLIST_REFRESH_SECS=0`). Null is also the state every other
    /// coroutine sees it in — nothing on the datapath reads this.
    refresh: ?*const Refresher = null,

    /// Null when TCP is disabled. The accept loop reads the server; the
    /// sweeper reads the table, to end idle connections.
    tcp: ?*const Tcp = null,

    /// The UDP payload size we advertise in our own OPT records, and the most
    /// a forwarded query may advertise on a client's behalf (P3.5): 1232 with a
    /// TCP listener to retry against, our 4096 buffer without one.
    edns_udp_size: u16 = edns.advertised_udp_size,

    pub fn init(
        client_socket: *const std.Io.net.Socket,
        upstream_socket: *const std.Io.net.Socket,
        upstream_addr: std.Io.net.IpAddress,
        pending_table: *PendingTable,
        policy: *Policy,
        cache: ?*Cache,
        gpa: std.mem.Allocator,
        question_seed: u64,
        refresh: ?*const Refresher,
    ) Context {
        return .{
            .client_socket = client_socket,
            .upstream_socket = upstream_socket,
            .upstream_addr = upstream_addr,
            .pending_table = pending_table,
            .policy = policy,
            .cache = cache,
            .gpa = gpa,
            .question_seed = question_seed,
            .refresh = refresh,
        };
    }
};

// One line of guard per container. `refAllDecls` is shallow and 0.16.0 has no
// recursive variant, so a type that is not named here has its methods left
// unanalysed — see resource_record.zig, where exactly that let a `pub fn` ship
// broken through four merged PRs and CI.
test "refAllDecls" {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(Context);
    std.testing.refAllDecls(Refresher);
    std.testing.refAllDecls(Tcp);
}
