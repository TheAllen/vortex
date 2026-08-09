const std = @import("std");

const DomainBlockList = @import("blocklist/domain_blocklist.zig").DomainBlockList;
const PendingTable = @import("utils/pending_table.zig").PendingTable;
const Policy = @import("blocklist/policy.zig").Policy;

pub const Context = struct {
    client_socket: *const std.Io.net.Socket = undefined,
    upstream_socket: *const std.Io.net.Socket = undefined,
    upstream_addr: std.Io.net.IpAddress = undefined,
    pending_table: *PendingTable = undefined,
    policy: *Policy = undefined,

    /// Long-lived allocator. Carried here so every background loop has the same
    /// `fn (Io, *const Context)` shape and can go through one supervisor.
    gpa: std.mem.Allocator = undefined,

    /// Per-process seed for `hashQuestion`. Drawn from `io.random` at startup so
    /// a colliding question cannot be precomputed offline against a fixed seed.
    question_seed: u64 = 0,

    pub fn init(
        client_socket: *const std.Io.net.Socket,
        upstream_socket: *const std.Io.net.Socket,
        upstream_addr: std.Io.net.IpAddress,
        pending_table: *PendingTable,
        policy: *Policy,
        gpa: std.mem.Allocator,
        question_seed: u64,
    ) Context {
        return .{
            .client_socket = client_socket,
            .upstream_socket = upstream_socket,
            .upstream_addr = upstream_addr,
            .pending_table = pending_table,
            .policy = policy,
            .gpa = gpa,
            .question_seed = question_seed,
        };
    }
};
