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

    pub fn init(
        client_socket: *const std.Io.net.Socket,
        upstream_socket: *const std.Io.net.Socket,
        upstream_addr: std.Io.net.IpAddress,
        pending_table: *PendingTable,
        policy: *Policy,
    ) Context {
        return .{
            .client_socket = client_socket,
            .upstream_socket = upstream_socket,
            .upstream_addr = upstream_addr,
            .pending_table = pending_table,
            .policy = policy,
        };
    }
};
