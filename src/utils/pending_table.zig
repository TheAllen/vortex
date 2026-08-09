const std = @import("std");

pub const PendingQuery = struct {
    client_id: u16,
    client_addr: std.Io.net.IpAddress,
    /// ns since the epoch, from `std.Io.Timestamp.now(io, .real)` — the same
    /// clock and unit the sweeper compares against. Not ms, and not since boot:
    /// a unit mismatch here is exactly what bug B1 was.
    expires_at: i64,
};

/// PendingTable is responsible for holding DNS queries that have been sent to upstream resolver.
/// It serves as a source of truth for DNS queries inflight.
/// It serves for DNS packet spoofing.
pub const PendingTable = struct {
    map: std.AutoHashMap(u16, PendingQuery),
    mutex: std.Io.Mutex,
    rng: std.Random.DefaultPrng,
    gpa: std.mem.Allocator,
    io: std.Io,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, seed: u64) PendingTable {
        return PendingTable{
            .map = std.AutoHashMap(u16, PendingQuery).init(gpa),
            .mutex = std.Io.Mutex.init,
            .rng = std.Random.DefaultPrng.init(seed),
            .gpa = gpa,
            .io = io,
        };
    }

    pub fn deinit(self: *PendingTable) void {
        self.map.deinit();
    }

    pub fn appendQuery(self: *PendingTable, pending_query: PendingQuery) !u16 {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        if (self.map.count() > std.math.maxInt(u16)) return error.IdSpaceExhausted;

        var attempts: u16 = 0;
        while (attempts < 16) : (attempts += 1) {
            const proxy_id: u16 = self.rng.random().int(u16);
            const entry = try self.map.getOrPut(proxy_id);
            if (!entry.found_existing) {
                entry.value_ptr.* = pending_query;
                return proxy_id;
            }
        }

        // Rare: keep scanning linearly
        const base = self.rng.random().int(u16);
        var id: u32 = 0;
        while (id <= std.math.maxInt(u16)) : (id += 1) {
            const proxy_id: u16 = base +% @as(u16, @truncate(id));
            const entry = try self.map.getOrPut(proxy_id);
            if (!entry.found_existing) {
                entry.value_ptr.* = pending_query;
                return proxy_id;
            }
        }

        return error.IdSpaceExhausted;
    }

    /// Attempts to acquire a mutex then fetchRemove a entry by proxy_id
    pub fn complete(self: *PendingTable, proxy_id: u16) ?PendingQuery {
        self.mutex.lock(self.io) catch {
            std.log.err("Failed to acquire lock while completing pending query...", .{});
            return null;
        };
        defer self.mutex.unlock(self.io);

        if (self.map.fetchRemove(proxy_id)) |query| {
            return query.value;
        }

        return null;
    }

    pub fn sweepExpiredQueries(self: *PendingTable) void {
        self.mutex.lock(self.io) catch {
            std.log.err("Failed to acquire lock on sweeper loop...", .{});
            return;
        };
        defer self.mutex.unlock(self.io);

        const now: i64 = @truncate(std.Io.Timestamp.now(self.io, std.Io.Clock.real).nanoseconds);
        var dead_queries = std.ArrayList(u16).initCapacity(self.gpa, 64) catch {
            std.log.err("Failed to initialize dead query array list...", .{});
            return;
        };
        defer dead_queries.deinit(self.gpa);

        var pending_iter = self.map.iterator();
        while (pending_iter.next()) |entry| {
            if (entry.value_ptr.expires_at <= now) {
                dead_queries.append(self.gpa, entry.key_ptr.*) catch break;
            }
        }
        for (dead_queries.items) |id| {
            _ = self.map.remove(id);
        }
    }
};
