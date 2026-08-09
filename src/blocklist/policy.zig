const std = @import("std");

const AllowList = @import("../blocklist/allowlist.zig").AllowList;
const DomainBlockList = @import("../blocklist/domain_blocklist.zig").DomainBlockList;
const SuffixBlockList = @import("../blocklist/suffix_blocklist.zig").SuffixBlockList;

pub const Verdict = enum {
    /// Explicitly permit; short-circuits later filters in a chain.
    allow,
    /// Explicitly block; caller synthesizes the NXDOMAIN response.
    block,
    /// No opinion; defer to the next filter (or default-allow if none left).
    pass,
};

/// Policy encapsulates AllowList, DomainBlockList, and SuffixBlockList
pub const Policy = struct {
    allow_list: AllowList,
    domain_blocklist: DomainBlockList,
    suffix_blocklist: SuffixBlockList,

    pub fn init(gpa: std.mem.Allocator) Policy {
        return Policy{
            .allow_list = .{},
            .domain_blocklist = DomainBlockList.init(std.Io.Writer.Allocating.init(gpa)),
            .suffix_blocklist = SuffixBlockList.init(std.Io.Writer.Allocating.init(gpa)),
        };
    }

    pub fn decide(self: *const Policy, domain: []const u8) Verdict {
        if (self.allow_list.decide(domain) == .allow) return .allow;
        if (self.domain_blocklist.decide(domain) == .block) return .block;
        return self.suffix_blocklist.decide(domain); // block or pass
    }

    pub fn deinit(self: *Policy, gpa: std.mem.Allocator) void {
        self.domain_blocklist.deinit(gpa);
        self.suffix_blocklist.deinit(gpa);
    }
};
