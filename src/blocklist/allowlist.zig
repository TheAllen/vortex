const std = @import("std");

const Verdict = @import("policy.zig").Verdict;

/// Curated allowlist of domains that OVERRIDE a block (filter-design.md §4c, §5).
///
/// Unlike the two blocklists — large, externally maintained, fetched at startup —
/// this list is small, developer-curated, and rarely changed, so it lives in the
/// binary as a comptime `StaticStringMap` instead of being loaded. That buys a zero
/// load path (no fetch/parse/alloc), no runtime failure mode for the one list that
/// most needs to be bulletproof, and build-time validation of the §3 lowercase
/// invariant (see the `comptime` block below). Editing it means recompiling — the
/// right trade for a list the developer owns. See filter-design.md §4c/§4d.
///
/// EXACT match only: an entry covers that FQDN, not its subdomains. Domains that
/// vary by subdomain (Apple push couriers, Google's rotating CDNs) can't be exact
/// entries — they wait on a suffix-allow matcher and are listed, commented, below.
const allow_set = std.StaticStringMap(void).initComptime(.{
    // ── Captive-portal / connectivity checks (else "no internet" popups on working nets)
    .{"captive.apple.com"},
    .{"connectivitycheck.gstatic.com"},
    .{"connectivitycheck.android.com"},
    .{"clients3.google.com"},
    .{"www.msftconnecttest.com"},
    .{"www.msftncsi.com"},

    // ── Microsoft / Office / Windows accounts (login + activation)
    .{"login.live.com"},
    .{"login.microsoftonline.com"},
    .{"outlook.office365.com"},
    .{"officeclient.microsoft.com"},

    // ── Google functional services (push, config, account, Play)
    .{"mtalk.google.com"},
    .{"android.clients.google.com"},
    .{"clients2.google.com"},
    .{"clients4.google.com"},
    .{"www.googleapis.com"},
    .{"fcm.googleapis.com"},
    .{"firebaseremoteconfig.googleapis.com"},
    .{"firebaseinstallations.googleapis.com"},

    // ── Facebook / Instagram login & Graph API (social sign-in on third-party apps)
    .{"graph.facebook.com"},
    .{"b-api.facebook.com"},
    .{"b-graph.facebook.com"},

    // ── Media / streaming that lists sometimes clip
    .{"s.youtube.com"},
    .{"s2.youtube.com"},
    .{"spclient.wg.spotify.com"},

    // ── reCAPTCHA / human-verification API host
    .{"www.recaptcha.net"},

    // ── NEEDS SUFFIX-ALLOW — vary by subdomain, cannot be exact entries. Enable by
    //    adding a suffix-allow matcher (mirror SuffixBlockList) and listing the zone:
    //    "push.apple.com" (N-courier.push.apple.com), "aaplimg.com", "gvt1.com", "gvt2.com"
});

// Enforce the §3 lowercase loader invariant at BUILD time, not runtime: a mixed-case
// entry would silently never match a (lowercased) QName. Here it's a compile error.
comptime {
    @setEvalBranchQuota(10_000);
    for (allow_set.keys()) |domain| {
        for (domain) |c| {
            if (std.ascii.isUpper(c)) @compileError("allowlist entry not lowercased: " ++ domain);
        }
    }
}

/// Exact-match allow filter. Zero-size: all state is the comptime `allow_set`, so
/// there is nothing to allocate, retain, or `deinit`, and nothing to thread through
/// `Context`/`main` construction.
pub const AllowList = struct {
    /// See the Filter contract in filter-design.md §3. Returns `.allow` on a hit so it
    /// can override a later block, `.pass` on a miss ("not on my list" is abstention,
    /// not permission).
    pub fn decide(_: AllowList, domain: []const u8) Verdict {
        return if (allow_set.has(domain)) .allow else .pass;
    }
};

test "allowlist hit allows, miss passes" {
    const al = AllowList{};
    try std.testing.expectEqual(Verdict.allow, al.decide("captive.apple.com"));
    try std.testing.expectEqual(Verdict.pass, al.decide("ads.example.com"));
    // exact-match: a subdomain of a listed name is NOT covered
    try std.testing.expectEqual(Verdict.pass, al.decide("sub.captive.apple.com"));
}
