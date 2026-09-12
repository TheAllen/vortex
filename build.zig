const std = @import("std");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    // Vortex is a binary, not a library. There is exactly one module — the
    // executable's — rooted at `main.zig`, which imports its own files by
    // relative path.
    //
    // There used to be a second, `addModule("vortex")` rooted at the template's
    // `src/root.zig`. Nothing ever imported it and its only test asserted
    // `add(3, 7) == 10`, but it was still the *first* module a reader met and
    // so read as the project's public surface. It also cost a whole second test
    // artifact: `zig build test` ran two binaries, one of which existed to run
    // that one stub. Both are gone.
    const exe = b.addExecutable(.{
        .name = "vortex",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // One module, so one test artifact. It runs every `test` block reachable
    // from `main.zig` — which means the aggregator block at the bottom of that
    // file is what pulls each module's tests in, and the `refAllDecls` blocks
    // are what force their *declarations* to be analysed. Neither is automatic;
    // see the comment on that aggregator.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);

    // ── Integration tests ──────────────────────────────────────────────────
    //
    // A *second* test artifact, deliberately. Everything in `exe_tests` is a
    // pure function over bytes; nothing there opens a socket. What these cover
    // is the layer that unit tests structurally cannot reach — `handleQuery`,
    // `dispatcherLoop` and the ingress loop are socket plumbing, so the only
    // way to exercise them is to run the real binary and talk to it over UDP.
    // See next_steps.md P2.5.
    //
    // They therefore need a built `vortex` to spawn and a blocklist pair to
    // point it at. Both arrive as build options rather than as hardcoded
    // relative paths, so the tests do not depend on the build runner's cwd and
    // `addOptionPath` registers the artifact dependency for us — asking for
    // `test-integration` builds the exe first, automatically.
    const integration_options = b.addOptions();
    integration_options.addOptionPath("vortex_exe", exe.getEmittedBin());
    integration_options.addOptionPath("blocklist_path", b.path("testdata/blocklist.hosts"));
    integration_options.addOptionPath("suffix_blocklist_path", b.path("testdata/suffix.txt"));

    // A case costs a process spawn and, for the two timeout cases, six seconds
    // of waiting — so running one at a time is worth an option. It is also what
    // makes these assertions checkable by mutation: break a rule in `src/`,
    // rerun the single case that should notice, and confirm it does. That is
    // the discipline the cache work established after mutation testing found
    // four assertions that could not fail; see next_steps.md P2.5.
    //
    //     zig build test-integration -Dtest-filter="TC=1"
    //
    // Zig's filter is a *compile-time* property of the test artifact, not a
    // runtime flag, which is why it arrives as a build option rather than after
    // a `--`.
    const test_filter = b.option(
        []const u8,
        "test-filter",
        "Run only integration cases whose name contains this substring",
    );

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    integration_tests.root_module.addOptions("build_options", integration_options);

    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Each case binds real ports and spawns a real process, so a cached "it
    // passed last time" is not evidence the current tree passes. Force the run.
    run_integration_tests.has_side_effects = true;

    const integration_step = b.step("test-integration", "Run the integration harness (spawns the binary)");
    integration_step.dependOn(&run_integration_tests.step);

    // `zig build test` runs both. The harness is the only coverage the
    // coroutine layer has; leaving it off the default test step is how it
    // would quietly stop being run.
    test_step.dependOn(&run_integration_tests.step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}
