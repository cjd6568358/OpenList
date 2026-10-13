const std = @import("std");

pub fn build(b: *std.Build) void {
    // The deployment target is the 光猫: aarch64, musl, fully static.
    //   zig build -Dtarget=aarch64-linux-musl -Doptimize=small
    // The default target is the host, so `zig build test` works on the dev box.
    const target = b.standardTargetOptions(.{});
    // `-Doptimize=` with a `small` *default*: a bare `zig build` must produce
    // the shippable binary, not a fat Debug one. (The idiomatic
    // `standardOptimizeOption(.{ .preferred_optimize_mode = ... })` would
    // instead expose a `-Drelease=true|false` switch, which is a worse fit for
    // a project whose whole point is one specific size-optimised artefact.)
    // The `test` step below pins `.debug` explicitly regardless.
    //
    // Zig 0.17 renamed the optimize modes to lowercase (`debug`/`safe`/`fast`/
    // `small`); `ReleaseSmall` still exists as a deprecated *constant* but is no
    // longer an enum field, so `.ReleaseSmall` does not resolve.
    const optimize = b.option(
        std.lang.Optimize,
        "optimize",
        "Prioritize performance, safety, or binary size",
    ) orelse .small;

    const exe = b.addExecutable(.{
        .name = "openlist",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Strip in every mode but debug: the 光猫 image has no use for
            // symbols and the squashfs is size-budgeted.
            .strip = optimize != .debug,
            // libc is required for exactly one thing: `statvfs`, used by the
            // `local` driver to report free space (std has no statvfs/statfs
            // wrapper). For the `aarch64-linux-musl` target this links musl
            // statically — the same shape as the Go binary it replaces.
            //
            // 0.17 moved this from `Step.Compile.linkLibC()` to a module field.
            .link_libc = true,
        }),
    });
    b.installArtifact(exe);

    // ---- zig build run -- <args> ----
    //
    // 0.17 removed the `b.args` field. Extra arguments passed after `--` are now
    // spliced in by the build runner itself, but only into Run steps that opt in
    // via `addPassthruArgs()`. So `zig build run -- --config foo.json` reaches
    // the server as `--config foo.json` without build.zig having to see them.
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Build and run the server");
    run_step.dependOn(&run_cmd.step);

    // ---- zig build test ----
    // Always debug: the unit tests exist to catch logic errors, and `small`
    // would compile out the very checks that make them useful.
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = .debug,
            .link_libc = true,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // ---- zig build size ----
    // Prints the size of the produced binary, so the size budget is a
    // one-command check rather than a manual `ls -l`.
    const size_step = b.step("size", "Report the size of the installed binary");
    const size_cmd = b.addSystemCommand(&.{ "sh", "-c", "ls -l zig-out/bin/openlist && (command -v xz >/dev/null && xz -6 -c zig-out/bin/openlist | wc -c || echo 'xz not available')" });
    size_cmd.step.dependOn(b.getInstallStep());
    size_step.dependOn(&size_cmd.step);
}
