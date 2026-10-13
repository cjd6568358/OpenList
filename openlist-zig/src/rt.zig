//! Process-wide runtime handles: the `Io` and the general purpose allocator.
//!
//! Why this module exists
//! ---------------------
//! Zig 0.17 finished the migration of `std.fs`/`std.net` into `std.Io`, and the
//! end state is that almost every filesystem and network call takes an explicit
//! `io: Io` argument:
//!
//!     dir.openFile(io, sub_path, .{})      // was: dir.openFile(sub_path, .{})
//!     file.readStreaming(io, &buffer)      // was: file.read(buffer)
//!     address.listen(io, .{})              // was: address.listen(.{})
//!
//! The `io` is not a per-call resource: it is the process's I/O backend, handed
//! to `main` once by the startup code as `std.process.Init.io`. Threading it
//! through every function signature in this codebase would mean touching
//! essentially every function in ~8 kloc, for zero behavioural gain.
//!
//! So instead we park it here at startup and read it back where it is needed.
//! This is sound because the implementation the runtime hands us is
//! `std.Io.Threaded`, which is explicitly thread-safe and intended to be shared:
//! the HTTP server runs one thread per connection and every one of them uses
//! the same handle concurrently.
//!
//! The `?T` + fallback shape is what makes this usable from unit tests, which
//! never run `main`. Under `zig test` the handles fall back to `std.testing`'s
//! equivalents, which the test runner sets up for us.

const std = @import("std");
const builtin = @import("builtin");

var g_io: ?std.Io = null;
var g_gpa: ?std.mem.Allocator = null;

/// Called once, at the top of `main`.
pub fn set(io_handle: std.Io, allocator: std.mem.Allocator) void {
    g_io = io_handle;
    g_gpa = allocator;
}

/// The process-wide `Io` backend.
///
/// Outside of tests this is only valid after `set` has run — which is why
/// `main` calls it before doing anything else.
pub fn io() std.Io {
    if (g_io) |x| return x;
    if (builtin.is_test) return std.testing.io;
    @panic("rt.set() has not been called");
}

/// The process-wide general purpose allocator.
///
/// Production code should prefer passing an allocator explicitly — the arena
/// owned by `Config` or the per-request arena in the HTTP server — and reach
/// for this only where a long-lived, shared allocator is genuinely what is
/// wanted (driver construction, the cookie jar, the HTTP client).
pub fn gpa() std.mem.Allocator {
    if (g_gpa) |x| return x;
    if (builtin.is_test) return std.testing.allocator;
    @panic("rt.set() has not been called");
}

// ---------------------------------------------------------------------------
// Wall clock
//
// 0.17 deleted `std.time.timestamp()` and `std.time.nanoTimestamp()`: time is
// now read through the `Io` handle like everything else, so that a non-blocking
// backend can serve it too. These two wrappers keep the call sites honest about
// what they want (whole seconds vs milliseconds) without repeating the
// `Clock.real.now(io).toX()` incantation.
// ---------------------------------------------------------------------------

/// Seconds since the Unix epoch, UTC.
pub fn nowSeconds() i64 {
    return std.Io.Clock.real.now(io()).toSeconds();
}

/// Milliseconds since the Unix epoch, UTC.
pub fn nowMillis() i64 {
    return std.Io.Clock.real.now(io()).toMilliseconds();
}

/// Block the calling thread for `ms` milliseconds.
///
/// `std.Thread.sleep` is gone in 0.17 — sleeping is an `Io` operation now, so
/// that a non-blocking backend can suspend the task instead of the OS thread.
/// `.awake` is the monotonic clock: the retry backoffs that call this must not
/// be stretched or compressed by NTP stepping the wall clock.
pub fn sleepMillis(ms: i64) void {
    std.Io.sleep(io(), .fromMilliseconds(ms), .awake) catch {};
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "io() is usable under the test runner" {
    // The point of the fallback: no `main`, no `set`, still a working handle.
    const cwd = try std.Io.Dir.cwd().realPathFileAlloc(io(), ".", testing.allocator);
    defer testing.allocator.free(cwd);
    try testing.expect(cwd.len > 0);
}

test "gpa() is the testing allocator under the test runner" {
    const p = try gpa().alloc(u8, 8);
    gpa().free(p);
}
