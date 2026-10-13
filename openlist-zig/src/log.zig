//! Tiny leveled logger.
//!
//! Writes to stderr via `std.debug.print`, which is the one output path that
//! has not moved between Zig 0.11 and 0.17 (`std.io.getStdOut()` and
//! `File.writer()` both did). A 光猫 has no journald and the binary runs under
//! a supervisor that captures stderr, so stderr-only is also the right choice
//! operationally. File logging is done by the caller if it wants it.

const std = @import("std");
const Buf = @import("util/buf.zig").Buf;
const rt = @import("rt.zig");

pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
    off = 4,

    pub fn parse(s: []const u8) Level {
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "error") or std.ascii.eqlIgnoreCase(s, "err")) return .err;
        if (std.ascii.eqlIgnoreCase(s, "off") or std.ascii.eqlIgnoreCase(s, "none")) return .off;
        return .info;
    }

    pub fn tag(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO ",
            .warn => "WARN ",
            .err => "ERROR",
            .off => "",
        };
    }
};

var g_level: Level = .info;
var g_lock: std.Io.Mutex = .init;

pub fn setLevel(l: Level) void {
    g_level = l;
}

pub fn level() Level {
    return g_level;
}

/// Comptime-format logging. Kept as a comptime-fmt API on purpose: it avoids
/// allocating on the hot path and matches `std.debug.print`'s contract.
pub fn log(comptime l: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(l) < @intFromEnum(g_level)) return;
    g_lock.lockUncancelable(rt.io());
    defer g_lock.unlock(rt.io());
    std.debug.print("[{s}] " ++ fmt ++ "\n", .{l.tag()} ++ args);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}
pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}
pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

/// Runtime-format variant for call sites that build the message themselves
/// (e.g. forwarding an error string from a driver). Costs one stack buffer.
pub fn raw(l: Level, msg: []const u8) void {
    if (@intFromEnum(l) < @intFromEnum(g_level)) return;
    g_lock.lockUncancelable(rt.io());
    defer g_lock.unlock(rt.io());
    std.debug.print("[{s}] {s}\n", .{ l.tag(), msg });
}
