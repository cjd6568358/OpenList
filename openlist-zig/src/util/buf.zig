//! Minimal growable containers.
//!
//! Deliberately hand-rolled instead of `std.ArrayList`: Zig reshaped
//! `std.ArrayList` in 0.15 (managed -> unmanaged) and this project wants to
//! stay buildable across 0.14 .. 0.17 without rewriting every call site.
//! `std.mem.Allocator.alloc/realloc/free` is the only std surface we depend on.

const std = @import("std");

/// Growable byte buffer. Doubles capacity, never shrinks.
pub const Buf = struct {
    data: []u8 = &.{},
    len: usize = 0,
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Buf {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Buf) void {
        if (self.data.len > 0) self.alloc.free(self.data);
        self.* = .{ .alloc = self.alloc };
    }

    pub fn clearRetainingCapacity(self: *Buf) void {
        self.len = 0;
    }

    fn ensure(self: *Buf, extra: usize) !void {
        if (self.len + extra <= self.data.len) return;
        var cap: usize = if (self.data.len == 0) 256 else self.data.len;
        while (cap < self.len + extra) cap *|= 2;
        const fresh = try self.alloc.alloc(u8, cap);
        @memcpy(fresh[0..self.len], self.data[0..self.len]);
        if (self.data.len > 0) self.alloc.free(self.data);
        self.data = fresh;
    }

    pub fn append(self: *Buf, bytes: []const u8) !void {
        try self.ensure(bytes.len);
        @memcpy(self.data[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn appendByte(self: *Buf, b: u8) !void {
        try self.ensure(1);
        self.data[self.len] = b;
        self.len += 1;
    }

    pub fn appendNTimes(self: *Buf, b: u8, n: usize) !void {
        try self.ensure(n);
        @memset(self.data[self.len..][0..n], b);
        self.len += n;
    }

    /// Formatting append. Grows the buffer until `bufPrint` fits, so no
    /// fixed-size scratch buffer is needed.
    pub fn print(self: *Buf, comptime fmt: []const u8, args: anytype) !void {
        var extra: usize = 128;
        while (true) {
            try self.ensure(extra);
            const out = std.fmt.bufPrint(self.data[self.len..], fmt, args) catch {
                extra *= 2;
                continue;
            };
            self.len += out.len;
            return;
        }
    }

    /// View of the written bytes. Invalidated by any further append.
    pub fn slice(self: *const Buf) []const u8 {
        return self.data[0..self.len];
    }

    /// Hand an exactly-sized copy to the caller; the buffer stays usable.
    pub fn toOwned(self: *Buf) ![]u8 {
        return self.alloc.dupe(u8, self.slice());
    }

    /// NUL-terminated copy, for C APIs (e.g. realpath, execve).
    pub fn toOwnedZ(self: *Buf) ![:0]u8 {
        return self.alloc.dupeSentinel(u8, self.slice(), 0);
    }
};

/// Growable slice of arbitrary `T`. Same rationale as `Buf`.
pub fn List(comptime T: type) type {
    return struct {
        data: []T = &.{},
        len: usize = 0,
        alloc: std.mem.Allocator,

        const Self = @This();

        pub fn init(alloc: std.mem.Allocator) Self {
            return .{ .alloc = alloc };
        }

        pub fn deinit(self: *Self) void {
            if (self.data.len > 0) self.alloc.free(self.data);
            self.* = .{ .alloc = self.alloc };
        }

        pub fn append(self: *Self, v: T) !void {
            if (self.len == self.data.len) {
                const cap: usize = if (self.data.len == 0) 8 else self.data.len * 2;
                const fresh = try self.alloc.alloc(T, cap);
                @memcpy(fresh[0..self.len], self.data[0..self.len]);
                if (self.data.len > 0) self.alloc.free(self.data);
                self.data = fresh;
            }
            self.data[self.len] = v;
            self.len += 1;
        }

        pub fn appendSlice(self: *Self, items: []const T) !void {
            for (items) |it| try self.append(it);
        }

        pub fn slice(self: *const Self) []const T {
            return self.data[0..self.len];
        }

        pub fn sliceMut(self: *Self) []T {
            return self.data[0..self.len];
        }

        /// Copies the live elements into an exactly-sized slice. `self` is
        /// borrowed (`*const`) because the copy is pure — callers routinely
        /// hold a `const` list and still want an owned result.
        pub fn toOwned(self: *const Self) ![]T {
            return self.alloc.dupe(T, self.slice());
        }
    };
}

test "Buf grows and keeps contents" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var b = Buf.init(arena.allocator());
    try b.append("hello");
    try b.append(" world");
    try b.print(" {d}", .{42});
    try std.testing.expectEqualStrings("hello world 42", b.slice());
}

test "Buf.print grows past initial capacity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var b = Buf.init(arena.allocator());
    var i: usize = 0;
    while (i < 200) : (i += 1) try b.print("0123456789", .{});
    try std.testing.expectEqual(@as(usize, 2000), b.len);
}

test "List appends past capacity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var l = List(u32).init(arena.allocator());
    var i: u32 = 0;
    while (i < 100) : (i += 1) try l.append(i);
    try std.testing.expectEqual(@as(usize, 100), l.len);
    try std.testing.expectEqual(@as(u32, 99), l.slice()[99]);
}
