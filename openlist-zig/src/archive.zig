//! Read-only virtual browsing for ZIP and TAR archives.
//!
//! The parser reads ZIP's end record + central directory by random access and
//! scans TAR headers without materialising the archive. That matters on the
//! target router (about 128 MiB RAM): browsing a multi-gigabyte archive must
//! not mean allocating the whole file. Extraction, encrypted archives, ZIP64,
//! and compressed tar variants are intentionally outside this module.

const std = @import("std");
const model = @import("model.zig");
const List = @import("util/buf.zig").List;

pub const Format = enum { zip, tar };

pub const Entry = struct {
    name: []const u8,
    size: i64 = 0,
    is_dir: bool = false,
    modified: i64 = 0,
};

pub const Error = error{
    UnsupportedFormat,
    InvalidArchive,
    ArchiveTooLarge,
    UnsupportedZip64,
};

const MAX_ZIP_DIRECTORY: usize = 16 * 1024 * 1024;
const EOCD_SIG: u32 = 0x06054b50;
const CENTRAL_SIG: u32 = 0x02014b50;

pub fn detect(name: []const u8) ?Format {
    if (std.ascii.endsWithIgnoreCase(name, ".zip")) return .zip;
    if (std.ascii.endsWithIgnoreCase(name, ".tar")) return .tar;
    return null;
}

/// Return only the immediate children of `inner_path`, synthesising virtual
/// directories from nested archive paths. Entries are sorted directories-first
/// and then by bytewise name, matching the ordinary filesystem list order.
pub fn list(alloc: std.mem.Allocator, src: model.Source, format: Format, inner_path: []const u8) ![]Entry {
    var out = List(Entry).init(alloc);
    errdefer {
        for (out.slice()) |entry| alloc.free(entry.name);
        out.deinit();
    }
    switch (format) {
        .zip => try listZip(alloc, src, inner_path, &out),
        .tar => try listTar(alloc, src, inner_path, &out),
    }
    std.mem.sort(Entry, out.sliceMut(), {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            if (a.is_dir != b.is_dir) return a.is_dir;
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    const result = try out.toOwned();
    out.deinit();
    return result;
}

fn listZip(alloc: std.mem.Allocator, src: model.Source, inner_path: []const u8, out: *List(Entry)) !void {
    const total_i = src.size();
    if (total_i < 22) return error.InvalidArchive;
    const total: u64 = @intCast(total_i);
    const tail_len: usize = @intCast(@min(total, 22 + 65535));
    const tail = try alloc.alloc(u8, tail_len);
    defer alloc.free(tail);
    const tail_start = total - tail_len;
    try readExact(src, tail_start, tail);

    // EOCD comment length can reach 65535; search backwards so a signature-like
    // byte sequence inside a comment cannot hide the real record.
    var eocd: ?usize = null;
    if (tail.len >= 22) {
        var i: usize = tail.len - 22;
        while (true) : (i -= 1) {
            if (u32le(tail[i..]) == EOCD_SIG) {
                const comment_len = u16le(tail[i + 20 ..]);
                if (i + 22 + comment_len <= tail.len) {
                    eocd = i;
                    break;
                }
            }
            if (i == 0) break;
        }
    }
    const e = eocd orelse return error.InvalidArchive;
    const record = tail[e..];
    const entries = u16le(record[10..]);
    const dir_size: usize = u32le(record[12..]);
    const dir_off: u64 = u32le(record[16..]);
    if (entries == 0xffff or dir_size == 0xffff_ffff or dir_off == 0xffff_ffff) return error.UnsupportedZip64;
    if (dir_size > MAX_ZIP_DIRECTORY) return error.ArchiveTooLarge;
    if (dir_off > total or dir_size > total - dir_off) return error.InvalidArchive;

    const directory = try alloc.alloc(u8, dir_size);
    defer alloc.free(directory);
    try readExact(src, dir_off, directory);
    var pos: usize = 0;
    var parsed: usize = 0;
    while (pos < directory.len and parsed < entries) : (parsed += 1) {
        if (directory.len - pos < 46 or u32le(directory[pos..]) != CENTRAL_SIG) return error.InvalidArchive;
        const h = directory[pos..];
        const flags = u16le(h[8..]);
        const method = u16le(h[10..]);
        const comp_size = u32le(h[20..]);
        const uncomp_size = u32le(h[24..]);
        const name_len: usize = u16le(h[28..]);
        const extra_len: usize = u16le(h[30..]);
        const comment_len: usize = u16le(h[32..]);
        const end = pos + 46 + name_len + extra_len + comment_len;
        if (end > directory.len) return error.InvalidArchive;
        const raw_name = h[46 .. 46 + name_len];
        // Encryption does not prevent listing names, but flag it as an
        // unsupported archive rather than claiming the content is readable.
        if ((flags & 1) != 0) return error.UnsupportedFormat;
        _ = method;
        _ = comp_size;
        const is_dir = raw_name.len > 0 and (raw_name[raw_name.len - 1] == '/' or raw_name[raw_name.len - 1] == '\\');
        const name = try normaliseArchivePath(alloc, raw_name);
        if (name.len > 0) addChild(alloc, out, name, @intCast(@min(uncomp_size, std.math.maxInt(i64))), is_dir, inner_path, 0) catch |err| {
            alloc.free(name);
            return err;
        };
        alloc.free(name);
        pos = end;
    }
}

fn listTar(alloc: std.mem.Allocator, src: model.Source, inner_path: []const u8, out: *List(Entry)) !void {
    const total_i = src.size();
    if (total_i < 512) return error.InvalidArchive;
    const total: u64 = @intCast(total_i);
    var header: [512]u8 = undefined;
    var offset: u64 = 0;
    while (offset + 512 <= total) {
        try readExact(src, offset, &header);
        if (allZero(&header)) break;
        const name_part = trimNulSpace(header[0..100]);
        const prefix_part = trimNulSpace(header[345..500]);
        const name = if (prefix_part.len > 0)
            try std.fmt.allocPrint(alloc, "{s}/{s}", .{ prefix_part, name_part })
        else
            try alloc.dupe(u8, name_part);
        const size = parseOctal(header[124..136]) orelse return error.InvalidArchive;
        if (size > total - offset - 512) return error.InvalidArchive;
        const mtime = parseOctal(header[136..148]) orelse 0;
        const kind = header[156];
        const is_dir = kind == '5' or (name.len > 0 and name[name.len - 1] == '/');
        const clean = normaliseArchivePath(alloc, name) catch |err| {
            alloc.free(name);
            return err;
        };
        if (clean.len > 0 and kind != 'x' and kind != 'g' and kind != 'L' and kind != 'K') {
            addChild(alloc, out, clean, @intCast(@min(size, std.math.maxInt(i64))), is_dir, inner_path, @intCast(@min(mtime, std.math.maxInt(i64)))) catch |err| {
                alloc.free(name);
                alloc.free(clean);
                return err;
            };
        }
        alloc.free(name);
        alloc.free(clean);
        const blocks = (size + 511) / 512;
        if (blocks > (total - offset - 512) / 512) return error.InvalidArchive;
        offset += 512 + blocks * 512;
    }
}

fn addChild(alloc: std.mem.Allocator, out: *List(Entry), path: []const u8, size: i64, is_dir: bool, inner_path: []const u8, modified: i64) !void {
    const inner = trimSlashes(inner_path);
    var rest = path;
    if (inner.len > 0) {
        if (!std.mem.startsWith(u8, path, inner)) return;
        if (path.len == inner.len) return;
        if (path[inner.len] != '/') return;
        rest = path[inner.len + 1 ..];
    }
    if (rest.len == 0) return;
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const child_name = if (slash) |n| rest[0..n] else rest;
    if (child_name.len == 0 or std.mem.eql(u8, child_name, ".") or std.mem.eql(u8, child_name, "..")) return;
    const child_dir = is_dir or slash != null;
    for (out.data[0..out.len]) |*existing| {
        if (!std.mem.eql(u8, existing.name, child_name)) continue;
        if (child_dir) existing.is_dir = true;
        if (!child_dir) {
            existing.size = size;
            existing.modified = modified;
        }
        return;
    }
    try out.append(.{
        .name = try alloc.dupe(u8, child_name),
        .size = if (child_dir) 0 else size,
        .is_dir = child_dir,
        .modified = modified,
    });
}

fn normaliseArchivePath(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, raw.len);
    var n: usize = 0;
    var prev_slash = false;
    for (raw) |c0| {
        const c = if (c0 == '\\') '/' else c0;
        if (c == '/') {
            if (prev_slash) continue;
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out[n] = c;
        n += 1;
    }
    const cleaned = try alloc.dupe(u8, std.mem.trim(u8, out[0..n], "/"));
    alloc.free(out);
    return cleaned;
}

fn trimSlashes(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, "/");
}

fn trimNulSpace(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and (s[end - 1] == 0 or s[end - 1] == ' ')) end -= 1;
    var start: usize = 0;
    while (start < end and s[start] == ' ') start += 1;
    return s[start..end];
}

fn parseOctal(s: []const u8) ?u64 {
    var value: u64 = 0;
    var seen = false;
    for (s) |c| {
        if (c == 0 or c == ' ') continue;
        if (c < '0' or c > '7') return null;
        seen = true;
        value = std.math.mul(u64, value, 8) catch return null;
        value = std.math.add(u64, value, c - '0') catch return null;
    }
    return if (seen) value else 0;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

fn readExact(src: model.Source, offset: u64, out: []u8) !void {
    var got: usize = 0;
    while (got < out.len) {
        const n = try src.readAt(offset + got, out[got..]);
        if (n == 0) return error.UnexpectedEof;
        got += n;
    }
}

fn u16le(p: []const u8) u16 {
    return @as(u16, p[0]) | (@as(u16, p[1]) << 8);
}

fn u32le(p: []const u8) u32 {
    return @as(u32, p[0]) | (@as(u32, p[1]) << 8) | (@as(u32, p[2]) << 16) | (@as(u32, p[3]) << 24);
}

const TestSource = struct {
    bytes: []const u8,

    fn size(p: *anyopaque) i64 {
        const self: *TestSource = @ptrCast(@alignCast(p));
        return @intCast(self.bytes.len);
    }
    fn readAt(p: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
        const self: *TestSource = @ptrCast(@alignCast(p));
        if (offset >= self.bytes.len) return 0;
        const n = @min(buf.len, self.bytes.len - @as(usize, @intCast(offset)));
        @memcpy(buf[0..n], self.bytes[@intCast(offset)..][0..n]);
        return n;
    }
    const vtable = model.Source.VTable{ .size = size, .readAt = readAt };
    fn source(self: *TestSource) model.Source {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "tar list synthesizes nested directories and filters inner path" {
    const a = std.testing.allocator;
    var tar: [2048]u8 = @splat(0);
    // header 1: folder/a.txt with 3-byte payload at block 1
    @memcpy(tar[0..12], "folder/a.txt");
    tar[124] = '3';
    tar[156] = '0';
    @memcpy(tar[512..515], "abc");
    // header 2: folder/sub/b.bin, zero-byte file
    @memcpy(tar[1024 .. 1024 + 16], "folder/sub/b.bin");
    tar[1024 + 124] = '0';
    tar[1024 + 156] = '0';

    var src = TestSource{ .bytes = &tar };
    const root = try list(a, src.source(), .tar, "/");
    defer a.free(root);
    defer for (root) |entry| a.free(entry.name);
    try std.testing.expectEqual(@as(usize, 1), root.len);
    try std.testing.expectEqualStrings("folder", root[0].name);
    try std.testing.expect(root[0].is_dir);

    const nested = try list(a, src.source(), .tar, "folder");
    defer a.free(nested);
    defer for (nested) |entry| a.free(entry.name);
    try std.testing.expectEqual(@as(usize, 2), nested.len);
    try std.testing.expectEqualStrings("sub", nested[0].name);
    try std.testing.expect(nested[0].is_dir);
    try std.testing.expectEqualStrings("a.txt", nested[1].name);
    try std.testing.expectEqual(@as(i64, 3), nested[1].size);
}

test "archive format detection is case-insensitive" {
    try std.testing.expectEqual(Format.zip, detect("backup.ZIP").?);
    try std.testing.expectEqual(Format.tar, detect("bundle.tar").?);
    try std.testing.expect(detect("bundle.7z") == null);
}

test "zip central directory lists immediate virtual children" {
    const a = std.testing.allocator;
    var zip: [119]u8 = @splat(0);
    // Local file header + stored payload for dir/a.txt (3 bytes).
    put32(&zip, 0, 0x04034b50);
    put16(&zip, 4, 20);
    put16(&zip, 18, 3);
    put16(&zip, 22, 3);
    put16(&zip, 26, 9);
    @memcpy(zip[30..39], "dir/a.txt");
    @memcpy(zip[39..42], "abc");

    // Central directory (one record, 55 bytes) and EOCD.
    put32(&zip, 42, CENTRAL_SIG);
    put16(&zip, 46, 20);
    put16(&zip, 48, 20);
    put32(&zip, 62, 3);
    put32(&zip, 66, 3);
    put16(&zip, 70, 9);
    put32(&zip, 84, 0);
    @memcpy(zip[88..97], "dir/a.txt");
    put32(&zip, 97, EOCD_SIG);
    put16(&zip, 105, 1);
    put16(&zip, 107, 1);
    put32(&zip, 109, 55);
    put32(&zip, 113, 42);

    var src = TestSource{ .bytes = &zip };
    const root = try list(a, src.source(), .zip, "");
    defer a.free(root);
    defer for (root) |entry| a.free(entry.name);
    try std.testing.expectEqual(@as(usize, 1), root.len);
    try std.testing.expectEqualStrings("dir", root[0].name);
    try std.testing.expect(root[0].is_dir);

    const nested = try list(a, src.source(), .zip, "dir");
    defer a.free(nested);
    defer for (nested) |entry| a.free(entry.name);
    try std.testing.expectEqual(@as(usize, 1), nested.len);
    try std.testing.expectEqualStrings("a.txt", nested[0].name);
    try std.testing.expectEqual(@as(i64, 3), nested[0].size);
}

fn put16(buf: []u8, offset: usize, value: u16) void {
    buf[offset] = @truncate(value);
    buf[offset + 1] = @truncate(value >> 8);
}

fn put32(buf: []u8, offset: usize, value: u32) void {
    buf[offset] = @truncate(value);
    buf[offset + 1] = @truncate(value >> 8);
    buf[offset + 2] = @truncate(value >> 16);
    buf[offset + 3] = @truncate(value >> 24);
}
