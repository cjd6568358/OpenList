//! URL parsing / percent-encoding / query building.
//!
//! Hand-rolled on purpose: `std.Uri` reworked its `component` / `percentDecode`
//! story across 0.13 -> 0.15, and the two things this project actually needs
//! (build a query string with a stable key order, and percent-encode a path
//! segment the way Go's `net/url` does) are ~120 lines.

const std = @import("std");
const Buf = @import("buf.zig").Buf;
const List = @import("buf.zig").List;

pub const EncodeSet = enum {
    /// RFC 3986 unreserved only: A-Z a-z 0-9 - . _ ~
    component,
    /// Path segment: additionally keeps `!$&'()*+,;=:@` — matches Go's
    /// `url.PathEscape` closely enough for our backends.
    path,
    /// Query value: keeps everything a query value may legally carry.
    query,
    /// Go's `url.QueryEscape` / `url.Values.Encode`: same character set as
    /// `component`, but a space becomes `+` instead of `%20`. The itvsh
    /// upload endpoint's query string is re-signed upstream, so this
    /// difference is load-bearing, not cosmetic.
    form,
};

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn needsEscape(c: u8, set: EncodeSet) bool {
    if (isUnreserved(c)) return false;
    return switch (set) {
        .component, .form => true,
        .path => switch (c) {
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/' => false,
            else => true,
        },
        .query => switch (c) {
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/', '?' => false,
            else => true,
        },
    };
}

pub fn encode(alloc: std.mem.Allocator, s: []const u8, set: EncodeSet) ![]u8 {
    var b = Buf.init(alloc);
    defer b.deinit(); // the returned slice is an owned copy
    try encodeInto(&b, s, set);
    return b.toOwned();
}

pub fn encodeInto(b: *Buf, s: []const u8, set: EncodeSet) !void {
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        if (c == ' ' and set == .form) {
            try b.appendByte('+');
        } else if (needsEscape(c, set)) {
            try b.appendByte('%');
            try b.appendByte(hex[c >> 4]);
            try b.appendByte(hex[c & 0x0F]);
        } else {
            try b.appendByte(c);
        }
    }
}

pub fn decode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var b = Buf.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '%' and i + 2 < s.len) {
            const hi = hexVal(s[i + 1]) orelse {
                try b.appendByte(c);
                i += 1;
                continue;
            };
            const lo = hexVal(s[i + 2]) orelse {
                try b.appendByte(c);
                i += 1;
                continue;
            };
            try b.appendByte(hi << 4 | lo);
            i += 3;
        } else if (c == '+') {
            // application/x-www-form-urlencoded: '+' means space.
            try b.appendByte(' ');
            i += 1;
        } else {
            try b.appendByte(c);
            i += 1;
        }
    }
    return b.toOwned();
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Insertion-ordered query string builder. Order matters to itvsh's upload
/// endpoint, whose chunk URL is signature-checked as a whole.
pub const Query = struct {
    b: Buf,
    count: usize = 0,

    pub fn init(alloc: std.mem.Allocator) Query {
        return .{ .b = Buf.init(alloc) };
    }

    pub fn deinit(self: *Query) void {
        self.b.deinit();
    }

    pub fn add(self: *Query, key: []const u8, val: []const u8) !void {
        try self.addSet(key, val, .form);
    }

    /// Same, with an explicit encoding set. `form` is the default because it
    /// matches Go's `url.Values.Encode`, which is what every OpenList driver
    /// was written against.
    pub fn addSet(self: *Query, key: []const u8, val: []const u8, set: EncodeSet) !void {
        if (self.count != 0) try self.b.appendByte('&');
        try encodeInto(&self.b, key, set);
        try self.b.appendByte('=');
        try encodeInto(&self.b, val, set);
        self.count += 1;
    }

    /// Go's `url.Values` sorts keys. Reproduced so that query strings sent to
    /// upstreams that re-sign the URL are byte-identical to the Go build's.
    pub fn addSorted(self: *Query, entries: []const [2][]const u8) !void {
        const idx = try self.b.alloc.alloc(usize, entries.len);
        defer self.b.alloc.free(idx);
        for (idx, 0..) |*p, i| p.* = i;
        std.mem.sort(usize, idx, entries, struct {
            fn lt(es: []const [2][]const u8, a: usize, b: usize) bool {
                return std.mem.order(u8, es[a][0], es[b][0]) == .lt;
            }
        }.lt);
        for (idx) |i| try self.add(entries[i][0], entries[i][1]);
    }

    pub fn addInt(self: *Query, key: []const u8, val: i64) !void {
        var tmp: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{d}", .{val}) catch unreachable;
        try self.add(key, s);
    }

    pub fn slice(self: *const Query) []const u8 {
        return self.b.slice();
    }
};

/// Parse a single query parameter out of a raw `a=1&b=2` string.
/// Returns a subslice of `raw` (still percent-encoded).
pub fn queryGet(raw: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, raw, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const k = if (eq) |i| pair[0..i] else pair;
        if (std.mem.eql(u8, k, key)) {
            return if (eq) |i| pair[i + 1 ..] else "";
        }
    }
    return null;
}

/// Decoded query parameter. Caller owns the result.
pub fn queryGetDecoded(alloc: std.mem.Allocator, raw: []const u8, key: []const u8) !?[]u8 {
    const v = queryGet(raw, key) orelse return null;
    return try decode(alloc, v);
}

// ---------------------------------------------------------------------------
// Absolute URL split
// ---------------------------------------------------------------------------

pub const Url = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    /// Path only, always starts with '/' for absolute URLs.
    path: []const u8,
    /// Raw query, no leading '?'.
    query: []const u8,

    pub fn parse(raw: []const u8) !Url {
        const sep = std.mem.indexOf(u8, raw, "://") orelse return error.InvalidUrl;
        const scheme = raw[0..sep];
        var rest = raw[sep + 3 ..];

        var authority_end = rest.len;
        if (std.mem.indexOfAny(u8, rest, "/?#")) |i| authority_end = i;
        const authority = rest[0..authority_end];
        rest = rest[authority_end..];

        var host = authority;
        var port: u16 = if (std.mem.eql(u8, scheme, "https")) 443 else 80;
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |i| {
            // Guard against IPv6 literals without brackets (not expected here).
            if (std.mem.indexOfScalar(u8, authority, ']') == null or i > std.mem.indexOfScalar(u8, authority, ']').?) {
                host = authority[0..i];
                port = std.fmt.parseInt(u16, authority[i + 1 ..], 10) catch return error.InvalidUrl;
            }
        }

        var path: []const u8 = "/";
        var query: []const u8 = "";
        if (rest.len > 0) {
            const q = std.mem.indexOfScalar(u8, rest, '?');
            const h = std.mem.indexOfScalar(u8, rest, '#');
            var cut = rest.len;
            if (q) |i| cut = @min(cut, i);
            if (h) |i| cut = @min(cut, i);
            path = if (cut == 0) "/" else rest[0..cut];
            if (q) |i| {
                const qend = if (h) |j| j else rest.len;
                query = rest[i + 1 .. qend];
            }
        }
        return .{ .scheme = scheme, .host = host, .port = port, .path = path, .query = query };
    }

    pub fn isHttps(self: Url) bool {
        return std.mem.eql(u8, self.scheme, "https");
    }

    /// "host:port", omitting the default port.
    pub fn hostPort(self: Url, buf: []u8) ![]const u8 {
        const def: u16 = if (self.isHttps()) 443 else 80;
        if (self.port == def) return self.host;
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ self.host, self.port });
    }
};

// ---------------------------------------------------------------------------
// Path helpers (mirror the Go driver helpers they replace)
// ---------------------------------------------------------------------------

/// Join two path fragments with exactly one '/'.
pub fn joinPath(alloc: std.mem.Allocator, a: []const u8, b: []const u8) ![]u8 {
    var out = Buf.init(alloc);
    defer out.deinit();
    const left = std.mem.trimEnd(u8, a, "/");
    const right = std.mem.trimStart(u8, b, "/");
    if (left.len == 0) {
        try out.appendByte('/');
        try out.append(right);
    } else {
        try out.append(left);
        if (right.len != 0) {
            try out.appendByte('/');
            try out.append(right);
        }
    }
    return out.toOwned();
}

/// Parent of a slash path. "/" -> "/", "/a" -> "/", "/a/b" -> "/a".
pub fn parentPath(p: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, p, "/");
    if (trimmed.len == 0) return "/";
    const idx = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return "/";
    if (idx == 0) return "/";
    return trimmed[0..idx];
}

/// Basename of a slash path.
pub fn baseName(p: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, p, "/");
    if (trimmed.len == 0) return "";
    const idx = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return trimmed;
    return trimmed[idx + 1 ..];
}

/// Collapse duplicate slashes and resolve `.` / `..`. Always returns an
/// absolute path with no trailing slash (except for "/").
pub fn cleanPath(alloc: std.mem.Allocator, p: []const u8) ![]u8 {
    var stack = List([]const u8).init(alloc);
    defer stack.deinit();
    var it = std.mem.splitScalar(u8, p, '/');
    while (it.next()) |seg| {
        if (seg.len == 0 or std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (stack.len > 0) stack.len -= 1;
            continue;
        }
        try stack.append(seg);
    }
    var out = Buf.init(alloc);
    defer out.deinit();
    // The root is "/" — not "" — because callers compare the result against
    // "/" (see `WebDav.urlFor`) and `Local.relPath` strips exactly one leading
    // slash.
    if (stack.len == 0) {
        try out.appendByte('/');
        return out.toOwned();
    }
    for (stack.slice()) |seg| {
        try out.appendByte('/');
        try out.append(seg);
    }
    return out.toOwned();
}

test "encode/decode roundtrip" {
    const a = std.testing.allocator;
    const enc = try encode(a, "/a b/中文?x=1", .component);
    defer a.free(enc);
    try std.testing.expectEqualStrings("%2Fa%20b%2F%E4%B8%AD%E6%96%87%3Fx%3D1", enc);
    const dec = try decode(a, enc);
    defer a.free(dec);
    try std.testing.expectEqualStrings("/a b/中文?x=1", dec);
}

test "path encode keeps separators" {
    const a = std.testing.allocator;
    const enc = try encode(a, "/家庭共享/视频 a.mp4", .path);
    defer a.free(enc);
    try std.testing.expectEqualStrings("/%E5%AE%B6%E5%BA%AD%E5%85%B1%E4%BA%AB/%E8%A7%86%E9%A2%91%20a.mp4", enc);
}

test "query builder preserves order" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var q = Query.init(arena.allocator());
    try q.add("uploadToken", "abc");
    try q.addInt("offset", 524288);
    try q.add("fileName", "a.mp4.crash");
    try std.testing.expectEqualStrings("uploadToken=abc&offset=524288&fileName=a.mp4.crash", q.slice());
}

test "url parse" {
    const u = try Url.parse("https://pan.itvsh.cn:8443/nas/user/login?x=1");
    try std.testing.expectEqualStrings("https", u.scheme);
    try std.testing.expectEqualStrings("pan.itvsh.cn", u.host);
    try std.testing.expectEqual(@as(u16, 8443), u.port);
    try std.testing.expectEqualStrings("/nas/user/login", u.path);
    try std.testing.expectEqualStrings("x=1", u.query);

    const d = try Url.parse("https://cdn.example.com/a/b");
    try std.testing.expectEqual(@as(u16, 443), d.port);
    try std.testing.expect(d.isHttps());
}

test "path helpers" {
    const a = std.testing.allocator;
    const j = try joinPath(a, "/homeshare/", "/视频");
    defer a.free(j);
    try std.testing.expectEqualStrings("/homeshare/视频", j);
    try std.testing.expectEqualStrings("/", parentPath("/a"));
    try std.testing.expectEqualStrings("/a", parentPath("/a/b"));
    try std.testing.expectEqualStrings("b", baseName("/a/b/"));
    const c = try cleanPath(a, "/a//b/../c/");
    defer a.free(c);
    try std.testing.expectEqualStrings("/a/c", c);
}
