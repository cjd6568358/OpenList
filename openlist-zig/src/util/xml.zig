//! Minimal XML parser — just enough for WebDAV PROPFIND responses.
//!
//! Scope, stated explicitly so nobody mistakes this for a general XML library:
//!   * element tree with attributes and text;
//!   * namespace prefixes are stripped, local names are kept verbatim
//!     (`D:getcontentlength` -> `getcontentlength`);
//!   * self-closing tags, CDATA, comments, the XML declaration, and the five
//!     predefined entities plus numeric character references.
//!
//! Deliberately NOT supported: DTDs (and therefore entity expansion — which
//! also means no billion-laughs surface), namespace URI resolution, XPath,
//! mixed-content ordering guarantees.
//!
//! Why hand-roll: WebDAV is the only XML in this project, `std` has no XML,
//! and pulling a Zig XML dependency into a binary whose whole purpose is to
//! be small would be self-defeating.

const std = @import("std");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;

pub const Attr = struct {
    name: []const u8,
    value: []const u8,
};

pub const Node = struct {
    /// Local name with any `prefix:` removed.
    name: []const u8,
    attrs: []Attr = &.{},
    children: []*Node = &.{},
    /// Concatenated character data directly inside this element.
    text: []const u8 = "",

    /// Depth-first search for the first descendant (or self) with this local
    /// name. Case-sensitive, as XML requires.
    pub fn find(self: *const Node, local_name: []const u8) ?*Node {
        if (std.mem.eql(u8, self.name, local_name)) return @constCast(self);
        for (self.children) |c| {
            if (c.find(local_name)) |hit| return hit;
        }
        return null;
    }

    pub fn findChild(self: *const Node, local_name: []const u8) ?*Node {
        for (self.children) |c| {
            if (std.mem.eql(u8, c.name, local_name)) return c;
        }
        return null;
    }

    /// Direct children with this name, appended to `out`.
    pub fn childrenNamed(self: *const Node, out: *List(*Node), local_name: []const u8) !void {
        for (self.children) |c| {
            if (std.mem.eql(u8, c.name, local_name)) try out.append(c);
        }
    }

    /// Trimmed text of the first descendant with this name.
    pub fn textOf(self: *const Node, local_name: []const u8) ?[]const u8 {
        const n = self.find(local_name) orelse return null;
        return std.mem.trim(u8, n.text, " \t\r\n");
    }

    pub fn attr(self: *const Node, local_name: []const u8) ?[]const u8 {
        for (self.attrs) |a| {
            if (std.mem.eql(u8, a.name, local_name)) return a.value;
        }
        return null;
    }
};

pub const ParseError = error{
    OutOfMemory,
    UnexpectedEnd,
    Malformed,
    DepthLimitExceeded,
};

pub fn parse(alloc: std.mem.Allocator, src: []const u8) ParseError!*Node {
    var p = Parser{ .src = src, .alloc = alloc };
    p.skipProlog();
    const root = try p.parseElement(0);
    return root;
}

const Parser = struct {
    src: []const u8,
    pos: usize = 0,
    alloc: std.mem.Allocator,
    max_depth: usize = 64,

    fn eof(self: *Parser) bool {
        return self.pos >= self.src.len;
    }

    fn peek(self: *Parser) ?u8 {
        return if (self.eof()) null else self.src[self.pos];
    }

    fn startsWith(self: *Parser, s: []const u8) bool {
        return std.mem.startsWith(u8, self.src[self.pos..], s);
    }

    /// Skip whitespace, the XML declaration, comments, and DOCTYPE.
    fn skipProlog(self: *Parser) void {
        while (!self.eof()) {
            if (isWs(self.src[self.pos])) {
                self.pos += 1;
            } else if (self.startsWith("<?")) {
                self.skipUntil("?>");
            } else if (self.startsWith("<!--")) {
                self.skipUntil("-->");
            } else if (self.startsWith("<!")) {
                // DOCTYPE (and anything else in the declaration space).
                // Ignored wholesale — see the note about entity expansion.
                self.skipDoctype();
            } else break;
        }
    }

    fn skipSpace(self: *Parser) void {
        while (!self.eof() and isWs(self.src[self.pos])) self.pos += 1;
    }

    /// Skip `<!DOCTYPE ...>`. A DOCTYPE may carry an internal subset
    /// (`[ <!ENTITY x "y"> ]`) whose contents contain `>` characters, so a
    /// plain scan-to-`>` would stop in the middle of it. Track bracket depth
    /// and only accept a `>` seen outside the subset.
    ///
    /// The subset is *skipped*, never expanded — which is what makes the
    /// parser immune to billion-laughs by construction.
    fn skipDoctype(self: *Parser) void {
        var depth: usize = 0;
        while (!self.eof()) {
            const c = self.src[self.pos];
            self.pos += 1;
            if (c == '[') {
                depth += 1;
            } else if (c == ']') {
                if (depth > 0) depth -= 1;
            } else if (c == '>' and depth == 0) {
                return;
            }
        }
    }

    fn skipUntil(self: *Parser, term: []const u8) void {
        if (std.mem.indexOf(u8, self.src[self.pos..], term)) |i| {
            self.pos += i + term.len;
        } else {
            self.pos = self.src.len;
        }
    }

    fn skipMisc(self: *Parser) void {
        while (!self.eof()) {
            if (isWs(self.src[self.pos])) {
                self.pos += 1;
            } else if (self.startsWith("<!--")) {
                self.skipUntil("-->");
            } else break;
        }
    }

    fn parseElement(self: *Parser, depth: usize) ParseError!*Node {
        if (depth > self.max_depth) return error.DepthLimitExceeded;
        if (self.peek() != '<') return error.Malformed;
        self.pos += 1;

        const raw_name = self.parseName() orelse return error.Malformed;
        const local = localName(raw_name);

        var attrs = List(Attr).init(self.alloc);
        while (true) {
            self.skipSpace();
            const c = self.peek() orelse return error.UnexpectedEnd;
            if (c == '>') {
                self.pos += 1;
                break;
            }
            if (c == '/') {
                // self-closing
                if (!self.startsWith("/>")) return error.Malformed;
                self.pos += 2;
                return self.newNode(local, attrs, &.{}, "");
            }
            const an = self.parseName() orelse return error.Malformed;
            self.skipSpace();
            if (self.peek() != '=') return error.Malformed;
            self.pos += 1;
            self.skipSpace();
            const av = try self.parseAttrValue();
            try attrs.append(.{ .name = localName(an), .value = av });
        }

        // Children and text until the matching close tag.
        var children = List(*Node).init(self.alloc);
        var text = Buf.init(self.alloc);
        while (true) {
            if (self.eof()) return error.UnexpectedEnd;
            if (self.startsWith("</")) {
                self.pos += 2;
                _ = self.parseName() orelse return error.Malformed;
                self.skipSpace();
                if (self.peek() != '>') return error.Malformed;
                self.pos += 1;
                break;
            }
            if (self.startsWith("<!--")) {
                self.skipUntil("-->");
                continue;
            }
            if (self.startsWith("<![CDATA[")) {
                self.pos += 9;
                const end = std.mem.indexOf(u8, self.src[self.pos..], "]]>") orelse return error.UnexpectedEnd;
                try text.append(self.src[self.pos..][0..end]);
                self.pos += end + 3;
                continue;
            }
            if (self.peek() == '<') {
                try children.append(try self.parseElement(depth + 1));
                continue;
            }
            // character data
            const start = self.pos;
            while (!self.eof() and self.src[self.pos] != '<') self.pos += 1;
            try self.decodeEntities(self.src[start..self.pos], &text);
        }
        return self.newNode(local, attrs, children.slice(), text.slice());
    }

    fn newNode(
        self: *Parser,
        local: []const u8,
        attrs: List(Attr),
        children: []const *Node,
        text: []const u8,
    ) !*Node {
        const n = try self.alloc.create(Node);
        n.* = .{
            .name = try self.alloc.dupe(u8, local),
            .attrs = try attrs.toOwned(),
            .children = try self.alloc.dupe(*Node, children),
            .text = try self.alloc.dupe(u8, text),
        };
        return n;
    }

    fn parseName(self: *Parser) ?[]const u8 {
        const start = self.pos;
        while (!self.eof()) {
            const c = self.src[self.pos];
            if (isWs(c) or c == '>' or c == '/' or c == '=' or c == '<') break;
            self.pos += 1;
        }
        if (self.pos == start) return null;
        return self.src[start..self.pos];
    }

    fn parseAttrValue(self: *Parser) ParseError![]const u8 {
        const quote = self.peek() orelse return error.UnexpectedEnd;
        if (quote != '"' and quote != '\'') return error.Malformed;
        self.pos += 1;
        const start = self.pos;
        while (!self.eof() and self.src[self.pos] != quote) self.pos += 1;
        if (self.eof()) return error.UnexpectedEnd;
        const raw = self.src[start..self.pos];
        self.pos += 1;

        var out = Buf.init(self.alloc);
        try self.decodeEntities(raw, &out);
        return out.toOwned();
    }

    /// Expand the five predefined entities plus numeric character references.
    /// Anything else is left verbatim — a WebDAV server that emits custom
    /// entities is out of scope by design (no DTD processing).
    fn decodeEntities(self: *Parser, raw: []const u8, out: *Buf) ParseError!void {
        _ = self;
        var i: usize = 0;
        while (i < raw.len) {
            if (raw[i] != '&') {
                try out.appendByte(raw[i]);
                i += 1;
                continue;
            }
            const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse {
                try out.appendByte(raw[i]);
                i += 1;
                continue;
            };
            const ent = raw[i + 1 .. semi];
            if (std.mem.eql(u8, ent, "amp")) {
                try out.appendByte('&');
            } else if (std.mem.eql(u8, ent, "lt")) {
                try out.appendByte('<');
            } else if (std.mem.eql(u8, ent, "gt")) {
                try out.appendByte('>');
            } else if (std.mem.eql(u8, ent, "quot")) {
                try out.appendByte('"');
            } else if (std.mem.eql(u8, ent, "apos")) {
                try out.appendByte('\'');
            } else if (ent.len > 1 and ent[0] == '#') {
                const cp: u21 = blk: {
                    if (ent.len > 2 and (ent[1] == 'x' or ent[1] == 'X')) {
                        const v = std.fmt.parseInt(u21, ent[2..], 16) catch break :blk 0;
                        break :blk v;
                    }
                    const v = std.fmt.parseInt(u21, ent[1..], 10) catch break :blk 0;
                    break :blk v;
                };
                if (cp == 0) {
                    try out.appendByte('&');
                    try out.append(ent);
                    try out.appendByte(';');
                } else {
                    var b: [4]u8 = undefined;
                    const n = encodeUtf8(cp, &b);
                    try out.append(b[0..n]);
                }
            } else {
                // Unknown entity: keep it literally rather than dropping data.
                try out.appendByte('&');
                try out.append(ent);
                try out.appendByte(';');
            }
            i = semi + 1;
        }
    }
};

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Strip a namespace prefix. `D:href` -> `href`, `href` -> `href`.
fn localName(qualified: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, qualified, ':')) |i| return qualified[i + 1 ..];
    return qualified;
}

/// Local copy of the UTF-8 encoder — `std.unicode.utf8Encode` changed signature
/// in 0.15 and this file has no other reason to care about Zig versions.
fn encodeUtf8(cp: u21, b: *[4]u8) usize {
    if (cp < 0x80) {
        b[0] = @intCast(cp);
        return 1;
    } else if (cp < 0x800) {
        b[0] = @intCast(0xC0 | (cp >> 6));
        b[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        b[0] = @intCast(0xE0 | (cp >> 12));
        b[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        b[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    }
    b[0] = @intCast(0xF0 | (cp >> 18));
    b[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
    b[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
    b[3] = @intCast(0x80 | (cp & 0x3F));
    return 4;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "parses a WebDAV multistatus" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const xml =
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<D:multistatus xmlns:D="DAV:">
        \\  <D:response>
        \\    <D:href>/dav/files/u/Photos/</D:href>
        \\    <D:propstat>
        \\      <D:prop>
        \\        <D:resourcetype><D:collection/></D:resourcetype>
        \\        <D:getlastmodified>Mon, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
        \\      </D:prop>
        \\      <D:status>HTTP/1.1 200 OK</D:status>
        \\    </D:propstat>
        \\  </D:response>
        \\  <D:response>
        \\    <D:href>/dav/files/u/Photos/a%20b.jpg</D:href>
        \\    <D:propstat><D:prop>
        \\      <D:getcontentlength>2048</D:getcontentlength>
        \\      <D:getlastmodified>Tue, 02 Jan 2024 10:30:00 GMT</D:getlastmodified>
        \\    </D:prop></D:propstat>
        \\  </D:response>
        \\</D:multistatus>
    ;
    const root = try parse(a, xml);
    try testing.expectEqualStrings("multistatus", root.name);

    var responses = List(*Node).init(a);
    try root.childrenNamed(&responses, "response");
    try testing.expectEqual(@as(usize, 2), responses.len);

    const r0 = responses.slice()[0];
    try testing.expectEqualStrings("/dav/files/u/Photos/", r0.textOf("href").?);
    try testing.expect(r0.find("collection") != null);

    const r1 = responses.slice()[1];
    try testing.expectEqualStrings("2048", r1.textOf("getcontentlength").?);
    try testing.expectEqualStrings("Tue, 02 Jan 2024 10:30:00 GMT", r1.textOf("getlastmodified").?);
    try testing.expect(r1.find("collection") == null);
}

test "self-closing tags, attributes and entities" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const root = try parse(a, "<a x=\"1\" y='2'><b/><c>1 &amp; 2 &lt;3&gt; &#65;&#x42;</c></a>");
    try testing.expectEqualStrings("1", root.attr("x").?);
    try testing.expectEqualStrings("2", root.attr("y").?);
    try testing.expect(root.findChild("b") != null);
    try testing.expectEqualStrings("1 & 2 <3> AB", root.textOf("c").?);
}

test "CDATA and comments are handled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const root = try parse(a, "<a><!-- ignore --><![CDATA[<raw> & stuff]]></a>");
    try testing.expectEqualStrings("<raw> & stuff", root.text);
}

test "a DTD is skipped without expanding entities" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The classic billion-laughs shape: we must not expand it.
    const xml =
        \\<?xml version="1.0"?>
        \\<!DOCTYPE lolz [
        \\  <!ENTITY lol "lol">
        \\  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        \\]>
        \\<root><x>&lol2;</x></root>
    ;
    const root = try parse(a, xml);
    try testing.expectEqualStrings("root", root.name);
    // The unknown entity survives verbatim instead of being expanded.
    try testing.expectEqualStrings("&lol2;", root.textOf("x").?);
}

test "deeply nested input is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var b = Buf.init(a);
    var i: usize = 0;
    while (i < 200) : (i += 1) try b.append("<a>");
    try testing.expectError(error.DepthLimitExceeded, parse(a, b.slice()));
}
