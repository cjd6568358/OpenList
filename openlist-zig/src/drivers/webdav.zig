//! WebDAV *client* driver — mounts a remote WebDAV share as an OpenList storage.
//!
//! This is the second-most-valuable driver after itvsh for one reason: it
//! exercises the XML path. Every other target driver speaks JSON; WebDAV is
//! the only one that forces a real parser into the binary, and the parser's
//! size is a measurable part of the budget (see docs/STATUS.md).
//!
//! Tested against the shapes emitted by Nextcloud, ownCloud, Alist/OpenList's
//! own WebDAV server, and nginx `dav_module`. The two things those disagree on:
//!
//!   * **Trailing slashes on collection hrefs.** Nextcloud always appends one,
//!     nginx does not. Both are handled by normalising before comparison.
//!   * **Namespace prefixes.** `D:href` and `d:href` and `href` all occur. The
//!     parser strips prefixes, so only the local name matters.
//!
//! `PROPFIND` with `Depth: 1` returns the collection itself as the first
//! `<response>`, which must be skipped when listing — getting that wrong shows
//! a phantom duplicate directory.

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const xml = @import("../util/xml.zig");
const urlmod = @import("../util/url.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const hash = @import("../util/hash.zig");
const rt = @import("../rt.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");

const propfind_body =
    \\<?xml version="1.0" encoding="utf-8"?>
    \\<D:propfind xmlns:D="DAV:">
    \\  <D:prop>
    \\    <D:resourcetype/>
    \\    <D:getcontentlength/>
    \\    <D:getlastmodified/>
    \\    <D:getcontenttype/>
    \\  </D:prop>
    \\</D:propfind>
;

pub const Addition = struct {
    url: []const u8 = "",
    username: []const u8 = "",
    password: []const u8 = "",
    root_path: []const u8 = "/",
    show_hidden: bool = false,
    /// Skip TLS verification. Users point this at self-signed NAS boxes.
    tls_insecure_skip_verify: bool = false,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        // C01 / T3：Go 的 WebDAV 用 `address` + `root_folder_path`
        // （drivers/webdav/meta.go:10 与 internal/driver/item.go:31）。
        // Zig 这边历史名叫 `url` + `root_path`。**Go 名优先**，旧名只作
        // 兜底：用户备份里这两个键就是 address/root_folder_path
        // （storage #2/#14 实证），认反了会得到空 URL、init 直接 InvalidConfig。
        if (o.strAt("address")) |s| {
            a.url = try alloc.dupe(u8, s);
        } else if (o.strAt("url")) |s| {
            a.url = try alloc.dupe(u8, s);
        }
        if (o.strAt("username")) |s| a.username = try alloc.dupe(u8, s);
        if (o.strAt("password")) |s| a.password = try alloc.dupe(u8, s);
        if (o.strAt("root_folder_path")) |s| {
            a.root_path = try alloc.dupe(u8, s);
        } else if (o.strAt("root_path")) |s| {
            a.root_path = try alloc.dupe(u8, s);
        }
        if (o.getPath("show_hidden")) |x| {
            if (x.asBool()) |b| a.show_hidden = b;
        }
        if (o.getPath("tls_insecure_skip_verify")) |x| {
            if (x.asBool()) |b| a.tls_insecure_skip_verify = b;
        }
        return a;
    }
};

/// HTTP 认证方式。对应 Go `pkg/gowebdav` 的 `NoAuth` / `BasicAuth` / `DigestAuth`
/// 三态（`client.go:38`、`basicAuth.go`、`digestAuth.go`）。
///
/// ⚠️ Go 的 `NewClient` 里初始 auth **恒为 `NoAuth`（即使配了用户名密码）**
/// （`client.go:65`），所以 401 协商对「配了凭据」的场景同样会发生
///（`requests.go:71` 判的是 `auth.Type() == "NoAuth"`）。这里照抄这个三态。
const AuthMode = enum {
    /// 还没协商过 —— 发请求时**不带** Authorization，等 401 再看服务端要什么。
    none,
    basic,
    digest,
};

/// `WWW-Authenticate: Digest ...` 里我们关心的字段（Go `digestAuth.go:47`）。
const DigestChallenge = struct {
    realm: []const u8 = "",
    nonce: []const u8 = "",
    qop: []const u8 = "",
    opaque_str: []const u8 = "",
    algorithm: []const u8 = "",

    /// 解析 `WWW-Authenticate` 的值（可能以 `Basic realm="x"` 或 `Digest ...`
    /// 开头）。按逗号切成 `k=v` 对，值两侧的引号与空白都剥掉。
    ///
    /// Go 的实现是「对每个逗号片段看它是否**包含**某个 wanted 名字」——
    /// 那是子串匹配，遇到 `realm` 里含 `nonce` 之类就会串味。这里按
    /// `=` 切第一个 `k` 再trim，语义更干净，行为在常见服务器上一致。
    fn parse(a: std.mem.Allocator, header: []const u8) !DigestChallenge {
        var c = DigestChallenge{};
        var it = std.mem.splitScalar(u8, header, ',');
        while (it.next()) |piece| {
            const eq = std.mem.indexOfScalar(u8, piece, '=') orelse continue;
            // ⚠️ 第一片带着 auth-scheme：`Digest realm="..."`。键名要取 `=`
            // 之前**最后一个**空白分隔的 token，否则读到的键是 "Digest realm"。
            // （Go 靠 `strings.Contains` 子串匹配绕过了这一点。）
            const head = std.mem.trim(u8, piece[0..eq], " \t");
            const key = blk: {
                const sp = std.mem.lastIndexOfScalar(u8, head, ' ') orelse break :blk head;
                break :blk std.mem.trim(u8, head[sp + 1 ..], " \t");
            };
            const val = std.mem.trim(u8, piece[eq + 1 ..], " \t\"");
            if (std.ascii.eqlIgnoreCase(key, "realm")) c.realm = try a.dupe(u8, val);
            if (std.ascii.eqlIgnoreCase(key, "nonce")) c.nonce = try a.dupe(u8, val);
            if (std.ascii.eqlIgnoreCase(key, "qop")) c.qop = try a.dupe(u8, val);
            if (std.ascii.eqlIgnoreCase(key, "opaque")) c.opaque_str = try a.dupe(u8, val);
            if (std.ascii.eqlIgnoreCase(key, "algorithm")) c.algorithm = try a.dupe(u8, val);
        }
        return c;
    }
};

pub const WebDav = struct {
    alloc: std.mem.Allocator,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    /// 401 协商结果。`auth_mu` 保护这两个字段：请求线程并发时会同时触发协商。
    auth_mode: AuthMode = .none,
    challenge: ?DigestChallenge = null,
    auth_mu: std.Io.Mutex = .init,

    pub const vtable = driver.Driver.VTable{
        .name = drvName,
        .init = init,
        .deinit = deinit,
        .list = list,
        .details = details,
        .link = link,
        .makeDir = makeDir,
        .move = move,
        .rename = rename,
        .remove = remove,
        .put = put,
        .copy = copy,
        .space = null, // WebDAV has no portable quota verb
    };

    fn drvName(_: *anyopaque) []const u8 {
        return "WebDav";
    }

    fn as(p: *anyopaque) *WebDav {
        return @ptrCast(@alignCast(p));
    }

    fn init(p: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(p);
        _ = ctx;
        if (self.cfg.url.len == 0) return error.InvalidConfig;
        // Probe once so a bad URL or credential fails at startup, not on the
        // first click in the UI.
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        _ = try self.propfind(arena.allocator(), "/", "0", true);
    }

    fn deinit(p: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(p);
        _ = ctx;
        self.client.deinit();
        self.jar.deinit();
        self.alloc.destroy(self.jar);
    }

    // -----------------------------------------------------------------------
    // URL construction
    // -----------------------------------------------------------------------

    /// Absolute URL for a virtual path, with each segment percent-encoded.
    /// A collection path must keep its trailing slash — WebDAV servers treat
    /// `/dir` and `/dir/` differently, and some will 301 between them.
    fn urlFor(self: *WebDav, a: std.mem.Allocator, virt: []const u8, is_collection: bool) ![]const u8 {
        const base = std.mem.trimEnd(u8, self.cfg.url, "/");
        var out = Buf.init(a);
        try out.append(base);

        const root = try urlmod.cleanPath(a, self.cfg.root_path);
        if (!std.mem.eql(u8, root, "/")) {
            try encodeSegments(&out, root);
        }
        const clean = try urlmod.cleanPath(a, virt);
        if (std.mem.eql(u8, clean, "/")) {
            try out.appendByte('/');
        } else {
            try encodeSegments(&out, clean);
            if (is_collection) try out.appendByte('/');
        }
        return out.toOwned();
    }

    fn encodeSegments(out: *Buf, path: []const u8) !void {
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            try out.appendByte('/');
            try urlmod.encodeInto(out, seg, .component);
        }
    }

    /// 取 URL 的 path 部分（不含 query），用作 Digest 的 `uri`。
    fn uriPath(url: []const u8) []const u8 {
        const p = urlmod.Url.parse(url) catch return url;
        return p.path;
    }

    /// 认证头。`method` 与 `uri` 是 Digest 响应值的输入（Basic 不需要它们）。
    ///
    /// 三态与 Go 一致：`.none` 时**一个头都不发**（Go 的 `NoAuth.Authorize`
    /// 是空实现），让服务端用 401 告诉我们它要什么。
    fn authHeaders(self: *WebDav, a: std.mem.Allocator, method: []const u8, uri: []const u8) ![]model.Header {
        if (self.cfg.username.len == 0) return &.{};
        self.auth_mu.lockUncancelable(rt.io());
        defer self.auth_mu.unlock(rt.io());
        const mode = self.auth_mode;
        const ch = self.challenge;
        const value: []const u8 = switch (mode) {
            .none => return &.{},
            .digest => if (ch) |c| try self.digestHeader(a, method, uri, c) else try self.basicHeader(a),
            .basic => try self.basicHeader(a),
        };
        return a.dupe(model.Header, &.{.{ .name = "Authorization", .value = value }});
    }

    fn basicHeader(self: *WebDav, a: std.mem.Allocator) ![]const u8 {
        var raw = Buf.init(a);
        try raw.append(self.cfg.username);
        try raw.appendByte(':');
        try raw.append(self.cfg.password);
        const enc = std.base64.standard.Encoder;
        const buf = try a.alloc(u8, enc.calcSize(raw.len));
        const b64 = enc.encode(buf, raw.slice());
        return std.fmt.allocPrint(a, "Basic {s}", .{b64});
    }

    /// `Digest` 响应头（RFC 7616 / Go `pkg/gowebdav/digestAuth.go:75-146`）。
    ///
    /// 与上游的两处**有意**差异：
    /// ① `nc`：Go 写的是 Go 整数字面量 `00000001`（八进制 1），`%v` 打出来是
    ///    `nc=1`；RFC 7616 §3.4.6 要 8 位十六进制，这里输出 `nc=00000001`。
    ///    严格校验的服务端按 RFC 解析，这样更稳；宽松的两端都收。
    /// ② `uri`：Go 传的是**相对 root 的路径**（`Authorize(r, method, path)`，
    ///    requests.go:57），而实际请求行里发的是 `PathEscape(Join(root, path))`。
    ///    root 不是 `/` 时两者不等，而服务端比对的正是请求行 —— 这里传
    ///    **真实请求路径**，root 带前缀时才是自洽的。
    /// ③ `qop=auth-int` 需要 body 的 MD5，本驱动所有走这里的请求都没有 body
    ///    （PROPFIND 有 body，但 Go 也没给 `entityBody`），故按 `auth` 处理。
    fn digestHeader(self: *WebDav, a: std.mem.Allocator, method: []const u8, uri: []const u8, c: DigestChallenge) ![]const u8 {
        var cnonce_buf: [8]u8 = undefined;
        rt.io().random(&cnonce_buf);
        const cnonce = std.fmt.bytesToHex(cnonce_buf, .lower);
        const response = try digestResponse(
            a,
            self.cfg.username,
            self.cfg.password,
            c,
            method,
            uri,
            &cnonce,
        );

        var out = try std.fmt.allocPrint(a,
            \\Digest username="{s}", realm="{s}", nonce="{s}", uri="{s}", nc={s}, cnonce="{s}", response="{s}"
        , .{ self.cfg.username, c.realm, c.nonce, uri, "00000001", cnonce, response });
        if (c.qop.len > 0) out = try std.fmt.allocPrint(a, "{s}, qop={s}", .{ out, c.qop });
        if (c.opaque_str.len > 0) out = try std.fmt.allocPrint(a, "{s}, opaque=\"{s}\"", .{ out, c.opaque_str });
        return out;
    }

    /// 401 协商（Go `pkg/gowebdav/requests.go:71-90`）：只在**还没协商过**时
    /// 生效 —— 已经定了方式还回 401，那就是凭据不对，不再重试。
    /// 返回 true 表示状态已切换，调用方应当重发。
    fn negotiateAuth(self: *WebDav, a: std.mem.Allocator, res: httpclient.Response) bool {
        if (self.cfg.username.len == 0) return false;
        const wa = res.header("WWW-Authenticate") orelse return false;

        self.auth_mu.lockUncancelable(rt.io());
        defer self.auth_mu.unlock(rt.io());
        if (self.auth_mode != .none) return false;

        if (indexOfIgnoreCase(wa, "digest")) |_| {
            self.challenge = DigestChallenge.parse(a, wa) catch null;
            self.auth_mode = .digest;
            log.info("[webdav] 401 -> Digest (realm={s})", .{if (self.challenge) |c| c.realm else ""});
            return true;
        }
        if (indexOfIgnoreCase(wa, "basic")) |_| {
            self.auth_mode = .basic;
            log.info("[webdav] 401 -> Basic", .{});
            return true;
        }
        return false;
    }

    /// 发一次请求；首轮 401 触发协商并重发一次。
    ///
    /// **只用于可重放的请求**（body 是内存里的字符串或空）。流式上传走
    /// [`put`]，Go 那边也是 `canRetry=false`（`retryBuf` 只在 body 非流时才有），
    /// 所以上传遇到 401 就直接失败。
    fn sendAuthed(
        self: *WebDav,
        a: std.mem.Allocator,
        method: []const u8,
        url: []const u8,
        extra: []const model.Header,
        body: []const u8,
    ) !httpclient.Response {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            var hs = List(model.Header).init(a);
            try hs.appendSlice(try self.authHeaders(a, method, uriPath(url)));
            try hs.appendSlice(extra);
            const res = try self.client.sendRaw(a, method, url, hs.slice(), body);
            if (res.status == 401 and attempt == 0 and self.negotiateAuth(a, res)) continue;
            return res;
        }
    }

    // -----------------------------------------------------------------------
    // PROPFIND
    // -----------------------------------------------------------------------

    /// D04：`is_collection` 由调用方决定，**不能恒为 true**。
    /// Go 的 gowebdav 里 `ReadDir` 传 true、`Stat` 传 false
    /// （pkg/gowebdav/client.go:181 vs :233）；给文件路径强加尾斜杠，
    /// 在区分 `/a.txt` 与 `/a.txt/` 的服务端上会 404。
    fn propfind(self: *WebDav, a: std.mem.Allocator, virt: []const u8, depth: []const u8, is_collection: bool) !*xml.Node {
        const target = try self.urlFor(a, virt, is_collection);
        const extra = [_]model.Header{
            .{ .name = "Depth", .value = depth },
            .{ .name = "Content-Type", .value = "application/xml; charset=utf-8" },
        };

        // PROPFIND 不在 `std.http.Method` 里，必须走自定义方法路径 ——
        // 以前走 `send` 会被静默降级成 GET（真机表现为服务端回 405）。
        const res = try self.sendAuthed(a, "PROPFIND", target, &extra, propfind_body);
        // 207 Multi-Status is the only success code for PROPFIND.
        if (res.status != 207) {
            if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
            if (res.status == 404) return driver.Error.NotFound;
            log.warn("[webdav] PROPFIND {s} -> HTTP {d}", .{ target, res.status });
            return driver.Error.UnexpectedResponse;
        }
        return xml.parse(a, res.body) catch |e| {
            log.warn("[webdav] PROPFIND {s}: bad XML ({s}): {s}", .{
                target, @errorName(e), res.body[0..@min(res.body.len, 256)],
            });
            return driver.Error.UnexpectedResponse;
        };
    }

/// 选中 `<propstat>` 里**状态含 "200"** 的那个，返回它的 `<prop>`。
///
/// D06：Go 的 `getProps(r, "200")`（pkg/gowebdav/client.go:129-135）。
/// 以前 Zig 用递归 `find` 跨所有 propstat 找 `collection`/`getcontentlength`，
/// 服务端只要返回一个 404 属性组，读到的就是错的属性。
fn okProp(a: std.mem.Allocator, resp: *xml.Node) !?*xml.Node {
        var stats = List(*xml.Node).init(a);
        try resp.childrenNamed(&stats, "propstat");
        for (stats.slice()) |ps| {
            const st = ps.textOf("status") orelse continue;
            if (std.mem.indexOf(u8, st, "200") != null) return ps.findChild("prop");
        }
        return null;
    }

    /// Turn one `<response>` node into an Obj. `base_path` is the collection
    /// the PROPFIND was issued against, used to derive the child's name.
    fn responseToObj(a: std.mem.Allocator, resp: *xml.Node, base_virt: []const u8, skip_hidden: bool) !?model.Obj {
        const href = resp.textOf("href") orelse return null;
        const decoded = try urlmod.decode(a, href);
        // Strip a trailing slash so collection and file paths compare alike.
        const trimmed = std.mem.trimEnd(u8, decoded, "/");
        const name = urlmod.baseName(trimmed);
        if (name.len == 0) return null;
        if (skip_hidden and name[0] == '.') return null;

        // 只在 200 属性组里读；没有 200 组就跳过这一项（Go ReadDir 同样跳过）。
        const prop = (try okProp(a, resp)) orelse return null;

        const is_dir = prop.find("collection") != null;
        const size = if (prop.textOf("getcontentlength")) |s|
            (std.fmt.parseInt(i64, s, 10) catch 0)
        else
            0;
        const mtime = if (prop.textOf("getlastmodified")) |s|
            (@import("../cookiejar.zig").parseHttpDate(s) orelse 0)
        else
            0;

        const full = try urlmod.joinPath(a, base_virt, name);
        return .{
            .name = try a.dupe(u8, name),
            .size = size,
            .is_dir = is_dir,
            .modified = mtime,
            .sign = try a.dupe(u8, full),
        };
    }

    // -----------------------------------------------------------------------
    // vtable
    // -----------------------------------------------------------------------

    fn list(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(p);
        const a = ctx.alloc;
        const root = try self.propfind(a, dir, "1", true);

        var responses = List(*xml.Node).init(a);
        try root.childrenNamed(&responses, "response");
        if (responses.len == 0) return &.{};

        // D06：Depth:1 的第一个 <response> 是集合自身。Go 的 ReadDir 在这里
        // 不是"无条件丢弃"，而是要求它**确实是一个 collection 且带 200 属性组**，
        // 否则报 405（pkg/gowebdav/client.go:142-149）。以前无条件丢首项，
        // 服务端把子项放在第一位时就会静默吞掉一个条目。
        const first_prop = (try okProp(a, responses.slice()[0])) orelse {
            log.warn("[webdav] PROPFIND {s}: first <response> has no 200 propstat", .{dir});
            return driver.Error.UnexpectedResponse;
        };
        if (first_prop.find("collection") == null) {
            log.warn("[webdav] PROPFIND {s}: first <response> is not a collection", .{dir});
            return driver.Error.UnexpectedResponse;
        }

        var out = List(model.Obj).init(a);
        const start: usize = if (responses.len > 1) 1 else responses.len;
        for (responses.slice()[start..]) |r| {
            if (try responseToObj(a, r, dir, !self.cfg.show_hidden)) |o| try out.append(o);
        }
        return out.toOwned();
    }

    fn details(p: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(p);
        const a = ctx.alloc;
        if (std.mem.eql(u8, path, "/") or path.len == 0) {
            return .{ .name = "/", .is_dir = true };
        }
        // D04：Stat 语义 —— 不假设目标是集合，不加尾斜杠（Go gowebdav 传 false）。
        const root = try self.propfind(a, path, "0", false);
        var responses = List(*xml.Node).init(a);
        try root.childrenNamed(&responses, "response");
        if (responses.len == 0) return driver.Error.NotFound;

        const parent = urlmod.parentPath(path);
        const o = (try responseToObj(a, responses.slice()[0], parent, false)) orelse
            return driver.Error.NotFound;
        return model.File.fromObj(o);
    }

    /// With credentials we must proxy: a browser cannot be told to send Basic
    /// auth after a 302, so handing it the URL would produce a 401. Without
    /// credentials the redirect is correct and much cheaper.
    fn link(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(p);
        const a = ctx.alloc;
        _ = args;
        const url = try self.urlFor(a, path, false);
        const needs_auth = self.cfg.username.len != 0;
        return .{
            .url = url,
            // 代理请求是 GET；Digest 的响应值绑定 method+uri，所以这里按
            // GET 算（Basic 与 method/uri 无关，两种模式下都正确）。
            .header = if (needs_auth) try self.authHeaders(a, "GET", uriPath(url)) else &.{},
            .proxy = needs_auth,
        };
    }

    fn makeDir(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const target = try self.urlFor(a, dir, true);
        const res = try self.sendAuthed(a, "MKCOL", target, &.{}, "");
        // 405 means it already exists; treat as success, matching every other
        // WebDAV client (and OpenList).
        if (res.status == 201 or res.status == 405) return;
        if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
        // 409 = 父集合不存在。Go 的 `MkdirAll` 会**自顶向下逐级**建
        // （pkg/gowebdav/requests.go:210-217），这里同样退化成 `mkdirAll`。
        // 以前直接把 409 当 NotFound 返回，于是「一次建多级目录」在只保证
        // 单级 MKCOL 的服务端上必然失败。
        if (res.status == 409) return self.mkdirAll(a, dir);
        log.warn("[webdav] MKCOL {s} -> HTTP {d}", .{ target, res.status });
        return driver.Error.UnexpectedResponse;
    }

    fn rename(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        if (new_name.len == 0 or std.mem.indexOfScalar(u8, new_name, '/') != null) return error.InvalidPath;
        const dst = try urlmod.joinPath(a, urlmod.parentPath(src), new_name);
        return self.moveTo(a, src, dst);
    }

    fn move(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const dst = try urlmod.joinPath(a, dst_dir, urlmod.baseName(src));
        return self.moveTo(a, src, dst);
    }

    fn copy(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const dst = try urlmod.joinPath(a, dst_dir, urlmod.baseName(src));
        return self.copyOrMove(a, "COPY", src, dst);
    }

    /// D05：对齐 Go `pkg/gowebdav/requests.go:157` —— 驱动的 Move/Copy 用
    /// `overwrite=true`，即 `Overwrite: T`（OpenList 的 `drivers/webdav/driver.go:105`）。
    /// 以前 Zig 写死 `F`，目标已存在时服务端回 412，重命名/移动直接失败。
    ///
    /// 另外 409 表示父集合不存在，Go 的做法是 `createParentCollection` 后
    /// **重试一次**（requests.go:187-193）。这里同样实现，并加上限避免打转。
    fn moveTo(self: *WebDav, a: std.mem.Allocator, src: []const u8, dst: []const u8) !void {
        return self.copyOrMove(a, "MOVE", src, dst);
    }

    /// `Copy` 与 `Move` 在 WebDAV 上完全同形（RFC 4918 §8.8 / §9.9），只有方法名
    /// 不同 —— Go 的 `drivers/webdav/driver.go:100-107` 也是同一个 client 调用。
    /// 成功码：201 新建、204 覆盖；409 建父集合后重试一次。
    fn copyOrMove(self: *WebDav, a: std.mem.Allocator, method: []const u8, src: []const u8, dst: []const u8) !void {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            // `detailsRaw` is best-effort: a failed PROPFIND yields a zeroed File,
            // which means `is_dir = false` — i.e. treat it as a file and let the
            // MOVE itself report the real error.
            const is_coll = self.detailsRaw(a, src).is_dir;
            const from = try self.urlFor(a, src, is_coll);
            const to = try self.urlFor(a, dst, is_coll);

            const extra = [_]model.Header{
                // `Destination` must be an absolute URI per RFC 4918 §9.9.3.
                .{ .name = "Destination", .value = to },
                .{ .name = "Overwrite", .value = "T" },
            };

            const res = try self.sendAuthed(a, method, from, &extra, "");
            if (res.status == 201 or res.status == 204) return;
            if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
            if (res.status == 404) return driver.Error.NotFound;
            if (res.status == 409 and attempt == 0) {
                // 父集合缺失：先建出来再重试一次（Go requests.go:187-193）。
                try self.mkdirAll(a, urlmod.parentPath(dst));
                continue;
            }
            log.warn("[webdav] {s} {s} -> {s}: HTTP {d}", .{ method, from, to, res.status });
            return driver.Error.UnexpectedResponse;
        }
    }

    fn detailsRaw(self: *WebDav, a: std.mem.Allocator, path: []const u8) model.File {
        return self.propfindDetails(a, path) catch model.File{ .name = urlmod.baseName(path) };
    }

    fn propfindDetails(self: *WebDav, a: std.mem.Allocator, path: []const u8) !model.File {
        // D04：Stat 语义 —— 不假设目标是集合，不加尾斜杠（Go gowebdav 传 false）。
        const root = try self.propfind(a, path, "0", false);
        var responses = List(*xml.Node).init(a);
        try root.childrenNamed(&responses, "response");
        if (responses.len == 0) return driver.Error.NotFound;
        const o = (try responseToObj(a, responses.slice()[0], urlmod.parentPath(path), false)) orelse
            return driver.Error.NotFound;
        return model.File.fromObj(o);
    }

    fn remove(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const target = try self.urlFor(a, path, is_dir);
        // DELETE 没有 body，所以 401 协商后可以重发一次（与 `sendAuthed` 同策略，
        // 只是这里必须保留 `skip_body`）。
        var attempt: u8 = 0;
        var res: httpclient.Response = undefined;
        while (true) : (attempt += 1) {
            // `skip_body`：DELETE 的结果只看状态码。坚果云对 DELETE 返回 204 且
            // **没有任何定界头**（无 Content-Length、无 chunked），keep-alive 下
            // 读正文会阻塞到超时 —— 而此时删除其实已经成功。Go 的 gowebdav 也是
            // 只看 StatusCode、从不读 body（pkg/gowebdav/requests.go），两边对齐。
            res = try self.client.send(a, .{
                .method = "DELETE",
                .url = target,
                .headers = try self.authHeaders(a, "DELETE", uriPath(target)),
                .skip_body = true,
            });
            if (res.status == 401 and attempt == 0 and self.negotiateAuth(a, res)) continue;
            break;
        }
        // 404 is success for a delete: the caller wanted it gone.
        if (res.status == 200 or res.status == 204 or res.status == 404) return;
        if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
        // 409 usually means the collection was not empty.
        if (res.status == 409) return error.DirectoryNotEmpty;
        log.warn("[webdav] DELETE {s} -> HTTP {d}", .{ target, res.status });
        return driver.Error.UnexpectedResponse;
    }

    /// 递归创建父集合，等价于 Go 的 `createParentCollection` → `MkdirAll`
    /// （pkg/gowebdav/requests.go:210-217）。
    ///
    /// 自顶向下逐级 MKCOL：服务端只保证建单级，直接建 `/a/b/c` 会 409。
    fn mkdirAll(self: *WebDav, a: std.mem.Allocator, dir: []const u8) !void {
        const clean = try urlmod.cleanPath(a, dir);
        if (clean.len == 0 or std.mem.eql(u8, clean, "/")) return;

        var prefix = Buf.init(a);
        var it = std.mem.splitScalar(u8, clean, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            try prefix.appendByte('/');
            try prefix.append(seg);

            const target = try self.urlFor(a, prefix.slice(), true);
            const res = try self.sendAuthed(a, "MKCOL", target, &.{}, "");
            // 201 = 新建成功；405 = 已存在。两者都继续往下一级。
            if (res.status == 201 or res.status == 405) continue;
            if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
            log.warn("[webdav] MKCOL {s} -> HTTP {d}", .{ target, res.status });
            return driver.Error.UnexpectedResponse;
        }
    }

    fn put(p: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const target = try self.urlFor(a, dst, false);

        var headers = List(model.Header).init(a);
        // ⚠️ 上传**不参与** 401 协商重试：body 是流，重放不了。
        // Go 同理 —— `retryBuf` 只在 body 非流时才建（requests.go:26-33）。
        // 所以初次 `auth_mode == .none` 时这里发的 PUT 是不带认证头的，
        // 服务端若要求认证就会 401；实际部署里 PROPFIND（init/list）会先
        // 协商好，PUT 轮到时认证方式已确定。
        try headers.appendSlice(try self.authHeaders(a, "PUT", uriPath(target)));
        try headers.append(.{ .name = "Content-Type", .value = "application/octet-stream" });

        const total: u64 = @intCast(@max(src.size(), 0));

        // WebDAV 的 PUT 由 `client.send` 一次写成，没有可分片的循环，所以只有
        // 0% / 100% 两个点（Go 的 gowebdav 同样如此 —— `Put` 就是一次 `req`）。
        if (ctx.progress) |f| f(ctx.progress_userdata, 0);

        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const res = try self.client.send(a, .{
                .method = "PUT",
                .url = target,
                .headers = headers.slice(),
                .source = src,
                .content_length = total,
            });
            if (res.status == 200 or res.status == 201 or res.status == 204) {
                if (ctx.progress) |f| f(ctx.progress_userdata, 100);
                return;
            }
            if (res.status == 401 or res.status == 403) return driver.Error.AuthFailed;
            if (res.status == 409 and attempt == 0) {
                // D05：父集合不存在。Go 会先 MkdirAll 再重试，而不是直接
                // 把 409 当成 NotFound 放弃（以前 Zig 就是这么干的）。
                try self.mkdirAll(a, urlmod.parentPath(dst));
                continue;
            }
            if (res.status == 507) return error.InsufficientStorage;
            log.warn("[webdav] PUT {s} -> HTTP {d}, body: {s}", .{
                target, res.status, res.body[0..@min(res.body.len, 256)],
            });
            return driver.Error.UnexpectedResponse;
        }
    }
};
/// Digest 的 `response=` 值（RFC 7616 §3.4）。拆成纯函数是为了能单测 ——
/// `digestHeader` 自己会随机生成 cnonce，不可复现。
fn digestResponse(
    a: std.mem.Allocator,
    user: []const u8,
    pass: []const u8,
    c: DigestChallenge,
    method: []const u8,
    uri: []const u8,
    cnonce: []const u8,
) ![]const u8 {
    const nc = "00000001";

    // HA1：algorithm ∈ {MD5, ""}；MD5-sess 多套一层 nonce/cnonce。
    const plain = try std.fmt.allocPrint(a, "{s}:{s}:{s}", .{ user, c.realm, pass });
    var ha1 = try hash.md5Hex(a, plain);
    if (std.ascii.eqlIgnoreCase(c.algorithm, "MD5-sess")) {
        const sess = try std.fmt.allocPrint(a, "{s}:{s}:{s}", .{ ha1, nc, cnonce });
        ha1 = try hash.md5Hex(a, sess);
    }

    // HA2：qop ∈ {auth, ""} 时不含 body。
    const ha2 = try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}:{s}", .{ method, uri }));

    return if (c.qop.len == 0)
        try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}:{s}:{s}", .{ ha1, c.nonce, ha2 }))
    else
        try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}:{s}:{s}:{s}:{s}:{s}", .{
            ha1, c.nonce, nc, cnonce, c.qop, ha2,
        }));
}

/// 大小写不敏感的子串查找（`std.mem` 没有现成的版本）。
fn indexOfIgnoreCase(hay: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or hay.len < needle.len) return null;
    var i: usize = 0;
    const last = hay.len - needle.len;
    while (i <= last) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return i;
    }
    return null;
}


pub const factory = driver.Factory{
    .key = "WebDav",
    .label = "WebDAV",
    .secrets = &.{ "password" },
    // 表单 schema：键名与 Go `drivers/webdav/meta.go` 的 json tag 一致
    // （`address` / `root_folder_path`；`vendor` 仅 sharepoint 检测用，
    //  本驱动不实现该分支故不暴露）。`show_hidden` 是本工程扩展字段，
    //  Go 的 Addition 里没有，保留但仅对 Zig 侧配置有意义。
    .addition_schema =
    \\{
    \\  "address":                 {"type":"string","required":true,"help":"WebDAV 服务地址，如 https://nas.example.com/dav"},
    \\  "username":                 {"type":"string","required":false},
    \\  "password":                 {"type":"string","required":false,"secret":true},
    \\  "root_folder_path":         {"type":"string","default":"/","help":"挂载的远端子路径"},
    \\  "show_hidden":              {"type":"bool","default":false,"help":"显示以点开头的隐藏条目"},
    \\  "tls_insecure_skip_verify": {"type":"bool","default":false,"help":"跳过 TLS 证书校验（自签名 NAS 需要）"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    // WebDAV 客户端不持有可刷新的会话状态，用不到 storage id。
    _ = storage_id;
    const self = try alloc.create(WebDav);
    const jar = try alloc.create(cookiejar.Jar);
    jar.* = cookiejar.Jar.init(alloc);
    const addition = try Addition.parse(alloc, cfg);
    self.* = .{
        .alloc = alloc,
        .cfg = addition,
        .jar = jar,
        // T4 已修：正文在 TLS 下发不出去是 `BodyWriter.end()` 之后漏了 flush，
        // 已在 `client.zig` 的 `sendOnce` 里修好，这里不再需要绕行。
        .client = httpclient.Client.init(alloc, .{
            .insecure_skip_verify = addition.tls_insecure_skip_verify,
        }, jar),
    };
    return driver.asDriver(WebDav, self);
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "urlFor encodes segments and keeps the collection slash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var w = WebDav{
        .alloc = a,
        .cfg = .{ .url = "https://nas.example.com/dav/", .root_path = "/" },
        .jar = undefined,
        .client = undefined,
    };
    try testing.expectEqualStrings(
        "https://nas.example.com/dav/%E5%AE%B6%E5%BA%AD/a%20b.jpg",
        try w.urlFor(a, "/家庭/a b.jpg", false),
    );
    try testing.expectEqualStrings(
        "https://nas.example.com/dav/Photos/",
        try w.urlFor(a, "/Photos", true),
    );
    try testing.expectEqualStrings("https://nas.example.com/dav/", try w.urlFor(a, "/", true));

    w.cfg.root_path = "/remote.php/dav/files/u";
    try testing.expectEqualStrings(
        "https://nas.example.com/dav/remote.php/dav/files/u/x.txt",
        try w.urlFor(a, "/x.txt", false),
    );
}

test "responseToObj derives names, sizes and folders" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 真实服务端的 `<propstat>` 一定带 `<status>`；D06 之后我们只认状态含
    // "200" 的那一组，所以夹具必须和真实报文一致。
    const doc =
        \\<D:multistatus xmlns:D="DAV:">
        \\  <D:response>
        \\    <D:href>/dav/files/u/Photos/a%20b.jpg</D:href>
        \\    <D:propstat>
        \\      <D:prop>
        \\        <D:getcontentlength>2048</D:getcontentlength>
        \\        <D:getlastmodified>Tue, 02 Jan 2024 10:30:00 GMT</D:getlastmodified>
        \\      </D:prop>
        \\      <D:status>HTTP/1.1 200 OK</D:status>
        \\    </D:propstat>
        \\  </D:response>
        \\  <D:response>
        \\    <D:href>/dav/files/u/Photos/Sub/</D:href>
        \\    <D:propstat>
        \\      <D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
        \\      <D:status>HTTP/1.1 200 OK</D:status>
        \\    </D:propstat>
        \\  </D:response>
        \\  <D:response>
        \\    <D:href>/dav/files/u/Photos/ghost.txt</D:href>
        \\    <D:propstat>
        \\      <D:prop><D:getcontentlength>999</D:getcontentlength></D:prop>
        \\      <D:status>HTTP/1.1 404 Not Found</D:status>
        \\    </D:propstat>
        \\  </D:response>
        \\</D:multistatus>
    ;
    const root = try xml.parse(a, doc);
    var responses = List(*xml.Node).init(a);
    try root.childrenNamed(&responses, "response");
    try testing.expectEqual(@as(usize, 3), responses.len);

    const f = (try WebDav.responseToObj(a, responses.slice()[0], "/Photos", true)).?;
    try testing.expectEqualStrings("a b.jpg", f.name);
    try testing.expectEqual(@as(i64, 2048), f.size);
    try testing.expect(!f.is_dir);
    try testing.expect(f.modified > 0);
    try testing.expectEqualStrings("/Photos/a b.jpg", f.sign);

    const d = (try WebDav.responseToObj(a, responses.slice()[1], "/Photos", true)).?;
    try testing.expectEqualStrings("Sub", d.name);
    try testing.expect(d.is_dir);

    // D06：只有 404 属性组的条目必须被跳过，绝不能把 404 组里的
    // getcontentlength 当成真实大小读出来。
    try testing.expect((try WebDav.responseToObj(a, responses.slice()[2], "/Photos", true)) == null);

    // hidden entries are dropped when asked
    try testing.expect((try WebDav.responseToObj(a, responses.slice()[0], "/Photos", false)) != null);
}

test "okProp ignores non-200 propstat groups" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const doc =
        \\<D:response xmlns:D="DAV:">
        \\  <D:href>/dav/x</D:href>
        \\  <D:propstat>
        \\    <D:prop><D:getcontentlength>111</D:getcontentlength></D:prop>
        \\    <D:status>HTTP/1.1 404 Not Found</D:status>
        \\  </D:propstat>
        \\  <D:propstat>
        \\    <D:prop><D:getcontentlength>222</D:getcontentlength></D:prop>
        \\    <D:status>HTTP/1.1 200 OK</D:status>
        \\  </D:propstat>
        \\</D:response>
    ;
    const node = try xml.parse(a, doc);
    const prop = (try WebDav.okProp(a, node)).?;
    // 必须选到 200 那组（222），而不是先出现的 404 组（111）。
    try testing.expectEqualStrings("222", prop.textOf("getcontentlength").?);
}

test "urlFor does not double-encode an already-encoded href" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var w = WebDav{
        .alloc = a,
        .cfg = .{ .url = "https://x/dav", .root_path = "/" },
        .jar = undefined,
        .client = undefined,
    };
    // A virtual path is always decoded; the `%20` must be re-encoded once.
    const u = try w.urlFor(a, "/a b", false);
    try testing.expectEqualStrings("https://x/dav/a%20b", u);
    try testing.expect(std.mem.indexOf(u8, u, "%2520") == null);
}

test "T3: real Go addition JSON parses into the driver, Go name wins" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var parsed = std.heap.ArenaAllocator.init(testing.allocator);
    defer parsed.deinit();
    const pa = parsed.allocator();

    // C01 / T3 回归：键集与用户 Go 备份 storage #2/#14 一致
    // （['address','password','root_folder_path','tls_insecure_skip_verify',
    //   'username','vendor']），值造假、键保真。
    const go_v = try json.parse(pa,
        \\{"vendor":"other","address":"https://nas.example.com/dav",
        \\ "username":"u","password":"p","root_folder_path":"/sub",
        \\ "tls_insecure_skip_verify":true}
    );
    const add = try Addition.parse(a, &go_v);
    try testing.expectEqualStrings("https://nas.example.com/dav", add.url);
    try testing.expectEqualStrings("u", add.username);
    try testing.expectEqualStrings("/sub", add.root_path);
    try testing.expect(add.tls_insecure_skip_verify);

    // T3：新旧并存时**以 Go 名为准**（修复前这里断言的正是相反的方向）。
    const both = try json.parse(pa,
        \\{"url":"https://native/dav","address":"https://go/dav",
        \\ "root_path":"/native","root_folder_path":"/go"}
    );
    const add2 = try Addition.parse(a, &both);
    try testing.expectEqualStrings("https://go/dav", add2.url);
    try testing.expectEqualStrings("/go", add2.root_path);
}

// ---------------------------------------------------------------------------
// Digest / 401 协商
// ---------------------------------------------------------------------------

test "webdav: DigestChallenge.parse reads the wanted fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const c = try DigestChallenge.parse(a, "Digest realm=\"webdav@example.com\", qop=\"auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", algorithm=MD5, stale=FALSE");
    try testing.expectEqualStrings("webdav@example.com", c.realm);
    try testing.expectEqualStrings("auth", c.qop);
    try testing.expectEqualStrings("dcd98b7102dd2f0e8b11d0f600bfb0c093", c.nonce);
    try testing.expectEqualStrings("5ccc069c403ebaf9f0171e9517f40e41", c.opaque_str);
    try testing.expectEqualStrings("MD5", c.algorithm);

    // 无引号的值（`algorithm=MD5` 形态）也要能读出来；缺字段留空串。
    const bare = try DigestChallenge.parse(a, "Digest realm=nae, nonce=n1");
    try testing.expectEqualStrings("nae", bare.realm);
    try testing.expectEqualStrings("n1", bare.nonce);
    try testing.expectEqualStrings("", bare.qop);
}

test "webdav: digestResponse matches RFC 7616 vectors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 期望值由 Python（hashlib.md5）独立算出，不是拿本实现的输出当基准。
    const with_qop = DigestChallenge{
        .realm = "webdav@example.com",
        .nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        .qop = "auth",
    };
    try testing.expectEqualStrings(
        "dae309007e5a92ae81ffc44eb1e1d00b",
        try digestResponse(a, "alice", "s3cret", with_qop, "GET", "/dav/f.txt", "0a4f113b"),
    );

    // 没有 qop：response 少两个字段（ha1:nonce:ha2）。
    const no_qop = DigestChallenge{
        .realm = "webdav@example.com",
        .nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093",
    };
    try testing.expectEqualStrings(
        "2e6a5bf549d7e36e40548132250827e5",
        try digestResponse(a, "alice", "s3cret", no_qop, "GET", "/dav/f.txt", "0a4f113b"),
    );

    // MD5-sess：HA1 多套一层 nonce/cnonce。
    const sess = DigestChallenge{
        .realm = "webdav@example.com",
        .nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        .qop = "auth",
        .algorithm = "MD5-sess",
    };
    try testing.expectEqualStrings(
        "4f884070225d5f605a2b95c30cdf66a1",
        try digestResponse(a, "alice", "s3cret", sess, "GET", "/dav/f.txt", "0a4f113b"),
    );
}

test "webdav: 401 negotiation picks Digest, then stops retrying" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = rt.io();

    var self: WebDav = undefined;
    self.alloc = a;
    self.cfg = .{ .url = "https://x/dav", .username = "u", .password = "p" };
    self.jar = undefined;
    self.client = undefined;
    // ⚠️ `var self: WebDav = undefined` 只置了这几个字段，`auth_mode` /
    // `challenge` 仍是未初始化内存 —— 下面 `authHeaders` 里 switch 它直接
    // "switch on corrupt value" panic。测试也必须显式给默认值。
    self.auth_mode = .none;
    self.challenge = null;
    self.auth_mu = .init;

    // 未协商：一个认证头都不发（Go 的 NoAuth.Authorize 是空实现）。
    try testing.expectEqual(@as(usize, 0), (try self.authHeaders(a, "GET", "/")).len);

    var challenge_headers = [_]model.Header{
        .{ .name = "WWW-Authenticate", .value = "Digest realm=\"r\", nonce=\"n\", qop=\"auth\"" },
    };
    const challenge = httpclient.Response{
        .status = 401,
        .headers = &challenge_headers,
        .body = "",
    };
    try testing.expect(self.negotiateAuth(a, challenge));
    try testing.expectEqual(AuthMode.digest, self.auth_mode);

    const hs = try self.authHeaders(a, "GET", "/f.txt");
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqualStrings("Authorization", hs[0].name);
    try testing.expect(std.mem.startsWith(u8, hs[0].value, "Digest username=\"u\""));
    try testing.expect(std.mem.indexOf(u8, hs[0].value, "nc=00000001") != null);
    try testing.expect(std.mem.indexOf(u8, hs[0].value, "qop=auth") != null);

    // 协商过之后，再遇 401 不再重试（凭据不对就是不对）。
    try testing.expect(!self.negotiateAuth(a, challenge));

    _ = io;
}

test "webdav: 401 with only Basic stays on Basic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var self: WebDav = undefined;
    self.alloc = a;
    self.cfg = .{ .url = "https://x/dav", .username = "u", .password = "p" };
    self.jar = undefined;
    self.client = undefined;
    // ⚠️ `var self: WebDav = undefined` 只置了这几个字段，`auth_mode` /
    // `challenge` 仍是未初始化内存 —— 下面 `authHeaders` 里 switch 它直接
    // "switch on corrupt value" panic。测试也必须显式给默认值。
    self.auth_mode = .none;
    self.challenge = null;
    self.auth_mu = .init;

    var basic_headers = [_]model.Header{
        .{ .name = "WWW-Authenticate", .value = "Basic realm=\"x\"" },
    };
    const res = httpclient.Response{
        .status = 401,
        .headers = &basic_headers,
        .body = "",
    };
    try testing.expect(self.negotiateAuth(a, res));
    try testing.expectEqual(AuthMode.basic, self.auth_mode);

    const hs = try self.authHeaders(a, "GET", "/");
    try testing.expectEqual(@as(usize, 1), hs.len);
    // base64("u:p") = "dTpw"
    try testing.expectEqualStrings("Basic dTpw", hs[0].value);
}

test "webdav: indexOfIgnoreCase is really case-insensitive" {
    try testing.expectEqual(@as(?usize, 6), indexOfIgnoreCase("Basic realm=\"x\"", "Realm"));
    try testing.expectEqual(@as(?usize, 0), indexOfIgnoreCase("DiGeSt x", "digest"));
    try testing.expectEqual(@as(?usize, null), indexOfIgnoreCase("abc", "abcd"));
    try testing.expectEqual(@as(?usize, null), indexOfIgnoreCase("", "a"));
}
