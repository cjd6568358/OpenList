//! 115 云盘驱动 —— Go 版 `drivers/115`（`config.Name = "115 Cloud"`）的 Zig 移植（T2）。
//!
//! 这是需求清单里三个「补课」驱动的最后一个（前两个：pan123 / quarkuc）。
//! key 必须逐字等于 Go 的 `115 Cloud`（`drivers/115/meta.go:28`），因为它就是
//! 写进配置 `Storage.driver` 的值。
//!
//! 与 `115open.zig`（开放平台变体）是**同一个网盘的两个不同驱动**：本驱动用
//! **Cookie 登录**（UID/CID/SEID/KID），走 `webapi.115.com` / `proapi.115.com`
//! 那套老接口，上传要过 `ec115`（P-224 ECDH）加密的 `initupload`。
//!
//! 移植时重点核对过的几处：
//!   1. **登录**：`Credential.FromCookie` 把 `UID/CID/SEID/KID` 抠出来，
//!      `LoginCheck`（`passportapi.115.com/.../check/sso`）里 **`state == 0`
//!      才算成功**（反直觉，但 Go 就是这么判的）。
//!   2. **列表是 ID 寻址**：`GET /files?cid=<id>&...`，目录的 id 在 `cid`
//!      字段、文件的在 `fid`；路径要先逐级 resolve 成 id。
//!   3. **字段名是极短的缩写**：`n`(name) `s`(size) `fid` `cid` `pid` `pc`(pickcode)
//!      `sha` `tp`(create) `t`(update) `u`(thumb) `ico` `fl`(labels)。
//!   4. **上传三段式**：闪传（`ec115` 加密的 `initupload`）→ 失败则 OSS
//!      普通 PUT（≤10MB）或 OSS 分片（>10MB）。
//!
//! 与 Go 版的差异（有意为之）：二维码登录未移植（需要 qrcode 会话状态机，
//! 而用户配置走的是 Cookie）；离线下载未移植；`Copy` vtable 没有槽位。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const urlmod = @import("../util/url.zig");
const ec115 = @import("../util/ec115.zig");
const m115 = @import("../util/m115.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量（115driver/pkg/driver/{api,consts}.go、drivers/115/appver.go）
// ---------------------------------------------------------------------------

const api_login_check = "https://passportapi.115.com/app/1.0/web/1.0/check/sso";
const api_dir_add = "https://webapi.115.com/files/add";
const api_file_delete = "https://webapi.115.com/rb/delete";
const api_file_move = "https://webapi.115.com/files/move";
const api_file_copy = "https://webapi.115.com/files/copy";
const api_file_rename = "https://webapi.115.com/files/batch_rename";
const api_file_index_info = "https://webapi.115.com/files/index_info";
const api_file_list = "https://webapi.115.com/files";
const api_file_info = "https://webapi.115.com/files/get_info";
const api_download_get_url = "https://proapi.115.com/app/chrome/downurl";
const api_upload_info = "https://proapi.115.com/app/uploadinfo";
const api_upload_init = "https://uplb.115.com/4.0/initupload.php";
const api_upload_oss_token = "https://uplb.115.com/3.0/gettoken.php";

const oss_endpoint = "cn-shenzhen.oss.aliyuncs.com";
const oss_user_agent = "aliyun-sdk-android/2.9.1";
const oss_security_token_header = "X-OSS-Security-Token";

/// `drivers/115/appver.go:12` —— 用户备份的 Go 版用的就是这个版本号。
const md5_salt = "Qclm8MGWUv59TnrR0XPg";
const app_ver = "35.6.0.3";

const default_root = "0";
/// `driver/dir.go:35`：单页上限，超过就按这个截断。
const max_dir_page_limit: i64 = 1150;
/// `drivers/115/driver.go:213`：≤10MB 走普通 OSS PUT，否则分片。
const oss_single_max: i64 = 10 * 1024 * 1024;
/// 预哈希长度（`drivers/115/driver.go:172`）。
const pre_hash_size: i64 = 128 * 1024;
const kb: i64 = 1024;
const mb: i64 = 1024 * 1024;
const gb: i64 = 1024 * 1024 * 1024;

pub const Error = error{
    /// 没配 Cookie，或 Cookie 解析失败。
    AuthFailed,
    UpstreamHttp,
    UpstreamNotJson,
    UpstreamError,
    InvalidResponse,
    InvalidPath,
    UploadFailed,
};

// ---------------------------------------------------------------------------
// 配置（drivers/115/meta.go）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    cookie: []const u8 = "",
    qrcode_token: []const u8 = "",
    qrcode_source: []const u8 = "linux",
    page_size: i64 = 1000,
    limit_rate: f64 = 2,
    /// 内嵌 `driver.RootID` → JSON 键 `root_folder_id`。
    root_folder_id: []const u8 = default_root,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        a.cookie = try dupeOr(alloc, o.strAt("cookie"), "");
        a.qrcode_token = try dupeOr(alloc, o.strAt("qrcode_token"), "");
        a.qrcode_source = try dupeOr(alloc, o.strAt("qrcode_source"), "linux");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        if (o.intAt("page_size")) |n| a.page_size = n;
        if (o.getPath("limit_rate")) |x| {
            if (x.asFloat()) |f| a.limit_rate = f;
        }
        return a;
    }

    /// 键名与 Go 的序列化形态逐字一致（字段声明顺序）。
    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        try b.append("{\"cookie\":");
        try json.writeString(&b, self.cookie);
        try b.append(",\"qrcode_token\":");
        try json.writeString(&b, self.qrcode_token);
        try b.append(",\"qrcode_source\":");
        try json.writeString(&b, self.qrcode_source);
        try b.print(",\"page_size\":{d},\"limit_rate\":{d},\"root_folder_id\":", .{ self.page_size, self.limit_rate });
        try json.writeString(&b, self.root_folder_id);
        try b.append("}");
        return b.toOwned();
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    return alloc.dupe(u8, v orelse fallback);
}

fn arrAt(v: *const json.Value, path: []const u8) []json.Value {
    const x = v.getPath(path) orelse return &.{};
    return x.asArray() orelse &.{};
}

/// 数值字段：JSON 可能是整数，也可能是数字字符串（`StringInt64`）。
fn numAt(v: *const json.Value, path: []const u8) ?i64 {
    const x = v.getPath(path) orelse return null;
    if (x.asInt()) |n| return n;
    if (x.asStr()) |s| return std.fmt.parseInt(i64, std.mem.trim(u8, s, " \t"), 10) catch null;
    return null;
}

/// `BoolInt`：JSON 可能是整数，也可能是 `false`（Go 里 `false` → -1）。
fn boolIntAt(v: *const json.Value, path: []const u8) i64 {
    const x = v.getPath(path) orelse return 0;
    if (x.asInt()) |n| return n;
    if (x.asBool()) |b| return if (b) 1 else -1;
    return 0;
}

/// `BasicResp`：`state == true` 才算成功；没有 `state` 字段时看 errno。
fn basicOk(v: *const json.Value) bool {
    if (v.getPath("state")) |s| {
        if (s.asBool()) |b| return b;
    }
    const e1 = v.intAt("errno") orelse 0;
    const e2 = v.intAt("errNo") orelse 0;
    return e1 == 0 and e2 == 0;
}

fn errCodeOf(v: *const json.Value) i64 {
    const e1 = v.intAt("errno") orelse 0;
    if (e1 != 0) return e1;
    return v.intAt("errNo") orelse 0;
}

/// `error.go:errMap` 的子集（只映射本工程会 surface 出来的码）。
fn mapUpstreamError(code: i64) anyerror {
    return switch (code) {
        99, 990001 => Error.AuthFailed,
        20004, 21003 => error.AlreadyExists,
        70005, 231011, 50015 => driver.Error.NotFound,
        50003, 50001 => driver.Error.NotFound,
        else => Error.UpstreamError,
    };
}

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------

pub const Pan115 = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    client: httpclient.Client,
    /// 规范化后的 `UID=..;CID=..;SEID=..;KID=..`，每个请求都带上。
    cookie: []const u8 = "",
    user_id: i64 = 0,
    userkey: []const u8 = "",
    /// 串行化同一驱动的请求（顺带保护 cookie/userkey 的并发写）。
    req_mu: std.Io.Mutex = .init,
    /// 上次请求时间（毫秒），用于 `limit_rate` 限速。
    last_req_ms: i64 = 0,

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
        .space = space,
    };

    fn drvName(_: *anyopaque) []const u8 {
        return "115 Cloud";
    }

    fn ua(self: *Pan115, arena: std.mem.Allocator) ![]const u8 {
        _ = self;
        return std.fmt.allocPrint(arena, "Mozilla/5.0 115Browser/{s}", .{app_ver});
    }

    /// 限速 + 发一次带 115 头的请求。
    fn request(
        self: *Pan115,
        arena: std.mem.Allocator,
        method: []const u8,
        url: []const u8,
        body: []const u8,
        extra: []const model.Header,
    ) !httpclient.Response {
        const io = rt.io();
        self.req_mu.lockUncancelable(io);
        defer self.req_mu.unlock(io);

        // `limit_rate` 是「每秒多少次」；0 表示不限速。
        if (self.cfg.limit_rate > 0) {
            const interval_ms: i64 = @intFromFloat(1000.0 / self.cfg.limit_rate);
            const now = rt.nowMillis();
            const delta = now - self.last_req_ms;
            if (delta < interval_ms) rt.sleepMillis(interval_ms - delta);
            self.last_req_ms = rt.nowMillis();
        }

        var hdrs = List(model.Header).init(arena);
        try hdrs.append(.{ .name = "User-Agent", .value = try self.ua(arena) });
        try hdrs.append(.{ .name = "Cookie", .value = self.cookie });
        try hdrs.append(.{ .name = "Referer", .value = "https://115.com/" });
        for (extra) |h| try hdrs.append(h);

        return self.client.send(arena, .{
            .method = method,
            .url = url,
            .headers = hdrs.slice(),
            .body = body,
            .use_cookies = false,
        });
    }

    fn get(self: *Pan115, arena: std.mem.Allocator, url: []const u8) ![]const u8 {
        const res = try self.request(arena, "GET", url, "", &.{});
        if (res.status < 200 or res.status >= 300) {
            log.warn("[115] GET {s} -> HTTP {d}", .{ url, res.status });
            return Error.UpstreamHttp;
        }
        return res.body;
    }

    fn postForm(self: *Pan115, arena: std.mem.Allocator, url: []const u8, form: []const [2][]const u8) ![]const u8 {
        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(form);
        const res = try self.request(arena, "POST", url, q.slice(), &.{
            .{ .name = "Content-Type", .value = "application/json;charset=UTF-8" },
        });
        if (res.status < 200 or res.status >= 300) {
            log.warn("[115] POST {s} -> HTTP {d}", .{ url, res.status });
            return Error.UpstreamHttp;
        }
        return res.body;
    }
};

fn as(p: *anyopaque) *Pan115 {
    return @ptrCast(@alignCast(p));
}

// ---------------------------------------------------------------------------
// Credential（login.go:86-124）
// ---------------------------------------------------------------------------

const Credential = struct {
    uid: []const u8,
    cid: []const u8,
    seid: []const u8,
    kid: []const u8,

    /// `Credential.FromCookie` —— 大小写不敏感，缺失 UID/CID/SEID 直接失败。
    fn fromCookie(alloc: std.mem.Allocator, cookie: []const u8) !Credential {
        var uid: []const u8 = "";
        var cid: []const u8 = "";
        var seid: []const u8 = "";
        var kid: []const u8 = "";
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, cookie, ';');
        while (it.next()) |raw| {
            const pair = std.mem.trim(u8, raw, " \t");
            if (pair.len == 0) continue;
            n += 1;
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return Error.AuthFailed;
            const k = std.mem.trim(u8, pair[0..eq], " \t");
            const v = std.mem.trim(u8, pair[eq + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(k, "UID")) uid = v;
            if (std.ascii.eqlIgnoreCase(k, "CID")) cid = v;
            if (std.ascii.eqlIgnoreCase(k, "SEID")) seid = v;
            if (std.ascii.eqlIgnoreCase(k, "KID")) kid = v;
        }
        if (n < 3) return Error.AuthFailed;
        if (uid.len == 0 or cid.len == 0 or seid.len == 0) return Error.AuthFailed;
        _ = alloc;
        return .{ .uid = uid, .cid = cid, .seid = seid, .kid = kid };
    }

    /// `Credential.Cookie`。
    fn toCookie(self: Credential, alloc: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(alloc, "UID={s};CID={s};SEID={s};KID={s}", .{ self.uid, self.cid, self.seid, self.kid });
    }
};

// ---------------------------------------------------------------------------
// 路径 → id
// ---------------------------------------------------------------------------

const Entry = struct {
    id: []const u8,
    name: []const u8,
    is_dir: bool,
    raw: ?*const json.Value = null,
};

/// `FileInfo` → `Entry`。目录没有 `fid`，id 取 `cid`；文件取 `fid`。
/// 返回的切片借用 `item`（调用方持有 arena）。
fn entryFrom(item: *const json.Value) !Entry {
    const fid = item.strAt("fid") orelse "";
    const name = item.strAt("n") orelse "";
    if (fid.len > 0) {
        return .{ .id = fid, .name = name, .is_dir = false, .raw = item };
    }
    const cid = item.strAt("cid") orelse return Error.InvalidResponse;
    return .{ .id = cid, .name = name, .is_dir = true, .raw = item };
}

fn objFrom(entry: Entry) model.Obj {
    const raw = entry.raw;
    var size: i64 = 0;
    var created: i64 = 0;
    var modified: i64 = 0;
    if (raw) |r| {
        size = numAt(r, "s") orelse 0;
        created = numAt(r, "tp") orelse 0;
        if (entry.is_dir) {
            modified = numAt(r, "t") orelse 0;
        } else {
            modified = parseCstMinutes(r.strAt("t") orelse "") orelse 0;
        }
    }
    return .{
        .name = entry.name,
        .size = size,
        .is_dir = entry.is_dir,
        .modified = modified,
        .created = created,
    };
}

/// 解析 `"2006-01-02 15:04"`（CST = UTC+8）为 unix 秒。
fn parseCstMinutes(s: []const u8) ?i64 {
    if (s.len < 16) return null;
    const year = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const mon = std.fmt.parseInt(i64, s[5..7], 10) catch return null;
    const day = std.fmt.parseInt(i64, s[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const min = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    if (mon < 1 or mon > 12 or day < 1 or day > 31) return null;
    const days = daysFromCivil(year, mon, day);
    const secs = days * 86400 + hour * 3600 + min * 60 - 8 * 3600;
    return secs;
}

/// Howard Hinnant 的 `days_from_civil`。
fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    var y = y_in;
    if (m <= 2) y -= 1;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const doy = @divTrunc(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + d - 1;
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// 列一页（`driver/dir.go:109-144` 的 `GetFiles`）。
fn listPage(self: *Pan115, arena: std.mem.Allocator, dir_id: []const u8, offset: i64, limit: i64) !*const json.Value {
    const cid = if (dir_id.len == 0) default_root else dir_id;
    const url = try std.fmt.allocPrint(arena, "{s}?aid=1&cid={s}&o=user_ptime&asc=1&offset={d}&show_dir=1&limit={d}&snap=0&natsort=0&record_open_time=1&format=json&fc_mix=0", .{ api_file_list, cid, offset, limit });
    const body = try self.get(arena, url);
    const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
    return &v;
}

fn listAll(self: *Pan115, arena: std.mem.Allocator, dir_id: []const u8, out: *List(model.Obj)) !void {
    var limit = self.cfg.page_size;
    if (limit <= 0) limit = 56; // driver115.FileListLimit
    if (limit > max_dir_page_limit) limit = max_dir_page_limit;

    var offset: i64 = 0;
    while (true) {
        const v = try listPage(self, arena, dir_id, offset, limit);
        const items = arrAt(v, "data");
        for (items) |*item| {
            const e = try entryFrom(item);
            try out.append(objFrom(e));
        }
        const count = numAt(v, "count") orelse 0;
        offset += limit;
        if (items.len == 0 or offset >= count) break;
    }
}

/// 在一级目录下按名字找子项。
fn findChild(self: *Pan115, arena: std.mem.Allocator, parent_id: []const u8, name: []const u8) !Entry {
    var limit = self.cfg.page_size;
    if (limit <= 0) limit = 56;
    if (limit > max_dir_page_limit) limit = max_dir_page_limit;

    var offset: i64 = 0;
    while (true) {
        const v = try listPage(self, arena, parent_id, offset, limit);
        const items = arrAt(v, "data");
        for (items) |*item| {
            const e = try entryFrom(item);
            if (std.mem.eql(u8, e.name, name)) return e;
        }
        const count = numAt(v, "count") orelse 0;
        offset += limit;
        if (items.len == 0 or offset >= count) break;
    }
    return driver.Error.NotFound;
}

/// 逐级 resolve 一个路径（`/` 或空串 = 根）。
fn resolve(self: *Pan115, arena: std.mem.Allocator, path: []const u8) !Entry {
    var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |seg| {
        if (!cur.is_dir) return driver.Error.NotFound;
        cur = try findChild(self, arena, cur.id, seg);
    }
    return cur;
}

fn resolveId(self: *Pan115, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    return (try resolve(self, arena, path)).id;
}

// ---------------------------------------------------------------------------
// vtable
// ---------------------------------------------------------------------------

fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    if (self.cfg.cookie.len == 0) {
        log.err("[115] no cookie configured (qrcode login is not ported)", .{});
        return Error.AuthFailed;
    }
    const cr = try Credential.fromCookie(a, self.cfg.cookie);
    // 用驱动自己的 allocator：`ctx.alloc` 是请求级 arena，init 返回后就没了。
    self.cookie = try cr.toCookie(self.alloc);

    // LoginCheck：`state == 0` 才算成功（`login.go:28-39`，`_` 是毫秒）。
    const url = try std.fmt.allocPrint(a, "{s}?_={d}", .{ api_login_check, rt.nowMillis() });
    const body = try self.get(a, url);
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if ((v.intAt("state") orelse 0) != 0) {
        log.err("[115] login check failed: {s}", .{v.strAt("message") orelse v.strAt("error") orelse ""});
        return Error.AuthFailed;
    }
    if (numAt(&v, "data.user_id")) |id| self.user_id = id;
}

fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
    const self = as(ptr);
    _ = ctx;
    self.client.deinit();
}

fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
    const self = as(ptr);
    const a = ctx.alloc;
    const e = try resolve(self, a, dir);
    if (!e.is_dir) return driver.Error.NotFound;
    var out = List(model.Obj).init(a);
    try listAll(self, a, e.id, &out);
    return out.toOwned();
}

fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
    const self = as(ptr);
    const a = ctx.alloc;
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    if (it.next() == null) return .{ .name = "/", .is_dir = true };
    const e = try resolve(self, a, path);
    const o = objFrom(e);
    return model.File.fromObj(o);
}

fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
    const self = as(ptr);
    const a = ctx.alloc;
    const e = try resolve(self, a, path);
    if (e.is_dir) return driver.Error.NotSupported;
    const pick = if (e.raw) |r| (r.strAt("pc") orelse "") else "";
    if (pick.len == 0) return Error.InvalidResponse;

    // `driver.go:70-79`：UA 透传给 downurl（下载地址可能绑定 UA）。
    var ua: []const u8 = "";
    for (args.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "User-Agent")) ua = h.value;
    }
    const info = try downloadWithUa(self, a, pick, ua);
    return .{
        .url = info.url,
        .header = info.header,
    };
}

fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const name = pathBase(dir) orelse return Error.InvalidPath;
    const parent_id = try resolveId(self, a, pathParent(dir) orelse return Error.InvalidPath);
    const body = try self.postForm(a, api_dir_add, &.{
        .{ "pid", parent_id },
        .{ "cname", name },
    });
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
}

/// Go `drivers/115/driver.go` 的 Copy = `WaitLimit` + `client.Copy(pid, fid)`，
/// 即 `files/copy` 的 `pid` + `fid[0]` —— 与 Move 同形，只有 URL 不同。
fn copy(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const src_id = try resolveId(self, a, src);
    const dst_id = try resolveId(self, a, dst_dir);
    const body = try self.postForm(a, api_file_copy, &.{
        .{ "pid", dst_id },
        .{ "fid[0]", src_id },
    });
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
}

fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const src_id = try resolveId(self, a, src);
    const dst_id = try resolveId(self, a, dst_dir);
    const body = try self.postForm(a, api_file_move, &.{
        .{ "pid", dst_id },
        .{ "fid[0]", src_id },
    });
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
}

fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const src_id = try resolveId(self, a, src);
    const key = try std.fmt.allocPrint(a, "files_new_name[{s}]", .{src_id});
    const body = try self.postForm(a, api_file_rename, &.{
        .{ "fid", src_id },
        .{ "file_name", new_name },
        .{ key, new_name },
    });
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
}

fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = is_dir;
    const id = try resolveId(self, a, path);
    const body = try self.postForm(a, api_file_delete, &.{
        .{ "fid[0]", id },
    });
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
}

fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
    const self = as(ptr);
    const a = ctx.alloc;
    const body = try self.get(a, api_file_index_info);
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
    return .{
        .total = numAt(&v, "data.space_info.all_total.size") orelse 0,
        .used = numAt(&v, "data.space_info.all_use.size") orelse 0,
    };
}

fn pathBase(path: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/\\");
    if (trimmed.len == 0) return null;
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse
        std.mem.lastIndexOfScalar(u8, trimmed, '\\') orelse return trimmed;
    return trimmed[slash + 1 ..];
}

fn pathParent(path: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/\\");
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse
        std.mem.lastIndexOfScalar(u8, trimmed, '\\') orelse return null;
    if (slash == 0) return "/";
    return trimmed[0..slash];
}

// ---------------------------------------------------------------------------
// 下载（download.go:69-108）—— m115 加密的 downurl
// ---------------------------------------------------------------------------

const DownloadInfo = struct {
    url: []const u8,
    header: []const model.Header,
};

fn downloadWithUa(self: *Pan115, arena: std.mem.Allocator, pick_code: []const u8, ua: []const u8) !DownloadInfo {
    var src: std.Random.IoSource = .{ .io = rt.io() };
    const rnd = src.interface();
    const key = m115.generateKey(rnd);

    const params = try std.fmt.allocPrint(arena, "{{\"pickcode\":\"{s}\"}}", .{pick_code});
    const data = try m115.encode(arena, params, key, rnd);

    const url = try std.fmt.allocPrint(arena, "{s}?t={d}", .{ api_download_get_url, rt.nowSeconds() });
    var q = urlmod.Query.init(arena);
    defer q.deinit();
    try q.add("data", data);

    var extra = List(model.Header).init(arena);
    try extra.append(.{ .name = "Content-Type", .value = "application/json" });
    if (ua.len > 0) try extra.append(.{ .name = "User-Agent", .value = ua });
    const res = try self.request(arena, "POST", url, q.slice(), extra.slice());
    if (res.status < 200 or res.status >= 300) return Error.UpstreamHttp;

    const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
    const encoded = v.strAt("data") orelse return Error.InvalidResponse;
    const decoded = try m115.decode(arena, encoded, key);
    const dv = json.parse(arena, decoded) catch return Error.UpstreamNotJson;

    // DownloadData 是 map[string]DownloadInfo，取第一个非负 size 的。
    const obj = dv.asObject() orelse return Error.InvalidResponse;
    for (obj.keys, obj.vals) |_, *info| {
        const size = numAt(info, "file_size") orelse 0;
        if (size < 0) return Error.UpstreamError;
        const u = info.strAt("url.url") orelse return Error.InvalidResponse;
        return .{ .url = u, .header = &.{} };
    }
    return Error.InvalidResponse;
}

// ---------------------------------------------------------------------------
// 上传（drivers/115/{driver,util}.go）
// ---------------------------------------------------------------------------

const UploadInit = struct {
    status: i64,
    pickcode: []const u8 = "",
    sign_key: []const u8 = "",
    sign_check: []const u8 = "",
    bucket: []const u8 = "",
    object: []const u8 = "",
    callback: []const u8 = "",
    callback_var: []const u8 = "",
};

const UploadMeta = struct {
    size_limit: i64,
    user_id: i64,
    userkey: []const u8,
};

/// `POST /app/uploadinfo` → userkey + user_id + meta（`upload.go:44-57`）。
fn getUploadInfo(self: *Pan115, arena: std.mem.Allocator) !UploadMeta {
    const res = try self.request(arena, "POST", api_upload_info, "", &.{
        .{ .name = "Content-Type", .value = "application/json;charset=UTF-8" },
    });
    if (res.status < 200 or res.status >= 300) return Error.UpstreamHttp;
    const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
    if (!basicOk(&v)) return mapUpstreamError(errCodeOf(&v));
    const userkey = v.strAt("userkey") orelse "";
    const uid = numAt(&v, "user_id") orelse 0;
    // userkey 要活过本次请求，用驱动自己的 allocator 存。
    self.userkey = try self.alloc.dupe(u8, userkey);
    if (uid != 0) self.user_id = uid;
    return .{
        .size_limit = numAt(&v, "size_limit") orelse std.math.maxInt(i64),
        .user_id = uid,
        .userkey = self.userkey,
    };
}

fn ensureUploadAvailable(self: *Pan115, arena: std.mem.Allocator) !UploadMeta {
    if (self.user_id != 0 and self.userkey.len > 0) {
        return .{ .size_limit = std.math.maxInt(i64), .user_id = self.user_id, .userkey = self.userkey };
    }
    return getUploadInfo(self, arena);
}

/// `drivers/115/util.go:109-114` `GenerateToken`（注意 `preID` 参数**没被用到**，
/// 这是 Go 原样的行为）。
fn generateToken(alloc: std.mem.Allocator, user_id: i64, file_id: []const u8, file_size: i64, sign_key: []const u8, sign_val: []const u8, timestamp: i64) ![]const u8 {
    var uid_buf: [24]u8 = undefined;
    const uid = std.fmt.bufPrint(&uid_buf, "{d}", .{user_id}) catch unreachable;
    const um = hash.md5(uid);
    const um_hex = try hash.hexLower(alloc, &um);

    var size_buf: [24]u8 = undefined;
    const size_s = std.fmt.bufPrint(&size_buf, "{d}", .{file_size}) catch unreachable;
    var ts_buf: [24]u8 = undefined;
    const ts_s = std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp}) catch unreachable;

    var b = Buf.init(alloc);
    defer b.deinit();
    try b.print("{s}{s}{s}{s}{s}{s}{s}{s}{s}", .{ md5_salt, file_id, size_s, sign_key, sign_val, uid, ts_s, um_hex, app_ver });
    const t = hash.md5(b.slice());
    return hash.hexLower(alloc, &t);
}

/// `drivers/115/util.go` `GenerateSignature`（115driver `upload.go:303-308`）。
fn generateSignature(alloc: std.mem.Allocator, user_id: i64, userkey: []const u8, file_id: []const u8, target: []const u8) ![]const u8 {
    var uid_buf: [24]u8 = undefined;
    const uid = std.fmt.bufPrint(&uid_buf, "{d}", .{user_id}) catch unreachable;

    var b1 = Buf.init(alloc);
    defer b1.deinit();
    try b1.print("{s}{s}{s}0", .{ uid, file_id, target });
    const h1 = hash.sha1(b1.slice());
    const h1_hex = try hash.hexLower(alloc, &h1);

    var b2 = Buf.init(alloc);
    defer b2.deinit();
    try b2.print("{s}{s}000000", .{ userkey, h1_hex });
    const h2 = hash.sha1(b2.slice());
    return hash.hexUpper(alloc, &h2);
}

/// 分片区间 SHA1（`util.go:201-218` `UploadDigestRange`）：`"start-end"` 闭区间。
fn uploadDigestRange(alloc: std.mem.Allocator, src: model.Source, range_spec: []const u8) ![]const u8 {
    const dash = std.mem.indexOfScalar(u8, range_spec, '-') orelse return Error.InvalidResponse;
    const start = std.fmt.parseInt(i64, range_spec[0..dash], 10) catch return Error.InvalidResponse;
    const end = std.fmt.parseInt(i64, range_spec[dash + 1 ..], 10) catch return Error.InvalidResponse;
    const len: usize = @intCast(end - start + 1);
    const buf = try alloc.alloc(u8, len);
    try src.readAllInto(@intCast(start), buf);
    return hash.sha1HexUpper(alloc, buf);
}

/// 一遍读，算首 128KB 与整文件两个 SHA1（`driver.go:172-193`）。
const Digest = struct { pre_id: []const u8, full_id: []const u8 };

fn digest(alloc: std.mem.Allocator, src: model.Source) !Digest {
    const size = src.size();
    if (size < 0) return Error.InvalidPath;

    var sha_pre = hash.Sha1.init(.{});
    var sha_full = hash.Sha1.init(.{});
    const chunk_len: usize = @intCast(@min(@as(i64, 256 * 1024), @max(size, 1)));
    const buf = try alloc.alloc(u8, chunk_len);

    var off: u64 = 0;
    const total: u64 = @intCast(size);
    const pre_limit: u64 = @intCast(@min(pre_hash_size, size));
    while (off < total) {
        const want: usize = @intCast(@min(@as(u64, chunk_len), total - off));
        try src.readAllInto(off, buf[0..want]);
        // 首 128KB 进 pre 哈希
        if (off < pre_limit) {
            const pre_want: usize = @intCast(@min(@as(u64, want), pre_limit - off));
            sha_pre.update(buf[0..pre_want]);
        }
        sha_full.update(buf[0..want]);
        off += want;
    }
    var dpre: [20]u8 = undefined;
    sha_pre.final(&dpre);
    var dfull: [20]u8 = undefined;
    sha_full.final(&dfull);
    return .{
        .pre_id = try hash.hexUpper(alloc, &dpre),
        .full_id = try hash.hexUpper(alloc, &dfull),
    };
}

/// `util.go:116-199` `rapidUpload`：ec115 加密的 initupload，含 status==7 重试。
fn rapidUpload(
    self: *Pan115,
    arena: std.mem.Allocator,
    file_size: i64,
    file_name: []const u8,
    dir_id: []const u8,
    pre_id: []const u8,
    file_id: []const u8,
    src: model.Source,
) !UploadInit {
    // Go 的 GenerateToken 收了 preID 却没用它（`util.go:109-114`）—— 保持一致。
    _ = pre_id;
    var src_rand: std.Random.IoSource = .{ .io = rt.io() };
    const rnd = src_rand.interface();
    const cipher = ec115.newCipher(rnd);

    var target_buf = Buf.init(arena);
    try target_buf.print("U_1_{s}", .{dir_id});
    const target = target_buf.slice();

    var size_buf: [24]u8 = undefined;
    const size_s = std.fmt.bufPrint(&size_buf, "{d}", .{file_size}) catch unreachable;

    const sig = try generateSignature(arena, self.user_id, self.userkey, file_id, target);

    var sign_key: []const u8 = "";
    var sign_val: []const u8 = "";

    while (true) {
        const t = rt.nowMillis();
        const encoded_token = ec115.encodeTokenRandom(cipher, @truncate(@as(u64, @bitCast(t))), rnd);

        const token = try generateToken(arena, self.user_id, file_id, file_size, sign_key, sign_val, t);

        var uid_buf: [24]u8 = undefined;
        const uid = std.fmt.bufPrint(&uid_buf, "{d}", .{self.user_id}) catch unreachable;
        var t_buf: [24]u8 = undefined;
        const t_s = std.fmt.bufPrint(&t_buf, "{d}", .{t}) catch unreachable;

        var pairs = List([2][]const u8).init(arena);
        try pairs.append(.{ "appid", "0" });
        try pairs.append(.{ "appversion", app_ver });
        try pairs.append(.{ "userid", uid });
        try pairs.append(.{ "filename", file_name });
        try pairs.append(.{ "filesize", size_s });
        try pairs.append(.{ "fileid", file_id });
        try pairs.append(.{ "target", target });
        try pairs.append(.{ "sig", sig });
        try pairs.append(.{ "t", t_s });
        try pairs.append(.{ "token", token });
        if (sign_key.len > 0 and sign_val.len > 0) {
            try pairs.append(.{ "sign_key", sign_key });
            try pairs.append(.{ "sign_val", sign_val });
        }

        var form = urlmod.Query.init(arena);
        defer form.deinit();
        try form.addSorted(pairs.slice());
        const encrypted = try ec115.encrypt(arena, cipher, form.slice());

        const url = try std.fmt.allocPrint(arena, "{s}?k_ec={s}", .{ api_upload_init, encoded_token });
        const res = try self.request(arena, "POST", url, encrypted, &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
        });
        if (res.status < 200 or res.status >= 300) return Error.UpstreamHttp;

        const decrypted = try ec115.decrypt(arena, cipher, res.body);
        const v = json.parse(arena, decrypted) catch return Error.UpstreamNotJson;

        const status = boolIntAt(&v, "status");
        const err_code = numAt(&v, "statuscode") orelse 0;
        if (err_code != 0 and err_code != 701) {
            log.warn("[115] initupload code {d}: {s}", .{ err_code, v.strAt("statusmsg") orelse "" });
            return mapUpstreamError(err_code);
        }

        const result = UploadInit{
            .status = status,
            .pickcode = try dupeOr(arena, v.strAt("pickcode"), ""),
            .sign_key = try dupeOr(arena, v.strAt("sign_key"), ""),
            .sign_check = try dupeOr(arena, v.strAt("sign_check"), ""),
            .bucket = try dupeOr(arena, v.strAt("bucket"), ""),
            .object = try dupeOr(arena, v.strAt("object"), ""),
            .callback = try dupeOr(arena, v.strAt("callback.callback"), ""),
            .callback_var = try dupeOr(arena, v.strAt("callback.callback_var"), ""),
        };

        if (status == 7) {
            sign_key = result.sign_key;
            sign_val = try uploadDigestRange(arena, src, result.sign_check);
            continue; // 重试
        }
        return result;
    }
}

const OssToken = struct {
    access_key_id: []const u8,
    access_key_secret: []const u8,
    security_token: []const u8,
};

/// `GET /3.0/gettoken.php`（`upload.go:177-185`）。
fn getOssToken(self: *Pan115, arena: std.mem.Allocator) !OssToken {
    const res = try self.request(arena, "GET", api_upload_oss_token, "", &.{
        .{ .name = "Content-Type", .value = "application/json;charset=UTF-8" },
    });
    if (res.status < 200 or res.status >= 300) return Error.UpstreamHttp;
    const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
    const status_code = v.strAt("StatusCode") orelse "";
    if (!std.mem.eql(u8, status_code, "200")) return Error.UpstreamError;
    return .{
        .access_key_id = v.strAt("AccessKeyID") orelse return Error.InvalidResponse,
        .access_key_secret = v.strAt("AccessKeySecret") orelse return Error.InvalidResponse,
        .security_token = v.strAt("SecurityToken") orelse "",
    };
}

/// OSS V1 签名（`VERB\nContent-MD5\nContent-Type\nDate\nCanonicalizedOSSHeaders
/// + CanonicalizedResource`）。`oss_headers` 必须已按名字升序、全部小写。
fn ossAuthorization(
    alloc: std.mem.Allocator,
    method: []const u8,
    content_type: []const u8,
    date: []const u8,
    oss_headers: []const [2][]const u8,
    bucket: []const u8,
    object: []const u8,
    ak: []const u8,
    sk: []const u8,
) ![]const u8 {
    var b = Buf.init(alloc);
    defer b.deinit();
    try b.print("{s}\n\n{s}\n{s}\n", .{ method, content_type, date });
    for (oss_headers) |h| try b.print("{s}:{s}\n", .{ h[0], h[1] });
    try b.print("/{s}/{s}", .{ bucket, object });

    const sig = hash.hmacSha1(sk, b.slice());
    const sig_b64 = try hash.base64Std(alloc, &sig);
    return std.fmt.allocPrint(alloc, "OSS {s}:{s}", .{ ak, sig_b64 });
}

fn ossUrl(alloc: std.mem.Allocator, bucket: []const u8, object: []const u8, query: []const u8) ![]const u8 {
    if (query.len > 0) {
        return std.fmt.allocPrint(alloc, "https://{s}.{s}/{s}?{s}", .{ bucket, oss_endpoint, object, query });
    }
    return std.fmt.allocPrint(alloc, "https://{s}.{s}/{s}", .{ bucket, oss_endpoint, object });
}

/// OSS 请求共用的头：security-token / callback / callback-var / UA。
fn ossHeaders(arena: std.mem.Allocator, tok: OssToken, callback: []const u8, callback_var: []const u8) !struct { hdrs: []const model.Header, canon: []const [2][]const u8 } {
    const cb = try hash.base64Std(arena, callback);
    const cbv = try hash.base64Std(arena, callback_var);

    // CanonicalizedOSSHeaders 必须按名字升序。
    var canon = List([2][]const u8).init(arena);
    try canon.append(.{ "x-oss-callback", cb });
    try canon.append(.{ "x-oss-callback-var", cbv });
    try canon.append(.{ "x-oss-security-token", tok.security_token });

    var hdrs = List(model.Header).init(arena);
    try hdrs.append(.{ .name = "x-oss-security-token", .value = tok.security_token });
    try hdrs.append(.{ .name = "x-oss-callback", .value = cb });
    try hdrs.append(.{ .name = "x-oss-callback-var", .value = cbv });
    try hdrs.append(.{ .name = "User-Agent", .value = oss_user_agent });
    return .{ .hdrs = hdrs.slice(), .canon = canon.slice() };
}

/// OSS 普通 PUT（`upload.go:134-153`）。返回回调体（115 的上传结果 JSON）。
fn ossPutObject(self: *Pan115, arena: std.mem.Allocator, up: UploadInit, data: []const u8) ![]const u8 {
    const tok = try getOssToken(self, arena);
    const date = try cookiejar.httpDate(arena, rt.nowSeconds());
    const shared = try ossHeaders(arena, tok, up.callback, up.callback_var);

    // 注意 Content-Type 留空：Go 的 OSS SDK 会按扩展名自动探测，但签名串里
    // 用的是什么就必须发什么。这里两侧都用空串，保持自洽。
    const auth = try ossAuthorization(arena, "PUT", "", date, shared.canon, up.bucket, up.object, tok.access_key_id, tok.access_key_secret);

    var hdrs = List(model.Header).init(arena);
    for (shared.hdrs) |h| try hdrs.append(h);
    try hdrs.append(.{ .name = "Date", .value = date });
    try hdrs.append(.{ .name = "Authorization", .value = auth });

    const res = try self.client.send(arena, .{
        .method = "PUT",
        .url = try ossUrl(arena, up.bucket, up.object, ""),
        .headers = hdrs.slice(),
        .body = data,
        .use_cookies = false,
        .omit_content_type = true,
    });
    if (res.status < 200 or res.status >= 300) {
        log.warn("[115] OSS PUT -> HTTP {d}: {s}", .{ res.status, res.body[0..@min(res.body.len, 200)] });
        return Error.UploadFailed;
    }
    return res.body;
}

const Chunk = struct { number: i64, offset: i64, size: i64 };
const OssPart = struct { number: i64, etag: []const u8 };

/// `SplitFile`（`util.go:416-437`）：按 GB 分档决定片数，片小于 100KB 时改按
/// 100KB 分片。
fn splitFile(alloc: std.mem.Allocator, size: i64) ![]Chunk {
    var chunk_num: i64 = 0;
    var i: i64 = 1;
    while (i < 10) : (i += 1) {
        if (size < i * gb) {
            chunk_num = i * 1000;
            break;
        }
    }
    if (size > 9 * gb) chunk_num = 10000;
    if (chunk_num == 0) chunk_num = 10000;
    if (chunk_num > size) chunk_num = @max(size, 1);

    var chunks = try splitByNum(alloc, size, chunk_num);
    if (chunks.len > 0 and chunks[0].size < 100 * kb) {
        chunks = try splitBySize(alloc, size, 100 * kb);
    }
    return chunks;
}

fn splitByNum(alloc: std.mem.Allocator, size: i64, n: i64) ![]Chunk {
    var chunks = try alloc.alloc(Chunk, @intCast(n));
    const base = @divTrunc(size, n);
    var i: i64 = 0;
    while (i < n) : (i += 1) {
        chunks[@intCast(i)] = .{
            .number = i + 1,
            .offset = i * base,
            .size = if (i == n - 1) base + @rem(size, n) else base,
        };
    }
    return chunks;
}

fn splitBySize(alloc: std.mem.Allocator, size: i64, chunk_size: i64) ![]Chunk {
    const n = @divTrunc(size, chunk_size);
    var count = n;
    if (@rem(size, chunk_size) > 0) count += 1;
    var chunks = try alloc.alloc(Chunk, @intCast(count));
    var i: i64 = 0;
    while (i < n) : (i += 1) {
        chunks[@intCast(i)] = .{ .number = i + 1, .offset = i * chunk_size, .size = chunk_size };
    }
    if (@rem(size, chunk_size) > 0) {
        chunks[@intCast(n)] = .{ .number = n + 1, .offset = n * chunk_size, .size = @rem(size, chunk_size) };
    }
    return chunks;
}

fn xmlValue(body: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const s = std.mem.indexOf(u8, body, open) orelse return null;
    const start = s + open.len;
    const e = std.mem.indexOfPos(u8, body, start, close) orelse return null;
    return body[start..e];
}

/// OSS 分片上传（`upload.go:364-513`）：init → 逐片 PUT → complete。
fn ossMultipart(self: *Pan115, arena: std.mem.Allocator, up: UploadInit, src: model.Source, size: i64, ctx: *const driver.Ctx) ![]const u8 {
    const tok = try getOssToken(self, arena);
    const date0 = try cookiejar.httpDate(arena, rt.nowSeconds());
    const shared0 = try ossHeaders(arena, tok, up.callback, up.callback_var);

    // 1) InitiateMultipartUpload
    const auth0 = try ossAuthorization(arena, "POST", "", date0, shared0.canon, up.bucket, up.object, tok.access_key_id, tok.access_key_secret);
    var h0 = List(model.Header).init(arena);
    for (shared0.hdrs) |h| try h0.append(h);
    try h0.append(.{ .name = "Date", .value = date0 });
    try h0.append(.{ .name = "Authorization", .value = auth0 });
    const init_res = try self.client.send(arena, .{
        .method = "POST",
        .url = try ossUrl(arena, up.bucket, up.object, "uploads"),
        .headers = h0.slice(),
        .body = "",
        .use_cookies = false,
        .omit_content_type = true,
    });
    if (init_res.status < 200 or init_res.status >= 300) {
        log.warn("[115] OSS init MPU -> HTTP {d}", .{init_res.status});
        return Error.UploadFailed;
    }
    const upload_id = xmlValue(init_res.body, "UploadId") orelse return Error.InvalidResponse;

    // 2) 逐片上传
    const chunks = try splitFile(arena, size);
    var parts = List(OssPart).init(arena);
    var sent: i64 = 0;
    const chunk_buf = try arena.alloc(u8, @intCast(chunks[0].size));
    for (chunks) |c| {
        sent += c.size;
        // 每片上报一次百分比（0–100，Go `model.UpdateProgress` 的语义）。
        // 秒传/单 PUT 只在首尾各报一次，大文件只有分片这条路有细粒度。
        if (ctx.progress) |f| {
            const pct: u64 = @intCast(@min(@divTrunc(sent * 100, @max(size, 1)), 100));
            f(ctx.progress_userdata, pct);
        }
        try src.readAllInto(@intCast(c.offset), chunk_buf[0..@intCast(c.size)]);

        const date = try cookiejar.httpDate(arena, rt.nowSeconds());
        const shared = try ossHeaders(arena, tok, up.callback, up.callback_var);
        const auth = try ossAuthorization(arena, "PUT", "", date, shared.canon, up.bucket, up.object, tok.access_key_id, tok.access_key_secret);

        var h = List(model.Header).init(arena);
        for (shared.hdrs) |x| try h.append(x);
        try h.append(.{ .name = "Date", .value = date });
        try h.append(.{ .name = "Authorization", .value = auth });

        const q = try std.fmt.allocPrint(arena, "partNumber={d}&uploadId={s}", .{ c.number, upload_id });
        const res = try self.client.send(arena, .{
            .method = "PUT",
            .url = try ossUrl(arena, up.bucket, up.object, q),
            .headers = h.slice(),
            .body = chunk_buf[0..@intCast(c.size)],
            .use_cookies = false,
            .omit_content_type = true,
        });
        if (res.status < 200 or res.status >= 300) {
            log.warn("[115] OSS part {d} -> HTTP {d}", .{ c.number, res.status });
            return Error.UploadFailed;
        }
        const etag = res.header("ETag") orelse return Error.InvalidResponse;
        try parts.append(.{ .number = c.number, .etag = etag });
    }

    // 3) CompleteMultipartUpload
    var xml = Buf.init(arena);
    defer xml.deinit();
    try xml.append("<CompleteMultipartUpload>");
    for (parts.slice()) |p| {
        try xml.print("<Part><PartNumber>{d}</PartNumber><ETag>{s}</ETag></Part>", .{ p.number, p.etag });
    }
    try xml.append("</CompleteMultipartUpload>");

    const date2 = try cookiejar.httpDate(arena, rt.nowSeconds());
    const shared2 = try ossHeaders(arena, tok, up.callback, up.callback_var);
    const auth2 = try ossAuthorization(arena, "POST", "", date2, shared2.canon, up.bucket, up.object, tok.access_key_id, tok.access_key_secret);

    var h2 = List(model.Header).init(arena);
    for (shared2.hdrs) |h| try h2.append(h);
    try h2.append(.{ .name = "Date", .value = date2 });
    try h2.append(.{ .name = "Authorization", .value = auth2 });

    const q2 = try std.fmt.allocPrint(arena, "uploadId={s}", .{upload_id});
    const fin = try self.client.send(arena, .{
        .method = "POST",
        .url = try ossUrl(arena, up.bucket, up.object, q2),
        .headers = h2.slice(),
        .body = xml.slice(),
        .use_cookies = false,
        .omit_content_type = true,
    });
    if (fin.status < 200 or fin.status >= 300) {
        log.warn("[115] OSS complete -> HTTP {d}", .{fin.status});
        return Error.UploadFailed;
    }
    return fin.body;
}

fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const size = src.size();
    if (size < 0) return Error.InvalidPath;
    const name = pathBase(dst) orelse return Error.InvalidPath;
    const dir_id = try resolveId(self, a, pathParent(dst) orelse return Error.InvalidPath);

    const meta = try ensureUploadAvailable(self, a);
    if (meta.size_limit != std.math.maxInt(i64) and size > meta.size_limit) {
        log.warn("[115] file {d} bytes exceeds upstream limit {d}", .{ size, meta.size_limit });
        return Error.UploadFailed;
    }

    const d = try digest(a, src);

    // 1) 闪传
    const up = try rapidUpload(self, a, size, name, dir_id, d.pre_id, d.full_id, src);
    if (up.status == 2) {
        // 秒传没有字节流经本地，直接报 100%。
        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
        return; // 秒传成功
    }
    if (up.status != 1) {
        log.warn("[115] initupload unexpected status {d}", .{up.status});
        return Error.UploadFailed;
    }

    // 2) OSS 上传
    if (size <= oss_single_max) {
        const chunk = try a.alloc(u8, @intCast(@max(size, 1)));
        if (size > 0) try src.readAllInto(0, chunk[0..@intCast(size)]);
        _ = try ossPutObject(self, a, up, chunk[0..@intCast(size)]);
    } else {
        _ = try ossMultipart(self, a, up, src, size, ctx);
    }
    if (ctx.progress) |f| f(ctx.progress_userdata, 100);
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    // 逐字等于 Go 的 `driver.Config.Name`（drivers/115/meta.go:28）。
    .key = "115 Cloud",
    .label = "115 云盘",
    .secrets = &.{"cookie"},
    .addition_schema =
    \\{
    \\  "cookie":        {"type":"string","required":true,"secret":true,"help":"浏览器里抓的 Cookie（UID/CID/SEID/KID）"},
    \\  "qrcode_token":  {"type":"string","help":"二维码登录 token（本工程未移植，留空即可）"},
    \\  "qrcode_source": {"type":"select","default":"linux","options":["web","android","ios","tv","alipaymini","wechatmini","qandroid","linux"]},
    \\  "page_size":     {"type":"number","default":1000,"help":"列表每页条数"},
    \\  "limit_rate":    {"type":"float","default":2,"help":"每秒请求数上限"},
    \\  "root_folder_id":{"type":"string","default":"0","help":"根目录 id，115 的根是 0"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    return driver.asDriver(Pan115, try createWithId(alloc, storage_id, cfg));
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Pan115 {
    const self = try alloc.create(Pan115);
    const jar = try alloc.create(cookiejar.Jar);
    jar.* = cookiejar.Jar.init(alloc);
    self.* = .{
        .alloc = alloc,
        .storage_id = storage_id,
        .cfg = try Addition.parse(alloc, cfg),
        .client = httpclient.Client.init(alloc, .{}, jar),
    };
    return self;
}

// ---------------------------------------------------------------------------
// 测试 —— 纯逻辑（向量来自 tools/gen_115_vectors.py 与内联 Python 计算）
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 测试用的内存 Source（`ptr` 指向一个 `[]const u8`）。
const MemSource = struct {
    data: []const u8,
    const vtable = model.Source.VTable{
        .size = struct {
            fn f(p: *anyopaque) i64 {
                const s: *const MemSource = @ptrCast(@alignCast(p));
                return @intCast(s.data.len);
            }
        }.f,
        .readAt = struct {
            fn f(p: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
                const s: *const MemSource = @ptrCast(@alignCast(p));
                if (offset >= s.data.len) return 0;
                const n = @min(buf.len, s.data.len - offset);
                @memcpy(buf[0..n], s.data[offset..][0..n]);
                return n;
            }
        }.f,
    };
    fn source(self: *MemSource) model.Source {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "T2: real Go addition JSON (backup shape) parses into the driver" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const src =
        \\{"cookie":"UID=1;CID=2;SEID=3;KID=4","qrcode_token":"","qrcode_source":"linux",
        \\ "page_size":1000,"limit_rate":2,"root_folder_id":"0"}
    ;
    const v = try json.parse(a, src);
    const add = try Addition.parse(a, &v);
    try testing.expectEqualStrings("UID=1;CID=2;SEID=3;KID=4", add.cookie);
    try testing.expectEqual(@as(i64, 1000), add.page_size);
    try testing.expectEqual(@as(f64, 2), add.limit_rate);
    try testing.expectEqualStrings("0", add.root_folder_id);

    const out = try add.toJson(a);
    try testing.expect(std.mem.indexOf(u8, out, "\"page_size\":1000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"root_folder_id\":\"0\"") != null);
}

test "T2: defaults match Go" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const add = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", add.root_folder_id);
    try testing.expectEqualStrings("linux", add.qrcode_source);
    try testing.expectEqual(@as(i64, 1000), add.page_size);
    try testing.expectEqual(@as(f64, 2), add.limit_rate);
}

test "T2: Credential.fromCookie normalises and rejects bad cookies" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const cr = try Credential.fromCookie(a, " uid=1 ; CID=2 ; seid=3 ; kid=4 ");
    try testing.expectEqualStrings("UID=1;CID=2;SEID=3;KID=4", try cr.toCookie(a));

    // 少于 3 项 / 缺 SEID 都要拒绝
    try testing.expectError(Error.AuthFailed, Credential.fromCookie(a, "UID=1;CID=2"));
    try testing.expectError(Error.AuthFailed, Credential.fromCookie(a, "UID=1;CID=2;KID=4"));
}

test "T2: parseCstMinutes converts a 115 timestamp to unix seconds" {
    // 2023-11-14 22:13 CST = 2023-11-14 14:13 UTC = 1699971180
    try testing.expectEqual(@as(i64, 1699971180), parseCstMinutes("2023-11-14 22:13").?);
    try testing.expect(parseCstMinutes("nope") == null);
}

test "T2: list JSON parses the short-key FileInfo entries" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"state":true,"errno":0,"count":2,"offset":0,"cid":"0","data":[
        \\ {"fid":"f1","cid":"0","pid":"0","n":"a.txt","s":"12","pc":"pc1","sha":"AB","tp":1700000000,"t":"2023-11-14 22:13","u":""},
        \\ {"fid":"","cid":"d1","pid":"0","n":"sub","s":0,"pc":"","sha":"","tp":1700000000,"t":"1700000000"}]}
    ;
    const v = try json.parse(a, body);
    try testing.expect(basicOk(&v));

    const items = arrAt(&v, "data");
    try testing.expectEqual(@as(usize, 2), items.len);

    const e1 = try entryFrom(&items[0]);
    try testing.expectEqualStrings("f1", e1.id);
    try testing.expect(!e1.is_dir);
    const o1 = objFrom(e1);
    try testing.expectEqualStrings("a.txt", o1.name);
    try testing.expectEqual(@as(i64, 12), o1.size);
    try testing.expectEqual(@as(i64, 1699971180), o1.modified);

    // 目录：fid 为空 → id 取 cid，update time 是 unix 秒
    const e2 = try entryFrom(&items[1]);
    try testing.expectEqualStrings("d1", e2.id);
    try testing.expect(e2.is_dir);
    try testing.expectEqual(@as(i64, 1700000000), objFrom(e2).modified);
}

test "T2: GenerateSignature matches the reference (sha1 chain, UPPER hex)" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const sig = try generateSignature(a, 12345678, "deadbeefcafe", "ABCDEF0123456789ABCDEF0123456789ABCDEF01", "U_1_0");
    try testing.expectEqualStrings("1BD253A8BD9427CB6315AC8B1521683E430415CE", sig);
}

test "T2: GenerateToken matches the reference (md5 chain, lower hex)" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const t1 = try generateToken(a, 12345678, "ABCDEF0123456789ABCDEF0123456789ABCDEF01", 1048576, "", "", 1700000000000);
    try testing.expectEqualStrings("e4d15d0310d89073a19b263229afcb2c", t1);

    const t2 = try generateToken(a, 87654321, "0000000000000000000000000000000000000000", 42, "sk", "sv", 1699999999999);
    try testing.expectEqualStrings("3729a3cb4208c84b82345301e64792a8", t2);
}

test "T2: OSS V1 Authorization matches the reference" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const oss_headers = [_][2][]const u8{
        .{ "x-oss-callback", "eyJjYWxsYmFja0JvZHkiOiIifQ==" },
        .{ "x-oss-callback-var", "eyJ4IjoiMSJ9" },
        .{ "x-oss-security-token", "STS_TOKEN_XYZ" },
    };
    const auth = try ossAuthorization(a, "PUT", "", "Tue, 14 Nov 2023 22:13:20 GMT", &oss_headers, "115-test-bucket", "115/test.bin", "AKID_DEMO", "SECRET_DEMO");
    try testing.expectEqualStrings("OSS AKID_DEMO:xifrflmuw/hFDWJt+I0yhuu//Uo=", auth);
}

test "T2: splitFile honours the 100KB floor and the part count" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 20MB：chunkNum=1000 → 片大小 20KB < 100KB → 改按 100KB 分 → 205 片
    const c1 = try splitFile(a, 20 * mb);
    try testing.expectEqual(@as(i64, 205), @as(i64, @intCast(c1.len)));
    try testing.expectEqual(@as(i64, 100 * kb), c1[0].size);
    try testing.expectEqual(@as(i64, 20 * mb - 100 * kb * 204), c1[c1.len - 1].size);

    // 100MB：chunkNum=1000 → 片大小 104857（≥100KB，不再改分片）
    const c2 = try splitFile(a, 100 * mb);
    try testing.expectEqual(@as(i64, 1000), @as(i64, @intCast(c2.len)));
    try testing.expect(c2[0].size >= 100 * kb);
    try testing.expectEqual(@as(i64, 104857), c2[0].size);
}

test "T2: digest computes the 128KB pre-hash and the whole-file hash" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var backing: [200 * 1024]u8 = undefined;
    for (&backing, 0..) |*b, i| b.* = @intCast(i & 0xff);
    var ms = MemSource{ .data = &backing };
    const src = ms.source();

    const d = try digest(a, src);
    // 独立算一遍：Python hashlib.sha1(...).hexdigest().upper()
    const pre = try hash.sha1HexUpper(a, backing[0 .. 128 * 1024]);
    const full = try hash.sha1HexUpper(a, &backing);
    try testing.expectEqualStrings(pre, d.pre_id);
    try testing.expectEqualStrings(full, d.full_id);
}

test "T2: pathBase/pathParent split the way the vtable promises" {
    try testing.expectEqualStrings("c.txt", pathBase("/a/b/c.txt").?);
    try testing.expectEqualStrings("/a/b", pathParent("/a/b/c.txt").?);
    try testing.expectEqualStrings("/", pathParent("/x").?);
    try testing.expect(pathParent("/") == null);
    try testing.expect(pathBase("/") == null);
}

test "T2: xmlValue pulls UploadId out of an OSS MPU response" {
    const body =
        "<?xml version=\"1.0\"?><InitiateMultipartUploadResult>" ++
        "<Bucket>b</Bucket><Key>k</Key><UploadId>UP-123</UploadId>" ++
        "</InitiateMultipartUploadResult>";
    try testing.expectEqualStrings("UP-123", xmlValue(body, "UploadId").?);
    try testing.expect(xmlValue(body, "Missing") == null);
}

test "T2: createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const self = try createWithId(a, 7, null);
    defer self.client.deinit();
    try testing.expectEqual(@as(i64, 7), self.storage_id);
    try testing.expectEqualStrings("115 Cloud", Pan115.drvName(@ptrCast(self)));
    try testing.expectEqualStrings("115 Cloud", factory.key);
}
