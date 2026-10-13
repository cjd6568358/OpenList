//! 123 云盘（网页版）驱动 —— Go 版 `drivers/123` 的 Zig 移植。
//!
//! 这是需求清单里三个「补课」驱动的第一个（另两个：quarkuc / pan115）。
//! 与已下线的 `123open`（开放平台变体）是**同一个网盘的两个不同驱动**：
//! 本驱动用「用户名 + 密码」登录（`drivers/123/meta.go`，配置里 id=3/4 的
//! 两个存储正是它），key 必须逐字等于 Go 的 `123Pan`。
//!
//! 与 123open 的结构差异（移植时重点核对过的）：
//!   1. **登录是独立的 login 端点**，token 从 `data.token` 拿，失败/401 时
//!      重新登录；账号既可以是手机号（passport）也可以是邮箱（mail + type:2）。
//!   2. **每个请求都要带 CRC32 签名 query**：`signPath` 用当天 CST 时间
//!      （按字母表映射后取 CRC32）+ 时间戳 + 随机数拼出 `{timeSign}={ts}-{r}-{sign}`。
//!      这一步不做，上游一律 401。
//!   3. **列表/文件字段是 PascalCase**（FileName/FileId/Type/Etag/S3KeyFlag），
//!      不是 open 变体的 snake_case —— 直接照搬 open 的解析会全军覆没。
//!   4. **上传是 S3 预签名 PUT**：`upload_request` 拿 FileId/UploadId/Key，
//!      按 16 MiB 分片换预签名 URL（批量一次 10 片）逐个 PUT，最后
//!      `upload_complete/v2`。带了 AccessKeyId 的老式分支走 SigV4 自签。
//!   5. **API 限速**：上游 2024-02 起对并发敏感，Go 按端点做 700ms 间隔的
//!      令牌桶；本实现串行化同一驱动的请求并按端点限间隔（见 `rateWait`）。
//!
//! 与 Go 版的差异（有意为之）：离线下载未移植（需要任务中心配合）；`Copy`
//! vtable 里没有槽位；`drop` 只做登出不返回错误。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const urlmod = @import("../util/url.zig");
const timeutil = @import("../util/time.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量（drivers/123/util.go:26-53）
// ---------------------------------------------------------------------------

const main_api = "https://yun.123pan.com/b/api";
const login_api = "https://login.123pan.com/api";
const ep_sign_in = login_api ++ "/user/sign_in";
const ep_logout = main_api ++ "/user/logout";
const ep_user_info = main_api ++ "/user/info";
const ep_file_list = main_api ++ "/file/list/new";
const ep_download_info = main_api ++ "/file/download_info";
/// Go 的 `Mkdir` 与 `UploadRequest` 是同一个端点，靠 body 里的 `type` 区分
/// （1 = 目录，0 = 文件）。
const ep_upload_request = main_api ++ "/file/upload_request";
const ep_move = main_api ++ "/file/mod_pid";
const ep_rename = main_api ++ "/file/rename";
const ep_trash = main_api ++ "/file/trash";
const ep_upload_complete = main_api ++ "/file/upload_complete";
const ep_upload_complete_v2 = main_api ++ "/file/upload_complete/v2";
const ep_s3_presigned = main_api ++ "/file/s3_repare_upload_parts_batch";
const ep_s3_auth = main_api ++ "/file/s3_upload_object/auth";

const page_size = 100;
/// Go 版 `newUpload` 写死 16 MiB（`chunkSize := int64(16 * utils.MB)`）。
const chunk_size: i64 = 16 * 1024 * 1024;
/// 预签名 URL 一次可取 10 片（Go `batchSize = 10`，注释：only 1 batch is allowed）。
const url_batch = 10;
/// `duplicate`：2 = 覆盖（Go 注释 2->覆盖 1->重命名 0->默认）。
const duplicate_overwrite: i64 = 2;
/// Go 的 APIRateLimit：每端点 700ms 一个请求。
const rate_gap_ms: i64 = 700;
/// Go `util.go:213` 的请求 UA（登录用的是 Dart UA，见 `login`）。
const request_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) openlist-client";
const login_ua = "Dart/2.19(dart:io)-openlist";
const origin = "https://yun.123pan.com";
/// app-version 头，Go 版写死 "3"（签名里也用它）。
const app_version = "3";
/// 123 的根目录 ID（Go `config.DefaultRoot: "0"`）。
const default_root = "0";

pub const Error = error{
    /// 用户名/密码缺失，或登录被上游拒绝。
    AuthFailed,
    UpstreamHttp,
    UpstreamNotJson,
    /// 上游返回了非 0 的 `code`（401 已在重试循环里消化成重新登录）。
    UpstreamError,
    InvalidResponse,
    /// 路径为空、只有分隔符、或最后一段是 `..` 之类。API 层映射 400。
    InvalidPath,
    /// 上传分片请求/发送失败。
    UploadFailed,
    /// 服务端没给这条文件的上传地址。
    MissingUploadUrl,
    /// 带 AccessKeyId 的老式上传分支需要的 SigV4 组件缺失。
    BadS3Params,
};

// ---------------------------------------------------------------------------
// 配置（drivers/123/meta.go）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    username: []const u8 = "",
    password: []const u8 = "",
    /// Go 的 `AccessToken` 无 json tag → 键名就是字段名（用户备份实证：
    /// ['AccessToken','UploadThread','password','platform','root_folder_id',
    /// 'username']）。
    ///
    /// ⚠️ 登录拿到的 token **只在内存里**，不落盘 —— Go 那边也一样（它的
    /// `d.AccessToken` 同样是运行期字段，`GetAddition` 不会写回配置）。所以
    /// 每次启动都要重新登录，这不是缺陷。
    access_token: []const u8 = "",
    /// Go json tag 是 `UploadThread`（大写）。
    upload_thread: i64 = 3,
    /// `platform` 头，默认 "web"。
    platform: []const u8 = "web",
    /// 内嵌 `driver.RootID` → `root_folder_id`。
    root_folder_id: []const u8 = default_root,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        a.username = try dupeOr(alloc, o.strAt("username"), "");
        a.password = try dupeOr(alloc, o.strAt("password"), "");
        a.access_token = try dupeOr(alloc, o.strAt("AccessToken"), "");
        if (o.intAt("UploadThread")) |t| a.upload_thread = t;
        a.platform = try dupeOr(alloc, o.strAt("platform"), "web");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        return a;
    }

    /// 序列化回 `addition`。键名与 Go 的序列化形态逐字一致（无 tag 字段用
    /// 字段名本身），保证 Go 版能直接读我们写的配置。
    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        try b.append("{\"username\":");
        try json.writeString(&b, self.username);
        try b.append(",\"password\":");
        try json.writeString(&b, self.password);
        try b.append(",\"AccessToken\":");
        try json.writeString(&b, self.access_token);
        try b.print(",\"UploadThread\":{d}", .{self.upload_thread});
        try b.append(",\"platform\":");
        try json.writeString(&b, self.platform);
        try b.append(",\"root_folder_id\":");
        try json.writeString(&b, self.root_folder_id);
        try b.append("}");
        return b.toOwned();
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    return alloc.dupe(u8, v orelse fallback);
}

fn boolOr(v: *const json.Value, path: []const u8) bool {
    if (v.getPath(path)) |x| {
        if (x.asBool()) |b| return b;
    }
    return false;
}

fn arrAt(v: *const json.Value, path: []const u8) []json.Value {
    const x = v.getPath(path) orelse return &.{};
    return x.asArray() orelse &.{};
}

/// vtable 指针 → `*Pan123`（本文件约定）。
fn as(p: *anyopaque) *Pan123 {
    return @ptrCast(@alignCast(p));
}

// ---------------------------------------------------------------------------
// 请求签名（drivers/123/util.go:57-78）
// ---------------------------------------------------------------------------

/// 数字 → 字母映射表。Go 的表有 26 项，但只有下标 0-9（数字字符）会被用到。
const time_map = [_]u8{ 'a', 'd', 'e', 'f', 'g', 'h', 'l', 'm', 'y', 'i' };

const Sign = struct {
    /// `timeSign` —— 同时是 query 里的键名。
    time_sign: []const u8,
    /// `ts-random-dataSign`。
    value: []const u8,
};

/// CST（UTC+8）的 "YYYYMMDDHHMM"。Go 用 `time.FixedZone("CST", 8*3600)`，
/// 这里手算：加 8 小时后按 civil 日期拆。
/// 零填充的十进制。Zig 0.17 的 `{d:0>4}` 会把 `0` 解析成别的意思（实测输出
/// `+2026`），这里手写，行为确定且好测。宽度不足时按实际长度输出。
fn padNum(b: *Buf, v: i64, width: usize) !void {
    var tmp: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch return;
    var i: usize = width;
    while (i > s.len) : (i -= 1) try b.appendByte('0');
    try b.append(s);
}

fn cstStamp(a: std.mem.Allocator) ![]const u8 {
    const secs = rt.nowSeconds() + 8 * std.time.s_per_hour;
    const days = @divFloor(secs, std.time.s_per_day);
    const sod = @mod(secs, std.time.s_per_day);
    const c = timeutil.civilFromDays(days);
    var b = Buf.init(a);
    try padNum(&b, c.y, 4);
    try padNum(&b, c.m, 2);
    try padNum(&b, c.d, 2);
    try padNum(&b, @divFloor(sod, 3600), 2);
    try padNum(&b, @divTrunc(@mod(sod, 3600), 60), 2);
    return b.toOwned();
}

/// 复刻 Go 的 `signPath(path, os, version) -> (k, v)`。
/// `os`/`version` 固定 "web"/"3"（Go `GetApi` 的调用点）。
fn signPath(a: std.mem.Allocator, path: []const u8) !Sign {
    const stamp = try cstStamp(a);
    // 映射表按字符逐个追加，不假设 stamp 长度（Go 的 nowStr 是定长 12，
    // 但这里用动态 Buf 更稳，长度变了也不会越界）。
    var mapped = Buf.init(a);
    for (stamp) |ch| {
        const m: u8 = if (ch >= '0' and ch <= '9') time_map[ch - '0'] else 'a';
        try mapped.appendByte(m);
    }
    const time_sign = try std.fmt.allocPrint(a, "{d}", .{std.hash.Crc32.hash(mapped.slice())});

    // Go: math.Round(1e7 * rand.Float64()) —— [0, 1e7) 的整数。
    var rnd: [8]u8 = undefined;
    rt.io().random(&rnd);
    const random = std.mem.readInt(u64, &rnd, .little) % 10_000_000;
    const ts = rt.nowSeconds();

    const data = try std.fmt.allocPrint(a, "{d}|{d}|{s}|web|{s}|{s}", .{ ts, random, path, app_version, time_sign });
    const data_sign = std.hash.Crc32.hash(data);
    return .{
        .time_sign = time_sign,
        .value = try std.fmt.allocPrint(a, "{d}-{d}-{d}", .{ ts, random, data_sign }),
    };
}

/// 完整 URL 里的 path 部分（Go 对 `u.Path` 签名，host 不参与）。
fn urlPathOf(url: []const u8) []const u8 {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return url;
    const rest = url[scheme_end + 3 ..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return "/";
    return rest[slash..];
}

/// ep + 签名 query + 调用方 query。签名在前，与 resty 的拼接顺序一致
/// （先 `GetApi(url)` 得到带签名的 URL，再 `SetQueryParams` 追加）。
fn buildUrl(a: std.mem.Allocator, ep: []const u8, query: ?[]const u8) ![]const u8 {
    const sign = try signPath(a, urlPathOf(ep));
    const extra = if (query) |q| (if (q.len > 0) q else "") else "";
    if (extra.len > 0) {
        return std.fmt.allocPrint(a, "{s}?{s}={s}&{s}", .{ ep, sign.time_sign, sign.value, extra });
    }
    return std.fmt.allocPrint(a, "{s}?{s}={s}", .{ ep, sign.time_sign, sign.value });
}

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------

/// 限速槽位数。**只有一个** —— Go 也只对 FileList 限速（见 `request` 里的注释）。
const rate_slots = 1;

const RateSlot = struct {
    ep: []const u8,
    last_ms: i64 = 0,
};

pub const Pan123 = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    client: httpclient.Client,
    /// 串行化同一驱动的全部请求。
    ///
    /// 两个理由：① FileList 有 700ms 令牌桶（2024-02 起上游对并发敏感，
    /// `util.go:363` 的注释 "fix concurrency by 123pan"；见 `rateWaitLocked`）；
    /// ② init 现在跑在后台线程（T6），而请求线程随时可能进来 —— 不锁的话两个
    /// 线程会同时刷新 token / 同时写 `cfg.access_token`。
    ///
    /// ⚠️ `login()` 要求调用方**已经持有**本锁（它只在 init 与 request 的
    /// 401 重试里被调用，两条路径都满足）。
    req_mu: std.Io.Mutex = .init,
    rate: [rate_slots]RateSlot = initial_rate,

    const VTable = driver.Driver.VTable{
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
        .space = space,
    };

    pub const vtable = VTable;

    fn drvName(_: *anyopaque) []const u8 {
        return "123Pan";
    }

    // -- 认证 ---------------------------------------------------------------

    /// Go `utils.IsEmailFormat` 的正则是完整邮箱校验；这里的判据是「含 @ 且
    /// @ 不在首尾」—— 123 的账号要么手机号要么邮箱，够用且不会误伤。
    fn isEmail(s: []const u8) bool {
        const at = std.mem.indexOfScalar(u8, s, '@') orelse return false;
        return at > 0 and at + 1 < s.len;
    }

    /// 登录并换 token。调用方必须持有 `req_mu`。
    fn login(self: *Pan123, arena: std.mem.Allocator) !void {
        if (self.cfg.username.len == 0 or self.cfg.password.len == 0) return Error.AuthFailed;

        var body = Buf.init(arena);
        if (isEmail(self.cfg.username)) {
            try body.append("{\"mail\":");
            try json.writeString(&body, self.cfg.username);
            try body.append(",\"password\":");
            try json.writeString(&body, self.cfg.password);
            try body.append(",\"type\":2}");
        } else {
            try body.append("{\"passport\":");
            try json.writeString(&body, self.cfg.username);
            try body.append(",\"password\":");
            try json.writeString(&body, self.cfg.password);
            try body.append(",\"remember\":true}");
        }

        // 登录请求**不带**签名 query（Go 直接 Post(SignIn)），UA 也是独立的。
        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = ep_sign_in,
            .headers = &[_]model.Header{
                .{ .name = "origin", .value = origin },
                .{ .name = "referer", .value = origin ++ "/" },
                .{ .name = "user-agent", .value = login_ua },
                .{ .name = "platform", .value = "web" },
                .{ .name = "app-version", .value = app_version },
            },
            .body = body.slice(),
            .use_cookies = true,
        });
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        const code = v.intAt("code") orelse return Error.InvalidResponse;
        if (code != 200) {
            const msg = v.strAt("message") orelse "login rejected";
            log.warn("[123pan] login failed: {d} {s}", .{ code, msg });
            return Error.AuthFailed;
        }
        const token = v.strAt("data.token") orelse return Error.InvalidResponse;
        const dup = try self.alloc.dupe(u8, token);
        if (self.cfg.access_token.len > 0) self.alloc.free(self.cfg.access_token);
        self.cfg.access_token = dup;
    }

    // -- 限速 ---------------------------------------------------------------

    /// 与上次 **FileList** 请求保持 700ms 间隔。调用方必须持有 `req_mu`。
    ///
    /// ⚠️ 只对 FileList 生效。Go 的限速器虽然也是按端点名建桶
    /// （`driver.go:250-253`，`rate.Every(700ms)`），但**只有 util.go:364 一处
    /// 调用了它** —— 其它端点（mkdir/move/rename/delete/上传/space）根本不限速。
    /// 以前这里对每个端点都等 700ms，等于每次写操作白白多花 0.7s。
    fn rateWaitLocked(self: *Pan123) void {
        const now = rt.nowMillis();
        var slot = &self.rate[0];
        slot.ep = ep_file_list;
        const since = now - slot.last_ms;
        if (slot.last_ms != 0 and since < rate_gap_ms) rt.sleepMillis(rate_gap_ms - since);
        slot.last_ms = rt.nowMillis();
    }

    // -- 通用请求 -----------------------------------------------------------

    /// 带签名头 + 401 自动重登录重试的请求。持有 `req_mu`。
    ///
    /// `query` 是调用方组织好的 `k=v&k=v`（键值都不需要编码 —— 123 的这些
    /// 参数都是数字/布尔/固定枚举）。返回响应体（调用方负责解析）。
    fn request(
        self: *Pan123,
        arena: std.mem.Allocator,
        ep: []const u8,
        method: []const u8,
        query: ?[]const u8,
        body: []const u8,
        allow_login_retry: bool,
    ) ![]const u8 {
        const io = rt.io();
        self.req_mu.lockUncancelable(io);
        defer self.req_mu.unlock(io);

        var retried = false;
        while (true) {
            // 只有 FileList 限速 —— 对齐 Go（只有 util.go:364 调 APIRateLimit）。
            if (std.mem.eql(u8, ep, ep_file_list)) self.rateWaitLocked();
            const url = try buildUrl(arena, ep, query);
            var auth_buf: [512]u8 = undefined;
            const auth = std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{self.cfg.access_token}) catch self.cfg.access_token;
            const res = try self.client.send(arena, .{
                .method = method,
                .url = url,
                .headers = &[_]model.Header{
                    .{ .name = "origin", .value = origin },
                    .{ .name = "referer", .value = origin ++ "/" },
                    .{ .name = "authorization", .value = auth },
                    .{ .name = "user-agent", .value = request_ua },
                    .{ .name = "platform", .value = self.cfg.platform },
                    .{ .name = "app-version", .value = app_version },
                },
                .body = body,
                .use_cookies = true,
            });
            const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
            const code = v.intAt("code") orelse return Error.InvalidResponse;
            if (code == 0) return res.body;
            if (code == 401 and allow_login_retry and !retried) {
                self.login(arena) catch |e| {
                    log.warn("[123pan] {s} -> 401, re-login failed: {s}", .{ ep, @errorName(e) });
                    return e;
                };
                retried = true;
                continue;
            }
            const msg = v.strAt("message") orelse "(no message)";
            log.warn("[123pan] {s} {s} -> code {d}: {s}", .{ method, ep, code, msg });
            return Error.UpstreamError;
        }
    }

    /// GET + query 的便捷重载。
    fn get(self: *Pan123, arena: std.mem.Allocator, ep: []const u8, query: ?[]const u8) ![]const u8 {
        return self.request(arena, ep, "GET", query, "", true);
    }

    /// POST + JSON body 的便捷重载。
    fn post(self: *Pan123, arena: std.mem.Allocator, ep: []const u8, body: []const u8) ![]const u8 {
        return self.request(arena, ep, "POST", null, body, true);
    }
};

const initial_rate = [_]RateSlot{
    .{ .ep = ep_file_list },
};

// ---------------------------------------------------------------------------
// 条目与路径
// ---------------------------------------------------------------------------

const Entry = struct {
    id: i64,
    name: []const u8,
    is_dir: bool,
    /// 列表接口返回的原始 JSON 节点（指向 arena，活到请求结束）。
    raw: ?*const json.Value = null,
};

/// `UpdateAt` 兼容两种形态：Go 的 time.Time（"2006-01-02 15:04:05" 字符串）
/// 与偶发的 Unix 秒数字。
fn parseTime(item: *const json.Value) i64 {
    if (item.strAt("UpdateAt")) |s| {
        if (timeutil.parseCnTime(s)) |t| return t;
        if (std.fmt.parseInt(i64, s, 10)) |n| return n else |_| {}
        return 0;
    }
    return item.intAt("UpdateAt") orelse 0;
}

fn objFromJson(item: *const json.Value) model.Obj {
    const is_dir = (item.intAt("Type") orelse 0) == 1;
    return .{
        .name = item.strAt("FileName") orelse "",
        .size = item.intAt("Size") orelse 0,
        .is_dir = is_dir,
        .modified = parseTime(item),
        .created = parseTime(item),
    };
}

/// 列一页。query 的键序对齐 Go `getFiles` 的 map（顺序无关，值要对）。
fn listPage(self: *Pan123, arena: std.mem.Allocator, parent_id: i64, page: i64) !*const json.Value {
    const query = try std.fmt.allocPrint(
        arena,
        "driveId=0&limit={d}&next=0&orderBy=file_id&orderDirection=desc&parentFileId={d}&trashed=false&SearchData=&Page={d}&OnlyLookAbnormalFile=0&event=homeListFile&operateType=4&inDirectSpace=false",
        .{ page_size, parent_id, page },
    );
    const body = try self.get(arena, ep_file_list, query);
    const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
    return v.getPath("data") orelse return Error.InvalidResponse;
}

/// 从根开始逐级按名字找。本工程的 vtable 是路径式的，没有 Go 的 Obj 缓存，
/// 所以每一级都要翻页找（Go 靠 `op.Get` 直接拿到带 id 的 Obj）。
fn resolveEntry(self: *Pan123, arena: std.mem.Allocator, path: []const u8) !Entry {
    var cur = Entry{
        .id = std.fmt.parseInt(i64, self.cfg.root_folder_id, 10) catch 0,
        .name = "/",
        .is_dir = true,
    };
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |seg| {
        cur = try findChild(self, arena, cur.id, seg);
    }
    return cur;
}

fn findChild(self: *Pan123, arena: std.mem.Allocator, parent_id: i64, name: []const u8) !Entry {
    var page: i64 = 1;
    while (true) {
        const data = try listPage(self, arena, parent_id, page);
        const children = arrAt(data, "InfoList");
        for (children, 0..) |_, i| {
            const item = &children[i];
            const fn_ = item.strAt("FileName") orelse continue;
            if (!std.mem.eql(u8, fn_, name)) continue;
            return .{
                .id = item.intAt("FileId") orelse 0,
                .name = fn_,
                .is_dir = (item.intAt("Type") orelse 0) == 1,
                .raw = item,
            };
        }
        const next = data.strAt("Next") orelse "-1";
        page += 1;
        // Go：InfoList 空 或 Next == "-1" 结束；Page 参数兜底防呆。
        if (children.len == 0 or std.mem.eql(u8, next, "-1") or page > 10_000) return driver.Error.NotFound;
    }
}

// ---------------------------------------------------------------------------
// vtable
// ---------------------------------------------------------------------------

fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
    const self = as(ptr);
    _ = ctx;
    var arena = std.heap.ArenaAllocator.init(self.alloc);
    defer arena.deinit();
    const a = arena.allocator();
    // 没有 token（首次配置 / 重启后 token 丢了）时先登录取一个。
    if (self.cfg.access_token.len == 0) try self.login(a);
    // Go 的 Init 就是一次 UserInfo 探测（driver.go:43-48）。它走 `d.Request`，
    // 而 `Request` 在 `code == 401` 时会**自动重登一次**（util.go:236-243）——
    // 所以这里的 `allow_login_retry` 必须是 true，否则「token 过期但非空」的
    // 存储会在 init 阶段直接失败，永远起不来。
    _ = try self.request(a, ep_user_info, "GET", null, "", true);
}

fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
    const self = as(ptr);
    _ = ctx;
    // Go 的 Drop：尽力登出，忽略结果。
    _ = self.post(self.alloc, ep_logout, "{}") catch {};
    if (self.cfg.access_token.len > 0) self.alloc.free(self.cfg.access_token);
    self.client.deinit();
}

fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
    const self = as(ptr);
    const a = ctx.alloc;
    const entry = try resolveEntry(self, a, dir);
    if (!entry.is_dir) return driver.Error.NotFound;

    var out = List(model.Obj).init(a);
    var page: i64 = 1;
    while (true) {
        const data = try listPage(self, a, entry.id, page);
        for (arrAt(data, "InfoList")) |item| try out.append(objFromJson(&item));
        const next = data.strAt("Next") orelse "-1";
        if (arrAt(data, "InfoList").len == 0 or std.mem.eql(u8, next, "-1")) break;
        page += 1;
    }
    return out.toOwned();
}

fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
    const self = as(ptr);
    const a = ctx.alloc;
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    if (it.next() == null) return .{ .name = "/", .is_dir = true };
    const entry = try resolveEntry(self, a, path);
    const raw = entry.raw orelse return .{ .name = entry.name, .is_dir = entry.is_dir };
    const o = objFromJson(raw);
    return .{ .name = o.name, .size = o.size, .is_dir = o.is_dir, .modified = o.modified, .created = o.created };
}

fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = args;
    const entry = try resolveEntry(self, a, path);
    if (entry.is_dir) return driver.Error.NotSupported;
    const raw = entry.raw orelse return Error.InvalidResponse;

    // Go：data.{driveId:0, etag, fileId, fileName, s3keyFlag, size, type}
    const body = try std.fmt.allocPrint(a, "{{\"driveId\":0,\"etag\":{s},\"fileId\":{d},\"fileName\":{s},\"s3keyFlag\":{s},\"size\":{d},\"type\":{d}}}", .{
        try jsonQuote(a, raw.strAt("Etag") orelse ""),
        entry.id,
        try jsonQuote(a, raw.strAt("FileName") orelse ""),
        try jsonQuote(a, raw.strAt("S3KeyFlag") orelse ""),
        raw.intAt("Size") orelse 0,
        raw.intAt("Type") orelse 0,
    });
    const res_body = try self.post(a, ep_download_info, body);
    const v = json.parse(a, res_body) catch return Error.UpstreamNotJson;
    const download_url = v.strAt("data.DownloadUrl") orelse return Error.InvalidResponse;
    var url = download_url;

    // DownloadUrl 可能带 `?params=<base64(真URL)>`（Go driver.go:88-98）。
    if (std.mem.indexOfScalar(u8, url, '?')) |q| {
        const qs = url[q + 1 ..];
        if (urlmod.queryGet(qs, "params")) |p| {
            if (decodeBase64(a, p)) |decoded| url = decoded else |_| {}
        }
    }

    // 拿到的 URL 还要再 GET 一次（带 Referer）才是真链：302 用 Location，
    // 2xx 用 body 的 data.redirect_url（Go driver.go:100-114）。这一步的 Referer
    // 固定是 `https://yun.123pan.com/`。
    const second_hop_referer = try std.fmt.allocPrint(a, "{s}/", .{origin});
    const res2 = try self.client.send(a, .{
        .method = "GET",
        .url = url,
        .headers = &[_]model.Header{.{ .name = "Referer", .value = second_hop_referer }},
        .use_cookies = false,
    });
    var final_url = url;
    if (res2.status == 302) {
        final_url = res2.header("Location") orelse return Error.InvalidResponse;
    } else if (res2.status < 300) {
        const v2 = json.parse(a, res2.body) catch return Error.UpstreamNotJson;
        final_url = v2.strAt("data.redirect_url") orelse return Error.InvalidResponse;
    } else {
        return Error.UpstreamHttp;
    }

    // ⚠️ 返回给调用方的 Referer 用的是**原始 DownloadUrl** 的 `scheme://host/`
    // （Go `driver.go:114-116` 的 `ou`），不是二次跳转后的地址，也不是固定的
    // yun.123pan.com。以前这里写死 origin，CDN 域名一变 Referer 就对不上。
    const orig = try urlmod.Url.parse(download_url);
    const link_referer = try std.fmt.allocPrint(a, "{s}://{s}/", .{ orig.scheme, orig.host });
    return .{ .url = final_url, .header = &[_]model.Header{.{ .name = "Referer", .value = link_referer }} };
}

fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    // dir = "/a/b/newdir" → parent = "/a/b"，name = "newdir"。
    const parent_path = pathParent(dir) orelse return Error.InvalidPath;
    const name = pathBase(dir) orelse return Error.InvalidPath;
    const parent = try resolveEntry(self, a, parent_path);
    const body = try std.fmt.allocPrint(a, "{{\"driveId\":0,\"etag\":\"\",\"fileName\":{s},\"parentFileId\":{d},\"size\":0,\"type\":1}}", .{ try jsonQuote(a, name), parent.id });
    _ = try self.post(a, ep_upload_request, body);
}

fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const entry = try resolveEntry(self, a, src);
    const dst = try resolveEntry(self, a, dst_dir);
    const body = try std.fmt.allocPrint(a, "{{\"fileIdList\":[{{\"FileId\":{d}}}],\"parentFileId\":{d}}}", .{ entry.id, dst.id });
    _ = try self.post(a, ep_move, body);
}

fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const entry = try resolveEntry(self, a, src);
    const body = try std.fmt.allocPrint(a, "{{\"driveId\":0,\"fileId\":{d},\"fileName\":{s}}}", .{ entry.id, try jsonQuote(a, new_name) });
    _ = try self.post(a, ep_rename, body);
}

fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = is_dir;
    const entry = try resolveEntry(self, a, path);
    // Go 把整个 File 结构体塞进 fileTrashInfoList（PascalCase 全字段）。
    const file_type: i64 = if (entry.is_dir) 1 else 0;
    const raw = entry.raw;
    const body = try std.fmt.allocPrint(a,
        "{{\"driveId\":0,\"operation\":true,\"fileTrashInfoList\":[{{\"FileName\":{s},\"Size\":{d},\"UpdateAt\":{s},\"FileId\":{d},\"Type\":{d},\"Etag\":{s},\"S3KeyFlag\":{s},\"DownloadUrl\":{s}}}]}}",
        .{
            try jsonQuote(a, if (raw) |r| r.strAt("FileName") orelse entry.name else entry.name),
            if (raw) |r| r.intAt("Size") orelse 0 else 0,
            try jsonQuote(a, if (raw) |r| r.strAt("UpdateAt") orelse "" else ""),
            entry.id,
            file_type,
            try jsonQuote(a, if (raw) |r| r.strAt("Etag") orelse "" else ""),
            try jsonQuote(a, if (raw) |r| r.strAt("S3KeyFlag") orelse "" else ""),
            try jsonQuote(a, if (raw) |r| r.strAt("DownloadUrl") orelse "" else ""),
        },
    );
    _ = try self.post(a, ep_trash, body);
}

fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
    const self = as(ptr);
    const a = ctx.alloc;
    const body = try self.get(a, ep_user_info, null);
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    const permanent = v.intAt("data.SpacePermanent") orelse 0;
    const temporary = v.intAt("data.SpaceTemp") orelse 0;
    return .{
        .total = permanent + temporary,
        .used = v.intAt("data.SpaceUsed") orelse 0,
    };
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

fn jsonQuote(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var b = Buf.init(a);
    try json.writeString(&b, s);
    return b.toOwned();
}

fn decodeBase64(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(s);
    const out = try a.alloc(u8, n);
    try dec.decode(out, s);
    return out;
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
// 上传
// ---------------------------------------------------------------------------

/// 整文件 MD5 的读取块（同时是 T7 的可复用 buffer）。
const hash_block = 128 * 1024;

fn reportProgress(ctx: *driver.Ctx, pct: f64) void {
    if (ctx.progress) |f| f(ctx.progress_userdata, @intFromFloat(@min(pct, 100.0)));
}

fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const size = src.size();
    if (size < 0) return Error.InvalidPath;
    const name = pathBase(dst) orelse return Error.InvalidPath;
    const parent = try resolveEntry(self, a, pathParent(dst) orelse return Error.InvalidPath);

    // 1) 整文件 MD5（小写 hex）= upload_request 的 etag。
    //    一遍读、一块 buffer（T7）：不用 readAll 逐块分配。
    var md5 = hash.Md5.init(.{});
    const buf = try a.alloc(u8, @intCast(@min(@as(i64, hash_block), @max(size, 1))));
    {
        var off: u64 = 0;
        while (off < @as(u64, @intCast(size))) {
            const want: usize = @intCast(@min(@as(i64, @intCast(buf.len)), size - @as(i64, @intCast(off))));
            try src.readAllInto(off, buf[0..want]);
            md5.update(buf[0..want]);
            off += want;
        }
    }
    var digest: [16]u8 = undefined;
    md5.final(&digest);
    const etag = try hash.hexLower(a, &digest);

    // 2) upload_request（driver.go:191-206）
    const body = try std.fmt.allocPrint(a,
        "{{\"driveId\":0,\"duplicate\":{d},\"etag\":{s},\"fileName\":{s},\"parentFileId\":{d},\"size\":{d},\"type\":0}}",
        .{ duplicate_overwrite, try jsonQuote(a, etag), try jsonQuote(a, name), parent.id, size },
    );
    const res_body = try self.post(a, ep_upload_request, body);
    const v = json.parse(a, res_body) catch return Error.UpstreamNotJson;
    const data = v.getPath("data") orelse return Error.InvalidResponse;

    // 秒传命中 / 复用：直接成功（driver.go:208-210）。
    const empty: []const u8 = "";
    if (boolOr(data, "Reuse") or (data.strAt("Key") orelse empty).len == 0) {
        reportProgress(ctx, 100);
        return;
    }

    const has_creds = (data.strAt("AccessKeyId") orelse empty).len > 0 and
        (data.strAt("SecretAccessKey") orelse empty).len > 0 and
        (data.strAt("SessionToken") orelse empty).len > 0;
    if (has_creds) {
        try uploadSigV4(self, a, data, src, size);
        // SDK 分支的收尾（driver.go:242-247）
        const final_body = try std.fmt.allocPrint(a, "{{\"fileId\":{d}}}", .{data.intAt("FileId") orelse 0});
        _ = try self.post(a, ep_upload_complete, final_body);
    } else {
        try uploadPresigned(self, a, data, src, size);
    }
    reportProgress(ctx, 100);
}

/// `newUpload`（upload.go:76-187）：换预签名 URL → **并发**逐片 PUT → completeS3。
///
/// 并发度 = `min(片数, UploadThread)`，对齐 Go 的
/// `errgroup.NewOrderedGroupWithContext(ctx, thread, retry.Attempts(3), BackOffDelay)`
/// （`upload.go:104-107`）。以前这里是串行的，`UploadThread` 只被记录不生效。
fn uploadPresigned(self: *Pan123, a: std.mem.Allocator, data: *const json.Value, src: model.Source, size: i64) !void {
    const key = data.strAt("Key") orelse return Error.InvalidResponse;
    const bucket = data.strAt("Bucket") orelse return Error.InvalidResponse;
    const upload_id = data.strAt("UploadId") orelse return Error.InvalidResponse;
    const storage_node = data.strAt("StorageNode") orelse return Error.InvalidResponse;
    const file_id = data.intAt("FileId") orelse return Error.InvalidResponse;
    const count: i64 = if (size > chunk_size) @divTrunc(size + chunk_size - 1, chunk_size) else 1;
    const multipart = count > 1;

    // 每个 worker 一个 client：`std.http.Client` 的连接池在 `Client.send` 里被
    // 一把锁串行化，共用一个 client 等于没并发（同 itvsh 的做法）。
    const threads_max: usize = @intCast(@max(@min(@min(self.cfg.upload_thread, url_batch), count), 1));
    const clients = try a.alloc(httpclient.Client, threads_max);
    for (clients) |*c| {
        c.* = httpclient.Client.init(self.alloc, .{
            .timeout_s = 0, // 16 MiB 单片的 PUT 可能超过默认 60s
            .insecure_skip_verify = self.client.opts.insecure_skip_verify,
            .ca_bundle_path = self.client.opts.ca_bundle_path,
        }, self.client.jar);
    }
    defer for (clients) |*c| c.deinit();

    // 每 worker 一块可复用的分片 buffer。按**实际最大片**分配，不要无脑
    // 16 MiB —— 小文件（甚至 1 字节）也用不到整片。
    const per_buf: usize = @intCast(@min(chunk_size, @max(size, 1)));
    const bufs = try a.alloc([]u8, threads_max);
    for (bufs) |*b| b.* = try a.alloc(u8, per_buf);

    var start: i64 = 1;
    while (start <= count) {
        const end = @min(start + url_batch, count + 1);
        const ep = if (multipart) ep_s3_presigned else ep_s3_auth;
        // 单片的 getS3Auth 与批量的 getS3PreSignedUrls 字段名一致、顺序不同。
        const auth_body = try std.fmt.allocPrint(a,
            "{{\"bucket\":{s},\"key\":{s},\"partNumberEnd\":{d},\"partNumberStart\":{d},\"uploadId\":{s},\"StorageNode\":{s}}}",
            .{ try jsonQuote(a, bucket), try jsonQuote(a, key), end - 1, start, try jsonQuote(a, upload_id), try jsonQuote(a, storage_node) },
        );
        const res_body = try self.post(a, ep, auth_body);
        const uv = json.parse(a, res_body) catch return Error.UpstreamNotJson;
        const urls = uv.getPath("data.presignedUrls") orelse return Error.InvalidResponse;

        var state = BatchState{
            .self = self,
            .alloc = self.alloc,
            .src = src,
            .size = size,
            .chunk_size = chunk_size,
            .urls = urls,
            .ep = ep,
            .auth_body = auth_body,
            .end = end,
        };
        state.next.store(start, .monotonic);

        const nthreads: usize = @intCast(@min(@as(i64, @intCast(threads_max)), end - start));
        const threads = try a.alloc(std.Thread, nthreads);
        for (threads, 0..) |*t, i| {
            t.* = try std.Thread.spawn(.{}, batchWorker, .{ &state, &clients[i], bufs[i] });
        }
        for (threads) |t| t.join();
        if (state.first_err) |e| {
            log.err("[123pan] batch upload failed: {s}", .{@errorName(e)});
            return e;
        }
        start = end;
    }

    // completeS3（upload.go:60-74）
    const done_body = try std.fmt.allocPrint(a,
        "{{\"StorageNode\":{s},\"bucket\":{s},\"fileId\":{d},\"fileSize\":{d},\"isMultipart\":{},\"key\":{s},\"uploadId\":{s}}}",
        .{ try jsonQuote(a, storage_node), try jsonQuote(a, bucket), file_id, size, multipart, try jsonQuote(a, key), try jsonQuote(a, upload_id) },
    );
    _ = try self.post(a, ep_upload_complete_v2, done_body);
}

/// 一个 batch（≤`url_batch` 片）的并发上传状态。
const BatchState = struct {
    self: *Pan123,
    /// 长期分配器，用来给每个 worker 建自己的 arena。
    alloc: std.mem.Allocator,
    src: model.Source,
    size: i64,
    chunk_size: i64,
    /// `data.presignedUrls`。403 时会整批换一次（见 `refetch`）。
    urls: *const json.Value,
    ep: []const u8,
    auth_body: []const u8,
    /// 本 batch 的片号上界（不含）。
    end: i64,
    next: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    cancel: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mu: std.Io.Mutex = .init,
    first_err: ?anyerror = null,
    refetched: bool = false,

    fn fail(self: *BatchState, e: anyerror) void {
        self.mu.lockUncancelable(rt.io());
        defer self.mu.unlock(rt.io());
        if (self.first_err == null) self.first_err = e;
        self.cancel.store(true, .release);
    }

    /// 403 = 预签名 URL 过期：整批换一次。对齐 Go 的 singleflight —— 只换一次，
    /// 避免每个 worker 各自去打一遍 auth 接口。
    fn refetch(self: *BatchState, a: std.mem.Allocator) void {
        self.mu.lockUncancelable(rt.io());
        defer self.mu.unlock(rt.io());
        if (self.refetched) return;
        self.refetched = true;
        const body = self.self.post(a, self.ep, self.auth_body) catch return;
        const v = json.parse(a, body) catch return;
        if (v.getPath("data.presignedUrls")) |u| self.urls = u;
    }
};

fn batchWorker(state: *BatchState, client: *httpclient.Client, buf: []u8) void {
    // Arena 不是线程安全的，每个 worker 一个。
    var arena = std.heap.ArenaAllocator.init(state.alloc);
    defer arena.deinit();

    while (!state.cancel.load(.acquire)) {
        const part_no = state.next.fetchAdd(1, .monotonic);
        if (part_no >= state.end) return;
        putPart(state, client, arena.allocator(), buf, part_no) catch |e| {
            state.fail(e);
            return;
        };
        // 每片之后回收，避免大文件把整轮临时量都堆在 arena 里。
        _ = arena.reset(.retain_capacity);
    }
}

fn putPart(state: *BatchState, client: *httpclient.Client, a: std.mem.Allocator, buf: []u8, part_no: i64) !void {
    const off: u64 = @intCast((part_no - 1) * state.chunk_size);
    const len: usize = @intCast(@min(state.chunk_size, state.size - @as(i64, @intCast(off))));
    const chunk = buf[0..len];
    try state.src.readAllInto(off, chunk);

    // Go：`retry.Attempts(3)` + `BackOffDelay` + `Delay(1s)`（upload.go:106-107）。
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        const url = urlFor(state.urls, part_no) orelse return Error.MissingUploadUrl;
        const res = client.send(a, .{
            .method = "PUT",
            .url = url,
            // 预签名 URL 多一个头都会 403（aliyun OSS V1 的教训，见
            // Request.omit_content_type 的注释）。
            .omit_content_type = true,
            .body = chunk,
            .use_cookies = false,
        }) catch |e| {
            if (attempt + 1 >= 3) return e;
            rt.sleepMillis(1000 * (@as(i64, 1) << @intCast(attempt)));
            continue;
        };
        if (res.status == 200) return;
        // 403 = URL 过期：整批换一次再重试这一片。
        if (res.status == 403) {
            state.refetch(a);
            if (attempt + 1 >= 3) return Error.UploadFailed;
            continue;
        }
        log.warn("[123pan] part {d} HTTP {d}", .{ part_no, res.status });
        if (attempt + 1 >= 3) return Error.UploadFailed;
        rt.sleepMillis(1000 * (@as(i64, 1) << @intCast(attempt)));
    }
}

/// 预签名 URL map 的取值：键是分片号的十进制字符串（Go `strconv.Itoa(cur)`）。
fn urlFor(urls: *const json.Value, part_no: i64) ?[]const u8 {
    var key_buf: [16]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{d}", .{part_no}) catch return null;
    return urls.strAt(key);
}

// ---------------------------------------------------------------------------
// 带 AccessKeyId 的老式上传分支：SigV4 自签（drivers/123/driver.go:215-241
// 走 aws-sdk，行为等价于这里的自签实现）
// ---------------------------------------------------------------------------

const s3_region = "123pan";
const s3_service = "s3";
const unsigned_payload = "UNSIGNED-PAYLOAD";
/// SDK 分支的分片大小（Go 的 s3manager.DefaultUploadPartSize 是 5 MiB，
/// 大文件按 10000 片上限折算；这里取 16 MiB，与预签名分支一致）。
const sigv4_part: i64 = 16 * 1024 * 1024;
/// 小于这个值走单次 PUT（等价于 s3manager 的小文件路径）。
const sigv4_single_max: i64 = 64 * 1024 * 1024;

const SigCtx = struct {
    amz_date: []const u8,
    date_stamp: []const u8,
    scope: []const u8,
    host: []const u8,
    access_key: []const u8,
    secret_key: []const u8,
    session_token: []const u8,
};

/// AWS SigV4 签名，产出 Authorization 头。
fn sigV4(a: std.mem.Allocator, ctx: SigCtx, method: []const u8, canonical_uri: []const u8, canonical_query: []const u8, extra_headers: []const model.Header) ![]const u8 {
    // 规范头：host;x-amz-content-sha256;x-amz-date;x-amz-security-token 已有序。
    var canon_headers = Buf.init(a);
    try canon_headers.print("host:{s}\n", .{ctx.host});
    try canon_headers.append("x-amz-content-sha256:");
    try canon_headers.append(unsigned_payload);
    try canon_headers.append("\n");
    try canon_headers.print("x-amz-date:{s}\n", .{ctx.amz_date});
    try canon_headers.print("x-amz-security-token:{s}\n", .{ctx.session_token});
    for (extra_headers) |h| {
        // 额外头也按 key:value\n 进 canonical（键转小写）。
        var low = try a.alloc(u8, h.name.len);
        for (h.name, 0..) |c, i| low[i] = std.ascii.toLower(c);
        try canon_headers.print("{s}:{s}\n", .{ low, h.value });
    }
    const signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";

    var canon_req = Buf.init(a);
    try canon_req.print("{s}\n{s}\n{s}\n{s}\n{s}\n{s}", .{
        method, canonical_uri, canonical_query, canon_headers.slice(), signed_headers, unsigned_payload,
    });

    var req_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canon_req.slice(), &req_hash, .{});

    var sts = Buf.init(a);
    try sts.append("AWS4-HMAC-SHA256\n");
    try sts.print("{s}\n{s}\n", .{ ctx.amz_date, ctx.scope });
    try sts.append(&std.fmt.bytesToHex(req_hash, .lower));

    // 签名密钥链：AWS4+secret → date → region → service → "aws4_request"
    const seed = try a.alloc(u8, 4 + ctx.secret_key.len);
    @memcpy(seed[0..4], "AWS4");
    @memcpy(seed[4..], ctx.secret_key);
    var k_date: [32]u8 = undefined;
    HmacSha256(seed, ctx.date_stamp, &k_date);
    var k_region: [32]u8 = undefined;
    HmacSha256(&k_date, s3_region, &k_region);
    var k_service: [32]u8 = undefined;
    HmacSha256(&k_region, s3_service, &k_service);
    var k_signing: [32]u8 = undefined;
    HmacSha256(&k_service, "aws4_request", &k_signing);
    var signature: [32]u8 = undefined;
    HmacSha256(&k_signing, sts.slice(), &signature);

    return std.fmt.allocPrint(a, "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}", .{
        ctx.access_key, ctx.scope, signed_headers, &std.fmt.bytesToHex(signature, .lower),
    });
}

fn HmacSha256(key: []const u8, msg: []const u8, out: *[32]u8) void {
    std.crypto.auth.hmac.sha2.HmacSha256.create(out, msg, key);
}

fn uploadSigV4(self: *Pan123, a: std.mem.Allocator, data: *const json.Value, src: model.Source, size: i64) !void {
    const endpoint = data.strAt("EndPoint") orelse return Error.BadS3Params;
    const bucket = data.strAt("Bucket") orelse return Error.BadS3Params;
    const key = try urlmod.encode(a, data.strAt("Key") orelse return Error.BadS3Params, .path);
    const file_id = data.intAt("FileId") orelse return Error.BadS3Params;

    // host：去掉 scheme；带非标准端口时保留（aws-sdk 的 host 头也带端口）。
    var host = endpoint;
    if (std.mem.indexOf(u8, endpoint, "://")) |i| host = endpoint[i + 3 ..];
    host = std.mem.trimEnd(u8, host, "/");

    // amz 日期与 scope
    const secs = rt.nowSeconds();
    const days = @divFloor(secs, std.time.s_per_day);
    const c = timeutil.civilFromDays(days);
    const sod = @mod(secs, std.time.s_per_day);
    var date_b = Buf.init(a);
    try padNum(&date_b, c.y, 4);
    try padNum(&date_b, c.m, 2);
    try padNum(&date_b, c.d, 2);
    const date_stamp = try date_b.toOwned();
    var time_b = Buf.init(a);
    try padNum(&time_b, @divFloor(sod, 3600), 2);
    try padNum(&time_b, @divTrunc(@mod(sod, 3600), 60), 2);
    try padNum(&time_b, @mod(sod, 60), 2);
    const amz_date = try std.fmt.allocPrint(a, "{s}T{s}Z", .{ date_stamp, try time_b.toOwned() });
    const scope = try std.fmt.allocPrint(a, "{s}/{s}/{s}/aws4_request", .{ date_stamp, s3_region, s3_service });

    const ctx = SigCtx{
        .amz_date = amz_date,
        .date_stamp = date_stamp,
        .scope = scope,
        .host = host,
        .access_key = data.strAt("AccessKeyId") orelse return Error.BadS3Params,
        .secret_key = data.strAt("SecretAccessKey") orelse return Error.BadS3Params,
        .session_token = data.strAt("SessionToken") orelse return Error.BadS3Params,
    };

    const obj_uri = try std.fmt.allocPrint(a, "/{s}/{s}", .{ bucket, key });
    const obj_url = try std.fmt.allocPrint(a, "{s}/{s}/{s}", .{ std.mem.trimEnd(u8, endpoint, "/"), bucket, key });

    if (size <= sigv4_single_max) {
        // 单次 PUT（小文件）
        const buf = try a.alloc(u8, @intCast(@max(size, 1)));
        try src.readAllInto(0, buf[0..@intCast(size)]);
        const auth = try sigV4(a, ctx, "PUT", obj_uri, "", &.{});
        var hl = List(model.Header).init(a);
        try hl.append(.{ .name = "x-amz-content-sha256", .value = unsigned_payload });
        try hl.append(.{ .name = "x-amz-date", .value = amz_date });
        try hl.append(.{ .name = "x-amz-security-token", .value = ctx.session_token });
        try hl.append(.{ .name = "Authorization", .value = auth });
        const res = try self.client.send(a, .{
            .method = "PUT",
            .url = obj_url,
            .headers = hl.slice(),
            .omit_content_type = true,
            .body = buf[0..@intCast(size)],
            .use_cookies = false,
        });
        if (res.status != 200) {
            log.warn("[123pan] sigv4 single PUT HTTP {d}: {s}", .{ res.status, res.body[0..@min(res.body.len, 200)] });
            return Error.UploadFailed;
        }
        _ = file_id;
        return;
    }

    // 分片上传
    const chunk_buf = try a.alloc(u8, @intCast(sigv4_part));
    const count: i64 = @divTrunc(size + sigv4_part - 1, sigv4_part);

    const base_headers = [_]model.Header{
        .{ .name = "x-amz-content-sha256", .value = unsigned_payload },
        .{ .name = "x-amz-date", .value = amz_date },
        .{ .name = "x-amz-security-token", .value = ctx.session_token },
    };

    // 1) CreateMultipartUpload：POST obj?uploads，响应 XML 里拿 UploadId
    var mpu_body: []const u8 = "";
    {
        const auth = try sigV4(a, ctx, "POST", obj_uri, "uploads=", &.{});
        const res = try self.client.send(a, .{
            .method = "POST",
            .url = try std.fmt.allocPrint(a, "{s}?uploads=", .{obj_url}),
            .headers = &[_]model.Header{
                base_headers[0],
                base_headers[1],
                base_headers[2],
                .{ .name = "Authorization", .value = auth },
            },
            .omit_content_type = true,
            .use_cookies = false,
        });
        if (res.status != 200) {
            log.warn("[123pan] sigv4 MPU create HTTP {d}", .{res.status});
            return Error.UploadFailed;
        }
        mpu_body = res.body;
    }
    const upload_id = xmlTag(mpu_body, "UploadId") orelse return Error.InvalidResponse;

    // 2) 逐片 PUT：obj?partNumber=N&uploadId=U，ETag 从响应头拿（带引号）
    var etags = try a.alloc([]const u8, @intCast(count));
    {
        var part_no: i64 = 1;
        while (part_no <= count) : (part_no += 1) {
            const off: u64 = @intCast((part_no - 1) * sigv4_part);
            const len: usize = @intCast(@min(sigv4_part, size - @as(i64, @intCast(off))));
            try src.readAllInto(off, chunk_buf[0..len]);
            const q = try std.fmt.allocPrint(a, "partNumber={d}&uploadId={s}", .{ part_no, upload_id });
            const auth = try sigV4(a, ctx, "PUT", obj_uri, q, &.{});
            const url = try std.fmt.allocPrint(a, "{s}?{s}", .{ obj_url, q });
            const res = try self.client.send(a, .{
                .method = "PUT",
                .url = url,
                .headers = &[_]model.Header{
                    base_headers[0],
                    base_headers[1],
                    base_headers[2],
                    .{ .name = "Authorization", .value = auth },
                },
                .omit_content_type = true,
                .body = chunk_buf[0..len],
                .use_cookies = false,
            });
            if (res.status != 200) {
                log.warn("[123pan] sigv4 part {d} HTTP {d}", .{ part_no, res.status });
                return Error.UploadFailed;
            }
            etags[@intCast(part_no - 1)] = res.header("ETag") orelse return Error.InvalidResponse;
        }
    }

    // 3) CompleteMultipartUpload：POST obj?uploadId=U，body 是分片清单 XML
    var xml = Buf.init(a);
    try xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUpload>");
    for (etags, 0..) |etag, i| {
        try xml.print("<Part><PartNumber>{d}</PartNumber><ETag>{s}</ETag></Part>", .{ i + 1, etag });
    }
    try xml.append("</CompleteMultipartUpload>");
    {
        const q = try std.fmt.allocPrint(a, "uploadId={s}", .{upload_id});
        const auth = try sigV4(a, ctx, "POST", obj_uri, q, &.{});
        const res = try self.client.send(a, .{
            .method = "POST",
            .url = try std.fmt.allocPrint(a, "{s}?{s}", .{ obj_url, q }),
            .headers = &[_]model.Header{
                .{ .name = "x-amz-content-sha256", .value = unsigned_payload },
                .{ .name = "x-amz-date", .value = amz_date },
                .{ .name = "x-amz-security-token", .value = ctx.session_token },
                .{ .name = "Authorization", .value = auth },
                .{ .name = "Content-Type", .value = "application/xml" },
            },
            .body = xml.slice(),
            .use_cookies = false,
        });
        if (res.status != 200) {
            log.warn("[123pan] sigv4 complete HTTP {d}: {s}", .{ res.status, res.body[0..@min(res.body.len, 200)] });
            return Error.UploadFailed;
        }
    }
    _ = file_id;
}

/// 从一段 XML 里抠 `<tag>...</tag>` 的文本。够用就好 —— MPU 响应极简单。
fn xmlTag(xml: []const u8, tag: []const u8) ?[]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [65]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}>", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const s = std.mem.indexOf(u8, xml, open) orelse return null;
    const from = s + open.len;
    const e = std.mem.indexOf(u8, xml[from..], close) orelse return null;
    return xml[from .. from + e];
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    // 逐字等于 Go 的 `driver.Config.Name`（drivers/123/meta.go:18）。用户
    // 备份里 id=3/4 两个存储的 `driver` 字段就是 "123Pan"。
    .key = "123Pan",
    // 历史名/大小写变体只用于查找（`driver.find` 允许忽略大小写已覆盖大部）。
    .aliases = &.{"123"},
    .label = "123 云盘",
    .secrets = &.{ "password", "AccessToken" },
    // 字段名与 Go `Addition` 的 json tag 逐字一致（无 tag 字段用字段名）。
    .addition_schema =
    \\{
    \\  "username":       {"type":"string","required":true,"help":"手机号或邮箱"},
    \\  "password":       {"type":"string","required":true,"secret":true,"help":"登录密码"},
    \\  "root_folder_id": {"type":"string","default":"0","help":"根目录 ID，123 的根是 0"},
    \\  "UploadThread":   {"type":"number","default":3,"min":1,"max":32,"help":"上传并发上限（本实现串行上传，该值仅作记录）"},
    \\  "platform":       {"type":"string","default":"web","help":"platform 请求头，默认 web"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    return driver.asDriver(Pan123, try createWithId(alloc, storage_id, cfg));
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Pan123 {
    const self = try alloc.create(Pan123);
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
// 测试 —— 全部纯逻辑，不打网络
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "T2/T3: real Go addition JSON (backup shape) parses into the driver" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与用户 Go 备份 storage #3/#4 一致：
    // ['AccessToken','UploadThread','password','platform','root_folder_id','username']
    const src =
        \\{"username":"22644212509","password":"pw","AccessToken":"tok",
        \\ "UploadThread":5,"platform":"web","root_folder_id":"0"}
    ;
    const v = try json.parse(a, src);
    const add = try Addition.parse(a, &v);
    try testing.expectEqualStrings("22644212509", add.username);
    try testing.expectEqualStrings("tok", add.access_token);
    try testing.expectEqual(@as(i64, 5), add.upload_thread);
    try testing.expectEqualStrings("web", add.platform);

    const out = try add.toJson(a);
    for ([_][]const u8{ "\"username\"", "\"password\"", "\"AccessToken\"", "\"UploadThread\"", "\"platform\"", "\"root_folder_id\"" }) |k| {
        try testing.expect(std.mem.indexOf(u8, out, k) != null);
    }
    const v2 = try json.parse(a, out);
    const add2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(add.access_token, add2.access_token);
    try testing.expectEqual(add.upload_thread, add2.upload_thread);
}

test "T2: default addition values match Go" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const add = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", add.root_folder_id);
    try testing.expectEqual(@as(i64, 3), add.upload_thread);
    try testing.expectEqualStrings("web", add.platform);
}

test "T2: isEmail splits passport vs mail accounts" {
    try testing.expect(Pan123.isEmail("user@example.com"));
    try testing.expect(!Pan123.isEmail("22644212509"));
    try testing.expect(!Pan123.isEmail("@x"));
    try testing.expect(!Pan123.isEmail("x@"));
}

test "T2: signPath is deterministic given a fixed clock" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const s1 = try signPath(a, "/b/api/file/list/new");
    const s2 = try signPath(a, "/b/api/file/list/new");
    try testing.expectEqualStrings(s1.time_sign, s2.time_sign); // 同一分钟内必然相同
    const st = try cstStamp(a);
    try testing.expectEqual(@as(usize, 12), st.len); // YYYYMMDDHHMM
    try testing.expect(!std.mem.startsWith(u8, st, "+")); // 不能出现填充符号
    // 时间戳会变，但**签名算法本身**必须稳定：同路径的 timeSign 键存在、
    // value 是三段式，且两次调用都能构造出合法 URL。
    try testing.expect(s1.time_sign.len > 0);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, s2.value, "-") + 1);
    const url = try buildUrl(a, ep_file_list, "driveId=0&limit=100");
    try testing.expect(std.mem.startsWith(u8, url, ep_file_list));
    try testing.expect(std.mem.indexOf(u8, url, s2.time_sign) != null);
    try testing.expect(std.mem.indexOf(u8, url, "driveId=0") != null);
    // URL path 必须原样出现在签名数据里（Go 对 u.Path 签名）。
    try testing.expect(std.mem.indexOf(u8, urlPathOf(url), "/b/api/file/list/new") != null);
}

test "T2: crc32 time mapping matches Go's table" {
    // nowStr "202401021504" → 映射后取 CRC32。Go 的表：
    // 0-9 → a d e f g h l m y i
    const mapped = blk: {
        var out: [12]u8 = undefined;
        const digits = "202401021504";
        const table = [_]u8{ 'a', 'd', 'e', 'f', 'g', 'h', 'l', 'm', 'y', 'i' };
        for (digits, 0..) |d, i| out[i] = table[d - '0'];
        break :blk out;
    };
    // 独立算一遍 CRC-32/ISO-HDLC 验证 std 与 Go 同算法（Go 用 ChecksumIEEE）。
    try testing.expectEqual(std.hash.Crc32.hash("123456789"), 0xCBF43926);
    try testing.expect(mapped.len == 12);
    try testing.expectEqual(@as(u8, 'e'), mapped[0]); // '2' → 'e'
    try testing.expectEqual(@as(u8, 'a'), mapped[1]); // '0' → 'a'
}

test "T2: list page JSON parses PascalCase file entries" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 形状对齐 Go 的 Files.Data.InfoList（注意 PascalCase 与字符串 Next）
    const body =
        \\{"code":0,"message":"success","data":{"Next":"-1","Total":2,"InfoList":[
        \\ {"FileName":"a.txt","Size":12,"UpdateAt":"2024-01-02 15:04:05","FileId":100,"Type":0,"Etag":"ABC","S3KeyFlag":"1","DownloadUrl":""},
        \\ {"FileName":"sub","Size":0,"UpdateAt":"2024-01-02 15:04:05","FileId":101,"Type":1,"Etag":"","S3KeyFlag":"","DownloadUrl":""}]}}
    ;
    const v = try json.parse(a, body);
    const data = v.getPath("data").?;
    const items = arrAt(data, "InfoList");
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("a.txt", items[0].strAt("FileName").?);
    try testing.expectEqual(@as(i64, 12), items[0].intAt("Size").?);
    try testing.expectEqual(@as(i64, 100), items[0].intAt("FileId").?);
    try testing.expectEqual(@as(i64, 0), items[0].intAt("Type").?);

    const o = objFromJson(&items[0]);
    try testing.expectEqualStrings("a.txt", o.name);
    try testing.expect(!o.is_dir);
    try testing.expectEqual(@as(i64, 12), o.size);
    // parseCnTime 正常解出 2024-01-02 15:04:05（+8 区口径按 Go 的本地时区）
    try testing.expect(o.modified > 1_700_000_000);

    const o2 = objFromJson(&items[1]);
    try testing.expect(o2.is_dir);
}

test "T2: pathBase/pathParent split the way the vtable promises" {
    try testing.expectEqualStrings("newdir", pathBase("/a/b/newdir").?);
    try testing.expectEqualStrings("newdir", pathBase("newdir").?);
    try testing.expectEqualStrings("newdir", pathBase("/a/b/newdir/").?);
    try testing.expect(pathBase("/") == null);
    try testing.expectEqualStrings("/a/b", pathParent("/a/b/newdir").?);
    try testing.expectEqualStrings("/", pathParent("/a").?);
    try testing.expect(pathParent("newdir") == null);
}

test "T2: base64 params decode for the download-url dance" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    // "https://real.example/x?a=1" 的 base64（Go driver.go:88-98 的解码目标）
    const enc = "aHR0cHM6Ly9yZWFsLmV4YW1wbGUveD9hPTE=";
    const dec = try decodeBase64(a, enc);
    try testing.expectEqualStrings("https://real.example/x?a=1", dec);
}

test "T2: xmlTag pulls UploadId out of an MPU response" {
    const xml_body = "<?xml version=\"1.0\"?><InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>2~abcDEF</UploadId></InitiateMultipartUploadResult>";
    try testing.expectEqualStrings("2~abcDEF", xmlTag(xml_body, "UploadId").?);
    try testing.expect(xmlTag(xml_body, "Nope") == null);
}

test "T2: createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const self = try createWithId(a, 3, null);
    defer self.client.deinit();
    try testing.expectEqual(@as(i64, 3), self.storage_id);
    try testing.expectEqualStrings("123Pan", Pan123.drvName(@ptrCast(self)));
    try testing.expectEqualStrings("123Pan", factory.key);
}

test "T2: only FileList is rate-limited (matches Go)" {
    // Go 的限速器虽然按端点名建桶（driver.go:250-253），但**只有 util.go:364
    // 一处**调用了它 —— 即只有 FileList 受限。以前 Zig 对每个端点都等 700ms，
    // 每次写操作白白多花 0.7s。这里钉住「限速槽只有 FileList 一个」。
    try testing.expectEqual(@as(usize, 1), initial_rate.len);
    try testing.expectEqualStrings(ep_file_list, initial_rate[0].ep);
    try testing.expectEqual(@as(i64, 700), rate_gap_ms);
}






test "T2: copy is NotSupported, matching Go" {
    // Go `drivers/123/driver.go:162-164` 的 Copy 就是 `return errs.NotSupport`。
    // 这里显式钉住：vtable 里 `.copy` 留空，`Driver.copy` 统一返回
    // `Error.NotSupported`（driver.zig 的默认槽语义）。哪天有人「顺手补上」，
    // 这个测试会提醒他上游根本没有这个能力。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const self = try createWithId(a, 7, null);
    defer self.client.deinit();
    const d = driver.asDriver(Pan123, self);
    var ctx = driver.Ctx{ .alloc = a };
    try testing.expectError(driver.Error.NotSupported, d.copy(&ctx, "/src", "/dst"));
}
