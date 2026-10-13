//! 123 云盘开放平台驱动 —— Go 版 `drivers/123_open` 的 Zig 移植。
//!
//! 这个驱动在九个目标里是**结构最规整**的一个，因此拿它当 ID 型驱动的样板。
//! 它踩中的难点与 itvsh 完全不同：
//!
//!   1. **路径 → ID 的映射**。123pan 的 API 全部以数字 `fileId` 为键，而本工程
//!      的 vtable 全部以**路径**为参数（见 `driver.zig`）。Go 版靠 OpenList 内核
//!      维护的 `model.Obj` 缓存绕过这个问题（它的 `List` 直接收到带 ID 的 Obj）；
//!      Zig 版没有那层缓存，所以这里自己实现 `resolveEntry()` —— 从根 ID 开始
//!      逐级列目录找名字。代价是深度次 API 调用，换来的是驱动可以无状态重启。
//!   2. **两套互斥的取 token 方式**。在线 API（`use_online_api`，走第三方
//!      renewapi）和开发者 API（`ClientID`/`ClientSecret`，走官方 access_token）
//!      返回的字段名完全不同（`access_token`/`refresh_token`/`expires_in`
//!      vs `data.accessToken`/`data.expiredAt`），且过期时间的表示一个是
//!      **相对秒数**、一个是 **RFC3339 字符串**。
//!   3. **401 自愈**。`Request()` 是个重试循环：401 强制刷 token 重来，429 退避
//!      重来，其它错误码才上抛。这个循环是驱动正确性的核心，所以单独成函数。
//!   4. **分片上传 + 秒传三级降级**：SHA1 秒传 → MD5 秒传 → 真上传 → 轮询完成。
//!
//! 与 Go 版的差异（都是有意为之，不是遗漏）：
//!
//!   * **并发分片上传改为串行**。Go 用 `errgroup` 起 `UploadThread` 个协程；
//!     本工程的 HTTP 客户端在 `Client.send` 上有一把全局互斥锁（`std.http.Client`
//!     的连接池不是线程安全的），并发在这里只会退化成串行 + 争锁。所以直接串行，
//!     `upload_thread` 只用于给用户一个"别把 123 打爆"的旋钮（映射到限速）。
//!   * **上传前必定本地算 SHA1 和 MD5**。Go 的 `file.GetHash()` 可能已经被上层
//!     算过；本工程的 `model.Source` 只有 `size`/`readAt`，没有哈希，所以无论
//!     如何都要自己过一遍。两个哈希在**同一遍**读里算完，不是两遍。
//!   * **`Copy` 不提供**。vtable 里本来就没有 `copy` 槽位，上游那个"用 MD5 秒传
//!     模拟复制"的实现依赖 `create` 的副作用，移植过来价值低、坑多。
//!   * **离线下载未移植**。它需要任务中心（`/api/task/*`）配合，属于已知缺口。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const timeutil = @import("../util/time.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

const api_base = "https://open-api.123pan.com";
/// 开发者 API 的 token 端点。注意它**不带** `/api/v1` 前缀。
const access_token_url = api_base ++ "/api/v1/access_token";

/// 在线 renewapi 的默认地址，与 Go 版 `Addition.APIAddress` 的 default 一致。
const default_api_address = "https://api.oplist.org/123cloud/renewapi";

/// 分页大小。Go 版写死 100（`getFiles(parentFileId, 100, fileLastId)`）。
const page_size: i64 = 100;
/// `duplicate` 参数：2 = 保留两者（重名时自动改名），与 Go 版一致。
const duplicate_keep_both: i64 = 2;
/// `type` 字段：1 = 目录，2 = 文件。
const type_dir: i64 = 1;
/// 上传完成后轮询 `upload_complete` 的上限与间隔，与 Go 版一致。
const complete_poll_max = 60;
const complete_poll_interval_ms: i64 = 1000;
/// token 提前 5 分钟视为过期，与 Go 版 `tm.expiredAt.Add(-5*time.Minute)` 一致。
const token_early_refresh_s: i64 = 300;
/// 没有刷新能力时（用户手填个人 token），假定 90 天有效 —— Go 版注释说
/// "默认过期时间90天，jwt exp 不可靠"，即不去解 JWT，纯靠时间兜底。
const personal_token_ttl_s: i64 = 90 * 24 * 3600;
/// 计算整文件哈希时的读取块大小。128 KiB 与 itvsh 的分块一致。
const hash_block = 128 * 1024;
/// 分片上传时单片的内存上限。服务端给的 `sliceSize` 正常是 5 MiB，
/// 但它是服务端可控的字段，这里设个天花板免得一个畸形响应把光猫的
/// 128 MiB 内存吃掉。
const max_slice_bytes: i64 = 16 * 1024 * 1024;

pub const Error = error{
    /// 没有可用的鉴权方式：既没配在线 API，也没配开发者密钥。
    NoAuthMethod,
    /// 刷新失败过，已熔断，不再重试 —— 对应 Go 的 `blockRefresh`。
    TokenRefreshBlocked,
    UpstreamHttp,
    UpstreamNotJson,
    /// 上游返回了非 0 的 `code`（401/429 已在重试循环里消化掉）。
    UpstreamError,
    /// 响应里缺了必需字段。
    InvalidResponse,
    /// 上传完成轮询超时。
    UploadTimeout,
    /// 服务端给出的 `sliceSize` 荒谬。
    BadSliceSize,
    /// 路径为空、只有分隔符，或缺少文件名。API 层把它映射成 400。
    InvalidPath,
    /// 驱动不提供的能力。
    NotSupported,
};

// ---------------------------------------------------------------------------
// 配置（对应 Go 的 Addition）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    /// 开发者密钥，从 https://www.123pan.com/developer 申请。
    client_id: []const u8 = "",
    client_secret: []const u8 = "",
    /// 直接写死的 AccessToken。有过期时间，Go 版注释明确"不建议直接填写"。
    access_token: []const u8 = "",
    /// 在线 API 方式的 refresh_token（对个人开发者暂未开放）。
    refresh_token: []const u8 = "",
    use_online_api: bool = true,
    api_url_address: []const u8 = default_api_address,
    upload_thread: i64 = 3,
    direct_link: bool = false,
    direct_link_private_key: []const u8 = "",
    /// 直链签名的有效期，单位分钟。
    direct_link_valid_duration: i64 = 30,
    /// 根目录 ID，对应 Go 的 `driver.RootID`（json tag `root_folder_id`）。
    /// 123pan 的根是 `"0"`。
    root_folder_id: []const u8 = "0",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.client_id = try dupeOr(alloc, o.strAt("ClientID"), "");
        a.client_secret = try dupeOr(alloc, o.strAt("ClientSecret"), "");
        a.access_token = try dupeOr(alloc, o.strAt("AccessToken"), "");
        a.refresh_token = try dupeOr(alloc, o.strAt("RefreshToken"), "");
        if (boolAt(o, "use_online_api")) |b| a.use_online_api = b;
        a.api_url_address = try dupeOr(alloc, o.strAt("api_url_address"), default_api_address);
        if (o.intAt("UploadThread")) |n| a.upload_thread = n;
        if (boolAt(o, "DirectLink")) |b| a.direct_link = b;
        a.direct_link_private_key = try dupeOr(alloc, o.strAt("DirectLinkPrivateKey"), "");
        if (o.intAt("DirectLinkValidDuration")) |n| a.direct_link_valid_duration = n;
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), "0");
        return a;
    }

    /// 序列化回 `addition` 字符串。键名与 Go 版 json tag 一致，便于双向迁移。
    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("ClientID", self.client_id);
        try w.str("ClientSecret", self.client_secret);
        try w.str("AccessToken", self.access_token);
        try w.str("RefreshToken", self.refresh_token);
        try w.boolean("use_online_api", self.use_online_api);
        try w.str("api_url_address", self.api_url_address);
        try w.int("UploadThread", self.upload_thread);
        try w.boolean("DirectLink", self.direct_link);
        try w.str("DirectLinkPrivateKey", self.direct_link_private_key);
        try w.int("DirectLinkValidDuration", self.direct_link_valid_duration);
        try w.str("root_folder_id", self.root_folder_id);
        try w.end();
        return b.toOwned();
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    const s = v orelse return alloc.dupe(u8, fallback);
    return alloc.dupe(u8, s);
}

/// 极小的有序对象写入器。字段顺序在源码里一眼可见 —— `addition` 是要跟
/// Go 版互相迁移的，用通用 builder 会把这个顺序藏起来。
const ObjWriter = struct {
    b: *Buf,
    first: bool = true,

    fn begin(self: *ObjWriter) !void {
        try self.b.appendByte('{');
    }
    fn key(self: *ObjWriter, name: []const u8) !void {
        if (!self.first) try self.b.appendByte(',');
        self.first = false;
        try json.writeString(self.b, name);
        try self.b.appendByte(':');
    }
    fn str(self: *ObjWriter, name: []const u8, v: []const u8) !void {
        try self.key(name);
        try json.writeString(self.b, v);
    }
    fn int(self: *ObjWriter, name: []const u8, v: i64) !void {
        try self.key(name);
        try self.b.print("{d}", .{v});
    }
    fn boolean(self: *ObjWriter, name: []const u8, v: bool) !void {
        try self.key(name);
        try self.b.append(if (v) "true" else "false");
    }
    fn end(self: *ObjWriter) !void {
        try self.b.appendByte('}');
    }
};

// ---------------------------------------------------------------------------
// 限速
// ---------------------------------------------------------------------------

/// 每个端点一个。Go 用的是容量 `qps`、每秒回填一次的信号量；这里用
/// **最小请求间隔**（`1000/qps` 毫秒）。
///
/// 两者的稳态速率相同。差别在突发：Go 允许瞬间打 `qps` 个请求，这里不允许。
/// 之所以可以接受这个弱化 —— 本工程的 `Client.send` 上有一把全局互斥锁
/// （`std.http.Client` 的连接池不是线程安全的），请求本来就是串行的，
/// 突发在结构上不存在。见 `client.zig` 里 `lock` 字段的注释。
const RateLimiter = struct {
    qps: u32 = 0,
    last_ms: i64 = 0,
    mu: std.Io.Mutex = .init,

    fn minIntervalMs(qps: u32) i64 {
        if (qps == 0) return 0;
        // 向上取整，避免 qps=3 时算成 333ms 而实际略微超速。
        return @divTrunc(999 + @as(i64, qps), @as(i64, qps));
    }

    /// 纯函数，便于测试：距离下一次允许发请求还有多少毫秒。
    fn waitMs(last_ms: i64, now_ms: i64, qps: u32) i64 {
        const interval = minIntervalMs(qps);
        if (interval == 0) return 0;
        const next = last_ms + interval;
        return if (now_ms >= next) 0 else next - now_ms;
    }

    fn acquire(self: *RateLimiter) void {
        if (self.qps == 0) return;
        self.mu.lockUncancelable(rt.io());
        defer self.mu.unlock(rt.io());
        const now = rt.nowMillis();
        const w = waitMs(self.last_ms, now, self.qps);
        if (w > 0) rt.sleepMillis(w);
        self.last_ms = rt.nowMillis();
    }
};

/// 一个 API 端点：URL + 限速器。
const Api = struct {
    url: []const u8,
    limiter: RateLimiter = .{},
};

fn api(url: []const u8, qps: u32) Api {
    return .{ .url = url, .limiter = .{ .qps = qps } };
}

/// 端点表。qps 全部照抄 Go 版 `util.go` 顶部的 `InitApiInfo(..., n)`。
///
/// 必须是 `var` 而不是 `const`：`Api` 里有可变状态（`limiter.last_ms`），
/// 而 `request()` 拿的是 `*Api`。写成 `const` 的话取地址会得到指向 comptime
/// 内存的指针，改它就是改 .rodata。
const endpoints = struct {
    var user_info = api(api_base ++ "/api/v1/user/info", 1);
    var file_list = api(api_base ++ "/api/v2/file/list", 3);
    var download_info = api(api_base ++ "/api/v1/file/download_info", 5);
    var direct_link = api(api_base ++ "/api/v1/direct-link/url", 5);
    var mkdir = api(api_base ++ "/upload/v1/file/mkdir", 2);
    var move = api(api_base ++ "/api/v1/file/move", 1);
    var rename = api(api_base ++ "/api/v1/file/name", 1);
    var trash = api(api_base ++ "/api/v1/file/trash", 2);
    var upload_create = api(api_base ++ "/upload/v2/file/create", 2);
    // D02：Go 的常量是 `InitApiInfo(Api+"/upload/v2/file/upload_complete", 0)`
    // （drivers/123_open/util.go:33）。以前少了 `upload_` 前缀，完成端点打错，
    // 上传收尾必然失败。
    var upload_complete = api(api_base ++ "/upload/v2/file/upload_complete", 0);
    var upload_sha1_reuse = api(api_base ++ "/upload/v2/file/sha1_reuse", 2);
};

// ---------------------------------------------------------------------------
// json 取值助手
//
// `getPath()` 返回 `?*const Value`，直接 `.?.asBool()` 在字段缺失时是
// 未定义行为（`.?` 对 null 是 panic 而非错误）。123pan 的响应会**省略**
// 布尔字段（`reuse`、`completed` 只在为真时才出现），所以每个取值点都必须
// 容忍缺失。这三个助手把这件事集中到一处。
// ---------------------------------------------------------------------------

fn boolAt(v: *const json.Value, path: []const u8) ?bool {
    const p = v.getPath(path) orelse return null;
    return p.asBool();
}

/// 布尔字段缺失按 false 处理。123pan 的响应会省略为假的布尔字段。
fn boolOr(v: *const json.Value, path: []const u8) bool {
    return boolAt(v, path) orelse false;
}

fn arrAt(v: *const json.Value, path: []const u8) []json.Value {
    const p = v.getPath(path) orelse return &.{};
    return p.asArray() orelse &.{};
}

// ---------------------------------------------------------------------------
// 驱动本体
// ---------------------------------------------------------------------------

pub const Open123 = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    /// 串行化「刷新 token」与「读 token」。Go 用 `sync.Mutex`，语义相同。
    token_mu: std.Io.Mutex = .init,
    /// token 的过期时刻（Unix 秒）。0 表示"未知，每次都要刷"。
    expired_at: i64 = 0,
    /// 刷新失败后熔断。对应 Go 的 `tm.blockRefresh`。
    block_refresh: bool = false,
    /// 用户 UID，直链签名要用。懒加载后缓存 —— Go 版存在 `d.UID`。
    uid: u64 = 0,

    /// 上一次落库的 addition，用来避免每次都写盘。
    last_saved: []const u8 = "",

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
        .space = space,
    };

    fn drvName(_: *anyopaque) []const u8 {
        return "123 Open";
    }

    fn as(ptr: *anyopaque) *Open123 {
        return @ptrCast(@alignCast(ptr));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        _ = ctx;

        if (self.cfg.upload_thread < 1 or self.cfg.upload_thread > 32) {
            self.cfg.upload_thread = 3;
        }

        const has_online = self.cfg.use_online_api and
            self.cfg.refresh_token.len > 0 and
            self.cfg.api_url_address.len > 0;
        const has_dev = self.cfg.client_id.len > 0 and self.cfg.client_secret.len > 0;

        if (has_online or has_dev) {
            // 主动刷新路径：把用户填的 token 清掉，强制走一次刷新，
            // 顺便验证密钥确实可用。Go 版同样写 `d.AccessToken = ""`。
            self.cfg.access_token = "";
            self.expired_at = 0;
        } else if (self.cfg.access_token.len > 0) {
            // 个人 token：被动刷新。不去解 JWT（Go 版注释说 exp 不可靠），
            // 直接假定 90 天有效，过期后靠 401 触发一次失败重登。
            self.expired_at = rt.nowSeconds() + personal_token_ttl_s;
        } else {
            log.err("[123open] 需要以下任一组配置：use_online_api+RefreshToken+api_url_address，" ++
                "或 ClientID+ClientSecret，或直接填 AccessToken", .{});
            return Error.NoAuthMethod;
        }

        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        _ = try self.getAccessToken(arena.allocator(), false);
        log.info("[123open] ready: root={s} upload_thread={d}", .{
            self.cfg.root_folder_id, self.cfg.upload_thread,
        });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        // 把可能已刷新的 token 落库。Go 版在 `Drop()` 里做同样的事。
        self.save();
    }

    // -----------------------------------------------------------------------
    // Token
    // -----------------------------------------------------------------------

    fn getAccessToken(self: *Open123, arena: std.mem.Allocator, force: bool) ![]const u8 {
        self.token_mu.lockUncancelable(rt.io());
        defer self.token_mu.unlock(rt.io());

        if (self.block_refresh) return Error.TokenRefreshBlocked;

        if (!force and self.cfg.access_token.len > 0) {
            const now = rt.nowSeconds();
            if (self.expired_at == 0 or now < self.expired_at - token_early_refresh_s) {
                return self.cfg.access_token;
            }
        }

        self.flushAccessToken(arena) catch |e| {
            // 刷新失败就熔断，免得每个请求都去撞一次墙。
            self.block_refresh = true;
            return e;
        };
        return self.cfg.access_token;
    }

    /// 两条互斥的刷新路径，返回字段名和过期时间表示都不同。
    fn flushAccessToken(self: *Open123, arena: std.mem.Allocator) !void {
        if (self.cfg.use_online_api and
            self.cfg.refresh_token.len > 0 and
            self.cfg.api_url_address.len > 0)
        {
            const url = try std.fmt.allocPrint(arena, "{s}?refresh_ui={s}&server_use=true&driver_txt={s}", .{
                self.cfg.api_url_address, self.cfg.refresh_token, "123cloud_oa",
            });
            const res = try self.client.send(arena, .{ .method = "GET", .url = url });
            if (res.status != 200) {
                log.warn("[123open] renewapi HTTP {d}: {s}", .{
                    res.status, res.body[0..@min(res.body.len, 200)],
                });
                return Error.UpstreamHttp;
            }
            const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

            const at = v.strAt("access_token") orelse "";
            const rtok = v.strAt("refresh_token") orelse "";
            if (at.len == 0 or rtok.len == 0) {
                // Go 版依次回退 error_description → text → message → error，
                // 就是为了在这种"200 但体是错误"的响应里捞出一句人话。
                const msg = firstNonEmpty(&.{
                    v.strAt("error_description"),
                    v.strAt("text"),
                    v.strAt("message"),
                    v.strAt("error"),
                });
                log.warn("[123open] renewapi returned no token: {s}", .{msg});
                return Error.UpstreamError;
            }
            const expires_in = v.intAt("expires_in") orelse 0;
            if (expires_in <= 0) {
                // Go 在这里返回 "invalid expires_in from official API"。
                log.warn("[123open] renewapi gave expires_in={d}", .{expires_in});
                return Error.InvalidResponse;
            }

            try self.setTokens(at, rtok);
            self.expired_at = rt.nowSeconds() + expires_in;
            self.block_refresh = false;
            self.save();
            return;
        }

        if (self.cfg.client_id.len > 0 and self.cfg.client_secret.len > 0) {
            var b = Buf.init(arena);
            var w = ObjWriter{ .b = &b };
            try w.begin();
            try w.str("clientID", self.cfg.client_id);
            try w.str("clientSecret", self.cfg.client_secret);
            try w.end();

            const res = try self.client.send(arena, .{
                .method = "POST",
                .url = access_token_url,
                .headers = &.{
                    .{ .name = "platform", .value = "open_platform" },
                    .{ .name = "Content-Type", .value = "application/json" },
                },
                .body = b.slice(),
            });
            if (res.status != 200) return Error.UpstreamHttp;
            const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

            const code = v.intAt("code") orelse 0;
            if (code != 0) {
                log.warn("[123open] access_token failed: code={d} message={s}", .{
                    code, v.strAt("message") orelse "",
                });
                return Error.UpstreamError;
            }
            const at = v.strAt("data.accessToken") orelse "";
            const exp = v.strAt("data.expiredAt") orelse "";
            if (at.len == 0 or exp.len == 0) return Error.InvalidResponse;
            const expired_at = timeutil.parseRfc3339(exp) orelse {
                log.warn("[123open] unparseable expiredAt: {s}", .{exp});
                return Error.InvalidResponse;
            };

            try self.setTokens(at, self.cfg.refresh_token);
            self.expired_at = expired_at;
            self.block_refresh = false;
            self.save();
            return;
        }

        return Error.NoAuthMethod;
    }

    /// 替换 token 并把旧的释放掉 —— 它们是 `self.alloc` 上的长期分配。
    fn setTokens(self: *Open123, at: []const u8, refresh: []const u8) !void {
        const new_at = try self.alloc.dupe(u8, at);
        const new_rt = try self.alloc.dupe(u8, refresh);
        if (self.cfg.access_token.len > 0) self.alloc.free(self.cfg.access_token);
        if (self.cfg.refresh_token.len > 0) self.alloc.free(self.cfg.refresh_token);
        self.cfg.access_token = new_at;
        self.cfg.refresh_token = new_rt;
    }

    fn save(self: *Open123) void {
        if (self.storage_id == 0) return;
        const text = self.cfg.toJson(self.alloc) catch return;
        defer self.alloc.free(text);
        if (text.len == self.last_saved.len and
            std.mem.eql(u8, text, self.last_saved)) return;
        if (self.last_saved.len > 0) self.alloc.free(self.last_saved);
        self.last_saved = self.alloc.dupe(u8, text) catch return;
        driver.persist(self.storage_id, self.last_saved);
    }

    // -----------------------------------------------------------------------
    // HTTP
    // -----------------------------------------------------------------------

    /// 发一次请求并跑完 Go 版的重试循环。
    ///
    /// 返回 **arena 里的 body**。循环语义：
    ///   * `code == 0`  → 成功，返回 body
    ///   * `code == 401` → 强制刷 token 后重来（token 过期）
    ///   * `code == 429` → 退避 500ms 后重来（限速）
    ///   * 其它          → 上抛 `UpstreamError`
    ///
    /// 注意循环**没有次数上限**，与 Go 版一致：退出只可能靠成功或上抛。
    /// 401/429 两条路径最终都会收敛（刷 token 失败会熔断，429 会一直退避），
    /// 所以不会死循环。
    fn request(
        self: *Open123,
        arena: std.mem.Allocator,
        ep: *Api,
        method: []const u8,
        query: []const u8,
        body: ?[]const u8,
    ) ![]const u8 {
        // D01：查询串必须进 URL。以前 GET 的 `?...` 被当成 `body` 发出去，
        // 服务端一个参数都收不到 —— 列目录、查下载地址、拿直链全部拿不到
        // 有效结果。Go 版用的是 resty 的 `SetQueryParams`。
        const url = try joinQuery(arena, ep.url, query);

        while (true) {
            const token = try self.getAccessToken(arena, false);
            const auth = try std.fmt.allocPrint(arena, "Bearer {s}", .{token});

            ep.limiter.acquire();
            const res = try self.client.send(arena, .{
                .method = method,
                .url = url,
                .headers = &.{
                    .{ .name = "authorization", .value = auth },
                    .{ .name = "platform", .value = "open_platform" },
                    .{ .name = "Content-Type", .value = "application/json" },
                },
                .body = body orelse "",
            });

            // D03：Go 版 `Request` **完全不看 HTTP 状态码**，只解 body 里的
            // `code`（drivers/123_open/util.go:69-85）。以前这里 `status != 200`
            // 就直接返回，于是「HTTP 401 + body code 401」这种真实形态永远
            // 走不到刷 token 的分支，429 同理。状态码现在只记日志。
            if (res.status != 200) {
                log.warn("[123open] {s} HTTP {d}: {s}", .{
                    url, res.status, res.body[0..@min(res.body.len, 200)],
                });
            }

            const v = json.parse(arena, res.body) catch {
                log.warn("[123open] {s} non-JSON: {s}", .{
                    url, res.body[0..@min(res.body.len, 200)],
                });
                return Error.UpstreamNotJson;
            };

            const code = v.intAt("code") orelse 0;
            if (code == 0) return res.body;
            if (code == 401) {
                _ = self.getAccessToken(arena, true) catch |e| {
                    log.warn("[123open] forced token refresh failed: {s}", .{@errorName(e)});
                    return e;
                };
                continue;
            }
            if (code == 429) {
                log.warn("[123open] {s} rate limited (429), backing off", .{url});
                rt.sleepMillis(500);
                continue;
            }

            const msg = v.strAt("message") orelse "";
            log.warn("[123open] {s} code={d} message={s}", .{ url, code, msg });
            return Error.UpstreamError;
        }
    }

    fn postJson(self: *Open123, arena: std.mem.Allocator, ep: *Api, body: []const u8) ![]const u8 {
        return self.request(arena, ep, "POST", "", body);
    }

    /// GET，无请求体，只有查询串。
    fn getQuery(self: *Open123, arena: std.mem.Allocator, ep: *Api, query: []const u8) ![]const u8 {
        return self.request(arena, ep, "GET", query, null);
    }

    // -----------------------------------------------------------------------
    // 路径 → ID
    // -----------------------------------------------------------------------

    const Entry = struct {
        id: i64,
        name: []const u8,
        is_dir: bool,
        /// 最后一级的原始 JSON 记录，`details` 直接拿它填字段。
        /// 根目录在 123pan 里没有实体记录，此时为 null。
        /// 指向 arena 里的解析树，不是栈上临时量 —— 见 `findChild` 的索引写法。
        raw: ?*const json.Value = null,
    };

    /// 把路径解析成 123pan 的 `fileId`。
    ///
    /// 根路径（`/`、空串）直接返回 `root_folder_id`。其它路径逐级列目录，
    /// 用**名字**匹配 —— 123pan 没有 by-path 的查询接口，这是唯一办法。
    ///
    /// 代价是每级一次 API 调用。这是本工程 vtable 用路径、而上游 API 用 ID
    /// 的必然结果；Go 版能免掉是因为 OpenList 内核替它缓存了 `model.Obj`。
    fn resolveEntry(self: *Open123, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{
            .id = std.fmt.parseInt(i64, self.cfg.root_folder_id, 10) catch 0,
            .name = "/",
            .is_dir = true,
        };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    /// 在 `parent_id` 下按名字找一个子项，翻页直到命中或翻完。
    fn findChild(self: *Open123, arena: std.mem.Allocator, parent_id: i64, name: []const u8) !Entry {
        var last_id: i64 = 0;
        while (true) {
            const body = try self.listPage(arena, parent_id, page_size, last_id);
            const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
            const children = arrAt(&v, "data.fileList");

            // 用索引而不是 `for (children) |item|`：后者给出的 `item` 是循环
            // 变量的**副本**，`&item` 会指向栈上的临时量，返回出去就是悬垂指针。
            for (children, 0..) |_, i| {
                const item = &children[i];
                const fn_ = item.strAt("filename") orelse continue;
                if (!std.mem.eql(u8, fn_, name)) continue;
                return .{
                    .id = item.intAt("fileId") orelse 0,
                    .name = fn_,
                    .is_dir = (item.intAt("type") orelse 0) == type_dir,
                    .raw = item,
                };
            }
            const next = v.intAt("data.lastFileId") orelse -1;
            if (next == -1 or next == last_id) return driver.Error.NotFound;
            last_id = next;
        }
    }

    fn listPage(self: *Open123, arena: std.mem.Allocator, parent_id: i64, limit: i64, last_id: i64) ![]const u8 {
        // 参数顺序与 Go `util.go:146-155` 的 SetQueryParams 一致。
        const query = try std.fmt.allocPrint(
            arena,
            "parentFileId={d}&limit={d}&lastFileId={d}&trashed=false&searchMode=&searchData=",
            .{ parent_id, limit, last_id },
        );
        return self.getQuery(arena, &endpoints.file_list, query);
    }

    /// 列一个目录的全部条目（翻页直到 `lastFileId == -1`），并过滤掉回收站里的。
    ///
    /// Go 版注释：`trashed` 查询参数在 123pan 侧失效，只能靠遍历过滤。
    fn listAll(self: *Open123, arena: std.mem.Allocator, parent_id: i64) ![]model.Obj {
        var out = List(model.Obj).init(arena);
        var last_id: i64 = 0;
        while (true) {
            const body = try self.listPage(arena, parent_id, page_size, last_id);
            const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
            for (arrAt(&v, "data.fileList")) |item| {
                const trashed = item.intAt("trashed") orelse 0;
                if (trashed != 0) continue;
                try out.append(objFromJson(&item));
            }
            const next = v.intAt("data.lastFileId") orelse -1;
            if (next == -1 or next == last_id) break;
            last_id = next;
        }
        return out.toOwned();
    }

    // -----------------------------------------------------------------------
    // vtable
    // -----------------------------------------------------------------------

    fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(ptr);
        const a = ctx.alloc;
        const entry = try self.resolveEntry(a, dir);
        if (!entry.is_dir) return driver.Error.NotFound;
        return self.listAll(a, entry.id);
    }

    fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(ptr);
        const a = ctx.alloc;

        // 根目录在 123pan 里没有实体记录，手工合成。
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        if (it.next() == null) {
            return .{ .name = "/", .is_dir = true };
        }

        const entry = try self.resolveEntry(a, path);
        // `resolveEntry` 已经把命中的那条原始记录带回来了，不用再查一次。
        const raw = entry.raw orelse return .{ .name = entry.name, .is_dir = entry.is_dir };
        const o = objFromJson(raw);
        return .{
            .name = o.name,
            .size = o.size,
            .is_dir = o.is_dir,
            .modified = o.modified,
            .created = o.created,
        };
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = args;

        const entry = try self.resolveEntry(a, path);

        if (self.cfg.direct_link) {
            const query = try std.fmt.allocPrint(a, "fileID={d}", .{entry.id});
            const body = try self.getQuery(a, &endpoints.direct_link, query);
            const v = json.parse(a, body) catch return Error.UpstreamNotJson;
            const raw = v.strAt("data.url") orelse return Error.InvalidResponse;

            if (self.cfg.direct_link_private_key.len == 0) {
                return .{ .url = raw };
            }

            const uid = try self.getUid(a);
            const duration_min: i64 = if (self.cfg.direct_link_valid_duration > 0)
                self.cfg.direct_link_valid_duration
            else
                30;
            var nonce: [16]u8 = undefined;
            rt.io().random(&nonce);
            return .{
                .url = try signUrl(a, raw, self.cfg.direct_link_private_key, uid, rt.nowSeconds() + duration_min * 60, &nonce),
            };
        }

        const query = try std.fmt.allocPrint(a, "fileId={d}", .{entry.id});
        const body = try self.getQuery(a, &endpoints.download_info, query);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const dl = v.strAt("data.downloadUrl") orelse return Error.InvalidResponse;
        return .{ .url = dl };
    }

    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const parent_path = parentOf(dir);
        const name = lastSegment(dir);
        if (name.len == 0) return Error.InvalidPath;

        const parent = try self.resolveEntry(a, parent_path);
        _ = try self.postJson(a, &endpoints.mkdir, try mkdirBody(a, parent.id, name));
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const s = try self.resolveEntry(a, src);
        const d = try self.resolveEntry(a, dst_dir);

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.key("fileIDs");
        try b.print("[{d}]", .{s.id});
        try w.int("toParentFileID", d.id);
        try w.end();

        _ = try self.postJson(a, &endpoints.move, b.slice());
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        if (new_name.len == 0) return Error.InvalidPath;

        const s = try self.resolveEntry(a, src);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.int("fileId", s.id);
        try w.str("fileName", new_name);
        try w.end();

        // 注意是 PUT，不是 POST —— Go 版 `rename()` 用 http.MethodPut。
        _ = try self.request(a, &endpoints.rename, "PUT", "", b.slice());
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = is_dir; // 123pan 的回收站接口对文件和目录是同一个

        const s = try self.resolveEntry(a, path);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.key("fileIDs");
        try b.print("[{d}]", .{s.id});
        try w.end();

        _ = try self.postJson(a, &endpoints.trash, b.slice());
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(ptr);
        const a = ctx.alloc;
        const body = try self.getQuery(a, &endpoints.user_info, "");
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const permanent = v.intAt("data.spacePermanent") orelse 0;
        const temp = v.intAt("data.spaceTemp") orelse 0;
        const used = v.intAt("data.spaceUsed") orelse 0;
        return .{ .total = permanent + temp, .used = used };
    }

    fn getUid(self: *Open123, arena: std.mem.Allocator) !u64 {
        if (self.uid != 0) return self.uid;
        const body = try self.getQuery(arena, &endpoints.user_info, "");
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const uid = v.intAt("data.uid") orelse return Error.InvalidResponse;
        if (uid <= 0) return Error.InvalidResponse;
        self.uid = @intCast(uid);
        return self.uid;
    }

    // -----------------------------------------------------------------------
    // 上传：SHA1 秒传 → MD5 秒传 → 真上传 → 轮询完成
    // -----------------------------------------------------------------------

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dst);
        if (name.len == 0) return Error.InvalidPath;
        const dst_dir = try self.resolveEntry(a, parentOf(dst));

        const size = src.size();
        if (size < 0) return Error.InvalidPath;

        // 同一遍读里把两个哈希都算出来。Go 版能从上层拿到已算好的哈希，
        // 本工程的 `model.Source` 没有哈希，所以这里是必做的一步。
        const hashes = try hashSource(a, src);
        const sha1_hex = try hash.hexLower(a, &hashes.sha1);
        const md5_hex = try hash.hexLower(a, &hashes.md5);

        // 1. SHA1 秒传
        {
            var b = Buf.init(a);
            var w = ObjWriter{ .b = &b };
            try w.begin();
            try w.int("parentFileID", dst_dir.id);
            try w.str("filename", name);
            try w.str("sha1", sha1_hex);
            try w.int("size", size);
            try w.int("duplicate", duplicate_keep_both);
            try w.end();

            // Go 版对失败是宽容的：`if err == nil && resp.Data.Reuse`，
            // 即接口挂了或没命中都继续往下走。
            if (self.postJson(a, &endpoints.upload_sha1_reuse, b.slice())) |body| {
                const v = json.parse(a, body) catch null;
                if (v) |vv| {
                    if (boolOr(&vv, "data.reuse")) {
                        log.info("[123open] {s}: sha1 instant-upload hit", .{name});
                        return;
                    }
                }
            } else |e| {
                log.warn("[123open] sha1_reuse failed, falling through: {s}", .{@errorName(e)});
            }
        }

        // 2. create（带 MD5）
        const created = try self.create(a, dst_dir.id, name, md5_hex, size);
        if (created.reuse and created.file_id != 0) {
            log.info("[123open] {s}: md5 instant-upload hit", .{name});
            return;
        }

        // 3. 真上传
        try self.uploadSlices(a, src, name, size, created);

        // 4. 轮询完成
        for (0..complete_poll_max) |_| {
            const done = try self.complete(a, created.preupload_id);
            if (done.completed and done.file_id != 0) return;
            rt.sleepMillis(complete_poll_interval_ms);
        }
        return Error.UploadTimeout;
    }

    const CreateResult = struct {
        file_id: i64,
        preupload_id: []const u8,
        reuse: bool,
        slice_size: i64,
        server: []const u8,
    };

    fn create(
        self: *Open123,
        arena: std.mem.Allocator,
        parent_id: i64,
        filename: []const u8,
        etag: []const u8,
        size: i64,
    ) !CreateResult {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.int("parentFileId", parent_id);
        try w.str("filename", filename);
        // Go 用 strings.ToLower(etag)；我们传进来的已经小写，但保持显式。
        try w.str("etag", etag);
        try w.int("size", size);
        try w.int("duplicate", duplicate_keep_both);
        try w.boolean("containDir", false);
        try w.end();

        const body = try self.postJson(arena, &endpoints.upload_create, b.slice());
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;

        const servers = arrAt(&v, "data.servers");
        const server = if (servers.len > 0) (servers[0].asStr() orelse "") else "";
        return .{
            .file_id = v.intAt("data.fileID") orelse 0,
            .preupload_id = v.strAt("data.preuploadID") orelse "",
            .reuse = boolOr(&v, "data.reuse"),
            .slice_size = v.intAt("data.sliceSize") orelse 0,
            .server = server,
        };
    }

    fn uploadSlices(
        self: *Open123,
        arena: std.mem.Allocator,
        src: model.Source,
        filename: []const u8,
        size: i64,
        created: CreateResult,
    ) !void {
        if (created.slice_size <= 0 or created.slice_size > max_slice_bytes) {
            log.warn("[123open] server asked for sliceSize={d}", .{created.slice_size});
            return Error.BadSliceSize;
        }
        if (created.server.len == 0) return Error.InvalidResponse;

        const chunk: u64 = @intCast(created.slice_size);
        const total: u64 = @intCast(size);
        const num_slices = (total + chunk - 1) / chunk;
        const slice_url = try std.fmt.allocPrint(arena, "{s}/upload/v2/file/slice", .{created.server});

        // 串行而不是并发 —— 见文件头的说明。
        // T7：整份上传复用同一个分片缓冲（旧代码每片 readAll 新分配，
        // arena 随文件大小线性增长）。
        const chunk_buf = try arena.alloc(u8, @intCast(chunk));
        var i: u64 = 0;
        while (i < num_slices) : (i += 1) {
            const offset = i * chunk;
            const len: usize = @intCast(@min(chunk, total - offset));
            const part_number = i + 1;

            const data = chunk_buf[0..len];
            try src.readAllInto(offset, data);
            const slice_md5 = try hash.md5Hex(arena, data);

            const form = try buildSliceForm(arena, created.preupload_id, part_number, slice_md5, filename, data);

            const token = try self.getAccessToken(arena, false);
            const auth = try std.fmt.allocPrint(arena, "Bearer {s}", .{token});

            endpoints.upload_complete.limiter.acquire();
            const res = try self.client.send(arena, .{
                .method = "POST",
                .url = slice_url,
                .headers = &.{
                    .{ .name = "Authorization", .value = auth },
                    .{ .name = "Content-Type", .value = form.content_type },
                    .{ .name = "Platform", .value = "open_platform" },
                },
                .body = form.body,
            });
            if (res.status != 200) {
                log.warn("[123open] slice {d}/{d} HTTP {d}", .{ part_number, num_slices, res.status });
                return Error.UpstreamHttp;
            }
            const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
            const code = v.intAt("code") orelse 0;
            if (code != 0) {
                log.warn("[123open] slice {d}/{d} failed: code={d} {s}", .{
                    part_number, num_slices, code, v.strAt("message") orelse "",
                });
                return Error.UpstreamError;
            }
        }
    }

    const CompleteResult = struct { completed: bool, file_id: i64 };

    fn complete(self: *Open123, arena: std.mem.Allocator, preupload_id: []const u8) !CompleteResult {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("preuploadID", preupload_id);
        try w.end();

        const body = try self.postJson(arena, &endpoints.upload_complete, b.slice());
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return .{
            .completed = boolOr(&v, "data.completed"),
            .file_id = v.intAt("data.fileID") orelse 0,
        };
    }
};

// ---------------------------------------------------------------------------
// 纯函数（都被单元测试覆盖）
// ---------------------------------------------------------------------------

fn firstNonEmpty(cands: []const ?[]const u8) []const u8 {
    for (cands) |c| {
        if (c) |s| if (s.len > 0) return s;
    }
    return "";
}

fn lastSegment(path: []const u8) []const u8 {
    var last: []const u8 = "";
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |seg| last = seg;
    return last;
}

/// 去掉最后一段，保留前导 `/`。`/a/b/c` → `/a/b`，`/a` → `/`，`/` → `/`。
fn parentOf(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/\\");
    if (trimmed.len == 0) return "/";
    const idx = std.mem.lastIndexOfAny(u8, trimmed, "/\\") orelse return "/";
    if (idx == 0) return "/";
    return trimmed[0..idx];
}

fn objFromJson(item: *const json.Value) model.Obj {
    const name = item.strAt("filename") orelse "";
    const type_ = item.intAt("type") orelse 0;
    const size = item.intAt("size") orelse 0;
    return .{
        .name = name,
        .size = size,
        .is_dir = type_ == type_dir,
        .modified = timeutil.parseCnTime(item.strAt("updateAt") orelse "") orelse 0,
        .created = timeutil.parseCnTime(item.strAt("createAt") orelse "") orelse 0,
    };
}

/// 123pan 的直链签名。
///
///   unsigned = path + "-" + ts + "-" + rand + "-" + uid + "-" + privateKey
///   auth_key = ts + "-" + rand + "-" + uid + "-" + md5hex(unsigned)
///
/// `ts` 是**过期时刻**（`now + validDuration`），不是签发时刻。
///
/// Go 版用 `uuid.New()` 去掉中划线当 `rand`；这里用 16 字节随机数的 hex，
/// 长度和字符集一致（32 个 `[0-9a-f]`）。`rand` 只要求"不能包含中划线"，
/// 不需要是合法 UUID，所以这不是降级。
///
/// 拼查询串时直接追加而不是像 Go 那样 `v.Encode()` 重编码整个 query：
/// `auth_key` 只含 `[0-9a-f-]`，不需要转义；重编码反而可能改动服务端原本
/// 给出的其它参数。两种做法在这组输入上等价。
fn signUrl(
    alloc: std.mem.Allocator,
    origin_url: []const u8,
    private_key: []const u8,
    uid: u64,
    ts: i64,
    nonce: *const [16]u8,
) ![]u8 {
    const q = std.mem.indexOfScalar(u8, origin_url, '?');
    const path_end = std.mem.indexOfScalarPos(u8, origin_url, 0, '#') orelse origin_url.len;
    const path = blk: {
        // 取 scheme://host 之后的路径部分。Go 用 url.Parse 再取 objURL.Path。
        const scheme_end = std.mem.indexOf(u8, origin_url, "://") orelse 0;
        const host_start = if (scheme_end == 0) 0 else scheme_end + 3;
        const slash = std.mem.indexOfScalarPos(u8, origin_url, host_start, '/') orelse path_end;
        break :blk origin_url[slash..@min(if (q) |qq| qq else path_end, path_end)];
    };

    const rand_hex = try hash.hexLower(alloc, nonce);
    defer alloc.free(rand_hex);

    const unsigned = try std.fmt.allocPrint(alloc, "{s}-{d}-{s}-{d}-{s}", .{
        path, ts, rand_hex, uid, private_key,
    });
    defer alloc.free(unsigned);

    const digest = try hash.md5Hex(alloc, unsigned);
    defer alloc.free(digest);

    const auth_key = try std.fmt.allocPrint(alloc, "{d}-{s}-{d}-{s}", .{ ts, rand_hex, uid, digest });
    defer alloc.free(auth_key);

    const sep: []const u8 = if (q != null) "&" else "?";
    return std.fmt.allocPrint(alloc, "{s}{s}auth_key={s}", .{ origin_url, sep, auth_key });
}

/// 分片上传的 multipart 表单。
///
/// 手写而不是找个库：本工程连 multipart 都没有（WebDAV 上传是裸 body），
/// 为一次上传拉一个解析器不划算，而且这里的形状是固定的四个字段。
/// 边界值与 Go 的 `multipart.Writer` 同形（60 个 `-` + 24 位十六进制），
/// 服务端只把它当不透明分隔符，具体取值不影响正确性。
const SliceForm = struct {
    content_type: []const u8,
    body: []const u8,
};

fn buildSliceForm(
    alloc: std.mem.Allocator,
    preupload_id: []const u8,
    part_number: u64,
    slice_md5: []const u8,
    filename: []const u8,
    data: []const u8,
) !SliceForm {
    // Go 的 `mime/multipart.randomBoundary()` 是 30 个随机字节的十六进制，
    // 即 60 个小写 hex 字符；分隔符再前缀 `--`。这里保持同形。
    var seed: [30]u8 = undefined;
    rt.io().random(&seed);
    // `bytesToHex` 返回的是值数组 `[60]u8`，需要 `&boundary` 才当成切片用。
    const boundary = std.fmt.bytesToHex(seed, .lower);

    var b = Buf.init(alloc);

    try writeField(&b, &boundary, "preuploadID", preupload_id);
    try writeField(&b, &boundary, "sliceNo", try std.fmt.allocPrint(alloc, "{d}", .{part_number}));
    try writeField(&b, &boundary, "sliceMD5", slice_md5);

    // 文件字段：Go 的 `w.CreateFormFile("slice", name+".partN")`，
    // 它会写出 Content-Type: application/octet-stream。
    try b.print("--{s}\r\n", .{boundary});
    try b.print(
        "Content-Disposition: form-data; name=\"slice\"; filename=\"{s}.part{d}\"\r\n",
        .{ filename, part_number },
    );
    try b.append("Content-Type: application/octet-stream\r\n\r\n");
    try b.append(data);
    try b.append("\r\n");
    try b.print("--{s}--\r\n", .{boundary});

    return .{
        .content_type = try std.fmt.allocPrint(alloc, "multipart/form-data; boundary={s}", .{boundary}),
        .body = b.slice(),
    };
}

fn writeField(b: *Buf, boundary: []const u8, name: []const u8, value: []const u8) !void {
    try b.print("--{s}\r\n", .{boundary});
    try b.print("Content-Disposition: form-data; name=\"{s}\"\r\n\r\n", .{name});
    try b.append(value);
    try b.append("\r\n");
}

/// 一遍读里把 SHA1 和 MD5 都算出来。
fn hashSource(arena: std.mem.Allocator, src: model.Source) !struct { sha1: [20]u8, md5: [16]u8 } {
    var sha = hash.Sha1Stream{};
    var md5s = hash.Md5Stream{};

    const size = src.size();
    if (size < 0) return error.UnexpectedEof;

    const buf = try arena.alloc(u8, hash_block);
    var offset: u64 = 0;
    const total: u64 = @intCast(size);
    while (offset < total) {
        const want: usize = @intCast(@min(@as(u64, hash_block), total - offset));
        const n = try src.readAt(offset, buf[0..want]);
        if (n == 0) return error.UnexpectedEof;
        sha.update(buf[0..n]);
        md5s.update(buf[0..n]);
        offset += n;
    }
    return .{ .sha1 = sha.final(), .md5 = md5s.final() };
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "123 Open",
    .label = "123 云盘开放平台",
    .secrets = &.{
        "ClientSecret", "AccessToken", "RefreshToken", "DirectLinkPrivateKey",
    },
    // 字段名与 Go 版 `Addition` 的 json tag 逐字一致。
    .addition_schema =
    \\{
    \\  "ClientID":                 {"type":"string","required":false,"help":"开发者 ClientID，从 123pan.com/developer 申请"},
    \\  "ClientSecret":             {"type":"string","required":false,"secret":true,"help":"开发者 ClientSecret"},
    \\  "AccessToken":              {"type":"string","required":false,"secret":true,"help":"个人 AccessToken，有过期时间，不建议直填"},
    \\  "RefreshToken":             {"type":"string","required":false,"secret":true,"help":"在线 API 方式的 refresh_token"},
    \\  "use_online_api":           {"type":"bool","default":true,"help":"用第三方 renewapi 续期；关掉则走开发者密钥或直填 token"},
    \\  "api_url_address":          {"type":"string","default":"https://api.oplist.org/123cloud/renewapi","help":"renewapi 地址"},
    \\  "UploadThread":             {"type":"number","default":3,"min":1,"max":32,"help":"上传并发上限（本实现串行上传，该值用于限速）"},
    \\  "DirectLink":               {"type":"bool","default":false,"help":"下载走直链接口而非临时下载地址"},
    \\  "DirectLinkPrivateKey":    {"type":"string","required":false,"secret":true,"help":"直链开启了 URL 鉴权时填私钥"},
    \\  "DirectLinkValidDuration": {"type":"number","default":30,"help":"直链有效期（分钟）"},
    \\  "root_folder_id":           {"type":"string","default":"0","help":"根目录 ID，123pan 的根是 0"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(Open123, self);
}

/// 带 storage id 的入口，供 API 层在配置变化时回写 `addition`。
pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Open123 {
    const self = try alloc.create(Open123);
    const jar = try alloc.create(cookiejar.Jar);
    jar.* = cookiejar.Jar.init(alloc);

    const addition = try Addition.parse(alloc, cfg);
    self.* = .{
        .alloc = alloc,
        .storage_id = storage_id,
        .cfg = addition,
        .jar = jar,
        .client = httpclient.Client.init(alloc, .{}, jar),
    };
    return self;
}

// ---------------------------------------------------------------------------
// 测试 —— 全部是纯逻辑，不打网络
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "addition round-trips through JSON with the Go field names" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const text =
        \\{"ClientID":"cid","ClientSecret":"sec","AccessToken":"at","RefreshToken":"rt",
        \\ "use_online_api":false,"api_url_address":"https://x/y","UploadThread":7,
        \\ "DirectLink":true,"DirectLinkPrivateKey":"pk","DirectLinkValidDuration":15,
        \\ "root_folder_id":"42"}
    ;
    const v = try json.parse(a, text);
    const parsed = try Addition.parse(a, &v);

    try testing.expectEqualStrings("cid", parsed.client_id);
    try testing.expectEqualStrings("sec", parsed.client_secret);
    try testing.expectEqualStrings("at", parsed.access_token);
    try testing.expectEqualStrings("rt", parsed.refresh_token);
    try testing.expect(!parsed.use_online_api);
    try testing.expectEqualStrings("https://x/y", parsed.api_url_address);
    try testing.expectEqual(@as(i64, 7), parsed.upload_thread);
    try testing.expect(parsed.direct_link);
    try testing.expectEqualStrings("pk", parsed.direct_link_private_key);
    try testing.expectEqual(@as(i64, 15), parsed.direct_link_valid_duration);
    try testing.expectEqualStrings("42", parsed.root_folder_id);

    // 再序列化回去，键名必须还是 Go 认的那套。
    const out = try parsed.toJson(a);
    for ([_][]const u8{
        "\"ClientID\"",       "\"ClientSecret\"",           "\"AccessToken\"",
        "\"RefreshToken\"",   "\"use_online_api\"",         "\"api_url_address\"",
        "\"UploadThread\"",   "\"DirectLink\"",             "\"DirectLinkPrivateKey\"",
        "\"DirectLinkValidDuration\"", "\"root_folder_id\"",
    }) |key| {
        try testing.expect(std.mem.indexOf(u8, out, key) != null);
    }

    // 往返一次应当稳定。
    const v2 = try json.parse(a, out);
    const again = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(parsed.root_folder_id, again.root_folder_id);
    try testing.expectEqual(parsed.upload_thread, again.upload_thread);
    try testing.expectEqual(parsed.use_online_api, again.use_online_api);
}

test "addition tolerates a missing or empty object" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const none = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", none.root_folder_id);
    try testing.expectEqualStrings(default_api_address, none.api_url_address);
    try testing.expect(none.use_online_api);
    try testing.expectEqual(@as(i64, 3), none.upload_thread);

    const empty = try json.parse(a, "{}");
    const e = try Addition.parse(a, &empty);
    try testing.expectEqualStrings("0", e.root_folder_id);
}

test "CN time parsing comes from util/time.zig" {
    // 123pan 的 createAt/updateAt 是「无时区、按 UTC+8 解释」的形状。
    // 解析器已经搬去 `util/time.zig`（天翼云盘的 lastOpTime 是同一个形状），
    // 这里只钉住**接线是对的** —— 驱动的行为不因为搬家而变。
    // 2026-10-10 12:00:00 UTC+8 == 2026-10-10 04:00:00 UTC == 1791604800
    const t = timeutil.parseCnTime("2026-10-10 12:00:00");
    try testing.expectEqual(@as(i64, 1_791_604_800), t.?);
    // 同一时刻用 UTC 表示，两者必须相等 —— 这正是"硬编码 UTC+8"的意义。
    try testing.expectEqual(t.?, timeutil.parseRfc3339("2026-10-10T04:00:00Z").?);
    // 纪元
    try testing.expectEqual(@as(i64, -8 * 3600), timeutil.parseCnTime("1970-01-01 00:00:00").?);
    // 垃圾输入
    try testing.expect(timeutil.parseCnTime("") == null);
    try testing.expect(timeutil.parseCnTime("2026-10-10") == null);
}

test "RFC3339 parsing comes from util/time.zig" {
    // 123pan 的开发者 API 用 `data.expiredAt`（RFC3339）表示过期时刻。
    // 解析器已经搬去 `util/time.zig`（阿里云盘要同一份），这里只钉住
    // **接线是对的** —— 驱动的行为不因为搬家而变。
    const base = timeutil.parseRfc3339("2026-10-10T04:00:00Z").?;
    try testing.expectEqual(@as(i64, 1_791_604_800), base);
    try testing.expectEqual(base, timeutil.parseRfc3339("2026-10-10T12:00:00+08:00").?);
    try testing.expectEqual(base, timeutil.parseRfc3339("2026-10-09T23:00:00-05:00").?);
    try testing.expectEqual(base, timeutil.parseRfc3339("2026-10-10T04:00:00.123456Z").?);
    // 缺时区不猜。
    try testing.expect(timeutil.parseRfc3339("2026-10-10T04:00:00") == null);
    try testing.expect(timeutil.parseRfc3339("") == null);
}

test "path helpers" {
    try testing.expectEqualStrings("c", lastSegment("/a/b/c"));
    try testing.expectEqualStrings("c", lastSegment("a/b/c"));
    try testing.expectEqualStrings("c", lastSegment("/a/b/c/"));
    try testing.expectEqualStrings("a", lastSegment("/a"));
    try testing.expectEqualStrings("", lastSegment("/"));
    try testing.expectEqualStrings("", lastSegment(""));

    try testing.expectEqualStrings("/a/b", parentOf("/a/b/c"));
    try testing.expectEqualStrings("/", parentOf("/a"));
    try testing.expectEqualStrings("/", parentOf("/"));
    try testing.expectEqualStrings("/", parentOf(""));
    try testing.expectEqualStrings("/a", parentOf("/a/b/"));
    // 顶层文件名的父目录是根
    try testing.expectEqualStrings("/", parentOf("/top.txt"));
}

test "signUrl matches the upstream algorithm" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 固定 nonce 与 ts，让结果可复现。
    // nonce 全 0x00 → rand_hex = "00000000000000000000000000000000"
    const nonce: [16]u8 = @splat(0);    const ts: i64 = 1_800_000_000;
    const url = "https://cdn.123pan.com/path/to/file.bin";

    const signed = try signUrl(a, url, "SECRET", 42, ts, &nonce);

    // 手工算一遍，验证字符串拼接与 md5 的输入形状：
    //   unsigned = "/path/to/file.bin-1800000000-<rand>-42-SECRET"
    const rand_hex = "00000000000000000000000000000000";
    const unsigned = try std.fmt.allocPrint(a, "/path/to/file.bin-{d}-{s}-42-SECRET", .{ ts, rand_hex });
    const digest = try hash.md5Hex(a, unsigned);
    const expected = try std.fmt.allocPrint(a, "{s}?auth_key={d}-{s}-42-{s}", .{ url, ts, rand_hex, digest });
    try testing.expectEqualStrings(expected, signed);

    // 已有 query 时用 & 连接，且不重写原参数。
    const with_q = try signUrl(a, "https://cdn.123pan.com/f?x=1", "K", 7, ts, &nonce);
    try testing.expect(std.mem.startsWith(u8, with_q, "https://cdn.123pan.com/f?x=1&auth_key="));

    // path 里不含 host，也不含 query。
    try testing.expect(std.mem.indexOf(u8, signed, "cdn.123pan.com-") == null);
}

test "rate limiter computes a minimum interval" {
    try testing.expectEqual(@as(i64, 0), RateLimiter.minIntervalMs(0));
    try testing.expectEqual(@as(i64, 1000), RateLimiter.minIntervalMs(1));
    // 向上取整：qps=3 时 1000/3 = 333.33 → 334。取 333 会略微超速。
    try testing.expectEqual(@as(i64, 334), RateLimiter.minIntervalMs(3));
    try testing.expectEqual(@as(i64, 200), RateLimiter.minIntervalMs(5));
    // qps=7 → 1000/7 = 142.86 → 143
    try testing.expectEqual(@as(i64, 143), RateLimiter.minIntervalMs(7));
    try testing.expectEqual(@as(i64, 1000), RateLimiter.minIntervalMs(1));

    // 第一次请求不等待
    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(0, 1_000_000, 3));
    // 紧接着的第二次要等满一个间隔
    try testing.expectEqual(@as(i64, 334), RateLimiter.waitMs(1_000_000, 1_000_000, 3));
    try testing.expectEqual(@as(i64, 234), RateLimiter.waitMs(1_000_000, 1_000_100, 3));
    // 已经等够了
    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(1_000_000, 1_000_400, 3));
    // qps=0 表示不限速
    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(1_000_000, 1_000_000, 0));
}

test "objFromJson maps 123pan file records" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const dir = try json.parse(a,
        \\{"filename":"docs","size":0,"type":1,"fileId":11,
        \\ "createAt":"2026-10-10 12:00:00","updateAt":"2026-10-10 13:00:00","trashed":0}
    );
    const d = objFromJson(&dir);
    try testing.expectEqualStrings("docs", d.name);
    try testing.expect(d.is_dir);
    try testing.expectEqual(@as(i64, 1_791_608_400), d.modified); // 13:00 UTC+8

    const file = try json.parse(a,
        \\{"filename":"a.bin","size":4096,"type":2,"fileId":12,"etag":"abc",
        \\ "updateAt":"2026-10-10 13:00:00"}
    );
    const f = objFromJson(&file);
    try testing.expect(!f.is_dir);
    try testing.expectEqual(@as(i64, 4096), f.size);

    // 缺字段不能 panic，时间解析失败退化为 0
    const bare = try json.parse(a, "{}");
    const b = objFromJson(&bare);
    try testing.expectEqualStrings("", b.name);
    try testing.expectEqual(@as(i64, 0), b.modified);
}

test "buildSliceForm emits the four fields Go's multipart writer emits" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const form = try buildSliceForm(a, "PRE-1", 3, "d41d8cd98f00b204e9800998ecf8427e", "a.bin", "HELLO");

    try testing.expect(std.mem.startsWith(u8, form.content_type, "multipart/form-data; boundary="));
    const boundary = form.content_type["multipart/form-data; boundary=".len..];

    // 三个普通字段
    for ([_][2][]const u8{
        .{ "preuploadID", "PRE-1" },
        .{ "sliceNo", "3" },
        .{ "sliceMD5", "d41d8cd98f00b204e9800998ecf8427e" },
    }) |kv| {
        const needle = try std.fmt.allocPrint(
            a,
            "--{s}\r\nContent-Disposition: form-data; name=\"{s}\"\r\n\r\n{s}\r\n",
            .{ boundary, kv[0], kv[1] },
        );
        try testing.expect(std.mem.indexOf(u8, form.body, needle) != null);
    }

    // 文件字段：名字是 <filename>.part<sliceNo>
    const file_header = try std.fmt.allocPrint(
        a,
        "--{s}\r\nContent-Disposition: form-data; name=\"slice\"; filename=\"a.bin.part3\"\r\n" ++
            "Content-Type: application/octet-stream\r\n\r\nHELLO\r\n",
        .{boundary},
    );
    try testing.expect(std.mem.indexOf(u8, form.body, file_header) != null);

    // 收尾边界
    const closing = try std.fmt.allocPrint(a, "--{s}--\r\n", .{boundary});
    try testing.expect(std.mem.endsWith(u8, form.body, closing));

    // 字段顺序与 Go 的 WriteField 调用顺序一致
    const i_pre = std.mem.indexOf(u8, form.body, "name=\"preuploadID\"").?;
    const i_no = std.mem.indexOf(u8, form.body, "name=\"sliceNo\"").?;
    const i_md5 = std.mem.indexOf(u8, form.body, "name=\"sliceMD5\"").?;
    const i_slice = std.mem.indexOf(u8, form.body, "name=\"slice\"").?;
    try testing.expect(i_pre < i_no and i_no < i_md5 and i_md5 < i_slice);
}

test "buildSliceForm boundary is 60 dashes plus 24 hex digits" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const form = try buildSliceForm(a, "p", 1, "m", "f", "d");
    const boundary = form.content_type["multipart/form-data; boundary=".len..];
    // Go 的 randomBoundary() 形状：60 个小写十六进制字符，没有前缀横线。
    try testing.expectEqual(@as(usize, 60), boundary.len);
    for (boundary) |c| try testing.expect(std.ascii.isHex(c));

    // 两次调用必须给出不同的边界，否则嵌套/重放的表单会互相截断。
    const form2 = try buildSliceForm(a, "p", 1, "m", "f", "d");
    const boundary2 = form2.content_type["multipart/form-data; boundary=".len..];
    try testing.expect(!std.mem.eql(u8, boundary, boundary2));
}

test "firstNonEmpty picks the first usable message" {
    try testing.expectEqualStrings("b", firstNonEmpty(&.{ null, "", "b", "c" }));
    try testing.expectEqualStrings("a", firstNonEmpty(&.{ "a", "b" }));
    try testing.expectEqualStrings("", firstNonEmpty(&.{ null, "" }));
    try testing.expectEqualStrings("", firstNonEmpty(&.{}));
}

test "hashSource computes both digests in one pass" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const payload = "The quick brown fox jumps over the lazy dog";

    const Fake = struct {
        data: []const u8,
        /// 每次最多吐这么多字节，逼 `hashSource` 走多轮循环。
        step: usize,
        fn size(ptr: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return @intCast(self.data.len);
        }
        fn readAt(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const off: usize = @intCast(offset);
            if (off >= self.data.len) return 0;
            const n = @min(@min(buf.len, self.step), self.data.len - off);
            @memcpy(buf[0..n], self.data[off .. off + n]);
            return n;
        }
    };

    var fake = Fake{ .data = payload, .step = 7 };
    const src = model.Source{ .ptr = &fake, .vtable = &.{ .size = Fake.size, .readAt = Fake.readAt } };

    const got = try hashSource(a, src);
    try testing.expectEqualStrings(
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        try hash.hexLower(a, &got.sha1),
    );
    try testing.expectEqualStrings(
        "9e107d9d372bb6826bd81d3542a419d6",
        try hash.hexLower(a, &got.md5),
    );

    // 空文件也要能算（两个哈希的"空串"值）
    var empty = Fake{ .data = "", .step = 7 };
    const esrc = model.Source{ .ptr = &empty, .vtable = &.{ .size = Fake.size, .readAt = Fake.readAt } };
    const e = try hashSource(a, esrc);
    try testing.expectEqualStrings(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        try hash.hexLower(a, &e.sha1),
    );
}

test "createWithId builds a driver with the expected name" {
    const a = testing.allocator;
    var arena = testArena();
    defer arena.deinit();

    const cfg = try json.parse(arena.allocator(),
        \\{"ClientID":"x","ClientSecret":"y","root_folder_id":"5"}
    );
    const d = try createWithId(a, 99, &cfg);

    // defer 是 LIFO：**先声明后执行**，所以这里的书写顺序是清理顺序的倒序。
    // 想按「client → jar → cfg → 释放内存」的顺序清理，就得倒着写。
    // 写反的后果不是泄漏而是崩溃：`a.destroy(d)` 会把 `d` 的内存涂成 0xAA，
    // 之后再碰 `d.client` 就会踩到 `std.http.Client` 里
    // "There are still active requests" 那个断言。
    defer a.destroy(d);
    defer a.destroy(d.jar);
    // `Addition.parse` 对每个字段都做了一次 dupe（包括用默认值的那些），
    // 所以七个字段全部要还回去，漏一个 `testing.allocator` 就会报泄漏。
    defer {
        a.free(d.cfg.client_id);
        a.free(d.cfg.client_secret);
        a.free(d.cfg.access_token);
        a.free(d.cfg.refresh_token);
        a.free(d.cfg.api_url_address);
        a.free(d.cfg.direct_link_private_key);
        a.free(d.cfg.root_folder_id);
    }
    defer d.jar.deinit();
    defer d.client.deinit();

    const drv = driver.asDriver(Open123, d);
    try testing.expectEqualStrings("123 Open", drv.name());
    try testing.expectEqualStrings("5", d.cfg.root_folder_id);
    try testing.expectEqual(@as(i64, 99), d.storage_id);
}

/// D01 的回归点：查询串必须拼进 URL。
fn joinQuery(alloc: std.mem.Allocator, base: []const u8, query: []const u8) ![]const u8 {
    if (query.len == 0) return base;
    return std.fmt.allocPrint(alloc, "{s}?{s}", .{ base, query });
}

/// `{"parentID":"<id>","name":"<name>"}`。
/// D03：Go 写的是**字符串**（drivers/123_open/util.go:196-199 的
/// `strconv.FormatInt(parentID, 10)`），不是数字。
fn mkdirBody(a: std.mem.Allocator, parent_id: i64, name: []const u8) ![]const u8 {
    var b = Buf.init(a);
    var w = ObjWriter{ .b = &b };
    try w.begin();
    try w.str("parentID", try std.fmt.allocPrint(a, "{d}", .{parent_id}));
    try w.str("name", name);
    try w.end();
    return b.slice();
}

test "joinQuery puts the query in the URL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 无查询串时保持端点原样，不加裸 `?`。
    try testing.expectEqualStrings("https://x/api", try joinQuery(a, "https://x/api", ""));
    // 有查询串时拼成 `?query`（D01 之前是把它当 body 发出去的）。
    try testing.expectEqualStrings(
        "https://x/api?fileId=7",
        try joinQuery(a, "https://x/api", "fileId=7"),
    );
}

test "mkdir body writes parentID as a string" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const body = try mkdirBody(a, 12345, "新目录");
    // parentID 必须是带引号的字符串；写成数字服务端契约不符。
    try testing.expect(std.mem.indexOf(u8, body, "\"parentID\":\"12345\"") != null);
    try testing.expect(std.mem.indexOf(u8, body, "\"parentID\":12345") == null);
    try testing.expect(std.mem.indexOf(u8, body, "新目录") != null);
}
