//! 阿里云盘开放平台驱动 —— Go 版 `drivers/aliyundrive_open` 的 Zig 移植。
//!
//! 九个目标驱动里，这个是**认证最绕**的一个。三处和别家都不一样：
//!
//!   1. **两条互斥的续期通道**。在线通道（`use_online_api`，走第三方
//!      renewapi）一个 GET 就换回新 token；本地通道要走官方
//!      `/oauth/access_token`，而且换回来的 refresh_token 必须和旧的是
//!      **同一个账号** —— 上游为此把 JWT 的 payload 解出来比 `sub`。少了这
//!      一步，一个配错的 client_id 会让驱动器悄悄挂到别人账号上。
//!   2. **两阶段秒传**。第一轮 create 只带 `pre_hash`（前 1024 字节的 SHA1）。
//!      服务端认得这个文件就回一个 `PreHashMatched` **错误码**（不是 200），
//!      于是第二轮改带整文件 SHA1 + `proof_code` 重发。`proof_code` 的取值
//!      位置由 **access_token 的 MD5** 决定 —— 注意和夸克不同，夸克用的是
//!      服务端下发的 `proof_seed`，这里没有 seed，种子就是自己的 token。
//!   3. **`drive_id` 是运行时查出来的**，不是配置项。`getDriveInfo` 一次返回
//!      `default_drive_id` / `resource_drive_id` / `backup_drive_id` 三个，
//!      选哪个由 `drive_type` 决定。所以 `init` 必须先打一次网络。
//!
//! 与 Go 版的差异（都是有意为之，不是遗漏）：
//!
//!   * **分片上传串行**。上游没有并发上传（它逐片 `for` 循环），所以这里天然
//!     一致；真正被砍掉的是 `CallbackConcurrency` 那道 per-user 并发闸门 ——
//!     它管的是**服务端代理下载**的并发数，而本工程的代理下载在 API 层做
//!     （见 `api.zig` 的 `handleDownload`），驱动没有插手的位置。配置项保留
//!     并原样回写，只是不起作用。
//!   * **`local_modified_at` / `local_created_at` 用上传时刻**。上游读的是
//!     `stream.ModTime()` / `stream.CreateTime()`，本工程的 `model.Source`
//!     只有 `size` / `readAt`，没有时间戳；HTTP PUT 本身也不带可信的 mtime。
//!   * **`copy` 不提供**。vtable 里没有这个槽位。
//!   * **`removeDuplicateFiles` 不移植**。上游靠 `op.List` 列父目录再逐个删
//!     同名项 —— 那依赖 OpenList 内核的目录缓存层，本工程没有。副作用是
//!     `check_name_mode: "ignore"` 留下的重名项不会被自动清理。
//!   * **限速器是每驱动一份**。上游按「用户 + 应用」全局共享（`user_id` 做
//!     key），本工程每个 storage 一个驱动实例。同一账号挂两个 storage 时，
//!     合起来会略微超过官方限速。见 `RateLimiter` 的注释。

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
// 常量
// ---------------------------------------------------------------------------

const api_base = "https://openapi.alipan.com";

/// 第三方续期服务。上游把它写成 `api_url_address` 的默认值。
const default_api_address = "https://api.oplist.org/alicloud/renewapi";

/// 上游用 `base.RestyClient`，它的 UA 是 OpenList 统一的那个。
/// 阿里云盘的网关会看 UA，别改成自己的。
const user_agent = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";

const default_root = "root";

/// 列表接口的 `limit`。上游写死 200，然后靠 `next_marker` 翻页。
const page_size: i64 = 200;

const path_drive_info = "/adrive/v1.0/user/getDriveInfo";
const path_space_info = "/adrive/v1.0/user/getSpaceInfo";
const path_file_list = "/adrive/v1.0/openFile/list";
const path_file_create = "/adrive/v1.0/openFile/create";
const path_upload_url = "/adrive/v1.0/openFile/getUploadUrl";
const path_complete = "/adrive/v1.0/openFile/complete";
const path_download_url = "/adrive/v1.0/openFile/getDownloadUrl";
const path_move = "/adrive/v1.0/openFile/move";
const path_copy = "/adrive/v1.0/openFile/copy";
const path_update = "/adrive/v1.0/openFile/update";
const path_delete = "/adrive/v1.0/openFile/delete";
const path_trash = "/adrive/v1.0/openFile/recyclebin/trash";
const path_oauth_token = "/oauth/access_token";

/// `internal_upload` 打开时把公网 CDN 换成长城内网地址（上游硬编码的两个）。
const internal_from = "https://cn-beijing-data.aliyundrive.net/";
const internal_to = "http://ccp-bj29-bj-1592982087.oss-cn-beijing-internal.aliyuncs.com/";

/// 上游判定「token 失效」的码。命中任意一个就刷新后重放一次。
const token_error_codes = [_][]const u8{ "AccessTokenInvalid", "AccessTokenExpired", "I400JD" };

/// 秒传预检读多少字节算 `pre_hash`。
const pre_hash_bytes: i64 = 1024;

/// 低于这个大小不做秒传（上游 `stream.GetSize() > 100*utils.KB`）。
const rapid_min_bytes: i64 = 100 * 1024;

/// 上传地址的有效期。上游每片上传前检查「距上次取地址超过 50 分钟」。
const upload_url_ttl_ms: i64 = 50 * 60 * 1000;

const mb: i64 = 1024 * 1024;
const gb: i64 = 1024 * mb;
const tb: i64 = 1024 * gb;

pub const Error = error{
    /// 既没有 refresh_token 也没有 access_token。
    NoToken,
    /// `getDriveInfo` 里没有对应 `drive_type` 的 drive_id。
    NoDriveId,
    /// 走本地续期但没有 client_id / client_secret。
    NoClientCredentials,
    /// 刷新前后的 refresh_token 不是同一个账号。
    SubMismatch,
    /// refresh_token 不是三段式 JWT。
    NotJwt,
    /// 拿到了下载接口的响应但没有 url（且不是 livp）。
    NoDownloadUrl,
    InvalidPath,
    InvalidResponse,
    BadPartSize,
    UpstreamHttp,
    UpstreamNotJson,
    UpstreamError,
};

// ---------------------------------------------------------------------------
// 限速
// ---------------------------------------------------------------------------

/// 三个独立桶。官方文档给的是 list 4/s、link 1/s、其它 15/s；上游各留了一点
/// 余量（3.9 / 0.9 / 14.9）并用容量 1 的令牌桶 —— 也就是**最小间隔**。
///
/// 这里直接实现最小间隔。与 `115open.zig` 同一套思路，理由也一样：本工程的
/// `Client.send` 上有一把全局互斥锁，请求本来就是串行的，令牌桶能提供的突发
/// 能力换不来任何东西。
///
/// 桶**按 `user_id` 进程级共享**（见下面的 `acquireLimiter`），对齐上游
/// `limiter.go` —— 阿里云的限速是「每用户每应用」，同一账号挂多个 storage
/// 必须共用一个桶，否则总量超速。
const Bucket = enum { list, link, other };

fn bucketIntervalMs(b: Bucket) i64 {
    return switch (b) {
        .list => 257, // ceil(1000 / 3.9)
        .link => 1112, // ceil(1000 / 0.9)
        .other => 68, // ceil(1000 / 14.9)
    };
}

const RateLimiter = struct {
    mu: std.Io.Mutex = .init,
    next_list_ms: i64 = 0,
    next_link_ms: i64 = 0,
    next_other_ms: i64 = 0,

    /// 睡够与上一次同类请求之间的最小间隔。
    ///
    /// 锁**跨睡眠持有**：不这样做，两个并发调用会同时读到「可以走」，然后一起
    /// 冲上去。既然底下的 HTTP 客户端本来就串行，把等待也串起来不损失吞吐。
    fn wait(self: *RateLimiter, b: Bucket) void {
        self.mu.lockUncancelable(rt.io());
        defer self.mu.unlock(rt.io());

        const slot = switch (b) {
            .list => &self.next_list_ms,
            .link => &self.next_link_ms,
            .other => &self.next_other_ms,
        };
        const now = rt.nowMillis();
        if (now < slot.*) {
            rt.sleepMillis(slot.* - now);
            slot.* = rt.nowMillis() + bucketIntervalMs(b);
        } else {
            slot.* = now + bucketIntervalMs(b);
        }
    }
};

// ---------------------------------------------------------------------------
// 进程级限速器表（对齐上游 limiter.go）
// ---------------------------------------------------------------------------

/// 尚未知道 `user_id` 时用的键，对应 Go 的 `globalLimiterUserID = ""`。
const global_limiter_key = "";

const max_limiter_users = 32;

const LimiterEntry = struct {
    user_id: []const u8,
    limiter: *RateLimiter,
    used_by: u32,
};

/// 固定大小、无全局 allocator 依赖的表。条目在 `deinit` 时按引用计数回收
/// （全局那条 `""` 永不回收，与 Go 一致）。
var limiter_table: [max_limiter_users]LimiterEntry = undefined;
var limiter_table_len: usize = 0;
var limiter_table_mu: std.Io.Mutex = .init;

/// 取（或建）`user_id` 对应的桶并 +1 引用。表满时返回 null，调用方退回私有桶。
fn acquireLimiter(alloc: std.mem.Allocator, user_id: []const u8) ?*RateLimiter {
    const io = rt.io();
    limiter_table_mu.lockUncancelable(io);
    defer limiter_table_mu.unlock(io);

    for (limiter_table[0..limiter_table_len]) |*e| {
        if (std.mem.eql(u8, e.user_id, user_id)) {
            e.used_by += 1;
            return e.limiter;
        }
    }
    if (limiter_table_len >= max_limiter_users) {
        log.warn("[aliopen] limiter table full ({d}); using a private limiter", .{max_limiter_users});
        return null;
    }
    const lim = alloc.create(RateLimiter) catch return null;
    lim.* = .{};
    const key = alloc.dupe(u8, user_id) catch {
        alloc.destroy(lim);
        return null;
    };
    limiter_table[limiter_table_len] = .{ .user_id = key, .limiter = lim, .used_by = 1 };
    limiter_table_len += 1;
    return lim;
}

/// -1 引用；归零且不是全局桶时销毁条目。
fn releaseLimiter(alloc: std.mem.Allocator, user_id: []const u8) void {
    const io = rt.io();
    limiter_table_mu.lockUncancelable(io);
    defer limiter_table_mu.unlock(io);

    var i: usize = 0;
    while (i < limiter_table_len) : (i += 1) {
        const e = &limiter_table[i];
        if (!std.mem.eql(u8, e.user_id, user_id)) continue;
        if (e.used_by > 0) e.used_by -= 1;
        if (e.used_by == 0 and !std.mem.eql(u8, e.user_id, global_limiter_key)) {
            alloc.free(e.user_id);
            alloc.destroy(e.limiter);
            limiter_table[i] = limiter_table[limiter_table_len - 1]; // swap-remove
            limiter_table_len -= 1;
        }
        return;
    }
}

// ---------------------------------------------------------------------------
// 配置（对应 Go 的 Addition）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    /// `""` 时 `init` 会当成 `"default"` —— 与上游 `Init` 的兜底一致。
    drive_type: []const u8 = "",
    root_folder_id: []const u8 = default_root,
    refresh_token: []const u8 = "",
    /// 上游 struct 上没有 `default` 标签，前端取 `options[0]`，所以实际生效
    /// 值就是 `name` / `ASC`。配置里显式写 `""` 会被原样保留。
    order_by: []const u8 = "name",
    order_direction: []const u8 = "ASC",
    use_online_api: bool = true,
    alipan_type: []const u8 = "default",
    api_url_address: []const u8 = default_api_address,
    client_id: []const u8 = "",
    client_secret: []const u8 = "",
    /// `"delete"` 才是永久删除，其余一律进回收站。
    remove_way: []const u8 = "trash",
    rapid_upload: bool = false,
    internal_upload: bool = false,
    livp_download_format: []const u8 = "jpeg",
    /// 只在服务端代理下载时有意义，本工程由 API 层代劳 —— 见文件头。
    callback_concurrency: i64 = 1,
    access_token: []const u8 = "",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.drive_type = try dupeOr(alloc, o.strAt("drive_type"), "");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        a.refresh_token = try dupeOr(alloc, o.strAt("refresh_token"), "");
        a.order_by = try dupeOr(alloc, o.strAt("order_by"), "name");
        a.order_direction = try dupeOr(alloc, o.strAt("order_direction"), "ASC");
        if (boolAt(o, "use_online_api")) |b| a.use_online_api = b;
        a.alipan_type = try dupeOr(alloc, o.strAt("alipan_type"), "default");
        a.api_url_address = try dupeOr(alloc, o.strAt("api_url_address"), default_api_address);
        a.client_id = try dupeOr(alloc, o.strAt("client_id"), "");
        a.client_secret = try dupeOr(alloc, o.strAt("client_secret"), "");
        a.remove_way = try dupeOr(alloc, o.strAt("remove_way"), "trash");
        if (boolAt(o, "rapid_upload")) |b| a.rapid_upload = b;
        if (boolAt(o, "internal_upload")) |b| a.internal_upload = b;
        a.livp_download_format = try dupeOr(alloc, o.strAt("livp_download_format"), "jpeg");
        if (o.intAt("callback_concurrency")) |n| a.callback_concurrency = n;
        // T3：Go 的 `AccessToken` 字段**没有 json tag**（drivers/aliyundrive_open/
        // meta.go:23），`encoding/json` 以字段名本身为键 —— 用户备份 storage #5
        // 里就是大写的 `AccessToken`。只认小写 `access_token` 会把用户已经
        // 授权过的 token 读丢，每次启动都得重新刷新。Go 名优先，小写兜底。
        a.access_token = try dupeOr(alloc, o.strAt("AccessToken") orelse o.strAt("access_token"), "");
        return a;
    }

    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_type", self.drive_type);
        try w.str("root_folder_id", self.root_folder_id);
        try w.str("refresh_token", self.refresh_token);
        try w.str("order_by", self.order_by);
        try w.str("order_direction", self.order_direction);
        try w.boolean("use_online_api", self.use_online_api);
        try w.str("alipan_type", self.alipan_type);
        try w.str("api_url_address", self.api_url_address);
        try w.str("client_id", self.client_id);
        try w.str("client_secret", self.client_secret);
        try w.str("remove_way", self.remove_way);
        try w.boolean("rapid_upload", self.rapid_upload);
        try w.boolean("internal_upload", self.internal_upload);
        try w.str("livp_download_format", self.livp_download_format);
        try w.int("callback_concurrency", self.callback_concurrency);
        // 与 Go 一致：无 tag 字段以字段名本身为键（用户备份里就是 AccessToken）。
        try w.str("AccessToken", self.access_token);
        try w.end();
        return b.toOwned();
    }

    /// 上传/建目录时带的 `local_modified_at` 用的格式。
    fn removeIsPermanent(self: Addition) bool {
        return std.mem.eql(u8, self.remove_way, "delete");
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    const s = v orelse return alloc.dupe(u8, fallback);
    return alloc.dupe(u8, s);
}

fn boolAt(v: *const json.Value, path: []const u8) ?bool {
    const p = v.getPath(path) orelse return null;
    return p.asBool();
}

fn boolOr(v: *const json.Value, path: []const u8) bool {
    return boolAt(v, path) orelse false;
}

fn arrAt(v: *const json.Value, path: []const u8) []json.Value {
    const p = v.getPath(path) orelse return &.{};
    return p.asArray() orelse &.{};
}

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
// 分片
// ---------------------------------------------------------------------------

/// 分片表的一项。
///
/// 必须是有名类型：Zig 里写在函数签名中的匿名 struct 每次出现都是**不同的
/// 类型**，`List(struct{...})` 和返回类型 `[]struct{...}` 之间没法转换。
const PartInfo = struct { number: i64, upload_url: []const u8 };

/// `part_info_list` 只带 `part_number`，从 1 开始。
///
/// `create` 和 `getUploadUrl` 两个请求用的是同一个形状，所以单独成函数 ——
/// 上游是手抄两遍的。
fn writePartInfos(b: *Buf, count: i64) !void {
    try b.appendByte('[');
    var i: i64 = 0;
    while (i < count) : (i += 1) {
        if (i > 0) try b.appendByte(',');
        try b.append("{\"part_number\":");
        try b.print("{d}", .{i + 1});
        try b.appendByte('}');
    }
    try b.appendByte(']');
}

/// 分片大小阶梯。**与 `115open.zig` 的 `calPartSize` 逐字相同** —— 两家用的是
/// 同一份魔数表（20MB 起步，超过 128GB 后按档位放大，保证 1TB 能切成 10000 片
/// 以内）。抄错一个数会导致超大文件上传在最后一片失败。
fn calPartSize(file_size: i64) i64 {
    var part_size: i64 = 20 * mb;
    if (file_size > part_size) {
        if (file_size > 1 * tb) {
            part_size = 5 * gb;
        } else if (file_size > 768 * gb) {
            part_size = 109951163;
        } else if (file_size > 512 * gb) {
            part_size = 82463373;
        } else if (file_size > 384 * gb) {
            part_size = 54975582;
        } else if (file_size > 256 * gb) {
            part_size = 41231687;
        } else if (file_size > 128 * gb) {
            part_size = 27487791;
        }
    }
    return part_size;
}

/// 从 `part_info_list` 响应里取出 (编号, 上传地址)。
fn parsePartInfos(alloc: std.mem.Allocator, items: []json.Value) ![]PartInfo {
    var out = List(PartInfo).init(alloc);
    for (items) |*it| {
        try out.append(.{
            .number = it.intAt("part_number") orelse 0,
            .upload_url = it.strAt("upload_url") orelse "",
        });
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// 秒传的 proof
// ---------------------------------------------------------------------------

const ProofRange = struct { start: i64, end: i64 };

/// 取 `md5hex(seed)` 的前 16 个十六进制字符当 uint64，对文件大小取模得到起点，
/// 再往后 8 个字节（不越过文件尾）。
///
/// **seed 是 access_token**，不是服务端下发的什么东西 —— 这是阿里云盘和夸克
/// 最大的区别（夸克用 `proof_seed1/2`，两个都由服务端参与决定）。文件大小为 0
/// 时返回空区间，调用方据此返回空串而不是报错。
fn getProofRange(alloc: std.mem.Allocator, seed: []const u8, file_size: i64) !ProofRange {
    if (file_size == 0) return .{ .start = 0, .end = 0 };

    const digest = try hash.md5Hex(alloc, seed);
    const v = std.fmt.parseInt(u64, digest[0..16], 16) catch return Error.InvalidResponse;
    const index: i64 = @intCast(v % @as(u64, @intCast(file_size)));

    var end = index + 8;
    if (end >= file_size) end = file_size;
    return .{ .start = index, .end = end };
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

/// 取出 JWT payload 里的 `sub`。
///
/// 用 `base64.RawStdEncoding`：**标准**字母表（含 `+` `/`）、**去掉 padding**。
/// 阿里云盘的 token 是标准 base64，不是 URL 安全的那套；用错字母表会在某些
/// token 上偶发解码失败，而那种 bug 极难复现。
///
/// payload 不是合法 JSON、或者没有 `sub` 字段时返回空串（与 Go 的
/// `utils.Json.Get(bs, "sub").ToString()` 一致），只有「不是三段」和「base64
/// 解不开」才是错误。
fn getSub(alloc: std.mem.Allocator, token: []const u8) ![]const u8 {
    var it = std.mem.splitScalar(u8, token, '.');
    _ = it.next() orelse return Error.NotJwt;
    const payload = it.next() orelse return Error.NotJwt;
    _ = it.next() orelse return Error.NotJwt;
    if (it.next() != null) return Error.NotJwt;

    const dec = std.base64.standard_no_pad.Decoder;
    const n = dec.calcSizeForSlice(payload) catch return Error.NotJwt;
    const raw = try alloc.alloc(u8, n);
    dec.decode(raw, payload) catch return Error.NotJwt;

    const v = json.parse(alloc, raw) catch return alloc.dupe(u8, "");
    return alloc.dupe(u8, v.strAt("sub") orelse "");
}

// ---------------------------------------------------------------------------
// 驱动本体
// ---------------------------------------------------------------------------

pub const AliyundriveOpen = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,
    /// 进程级共享的限速器（按 `user_id`）。null = 表满，退回 `private_limiter`。
    limiter: ?*RateLimiter = null,
    /// 全局表满时的兜底桶（32 个用户同时在线才可能发生）。
    private_limiter: RateLimiter = .{},

    /// `init` 查出来的 `{drive_type}_drive_id`。所有文件操作都要它。
    drive_id: []const u8 = "",
    /// 仅用于日志与将来的 per-user 限速。
    user_id: []const u8 = "",
    /// `drive_type` / `livp_download_format` 的生效值（补过默认之后）。
    /// 不写回 `cfg`：那会让 `save()` 在配置里凭空多出两个键。
    eff_drive_type: []const u8 = "default",
    eff_livp_format: []const u8 = "jpeg",

    /// 串行化「刷新 token」。
    refresh_mu: std.Io.Mutex = .init,
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
        .copy = copy,
        .space = space,
    };

    fn drvName(_: *anyopaque) []const u8 {
        return "AliyundriveOpen";
    }

    fn as(ptr: *anyopaque) *AliyundriveOpen {
        return @ptrCast(@alignCast(ptr));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        _ = ctx;

        if (self.cfg.refresh_token.len == 0 and self.cfg.access_token.len == 0) {
            log.err("[aliopen] 需要 RefreshToken（推荐）或 AccessToken", .{});
            return Error.NoToken;
        }

        self.eff_drive_type = if (self.cfg.drive_type.len == 0) "default" else self.cfg.drive_type;
        self.eff_livp_format = if (self.cfg.livp_download_format.len == 0) "jpeg" else self.cfg.livp_download_format;

        // 上游在拿到 user_id 之前先用全局桶限制初始请求（`limiter.go:38`），
        // 拿到之后换成 per-user 桶（`limiter.go:52-54`）。
        self.limiter = acquireLimiter(self.alloc, global_limiter_key);
        errdefer {
            releaseLimiter(self.alloc, global_limiter_key);
            self.limiter = null;
        }

        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const body = try self.request(a, path_drive_info, "POST", null, .other);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;

        const key = try std.fmt.allocPrint(a, "{s}_drive_id", .{self.eff_drive_type});
        const did = v.strAt(key) orelse "";
        if (did.len == 0) {
            log.err("[aliopen] getDriveInfo 里没有 {s}", .{key});
            return Error.NoDriveId;
        }

        self.drive_id = try self.alloc.dupe(u8, did);
        self.user_id = try self.alloc.dupe(u8, v.strAt("user_id") orelse "");

        // 换成 per-user 桶：先还掉全局那份引用，再取账号自己的。
        releaseLimiter(self.alloc, global_limiter_key);
        self.limiter = acquireLimiter(self.alloc, self.user_id);

        log.info("[aliopen] ready: drive={s} user={s} root={s}", .{
            self.drive_id, self.user_id, self.cfg.root_folder_id,
        });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        if (self.limiter != null) {
            releaseLimiter(self.alloc, self.user_id);
            self.limiter = null;
        }
        self.save();
    }

    fn save(self: *AliyundriveOpen) void {
        if (self.storage_id == 0) return;
        const text = self.cfg.toJson(self.alloc) catch return;
        defer self.alloc.free(text);
        if (text.len == self.last_saved.len and std.mem.eql(u8, text, self.last_saved)) return;
        if (self.last_saved.len > 0) self.alloc.free(self.last_saved);
        self.last_saved = self.alloc.dupe(u8, text) catch return;
        driver.persist(self.storage_id, self.last_saved);
    }

    // -----------------------------------------------------------------------
    // HTTP
    // -----------------------------------------------------------------------

    /// 一次请求的结果。
    ///
    /// 上游把「上游返回了业务错误码」表示成 `(body, error, *ErrResp)` 三元组，
    /// 因为上传路径要看 `PreHashMatched` 这个**错误码**。这里用一个结构体代替：
    /// `code` 非空即表示上游拒绝了这次调用。
    ///
    /// 只有传输失败、响应不是 JSON、以及刷新 token 失败才走 `!`。
    const Reply = struct {
        body: []const u8,
        code: []const u8 = "",
        message: []const u8 = "",
    };

    fn requestRaw(
        self: *AliyundriveOpen,
        arena: std.mem.Allocator,
        uri: []const u8,
        method: []const u8,
        body: ?[]const u8,
        bucket: Bucket,
        retried: bool,
    ) !Reply {
        (self.limiter orelse &self.private_limiter).wait(bucket);

        const url = try std.fmt.allocPrint(arena, "{s}{s}", .{ api_base, uri });
        const auth = try std.fmt.allocPrint(arena, "Bearer {s}", .{self.cfg.access_token});

        var headers = List(model.Header).init(arena);
        try headers.append(.{ .name = "Authorization", .value = auth });
        try headers.append(.{ .name = "User-Agent", .value = user_agent });
        try headers.append(.{ .name = "Accept", .value = "application/json, text/plain, */*" });
        // 上游只在 POST 上设 Content-Type，照抄。
        if (std.mem.eql(u8, method, "POST")) {
            try headers.append(.{ .name = "Content-Type", .value = "application/json" });
        }

        const res = try self.client.send(arena, .{
            .method = method,
            .url = url,
            .headers = headers.slice(),
            .body = body orelse "",
        });

        const v = json.parse(arena, res.body) catch {
            log.warn("[aliopen] {s} non-JSON (HTTP {d}): {s}", .{
                uri, res.status, res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamNotJson;
        };

        const code = v.strAt("code") orelse "";
        if (code.len == 0) return .{ .body = res.body };

        const message = v.strAt("message") orelse "";
        const is_token_error = blk: {
            for (token_error_codes) |c| {
                if (std.mem.eql(u8, c, code)) break :blk true;
            }
            break :blk self.cfg.access_token.len == 0;
        };
        if (!retried and is_token_error) {
            log.info("[aliopen] {s} -> {s}, refreshing token", .{ uri, code });
            try self.refreshToken(arena);
            return self.requestRaw(arena, uri, method, body, bucket, true);
        }
        return .{ .body = res.body, .code = code, .message = message };
    }

    /// 同上，但把业务错误码直接翻成错误。
    fn request(
        self: *AliyundriveOpen,
        arena: std.mem.Allocator,
        uri: []const u8,
        method: []const u8,
        body: ?[]const u8,
        bucket: Bucket,
    ) ![]const u8 {
        const r = try self.requestRaw(arena, uri, method, body, bucket, false);
        if (r.code.len > 0) {
            log.warn("[aliopen] {s} failed: {s}: {s}", .{ uri, r.code, r.message });
            return Error.UpstreamError;
        }
        return r.body;
    }

    /// 续期。上游的循环是「1 次 + 最多 3 次重试」= 4 次尝试，这里照抄。
    fn refreshToken(self: *AliyundriveOpen, arena: std.mem.Allocator) !void {
        self.refresh_mu.lockUncancelable(rt.io());
        defer self.refresh_mu.unlock(rt.io());

        var last_err: anyerror = Error.UpstreamHttp;
        var attempt: usize = 0;
        while (attempt < 4) : (attempt += 1) {
            if (attempt > 0) rt.sleepMillis(1000);
            const pair = self.refreshOnce(arena) catch |e| {
                log.err("[aliopen] refresh attempt {d} failed: {s}", .{ attempt + 1, @errorName(e) });
                last_err = e;
                continue;
            };

            const new_rt = try self.alloc.dupe(u8, pair.refresh);
            const new_at = try self.alloc.dupe(u8, pair.access);
            if (self.cfg.refresh_token.len > 0) self.alloc.free(self.cfg.refresh_token);
            if (self.cfg.access_token.len > 0) self.alloc.free(self.cfg.access_token);
            self.cfg.refresh_token = new_rt;
            self.cfg.access_token = new_at;
            self.save();
            log.info("[aliopen] token refreshed", .{});
            return;
        }
        return last_err;
    }

    const TokenPair = struct { refresh: []const u8, access: []const u8 };

    fn refreshOnce(self: *AliyundriveOpen, arena: std.mem.Allocator) !TokenPair {
        if (self.cfg.use_online_api and self.cfg.api_url_address.len > 0) {
            const driver_txt = if (std.mem.eql(u8, self.cfg.alipan_type, "alipanTV")) "alicloud_tv" else "alicloud_qr";
            const url = try std.fmt.allocPrint(arena, "{s}?refresh_ui={s}&server_use=true&driver_txt={s}", .{
                self.cfg.api_url_address, self.cfg.refresh_token, driver_txt,
            });
            (self.limiter orelse &self.private_limiter).wait(.other);
            const res = try self.client.send(arena, .{
                .method = "GET",
                .url = url,
                .headers = &.{.{ .name = "User-Agent", .value = user_agent }},
            });
            const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
            const refresh = v.strAt("refresh_token") orelse "";
            const access = v.strAt("access_token") orelse "";
            if (refresh.len == 0 or access.len == 0) {
                const text = v.strAt("text") orelse "";
                if (text.len > 0) log.err("[aliopen] renewapi: {s}", .{text});
                return Error.UpstreamError;
            }
            return .{ .refresh = refresh, .access = access };
        }

        // 本地续期：必须自带 client_id / client_secret。
        if (self.cfg.client_id.len == 0 or self.cfg.client_secret.len == 0) {
            return Error.NoClientCredentials;
        }

        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("client_id", self.cfg.client_id);
        try w.str("client_secret", self.cfg.client_secret);
        try w.str("grant_type", "refresh_token");
        try w.str("refresh_token", self.cfg.refresh_token);
        try w.end();

        (self.limiter orelse &self.private_limiter).wait(.other);
        const url = try std.fmt.allocPrint(arena, "{s}{s}", .{ api_base, path_oauth_token });
        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = url,
            .headers = &.{
                .{ .name = "User-Agent", .value = user_agent },
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = b.slice(),
        });
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        const code = v.strAt("code") orelse "";
        if (code.len > 0) {
            log.err("[aliopen] oauth: {s}: {s}", .{ code, v.strAt("message") orelse "" });
            return Error.UpstreamError;
        }
        const refresh = v.strAt("refresh_token") orelse "";
        const access = v.strAt("access_token") orelse "";
        if (refresh.len == 0) {
            log.warn("[aliopen] oauth returned no refresh_token: {s}", .{
                res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamError;
        }

        // 新旧 token 必须是同一个账号。少了这一步，一个配错的 client_id 会把
        // 驱动器悄悄挂到别人的盘上 —— 而且一切看起来都正常。
        const cur_sub = try getSub(arena, self.cfg.refresh_token);
        const new_sub = try getSub(arena, refresh);
        if (!std.mem.eql(u8, cur_sub, new_sub)) {
            log.err("[aliopen] 刷新前后 sub 不一致（{s} != {s}），拒绝使用新 token", .{ cur_sub, new_sub });
            return Error.SubMismatch;
        }
        return .{ .refresh = refresh, .access = access };
    }

    // -----------------------------------------------------------------------
    // 路径 → file_id
    // -----------------------------------------------------------------------

    const Entry = struct {
        id: []const u8,
        name: []const u8,
        is_dir: bool,
        raw: ?*const json.Value = null,
    };

    /// 阿里云盘和夸克、123pan 一样只认 ID，所以同样要逐级列目录。
    fn resolveEntry(self: *AliyundriveOpen, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    fn findChild(self: *AliyundriveOpen, arena: std.mem.Allocator, parent_id: []const u8, name: []const u8) !Entry {
        var marker: []const u8 = "";
        while (true) {
            const page = try self.listPage(arena, parent_id, marker);
            for (page.items) |*item| {
                const n = item.strAt("name") orelse continue;
                if (!std.mem.eql(u8, n, name)) continue;
                return entryFromJson(item);
            }
            if (page.next_marker.len == 0) return driver.Error.NotFound;
            marker = page.next_marker;
        }
    }

    const Page = struct {
        items: []json.Value,
        next_marker: []const u8,
    };

    /// 一页目录。
    ///
    /// 上游从 `marker = "first"` 起步然后立刻把它清空，等价于「第一轮发空
    /// marker，之后用上一页的 `next_marker`」。这里直接发空 marker。
    fn listPage(self: *AliyundriveOpen, arena: std.mem.Allocator, parent_id: []const u8, marker: []const u8) !Page {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.int("limit", page_size);
        try w.str("marker", marker);
        try w.str("order_by", self.cfg.order_by);
        try w.str("order_direction", self.cfg.order_direction);
        try w.str("parent_file_id", parent_id);
        try w.end();

        const body = try self.request(arena, path_file_list, "POST", b.slice(), .list);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return .{
            .items = arrAt(&v, "items"),
            .next_marker = v.strAt("next_marker") orelse "",
        };
    }

    fn listAll(self: *AliyundriveOpen, arena: std.mem.Allocator, parent_id: []const u8) ![]model.Obj {
        var out = List(model.Obj).init(arena);
        var marker: []const u8 = "";
        while (true) {
            const page = try self.listPage(arena, parent_id, marker);
            for (page.items) |*item| try out.append(objFromJson(item));
            if (page.next_marker.len == 0) break;
            marker = page.next_marker;
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

        var it = std.mem.tokenizeAny(u8, path, "/\\");
        if (it.next() == null) return .{ .name = "/", .is_dir = true };

        const entry = try self.resolveEntry(a, path);
        const raw = entry.raw orelse return .{ .name = entry.name, .is_dir = entry.is_dir };
        const o = objFromJson(raw);
        return model.File.fromObj(o);
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;

        const entry = try self.resolveEntry(a, path);
        if (entry.is_dir) return driver.Error.NotFound;

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", entry.id);
        try w.int("expire_sec", 14400);
        try w.end();

        const body = try self.request(a, path_download_url, "POST", b.slice(), .link);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;

        var url = v.strAt("url") orelse "";
        if (url.len == 0) {
            // 实况照片（livp）拿不到直链，退回 streamsUrl 里的一个静态帧或视频。
            if (!isLivp(entry.name)) {
                log.warn("[aliopen] getDownloadUrl 没有 url: {s}", .{
                    body[0..@min(body.len, 200)],
                });
                return Error.NoDownloadUrl;
            }
            const key = try std.fmt.allocPrint(a, "streamsUrl.{s}", .{self.eff_livp_format});
            url = v.strAt(key) orelse "";
            if (url.len == 0) return Error.NoDownloadUrl;
        }

        // `args.redirect` 与上游的 `args.Redirect` 同极性：为真说明调用方
        // 跟得了 302，直接给链接；为假则要求服务端代取。
        if (args.redirect) return .{ .url = url };
        return .{ .url = url, .proxy = true };
    }

    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dir);
        if (name.len == 0) return Error.InvalidPath;
        const parent = try self.resolveEntry(a, parentOf(dir));

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("parent_file_id", parent.id);
        try w.str("name", name);
        try w.str("type", "folder");
        // 目录用 refuse：同名目录直接报错，避免 `ignore` 造成的静默重名。
        try w.str("check_name_mode", "refuse");
        try w.end();
        _ = try self.request(a, path_file_create, "POST", b.slice(), .other);
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const s = try self.resolveEntry(a, src);
        const d = try self.resolveEntry(a, dst_dir);

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", s.id);
        try w.str("to_parent_file_id", d.id);
        try w.str("check_name_mode", "ignore");
        try w.end();
        _ = try self.request(a, path_move, "POST", b.slice(), .other);
    }

    /// Go `drivers/aliyundrive_open/driver.go` 的 Copy：`/openFile/copy`，
    /// `auto_rename=false`。上游随后还会 `removeDuplicateFiles` 清理目标目录里
    /// 的重名项 —— 那个逻辑依赖 `op.List`（会绕过本驱动直接列父目录），不移植
    /// （见文件头「未移植」清单）；上游自己也只 warn 不报错，复制本身已完成。
    fn copy(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const s = try self.resolveEntry(a, src);
        const d = try self.resolveEntry(a, dst_dir);

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", s.id);
        try w.str("to_parent_file_id", d.id);
        try w.boolean("auto_rename", false);
        try w.end();
        _ = try self.request(a, path_copy, "POST", b.slice(), .other);
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        if (new_name.len == 0) return Error.InvalidPath;

        const s = try self.resolveEntry(a, src);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", s.id);
        try w.str("name", new_name);
        try w.end();
        _ = try self.request(a, path_update, "POST", b.slice(), .other);
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = is_dir; // 阿里云盘的删除接口对文件和目录是同一个

        const s = try self.resolveEntry(a, path);
        const uri = if (self.cfg.removeIsPermanent()) path_delete else path_trash;

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", s.id);
        try w.end();
        _ = try self.request(a, uri, "POST", b.slice(), .other);
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(ptr);
        const a = ctx.alloc;

        const body = try self.request(a, path_space_info, "POST", null, .other);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        return .{
            .total = v.intAt("personal_space_info.total_size") orelse 0,
            .used = v.intAt("personal_space_info.used_size") orelse 0,
        };
    }

    // -----------------------------------------------------------------------
    // 上传：create（可带 pre_hash）→ 逐片 PUT → complete
    // -----------------------------------------------------------------------

    /// `create` 请求体里「秒传相关字段」的三种形态。
    const RapidMode = enum {
        /// 不启用秒传。
        none,
        /// 第一轮：只带 `size` + `pre_hash`（前 1024 字节的 SHA1）。
        pre_hash,
        /// 第二轮：`PreHashMatched` 之后，带 `size` + 整文件 SHA1 + `proof_code`。
        /// 注意**不带** `pre_hash` —— 上游是 `delete(createData, "pre_hash")`。
        proof,
    };

    fn buildCreateBody(
        self: *AliyundriveOpen,
        a: std.mem.Allocator,
        parent_id: []const u8,
        name: []const u8,
        size: i64,
        count: i64,
        mtime_iso: []const u8,
        mode: RapidMode,
        hash_value: []const u8,
        proof_code: []const u8,
    ) ![]u8 {
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("parent_file_id", parent_id);
        try w.str("name", name);
        try w.str("type", "file");
        try w.str("check_name_mode", "ignore");
        try w.str("local_modified_at", mtime_iso);
        try w.str("local_created_at", mtime_iso);
        try w.key("part_info_list");
        try writePartInfos(&b, count);
        switch (mode) {
            .none => {},
            .pre_hash => {
                try w.int("size", size);
                try w.str("pre_hash", hash_value);
            },
            .proof => {
                try w.int("size", size);
                try w.str("proof_version", "v1");
                try w.str("content_hash_name", "sha1");
                try w.str("content_hash", hash_value);
                try w.str("proof_code", proof_code);
            },
        }
        try w.end();
        return b.toOwned();
    }

    fn getUploadUrl(
        self: *AliyundriveOpen,
        a: std.mem.Allocator,
        count: i64,
        file_id: []const u8,
        upload_id: []const u8,
    ) ![]PartInfo {
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", file_id);
        try w.key("part_info_list");
        try writePartInfos(&b, count);
        try w.str("upload_id", upload_id);
        try w.end();

        const body = try self.request(a, path_upload_url, "POST", b.slice(), .other);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        return parsePartInfos(a, arrAt(&v, "part_info_list"));
    }

    fn completeUpload(self: *AliyundriveOpen, a: std.mem.Allocator, file_id: []const u8, upload_id: []const u8) ![]const u8 {
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("drive_id", self.drive_id);
        try w.str("file_id", file_id);
        try w.str("upload_id", upload_id);
        try w.end();
        return self.request(a, path_complete, "POST", b.slice(), .other);
    }

    fn uploadPart(self: *AliyundriveOpen, a: std.mem.Allocator, part: PartInfo, data: []const u8) !void {
        const url = if (self.cfg.internal_upload) try replaceInternal(a, part.upload_url) else part.upload_url;
        const res = try self.client.send(a, .{
            .method = "PUT",
            .url = url,
            .headers = &.{
                .{ .name = "User-Agent", .value = user_agent },
                .{ .name = "Accept-Encoding", .value = "gzip" },
                // ⚠️ **绝不能带 Content-Type**。
                //
                // 这里的 `upload_url` 是阿里云 OSS 的**预签名 URL**，签名串里
                // 含 `Content-Type`（OSS V1 签名：VERB + Content-MD5 +
                // Content-Type + Expires + ...）。多带一个头就会算出不同的签名，
                // OSS 直接回 **403 `SignatureDoesNotMatch`**（真机实测，
                // 6 次重试全部 403，上传完全不可用）。
                //
                // 上游 `drivers/aliyundrive_open/upload.go:67-85` 用的是
                // `base.HttpClient`（裸 net/http）+ `http.NewRequest(PUT, url, r)`，
                // **一个额外头都不加** —— 之前这里写了"多一个头不影响校验"，
                // 是没验证的臆断，已按实测纠正。
            },
            .body = data,
            .use_cookies = false,
            // 预签名 URL：一个额外的 Content-Type 都不能有。
            .omit_content_type = true,
            // 结果只看状态码（200/409），不读响应体 —— 见 Request.skip_body。
            .skip_body = true,
        });
        // 409 = 这一片已经存在（重试场景）。上游把它和 200 一样当成功。
        if (res.status != 200 and res.status != 409) {
            log.warn("[aliopen] part {d} HTTP {d}: {s}", .{
                part.number, res.status, res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamHttp;
        }
    }

    /// 上游 `retry.Do(..., Attempts(3), BackOffDelay, Delay(1s))` —— 3 次尝试，
    /// 退避 1s、2s。
    fn uploadPartRetrying(self: *AliyundriveOpen, a: std.mem.Allocator, part: PartInfo, data: []const u8) !void {
        var last: anyerror = Error.UpstreamHttp;
        var attempt: usize = 0;
        while (attempt < 3) : (attempt += 1) {
            if (attempt > 0) rt.sleepMillis(@as(i64, 1000) << @intCast(attempt - 1));
            self.uploadPart(a, part, data) catch |e| {
                last = e;
                continue;
            };
            return;
        }
        return last;
    }

    /// 取 `proof_code`：读出 `getProofRange` 指出的 8 字节再 base64。
    fn proofCode(self: *AliyundriveOpen, a: std.mem.Allocator, src: model.Source) ![]u8 {
        const range = try getProofRange(a, self.cfg.access_token, src.size());
        const len = range.end - range.start;
        if (len <= 0) return a.dupe(u8, "");
        const data = try src.readAll(a, @intCast(range.start), @intCast(len));
        return hash.base64Std(a, data);
    }

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dst);
        if (name.len == 0) return Error.InvalidPath;
        const dst_dir = try self.resolveEntry(a, parentOf(dst));
        if (!dst_dir.is_dir) return Error.InvalidPath;

        const size = src.size();
        if (size < 0) return Error.InvalidPath;

        const part_size = calPartSize(size);
        if (part_size <= 0) return Error.BadPartSize;
        // 上游是 `math.Ceil(float64(size)/float64(partSize))` —— size==0 时是 0。
        const count: i64 = if (size == 0) 0 else @divTrunc(size + part_size - 1, part_size);

        // 上游读 stream.ModTime()/CreateTime()；本工程的 Source 没有时间戳。
        var mtime = Buf.init(a);
        try timeutil.formatIsoMillisZ(&mtime, rt.nowSeconds());

        const rapid = size > rapid_min_bytes and self.cfg.rapid_upload;
        var pre_hash: []const u8 = "";
        if (rapid) {
            const head_len: usize = @intCast(@min(size, pre_hash_bytes));
            const head = try src.readAll(a, 0, head_len);
            pre_hash = try hash.sha1Hex(a, head);
        }

        var body = try buildCreateBody(
            self,
            a,
            dst_dir.id,
            name,
            size,
            count,
            mtime.slice(),
            if (rapid) .pre_hash else .none,
            pre_hash,
            "",
        );
        var reply = try self.requestRaw(a, path_file_create, "POST", body, .other, false);

        if (reply.code.len > 0) {
            // 第一轮秒传预检的「命中」是一个**错误码**，不是 200。
            if (!rapid or !std.mem.eql(u8, reply.code, "PreHashMatched")) {
                log.warn("[aliopen] create {s} failed: {s}: {s}", .{ name, reply.code, reply.message });
                return Error.UpstreamError;
            }
            log.info("[aliopen] {s}: pre_hash matched, retrying with a full-file proof", .{name});

            const content_hash = try sha1HexOfSource(a, src);
            const pcode = try self.proofCode(a, src);
            body = try buildCreateBody(
                self,
                a,
                dst_dir.id,
                name,
                size,
                count,
                mtime.slice(),
                .proof,
                content_hash,
                pcode,
            );
            reply = try self.requestRaw(a, path_file_create, "POST", body, .other, false);
            if (reply.code.len > 0) {
                log.warn("[aliopen] create(proof) {s} failed: {s}: {s}", .{ name, reply.code, reply.message });
                return Error.UpstreamError;
            }
        }

        const created = json.parse(a, reply.body) catch return Error.UpstreamNotJson;
        const file_id = created.strAt("file_id") orelse return Error.InvalidResponse;
        const upload_id = created.strAt("upload_id") orelse "";
        const rapid_hit = boolOr(&created, "rapid_upload");

        if (!rapid_hit) {
            var parts = try parsePartInfos(a, arrAt(&created, "part_info_list"));
            if (parts.len == 0 and count > 0) {
                log.warn("[aliopen] create returned no part_info_list for {s}", .{name});
                return Error.InvalidResponse;
            }

            var fetched_at = rt.nowMillis();
            var offset: i64 = 0;
            var length = part_size;
            const total_parts = parts.len;
            // T7：整份上传复用同一个分片缓冲（旧代码每片 readAll 新分配，
            // 请求 arena 随文件大小线性增长）。`uploadPartRetrying` 是同步
            // 发送的，返回时 url 已带 body 发完，覆盖复用安全。
            const chunk_buf = try a.alloc(u8, @intCast(part_size));
            for (0..total_parts) |i| {
                // 上传地址 50 分钟过期，上游每片之前检查一次。
                if (rt.nowMillis() - fetched_at > upload_url_ttl_ms) {
                    parts = try self.getUploadUrl(a, count, file_id, upload_id);
                    fetched_at = rt.nowMillis();
                    if (i >= parts.len) return Error.InvalidResponse;
                }

                const remain = size - offset;
                if (remain <= 0) break;
                if (length > remain) length = remain;

                const data = chunk_buf[0..@intCast(length)];
                try src.readAllInto(@intCast(offset), data);
                try self.uploadPartRetrying(a, parts[i], data);
                offset += part_size;
                // 每片报一次百分比（0–100，Go `model.UpdateProgress` 语义）。
                if (ctx.progress) |f| {
                    const pct: u64 = @intCast(@min(@divTrunc(offset * 100, @max(size, 1)), 100));
                    f(ctx.progress_userdata, pct);
                }
            }
        } else {
            log.info("[aliopen] {s}: instant-upload hit", .{name});
            // 秒传没有字节流经本地，直接满进度。
            if (ctx.progress) |f| f(ctx.progress_userdata, 100);
        }

        _ = try self.completeUpload(a, file_id, upload_id);
        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
    }
};

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

fn lastSegment(path: []const u8) []const u8 {
    var last: []const u8 = "";
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |seg| last = seg;
    return last;
}

fn parentOf(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/\\");
    if (trimmed.len == 0) return "/";
    const idx = std.mem.lastIndexOfAny(u8, trimmed, "/\\") orelse return "/";
    if (idx == 0) return "/";
    return trimmed[0..idx];
}

/// 复现 `utils.Ext(name) == "livp"`（小写、不带点）。
fn isLivp(name: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return false;
    return std.ascii.eqlIgnoreCase(name[dot + 1 ..], "livp");
}

/// 一个文件记录 → `model.Obj`。
///
/// 时间戳是 RFC3339 字符串（Go 的 `time.Time` 直接反序列化），要自己解。
/// `content_hash` 是 SHA1，塞进 `hash_info` 让前端能显示。
fn objFromJson(item: *const json.Value) model.Obj {
    const content_hash = item.strAt("content_hash") orelse "";
    return .{
        .name = item.strAt("name") orelse item.strAt("file_name") orelse "",
        .size = item.intAt("size") orelse 0,
        .is_dir = std.mem.eql(u8, item.strAt("type") orelse "", "folder"),
        .modified = timeutil.parseRfc3339(item.strAt("updated_at") orelse "") orelse 0,
        .created = timeutil.parseRfc3339(item.strAt("created_at") orelse "") orelse 0,
        .thumb = item.strAt("thumbnail") orelse "",
        .hash_info = if (content_hash.len > 0)
            model.HashInfo{ .hash_name = "sha1", .hash_value = content_hash }
        else
            null,
    };
}

fn entryFromJson(item: *const json.Value) AliyundriveOpen.Entry {
    return .{
        .id = item.strAt("file_id") orelse "",
        .name = item.strAt("name") orelse item.strAt("file_name") orelse "",
        .is_dir = std.mem.eql(u8, item.strAt("type") orelse "", "folder"),
        .raw = item,
    };
}

/// 整文件 SHA1（小写 hex），一遍读。
///
/// 上游用的是 `utils.HashReader`，它内部是 `hex.EncodeToString` —— **小写**。
/// `pre_hash` 和 `content_hash` 必须用同一套大小写，否则服务端算出来的对不上。
fn sha1HexOfSource(a: std.mem.Allocator, src: model.Source) ![]u8 {
    var h = hash.Sha1Stream{};
    const size = src.size();
    if (size < 0) return error.UnexpectedEof;

    const buf = try a.alloc(u8, 128 * 1024);
    var offset: u64 = 0;
    const total: u64 = @intCast(size);
    while (offset < total) {
        const want: usize = @intCast(@min(@as(u64, buf.len), total - offset));
        const n = try src.readAt(offset, buf[0..want]);
        if (n == 0) return error.UnexpectedEof;
        h.update(buf[0..n]);
        offset += n;
    }
    const digest = h.final();
    return hash.hexLower(a, &digest);
}

/// `internal_upload`：把公网 CDN 前缀换成长城内网地址。
fn replaceInternal(a: std.mem.Allocator, url: []const u8) ![]const u8 {
    const idx = std.mem.indexOf(u8, url, internal_from) orelse return url;
    var b = Buf.init(a);
    try b.append(url[0..idx]);
    try b.append(internal_to);
    try b.append(url[idx + internal_from.len ..]);
    return b.toOwned();
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "AliyundriveOpen",
    .label = "阿里云盘开放平台",
    // secrets 两种拼写都收：Go 无 tag 字段以字段名为键（`AccessToken`），
    // 本工程早期版本写小写（`access_token`）。
    .secrets = &.{ "refresh_token", "AccessToken", "access_token", "client_id", "client_secret" },
    .addition_schema =
    \\{
    \\  "drive_type":           {"type":"select","default":"resource","options":["default","resource","backup"],"help":"默认盘 / 资源盘 / 备份盘，对应 getDriveInfo 返回的三个 drive_id"},
    \\  "root_folder_id":       {"type":"string","default":"root","help":"根目录 file_id，阿里云盘的根是 root"},
    \\  "refresh_token":        {"type":"string","required":true,"secret":true,"help":"必填。推荐只填这个，access_token 自动换取"},
    \\  "order_by":             {"type":"select","default":"name","options":["name","size","updated_at","created_at"],"help":"排序字段"},
    \\  "order_direction":      {"type":"select","default":"ASC","options":["ASC","DESC"],"help":"排序方向"},
    \\  "use_online_api":       {"type":"bool","default":true,"help":"用第三方 renewapi 续期；关闭则必须填 client_id/client_secret"},
    \\  "alipan_type":          {"type":"select","default":"default","options":["default","alipanTV"],"help":"影响 renewapi 走哪条通道"},
    \\  "api_url_address":      {"type":"string","default":"https://api.oplist.org/alicloud/renewapi","help":"renewapi 地址"},
    \\  "client_id":            {"type":"string","required":false,"secret":true,"help":"没有就留空（用 renewapi 时不需要）"},
    \\  "client_secret":        {"type":"string","required":false,"secret":true,"help":"没有就留空"},
    \\  "remove_way":           {"type":"select","default":"trash","options":["trash","delete"],"help":"trash 进回收站，delete 永久删除"},
    \\  "rapid_upload":         {"type":"bool","default":false,"help":"秒传。开启后先算 pre_hash，命中则不上传内容，进度条会不准"},
    \\  "internal_upload":      {"type":"bool","default":false,"help":"阿里云北京 ECS 上打开可走内网上传"},
    \\  "livp_download_format": {"type":"select","default":"jpeg","options":["jpeg","mov"],"help":"实况照片取不到直链时回退成静态帧还是视频"},
    \\  "callback_concurrency": {"type":"number","default":1,"help":"保留字段：代理下载的并发闸门由 API 层负责，本工程未使用"},
    \\  "AccessToken":          {"type":"string","required":false,"secret":true,"help":"由 refresh_token 换得；与 Go 版一致使用大写键名"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(AliyundriveOpen, self);
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*AliyundriveOpen {
    const self = try alloc.create(AliyundriveOpen);
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
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

/// 内存里的 `model.Source`，给 proof / 哈希的测试用。
const MemSource = struct {
    data: []const u8,

    fn sizeFn(ptr: *anyopaque) i64 {
        const s: *MemSource = @ptrCast(@alignCast(ptr));
        return @intCast(s.data.len);
    }

    fn readAtFn(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
        const s: *MemSource = @ptrCast(@alignCast(ptr));
        const off: usize = @intCast(offset);
        if (off >= s.data.len) return 0;
        const n = @min(buf.len, s.data.len - off);
        @memcpy(buf[0..n], s.data[off..][0..n]);
        return n;
    }

    const vtable = model.Source.VTable{ .size = sizeFn, .readAt = readAtFn };

    fn source(self: *MemSource) model.Source {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

test "addition round-trips through JSON with the Go field names" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与用户 Go 备份 storage #5 一致；`AccessToken` 大写是 Go 无 json tag
    // 字段的序列化形态（drivers/aliyundrive_open/meta.go:23）。
    const text =
        \\{"drive_type":"backup","root_folder_id":"abc","refresh_token":"rt",
        \\ "order_by":"size","order_direction":"DESC","use_online_api":false,
        \\ "alipan_type":"alipanTV","api_url_address":"https://example.test/x",
        \\ "client_id":"cid","client_secret":"sec","remove_way":"delete",
        \\ "rapid_upload":true,"internal_upload":true,"livp_download_format":"mov",
        \\ "callback_concurrency":4,"AccessToken":"at"}
    ;
    const v = try json.parse(a, text);
    const cfg = try Addition.parse(a, &v);

    try testing.expectEqualStrings("backup", cfg.drive_type);
    try testing.expectEqualStrings("abc", cfg.root_folder_id);
    try testing.expectEqualStrings("rt", cfg.refresh_token);
    try testing.expectEqualStrings("size", cfg.order_by);
    try testing.expectEqualStrings("DESC", cfg.order_direction);
    try testing.expect(!cfg.use_online_api);
    try testing.expectEqualStrings("alipanTV", cfg.alipan_type);
    try testing.expectEqualStrings("https://example.test/x", cfg.api_url_address);
    try testing.expectEqualStrings("cid", cfg.client_id);
    try testing.expectEqualStrings("sec", cfg.client_secret);
    try testing.expectEqualStrings("delete", cfg.remove_way);
    try testing.expect(cfg.rapid_upload);
    try testing.expect(cfg.internal_upload);
    try testing.expectEqualStrings("mov", cfg.livp_download_format);
    try testing.expectEqual(@as(i64, 4), cfg.callback_concurrency);
    try testing.expectEqualStrings("at", cfg.access_token);
    try testing.expect(cfg.removeIsPermanent());

    // 回写必须用 Go 的键名（大写 AccessToken），再解一遍值不变。
    const out = try cfg.toJson(a);
    try testing.expect(std.mem.indexOf(u8, out, "\"AccessToken\"") != null);
    const v2 = try json.parse(a, out);
    const cfg2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(cfg.refresh_token, cfg2.refresh_token);
    try testing.expectEqualStrings(cfg.access_token, cfg2.access_token);
    try testing.expectEqualStrings(cfg.livp_download_format, cfg2.livp_download_format);
    try testing.expectEqual(cfg.callback_concurrency, cfg2.callback_concurrency);
    try testing.expect(cfg2.use_online_api == cfg.use_online_api);
}

test "T3: Go's AccessToken key wins over the legacy lowercase spelling" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 本工程早期写的小写键仍要认（别把老配置读坏）
    const legacy = try json.parse(a, "{\"access_token\":\"lower\"}");
    const add1 = try Addition.parse(a, &legacy);
    try testing.expectEqualStrings("lower", add1.access_token);

    // 新旧并存时以 Go 名为准
    const both = try json.parse(a, "{\"access_token\":\"lower\",\"AccessToken\":\"upper\"}");
    const add2 = try Addition.parse(a, &both);
    try testing.expectEqualStrings("upper", add2.access_token);
}

test "addition defaults and tolerates a missing object" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const empty = try Addition.parse(a, null);
    try testing.expectEqualStrings("", empty.drive_type); // init 里再兜成 "default"
    try testing.expectEqualStrings(default_root, empty.root_folder_id);
    try testing.expectEqualStrings("name", empty.order_by);
    try testing.expectEqualStrings("ASC", empty.order_direction);
    try testing.expectEqualStrings("trash", empty.remove_way);
    try testing.expectEqualStrings("jpeg", empty.livp_download_format);
    try testing.expectEqual(@as(i64, 1), empty.callback_concurrency);
    try testing.expect(empty.use_online_api);
    try testing.expect(!empty.removeIsPermanent());

    // 显式的空串要保留（不能当成「缺省」）。
    const v = try json.parse(a, "{\"order_by\":\"\",\"order_direction\":\"\"}");
    const cfg = try Addition.parse(a, &v);
    try testing.expectEqualStrings("", cfg.order_by);
    try testing.expectEqualStrings("", cfg.order_direction);

    // 非数字的 callback_concurrency 回落到默认值。
    const v2 = try json.parse(a, "{\"callback_concurrency\":\"lots\"}");
    const cfg2 = try Addition.parse(a, &v2);
    try testing.expectEqual(@as(i64, 1), cfg2.callback_concurrency);

    // 数字字符串是宽松接受的。
    const v3 = try json.parse(a, "{\"callback_concurrency\":\"8\"}");
    const cfg3 = try Addition.parse(a, &v3);
    try testing.expectEqual(@as(i64, 8), cfg3.callback_concurrency);
}

test "calPartSize thresholds match the upstream ladder" {
    try testing.expectEqual(@as(i64, 20 * mb), calPartSize(0));
    try testing.expectEqual(@as(i64, 20 * mb), calPartSize(20 * mb));
    try testing.expectEqual(@as(i64, 20 * mb), calPartSize(128 * gb)); // 不含等于
    try testing.expectEqual(@as(i64, 27487791), calPartSize(128 * gb + 1));
    try testing.expectEqual(@as(i64, 27487791), calPartSize(256 * gb));
    try testing.expectEqual(@as(i64, 41231687), calPartSize(256 * gb + 1));
    try testing.expectEqual(@as(i64, 54975582), calPartSize(384 * gb + 1));
    try testing.expectEqual(@as(i64, 82463373), calPartSize(512 * gb + 1));
    try testing.expectEqual(@as(i64, 109951163), calPartSize(768 * gb + 1));
    try testing.expectEqual(@as(i64, 5 * gb), calPartSize(1 * tb + 1));
}

test "calPartSize keeps a 1TB file inside 10000 parts" {
    // 上游注释说 20MB × 10000 ≈ 195GB；阶梯的作用就是保证 1TB 也切得下。
    const tb1 = 1 * tb;
    const parts = @divTrunc(tb1 + calPartSize(tb1) - 1, calPartSize(tb1));
    try testing.expect(parts <= 10_000);
}

test "getProofRange seeds off the access token and clamps at EOF" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 向量由 Python 的 hashlib 独立算出：
    //   md5("test_token") = c452458f4e50cdf9c8a1338016a6289d
    //   前 16 位 c452458f4e50cdf9 = 14146445861320707577，% 1000 = 577
    try testing.expectEqual(@as(i64, 14146445861320707577 % 1000), (try getProofRange(a, "test_token", 1000)).start);
    const r = try getProofRange(a, "test_token", 1000);
    try testing.expectEqual(@as(i64, 577), r.start);
    try testing.expectEqual(@as(i64, 585), r.end);

    // 贴边：start+8 超过文件尾时 End 被夹到 size。
    const small = try getProofRange(a, "test_token", 4);
    try testing.expectEqual(@as(i64, 1), small.start);
    try testing.expectEqual(@as(i64, 4), small.end);

    // size == 8 时 start+8 == size，End 也夹到 8（区间长度 7）。
    const eight = try getProofRange(a, "test_token", 8);
    try testing.expectEqual(@as(i64, 1), eight.start);
    try testing.expectEqual(@as(i64, 8), eight.end);

    // 0 字节文件：空区间，不是错误。
    const zero = try getProofRange(a, "test_token", 0);
    try testing.expectEqual(@as(i64, 0), zero.start);
    try testing.expectEqual(@as(i64, 0), zero.end);

    // 另一个种子，确认不是巧合。
    const other = try getProofRange(a, "abcdef", 1_000_000);
    try testing.expectEqual(@as(i64, 562364), other.start);
    try testing.expectEqual(@as(i64, 562372), other.end);

    // 区间永远落在文件里，且长度不超过 8。
    for ([_]i64{ 1, 2, 7, 9, 64, 4096, 1_000_000 }) |size| {
        const g = try getProofRange(a, "seed", size);
        try testing.expect(g.start >= 0);
        try testing.expect(g.end <= size);
        try testing.expect(g.end - g.start <= 8);
        try testing.expect(g.end >= g.start);
    }
}

test "proofCode base64s exactly the proof range" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const bytes = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var ms = MemSource{ .data = &bytes };
    const src = ms.source();

    const driver_inst = try createWithId(a, 0, null);
    driver_inst.cfg.access_token = "test_token";

    // md5("test_token") 前 16 位对 8 取模是 1，区间 [1, 8) —— 7 个字节。
    try testing.expectEqualStrings("AQIDBAUGBw==", try driver_inst.proofCode(a, src));

    // 0 字节文件 → 空串。
    var empty = MemSource{ .data = &.{} };
    try testing.expectEqualStrings("", try driver_inst.proofCode(a, empty.source()));
}

test "getSub reads the JWT payload with the standard (not URL-safe) alphabet" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // payload = {"sub":"abc123"} → base64 std 无 padding。
    const token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhYmMxMjMifQ.sig";
    try testing.expectEqualStrings("abc123", try getSub(a, token));

    // `////` 是**标准**字母表里合法的 base64（解码成 3 个 0xff 字节），
    // 但 URL-safe 字母表认不出 `/`。它解出来不是 JSON，所以结果是空串而
    // **不是错误** —— 这正好把「用的是标准字母表」钉死。
    try testing.expectEqualStrings("", try getSub(a, "a.////.b"));

    // 反过来，`_` 是 URL-safe 专有的，标准字母表必须拒绝。
    try testing.expectError(Error.NotJwt, getSub(a, "a.____.b"));

    // 段数不对。
    try testing.expectError(Error.NotJwt, getSub(a, "only.two"));
    try testing.expectError(Error.NotJwt, getSub(a, "a.b.c.d"));
    try testing.expectError(Error.NotJwt, getSub(a, ""));

    // 合法 base64 但 JSON 里没有 sub。
    try testing.expectEqualStrings("", try getSub(a, "a.eyJ4IjoxfQ.b"));

    // 非法字符（`@` 不在标准字母表里）必须报错。
    try testing.expectError(Error.NotJwt, getSub(a, "a.@@@@.b"));
    // 1 个字符的 payload：尾部 6 位多于一个字节能容纳的 4 位 → InvalidPadding。
    try testing.expectError(Error.NotJwt, getSub(a, "a.e.b"));
    // 注意 `a.eyJzdWIiOiJh.b` **不是**错误用例：12 个字符是合法的 base64
    // （正好 9 个字节），解出来只是 JSON 不完整，所以结果是空串。
    try testing.expectEqualStrings("", try getSub(a, "a.eyJzdWIiOiJh.b"));
}

test "writePartInfos numbers parts from 1" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var b = Buf.init(a);
    try writePartInfos(&b, 3);
    try testing.expectEqualStrings("[{\"part_number\":1},{\"part_number\":2},{\"part_number\":3}]", b.slice());

    // 0 片（空文件）是空数组，不是 null。
    var b0 = Buf.init(a);
    try writePartInfos(&b0, 0);
    try testing.expectEqualStrings("[]", b0.slice());
}

test "buildCreateBody emits the three rapid-upload shapes" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const self = try createWithId(a, 0, null);
    self.drive_id = "drv";
    const mtime = "2026-10-10T04:00:00.000Z";

    const plain = try AliyundriveOpen.buildCreateBody(self, a, "p1", "f.bin", 30, 2, mtime, .none, "", "");
    try testing.expectEqualStrings(
        "{\"drive_id\":\"drv\",\"parent_file_id\":\"p1\",\"name\":\"f.bin\",\"type\":\"file\"," ++
            "\"check_name_mode\":\"ignore\",\"local_modified_at\":\"2026-10-10T04:00:00.000Z\"," ++
            "\"local_created_at\":\"2026-10-10T04:00:00.000Z\"," ++
            "\"part_info_list\":[{\"part_number\":1},{\"part_number\":2}]}",
        plain,
    );

    const pre = try AliyundriveOpen.buildCreateBody(self, a, "p1", "f.bin", 30, 2, mtime, .pre_hash, "aabb", "");
    try testing.expect(std.mem.indexOf(u8, pre, "\"size\":30") != null);
    try testing.expect(std.mem.indexOf(u8, pre, "\"pre_hash\":\"aabb\"") != null);
    try testing.expect(std.mem.indexOf(u8, pre, "proof_version") == null);

    const proof = try AliyundriveOpen.buildCreateBody(self, a, "p1", "f.bin", 30, 2, mtime, .proof, "ccdd", "AAECAwQFBgc=");
    try testing.expect(std.mem.indexOf(u8, proof, "\"size\":30") != null);
    // 第二轮**不能**再带 pre_hash —— 上游是 delete(createData, "pre_hash")。
    try testing.expect(std.mem.indexOf(u8, proof, "pre_hash") == null);
    try testing.expect(std.mem.indexOf(u8, proof, "\"proof_version\":\"v1\"") != null);
    try testing.expect(std.mem.indexOf(u8, proof, "\"content_hash_name\":\"sha1\"") != null);
    try testing.expect(std.mem.indexOf(u8, proof, "\"content_hash\":\"ccdd\"") != null);
    try testing.expect(std.mem.indexOf(u8, proof, "\"proof_code\":\"AAECAwQFBgc=\"") != null);
}

test "parsePartInfos keeps order and tolerates missing fields" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const v = try json.parse(a,
        \\{"part_info_list":[
        \\  {"part_number":1,"upload_url":"https://u/1"},
        \\  {"part_number":2},
        \\  {"upload_url":"https://u/3"}
        \\ ]}
    );
    const parts = try parsePartInfos(a, arrAt(&v, "part_info_list"));
    try testing.expectEqual(@as(usize, 3), parts.len);
    try testing.expectEqual(@as(i64, 1), parts[0].number);
    try testing.expectEqualStrings("https://u/1", parts[0].upload_url);
    try testing.expectEqual(@as(i64, 2), parts[1].number);
    try testing.expectEqualStrings("", parts[1].upload_url);
    try testing.expectEqual(@as(i64, 0), parts[2].number);
    try testing.expectEqualStrings("https://u/3", parts[2].upload_url);

    // 缺字段 → 空表，而不是崩。
    const v2 = try json.parse(a, "{}");
    try testing.expectEqual(@as(usize, 0), (try parsePartInfos(a, arrAt(&v2, "part_info_list"))).len);
}

test "objFromJson maps the Aliyun file record" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const v = try json.parse(a,
        \\{"file_id":"fid","name":"movie.mkv","size":123,"type":"file",
        \\ "content_hash":"AABBCC","thumbnail":"https://t/x.jpg",
        \\ "created_at":"2026-10-10T04:00:00.000Z","updated_at":"2026-10-10T05:00:00Z"}
    );
    const o = objFromJson(&v);
    try testing.expectEqualStrings("movie.mkv", o.name);
    try testing.expectEqual(@as(i64, 123), o.size);
    try testing.expect(!o.is_dir);
    try testing.expectEqual(@as(i64, 1_791_604_800), o.created);
    try testing.expectEqual(@as(i64, 1_791_608_400), o.modified);
    try testing.expectEqualStrings("https://t/x.jpg", o.thumb);
    try testing.expectEqualStrings("sha1", o.hash_info.?.hash_name);
    try testing.expectEqualStrings("AABBCC", o.hash_info.?.hash_value);

    // 目录：type == "folder"；没有 content_hash 时不产生 hash_info。
    const d = try json.parse(a, "{\"name\":\"dir\",\"type\":\"folder\"}");
    const od = objFromJson(&d);
    try testing.expect(od.is_dir);
    try testing.expect(od.hash_info == null);
    try testing.expectEqual(@as(i64, 0), od.created);
    try testing.expectEqual(@as(i64, 0), od.modified);

    // 只有 file_name（create 的响应形状）。
    const n = try json.parse(a, "{\"file_name\":\"only.bin\",\"type\":\"file\"}");
    try testing.expectEqualStrings("only.bin", objFromJson(&n).name);
}

test "isLivp / lastSegment / parentOf" {
    try testing.expect(isLivp("a.LIVP"));
    try testing.expect(isLivp("IMG_0001.livp"));
    try testing.expect(!isLivp("a.livp.mp4"));
    try testing.expect(!isLivp("livp"));
    try testing.expect(!isLivp(""));

    try testing.expectEqualStrings("c", lastSegment("/a/b/c"));
    try testing.expectEqualStrings("c", lastSegment("a/b/c/"));
    try testing.expectEqualStrings("", lastSegment("/"));
    try testing.expectEqualStrings("", lastSegment(""));

    try testing.expectEqualStrings("/a/b", parentOf("/a/b/c"));
    try testing.expectEqualStrings("/", parentOf("/a"));
    try testing.expectEqualStrings("/", parentOf("/"));
    try testing.expectEqualStrings("/", parentOf(""));
}

test "replaceInternal rewrites only the known CDN prefix" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const url = "https://cn-beijing-data.aliyundrive.net/abc/def?x=1";
    try testing.expectEqualStrings(
        "http://ccp-bj29-bj-1592982087.oss-cn-beijing-internal.aliyuncs.com/abc/def?x=1",
        try replaceInternal(a, url),
    );

    // 不含前缀时原样返回（返回的是同一个 slice，没有多余分配）。
    const other = "https://example.test/abc";
    const out = try replaceInternal(a, other);
    try testing.expectEqualStrings(other, out);
    try testing.expect(out.ptr == other.ptr);
}

test "sha1HexOfSource hashes the whole source in one pass" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 1024 字节的 0..255 循环，SHA1 由 Python 独立算出。
    var data: [1024]u8 = undefined;
    for (&data, 0..) |*p, i| p.* = @intCast(i % 256);
    var ms = MemSource{ .data = &data };
    try testing.expectEqualStrings(
        "5b00669c480d5cffbdfa8bdba99561160f2d1b77",
        try sha1HexOfSource(a, ms.source()),
    );

    // 空源 → SHA1 of ""。
    var empty = MemSource{ .data = &.{} };
    try testing.expectEqualStrings(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        try sha1HexOfSource(a, empty.source()),
    );
}

test "the request rate limiter uses the documented intervals" {
    // 三档间隔直接对着官方文档：list 4/s、link 1/s、其它 15/s，上游各留了余量。
    try testing.expectEqual(@as(i64, 257), bucketIntervalMs(.list));
    try testing.expectEqual(@as(i64, 1112), bucketIntervalMs(.link));
    try testing.expectEqual(@as(i64, 68), bucketIntervalMs(.other));

    // link 桶必须比 list 桶稀疏 —— 这是文档里差异最大的一对。
    try testing.expect(bucketIntervalMs(.link) > bucketIntervalMs(.list));
    try testing.expect(bucketIntervalMs(.list) > bucketIntervalMs(.other));
}

test "createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const self = try createWithId(a, 7, null);
    try testing.expectEqual(@as(i64, 7), self.storage_id);
    try testing.expectEqualStrings("AliyundriveOpen", AliyundriveOpen.drvName(@ptrCast(self)));
    try testing.expectEqualStrings("default", self.eff_drive_type); // init 之前的初值
    // factory 的 key 必须和 Go 的 config.Name 逐字一致。
    try testing.expectEqualStrings("AliyundriveOpen", factory.key);
}
