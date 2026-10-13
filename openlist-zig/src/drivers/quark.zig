//! 夸克网盘开放平台驱动 —— Go 版 `drivers/quark_open` 的 Zig 移植。
//!
//! 与 `123_open` 相比，夸克多出来的难点集中在**上传前的 proof 校验**：
//!
//!   1. **`x-pan-token` 是路径相关的**。签名输入是
//!      `method + "&" + pathname + "&" + 毫秒时间戳 + "&" + signKey` 的 SHA-256，
//!      所以每次请求都要现算，而且**同一个 token 必须在同一次请求里用完**。
//!      上传预检尤其绕：`proof_seed1` 依赖 `x-pan-token`，而 `x-pan-token` 又是
//!      为 `/open/v1/file/upload_pre` 这条路径算的 —— 于是签名必须先生成、
//!      算完 proof、再带着**同一个**签名发请求。Go 版用一个可选的
//!      `manualSign` 变参绕过去，这里用一个显式的 `Sign` 结构体。
//!   2. **proof 是从文件里"抽查"出来的**。`getProofRange` 把 seed 的 MD5 前
//!      16 个十六进制字符当成一个 uint64，对文件大小取模得到起点，读 8 个字节
//!      base64 编码。这是纯函数 + 一次随机读，很好测。
//!   3. **错误码藏在 body 里**。HTTP 可能是 200，真正的判定是 body 的
//!      `status`/`errno`；token 过期有两条不同的码（`11001`，或 `14001` 且
//!      `error_info` 里含 `access_token`），必须都认。
//!
//! 与 Go 版的有意差异：
//!
//!   * **分片上传串行**（同 `123open.zig`）：本工程 HTTP 客户端有全局互斥锁。
//!   * **上传前必定本地算 MD5 + SHA1**（同一遍读）：`model.Source` 没有哈希。
//!   * **`space` 不提供**。Go 版也没有实现 `GetDetails`，vtable 里留 null，
//!     API 层会报零而不是报错 —— 这正是 `space` 设计成可选的原因。
//!   * **本地刷新 token 未实现**，与 Go 版一致（上游那里是 `TODO`）。
//!     只有在线 renewapi 一条路。
//!   * **`Link` 的 `Concurrency`/`PartSize` 字段未移植**：本工程的
//!     `model.Link` 没有这两个字段（代理下载的分片策略由下载端决定）。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const urlmod = @import("../util/url.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

const api_base = "https://open-api-drive.quark.cn";

/// 与 Go 版 `Conf.ua` 逐字一致。夸克会校验 UA 的形状。
const user_agent = "go-resty/3.0.0-beta.1 (https://resty.dev)";

/// 在线 renewapi 的默认地址，与 Go 版 `Addition.APIAddress` 的 default 一致。
const default_api_address = "https://api.oplist.org/quarkyun/renewapi";

const path_user_info = "/open/v1/user/info";
const path_file_list = "/open/v1/file/list";
const path_download_url = "/open/v1/file/get_download_url";
const path_mkdir = "/open/v1/dir";
const path_move = "/open/v1/file/move";
const path_rename = "/open/v1/file/rename";
const path_delete = "/open/v1/file/delete";
const path_upload_pre = "/open/v1/file/upload_pre";
const path_upload_urls = "/open/v1/file/get_upload_urls";
const path_upload_finish = "/open/v1/file/upload_finish";

/// 列表分页大小，Go 版写死 100。
const page_size: i64 = 100;
/// `file_type == "0"` 表示目录（是字符串，不是数字）。
const file_type_dir = "0";
/// proof 抽查的字节数。
const proof_span: i64 = 8;
/// 分片内存上限，服务端可控字段，防止畸形响应吃掉光猫的内存。
const max_part_bytes: i64 = 16 * 1024 * 1024;
/// 分片 PUT 的重试次数。对齐 Go drivers/quark_open/driver.go:223
/// （`retry.Attempts(3)`）；整次上传不该被一片的网络抖动报废。
const part_attempts: u32 = 3;

pub const Error = error{
    /// 拿不到 user_id，后续所有签名都依赖它。
    NoUserId,
    /// 没有可用的刷新方式（本地刷新上游也是 TODO）。
    NoRefreshMethod,
    UpstreamHttp,
    UpstreamNotJson,
    UpstreamError,
    InvalidResponse,
    /// 刷新过一轮仍然被判定为 token 过期。
    TokenExpired,
    BadPartSize,
    InvalidPath,
};

// ---------------------------------------------------------------------------
// 配置（对应 Go 的 Addition）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    root_folder_id: []const u8 = "0",
    order_by: []const u8 = "none",
    order_direction: []const u8 = "asc",
    use_online_api: bool = true,
    api_url_address: []const u8 = default_api_address,
    access_token: []const u8 = "",
    refresh_token: []const u8 = "",
    app_id: []const u8 = "",
    sign_key: []const u8 = "",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), "0");
        a.order_by = try dupeOr(alloc, o.strAt("order_by"), "none");
        a.order_direction = try dupeOr(alloc, o.strAt("order_direction"), "asc");
        if (boolAt(o, "use_online_api")) |b| a.use_online_api = b;
        a.api_url_address = try dupeOr(alloc, o.strAt("api_url_address"), default_api_address);
        a.access_token = try dupeOr(alloc, o.strAt("access_token"), "");
        a.refresh_token = try dupeOr(alloc, o.strAt("refresh_token"), "");
        a.app_id = try dupeOr(alloc, o.strAt("app_id"), "");
        a.sign_key = try dupeOr(alloc, o.strAt("sign_key"), "");
        return a;
    }

    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("root_folder_id", self.root_folder_id);
        try w.str("order_by", self.order_by);
        try w.str("order_direction", self.order_direction);
        try w.boolean("use_online_api", self.use_online_api);
        try w.str("api_url_address", self.api_url_address);
        try w.str("access_token", self.access_token);
        try w.str("refresh_token", self.refresh_token);
        try w.str("app_id", self.app_id);
        try w.str("sign_key", self.sign_key);
        try w.end();
        return b.toOwned();
    }

    /// `sort` 请求字段：`OrderBy != "none"` 时用 `字段:方向`，否则 `file_name:asc`。
    fn sortSpec(self: Addition, alloc: std.mem.Allocator) ![]const u8 {
        if (std.mem.eql(u8, self.order_by, "none")) return "file_name:asc";
        return std.fmt.allocPrint(alloc, "{s}:{s}", .{ self.order_by, self.order_direction });
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
// 签名
// ---------------------------------------------------------------------------

/// 一次请求用到的三个签名参数。
///
/// 单独成结构体是因为它们**必须一起用**：`x-pan-token` 的输入里有 pathname，
/// 而上传预检的 `proof_seed1` 又依赖这个 token，所以生成一次就得原样复用，
/// 不能在发请求时重新算一遍。
const Sign = struct {
    tm: []const u8 = "",
    token: []const u8 = "",
    req_id: []const u8 = "",
};

/// `x-pan-token = sha256hex(method + "&" + pathname + "&" + tm + "&" + signKey)`
///
/// `tm` 是 13 位毫秒时间戳，`req_id` 是 UUID v4。
fn generateSign(alloc: std.mem.Allocator, method: []const u8, pathname: []const u8, sign_key: []const u8, now_ms: i64, uuid: *const [16]u8) !Sign {
    const tm = try std.fmt.allocPrint(alloc, "{d}", .{now_ms});
    const material = try std.fmt.allocPrint(alloc, "{s}&{s}&{s}&{s}", .{ method, pathname, tm, sign_key });
    const token = try hash.sha256Hex(alloc, material);
    return .{
        .tm = tm,
        .token = token,
        .req_id = try formatUuid(alloc, uuid),
    };
}

/// UUID v4 的字符串形式（8-4-4-4-12，带中划线）。
///
/// Go 用 `uuid.NewRandom()`。这里按 RFC 4122 §4.4 手工设置版本位（高 4 位
/// 置 0100）与变体位（高 2 位置 10）—— `req_id` 只被当成不透明去重标识，
/// 但既然要叫 UUID 就按规范生成，免得服务端哪天真的去解析它。
fn formatUuid(alloc: std.mem.Allocator, raw: *const [16]u8) ![]u8 {
    var b = raw.*;
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant 10xx

    const hex = std.fmt.bytesToHex(b, .lower);
    return std.fmt.allocPrint(alloc, "{s}-{s}-{s}-{s}-{s}", .{
        hex[0..8], hex[8..12], hex[12..16], hex[16..20], hex[20..32],
    });
}

// ---------------------------------------------------------------------------
// proof 校验（纯函数 + 一次随机读）
// ---------------------------------------------------------------------------

const ProofRange = struct { start: i64, end: i64 };

/// `md5hex(seed)` 的前 16 个十六进制字符当 uint64，对文件大小取模得到起点，
/// 再往后 8 个字节（不越过文件尾）。
///
/// 文件大小为 0 时返回空区间 —— 调用方据此返回空字符串，而不是报错。
fn getProofRange(alloc: std.mem.Allocator, proof_seed: []const u8, file_size: i64) !ProofRange {
    if (file_size <= 0) return .{ .start = 0, .end = 0 };

    const digest = try hash.md5Hex(alloc, proof_seed);
    defer alloc.free(digest);
    const prefix = digest[0..16];

    const v = std.fmt.parseInt(u64, prefix, 16) catch return .{ .start = 0, .end = 0 };
    const index: i64 = @intCast(v % @as(u64, @intCast(file_size)));

    return .{ .start = index, .end = @min(index + proof_span, file_size) };
}

/// 读出区间并 base64。区间长度为 0 时返回空串（与 Go 一致）。
fn proofCode(alloc: std.mem.Allocator, src: model.Source, proof_seed: []const u8, file_size: i64) ![]u8 {
    const range = try getProofRange(alloc, proof_seed, file_size);
    const len = range.end - range.start;
    if (len <= 0) return alloc.dupe(u8, "");
    const data = try src.readAll(alloc, @intCast(range.start), @intCast(len));
    return hash.base64Std(alloc, data);
}

const Proof = struct {
    version: []const u8,
    seed1: []const u8,
    seed2: []const u8,
    code1: []const u8,
    code2: []const u8,
};

fn generateProof(alloc: std.mem.Allocator, src: model.Source, user_id: []const u8, x_pan_token: []const u8, file_size: i64) !Proof {
    // seed1 = md5hex(userId + x-pan-token)
    const s1_material = try std.fmt.allocPrint(alloc, "{s}{s}", .{ user_id, x_pan_token });
    const seed1 = try hash.md5Hex(alloc, s1_material);

    // seed2 = md5hex(十进制文件大小)
    const size_str = try std.fmt.allocPrint(alloc, "{d}", .{file_size});
    const seed2 = try hash.md5Hex(alloc, size_str);

    return .{
        .version = "v1",
        .seed1 = seed1,
        .seed2 = seed2,
        .code1 = try proofCode(alloc, src, seed1, file_size),
        .code2 = try proofCode(alloc, src, seed2, file_size),
    };
}

/// 分片表的一项。
///
/// 必须是有名类型：Zig 里写在函数签名中的匿名 struct 每次出现都是**不同的
/// 类型**，`List(struct{...})` 和返回类型 `[]struct{...}` 之间没法转换。
const PartInfo = struct { number: i64, size: i64 };

/// 分片表：`part_number` 从 1 开始，每片 `part_size`，最后一片是余数。
fn buildPartInfo(alloc: std.mem.Allocator, total: i64, part_size: i64) ![]PartInfo {
    var out = List(PartInfo).init(alloc);
    if (part_size <= 0 or total <= 0) return out.toOwned();

    var left = total;
    var number: i64 = 1;
    while (left > 0) : (number += 1) {
        const size = @min(part_size, left);
        try out.append(.{ .number = number, .size = size });
        left -= size;
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// 驱动本体
// ---------------------------------------------------------------------------

pub const QuarkOpen = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    /// `Init` 时取到的用户 ID。`proof_seed1` 要用它，所有签名都间接依赖。
    user_id: []const u8 = "",
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
        // space 留空：上游没有 GetDetails，报零比编一个数字诚实。
    };

    fn drvName(_: *anyopaque) []const u8 {
        return "QuarkOpen";
    }

    fn as(ptr: *anyopaque) *QuarkOpen {
        return @ptrCast(@alignCast(ptr));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        _ = ctx;

        if (self.cfg.refresh_token.len == 0 and self.cfg.access_token.len == 0) {
            log.err("[quark] 需要 RefreshToken（推荐）或 AccessToken", .{});
            return Error.InvalidResponse;
        }

        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const body = try self.request(a, path_user_info, "GET", null, .{}, false);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const uid = v.strAt("data.user_id") orelse "";
        if (uid.len == 0) return Error.NoUserId;

        self.user_id = try self.alloc.dupe(u8, uid);
        log.info("[quark] ready: user_id={s} root={s}", .{ self.user_id, self.cfg.root_folder_id });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        self.save();
    }

    fn save(self: *QuarkOpen) void {
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

    /// 发一次请求。
    ///
    /// `sign` 为空（`.{}`）时按 `method`/`pathname` 现算签名；上传预检会传入
    /// 自己算好的那份，因为 proof 依赖它。
    ///
    /// `retried` 用于保证 token 过期只重试一轮 —— Go 版靠递归，理论上可以
    /// 无限套娃（每次刷新都失败的话）；这里显式收口。
    fn request(
        self: *QuarkOpen,
        arena: std.mem.Allocator,
        pathname: []const u8,
        method: []const u8,
        body: ?[]const u8,
        sign_in: Sign,
        retried: bool,
    ) ![]const u8 {
        var sign = sign_in;
        if (sign.token.len == 0) {
            var uuid: [16]u8 = undefined;
            rt.io().random(&uuid);
            sign = try generateSign(arena, method, pathname, self.cfg.sign_key, rt.nowMillis(), &uuid);
        }

        const query = try buildQuery(arena, &.{
            .{ "req_id", sign.req_id },
            .{ "access_token", self.cfg.access_token },
        });
        const url = try std.fmt.allocPrint(arena, "{s}{s}?{s}", .{ api_base, pathname, query });

        const res = try self.client.send(arena, .{
            .method = method,
            .url = url,
            .headers = &.{
                .{ .name = "Accept", .value = "application/json, text/plain, */*" },
                .{ .name = "User-Agent", .value = user_agent },
                .{ .name = "x-pan-tm", .value = sign.tm },
                .{ .name = "x-pan-token", .value = sign.token },
                .{ .name = "x-pan-client-id", .value = self.cfg.app_id },
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .body = body orelse "",
        });

        const v = json.parse(arena, res.body) catch {
            log.warn("[quark] {s} non-JSON (HTTP {d}): {s}", .{
                pathname, res.status, res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamNotJson;
        };

        const status = v.intAt("status") orelse 0;
        const errno = v.intAt("errno") orelse 0;
        const info = v.strAt("error_info") orelse "";

        // token 过期的两条判定，与 Go 版逐字一致：
        //   status == -1 && (errno == 11001 || (errno == 14001 && error_info 含 "access_token"))
        // 第二条的存在说明夸克在不同接口上用了不同的码，少认一条就会在某个
        // 具体操作上永远失败。
        const expired = status == -1 and
            (errno == 11001 or (errno == 14001 and std.mem.indexOf(u8, info, "access_token") != null));
        if (expired) {
            if (retried) return Error.TokenExpired;
            log.info("[quark] access_token expired (errno={d}), refreshing", .{errno});
            try self.refreshToken(arena);
            return self.request(arena, pathname, method, body, .{}, true);
        }

        if (status >= 400 or errno != 0) {
            log.warn("[quark] {s} status={d} errno={d} info={s}", .{ pathname, status, errno, info });
            return Error.UpstreamError;
        }
        return res.body;
    }

    fn postJson(self: *QuarkOpen, arena: std.mem.Allocator, pathname: []const u8, body: []const u8) ![]const u8 {
        return self.request(arena, pathname, "POST", body, .{}, false);
    }

    /// 在线 renewapi 续期。Go 版重试 3 次，这里同样。
    fn refreshToken(self: *QuarkOpen, arena: std.mem.Allocator) !void {
        self.refresh_mu.lockUncancelable(rt.io());
        defer self.refresh_mu.unlock(rt.io());

        if (!self.cfg.use_online_api or self.cfg.api_url_address.len == 0) {
            // 上游的本地刷新也是 TODO，没有第二条路。
            log.err("[quark] 本地刷新 token 未实现，请开启 use_online_api", .{});
            return Error.NoRefreshMethod;
        }

        const query = try buildQuery(arena, &.{
            .{ "refresh_ui", self.cfg.refresh_token },
            .{ "server_use", "true" },
            .{ "driver_txt", "quarkyun_oa" },
        });
        const url = try std.fmt.allocPrint(arena, "{s}?{s}", .{ self.cfg.api_url_address, query });

        var last_err: anyerror = Error.UpstreamHttp;
        for (0..3) |attempt| {
            if (attempt > 0) rt.sleepMillis(1000);
            const res = self.client.send(arena, .{ .method = "GET", .url = url }) catch |e| {
                last_err = e;
                continue;
            };
            if (res.status != 200) {
                last_err = Error.UpstreamHttp;
                continue;
            }
            const v = json.parse(arena, res.body) catch {
                last_err = Error.UpstreamNotJson;
                continue;
            };
            const refresh = v.strAt("refresh_token") orelse "";
            const access = v.strAt("access_token") orelse "";
            if (refresh.len == 0 or access.len == 0) {
                const msg = v.strAt("text") orelse "";
                log.warn("[quark] renewapi returned no token: {s}", .{msg});
                last_err = Error.UpstreamError;
                continue;
            }

            const new_rt = try self.alloc.dupe(u8, refresh);
            const new_at = try self.alloc.dupe(u8, access);
            if (self.cfg.refresh_token.len > 0) self.alloc.free(self.cfg.refresh_token);
            if (self.cfg.access_token.len > 0) self.alloc.free(self.cfg.access_token);
            self.cfg.refresh_token = new_rt;
            self.cfg.access_token = new_at;
            self.save();
            log.info("[quark] token refreshed", .{});
            return;
        }
        return last_err;
    }

    // -----------------------------------------------------------------------
    // 路径 → fid
    // -----------------------------------------------------------------------

    const Entry = struct {
        id: []const u8,
        name: []const u8,
        is_dir: bool,
        raw: ?*const json.Value = null,
    };

    /// 夸克和 123pan 一样只认 ID，所以同样要逐级列目录。
    fn resolveEntry(self: *QuarkOpen, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    fn findChild(self: *QuarkOpen, arena: std.mem.Allocator, parent_fid: []const u8, name: []const u8) !Entry {
        var cursor_version: []const u8 = "";
        var cursor_token: []const u8 = "";
        while (true) {
            const body = try self.listPage(arena, parent_fid, cursor_version, cursor_token);
            const v = json.parse(arena, body) catch return Error.UpstreamNotJson;

            const children = arrAt(&v, "data.file_list");
            for (children, 0..) |_, i| {
                const item = &children[i];
                const fn_ = item.strAt("filename") orelse continue;
                if (!std.mem.eql(u8, fn_, name)) continue;
                const fid = item.strAt("fid") orelse return Error.InvalidResponse;
                return .{
                    .id = fid,
                    .name = fn_,
                    .is_dir = std.mem.eql(u8, item.strAt("file_type") orelse "", file_type_dir),
                    .raw = item,
                };
            }
            if (boolOr(&v, "data.last_page")) return driver.Error.NotFound;
            cursor_version = v.strAt("data.next_query_cursor.version") orelse "";
            cursor_token = v.strAt("data.next_query_cursor.token") orelse "";
            if (cursor_token.len == 0) return driver.Error.NotFound;
        }
    }

    fn listPage(
        self: *QuarkOpen,
        arena: std.mem.Allocator,
        parent_fid: []const u8,
        cursor_version: []const u8,
        cursor_token: []const u8,
    ) ![]const u8 {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("parent_fid", parent_fid);
        try w.int("size", page_size);
        try w.str("sort", try self.cfg.sortSpec(arena));
        if (cursor_token.len > 0) {
            try w.key("query_cursor");
            var inner = ObjWriter{ .b = &b };
            try inner.begin();
            try inner.str("version", cursor_version);
            try inner.str("token", cursor_token);
            try inner.end();
        }
        try w.end();
        return self.postJson(arena, path_file_list, b.slice());
    }

    fn listAll(self: *QuarkOpen, arena: std.mem.Allocator, parent_fid: []const u8) ![]model.Obj {
        var out = List(model.Obj).init(arena);
        var cursor_version: []const u8 = "";
        var cursor_token: []const u8 = "";
        while (true) {
            const body = try self.listPage(arena, parent_fid, cursor_version, cursor_token);
            const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
            for (arrAt(&v, "data.file_list")) |item| try out.append(objFromJson(&item));
            if (boolOr(&v, "data.last_page")) break;
            cursor_version = v.strAt("data.next_query_cursor.version") orelse "";
            cursor_token = v.strAt("data.next_query_cursor.token") orelse "";
            if (cursor_token.len == 0) break;
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
        return .{
            .name = o.name,
            .size = o.size,
            .is_dir = o.is_dir,
            .modified = o.modified,
            .created = o.created,
            .thumb = o.thumb,
        };
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = args;

        const entry = try self.resolveEntry(a, path);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("fid", entry.id);
        try w.end();

        const body = try self.postJson(a, path_download_url, b.slice());
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const url = v.strAt("data.download_url") orelse return Error.InvalidResponse;

        // 下载 URL 指向 CDN，需要带上身份 cookie 才认；且必须走代理（Go
        // meta.go:32 的 OnlyProxy），否则 api.zig 会 302 出去把 Cookie 丢掉。
        const cookie = try std.fmt.allocPrint(a, "x_pan_client_id={s}; x_pan_access_token={s}", .{
            self.cfg.app_id, self.cfg.access_token,
        });
        return linkResult(a, url, cookie);
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
        try w.str("dir_path", name);
        try w.str("pdir_fid", parent.id);
        try w.end();
        _ = try self.postJson(a, path_mkdir, b.slice());
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const s = try self.resolveEntry(a, src);
        const d = try self.resolveEntry(a, dst_dir);

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.int("action_type", 1);
        // 上游是 base.Json{"fid_list": []string{srcObj.GetID()}} —— 字符串数组，
        // 而 to_pdir_fid 是单个字符串 fid（夸克的 fid 不是数字）。
        try w.key("fid_list");
        try b.appendByte('[');
        try json.writeString(&b, s.id);
        try b.appendByte(']');
        try w.str("to_pdir_fid", d.id);
        try w.end();
        _ = try self.postJson(a, path_move, b.slice());
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        if (new_name.len == 0) return Error.InvalidPath;

        const s = try self.resolveEntry(a, src);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("fid", s.id);
        try w.str("file_name", new_name);
        try w.str("conflict_mode", "REUSE");
        try w.end();
        _ = try self.postJson(a, path_rename, b.slice());
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = is_dir; // 夸克的删除接口对文件和目录是同一个

        const s = try self.resolveEntry(a, path);
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.int("action_type", 1);
        try w.key("fid_list");
        try json.writeString(&b, s.id);
        try w.end();
        _ = try self.postJson(a, path_delete, b.slice());
    }

    // -----------------------------------------------------------------------
    // 上传：proof 预检 → 取分片 URL → 逐片 PUT → finish
    // -----------------------------------------------------------------------

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dst);
        if (name.len == 0) return Error.InvalidPath;
        const dst_dir = try self.resolveEntry(a, parentOf(dst));
        const size = src.size();
        if (size < 0) return Error.InvalidPath;

        const hashes = try hashSource(a, src);
        const md5_hex = try hash.hexLower(a, &hashes.md5);
        const sha1_hex = try hash.hexLower(a, &hashes.sha1);

        // 1. 预检。签名要先算好，因为 proof_seed1 依赖 x-pan-token。
        var uuid: [16]u8 = undefined;
        rt.io().random(&uuid);
        const sign = try generateSign(a, "POST", path_upload_pre, self.cfg.sign_key, rt.nowMillis(), &uuid);
        const proof = try generateProof(a, src, self.user_id, sign.token, size);

        var pre_body = Buf.init(a);
        var w = ObjWriter{ .b = &pre_body };
        try w.begin();
        try w.str("file_name", name);
        try w.int("size", size);
        try w.str("format_type", mimeFor(name));
        try w.str("md5", md5_hex);
        try w.str("sha1", sha1_hex);
        try w.int("l_created_at", rt.nowMillis());
        try w.int("l_updated_at", rt.nowMillis());
        try w.str("pdir_fid", dst_dir.id);
        try w.boolean("same_path_reuse", true);
        try w.str("proof_version", proof.version);
        try w.str("proof_seed1", proof.seed1);
        try w.str("proof_seed2", proof.seed2);
        try w.str("proof_code1", proof.code1);
        try w.str("proof_code2", proof.code2);
        try w.end();

        const pre_raw = try self.request(a, path_upload_pre, "POST", pre_body.slice(), sign, false);
        const pre = json.parse(a, pre_raw) catch return Error.UpstreamNotJson;

        // 秒传命中
        if (boolOr(&pre, "data.finish")) {
            log.info("[quark] {s}: instant-upload hit", .{name});
            return;
        }

        const task_id = pre.strAt("data.task_id") orelse return Error.InvalidResponse;
        const part_size = pre.intAt("data.part_size") orelse 0;
        if (part_size <= 0 or part_size > max_part_bytes) {
            log.warn("[quark] server asked for part_size={d}", .{part_size});
            return Error.BadPartSize;
        }

        // 2. 取分片上传地址
        const parts = try buildPartInfo(a, size, part_size);
        var urls_body = Buf.init(a);
        var uw = ObjWriter{ .b = &urls_body };
        try uw.begin();
        try uw.str("task_id", task_id);
        try uw.key("part_info_list");
        try writePartInfoList(&urls_body, parts, null);
        try uw.end();

        const urls_raw = try self.postJson(a, path_upload_urls, urls_body.slice());
        const urls = json.parse(a, urls_raw) catch return Error.UpstreamNotJson;

        const upload_urls = arrAt(&urls, "data.upload_urls");
        if (upload_urls.len != parts.len) {
            log.warn("[quark] {d} parts but {d} upload urls", .{ parts.len, upload_urls.len });
            return Error.InvalidResponse;
        }
        const common_sha = urls.strAt("data.common_headers.X-Oss-Content-Sha256") orelse "";
        const common_date = urls.strAt("data.common_headers.X-Oss-Date") orelse "";

        // 3. 逐片 PUT。串行，见文件头。
        // T7：整份上传复用同一个分片缓冲（旧代码每片 readAll 新分配，
        //  arena 随文件大小线性增长）。下面的 send 是同步的。
        const chunk_buf = try a.alloc(u8, @intCast(part_size));
        const etags = try a.alloc([]const u8, parts.len);
        for (parts, 0..) |part, i| {
            const offset: u64 = @intCast(part.number - 1);
            const start: u64 = @intCast(offset * @as(u64, @intCast(part_size)));
            const data = chunk_buf[0..@intCast(part.size)];
            try src.readAllInto(start, data);

            const put_url = upload_urls[i].strAt("upload_url") orelse return Error.InvalidResponse;
            const signature = upload_urls[i].strAt("signature_info.signature") orelse "";

            // 对齐 Go drivers/quark_open/driver.go:213-229：3 次重试 + 退避。
            // 失败仍然直接返回（不回滚）—— Go 版同样不清理已上传的分片。
            var attempt: u32 = 0;
            while (true) {
                attempt += 1;
                if (attempt > 1) rt.sleepMillis(partRetryDelayMs(attempt));
                const res = self.client.send(a, .{
                    .method = "PUT",
                    .url = put_url,
                    .headers = &.{
                        .{ .name = "Authorization", .value = signature },
                        .{ .name = "X-Oss-Date", .value = common_date },
                        .{ .name = "X-Oss-Content-Sha256", .value = common_sha },
                        .{ .name = "Accept-Encoding", .value = "gzip" },
                        .{ .name = "User-Agent", .value = "Go-http-client/1.1" },
                    },
                    .body = data,
                }) catch |e| {
                    log.warn("[quark] part {d}/{d} send failed: {s}", .{ part.number, parts.len, @errorName(e) });
                    if (attempt >= part_attempts) return e;
                    continue;
                };
                if (res.status != 200) {
                    log.warn("[quark] part {d}/{d} HTTP {d}: {s}", .{
                        part.number, parts.len, res.status, res.body[0..@min(res.body.len, 200)],
                    });
                    if (attempt >= part_attempts) return Error.UpstreamHttp;
                    continue;
                }
                // ETag 是 finish 阶段的必填项，缺了就没法提交。
                const etag = res.header("Etag") orelse res.header("ETag") orelse "";
                if (etag.len == 0) {
                    log.warn("[quark] part {d} returned no ETag", .{part.number});
                    if (attempt >= part_attempts) return Error.InvalidResponse;
                    continue;
                }
                etags[i] = etag;
                break;
            }
        }

        // 4. finish
        var fin_body = Buf.init(a);
        var fw = ObjWriter{ .b = &fin_body };
        try fw.begin();
        try fw.str("task_id", task_id);
        try fw.key("part_info_list");
        try writePartInfoList(&fin_body, parts, etags);
        try fw.end();

        const fin_raw = try self.postJson(a, path_upload_finish, fin_body.slice());
        const fin = json.parse(a, fin_raw) catch return Error.UpstreamNotJson;
        if (!boolOr(&fin, "data.finish")) {
            log.warn("[quark] upload_finish returned finish=false, task_id={s}", .{task_id});
            return Error.UpstreamError;
        }
    }
};

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

/// Go 的 resty `SetQueryParams` 走 `url.Values.Encode()`：按 key 排序 +
/// `QueryEscape`（空格 → `+`）。token 里出现 `+`/`&` 时裸拼会被服务端解错，
/// 所以这里必须编码。对齐 Go drivers/quark_open/util.go:51-54,442-449。
fn buildQuery(alloc: std.mem.Allocator, pairs: []const [2][]const u8) ![]const u8 {
    var q = urlmod.Query.init(alloc);
    try q.addSorted(pairs);
    // `q` 是栈上的 Query，但它的字节缓冲是 `alloc` 分配的堆内存；返回的切片
    // 在分配器生命周期内有效。调用方都只读，不需要可写切片。
    return q.slice();
}

/// Go 的 `retry.BackOffDelay`（drivers/quark_open/driver.go:224）：第 1 次不
/// 等，之后按 1s、2s、4s 翻倍。
fn partRetryDelayMs(attempt: u32) u32 {
    if (attempt <= 1) return 0;
    return 1000 * (@as(u32, 1) << @intCast(attempt - 2));
}

/// Go 的 `driver.Config.OnlyProxy`（drivers/quark_open/meta.go:32）：直链必须
/// 经服务端代理 —— CDN 靠 `Cookie` 头认身份，302 给浏览器会把头丢掉。
/// 抽成纯函数是为了能直接断言，`link()` 本身要联网。
fn linkResult(alloc: std.mem.Allocator, url: []const u8, cookie: []const u8) !model.Link {
    // `header` 必须是分配器拥有的切片。原先这里写 `&.{.{...}}`，那个数组字面量
    // 落在 `linkResult` 自己的栈帧里，函数一返回 `Link.header` 就悬空 ——
    // 单元测试里表现为 `lk.header[0]` 解引用段错误，生产里就是代理下载拿到
    // 一段垃圾头（Cookie 丢失 → CDN 拒绝）。
    const hdrs = try alloc.alloc(model.Header, 1);
    hdrs[0] = .{ .name = "Cookie", .value = cookie };
    return .{
        .url = url,
        .header = hdrs,
        .proxy = true,
    };
}

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

/// 时间戳是**毫秒**（`time.UnixMilli`），不是秒。
fn objFromJson(item: *const json.Value) model.Obj {
    const ms_to_s = struct {
        fn f(ms: i64) i64 {
            return @divTrunc(ms, 1000);
        }
    }.f;
    return .{
        .name = item.strAt("filename") orelse "",
        .size = item.intAt("size") orelse 0,
        .is_dir = std.mem.eql(u8, item.strAt("file_type") orelse "", file_type_dir),
        .modified = ms_to_s(item.intAt("updated_at") orelse 0),
        .created = ms_to_s(item.intAt("created_at") orelse 0),
        .thumb = item.strAt("thumbnail_url") orelse "",
    };
}

/// 把 `part_info_list` 写进当前的 JSON 对象值位置。
///
/// `etags` 为 null 时写 `{part_number, part_size}`（取上传地址阶段用），
/// 非 null 时补上 `etag`（finish 阶段用）。两个阶段的字段集只差这一个，
/// 用同一个函数保证 `part_number`/`part_size` 一定一致 —— Go 版是手抄两遍的。
fn writePartInfoList(b: *Buf, parts: []const PartInfo, etags: ?[]const []const u8) !void {
    try b.appendByte('[');
    for (parts, 0..) |part, i| {
        if (i > 0) try b.appendByte(',');
        try b.appendByte('{');
        try b.append("\"part_number\":");
        try b.print("{d}", .{part.number});
        try b.append(",\"part_size\":");
        try b.print("{d}", .{part.size});
        if (etags) |es| {
            try b.append(",\"etag\":");
            try json.writeString(b, es[i]);
        }
        try b.appendByte('}');
    }
    try b.appendByte(']');
}

/// 上传时声明的 MIME。Go 用 `file.GetMimetype()`，本工程的 `model.Source`
/// 不带 MIME，所以按扩展名推一个。夸克只用它做分类，推错不影响上传本身。
fn mimeFor(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "application/octet-stream";
    const ext = name[dot + 1 ..];
    const table = .{
        .{ "mp4", "video/mp4" },
        .{ "mkv", "video/x-matroska" },
        .{ "avi", "video/x-msvideo" },
        .{ "mp3", "audio/mpeg" },
        .{ "flac", "audio/flac" },
        .{ "jpg", "image/jpeg" },
        .{ "jpeg", "image/jpeg" },
        .{ "png", "image/png" },
        .{ "gif", "image/gif" },
        .{ "webp", "image/webp" },
        .{ "pdf", "application/pdf" },
        .{ "zip", "application/zip" },
        .{ "rar", "application/vnd.rar" },
        .{ "7z", "application/x-7z-compressed" },
        .{ "txt", "text/plain" },
        .{ "json", "application/json" },
        .{ "apk", "application/vnd.android.package-archive" },
        .{ "iso", "application/x-iso9660-image" },
    };
    inline for (table) |entry| {
        if (std.ascii.eqlIgnoreCase(ext, entry[0])) return entry[1];
    }
    return "application/octet-stream";
}

/// 一遍读里把 MD5 和 SHA1 都算出来（`123open.zig` 里是 SHA1+MD5，同样思路）。
fn hashSource(arena: std.mem.Allocator, src: model.Source) !struct { md5: [16]u8, sha1: [20]u8 } {
    var md5s = hash.Md5Stream{};
    var sha = hash.Sha1Stream{};

    const size = src.size();
    if (size < 0) return error.UnexpectedEof;

    const buf = try arena.alloc(u8, 128 * 1024);
    var offset: u64 = 0;
    const total: u64 = @intCast(size);
    while (offset < total) {
        const want: usize = @intCast(@min(@as(u64, buf.len), total - offset));
        const n = try src.readAt(offset, buf[0..want]);
        if (n == 0) return error.UnexpectedEof;
        md5s.update(buf[0..n]);
        sha.update(buf[0..n]);
        offset += n;
    }
    return .{ .md5 = md5s.final(), .sha1 = sha.final() };
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "QuarkOpen",
    .label = "夸克网盘开放平台",
    .secrets = &.{ "access_token", "refresh_token", "app_id", "sign_key" },
    .addition_schema =
    \\{
    \\  "root_folder_id":  {"type":"string","default":"0","help":"根目录 fid，夸克的根是 0"},
    \\  "order_by":        {"type":"select","default":"none","options":["none","file_type","file_name","updated_at","created_at"],"help":"排序字段"},
    \\  "order_direction": {"type":"select","default":"asc","options":["asc","desc"],"help":"排序方向"},
    \\  "use_online_api":  {"type":"bool","default":true,"help":"用第三方 renewapi 续期 token"},
    \\  "api_url_address": {"type":"string","default":"https://api.oplist.org/quarkyun/renewapi","help":"renewapi 地址"},
    \\  "access_token":    {"type":"string","required":false,"secret":true,"help":"可留空，由 refresh_token 换得"},
    \\  "refresh_token":   {"type":"string","required":true,"secret":true,"help":"必填"},
    \\  "app_id":          {"type":"string","required":false,"secret":true,"help":"开放平台 app_id，没有就留空"},
    \\  "sign_key":        {"type":"string","required":false,"secret":true,"help":"开放平台 sign_key，没有就留空"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(QuarkOpen, self);
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*QuarkOpen {
    const self = try alloc.create(QuarkOpen);
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

test "addition round-trips through JSON with the Go field names" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const text =
        \\{"root_folder_id":"7","order_by":"updated_at","order_direction":"desc",
        \\ "use_online_api":false,"api_url_address":"https://x/y","access_token":"at",
        \\ "refresh_token":"rt","app_id":"app","sign_key":"sk"}
    ;
    const v = try json.parse(a, text);
    const p = try Addition.parse(a, &v);

    try testing.expectEqualStrings("7", p.root_folder_id);
    try testing.expectEqualStrings("updated_at", p.order_by);
    try testing.expectEqualStrings("desc", p.order_direction);
    try testing.expect(!p.use_online_api);
    try testing.expectEqualStrings("https://x/y", p.api_url_address);
    try testing.expectEqualStrings("at", p.access_token);
    try testing.expectEqualStrings("rt", p.refresh_token);
    try testing.expectEqualStrings("app", p.app_id);
    try testing.expectEqualStrings("sk", p.sign_key);

    const out = try p.toJson(a);
    for ([_][]const u8{
        "\"root_folder_id\"",  "\"order_by\"",       "\"order_direction\"",
        "\"use_online_api\"",  "\"api_url_address\"", "\"access_token\"",
        "\"refresh_token\"",   "\"app_id\"",          "\"sign_key\"",
    }) |key| {
        try testing.expect(std.mem.indexOf(u8, out, key) != null);
    }
}

test "addition defaults and sortSpec" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const d = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", d.root_folder_id);
    try testing.expectEqualStrings("none", d.order_by);
    try testing.expectEqualStrings("asc", d.order_direction);
    try testing.expectEqualStrings(default_api_address, d.api_url_address);

    // order_by == "none" 时用固定排序，不拼 "none:asc"
    try testing.expectEqualStrings("file_name:asc", try d.sortSpec(a));

    var custom = d;
    custom.order_by = "updated_at";
    custom.order_direction = "desc";
    try testing.expectEqualStrings("updated_at:desc", try custom.sortSpec(a));
}

test "generateSign hashes method&pathname&tm&signKey" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const uuid: [16]u8 = @splat(0);
    const sign = try generateSign(a, "POST", "/open/v1/file/list", "SIGNKEY", 1_800_000_000_000, &uuid);

    try testing.expectEqualStrings("1800000000000", sign.tm);
    // 手工算一遍 sha256("POST&/open/v1/file/list&1800000000000&SIGNKEY")
    const expected = try hash.sha256Hex(a, "POST&/open/v1/file/list&1800000000000&SIGNKEY");
    try testing.expectEqualStrings(expected, sign.token);
    try testing.expectEqual(@as(usize, 64), sign.token.len);

    // 路径变了 token 必须变 —— 这正是它不能复用的原因。
    const other = try generateSign(a, "POST", "/open/v1/file/upload_pre", "SIGNKEY", 1_800_000_000_000, &uuid);
    try testing.expect(!std.mem.eql(u8, sign.token, other.token));

    // 方法变了也要变
    const get = try generateSign(a, "GET", "/open/v1/file/list", "SIGNKEY", 1_800_000_000_000, &uuid);
    try testing.expect(!std.mem.eql(u8, sign.token, get.token));
}

test "formatUuid produces an RFC 4122 v4 string" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const zero: [16]u8 = @splat(0);
    const s = try formatUuid(a, &zero);
    try testing.expectEqual(@as(usize, 36), s.len);
    try testing.expectEqual(@as(u8, '-'), s[8]);
    try testing.expectEqual(@as(u8, '-'), s[13]);
    try testing.expectEqual(@as(u8, '-'), s[18]);
    try testing.expectEqual(@as(u8, '-'), s[23]);
    // 版本位
    try testing.expectEqual(@as(u8, '4'), s[14]);
    // 变体位：第三段的第一个字符必须是 8/9/a/b
    try testing.expect(std.mem.indexOfScalar(u8, "89ab", s[19]) != null);

    // 全 0xFF 时也要满足同样的位约束
    const ones: [16]u8 = @splat(0xFF);
    const t = try formatUuid(a, &ones);
    try testing.expectEqual(@as(u8, '4'), t[14]);
    try testing.expect(std.mem.indexOfScalar(u8, "89ab", t[19]) != null);
    try testing.expect(!std.mem.eql(u8, s, t));
}

test "getProofRange matches the upstream modulo rule" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 文件为 0 → 空区间（调用方据此返回空 proof code）
    const empty = try getProofRange(a, "seed", 0);
    try testing.expectEqual(@as(i64, 0), empty.start);
    try testing.expectEqual(@as(i64, 0), empty.end);

    // 正常：start = uint64(md5hex(seed)[0..16]) % size，end = min(start+8, size)
    const seed = "0123456789abcdef0123456789abcdef";
    const size: i64 = 1000;
    const digest = try hash.md5Hex(a, seed);
    const want_index: i64 = @intCast(
        (try std.fmt.parseInt(u64, digest[0..16], 16)) % @as(u64, size),
    );
    const r = try getProofRange(a, seed, size);
    try testing.expectEqual(want_index, r.start);
    try testing.expectEqual(want_index + 8, r.end);

    // 贴边：end 被截到文件尾
    const small: i64 = 4;
    const want_small: i64 = @intCast(
        (try std.fmt.parseInt(u64, digest[0..16], 16)) % @as(u64, small),
    );
    const r2 = try getProofRange(a, seed, small);
    try testing.expectEqual(want_small, r2.start);
    try testing.expectEqual(small, r2.end);
    try testing.expect(r2.start >= 0 and r2.start < small);

    // 长度永远是 8 或更少
    for ([_]i64{ 8, 9, 100, 1 << 20 }) |sz| {
        const rr = try getProofRange(a, seed, sz);
        try testing.expect(rr.end - rr.start <= 8);
        try testing.expect(rr.start >= 0 and rr.end <= sz);
    }
}

test "buildPartInfo splits into part_size chunks with a remainder" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const exact = try buildPartInfo(a, 30, 10);
    try testing.expectEqual(@as(usize, 3), exact.len);
    try testing.expectEqual(@as(i64, 1), exact[0].number);
    try testing.expectEqual(@as(i64, 10), exact[0].size);
    try testing.expectEqual(@as(i64, 3), exact[2].number);
    try testing.expectEqual(@as(i64, 10), exact[2].size);

    // 有余数
    const rem = try buildPartInfo(a, 25, 10);
    try testing.expectEqual(@as(usize, 3), rem.len);
    try testing.expectEqual(@as(i64, 10), rem[0].size);
    try testing.expectEqual(@as(i64, 5), rem[2].size);

    // 比一片还小
    const tiny = try buildPartInfo(a, 3, 10);
    try testing.expectEqual(@as(usize, 1), tiny.len);
    try testing.expectEqual(@as(i64, 3), tiny[0].size);

    // 空文件 / 非法分片大小
    try testing.expectEqual(@as(usize, 0), (try buildPartInfo(a, 0, 10)).len);
    try testing.expectEqual(@as(usize, 0), (try buildPartInfo(a, 100, 0)).len);
}

test "writePartInfoList emits the two shapes" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const parts = [_]PartInfo{
        .{ .number = 1, .size = 10 },
        .{ .number = 2, .size = 5 },
    };

    var b1 = Buf.init(a);
    try writePartInfoList(&b1, &parts, null);
    try testing.expectEqualStrings(
        "[{\"part_number\":1,\"part_size\":10},{\"part_number\":2,\"part_size\":5}]",
        b1.slice(),
    );

    // etag 直接来自 `resp.Header.Get("Etag")`，而 HTTP 的 ETag 头**自带引号**，
    // 所以它作为 JSON 字符串写出去时里面的引号必须转义 —— 这正是 Go
    // `json.Marshal` 对同一份输入的行为，不能"顺手"把引号剥掉。
    const etags = [_][]const u8{ "\"aaa\"", "\"bbb\"" };
    var b2 = Buf.init(a);
    try writePartInfoList(&b2, &parts, &etags);
    try testing.expectEqualStrings(
        "[{\"part_number\":1,\"part_size\":10,\"etag\":\"\\\"aaa\\\"\"}," ++
            "{\"part_number\":2,\"part_size\":5,\"etag\":\"\\\"bbb\\\"\"}]",
        b2.slice(),
    );
}

test "objFromJson converts millisecond timestamps and file_type" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const dir = try json.parse(a,
        \\{"fid":"d1","filename":"movies","size":0,"file_type":"0",
        \\ "created_at":1791604800000,"updated_at":1791608400000}
    );
    const d = objFromJson(&dir);
    try testing.expectEqualStrings("movies", d.name);
    try testing.expect(d.is_dir);
    try testing.expectEqual(@as(i64, 1_791_608_400), d.modified); // 毫秒 → 秒

    const file = try json.parse(a,
        \\{"fid":"f1","filename":"a.mp4","size":12345,"file_type":"1",
        \\ "thumbnail_url":"https://t/x.jpg","updated_at":1791608400000}
    );
    const f = objFromJson(&file);
    try testing.expect(!f.is_dir);
    try testing.expectEqual(@as(i64, 12345), f.size);
    try testing.expectEqualStrings("https://t/x.jpg", f.thumb);

    // 缺字段不 panic
    const bare = try json.parse(a, "{}");
    const b = objFromJson(&bare);
    try testing.expectEqualStrings("", b.name);
    try testing.expectEqual(@as(i64, 0), b.modified);
}

test "path helpers" {
    try testing.expectEqualStrings("c", lastSegment("/a/b/c"));
    try testing.expectEqualStrings("c", lastSegment("/a/b/c/"));
    try testing.expectEqualStrings("", lastSegment("/"));
    try testing.expectEqualStrings("/a/b", parentOf("/a/b/c"));
    try testing.expectEqualStrings("/", parentOf("/a"));
    try testing.expectEqualStrings("/", parentOf(""));
}

test "mimeFor covers the common video/archive types" {
    try testing.expectEqualStrings("video/mp4", mimeFor("a.mp4"));
    try testing.expectEqualStrings("video/mp4", mimeFor("A.MP4")); // 大小写无关
    try testing.expectEqualStrings("application/zip", mimeFor("x.zip"));
    try testing.expectEqualStrings("image/jpeg", mimeFor("photo.JPEG"));
    try testing.expectEqualStrings("application/octet-stream", mimeFor("noext"));
    try testing.expectEqualStrings("application/octet-stream", mimeFor("weird.unknownext"));
}

test "hashSource computes md5 and sha1 in one pass" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const payload = "The quick brown fox jumps over the lazy dog";

    const Fake = struct {
        data: []const u8,
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

    var fake = Fake{ .data = payload, .step = 5 };
    const src = model.Source{ .ptr = &fake, .vtable = &.{ .size = Fake.size, .readAt = Fake.readAt } };

    const got = try hashSource(a, src);
    try testing.expectEqualStrings(
        "9e107d9d372bb6826bd81d3542a419d6",
        try hash.hexLower(a, &got.md5),
    );
    try testing.expectEqualStrings(
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        try hash.hexLower(a, &got.sha1),
    );
}

test "proofCode reads exactly the proof range and base64s it" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const data = "0123456789ABCDEFGHIJ";
    const Fake = struct {
        data: []const u8,
        fn size(ptr: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return @intCast(self.data.len);
        }
        fn readAt(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const off: usize = @intCast(offset);
            if (off >= self.data.len) return 0;
            const n = @min(buf.len, self.data.len - off);
            @memcpy(buf[0..n], self.data[off .. off + n]);
            return n;
        }
    };
    var fake = Fake{ .data = data };
    const src = model.Source{ .ptr = &fake, .vtable = &.{ .size = Fake.size, .readAt = Fake.readAt } };

    const seed = "seed-value";
    const range = try getProofRange(a, seed, data.len);
    const code = try proofCode(a, src, seed, data.len);

    const expect_slice = data[@intCast(range.start)..@intCast(range.end)];
    const expect_b64 = try hash.base64Std(a, expect_slice);
    try testing.expectEqualStrings(expect_b64, code);

    // 空文件 → 空字符串，不是错误
    const empty_code = try proofCode(a, src, seed, 0);
    try testing.expectEqualStrings("", empty_code);
}

test "createWithId builds a driver with the expected name" {
    const a = testing.allocator;
    var arena = testArena();
    defer arena.deinit();

    const cfg = try json.parse(arena.allocator(),
        \\{"refresh_token":"rt","app_id":"app","sign_key":"sk","root_folder_id":"9"}
    );
    const d = try createWithId(a, 77, &cfg);

    // defer 是 LIFO：书写顺序是清理顺序的倒序（详见 123open.zig 的同一处注释）。
    defer a.destroy(d);
    defer a.destroy(d.jar);
    defer {
        a.free(d.cfg.root_folder_id);
        a.free(d.cfg.order_by);
        a.free(d.cfg.order_direction);
        a.free(d.cfg.api_url_address);
        a.free(d.cfg.access_token);
        a.free(d.cfg.refresh_token);
        a.free(d.cfg.app_id);
        a.free(d.cfg.sign_key);
    }
    defer d.jar.deinit();
    defer d.client.deinit();

    const drv = driver.asDriver(QuarkOpen, d);
    try testing.expectEqualStrings("QuarkOpen", drv.name());
    try testing.expectEqualStrings("9", d.cfg.root_folder_id);
    try testing.expectEqual(@as(i64, 77), d.storage_id);
    // space 没有实现 → 报零而不是报错
    var ctx = driver.Ctx{ .alloc = arena.allocator() };
    const usage = drv.space(&ctx);
    try testing.expectEqual(@as(i64, 0), usage.total);
    try testing.expectEqual(@as(i64, 0), usage.used);
}

test "buildQuery encodes like Go's url.Values.Encode" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // key 排序 + QueryEscape：`+` 和 `&` 必须编码，否则服务端会把 token 截断。
    // 对齐 Go drivers/quark_open/util.go:51-54
    const q = try buildQuery(a, &.{
        .{ "req_id", "uuid-1" },
        .{ "access_token", "a+b&c d" },
    });
    try testing.expectEqualStrings("access_token=a%2Bb%26c+d&req_id=uuid-1", q);

    // renewapi 的三个参数同样按 key 排序（driver_txt, refresh_ui, server_use）。
    // 对齐 Go drivers/quark_open/util.go:442-449
    const r = try buildQuery(a, &.{
        .{ "refresh_ui", "rt" },
        .{ "server_use", "true" },
        .{ "driver_txt", "quarkyun_oa" },
    });
    try testing.expectEqualStrings("driver_txt=quarkyun_oa&refresh_ui=rt&server_use=true", r);
}

test "linkResult marks the download as proxied and keeps the cookie" {
    // Go 的 Config.OnlyProxy（meta.go:32）：CDN 靠 Cookie 认身份，302 出去就
    // 丢头了，所以必须 proxy=true。
    var arena = testArena();
    defer arena.deinit();
    const lk = try linkResult(arena.allocator(), "https://cdn.example/f", "x_pan_client_id=a; x_pan_access_token=b");
    try testing.expect(lk.proxy);
    try testing.expectEqualStrings("https://cdn.example/f", lk.url);
    try testing.expectEqual(@as(usize, 1), lk.header.len);
    try testing.expectEqualStrings("Cookie", lk.header[0].name);
    try testing.expectEqualStrings("x_pan_client_id=a; x_pan_access_token=b", lk.header[0].value);
}

test "partRetryDelayMs mirrors retry-go's BackOffDelay" {
    // 对齐 Go drivers/quark_open/driver.go:224
    try testing.expectEqual(@as(u32, 0), partRetryDelayMs(1));
    try testing.expectEqual(@as(u32, 1000), partRetryDelayMs(2));
    try testing.expectEqual(@as(u32, 2000), partRetryDelayMs(3));
}
