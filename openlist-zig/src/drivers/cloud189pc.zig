//! 天翼云盘（PC 端 / 家庭云）—— OpenList 的 `189CloudPC`。
//!
//! 与 `189Cloud`（个人云）是**两套互不相干**的 API：这一套走 `api.cloud.189.cn`
//! 的 appId + accessToken/refreshToken，每个请求都要带 HMAC-SHA1 签名，查询参数
//! 里的 `params` 是 AES-128-ECB 加密后的十六进制串。
//!
//! 三处最容易写错的地方：
//!
//!   * **`params` 的明文既不能转义、又要按键排序**（对齐 Go
//!     `drivers/189pc/types.go:401` 的 `Params.Encode()`：只 `sort.Strings`，
//!     值原样写出，不碰 `%XX`）。这是 AES 之前的**明文**，此时 `fileName` 已经
//!     被 `url.QueryEscape` 过（Go `utils.go:710`）、`partInfo` 是带 `+ / =`
//!     的标准 base64（Go `utils.go:803`）——再编码一次就会把 `+` 变成 `%2B`、
//!     把 `%E4%B8%AD` 变成 `%25E4%25B8%25AD`，上传必然失败。
//!     `189Cloud` 的 `EncodeParam`（`drivers/189/help.go:100`）也是**不转义**的，
//!     两家唯一的差别就是这里要排序。
//!   * **十六进制大小写与 `189Cloud` 相反**：这里的 `RsaEncrypt`、
//!     `AesECBEncrypt`、`signatureOfHmac` 全是**大写**。
//!   * **签名只覆盖 URL 的 path**，不含 query。上游用正则从完整 URL 里抠出来，
//!     这里等价地取「`://` 之后第一个 `/` 起，到 `?`/`#` 为止」。
//!
//! 未移植（每一项都是本工程结构上做不到或无关的）：
//!   * 扫码登录（`loginByQRCode`）：要生成二维码图片并通过 error 文本回传前端，
//!     本工程没有这条通道。选了 `qrcode` 会明确报 `NeedInteractiveAuth`。
//!   * 图形验证码 OCR：需要外部 OCR 服务。触发验证码时直接报错并提示改用 token。
//!   * 家庭云转存（`FamilyTransfer`）、torrent 生成、cron `keepAlive`、
//!     `Copy`、旧版 `OldUpload` / `RapidUpload`。
//!   * 上传并发：上游用 errgroup 多线程，`src/client.zig` 的 `send` 有一把全局
//!     互斥锁（`std.http.Client` 连接池非线程安全），所以分片串行上传。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const rsa = @import("../util/rsa.zig");
const aes = @import("../util/aes.zig");
const urlmod = @import("../util/url.zig");
const timeutil = @import("../util/time.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const ACCOUNT_TYPE = "02";
/// 官方 PC 端使用的 appId。登录、换 session 必须全程同一个。
///
/// **取值依据**：对齐**上游 `OpenListTeam/OpenList` main 分支**
/// `drivers/189pc/utils.go`（`APP_ID = "9317140619"`、`VERSION = "7.2.4.0"`）。
/// 本地对照仓库 `D:/workspace/OpenList`（分支 `feat/zhijiadisk`）里的这份
/// `utils.go:44,46` 还是旧值 `8025431004` / `6.2` —— 那个分支没有跟上游，
/// 不是本工程的偏差。**不要照本地分支改回去。**
const APP_ID = "9317140619";
const CLIENT_TYPE = "10020";
const VERSION = "7.2.4.0";

const WEB_URL = "https://cloud.189.cn";
const AUTH_URL = "https://open.e.189.cn";
const API_URL = "https://api.cloud.189.cn";
const UPLOAD_URL = "https://upload.cloud.189.cn";

const RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html";

const PC = "TELEPC";
const CHANNEL_ID = "web_cloud.189.cn";

/// 短信二次校验后服务端下发的设备标识（cookie 名）。
const DEVICE_ID_COOKIE = "DEVICEID";

/// 刷新 session 时返回这个 res_code 说明 accessToken 已废，要用 refreshToken 换。
const USER_INVALID_OPEN_TOKEN = "UserInvalidOpenToken";

/// 密码登录返回这个 result 表示需要设备二次校验（短信）。
const SECOND_DEVICE_AUTH_RESULT: i64 = -133;

/// `config.DefaultRoot`。个人云 `-11`，家庭云是空串。
const default_personal_root = "-11";

const page_size: usize = 1000;
const max_redirects: usize = 5;

/// 分片基准 10 MiB。`partSize` 在此基础上按文件大小放大。
const slice_base: i64 = 10 * 1024 * 1024;

const user_agent = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";

const hex_digits = "0123456789abcdef";

/// 189 的时间串里 AM/PM 前可能是 U+202F 或 U+00A0，两个都要换成普通空格。
const narrow_nbsp = "\xe2\x80\xaf";
const nbsp = "\xc2\xa0";

pub const Error = error{
    /// 既没有 token 也没有账号密码。
    NoCredentials,
    UpstreamHttp,
    UpstreamNotJson,
    UpstreamError,
    InvalidResponse,
    InvalidPath,
    InvalidKey,
    LoginFailed,
    /// 上游要求图形验证码或短信二次校验，本工程无法交互完成。
    NeedInteractiveAuth,
    /// 批量任务撞上了同名目标。
    Conflict,
    /// 无法自动获取家庭云 ID，需要用户手填。
    FamilyIdRequired,
};

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

pub const Addition = struct {
    /// `password` / `qrcode`。后者本工程不支持（见文件头）。
    login_type: []const u8 = "password",
    username: []const u8 = "",
    password: []const u8 = "",
    /// 图形验证码。触发时填进来再保存一次 —— 本工程不能 OCR，只能靠手填。
    validate_code: []const u8 = "",
    /// 短信二次校验码。
    sms_code: []const u8 = "",
    access_token: []const u8 = "",
    refresh_token: []const u8 = "",
    /// 二次校验通过后服务端下发的设备标识，留着可以不再触发校验。
    device_id: []const u8 = "",
    client_sn: []const u8 = "",
    jg_open_id: []const u8 = "",
    /// 设备指纹。为空时生成并保存。
    user_finger: []const u8 = "",
    root_folder_id: []const u8 = default_personal_root,
    order_by: []const u8 = "filename",
    order_direction: []const u8 = "asc",
    /// `personal` / `family`。
    type: []const u8 = "personal",
    family_id: []const u8 = "",
    /// `stream` / `rapid`。`rapid` 先算 MD5，能秒传。
    upload_method: []const u8 = "stream",
    upload_thread: []const u8 = "3",
    family_transfer: bool = false,
    rapid_upload: bool = false,
    no_use_ocr: bool = false,
    /// 上传后顺带生成 `.cas.torrent`。本工程未实现。
    generate_torrent: bool = false,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.login_type = try dupeOr(alloc, o.strAt("login_type"), "password");
        a.username = try dupeOr(alloc, o.strAt("username"), "");
        a.password = try dupeOr(alloc, o.strAt("password"), "");
        a.validate_code = try dupeOr(alloc, o.strAt("validate_code"), "");
        a.sms_code = try dupeOr(alloc, o.strAt("sms_code"), "");
        a.access_token = try dupeOr(alloc, o.strAt("access_token"), "");
        a.refresh_token = try dupeOr(alloc, o.strAt("refresh_token"), "");
        a.device_id = try dupeOr(alloc, o.strAt("device_id"), "");
        a.client_sn = try dupeOr(alloc, o.strAt("client_sn"), "");
        a.jg_open_id = try dupeOr(alloc, o.strAt("jg_open_id"), "");
        a.user_finger = try dupeOr(alloc, o.strAt("user_finger"), "");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_personal_root);
        a.order_by = try dupeOr(alloc, o.strAt("order_by"), "filename");
        a.order_direction = try dupeOr(alloc, o.strAt("order_direction"), "asc");
        a.type = try dupeOr(alloc, o.strAt("type"), "personal");
        a.family_id = try dupeOr(alloc, o.strAt("family_id"), "");
        a.upload_method = try dupeOr(alloc, o.strAt("upload_method"), "stream");
        a.upload_thread = try dupeOr(alloc, o.strAt("upload_thread"), "3");
        if (boolAt(o, "family_transfer")) |b| a.family_transfer = b;
        if (boolAt(o, "rapid_upload")) |b| a.rapid_upload = b;
        if (boolAt(o, "no_use_ocr")) |b| a.no_use_ocr = b;
        if (boolAt(o, "generate_torrent")) |b| a.generate_torrent = b;
        return a;
    }

    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("login_type", self.login_type);
        try w.str("username", self.username);
        try w.str("password", self.password);
        try w.str("validate_code", self.validate_code);
        try w.str("sms_code", self.sms_code);
        try w.str("access_token", self.access_token);
        try w.str("refresh_token", self.refresh_token);
        try w.str("device_id", self.device_id);
        try w.str("client_sn", self.client_sn);
        try w.str("jg_open_id", self.jg_open_id);
        try w.str("user_finger", self.user_finger);
        try w.str("root_folder_id", self.root_folder_id);
        try w.str("order_by", self.order_by);
        try w.str("order_direction", self.order_direction);
        try w.str("type", self.type);
        try w.str("family_id", self.family_id);
        try w.str("upload_method", self.upload_method);
        try w.str("upload_thread", self.upload_thread);
        try w.boolean("family_transfer", self.family_transfer);
        try w.boolean("rapid_upload", self.rapid_upload);
        try w.boolean("no_use_ocr", self.no_use_ocr);
        try w.boolean("generate_torrent", self.generate_torrent);
        try w.end();
        return b.toOwned();
    }

    pub fn isFamily(self: Addition) bool {
        return std.mem.eql(u8, self.type, "family");
    }

    /// 上游 `strconv.Atoi` 失败或越界都回落到 3。
    pub fn uploadThread(self: Addition) i64 {
        const n = std.fmt.parseInt(i64, self.upload_thread, 10) catch return 3;
        if (n < 1 or n > 32) return 3;
        return n;
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    return alloc.dupe(u8, v orelse fallback);
}

fn boolAt(v: *const json.Value, path: []const u8) ?bool {
    const p = v.getPath(path) orelse return null;
    return p.asBool();
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
    fn boolean(self: *ObjWriter, name: []const u8, v: bool) !void {
        try self.key(name);
        try self.b.append(if (v) "true" else "false");
    }
    fn end(self: *ObjWriter) !void {
        try self.b.appendByte('}');
    }
};

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

/// 每个请求都要带的固定查询参数。
///
/// `rand` 是 `{Int63n(1e5)}_{Int63n(1e10)}` —— 上游靠它破缓存。
fn clientSuffix(alloc: std.mem.Allocator, rnd: std.Random) ![4][2][]const u8 {
    const a = try std.fmt.allocPrint(alloc, "{d}", .{rnd.intRangeAtMostBiased(u64, 0, 99_999)});
    const b = try std.fmt.allocPrint(alloc, "{d}", .{rnd.intRangeAtMostBiased(u64, 0, 9_999_999_999)});
    const rand = try std.fmt.allocPrint(alloc, "{s}_{s}", .{ a, b });
    return .{
        .{ "clientType", PC },
        .{ "version", VERSION },
        .{ "channelId", CHANNEL_ID },
        .{ "rand", rand },
    };
}

/// `urlpath := regexp.MustCompile("://[^/]+((/[^/\\s?#]+)*)").FindStringSubmatch(fullUrl)[1]`
///
/// 也就是「主机之后、查询/片段之前的路径」。签名只覆盖这一段 —— query 里那些
/// `clientType/version/rand` 变了不影响签名。
fn requestPath(url: []const u8) []const u8 {
    const scheme = std.mem.indexOf(u8, url, "://") orelse return url;
    const after = url[scheme + 3 ..];
    const slash = std.mem.indexOfScalar(u8, after, '/') orelse return "";
    const rest = after[slash..];
    const end = std.mem.indexOfAny(u8, rest, "?#") orelse rest.len;
    return rest[0..end];
}

/// `signatureOfHmac` —— HMAC-SHA1，**大写**十六进制。
fn signatureOfHmac(
    alloc: std.mem.Allocator,
    session_secret: []const u8,
    session_key: []const u8,
    operate: []const u8,
    url: []const u8,
    date_of_gmt: []const u8,
    param: []const u8,
) ![]u8 {
    var b = Buf.init(alloc);
    defer b.deinit();
    try b.print("SessionKey={s}&Operate={s}&RequestURI={s}&Date={s}", .{
        session_key, operate, requestPath(url), date_of_gmt,
    });
    if (param.len > 0) try b.print("&params={s}", .{param});
    return hash.hmacSha1HexUpper(alloc, session_secret, b.slice());
}

/// `RsaEncrypt` —— PKCS#1 v1.5 + **大写**十六进制（`189Cloud` 那边是小写）。
fn rsaEncryptUpper(alloc: std.mem.Allocator, pem_or_body: []const u8, msg: []const u8, rnd: std.Random) ![]u8 {
    var owned = rsa.parsePem(alloc, pem_or_body) catch return Error.InvalidKey;
    defer owned.deinit(alloc);
    return rsa.encryptToHexUpper(alloc, msg, owned.key, rnd) catch |e| switch (e) {
        error.MessageTooLong => return Error.InvalidKey,
        else => return Error.InvalidKey,
    };
}

/// `AesECBEncrypt` —— AES-128-ECB + PKCS#7 + **大写**十六进制。
fn aesEcbEncryptHex(alloc: std.mem.Allocator, key16: []const u8, plain: []const u8) ![]u8 {
    if (key16.len != 16) return Error.InvalidKey;
    const padded = try aes.pkcs7Pad(alloc, plain, aes.BLOCK);
    const ct = try aes.ecbEncrypt(alloc, key16, padded);
    return hash.hexUpper(alloc, ct);
}

/// `Params.Encode()` —— 与 `189Cloud` 的 `EncodeParam` 唯一的区别是**按键排序**。
///
/// 两者**都不做百分号转义**（对齐 Go `drivers/189pc/types.go:401`）：上游是把
/// 值原样拼进 `strings.Builder` 的。所以这里不能用 `urlmod.Query`（它会
/// `addSet(..., .form)` 再编码一遍），得自己排完序裸拼 —— 明文里的 `+ / =`
/// 和 `%E4%B8%AD` 必须原封不动进 AES。
fn encodeParams(alloc: std.mem.Allocator, entries: []const [2][]const u8) ![]u8 {
    // Go 是 `sort.Strings(keys)` —— 纯字节序，这里等价。
    const idx = try alloc.alloc(usize, entries.len);
    defer alloc.free(idx);
    for (idx, 0..) |*p, i| p.* = i;
    std.mem.sort(usize, idx, entries, struct {
        fn lt(es: []const [2][]const u8, a: usize, b: usize) bool {
            return std.mem.order(u8, es[a][0], es[b][0]) == .lt;
        }
    }.lt);

    var b = Buf.init(alloc);
    defer b.deinit();
    for (idx, 0..) |i, n| {
        if (n > 0) try b.appendByte('&');
        try b.append(entries[i][0]);
        try b.appendByte('=');
        try b.append(entries[i][1]);
    }
    return b.toOwned();
}

/// `partSize` —— 分片大小阶梯。
///
/// 上游是浮点运算（`math.Ceil(size/1999/10MiB)`），这里换成整数上取整，结果
/// 一致但不会因为 1TB 附近的浮点误差差一片。
fn partSize(size: i64) i64 {
    const unit = 1999 * slice_base;
    if (size > 2 * 999 * slice_base) {
        const mult = @divTrunc(size + unit - 1, unit);
        return @max(mult, 5) * slice_base;
    }
    if (size > 999 * slice_base) return 2 * slice_base;
    return slice_base;
}

/// 第 `part`（从 1 开始）片的长度。最后一片是余数，整除时就是整片。
fn partLen(size: i64, slice: i64, part: i64, count: i64) i64 {
    if (part != count) return slice;
    const last = @mod(size, slice);
    return if (last == 0) slice else last;
}

/// `uuid.NewString()` —— RFC 4122 v4，`X-Request-ID` 用它。
fn uuidV4(alloc: std.mem.Allocator, rnd: std.Random) ![]u8 {
    const out = try alloc.alloc(u8, 36);
    var i: usize = 0;
    var n: usize = 0;
    while (n < 16) : (n += 1) {
        if (n == 4 or n == 6 or n == 8 or n == 10) {
            out[i] = '-';
            i += 1;
        }
        var v = rnd.int(u8);
        if (n == 6) v = (v & 0x0f) | 0x40; // 版本 4
        if (n == 8) v = (v & 0x3f) | 0x80; // 变体 10xx
        out[i] = hex_digits[v >> 4];
        out[i + 1] = hex_digits[v & 0x0f];
        i += 2;
    }
    return out;
}

/// `ParseHttpHeader` —— `k=v&k=v` 切成 header 表，按第一个 `=` 切。
fn parseHttpHeader(alloc: std.mem.Allocator, s: []const u8) ![]model.Header {
    var out = List(model.Header).init(alloc);
    var it = std.mem.splitScalar(u8, s, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        try out.append(.{ .name = pair[0..eq], .value = pair[eq + 1 ..] });
    }
    return out.toOwned();
}

/// 189 的响应里 `&amp;` 是字面量，要先还原再把 scheme 升成 https。
fn normalizeDownloadUrl(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var b = Buf.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, raw, i, "&amp;")) |at| {
        try b.append(raw[i..at]);
        try b.appendByte('&');
        i = at + "&amp;".len;
    }
    try b.append(raw[i..]);

    const s = b.slice();
    const idx = std.mem.indexOf(u8, s, "http://") orelse return alloc.dupe(u8, s);
    var out = Buf.init(alloc);
    try out.append(s[0..idx]);
    try out.append("https://");
    try out.append(s[idx + "http://".len ..]);
    return out.toOwned();
}

/// `normalizeCloud189Name` —— 名字里的 `\'` 还原成 `'`。
fn normalizeName(alloc: std.mem.Allocator, name: []const u8) ![]const u8 {
    if (std.mem.indexOf(u8, name, "\\'") == null) return name;
    var b = Buf.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, name, i, "\\'")) |at| {
        try b.append(name[i..at]);
        try b.appendByte('\'');
        i = at + 2;
    }
    try b.append(name[i..]);
    return alloc.dupe(u8, b.slice());
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

fn queryPart(u: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, u, '?') orelse return "";
    const rest = u[q + 1 ..];
    const h = std.mem.indexOfScalar(u8, rest, '#') orelse return rest;
    return rest[0..h];
}

fn resolveUrl(alloc: std.mem.Allocator, base: []const u8, loc: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, loc, "http://") or std.mem.startsWith(u8, loc, "https://")) {
        return alloc.dupe(u8, loc);
    }
    if (std.mem.startsWith(u8, loc, "//")) return std.fmt.allocPrint(alloc, "https:{s}", .{loc});
    if (std.mem.startsWith(u8, loc, "/")) {
        const scheme_end = std.mem.indexOf(u8, base, "://") orelse return alloc.dupe(u8, loc);
        const host_start = scheme_end + 3;
        const host_end = std.mem.indexOfAny(u8, base[host_start..], "/?#") orelse (base.len - host_start);
        return std.fmt.allocPrint(alloc, "{s}{s}", .{ base[0 .. host_start + host_end], loc });
    }
    const cut = std.mem.lastIndexOfAny(u8, base, "/?#") orelse return alloc.dupe(u8, loc);
    return std.fmt.allocPrint(alloc, "{s}/{s}", .{ base[0..cut], loc });
}

fn numStr(alloc: std.mem.Allocator, n: i64) ![]const u8 {
    return std.fmt.allocPrint(alloc, "{d}", .{n});
}

/// 189 列表项的 `id` 是 JSON 数字，接口收的却是字符串 —— 个人版驱动
/// `cloud189.zig` 早就踩过并注释过（“189 的 id 是数字，但接口收的是字符
/// 串”，`idStr` 旁）。两种形态都接：字符串原样借用（与页数据同生共死），
/// 数字在 arena 里格式化成十进制串。
///
/// 取不到 id 一律算坏响应：空 id 会被上游当成根目录（家庭云 `folderId=""`
/// 就是家庭根），mkdir/上传会把文件建到根上还不报错，rename/move/delete
/// 则带着空 fileId 被上游拒绝 —— 2026-10-12 的 e2e 就是这样：临时目录里
/// 的文件全都落到家庭云根目录，rename 报 `srcFileId=null`。
fn idOf(arena: std.mem.Allocator, item: *const json.Value) ![]const u8 {
    if (item.strAt("id")) |s| return s;
    const n = item.intAt("id") orelse return Error.InvalidResponse;
    return try std.fmt.allocPrint(arena, "{d}", .{n});
}

fn toFamilyOrderBy(o: []const u8) []const u8 {
    if (std.mem.eql(u8, o, "filesize")) return "2";
    if (std.mem.eql(u8, o, "lastOpTime")) return "3";
    return "1";
}

fn toDesc(o: []const u8) []const u8 {
    return if (std.mem.eql(u8, o, "desc")) "true" else "false";
}

// ---------------------------------------------------------------------------
// 189 的时间格式
// ---------------------------------------------------------------------------

const MONTHS = [_][]const u8{ "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };

/// `Time.Unmarshal` —— 三种布局 × 有无时区，落在 `utils.CNLoc`（UTC+8）。
///
/// 189 的时间串形状不固定：`"2026-10-10 12:00:00"`、`"Oct 10, 2026, 10:37:18 PM"`、
/// `"Oct 10, 2026 10:37:18 PM +08"` 都见过。没有时区时按 UTC+8 解释。
fn parse189Time(s_in: []const u8) ?i64 {
    var buf: [256]u8 = undefined;
    const trimmed = std.mem.trim(u8, s_in, " \t\r\n\"");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;

    // U+202F / U+00A0 → 普通空格
    var n: usize = 0;
    var i: usize = 0;
    while (i < trimmed.len) {
        if (i + narrow_nbsp.len <= trimmed.len and std.mem.startsWith(u8, trimmed[i..], narrow_nbsp)) {
            buf[n] = ' ';
            n += 1;
            i += narrow_nbsp.len;
            continue;
        }
        if (i + nbsp.len <= trimmed.len and std.mem.startsWith(u8, trimmed[i..], nbsp)) {
            buf[n] = ' ';
            n += 1;
            i += nbsp.len;
            continue;
        }
        buf[n] = trimmed[i];
        n += 1;
        i += 1;
    }
    const s = buf[0..n];

    const local = parseIsh(s) orelse parseEnglish(s) orelse return null;
    return local - (offsetSeconds(s) orelse 8 * 3600);
}

/// `2006-01-02 15:04:05` —— 返回**本地读数**对应的 UTC 秒（还没减时区）。
fn parseIsh(s: []const u8) ?i64 {
    if (s.len < 19) return null;
    if (s[4] != '-' or s[7] != '-' or s[10] != ' ') return null;
    if (s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(i64, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, s[8..10], 10) catch return null;
    const h = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const se = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (mo < 1 or mo > 12) return null;
    if (d < 1 or d > timeutil.daysInMonth(y, mo)) return null;
    if (h > 23 or mi > 59 or se > 60) return null;
    return timeutil.daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
}

/// `Jan 2, 2006, 3:04:05 PM`（逗号可选）—— 同样返回本地读数。
fn parseEnglish(s: []const u8) ?i64 {
    var rest = s;
    var mo: i64 = 0;
    for (MONTHS, 1..) |m, idx| {
        if (rest.len >= 3 and std.ascii.eqlIgnoreCase(rest[0..3], m)) {
            mo = @intCast(idx);
            rest = rest[3..];
            break;
        }
    }
    if (mo == 0) return null;

    rest = std.mem.trimStart(u8, rest, " ");
    const sp1 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    // "10," —— 日后面总有逗号，年后面可能有，都要先剥掉。
    const d = std.fmt.parseInt(i64, std.mem.trimEnd(u8, rest[0..sp1], ","), 10) catch return null;
    rest = std.mem.trimStart(u8, rest[sp1..], " ,");

    const sp2 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const y = std.fmt.parseInt(i64, std.mem.trimEnd(u8, rest[0..sp2], ","), 10) catch return null;
    rest = std.mem.trimStart(u8, rest[sp2..], " ,");

    const sp3 = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const clock = rest[0..sp3];
    var tail = std.mem.trimStart(u8, rest[sp3..], " ");

    const c1 = std.mem.indexOfScalar(u8, clock, ':') orelse return null;
    const c2 = std.mem.indexOfScalar(u8, clock[c1 + 1 ..], ':') orelse return null;
    var h = std.fmt.parseInt(i64, clock[0..c1], 10) catch return null;
    const mi = std.fmt.parseInt(i64, clock[c1 + 1 .. c1 + 1 + c2], 10) catch return null;
    const se = std.fmt.parseInt(i64, clock[c1 + 1 + c2 + 1 ..], 10) catch return null;

    if (tail.len >= 2 and std.ascii.eqlIgnoreCase(tail[0..2], "pm")) {
        if (h < 12) h += 12;
    } else if (tail.len >= 2 and std.ascii.eqlIgnoreCase(tail[0..2], "am")) {
        if (h == 12) h = 0;
    }
    // 时区由 offsetSeconds 统一处理，这里不管。

    if (d < 1 or d > timeutil.daysInMonth(y, mo)) return null;
    if (h > 23 or mi > 59 or se > 60) return null;
    return timeutil.daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
}

/// 取最后一个空格之后的 `+08` / `-05` / `+0800` / `-05:00`。没有就返回 null
/// （调用方按 UTC+8 处理）。
fn offsetSeconds(s: []const u8) ?i64 {
    const sp = std.mem.lastIndexOfScalar(u8, s, ' ') orelse return null;
    const tok = s[sp + 1 ..];
    if (tok.len == 0) return null;
    const sign: i64 = switch (tok[0]) {
        '+' => 1,
        '-' => -1,
        else => return null,
    };
    var digits: [5]u8 = undefined;
    var n: usize = 0;
    for (tok[1..]) |c| {
        if (c >= '0' and c <= '9') {
            if (n == digits.len) return null;
            digits[n] = c;
            n += 1;
        } else if (c == ':') {
            continue;
        } else return null;
    }
    if (n != 2 and n != 4) return null;
    const hh = std.fmt.parseInt(i64, digits[0..2], 10) catch return null;
    const mm: i64 = if (n == 4) std.fmt.parseInt(i64, digits[2..4], 10) catch return null else 0;
    return sign * (hh * 3600 + mm * 60);
}

/// `matchLoginParam` —— 老登陆页把参数写在 JS 变量里。
///
/// `prefix` 是值前面的**字面**文本（含那个开引号），例如 `lt = "` 或
/// `'captchaToken' value='`。不引正则引擎：只需要这两种固定形状。
fn matchLoginParam(alloc: std.mem.Allocator, body: []const u8, prefix: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, body, prefix) orelse return null;
    const quote = prefix[prefix.len - 1];
    const start = at + prefix.len;
    const close = std.mem.indexOfScalar(u8, body[start..], quote) orelse return null;
    if (close == 0) return null;
    return alloc.dupe(u8, body[start .. start + close]) catch null;
}

/// `AppConfResp.Succeeded()` —— result 可能是数字也可能是字符串，缺失算成功。
fn appConfOk(v: *const json.Value) bool {
    const r = v.getPath("result") orelse return true;
    return switch (r.*) {
        .null => true,
        .string => |s| std.mem.eql(u8, s, "0") or s.len == 0,
        .int => |i| i == 0,
        .float => |f| f == 0,
        else => false,
    };
}

/// `RespErr.HasError()` —— 上游「居然有四种返回方式」。
fn checkRespErr(alloc: std.mem.Allocator, url: []const u8, body: []const u8) !void {
    const v = json.parse(alloc, body) catch return; // 非 JSON（XML / HTML）就放过
    if (v.getPath("res_code")) |rc| {
        switch (rc.*) {
            .int => |n| {
                if (n == 0) return;
                log.warn("[189pc] {s}: res_code {d} {s}", .{ url, n, v.strAt("res_message") orelse "" });
                return Error.UpstreamError;
            },
            .float => |f| {
                if (f == 0) return;
                log.warn("[189pc] {s}: res_code {d} {s}", .{ url, f, v.strAt("res_message") orelse "" });
                return Error.UpstreamError;
            },
            .string => |s| {
                // 字符串形态只要非空就算错误 —— 哪怕它是 "0"。
                if (s.len == 0) return;
                log.warn("[189pc] {s}: res_code {s} {s}", .{ url, s, v.strAt("res_message") orelse "" });
                return Error.UpstreamError;
            },
            else => {},
        }
    }
    const code = v.strAt("code") orelse "";
    if (code.len > 0 and !std.mem.eql(u8, code, "SUCCESS")) {
        log.warn("[189pc] {s}: {s} {s}", .{ url, code, v.strAt("msg") orelse v.strAt("message") orelse @as([]const u8, "") });
        return Error.UpstreamError;
    }
    if ((v.strAt("errorCode") orelse @as([]const u8, "")).len > 0) {
        log.warn("[189pc] {s}: {s} {s}", .{ url, v.strAt("errorCode") orelse "", v.strAt("errorMsg") orelse "" });
        return Error.UpstreamError;
    }
    if ((v.strAt("error") orelse @as([]const u8, "")).len > 0) {
        log.warn("[189pc] {s}: error {s}", .{ url, v.strAt("message") orelse "" });
        return Error.UpstreamError;
    }
}

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------

pub const Cloud189PC = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    session_key: []const u8 = "",
    session_secret: []const u8 = "",
    family_session_key: []const u8 = "",
    family_session_secret: []const u8 = "",
    login_name: []const u8 = "",

    /// 登录流程的中间状态。设备二次校验要求复用同一套参数，所以留在这里。
    lt: []const u8 = "",
    req_id: []const u8 = "",
    referer: []const u8 = "",
    param_id: []const u8 = "",
    captcha_token: []const u8 = "",
    rsa_pem: []const u8 = "",
    rsa_prefix: []const u8 = "",
    second_auth_mobile: []const u8 = "",

    login_mu: std.Io.Mutex = .init,
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
        return "189CloudPC";
    }

    fn as(ptr: *anyopaque) *Cloud189PC {
        return @ptrCast(@alignCast(ptr));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        // 个人云与家庭云的根目录约定不同：家庭云没有 -11。
        if (self.cfg.isFamily() and std.mem.eql(u8, self.cfg.root_folder_id, default_personal_root)) {
            try self.setCfgStr(&self.cfg.root_folder_id, "");
        } else if (!self.cfg.isFamily() and self.cfg.root_folder_id.len == 0) {
            try self.setCfgStr(&self.cfg.root_folder_id, default_personal_root);
        }
        if (self.cfg.login_type.len == 0) try self.setCfgStr(&self.cfg.login_type, "password");
        if (std.mem.eql(u8, self.cfg.login_type, "qrcode")) {
            log.err("[189pc] 扫码登录需要把二维码图片回传前端，本工程没有这条通道；请改用 password 或填 access_token", .{});
            return Error.NeedInteractiveAuth;
        }
        // 越界的线程数归一化一次，省得每次读配置都要再判。
        if (!std.mem.eql(u8, self.cfg.upload_thread, "3") and self.cfg.uploadThread() == 3) {
            try self.setCfgStr(&self.cfg.upload_thread, "3");
        }

        if (self.cfg.access_token.len > 0) {
            try self.refreshSession(a, 0);
        } else if (self.cfg.refresh_token.len > 0) {
            try self.refreshToken(a, 0);
        } else {
            try self.login(a);
        }

        if (self.cfg.family_id.len == 0) {
            const id = try self.getFamilyId(a);
            try self.setCfgStr(&self.cfg.family_id, id);
        }
        self.save();
        log.info("[189pc] ready: type={s} root={s} family={s}", .{
            self.cfg.type, self.cfg.root_folder_id, self.cfg.family_id,
        });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        self.save();
    }

    fn save(self: *Cloud189PC) void {
        if (self.storage_id == 0) return;
        const text = self.cfg.toJson(self.alloc) catch return;
        defer self.alloc.free(text);
        if (text.len == self.last_saved.len and std.mem.eql(u8, text, self.last_saved)) return;
        if (self.last_saved.len > 0) self.alloc.free(self.last_saved);
        self.last_saved = self.alloc.dupe(u8, text) catch return;
        driver.persist(self.storage_id, self.last_saved);
    }

    fn setCfgStr(self: *Cloud189PC, slot: *[]const u8, next: []const u8) !void {
        if (slot.*.len > 0) self.alloc.free(slot.*);
        slot.* = try self.alloc.dupe(u8, next);
    }

    fn setStr(self: *Cloud189PC, slot: *[]const u8, next: []const u8) !void {
        if (slot.*.len > 0) self.alloc.free(slot.*);
        slot.* = try self.alloc.dupe(u8, next);
    }

    fn isFamily(self: *const Cloud189PC) bool {
        return self.cfg.isFamily();
    }

    fn sessionKeyFor(self: *const Cloud189PC, is_family: bool) []const u8 {
        return if (is_family) self.family_session_key else self.session_key;
    }

    fn sessionSecretFor(self: *const Cloud189PC, is_family: bool) []const u8 {
        return if (is_family) self.family_session_secret else self.session_secret;
    }

    fn uploadBase(self: *const Cloud189PC) []const u8 {
        return if (self.isFamily()) UPLOAD_URL ++ "/family" else UPLOAD_URL ++ "/person";
    }

    /// 取设备指纹，为空时生成并保存。
    fn userFinger(self: *Cloud189PC) ![]const u8 {
        if (self.cfg.user_finger.len > 0) return self.cfg.user_finger;
        var src = std.Random.IoSource{ .io = rt.io() };
        const n = src.interface().intRangeAtMostBiased(u64, 1_000_000_000, 9_999_999_999);
        const s = try std.fmt.allocPrint(self.alloc, "{d}", .{n});
        try self.setCfgStr(&self.cfg.user_finger, s);
        return self.cfg.user_finger;
    }

    /// 把已保存的设备标识塞进 cookie jar，避免重复触发设备二次校验。
    fn applyDeviceId(self: *Cloud189PC) void {
        if (self.cfg.device_id.len == 0) return;
        self.jar.store(.{
            .name = DEVICE_ID_COOKIE,
            .value = self.cfg.device_id,
            .path = "/",
            .domain = "e.189.cn",
            .host_only = false,
        }, rt.nowSeconds());
    }

    /// 保存服务端下发的设备标识。
    fn saveDeviceId(self: *Cloud189PC, res: httpclient.Response) void {
        for (res.headers) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, "set-cookie")) continue;
            if (!std.mem.startsWith(u8, h.value, DEVICE_ID_COOKIE)) continue;
            const eq = std.mem.indexOfScalar(u8, h.value, '=') orelse continue;
            const end = std.mem.indexOfScalar(u8, h.value, ';') orelse h.value.len;
            if (end < eq + 1) continue;
            const v = std.mem.trim(u8, h.value[eq + 1 .. end], " \t");
            if (v.len == 0 or std.mem.eql(u8, v, self.cfg.device_id)) continue;
            const dup = self.alloc.dupe(u8, v) catch return;
            self.setCfgStr(&self.cfg.device_id, dup) catch return;
            self.save();
            return;
        }
    }
    fn saveDeviceIdNoErr(self: *Cloud189PC, res: httpclient.Response) void {
        self.saveDeviceId(res);
    }

    // -----------------------------------------------------------------------
    // HTTP
    // -----------------------------------------------------------------------

    /// `EncryptParams` —— AES 加密后的 `params`。空参数表返回空串，此时既不传
    /// 这个 query 键，签名里也不带 `&params=`。
    fn encryptParams(
        self: *Cloud189PC,
        alloc: std.mem.Allocator,
        params: []const [2][]const u8,
        is_family: bool,
    ) ![]const u8 {
        if (params.len == 0) return "";
        const secret = self.sessionSecretFor(is_family);
        if (secret.len < 16) return Error.InvalidKey;
        return aesEcbEncryptHex(alloc, secret[0..16], try encodeParams(alloc, params));
    }

    fn signatureHeaders(
        self: *Cloud189PC,
        alloc: std.mem.Allocator,
        url: []const u8,
        method: []const u8,
        params_data: []const u8,
        is_family: bool,
    ) ![]model.Header {
        var date = Buf.init(alloc);
        defer date.deinit();
        try timeutil.formatHttpDate(&date, rt.nowSeconds());

        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        const sig = try signatureOfHmac(
            alloc,
            self.sessionSecretFor(is_family),
            self.sessionKeyFor(is_family),
            method,
            url,
            date.slice(),
            params_data,
        );
        var out = List(model.Header).init(alloc);
        try out.append(.{ .name = "Date", .value = try alloc.dupe(u8, date.slice()) });
        try out.append(.{ .name = "SessionKey", .value = self.sessionKeyFor(is_family) });
        try out.append(.{ .name = "X-Request-ID", .value = try uuidV4(alloc, rnd) });
        try out.append(.{ .name = "Signature", .value = sig });
        return out.toOwned();
    }

    fn stdHeaders(arena: std.mem.Allocator) ![]model.Header {
        var out = List(model.Header).init(arena);
        try out.append(.{ .name = "Accept", .value = "application/json;charset=UTF-8" });
        try out.append(.{ .name = "User-Agent", .value = user_agent });
        return out.toOwned();
    }

    /// 一次带签名的请求。
    ///
    /// `params` 是要 AES 加密后塞进 `params` 查询键的那组；`query` 是明文查询
    /// 参数。上游把它们全放进 resty 的 `QueryParam`，而 Go 的
    /// `url.Values.Encode()` 会按键排序 —— 这里三组合并后统一排序，逐字节一致。
    fn request(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        url: []const u8,
        method: []const u8,
        params: []const [2][]const u8,
        query: []const [2][]const u8,
        is_family: bool,
        retried: bool,
    ) !httpclient.Response {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        const params_data = try self.encryptParams(arena, params, is_family);
        const suffix = try clientSuffix(arena, rnd);

        var entries = List([2][]const u8).init(arena);
        for (suffix) |e| try entries.append(e);
        for (query) |e| try entries.append(e);
        if (params_data.len > 0) try entries.append(.{ "params", params_data });

        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(entries.slice());
        const full = try std.fmt.allocPrint(arena, "{s}?{s}", .{ url, q.slice() });

        var headers = List(model.Header).init(arena);
        try headers.appendSlice(try stdHeaders(arena));
        try headers.append(.{ .name = "Referer", .value = WEB_URL ++ "/" });
        try headers.appendSlice(try self.signatureHeaders(arena, url, method, params_data, is_family));

        const res = try self.client.send(arena, .{
            .method = method,
            .url = full,
            .headers = headers.slice(),
        });

        // 会话失效：上游靠这两个字符串判断，然后刷新 session 重放一次。
        if (!retried and (std.mem.indexOf(u8, res.body, "userSessionBO is null") != null or
            std.mem.indexOf(u8, res.body, "InvalidSessionKey") != null))
        {
            log.info("[189pc] {s}: session invalid, refreshing", .{requestPath(url)});
            try self.refreshSession(arena, 0);
            return self.request(arena, url, method, params, query, is_family, true);
        }

        try checkRespErr(arena, url, res.body);
        return res;
    }

    fn getBody(self: *Cloud189PC, arena: std.mem.Allocator, url: []const u8, query: []const [2][]const u8, is_family: bool) ![]const u8 {
        return (try self.request(arena, url, "GET", &.{}, query, is_family, false)).body;
    }

    fn postBody(self: *Cloud189PC, arena: std.mem.Allocator, url: []const u8, query: []const [2][]const u8, is_family: bool) ![]const u8 {
        return (try self.request(arena, url, "POST", &.{}, query, is_family, false)).body;
    }

    /// 登录流程里的裸请求：不带签名、不带 clientSuffix，失败只看 HTTP 状态码。
    fn rawPost(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        url: []const u8,
        headers: []const model.Header,
        form: []const u8,
    ) !httpclient.Response {
        var hs = List(model.Header).init(arena);
        try hs.appendSlice(try stdHeaders(arena));
        try hs.appendSlice(headers);
        try hs.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" });

        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = url,
            .headers = hs.slice(),
            .body = form,
        });
        if (!res.isOk()) {
            log.warn("[189pc] {s} HTTP {d}", .{ url, res.status });
            return Error.UpstreamHttp;
        }
        return res;
    }

    /// 批量任务那一组接口（`createBatchTask` / `checkBatchTask` / ...）走 form 且**带签名** ——
    /// 上游 `y.post(...)` 其实会经过 `y.request(...)`，于是既有 `clientSuffix` 查询键，又有 HMAC
    /// `Signature` 头；业务字段则通过 `SetFormData` 放进 **body**（而不是 query）。这里逐字节对齐：
    /// 仅 `clientSuffix` 进 query，`params` 留空（签名里也就不带 `&params=`），字段全部 urlencoded 进 body。
    fn signedFormPost(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        url: []const u8,
        form: []const u8,
        is_family: bool,
        retried: bool,
    ) ![]const u8 {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        const suffix = try clientSuffix(arena, rnd);
        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(&suffix);
        const full = try std.fmt.allocPrint(arena, "{s}?{s}", .{ url, q.slice() });

        var headers = List(model.Header).init(arena);
        try headers.appendSlice(try stdHeaders(arena));
        try headers.append(.{ .name = "Referer", .value = WEB_URL ++ "/" });
        try headers.appendSlice(try self.signatureHeaders(arena, url, "POST", "", is_family));
        try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" });

        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = full,
            .headers = headers.slice(),
            .body = form,
        });

        // 会话失效：与 `request` 一致，命中后刷新 session 重放一次。
        if (!retried and (std.mem.indexOf(u8, res.body, "userSessionBO is null") != null or
            std.mem.indexOf(u8, res.body, "InvalidSessionKey") != null))
        {
            log.info("[189pc] {s}: session invalid, refreshing", .{requestPath(url)});
            try self.refreshSession(arena, 0);
            return self.signedFormPost(arena, url, form, is_family, true);
        }

        try checkRespErr(arena, url, res.body);
        return res.body;
    }

    // -----------------------------------------------------------------------
    // 登录
    // -----------------------------------------------------------------------

    fn loginHeaders(self: *Cloud189PC, arena: std.mem.Allocator) ![]model.Header {
        var out = List(model.Header).init(arena);
        try out.append(.{ .name = "REQID", .value = self.req_id });
        try out.append(.{ .name = "lt", .value = self.lt });
        try out.append(.{ .name = "user-finger", .value = try self.userFinger() });
        try out.append(.{ .name = "Referer", .value = if (self.referer.len > 0) self.referer else AUTH_URL });
        return out.toOwned();
    }

    /// `LoginParam.encryptSecret` —— `pre + RsaEncrypt(pubKey, value)`。
    fn encryptSecret(self: *Cloud189PC, arena: std.mem.Allocator, value: []const u8, rnd: std.Random) ![]const u8 {
        const enc = try rsaEncryptUpper(arena, self.rsa_pem, value, rnd);
        return std.fmt.allocPrint(arena, "{s}{s}", .{ self.rsa_prefix, enc });
    }

    fn login(self: *Cloud189PC, arena: std.mem.Allocator) !void {
        self.login_mu.lockUncancelable(rt.io());
        defer self.login_mu.unlock(rt.io());

        if (self.cfg.username.len == 0 or self.cfg.password.len == 0) {
            log.err("[189pc] 需要 username/password，或者填 access_token / refresh_token", .{});
            return Error.NoCredentials;
        }
        try self.initLoginParam(arena);
        return self.loginByPassword(arena);
    }

    /// `initBaseParams` + `encryptConf` + `needcaptcha`。
    fn initLoginParam(self: *Cloud189PC, arena: std.mem.Allocator) !void {
        self.jar.clear();
        self.applyDeviceId();

        const ts = try numStr(arena, rt.nowMillis());

        // 1) 跟跳 unifyLoginForPC.action，从最终 URL 上取 lt/reqId
        var cur: []const u8 = try std.fmt.allocPrint(arena, "{s}/api/portal/unifyLoginForPC.action?appId={s}&clientType={s}&returnURL={s}&timeStamp={s}", .{
            WEB_URL, APP_ID, CLIENT_TYPE, RETURN_URL, ts,
        });
        var body: []const u8 = "";
        var hop: usize = 0;
        while (hop < max_redirects) : (hop += 1) {
            const res = try self.client.send(arena, .{
                .method = "GET",
                .url = cur,
                .headers = &.{ .{ .name = "User-Agent", .value = user_agent } },
            });
            if (res.status < 300 or res.status >= 400) {
                body = res.body;
                break;
            }
            const loc = res.header("Location") orelse break;
            cur = try resolveUrl(arena, cur, loc);
        }

        try self.setStr(&self.lt, "");
        try self.setStr(&self.req_id, "");
        try self.setStr(&self.referer, cur);

        const q = queryPart(cur);
        if ((try urlmod.queryGetDecoded(arena, q, "lt"))) |lt| if (lt.len > 0) try self.setStr(&self.lt, lt);
        if ((try urlmod.queryGetDecoded(arena, q, "reqId"))) |r| if (r.len > 0) try self.setStr(&self.req_id, r);


        if (self.lt.len == 0 or self.req_id.len == 0) {
            // 老登陆页：参数写在页内 JS 变量里
            const lt2 = matchLoginParam(arena, body, "lt = \"") orelse return Error.LoginFailed;
            const req2 = matchLoginParam(arena, body, "reqId = \"") orelse return Error.LoginFailed;
            const pid = matchLoginParam(arena, body, "paramId = \"") orelse return Error.LoginFailed;
            try self.setStr(&self.lt, lt2);
            try self.setStr(&self.req_id, req2);
            try self.setStr(&self.param_id, pid);
            try self.setStr(&self.captcha_token, matchLoginParam(arena, body, "'captchaToken' value='") orelse "");
        } else {
            // 新页面：paramId 要再问一次 appConf.do
            var f = urlmod.Query.init(arena);
            defer f.deinit();
            try f.add("version", "2.0");
            try f.add("appKey", APP_ID);
            const conf_res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/oauth2/appConf.do", try self.loginHeaders(arena), f.slice());
            const conf = json.parse(arena, conf_res.body) catch return Error.UpstreamNotJson;
            if (!appConfOk(&conf)) {
                log.err("[189pc] appConf: {s}", .{conf.strAt("msg") orelse ""});
                return Error.LoginFailed;
            }
            const pid = conf.strAt("data.paramId") orelse "";
            if (pid.len == 0) return Error.LoginFailed;
            try self.setStr(&self.param_id, pid);
        }

        // 2) RSA 公钥
        var f2 = urlmod.Query.init(arena);
        defer f2.deinit();
        try f2.add("appId", APP_ID);
        const enc_res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/config/encryptConf.do", &.{}, f2.slice());
        const enc = json.parse(arena, enc_res.body) catch return Error.UpstreamNotJson;
        if ((enc.intAt("result") orelse -1) != 0) {
            log.err("[189pc] encryptConf: {s}", .{enc_res.body[0..@min(enc_res.body.len, 200)]});
            return Error.LoginFailed;
        }
        const pre = enc.strAt("data.pre") orelse "";
        const pub_key = enc.strAt("data.pubKey") orelse "";
        if (pub_key.len == 0) return Error.LoginFailed;
        const pem = try std.fmt.allocPrint(arena, "-----BEGIN PUBLIC KEY-----\n{s}\n-----END PUBLIC KEY-----", .{pub_key});
        try self.setStr(&self.rsa_pem, pem);
        try self.setStr(&self.rsa_prefix, pre);

        // 3) 是否需要图形验证码
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();
        var f3 = urlmod.Query.init(arena);
        defer f3.deinit();
        try f3.add("appKey", APP_ID);
        try f3.add("accountType", ACCOUNT_TYPE);
        try f3.add("userName", try self.encryptSecret(arena, self.cfg.username, rnd));
        const nc_res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/oauth2/needcaptcha.do", try self.loginHeaders(arena), f3.slice());
        if (std.mem.eql(u8, std.mem.trim(u8, nc_res.body, " \t\r\n"), "0")) return;

        // 需要验证码：本工程没有 OCR，也不能把图片交给前端。
        log.err("[189pc] 登录需要图形验证码。请改填 access_token / refresh_token（从官方客户端抓），或在能交互的环境里先登录一次", .{});
        return Error.NeedInteractiveAuth;
    }

    fn loginByPassword(self: *Cloud189PC, arena: std.mem.Allocator) !void {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        const enc_user = try self.encryptSecret(arena, self.cfg.username, rnd);
        const enc_pass = try self.encryptSecret(arena, self.cfg.password, rnd);

        var f = urlmod.Query.init(arena);
        defer f.deinit();
        try f.add("version", "v2.0");
        try f.add("apToken", "");
        try f.add("appKey", APP_ID);
        try f.add("pageKey", "normal");
        try f.add("accountType", ACCOUNT_TYPE);
        try f.add("userName", enc_user);
        try f.add("password", enc_pass);
        try f.add("epd", enc_pass);
        try f.add("validateCode", self.cfg.validate_code);
        try f.add("captchaToken", self.captcha_token);
        try f.add("returnUrl", RETURN_URL);
        try f.add("dynamicCheck", "FALSE");
        try f.add("clientType", CLIENT_TYPE);
        try f.add("cb_SaveName", "1");
        try f.add("isOauth2", "false");
        try f.add("state", "");
        try f.add("paramId", self.param_id);

        const res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/oauth2/loginSubmit.do", try self.loginHeaders(arena), f.slice());
        self.saveDeviceIdNoErr(res);
        const lr = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

        // 验证码一次性：用完就清掉，免得下次登录带上一个过期的。
        if (self.cfg.validate_code.len > 0) try self.setCfgStr(&self.cfg.validate_code, "");

        if ((lr.intAt("result") orelse -1) == SECOND_DEVICE_AUTH_RESULT) {
            return self.secondDeviceAuth(arena, lr.strAt("mobile") orelse "");
        }
        const to_url = lr.strAt("toUrl") orelse "";
        if (to_url.len == 0) {
            log.err("[189pc] 登录失败: {s}", .{lr.strAt("msg") orelse res.body});
            return Error.LoginFailed;
        }
        return self.getSessionByRedirectUrl(arena, to_url);
    }

    /// 短信二次校验。填了 `sms_code` 就提交，否则发短信然后报错让用户去填。
    fn secondDeviceAuth(self: *Cloud189PC, arena: std.mem.Allocator, mobile: []const u8) !void {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        if (mobile.len > 0) try self.setStr(&self.second_auth_mobile, mobile);
        if (self.second_auth_mobile.len == 0) {
            log.err("[189pc] 需要设备二次校验，但服务端没返回手机号", .{});
            return Error.NeedInteractiveAuth;
        }

        if (self.cfg.sms_code.len > 0) {
            var f = urlmod.Query.init(arena);
            defer f.deinit();
            try f.add("mobile", self.second_auth_mobile);
            try f.add("appKey", APP_ID);
            try f.add("userName", try self.encryptSecret(arena, self.cfg.username, rnd));
            // 这个接口没有独立的验证码字段，短信码要加密后放进 epd
            // （登录时 epd 装的是密码）。
            try f.add("epd", try self.encryptSecret(arena, self.cfg.sms_code, rnd));
            try f.add("accountType", ACCOUNT_TYPE);
            try f.add("returnUrl", RETURN_URL);
            try f.add("isOauth2", "false");
            try f.add("cb_SaveName", "1");
            try f.add("state", "");
            try f.add("paramId", self.param_id);
            try self.setCfgStr(&self.cfg.sms_code, "");

            const res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/oauth2/submitForSecondAuth.do", try self.loginHeaders(arena), f.slice());
            self.saveDeviceIdNoErr(res);
            const ar = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
            if ((ar.intAt("result") orelse -1) != 0) {
                log.err("[189pc] 二次校验失败: {s}", .{ar.strAt("msg") orelse ""});
                return Error.LoginFailed;
            }
            const to_url = ar.strAt("toUrl") orelse "";
            if (to_url.len == 0) return Error.LoginFailed;
            return self.getSessionByRedirectUrl(arena, to_url);
        }

        var f = urlmod.Query.init(arena);
        defer f.deinit();
        try f.add("mobile", self.second_auth_mobile);
        try f.add("appKey", APP_ID);
        const res = try self.rawPost(arena, AUTH_URL ++ "/api/logbox/oauth2/sendSmsCodeForSecondAuth.do", try self.loginHeaders(arena), f.slice());
        const sr = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        if ((sr.intAt("result") orelse -1) != 0) {
            log.err("[189pc] 发送短信失败: {s}", .{sr.strAt("msg") orelse ""});
            return Error.LoginFailed;
        }
        log.warn("[189pc] 需要短信二次校验：验证码已发送，请填进 sms_code 再保存一次", .{});
        return Error.NeedInteractiveAuth;
    }

    /// `getSessionByRedirectURL` —— 用登录结果的跳转地址换 session。
    fn getSessionByRedirectUrl(self: *Cloud189PC, arena: std.mem.Allocator, redirect_url: []const u8) !void {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        var entries = List([2][]const u8).init(arena);
        const suffix = try clientSuffix(arena, rnd);
        for (suffix) |e| try entries.append(e);
        try entries.append(.{ "returnType", "JSON" });
        if (self.cfg.client_sn.len > 0) try entries.append(.{ "clientSn", self.cfg.client_sn });
        if (self.cfg.jg_open_id.len > 0) try entries.append(.{ "jgOpenId", self.cfg.jg_open_id });
        try entries.append(.{ "redirectURL", redirect_url });

        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(entries.slice());

        var hs = List(model.Header).init(arena);
        try hs.appendSlice(try stdHeaders(arena));
        try hs.append(.{ .name = "X-Request-ID", .value = try uuidV4(arena, rnd) });

        const url = try std.fmt.allocPrint(arena, "{s}/getSessionForPC.action?{s}", .{ API_URL, q.slice() });
        const res = try self.client.send(arena, .{ .method = "POST", .url = url, .headers = hs.slice() });
        try checkRespErr(arena, url, res.body);

        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        try self.applySession(&v);
        try self.setCfgStr(&self.cfg.access_token, v.strAt("accessToken") orelse "");
        try self.setCfgStr(&self.cfg.refresh_token, v.strAt("refreshToken") orelse "");
        self.save();
    }

    fn applySession(self: *Cloud189PC, v: *const json.Value) !void {
        try self.setStr(&self.session_key, v.strAt("sessionKey") orelse "");
        try self.setStr(&self.session_secret, v.strAt("sessionSecret") orelse "");
        try self.setStr(&self.family_session_key, v.strAt("familySessionKey") orelse "");
        try self.setStr(&self.family_session_secret, v.strAt("familySessionSecret") orelse "");
        try self.setStr(&self.login_name, v.strAt("loginName") orelse "");
    }

    /// `refreshSession` —— 用 accessToken 换 session。
    fn refreshSession(self: *Cloud189PC, arena: std.mem.Allocator, retry: usize) !void {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        var entries = List([2][]const u8).init(arena);
        const suffix = try clientSuffix(arena, rnd);
        for (suffix) |e| try entries.append(e);
        try entries.append(.{ "returnType", "JSON" });
        if (self.cfg.client_sn.len > 0) try entries.append(.{ "clientSn", self.cfg.client_sn });
        if (self.cfg.jg_open_id.len > 0) try entries.append(.{ "jgOpenId", self.cfg.jg_open_id });
        try entries.append(.{ "appId", APP_ID });
        try entries.append(.{ "accessToken", self.cfg.access_token });

        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(entries.slice());

        var hs = List(model.Header).init(arena);
        try hs.appendSlice(try stdHeaders(arena));
        try hs.append(.{ .name = "X-Request-ID", .value = try uuidV4(arena, rnd) });

        const url = try std.fmt.allocPrint(arena, "{s}/getSessionForPC.action?{s}", .{ API_URL, q.slice() });
        const res = try self.client.send(arena, .{ .method = "GET", .url = url, .headers = hs.slice() });

        // accessToken 作废 → 用 refreshToken 换一对新的
        if (json.parse(arena, res.body)) |v| {
            if (std.mem.eql(u8, v.strAt("res_code") orelse "", USER_INVALID_OPEN_TOKEN)) {
                return self.refreshToken(arena, retry);
            }
        } else |_| {}
        try checkRespErr(arena, url, res.body);
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        try self.applySession(&v);
    }

    /// `refreshTokenWithRetry` —— 用 refreshToken 换一对新 token，再换 session。
    /// 最多 3 次，超过就清掉 refreshToken。
    fn refreshToken(self: *Cloud189PC, arena: std.mem.Allocator, retry: usize) !void {
        if (retry >= 3) {
            try self.setCfgStr(&self.cfg.refresh_token, "");
            log.err("[189pc] refresh token 连续失败 3 次，已清空 refresh_token", .{});
            return Error.LoginFailed;
        }

        var f = urlmod.Query.init(arena);
        defer f.deinit();
        try f.add("clientId", APP_ID);
        try f.add("refreshToken", self.cfg.refresh_token);
        try f.add("grantType", "refresh_token");
        try f.add("format", "json");

        const res = try self.rawPost(arena, AUTH_URL ++ "/api/oauth2/refreshToken.do", &.{}, f.slice());
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

        // 这个接口失败时也是 HTTP 200，只能看响应体。
        const access = v.strAt("accessToken") orelse "";
        if ((v.intAt("result") orelse -1) != 0 or access.len == 0) {
            try self.setCfgStr(&self.cfg.refresh_token, "");
            if (self.cfg.username.len == 0 or self.cfg.password.len == 0) {
                log.err("[189pc] refresh token 失败: {s}", .{v.strAt("msg") orelse ""});
                return Error.LoginFailed;
            }
            log.info("[189pc] refresh token 失败，回退到完整登录", .{});
            return self.login(arena);
        }

        try self.setCfgStr(&self.cfg.access_token, access);
        try self.setCfgStr(&self.cfg.refresh_token, v.strAt("refreshToken") orelse "");
        self.save();
        return self.refreshSession(arena, retry + 1);
    }

    fn getFamilyId(self: *Cloud189PC, arena: std.mem.Allocator) ![]const u8 {
        const body = try self.getBody(arena, API_URL ++ "/family/manage/getFamilyList.action", &.{}, true);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const infos = if (v.getPath("familyInfoResp")) |p| p.asArray() orelse &.{} else &.{};
        if (infos.len == 0) {
            log.err("[189pc] 取不到家庭云列表，请在配置里手填 family_id", .{});
            return Error.FamilyIdRequired;
        }
        for (infos) |item| {
            const remark = item.strAt("remarkName") orelse "";
            if (remark.len > 0 and std.mem.indexOf(u8, self.login_name, remark) != null) {
                return numStr(arena, item.intAt("familyId") orelse 0);
            }
        }
        return numStr(arena, infos[0].intAt("familyId") orelse 0);
    }

    // -----------------------------------------------------------------------
    // 目录
    // -----------------------------------------------------------------------

    const Entry = struct {
        id: []const u8,
        name: []const u8,
        is_dir: bool,
    };

    const Page = struct {
        count: i64,
        folders: []const json.Value,
        files: []const json.Value,
    };

    fn listPage(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        folder_id: []const u8,
        page_num: i64,
        size: i64,
        order_by: []const u8,
        order_direction: []const u8,
    ) !Page {
        const url = if (self.isFamily())
            API_URL ++ "/family/file/listFiles.action"
        else
            API_URL ++ "/listFiles.action";

        var entries = List([2][]const u8).init(arena);
        try entries.append(.{ "folderId", folder_id });
        try entries.append(.{ "fileType", "0" });
        try entries.append(.{ "mediaAttr", "0" });
        try entries.append(.{ "iconOption", "5" });
        try entries.append(.{ "pageNum", try numStr(arena, page_num) });
        try entries.append(.{ "pageSize", try numStr(arena, size) });
        if (self.isFamily()) {
            try entries.append(.{ "familyId", self.cfg.family_id });
            try entries.append(.{ "orderBy", toFamilyOrderBy(order_by) });
            try entries.append(.{ "descending", toDesc(order_direction) });
        } else {
            try entries.append(.{ "recursive", "0" });
            try entries.append(.{ "orderBy", order_by });
            try entries.append(.{ "descending", toDesc(order_direction) });
        }

        const body = try self.getBody(arena, url, entries.slice(), self.isFamily());
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const ao = v.getPath("fileListAO") orelse return .{ .count = 0, .folders = &.{}, .files = &.{} };
        return .{
            .count = ao.intAt("count") orelse 0,
            .folders = if (ao.getPath("folderList")) |p| p.asArray() orelse &.{} else &.{},
            .files = if (ao.getPath("fileList")) |p| p.asArray() orelse &.{} else &.{},
        };
    }

    fn getFiles(self: *Cloud189PC, alloc: std.mem.Allocator, folder_id: []const u8) ![]model.Obj {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        var out = List(model.Obj).init(alloc);
        var page_num: i64 = 1;
        while (true) {
            const page = try self.listPage(a, folder_id, page_num, @intCast(page_size), self.cfg.order_by, self.cfg.order_direction);
            if (page.count == 0) break;

            for (page.folders) |item| {
                try out.append(.{
                    .name = try normalizeName(alloc, item.strAt("name") orelse ""),
                    .size = 0,
                    .is_dir = true,
                    .modified = parse189Time(item.strAt("lastOpTime") orelse "") orelse 0,
                    .created = parse189Time(item.strAt("createDate") orelse "") orelse 0,
                });
            }
            for (page.files) |item| {
                const icon = item.getPath("icon");
                try out.append(.{
                    .name = try normalizeName(alloc, item.strAt("name") orelse ""),
                    .size = item.intAt("size") orelse 0,
                    .is_dir = false,
                    .modified = parse189Time(item.strAt("lastOpTime") orelse "") orelse 0,
                    .created = parse189Time(item.strAt("createDate") orelse "") orelse 0,
                    .thumb = if (icon) |ic| ic.strAt("smallUrl") orelse "" else "",
                    .hash_info = if (item.strAt("md5")) |m|
                        model.HashInfo{ .hash_name = "md5", .hash_value = m }
                    else
                        null,
                });
            }

            // 本页没填满说明是最后一页。
            if (page.folders.len + page.files.len < page_size) break;
            page_num += 1;
        }
        return out.toOwned();
    }

    fn resolve(self: *Cloud189PC, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    fn findChild(self: *Cloud189PC, arena: std.mem.Allocator, parent_id: []const u8, name: []const u8) !Entry {
        var page_num: i64 = 1;
        while (true) {
            const page = try self.listPage(arena, parent_id, page_num, @intCast(page_size), "filename", "asc");
            if (page.count == 0) return driver.Error.NotFound;
            // ⚠️ `name` 是调用方给的路径段（已经过 `normalizeName`，因为 list 返回的
            // 就是归一化后的名字）。服务端返回的是**原始名**，可能含 `\'`。不归一化
            // 就比对，含撇号的文件/目录永远匹配不上 → 按路径解析 404。
            // 对齐 Go：那边靠 ID 寻址，不经过名字匹配，所以没这个坑。
            for (page.folders) |item| {
                if (std.mem.eql(u8, try normalizeName(arena, item.strAt("name") orelse ""), name)) {
                    return .{ .id = try idOf(arena, &item), .name = name, .is_dir = true };
                }
            }
            for (page.files) |item| {
                if (std.mem.eql(u8, try normalizeName(arena, item.strAt("name") orelse ""), name)) {
                    return .{ .id = try idOf(arena, &item), .name = name, .is_dir = false };
                }
            }
            if (page.folders.len + page.files.len < page_size) return driver.Error.NotFound;
            page_num += 1;
        }
    }

    // -----------------------------------------------------------------------
    // 批量任务（移动 / 删除）
    // -----------------------------------------------------------------------

    fn writeTaskInfos(b: *Buf, tasks: []const Entry) !void {
        try b.appendByte('[');
        for (tasks, 0..) |t, i| {
            if (i > 0) try b.appendByte(',');
            try b.appendByte('{');
            try json.writeString(b, "fileId");
            try b.appendByte(':');
            try json.writeString(b, t.id);
            try b.appendByte(',');
            try json.writeString(b, "fileName");
            try b.appendByte(':');
            try json.writeString(b, t.name);
            try b.appendByte(',');
            try json.writeString(b, "isFolder");
            try b.appendByte(':');
            try b.append(if (t.is_dir) "1" else "0");
            try b.appendByte('}');
        }
        try b.appendByte(']');
    }

    /// 批处理任务的 `familyId` —— 对齐 Go `driver.go:254/357` 的
    /// `IF(isFamily, y.FamilyID, "")`。`utils.go:1523` 只在这个值非空时写进
    /// form，所以「个人云」的返回值必须是空串 —— 哪怕 `init` 已经把
    /// `family_id` 取回来了（Go 的 `Init` 也一样无条件取）。
    fn batchFamilyId(self: *const Cloud189PC) []const u8 {
        return if (self.isFamily()) self.cfg.family_id else "";
    }

    fn createBatchTask(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        kind: []const u8,
        target_folder_id: []const u8,
        tasks: []const Entry,
        other: []const [2][]const u8,
    ) ![]const u8 {
        var tasks_buf = Buf.init(arena);
        try writeTaskInfos(&tasks_buf, tasks);

        var f = urlmod.Query.init(arena);
        defer f.deinit();
        try f.add("type", kind);
        try f.add("taskInfos", tasks_buf.slice());
        if (target_folder_id.len > 0) try f.add("targetFolderId", target_folder_id);
        // 对齐 Go `driver.go:254/357`：家族 id 传的是 `IF(isFamily, FamilyID, "")`，
        // 个人云是**空串**，而 `utils.go:1523` 只在非空时才写进 form。
        // 不判 `isFamily` 的话，个人云的 MOVE/DELETE 会带上一个家庭云的 familyId。
        const family_id = self.batchFamilyId();
        if (family_id.len > 0) try f.add("familyId", family_id);
        for (other) |o| try f.add(o[0], o[1]);

        // 上游 `y.CreateBatchTask` 经 `y.post` → `y.request`，带 clientSuffix + 签名；
        // familyID 非空时（familyId 已在 form 里）用 family 会话签名。
        const body = try self.signedFormPost(arena, API_URL ++ "/batch/createBatchTask.action", f.slice(), self.isFamily(), false);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return v.strAt("taskId") orelse return Error.InvalidResponse;
    }

    fn checkBatchTask(self: *Cloud189PC, arena: std.mem.Allocator, kind: []const u8, task_id: []const u8) !i64 {
        var f = urlmod.Query.init(arena);
        defer f.deinit();
        try f.add("type", kind);
        try f.add("taskId", task_id);
        // 上游 `y.CheckBatchTask` 经 `y.post`，但没传 isFamily，所以始终用个人会话签名。
        const body = try self.signedFormPost(arena, API_URL ++ "/batch/checkBatchTask.action", f.slice(), false, false);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return v.intAt("taskStatus") orelse 0;
    }

    /// `WaitBatchTask` —— 1 初始化 / 2 冲突 / 3 执行中 / 4 完成。
    fn waitBatchTask(self: *Cloud189PC, arena: std.mem.Allocator, kind: []const u8, task_id: []const u8, interval_ms: i64) !void {
        while (true) {
            const st = try self.checkBatchTask(arena, kind, task_id);
            if (st == 2) {
                log.warn("[189pc] 批量任务 {s} 撞上同名目标", .{task_id});
                return Error.Conflict;
            }
            if (st == 4) return;
            rt.sleepMillis(interval_ms);
        }
    }

    // -----------------------------------------------------------------------
    // vtable
    // -----------------------------------------------------------------------

    fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(ptr);
        const e = try self.resolve(ctx.alloc, dir);
        return self.getFiles(ctx.alloc, e.id);
    }

    fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(ptr);
        const e = try self.resolve(ctx.alloc, path);
        return model.File.fromObj(.{ .name = e.name, .is_dir = e.is_dir });
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: model.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;

        const e = try self.resolve(a, path);
        const url = if (self.isFamily())
            API_URL ++ "/family/file/getFileDownloadUrl.action"
        else
            API_URL ++ "/getFileDownloadUrl.action";

        var entries = List([2][]const u8).init(a);
        try entries.append(.{ "fileId", e.id });
        if (self.isFamily()) {
            try entries.append(.{ "familyId", self.cfg.family_id });
        } else {
            try entries.append(.{ "dt", "3" });
            try entries.append(.{ "flag", "1" });
        }

        const body = try self.getBody(a, url, entries.slice(), self.isFamily());
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const raw = v.strAt("fileDownloadUrl") orelse return Error.InvalidResponse;
        const first = try normalizeDownloadUrl(a, raw);

        // 上游用 NoRedirectClient 解一跳。
        var final_url: []const u8 = first;
        const res = try self.client.send(a, .{
            .method = "GET",
            .url = first,
            .headers = &.{.{ .name = "User-Agent", .value = user_agent }},
            .use_cookies = false,
        });
        if (res.status == 302) {
            if (res.header("location")) |loc| final_url = loc;
        }

        if (args.redirect) return .{ .url = final_url, .proxy = false };
        // 同上：`header` 必须分配在 ctx.alloc 上，`&.{.{...}}` 返回的是栈临时量。
        const hdrs = try a.alloc(model.Header, 1);
        hdrs[0] = .{ .name = "User-Agent", .value = user_agent };
        return .{
            .url = final_url,
            .header = hdrs,
            .proxy = true,
        };
    }

    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dir);
        if (name.len == 0) return Error.InvalidPath;
        const parent = try self.resolve(a, parentOf(dir));

        const url = if (self.isFamily())
            API_URL ++ "/family/file/createFolder.action"
        else
            API_URL ++ "/createFolder.action";

        var entries = List([2][]const u8).init(a);
        try entries.append(.{ "folderName", name });
        try entries.append(.{ "relativePath", "" });
        if (self.isFamily()) {
            try entries.append(.{ "familyId", self.cfg.family_id });
            try entries.append(.{ "parentId", parent.id });
        } else {
            try entries.append(.{ "parentFolderId", parent.id });
        }
        _ = try self.postBody(a, url, entries.slice(), self.isFamily());
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src_path: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, src_path);
        const dst = try self.resolve(a, dst_dir);

        // 上游把目标目录的**名字**放在 targetFileName 里（不是要改成的名字）。
        const other = [1][2][]const u8{.{ "targetFileName", dst.name }};
        const tasks = [1]Entry{src};
        const task_id = try self.createBatchTask(a, "MOVE", dst.id, &tasks, &other);
        try self.waitBatchTask(a, "MOVE", task_id, 400);
    }

    /// Go `drivers/189pc/driver.go:327-345`：COPY 与 MOVE 一样是
    /// `CreateBatchTask` + `WaitBatchTask`，区别是
    /// ① `type=COPY`；② 轮询间隔 1s（MOVE 400ms、DELETE 200ms）。
    ///
    /// 未移植的部分（已在源码里声明）：Go 还会在复制非目录后
    /// `torrentFollowCopy` 跟着复制同名 torrent —— 那是 BT 专属功能，
    /// 本工程没有离线下载，略过不影响其它场景。
    fn copy(ptr: *anyopaque, ctx: *driver.Ctx, src_path: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, src_path);
        const dst = try self.resolve(a, dst_dir);

        const other = [1][2][]const u8{.{ "targetFileName", dst.name }};
        const tasks = [1]Entry{src};
        const task_id = try self.createBatchTask(a, "COPY", dst.id, &tasks, &other);
        try self.waitBatchTask(a, "COPY", task_id, 1000);
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        var src = try self.resolve(a, path);
        if (is_dir) src.is_dir = true;
        const tasks = [1]Entry{src};
        const task_id = try self.createBatchTask(a, "DELETE", "", &tasks, &.{});
        // 上游注释：批量任务过快会导致删不掉。
        try self.waitBatchTask(a, "DELETE", task_id, 200);
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, path);

        var entries = List([2][]const u8).init(a);
        var url: []const u8 = undefined;
        var method: []const u8 = "POST";
        if (self.isFamily()) {
            try entries.append(.{ "familyId", self.cfg.family_id });
            method = "GET";
            url = if (src.is_dir)
                API_URL ++ "/family/file/renameFolder.action"
            else
                API_URL ++ "/family/file/renameFile.action";
        } else {
            url = if (src.is_dir)
                API_URL ++ "/renameFolder.action"
            else
                API_URL ++ "/renameFile.action";
        }
        if (src.is_dir) {
            try entries.append(.{ "folderId", src.id });
            try entries.append(.{ "destFolderName", new_name });
        } else {
            try entries.append(.{ "fileId", src.id });
            try entries.append(.{ "destFileName", new_name });
        }
        _ = try self.request(a, url, method, &.{}, entries.slice(), self.isFamily(), false);
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(ptr);
        const a = ctx.alloc;
        const body = try self.getBody(a, API_URL ++ "/portal/getUserSizeInfo.action", &.{}, false);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        return if (self.isFamily()) .{
            .total = v.intAt("familyCapacityInfo.totalSize") orelse 0,
            .used = v.intAt("familyCapacityInfo.usedSize") orelse 0,
        } else .{
            .total = v.intAt("cloudCapacityInfo.totalSize") orelse 0,
            .used = v.intAt("cloudCapacityInfo.usedSize") orelse 0,
        };
    }

    // -----------------------------------------------------------------------
    // 上传
    // -----------------------------------------------------------------------

    const UploadTarget = struct {
        url: []const u8,
        headers: []model.Header,
    };

    /// `GetMultiUploadUrls` —— 一次只问一片。
    fn getMultiUploadUrls(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        upload_file_id: []const u8,
        part_info: []const u8,
    ) !UploadTarget {
        const params = [2][2][]const u8{
            .{ "uploadFileId", upload_file_id },
            .{ "partInfo", part_info },
        };
        const res = try self.request(
            arena,
            try std.fmt.allocPrint(arena, "{s}/getMultiUploadUrls", .{self.uploadBase()}),
            "GET",
            &params,
            &.{},
            self.isFamily(),
            false,
        );
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

        // `uploadUrls` 是 {"partNumber_1": {...}}，键名带分片号 —— 只问了一片，
        // 取第一个值即可，不用去猜键名。
        const urls = v.getPath("uploadUrls") orelse return Error.InvalidResponse;
        const obj = urls.asObject() orelse return Error.InvalidResponse;
        // 一次只问了一片，所以 `uploadUrls` 里只有一个 "partNumber_N" 键 ——
        // 不用去拼键名，取第一个值即可（上游是按 partNumber 排序后取 [0]）。
        if (obj.vals.len == 0) return Error.InvalidResponse;
        const node = &obj.vals[0];
        const request_url = node.strAt("requestURL") orelse return Error.InvalidResponse;

        var hs = List(model.Header).init(arena);
        try hs.append(.{ .name = "User-Agent", .value = user_agent });
        try hs.appendSlice(try parseHttpHeader(arena, node.strAt("requestHeader") orelse ""));
        return .{ .url = request_url, .headers = try hs.toOwned() };
    }

    /// 上传一个分片。分片 URL 上也要带 `clientSuffix`（Go 的 `put` 显式加）。
    fn putPart(
        self: *Cloud189PC,
        arena: std.mem.Allocator,
        upload_file_id: []const u8,
        part_number: i64,
        md5_b64: []const u8,
        chunk: []const u8,
    ) !void {
        const part_info = try std.fmt.allocPrint(arena, "{d}-{s}", .{ part_number, md5_b64 });
        const target = try self.getMultiUploadUrls(arena, upload_file_id, part_info);

        var src = std.Random.IoSource{ .io = rt.io() };
        const suffix = try clientSuffix(arena, src.interface());
        var q = urlmod.Query.init(arena);
        defer q.deinit();
        try q.addSorted(&suffix);
        const full = try std.fmt.allocPrint(arena, "{s}{s}{s}", .{
            target.url,
            if (std.mem.indexOfScalar(u8, target.url, '?') != null) "&" else "?",
            q.slice(),
        });

        const res = try self.client.send(arena, .{
            .method = "PUT",
            .url = full,
            .headers = target.headers,
            .body = chunk,
            .use_cookies = false,
        });
        if (res.status != 200) {
            log.warn("[189pc] 第 {d} 片 HTTP {d}: {s}", .{
                part_number, res.status, res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamHttp;
        }
    }

    /// 各分片 MD5（大写）用 "\n" 连起来再 MD5 —— 同样大写。
    fn joinSliceMd5(alloc: std.mem.Allocator, parts: []const []const u8) ![]const u8 {
        var joined = Buf.init(alloc);
        defer joined.deinit();
        for (parts, 0..) |m, i| {
            if (i > 0) try joined.appendByte('\n');
            try joined.append(m);
        }
        const d = hash.md5(joined.slice());
        return hash.hexUpper(alloc, &d);
    }

    /// `StreamUpload` —— 边传边算 MD5，适合不能回头的流。
    fn streamUpload(self: *Cloud189PC, a: std.mem.Allocator, dir: Entry, name: []const u8, src: model.Source, ctx: *const driver.Ctx) !void {
        const size = src.size();
        if (size < 0) return Error.InvalidPath;
        const slice = partSize(size);
        const count: i64 = if (size > slice) @divTrunc(size + slice - 1, slice) else 1;

        var params = List([2][]const u8).init(a);
        try params.append(.{ "parentFolderId", dir.id });
        try params.append(.{ "fileName", try urlmod.encode(a, name, .form) });
        try params.append(.{ "fileSize", try numStr(a, size) });
        try params.append(.{ "sliceSize", try numStr(a, slice) });
        try params.append(.{ "lazyCheck", "1" });
        if (self.isFamily()) try params.append(.{ "familyId", self.cfg.family_id });

        const body = (try self.request(
            a,
            try std.fmt.allocPrint(a, "{s}/initMultiUpload", .{self.uploadBase()}),
            "GET",
            params.slice(),
            &.{},
            self.isFamily(),
            false,
        )).body;
        const init_v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const data = init_v.getPath("data") orelse return Error.InvalidResponse;
        const upload_file_id = data.strAt("uploadFileId") orelse return Error.InvalidResponse;

        // T7：整份上传复用同一个块缓冲。旧的 `readAll` 每块都往请求 arena
        // 新分配 —— 1 GB 文件（slice 阶梯最大到几十 MB）能把 arena 堆到
        // 1 GB，直到请求结束才释放；fastUpload 还有第二遍读，峰值翻倍。
        // 光猫上几个并发上传就 OOM。改成 slice 大小的一个 buffer，
        // 逐块读入 / 算 MD5 / putPart 同步发送 / 覆盖复用。
        const chunk_buf = try a.alloc(u8, @intCast(slice));
        var full = hash.Md5Stream{};
        var slice_md5s = List([]const u8).init(a);
        var part: i64 = 1;
        var offset: i64 = 0;
        while (part <= count) : (part += 1) {
            const want = partLen(size, slice, part, count);
            const real: i64 = @min(want, @max(size - offset, 0));
            const chunk = chunk_buf[0..@intCast(real)];
            try src.readAllInto(@intCast(offset), chunk);
            full.update(chunk);
            const d = hash.md5(chunk);
            try slice_md5s.append(try hash.hexUpper(a, &d));
            offset += real;
            try self.putPart(a, upload_file_id, part, try hash.base64Std(a, &d), chunk);
            // 每片报一次百分比（0–100，Go `model.UpdateProgress` 语义）。
            if (ctx.progress) |f| {
                const pct: u64 = @intCast(@min(@divTrunc(offset * 100, @max(size, 1)), 100));
                f(ctx.progress_userdata, pct);
            }
        }

        const file_md5 = try full.finalHexUpper(a);
        const slice_md5: []const u8 = if (size > slice)
            try joinSliceMd5(a, slice_md5s.slice())
        else
            file_md5;

        var commit = List([2][]const u8).init(a);
        try commit.append(.{ "uploadFileId", upload_file_id });
        try commit.append(.{ "fileMd5", file_md5 });
        try commit.append(.{ "sliceMd5", slice_md5 });
        try commit.append(.{ "lazyCheck", "1" });
        try commit.append(.{ "isLog", "0" });
        try commit.append(.{ "opertype", "3" });
        _ = try self.request(
            a,
            try std.fmt.allocPrint(a, "{s}/commitMultiUploadFile", .{self.uploadBase()}),
            "GET",
            commit.slice(),
            &.{},
            self.isFamily(),
            false,
        );
        // 流式路径的最后一片已在循环里报过进度，这里补一个收尾的 100%。
        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
    }

    /// `FastUpload` —— 先算完整个文件的 MD5 再上传，这样 `initMultiUpload`
    /// 就能直接判断能不能秒传。
    fn fastUpload(self: *Cloud189PC, a: std.mem.Allocator, dir: Entry, name: []const u8, src: model.Source, ctx: *const driver.Ctx) !void {
        const size = src.size();
        if (size < 0) return Error.InvalidPath;
        const slice = partSize(size);
        const count: i64 = if (size > slice) @divTrunc(size + slice - 1, slice) else 1;

        // T7：两遍读（先算 MD5 判秒传，再上传）共用**同一个**块缓冲。
        // 修复前每遍每块都新分配，峰值 2×文件大小。
        const chunk_buf = try a.alloc(u8, @intCast(slice));
        var full = hash.Md5Stream{};
        var slice_md5s = List([]const u8).init(a);
        var part: i64 = 1;
        var offset: i64 = 0;
        while (part <= count) : (part += 1) {
            const want = partLen(size, slice, part, count);
            const real: i64 = @min(want, @max(size - offset, 0));
            const chunk = chunk_buf[0..@intCast(real)];
            try src.readAllInto(@intCast(offset), chunk);
            full.update(chunk);
            try slice_md5s.append(try hash.hexUpper(a, &hash.md5(chunk)));
            offset += real;
        }
        const file_md5 = try full.finalHexUpper(a);
        const slice_md5: []const u8 = if (size > slice)
            try joinSliceMd5(a, slice_md5s.slice())
        else
            file_md5;

        var params = List([2][]const u8).init(a);
        try params.append(.{ "parentFolderId", dir.id });
        try params.append(.{ "fileName", try urlmod.encode(a, name, .form) });
        try params.append(.{ "fileSize", try numStr(a, size) });
        try params.append(.{ "fileMd5", file_md5 });
        try params.append(.{ "sliceSize", try numStr(a, slice) });
        try params.append(.{ "sliceMd5", slice_md5 });
        if (self.isFamily()) try params.append(.{ "familyId", self.cfg.family_id });

        const body = (try self.request(
            a,
            try std.fmt.allocPrint(a, "{s}/initMultiUpload", .{self.uploadBase()}),
            "GET",
            params.slice(),
            &.{},
            self.isFamily(),
            false,
        )).body;
        const init_v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const data = init_v.getPath("data") orelse return Error.InvalidResponse;
        const upload_file_id = data.strAt("uploadFileId") orelse return Error.InvalidResponse;

        if ((data.intAt("fileDataExists") orelse 0) != 1) {
            var part_no: i64 = 1;
            var off: i64 = 0;
            while (part_no <= count) : (part_no += 1) {
                const want = partLen(size, slice, part_no, count);
                const real: i64 = @min(want, @max(size - off, 0));
                const chunk = chunk_buf[0..@intCast(real)];
                try src.readAllInto(@intCast(off), chunk);
                off += real;
                const d = hash.md5(chunk);
                try self.putPart(a, upload_file_id, part_no, try hash.base64Std(a, &d), chunk);
            }
        } else {
            log.info("[189pc] {s}: 秒传命中", .{name});
        }

        var commit = List([2][]const u8).init(a);
        try commit.append(.{ "uploadFileId", upload_file_id });
        try commit.append(.{ "isLog", "0" });
        try commit.append(.{ "opertype", "3" });
        _ = try self.request(
            a,
            try std.fmt.allocPrint(a, "{s}/commitMultiUploadFile", .{self.uploadBase()}),
            "GET",
            commit.slice(),
            &.{},
            self.isFamily(),
            false,
        );
        // fast 路径的字节只在「算整文件 MD5」时流经本地，提交完成后报 100%。
        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
    }

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dst);
        if (name.len == 0) return Error.InvalidPath;
        const dir = try self.resolve(a, parentOf(dst));
        if (!dir.is_dir) return Error.InvalidPath;

        // `rapid` 先算 MD5 好秒传；`stream` 遇到 0 字节文件也只能走 fast ——
        // stream 路径对空文件会按一个整片去读，必然失败（上游注释里也写了）。
        if (std.mem.eql(u8, self.cfg.upload_method, "rapid") or src.size() == 0) {
            return self.fastUpload(a, dir, name, src, ctx);
        }
        return self.streamUpload(a, dir, name, src, ctx);
    }
};

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "189CloudPC",
    .label = "天翼云盘（PC 端 / 家庭云）",
    .secrets = &.{ "password", "access_token", "refresh_token", "sms_code" },
    .addition_schema =
    \\{
    \\  "login_type":       {"type":"select","default":"password","options":["password","qrcode"],"help":"qrcode 本工程不支持（无法把二维码回传前端）"},
    \\  "username":         {"type":"string","help":"有 access_token / refresh_token 时可不填"},
    \\  "password":         {"type":"string","secret":true,"help":"有 access_token / refresh_token 时可不填"},
    \\  "validate_code":    {"type":"string","help":"图形验证码。本工程不能 OCR，触发时建议改填 token"},
    \\  "sms_code":         {"type":"string","help":"短信二次校验码，收到后填进来再保存一次"},
    \\  "access_token":     {"type":"string","secret":true,"help":"从官方客户端抓"},
    \\  "refresh_token":    {"type":"string","secret":true,"help":"换账号请清空这个字段"},
    \\  "device_id":        {"type":"string","secret":true,"help":"二次校验后服务端下发的设备标识，留着可不再校验"},
    \\  "client_sn":        {"type":"string","help":"官方客户端的设备序列号，没有就留空"},
    \\  "jg_open_id":       {"type":"string","help":"官方客户端上报的推送 id，可选"},
    \\  "user_finger":      {"type":"string","help":"设备指纹，留空会自动生成并保存"},
    \\  "root_folder_id":   {"type":"string","default":"-11","help":"个人云 -11，家庭云留空"},
    \\  "order_by":         {"type":"select","default":"filename","options":["filename","filesize","lastOpTime"]},
    \\  "order_direction":  {"type":"select","default":"asc","options":["asc","desc"]},
    \\  "type":             {"type":"select","default":"personal","options":["personal","family"]},
    \\  "family_id":        {"type":"string","help":"留空会自动获取"},
    \\  "upload_method":    {"type":"select","default":"stream","options":["stream","rapid"],"help":"rapid 先算 MD5 可秒传；stream 边传边算"},
    \\  "upload_thread":    {"type":"string","default":"3","help":"保留字段：本工程串行上传（HTTP 客户端有全局锁）"},
    \\  "family_transfer":  {"type":"bool","default":false,"help":"保留字段：家庭云转存本工程未实现"},
    \\  "rapid_upload":     {"type":"bool","default":false,"help":"保留字段：旧接口的秒传本工程未实现"},
    \\  "no_use_ocr":       {"type":"bool","default":false,"help":"保留字段：本工程从不使用 OCR"},
    \\  "generate_torrent": {"type":"bool","default":false,"help":"保留字段：上传后生成 .cas.torrent 本工程未实现"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(Cloud189PC, self);
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Cloud189PC {
    const self = try alloc.create(Cloud189PC);
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

test "partSize follows the documented ladder" {
    const mb = 1024 * 1024;
    // 999 片以内都是 10 MiB
    try testing.expectEqual(@as(i64, slice_base), partSize(0));
    try testing.expectEqual(@as(i64, slice_base), partSize(10 * mb));
    try testing.expectEqual(@as(i64, slice_base), partSize(999 * slice_base));
    // 再大 → 20 MiB
    try testing.expectEqual(@as(i64, 2 * slice_base), partSize(999 * slice_base + 1));
    try testing.expectEqual(@as(i64, 2 * slice_base), partSize(2 * 999 * slice_base));
    // 再大 → max(ceil(size/1999/10MiB), 5) * 10MiB
    try testing.expectEqual(@as(i64, 5 * slice_base), partSize(2 * 999 * slice_base + 1));
    try testing.expectEqual(@as(i64, 5 * slice_base), partSize(50 * 1024 * mb));
    try testing.expectEqual(@as(i64, 6 * slice_base), partSize(100 * 1024 * mb));
    try testing.expectEqual(@as(i64, 53 * slice_base), partSize(1024 * 1024 * mb));
}

test "partLen gives the remainder to the last part" {
    try testing.expectEqual(@as(i64, 10), partLen(25, 10, 1, 3));
    try testing.expectEqual(@as(i64, 10), partLen(25, 10, 2, 3));
    try testing.expectEqual(@as(i64, 5), partLen(25, 10, 3, 3));
    // 整除时最后一片也是整片
    try testing.expectEqual(@as(i64, 10), partLen(20, 10, 2, 2));
}

test "requestPath is the only part of the URL that gets signed" {
    try testing.expectEqualStrings("/person/initMultiUpload", requestPath("https://upload.cloud.189.cn/person/initMultiUpload"));
    // query 与 fragment 都不进签名
    try testing.expectEqualStrings("/a/b", requestPath("https://h/a/b?x=1&y=2#z"));
    try testing.expectEqualStrings("", requestPath("https://h"));
    // 没有 scheme 时原样返回（上游的正则也取不到第 1 组）
    try testing.expectEqualStrings("/a", requestPath("/a"));
}

test "signatureOfHmac is uppercase and skips params when empty" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const with_params = try signatureOfHmac(a, "key", "sk", "GET", "https://h/a/b", "D", "P");
    try testing.expectEqual(@as(usize, 40), with_params.len);
    for (with_params) |c| try testing.expect((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F'));

    // params 为空时不带 &params=。
    const without = try signatureOfHmac(a, "key", "sk", "GET", "https://h/a/b", "D", "");
    const expect = try hash.hmacSha1HexUpper(a, "key", "SessionKey=sk&Operate=GET&RequestURI=/a/b&Date=D");
    try testing.expectEqualStrings(expect, without);
}

test "encodeParams sorts keys, unlike 189Cloud's EncodeParam" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("a=1&b=2&c=3", try encodeParams(a, &.{
        .{ "c", "3" }, .{ "a", "1" }, .{ "b", "2" },
    }));
    try testing.expectEqualStrings("", try encodeParams(a, &.{}));
}

// 这是 `params` 进 AES 之前的**明文**。上游 `Params.Encode()` 不转义，所以
// 调用点已经转义过的值（`fileName` 的 `url.QueryEscape`、`partInfo` 的标准
// base64）必须原样保留 —— 之前这里走了 `urlmod.Query`（会再编码一遍），
// 把 `+` 变成 `%2B`、`%E4%B8%AD` 变成 `%25E4%25B8%25AD`，上传直接失败。
// （普通注释而非 `///`：Zig 不允许文档注释挂在 `test` 上。）
test "encodeParams escapes nothing, only sorts" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // partInfo = "{序号}-{分片MD5的标准base64}"，base64 里必有 `+ / =`。
    const part_info = "1-ab+cd/ef==";
    // fileName 是 url.QueryEscape 之后的形状：空格变 `+`，中文变 `%XX`。
    const file_name = "a+b%E4%B8%AD.txt";

    const out = try encodeParams(a, &.{
        .{ "partInfo", part_info },
        .{ "fileName", file_name },
        .{ "uploadFileId", "9" },
    });

    // 键按字节序：fileName < partInfo < uploadFileId
    try testing.expectEqualStrings(
        "fileName=a+b%E4%B8%AD.txt&partInfo=1-ab+cd/ef==&uploadFileId=9",
        out,
    );
    // 双重编码的特征串一个都不能出现。
    try testing.expect(std.mem.indexOf(u8, out, "%2B") == null);
    try testing.expect(std.mem.indexOf(u8, out, "%2F") == null);
    try testing.expect(std.mem.indexOf(u8, out, "%3D") == null);
    try testing.expect(std.mem.indexOf(u8, out, "%25") == null);
}

test "batch tasks only carry familyId for the family cloud" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var self = try createWithId(a, 0, null);

    // 个人云：哪怕 init 已经把 family_id 取回来了，form 里也不能带
    // （Go driver.go:357 传的是空串，utils.go:1523 只在非空时写）。
    self.cfg.family_id = "12345";
    try testing.expectEqualStrings("", self.batchFamilyId());

    // 家庭云：原样带上。
    self.cfg.type = "family";
    try testing.expectEqualStrings("12345", self.batchFamilyId());

    // 家庭云但还没取到 id —— 与 Go 一致：空串，form 里就不写这个键。
    self.cfg.family_id = "";
    try testing.expectEqualStrings("", self.batchFamilyId());
}

// 回归：189 列表项的 id 是 JSON 数字，而 rename/move/delete 的接口收的是字符
// 串。2026-10-12 之前这里用 strAt("id")，数字形态取不到 → 空 fileId，rename
// 被上游拒（srcFileId=null），mkdir/上传则把文件静默建到了根目录上。
test "idOf reads 189 ids whether they arrive as numbers or strings" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var num = try json.parse(a, "{\"id\": 7123456789012345, \"name\": \"a.txt\"}");
    var str = try json.parse(a, "{\"id\": \"7123456789012345\", \"name\": \"b.txt\"}");
    var none = try json.parse(a, "{\"name\": \"c.txt\"}");

    try testing.expectEqualStrings("7123456789012345", try idOf(a, &num));
    try testing.expectEqualStrings("7123456789012345", try idOf(a, &str));
    // 没有 id 的项必须报错，不能再静默返回空串（空串会被上游当成根目录）。
    try testing.expectError(Error.InvalidResponse, idOf(a, &none));
}

test "aesEcbEncryptHex returns uppercase hex and round-trips" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const hex = try aesEcbEncryptHex(a, "0123456789abcdef", "parentFolderId=-11");
    for (hex) |c| try testing.expect((c >= '0' and c <= '9') or (c >= 'A' and c <= 'F'));
    const ct = try hash.hexDecode(a, hex);
    const back = try aes.ecbDecrypt(a, "0123456789abcdef", ct);
    try testing.expectEqualStrings("parentFolderId=-11", try aes.pkcs7Unpad(back, aes.BLOCK));

    try testing.expectError(Error.InvalidKey, aesEcbEncryptHex(a, "short", "x"));
}

test "uuidV4 has the version and variant bits set" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var src = std.Random.IoSource{ .io = rt.io() };
    const rnd = src.interface();
    const u = try uuidV4(a, rnd);
    try testing.expectEqual(@as(usize, 36), u.len);
    try testing.expectEqual(@as(u8, '-'), u[8]);
    try testing.expectEqual(@as(u8, '4'), u[14]); // 版本位
    const variant = std.mem.indexOfScalar(u8, hex_digits, u[19]).?;
    try testing.expect(variant >= 8 and variant <= 11); // 变体 10xx
}

test "parseHttpHeader cuts at the first equals sign" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const hs = try parseHttpHeader(a, "Content-Type=a%2Fb&X-N=1&novalue&k=v=w");
    try testing.expectEqual(@as(usize, 3), hs.len);
    try testing.expectEqualStrings("Content-Type", hs[0].name);
    try testing.expectEqualStrings("a%2Fb", hs[0].value);
    try testing.expectEqualStrings("X-N", hs[1].name);
    // 值里的 '=' 保留。
    try testing.expectEqualStrings("v=w", hs[2].value);
}

test "normalizeDownloadUrl unescapes amp and upgrades the scheme once" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("https://a/b?x=1&y=2", try normalizeDownloadUrl(a, "http://a/b?x=1&amp;y=2"));
    // 只替换第一处，而且是在整个串里找。
    try testing.expectEqualStrings("x?u=https://a&v=http://b", try normalizeDownloadUrl(a, "x?u=http://a&v=http://b"));
    try testing.expectEqualStrings("//a/b", try normalizeDownloadUrl(a, "//a/b"));
}

test "normalizeName turns a backslash-quote into a quote" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("it's", try normalizeName(a, "it\\'s"));
    const plain = "plain";
    try testing.expectEqualStrings(plain, try normalizeName(a, plain));
}

test "findChild's matching contract: server raw name vs normalized path segment" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // `list` 返回归一化后的名字（`it's`），所以调用方传进来的路径段也是归一化后的；
    // 而 `findChild` 从服务端拿到的是**原始名**（`it\'s`）。两者必须先归一化再比，
    // 否则含撇号的文件按路径解析永远 404。
    const server_raw = "it\\'s a file.txt";
    const requested = "it's a file.txt";
    try testing.expect(std.mem.eql(u8, try normalizeName(a, server_raw), requested));
    // 不归一化直接比会失配 —— 这正是修复前的行为，留作回归闸门。
    try testing.expect(!std.mem.eql(u8, server_raw, requested));
}

test "parse189Time handles both layouts and both timezone shapes" {
    // 中文形态，无时区 → 按 UTC+8 解释。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("2026-10-10 12:00:00"));
    // 显式 +08 与不写时区必须一致。
    try testing.expectEqual(parse189Time("2026-10-10 12:00:00"), parse189Time("2026-10-10 12:00:00 +08"));
    // UTC 读数比 +08 晚 8 小时（同一瞬间）。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("2026-10-10 04:00:00 +00"));

    // 英文形态：PM、带逗号、带时区。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("Oct 10, 2026, 12:00:00 PM +08"));
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("Oct 10, 2026 12:00:00 PM +08"));
    // 午夜是 AM 12 点。
    try testing.expectEqual(@as(?i64, 1_791_561_600), parse189Time("Oct 10, 2026, 12:00:00 AM +08"));
    // U+202F / U+00A0 也要认（189 真的会发这种）。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("Oct 10, 2026, 12:00:00\xe2\x80\xafPM +08"));
    try testing.expectEqual(@as(?i64, 1_791_604_800), parse189Time("Oct 10, 2026, 12:00:00\xc2\xa0PM +08"));

    // 垃圾
    try testing.expect(parse189Time("") == null);
    try testing.expect(parse189Time("not a time") == null);
    try testing.expect(parse189Time("2026-13-01 00:00:00") == null);
}

test "matchLoginParam pulls the value out of a page variable" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const body = "var lt = \"abc123\"; var reqId = \"r-1\"; <input name='captchaToken' value='tok'>";
    try testing.expectEqualStrings("abc123", matchLoginParam(a, body, "lt = \"").?);
    try testing.expectEqualStrings("r-1", matchLoginParam(a, body, "reqId = \"").?);
    try testing.expectEqualStrings("tok", matchLoginParam(a, body, "'captchaToken' value='").?);
    try testing.expect(matchLoginParam(a, body, "nope = \"") == null);
}

test "appConfOk accepts every shape upstream tolerates" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var v1 = try json.parse(a, "{\"result\":\"0\",\"data\":{\"paramId\":\"p\"}}");
    try testing.expect(appConfOk(&v1));
    var v2 = try json.parse(a, "{\"result\":0}");
    try testing.expect(appConfOk(&v2));
    var v3 = try json.parse(a, "{\"data\":{\"paramId\":\"p\"}}");
    try testing.expect(appConfOk(&v3)); // 缺 result 算成功
    var v4 = try json.parse(a, "{\"result\":\"1\",\"msg\":\"bad\"}");
    try testing.expect(!appConfOk(&v4));
}

test "Addition.parse keeps the documented defaults" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const empty = try Addition.parse(a, null);
    try testing.expectEqualStrings(default_personal_root, empty.root_folder_id);
    try testing.expectEqualStrings("password", empty.login_type);
    try testing.expectEqualStrings("stream", empty.upload_method);
    try testing.expectEqual(@as(i64, 3), empty.uploadThread());

    var v = try json.parse(a, "{\"type\":\"family\",\"upload_thread\":\"99\"}");
    const got = try Addition.parse(a, &v);
    try testing.expect(got.isFamily());
    // 越界的线程数回落到 3
    try testing.expectEqual(@as(i64, 3), got.uploadThread());
}

test "T3: real Go addition JSON (backup shape) parses into the driver" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与用户 Go 备份 storage #11/#12 逐字一致：
    // ['access_token','family_id','family_transfer','generate_torrent',
    //  'login_type','no_use_ocr','order_by','order_direction','password',
    //  'rapid_upload','refresh_token','root_folder_id','type','upload_method',
    //  'upload_thread','username','validate_code']。
    const src =
        \\{"login_type":"password","username":"22644212509","password":"pw",
        \\ "validate_code":"","access_token":"","refresh_token":"rt",
        \\ "root_folder_id":"-11","order_by":"filename","order_direction":"asc",
        \\ "type":"family","family_id":"679090111","upload_method":"stream",
        \\ "upload_thread":"3","family_transfer":false,"rapid_upload":false,
        \\ "no_use_ocr":false,"generate_torrent":false}
    ;
    const v = try json.parse(a, src);
    const got = try Addition.parse(a, &v);
    try testing.expectEqualStrings("22644212509", got.username);
    try testing.expectEqualStrings("rt", got.refresh_token);
    try testing.expectEqualStrings("679090111", got.family_id);
    try testing.expect(got.isFamily());
    try testing.expectEqualStrings("3", got.upload_thread);

    // 写回后 Go 能原样读回（键名不变）
    const out = try got.toJson(a);
    const v2 = try json.parse(a, out);
    const got2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(got.family_id, got2.family_id);
    try testing.expect(got2.isFamily());
}

test "createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const self = try createWithId(a, 11, null);
    try testing.expectEqual(@as(i64, 11), self.storage_id);
    try testing.expectEqualStrings("189CloudPC", Cloud189PC.drvName(@ptrCast(self)));
    try testing.expectEqualStrings("189CloudPC", factory.key);
}
