//! 天翼云盘（个人版）—— OpenList 的 `189Cloud`。
//!
//! 与 `189pc`（家庭版）是两个**互不相干**的 API：这一套是老的个人云，靠
//! 浏览器会话 cookie 鉴权，登录走 `open.e.189.cn` 的 RSA 表单。
//!
//! 三处值得单独说明的实现取舍：
//!
//!   * **登录要跟 302。** `loginUrl.action` 会把未登录的请求重定向到
//!     `open.e.189.cn/.../unifyAccountLogin.do?lt=..&reqId=..&appId=..`，
//!     而 Go 版读的是 `res.RawResponse.Request.URL`（跟随后的**最终** URL）。
//!     本工程的 `Client` 不暴露最终 URL，所以这里手工跟跳。
//!   * **`RsaEncode(..., hex=true)` 就是密文的十六进制。** 上游先 base64 再过
//!     一个叫 `b64tohex` 的函数，那个函数实际上是「6 个字符表示 3 个字节」的
//!     十六进制编码（已逐位验算过状态机），所以直接对密文取 hex 即可 ——
//!     `util/rsa.zig` 的 `encryptToHexLower` 就是这么做的。
//!   * **上传请求的参数是 AES-128-ECB 加密后放在 query 里的。** 密钥是随机串
//!     的前 16 字节，密钥本身再用 RSA 加密放在 `EncryptionText` 头里。
//!     签名 `Signature` 是 `HMAC-SHA1(..., l)`，注意密钥是**整条**随机串
//!     （16~31 字节），不是加密用的那 16 字节。
//!
//! 未移植：
//!   * `Copy` —— 本工程的 vtable 没有这个槽位（见 `src/driver.zig` 文件头）。
//!   * `newUpload` 里那个 fire-and-forget 的 torrent 生成 goroutine —— 它在
//!     goroutine 里跑、失败只打一行日志、不影响上传结果，属于离线下载生态，
//!     与「能列、能传、能下载」无关。

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

const api_base = "https://cloud.189.cn";
/// 登录门户在另一个域上，cookie 也落在这里。
const login_base = "https://open.e.189.cn";
/// 上传是**第三个**域，签名方式也完全不同。
const upload_base = "https://upload.cloud.189.cn";

/// Go 的 `config.DefaultRoot`。个人云的根目录 id 是 `-11`。
const default_root = "-11";

/// `newLogin` 的入口。redirectURL 是硬编码且已 percent-encoded 的。
const path_login = api_base ++ "/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fmain.action";
/// 已登录时上面那条会直接落到这里。
const logged_in_prefix = api_base ++ "/web/main";

const app_conf_url = login_base ++ "/api/logbox/oauth2/appConf.do";
const encrypt_conf_url = login_base ++ "/api/logbox/config/encryptConf.do";
const login_submit_url = login_base ++ "/api/logbox/oauth2/loginSubmit.do";

const path_list = api_base ++ "/api/open/file/listFiles.action";
const path_file_info = api_base ++ "/api/portal/getFileInfo.action";
const path_mkdir = api_base ++ "/api/open/file/createFolder.action";
const path_batch = api_base ++ "/api/open/batch/createBatchTask.action";
const path_rename_file = api_base ++ "/api/open/file/renameFile.action";
const path_rename_folder = api_base ++ "/api/open/file/renameFolder.action";
const path_capacity = api_base ++ "/api/portal/getUserSizeInfo.action";
const path_user_brief = api_base ++ "/v2/getUserBriefInfo.action";
const path_rsa_key = api_base ++ "/api/security/generateRsaKey.action";

const uri_init_upload = "/person/initMultiUpload";
const uri_upload_urls = "/person/getMultiUploadUrls";
const uri_commit_upload = "/person/commitMultiUploadFile";

/// 上游的 `DEFAULT`。天翼的固定分片大小，不随文件大
/// 小变化 —— 传 1TB 就是 10 万片，这也是上游不给它做分片阶梯的原因。
const slice_size: i64 = 10485760;

const page_size: i64 = 60;
const max_redirects: usize = 5;

/// 与 `drivers/base.UserAgent` 逐字一致 —— 下载直链那一步上游显式设了它。
const user_agent = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";
/// Go 的 `net/http` 在没有显式 UA 时发的默认串。189 的分片 PUT 走的是裸
/// `http.Client`，所以线上看到的就是这个。
const go_default_ua = "Go-http-client/1.1";

/// `Referer` 是 `Init` 时设在 resty client 上的，所以**所有**请求都带。
const referer = "https://cloud.189.cn/";

/// `Random("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx")`。
const uuid_pattern = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
/// `Random("xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx")` —— 32 个字符，随后截成
/// 16~31 字节：前 16 字节当 AES 密钥，整条当 HMAC 密钥。
const l_pattern = "xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx";

const hex_digits = "0123456789abcdef";

pub const Error = error{
    /// 没填用户名或密码。
    NoCredentials,
    UpstreamHttp,
    /// 响应不是 JSON（多半是 WAF 的 HTML 错误页）。
    UpstreamNotJson,
    /// 上游返回了 `res_code != 0` 或 `errorCode`。
    UpstreamError,
    /// JSON 里缺字段。
    InvalidResponse,
    InvalidPath,
    /// RSA 公钥解析失败。
    InvalidKey,
    /// 登录被拒。
    LoginFailed,
    /// 上传接口返回的 `code` 不是 `SUCCESS`。
    UploadFailed,
    /// RSA 加密本身的输入过长。
    MessageTooLong,
};

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

pub const Addition = struct {
    username: []const u8 = "",
    password: []const u8 = "",
    /// 上游的 `Addition` 里有这个字段（help: "Fill in the cookie if need
    /// captcha"），但整个 `_189` 包**没有任何一行读它** —— 历史遗留。
    /// 这里保留字段名让前端表单对得上，并在 schema 里说明它不生效。
    cookie: []const u8 = "",
    root_folder_id: []const u8 = default_root,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.username = try dupeOr(alloc, o.strAt("username"), "");
        a.password = try dupeOr(alloc, o.strAt("password"), "");
        a.cookie = try dupeOr(alloc, o.strAt("cookie"), "");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        return a;
    }

    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("username", self.username);
        try w.str("password", self.password);
        try w.str("cookie", self.cookie);
        try w.str("root_folder_id", self.root_folder_id);
        try w.end();
        return b.toOwned();
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    return alloc.dupe(u8, v orelse fallback);
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
// 纯函数：登录/上传要用到的那些小工具
// ---------------------------------------------------------------------------

/// `random()` —— `fmt.Sprintf("0.%17v", rand.Int63n(1e17))`。
///
/// 每个请求的 `noCache` 参数。注意宽度 17 是**右对齐**补空格，不是零填充：
/// `"0." + fmt("%17d", n)`。形状本身没有语义（服务端只是拿它破缓存），但
/// 照抄可以在抓包比对时少一个变量。
fn noCache(alloc: std.mem.Allocator, rnd: std.Random) ![]const u8 {
    const n = rnd.intRangeAtMostBiased(u64, 0, 99_999_999_999_999_999);
    var tmp: [24]u8 = undefined;
    const s = try std.fmt.bufPrint(&tmp, "0.{d: >17}", .{n});
    return alloc.dupe(u8, s);
}

/// `Random(v)` —— 把模板里的 `x`/`y` 换成十六进制字符，其余字符原样保留。
///
/// `x` → `int(16*rand.Float32())`（0~15）；`y` → `3&t | 8`（8~15），
/// 也就是 RFC 4122 变体位固定为 `10xx`。模板里的 `4` 是**字面量**，不替换
/// —— 上游用的是 `regexp.MustCompilePOSIX("[xy]")`，只认 x 和 y。
fn randomPattern(rnd: std.Random, out: []u8, pattern: []const u8) void {
    for (pattern, out) |c, *o| {
        switch (c) {
            'x', 'y' => {
                const t: u8 = @intFromFloat(16.0 * rnd.float(f32));
                o.* = hex_digits[if (c == 'x') t else (t & 3) | 8];
            },
            else => o.* = c,
        }
    }
}

/// `EncodeParam(v url.Values)` —— `k=v&k=v`，**不做**任何转义。
///
/// 上游 `qs()` 的键顺序是 Go map 的迭代顺序（随机）。服务端解密后按 `&`
/// 和第一个 `=` 切分，顺序无关，所以这里用调用点给的顺序，反而更可复现。
/// 需要转义的字段（`fileName`）由调用点自己先 `url.QueryEscape`。
fn encodeParam(alloc: std.mem.Allocator, entries: []const [2][]const u8) ![]u8 {
    var b = Buf.init(alloc);
    for (entries, 0..) |e, i| {
        if (i > 0) try b.appendByte('&');
        try b.append(e[0]);
        try b.appendByte('=');
        try b.append(e[1]);
    }
    return b.toOwned();
}

/// `decodeURIComponent` —— `url.PathUnescape`，只解 `%XX`，**不**把 `+`
/// 变成空格（那是 `QueryUnescape` 的行为）。
///
/// 上传接口的 `requestHeader` 是 `k=v&k=v` 形式的百分号编码串，里面有
/// `Content-Length` 之类的值，不能把 `+` 吃掉。
fn pathUnescape(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var b = Buf.init(alloc);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (hexVal(s[i + 1])) |hi| {
                if (hexVal(s[i + 2])) |lo| {
                    try b.appendByte(hi << 4 | lo);
                    i += 3;
                    continue;
                }
            }
        }
        try b.appendByte(s[i]);
        i += 1;
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

/// `strings.Replace(s, "http://", "https://", 1)` —— 替换**第一处出现**，
/// 而且是在整个串里找（不是只匹配前缀）。上游的下载直链改造靠的就是这个。
fn httpToHttps(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    const idx = std.mem.indexOf(u8, s, "http://") orelse return alloc.dupe(u8, s);
    var b = Buf.init(alloc);
    try b.append(s[0..idx]);
    try b.append("https://");
    try b.append(s[idx + "http://".len ..]);
    return b.toOwned();
}

/// 取 URL 的查询串部分（不含 `?`，不含 `#` 之后）。
fn queryPart(u: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, u, '?') orelse return "";
    const rest = u[q + 1 ..];
    const h = std.mem.indexOfScalar(u8, rest, '#') orelse return rest;
    return rest[0..h];
}

/// 把 `Location` 头和当前 URL 拼成绝对 URL。只处理真实会遇见的四种形状：
/// 绝对 URL、协议相对 `//host/...`、根相对 `/path`、相对 `path`。
fn resolveUrl(alloc: std.mem.Allocator, base: []const u8, loc: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, loc, "http://") or std.mem.startsWith(u8, loc, "https://")) {
        return alloc.dupe(u8, loc);
    }
    if (std.mem.startsWith(u8, loc, "//")) {
        // 站点是 https，协议相对就用 https。
        return std.fmt.allocPrint(alloc, "https:{s}", .{loc});
    }
    if (std.mem.startsWith(u8, loc, "/")) {
        const scheme_end = std.mem.indexOf(u8, base, "://") orelse return alloc.dupe(u8, loc);
        const host_start = scheme_end + 3;
        const host_end = std.mem.indexOfAny(u8, base[host_start..], "/?#") orelse
            (base.len - host_start);
        return std.fmt.allocPrint(alloc, "{s}{s}", .{ base[0 .. host_start + host_end], loc });
    }
    const cut = std.mem.lastIndexOfAny(u8, base, "/?#") orelse return alloc.dupe(u8, loc);
    return std.fmt.allocPrint(alloc, "{s}/{s}", .{ base[0..cut], loc });
}

/// `RsaEncode(origData, j_rsakey, hex)`。
///
/// `hex=true` 走 `b64tohex`，等价于直接对密文取小写十六进制（见文件头）；
/// `hex=false` 就是标准 base64。
fn rsaEncode(
    alloc: std.mem.Allocator,
    msg: []const u8,
    pem_or_body: []const u8,
    rnd: std.Random,
    comptime as_hex: bool,
) ![]u8 {
    var owned = rsa.parsePem(alloc, pem_or_body) catch return Error.InvalidKey;
    defer owned.deinit(alloc);

    const k = owned.key.ciphertextLen();
    const ct = try alloc.alloc(u8, k);
    defer alloc.free(ct);
    rsa.encryptPkcs1v15(ct, msg, owned.key, rnd) catch |e| switch (e) {
        error.MessageTooLong => return Error.MessageTooLong,
        else => return Error.InvalidKey,
    };

    return if (as_hex) hash.hexLower(alloc, ct) else hash.base64Std(alloc, ct);
}

/// `AesEncrypt(data, key)` —— AES-128-ECB + PKCS#7。
///
/// 上游在 `aes.NewCipher` 失败时返回空切片（然后发出去一个空的 `params`），
/// 这里显式报错：静默退化只会让服务端回一个看不懂的签名错误。
fn aesEncryptHex(alloc: std.mem.Allocator, key16: []const u8, plain: []const u8) ![]u8 {
    if (key16.len != 16) return Error.InvalidKey;
    const padded = try aes.pkcs7Pad(alloc, plain, aes.BLOCK);
    const ct = try aes.ecbEncrypt(alloc, key16, padded);
    return hash.hexLower(alloc, ct);
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

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------

pub const Cloud189 = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    /// 上传域的会话串。每次 `put` 开头重新取。
    session_key: []const u8 = "",
    /// `generateRsaKey` 的结果与过期时间（毫秒）。
    rsa_pub_key: []const u8 = "",
    rsa_pk_id: []const u8 = "",
    rsa_expire: i64 = 0,

    /// 串行化「重新登录」：`request` 遇到 `InvalidSessionKey` 会重登，多个
    /// 并发请求同时触发只会把会话刷掉一次。
    login_mu: std.Io.Mutex = .init,

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
        return "189Cloud";
    }

    fn as(ptr: *anyopaque) *Cloud189 {
        return @ptrCast(@alignCast(ptr));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        try self.newLogin(a);
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        self.alloc.free(self.session_key);
        self.alloc.free(self.rsa_pub_key);
        self.alloc.free(self.rsa_pk_id);
        self.session_key = "";
        self.rsa_pub_key = "";
        self.rsa_pk_id = "";
    }

    /// 换掉一个字符串字段。旧值可能不存在（首次赋值时是空串，不能 free）。
    fn setStr(self: *Cloud189, slot: *[]const u8, next: []const u8) !void {
        if (slot.*.len > 0) self.alloc.free(slot.*);
        slot.* = try self.alloc.dupe(u8, next);
    }

    // -----------------------------------------------------------------------
    // HTTP
    // -----------------------------------------------------------------------

    /// 一次带会话的请求。
    ///
    /// 上游的错误模型是 `(body, error)`：`errorCode == "InvalidSessionKey"`
    /// 时重登并**重放一次**；`res_code != 0` 时把 `res_message` 包成 error
    /// 但**仍然返回 body**。这里直接把后者当错误 —— 没有调用点需要看那个
    /// body，留着只会让上层忘记判错。
    fn request(
        self: *Cloud189,
        arena: std.mem.Allocator,
        url: []const u8,
        method: []const u8,
        form: ?[]const u8,
        retried: bool,
    ) ![]const u8 {
        var src = std.Random.IoSource{ .io = rt.io() };
        const nc = try noCache(arena, src.interface());
        const full = try std.fmt.allocPrint(arena, "{s}{s}noCache={s}", .{
            url,
            if (std.mem.indexOfScalar(u8, url, '?') != null) "&" else "?",
            nc,
        });

        var headers = List(model.Header).init(arena);
        try headers.append(.{ .name = "Accept", .value = "application/json;charset=UTF-8" });
        try headers.append(.{ .name = "User-Agent", .value = user_agent });
        try headers.append(.{ .name = "Referer", .value = referer });
        if (form != null) {
            try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" });
        }

        const res = try self.client.send(arena, .{
            .method = method,
            .url = full,
            .headers = headers.slice(),
            .body = form orelse "",
        });

        if (json.parse(arena, res.body)) |v| {
            const ec = v.strAt("errorCode") orelse "";
            if (ec.len > 0) {
                if (std.mem.eql(u8, ec, "InvalidSessionKey")) {
                    if (retried) return driver.Error.AuthFailed;
                    log.info("[189] session expired, logging in again", .{});
                    try self.newLogin(arena);
                    return self.request(arena, url, method, form, true);
                }
                log.warn("[189] {s}: {s} {s}", .{ url, ec, v.strAt("errorMsg") orelse "" });
                return Error.UpstreamError;
            }
            const rc = v.intAt("res_code") orelse 0;
            if (rc != 0) {
                log.warn("[189] {s}: res_code {d} {s}", .{ url, rc, v.strAt("res_message") orelse "" });
                return Error.UpstreamError;
            }
        } else |_| {
            // 不是 JSON：登录页、WAF 拦截页、空 body 都会走到这里。
            // `res_code` 取不到就是 0，上游同样当作没错误。
        }

        return res.body;
    }

    // -----------------------------------------------------------------------
    // 登录
    // -----------------------------------------------------------------------

    /// `newLogin()`。
    ///
    /// 四步：跟 `loginUrl.action` 的 302 拿 `lt/reqId/appId` → `appConf.do`
    /// → `encryptConf.do` 拿 RSA 公钥 → `loginSubmit.do`。
    fn newLogin(self: *Cloud189, arena: std.mem.Allocator) !void {
        self.login_mu.lockUncancelable(rt.io());
        defer self.login_mu.unlock(rt.io());

        if (self.cfg.username.len == 0 or self.cfg.password.len == 0) {
            log.err("[189] 需要用户名和密码", .{});
            return Error.NoCredentials;
        }

        // 1) 跟跳。Go 版读的是跟随之后的最终 URL。
        var cur: []const u8 = path_login;
        var hop: usize = 0;
        while (hop < max_redirects) : (hop += 1) {
            const res = try self.client.send(arena, .{
                .method = "GET",
                .url = cur,
                .headers = &.{ .{ .name = "User-Agent", .value = user_agent } },
            });
            if (res.status < 300 or res.status >= 400) break;
            const loc = res.header("Location") orelse break;
            cur = try resolveUrl(arena, cur, loc);
        }
        if (std.mem.startsWith(u8, cur, logged_in_prefix)) {
            log.info("[189] 会话仍然有效，跳过登录", .{});
            return;
        }

        const q = queryPart(cur);
        const lt = (try urlmod.queryGetDecoded(arena, q, "lt")) orelse "";
        const req_id = (try urlmod.queryGetDecoded(arena, q, "reqId")) orelse "";
        const app_id = (try urlmod.queryGetDecoded(arena, q, "appId")) orelse "";
        if (app_id.len == 0) {
            log.err("[189] 登录跳转 URL 里没有 appId: {s}", .{cur});
            return Error.LoginFailed;
        }

        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        var headers = List(model.Header).init(arena);
        try headers.append(.{ .name = "lt", .value = lt });
        try headers.append(.{ .name = "reqid", .value = req_id });
        try headers.append(.{ .name = "referer", .value = cur });
        try headers.append(.{ .name = "origin", .value = login_base });
        try headers.append(.{ .name = "User-Agent", .value = user_agent });
        const hs = headers.slice();

        // 2) appConf
        var f = urlmod.Query.init(arena);
        try f.add("version", "2.0");
        try f.add("appKey", app_id);
        const conf_body = try self.post(arena, app_conf_url, hs, f.slice());
        const conf = json.parse(arena, conf_body) catch return Error.UpstreamNotJson;
        if (!std.mem.eql(u8, conf.strAt("result") orelse "", "0")) {
            log.err("[189] appConf: {s}", .{conf.strAt("msg") orelse ""});
            return Error.LoginFailed;
        }
        const account_type = conf.strAt("data.accountType") orelse "";
        const return_url = conf.strAt("data.returnUrl") orelse "";
        const mail_suffix = conf.strAt("data.mailSuffix") orelse "";
        const client_type = conf.intAt("data.clientType") orelse 0;
        const is_oauth2 = blk: {
            const p = conf.getPath("data.isOauth2") orelse break :blk false;
            break :blk p.asBool() orelse false;
        };
        const param_id = conf.strAt("data.paramId") orelse "";

        // 3) encryptConf —— RSA 公钥
        var f2 = urlmod.Query.init(arena);
        try f2.add("appId", app_id);
        const enc_body = try self.post(arena, encrypt_conf_url, hs, f2.slice());
        const enc = json.parse(arena, enc_body) catch return Error.UpstreamNotJson;
        if ((enc.intAt("result") orelse -1) != 0) {
            log.err("[189] encryptConf: {s}", .{enc_body[0..@min(enc_body.len, 200)]});
            return Error.LoginFailed;
        }
        const pre = enc.strAt("data.pre") orelse "";
        const pub_key = enc.strAt("data.pubKey") orelse "";
        if (pub_key.len == 0) return Error.LoginFailed;

        // 4) loginSubmit
        const enc_user = try rsaEncode(arena, self.cfg.username, pub_key, rnd, true);
        const enc_pass = try rsaEncode(arena, self.cfg.password, pub_key, rnd, true);

        var f3 = urlmod.Query.init(arena);
        try f3.add("version", "v2.0");
        try f3.add("apToken", "");
        try f3.add("appKey", app_id);
        try f3.add("accountType", account_type);
        try f3.add("userName", try std.fmt.allocPrint(arena, "{s}{s}", .{ pre, enc_user }));
        try f3.add("epd", try std.fmt.allocPrint(arena, "{s}{s}", .{ pre, enc_pass }));
        try f3.add("captchaType", "");
        try f3.add("validateCode", "");
        try f3.add("smsValidateCode", "");
        try f3.add("captchaToken", "");
        try f3.add("returnUrl", return_url);
        try f3.add("mailSuffix", mail_suffix);
        try f3.add("dynamicCheck", "FALSE");
        try f3.add("clientType", try std.fmt.allocPrint(arena, "{d}", .{client_type}));
        try f3.add("cb_SaveName", "3");
        try f3.add("isOauth2", if (is_oauth2) "true" else "false");
        try f3.add("state", "");
        try f3.add("paramId", param_id);

        const login_body = try self.post(arena, login_submit_url, hs, f3.slice());
        const lr = json.parse(arena, login_body) catch return Error.UpstreamNotJson;
        if ((lr.intAt("result") orelse -1) != 0) {
            log.err("[189] 登录失败: {s}", .{lr.strAt("msg") orelse login_body});
            return Error.LoginFailed;
        }
        log.info("[189] 登录成功", .{});
    }

    /// 登录流程里的裸 POST：不带 `noCache`，不判 `res_code`（这三个接口的
    /// 成功标志是各自的 `result` 字段）。
    fn post(
        self: *Cloud189,
        arena: std.mem.Allocator,
        url: []const u8,
        headers: []const model.Header,
        form: []const u8,
    ) ![]const u8 {
        var hs = List(model.Header).init(arena);
        try hs.appendSlice(headers);
        try hs.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" });
        try hs.append(.{ .name = "Accept", .value = "application/json;charset=UTF-8" });

        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = url,
            .headers = hs.slice(),
            .body = form,
        });
        if (!res.isOk()) {
            log.warn("[189] {s} HTTP {d}", .{ url, res.status });
            return Error.UpstreamHttp;
        }
        return res.body;
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

    /// 一页 `listFiles`。
    ///
    /// 上游的分页循环是「`fileListAO.count == 0` 就停」。`count` 究竟是本页
    /// 条数还是总数，文档没说；若它是总数，一个非空目录会永远翻不完。这里
    /// 额外加了「本页两个列表都空」这个短路 —— 真机上只可能是多发了最后一
    /// 次请求，不会死循环。
    fn listPage(self: *Cloud189, arena: std.mem.Allocator, folder_id: []const u8, page_num: i64) !Page {
        var q = urlmod.Query.init(arena);
        try q.addInt("pageSize", page_size);
        try q.addInt("pageNum", page_num);
        try q.add("mediaType", "0");
        try q.add("folderId", folder_id);
        try q.add("iconOption", "5");
        try q.add("orderBy", "lastOpTime");
        try q.add("descending", "true");

        const url = try std.fmt.allocPrint(arena, "{s}?{s}", .{ path_list, q.slice() });
        const body = try self.request(arena, url, "GET", null, false);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;

        const ao = v.getPath("fileListAO") orelse return .{ .count = 0, .folders = &.{}, .files = &.{} };
        const folders = if (ao.getPath("folderList")) |p| p.asArray() orelse &.{} else &.{};
        const files = if (ao.getPath("fileList")) |p| p.asArray() orelse &.{} else &.{};
        return .{
            .count = ao.intAt("count") orelse 0,
            .folders = folders,
            .files = files,
        };
    }

    fn getFiles(self: *Cloud189, alloc: std.mem.Allocator, folder_id: []const u8) ![]model.Obj {
        var arena = std.heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        const a = arena.allocator();

        var out = List(model.Obj).init(alloc);
        var page_num: i64 = 1;
        while (true) {
            const page = try self.listPage(a, folder_id, page_num);
            if (page.count == 0 or (page.folders.len == 0 and page.files.len == 0)) break;

            for (page.folders) |item| {
                try out.append(.{
                    .name = item.strAt("name") orelse "",
                    .size = 0,
                    .is_dir = true,
                    .modified = timeutil.parseCnTime(item.strAt("lastOpTime") orelse "") orelse 0,
                });
            }
            for (page.files) |item| {
                const icon = item.getPath("icon");
                try out.append(.{
                    .name = item.strAt("name") orelse "",
                    .size = item.intAt("size") orelse 0,
                    .is_dir = false,
                    .modified = timeutil.parseCnTime(item.strAt("lastOpTime") orelse "") orelse 0,
                    .thumb = if (icon) |ic| ic.strAt("smallUrl") orelse "" else "",
                });
            }
            page_num += 1;
        }
        return out.toOwned();
    }

    fn resolve(self: *Cloud189, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    fn findChild(self: *Cloud189, arena: std.mem.Allocator, parent_id: []const u8, name: []const u8) !Entry {
        var page_num: i64 = 1;
        while (true) {
            const page = try self.listPage(arena, parent_id, page_num);
            if (page.count == 0 or (page.folders.len == 0 and page.files.len == 0)) {
                return driver.Error.NotFound;
            }
            for (page.folders) |item| {
                if (std.mem.eql(u8, item.strAt("name") orelse "", name)) {
                    return .{
                        .id = try idStr(arena, item.intAt("id") orelse 0),
                        .name = name,
                        .is_dir = true,
                    };
                }
            }
            for (page.files) |item| {
                if (std.mem.eql(u8, item.strAt("name") orelse "", name)) {
                    return .{
                        .id = try idStr(arena, item.intAt("id") orelse 0),
                        .name = name,
                        .is_dir = false,
                    };
                }
            }
            page_num += 1;
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
        const a = ctx.alloc;
        const e = try self.resolve(a, path);
        return model.File.fromObj(.{
            .name = e.name,
            .size = 0,
            .is_dir = e.is_dir,
        });
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: model.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;

        const e = try self.resolve(a, path);
        const url = try std.fmt.allocPrint(a, "{s}?fileId={s}", .{ path_file_info, e.id });
        const body = try self.request(a, url, "GET", null, false);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        const raw = v.strAt("downloadUrl") orelse return Error.InvalidResponse;

        // `downloadUrl` 是 `//host/path` 形状，上游直接拼 "https:"。
        const first = try std.fmt.allocPrint(a, "https:{s}", .{raw});

        // 上游用 `ErrUseLastResponse` 关掉自动跟随，只解一跳。
        //
        // 它后面那句 `_, _ = client.R().Get(link.URL)` 的结果**没有被使用**
        // —— 判的还是第一次请求的 `res`，所以「第三跳」那段是死代码，实际
        // 行为就是解一跳。这里照实际行为写。
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

        const out = try httpToHttps(a, final_url);
        if (args.redirect) {
            return .{ .url = out, .proxy = false };
        }
        // 直链带会话参数且有时效，代理模式下由 API 层回源。
        return .{ .url = out, .proxy = true };
    }

    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dir);
        if (name.len == 0) return Error.InvalidPath;
        const parent = try self.resolve(a, parentOf(dir));

        var q = urlmod.Query.init(a);
        try q.add("parentFolderId", parent.id);
        try q.add("folderName", name);
        _ = try self.request(a, path_mkdir, "POST", q.slice(), false);
    }

    /// 移动/删除都走 `createBatchTask`，只有 `type` 不同。
    fn batchTask(self: *Cloud189, a: std.mem.Allocator, kind: []const u8, src: Entry, target: []const u8) !void {
        var infos = Buf.init(a);
        try infos.appendByte('[');
        try infos.appendByte('{');
        try json.writeString(&infos, "fileId");
        try infos.appendByte(':');
        try json.writeString(&infos, src.id);
        try infos.appendByte(',');
        try json.writeString(&infos, "fileName");
        try infos.appendByte(':');
        try json.writeString(&infos, src.name);
        try infos.appendByte(',');
        try json.writeString(&infos, "isFolder");
        try infos.append(":") ;
        try infos.append(if (src.is_dir) "1" else "0");
        try infos.appendByte('}');
        try infos.appendByte(']');

        var q = urlmod.Query.init(a);
        try q.add("type", kind);
        try q.add("targetFolderId", target);
        try q.add("taskInfos", infos.slice());
        _ = try self.request(a, path_batch, "POST", q.slice(), false);
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src_path: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, src_path);
        const dst = try self.resolve(a, dst_dir);
        try self.batchTask(a, "MOVE", src, dst.id);
    }

    /// Go `drivers/189/driver.go` 的 Copy 与 Move 同形，只有 `type` 不同
    ///（`"COPY"` vs `"MOVE"`）—— 都是 `createBatchTask` + `targetFolderId`。
    fn copy(ptr: *anyopaque, ctx: *driver.Ctx, src_path: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, src_path);
        const dst = try self.resolve(a, dst_dir);
        try self.batchTask(a, "COPY", src, dst.id);
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        var src = try self.resolve(a, path);
        if (is_dir) src.is_dir = true;
        try self.batchTask(a, "DELETE", src, "");
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const src = try self.resolve(a, path);

        var q = urlmod.Query.init(a);
        if (src.is_dir) {
            try q.add("folderId", src.id);
            try q.add("destFolderName", new_name);
            _ = try self.request(a, path_rename_folder, "POST", q.slice(), false);
        } else {
            try q.add("fileId", src.id);
            try q.add("destFileName", new_name);
            _ = try self.request(a, path_rename_file, "POST", q.slice(), false);
        }
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(ptr);
        const a = ctx.alloc;
        const body = try self.request(a, path_capacity, "GET", null, false);
        const v = json.parse(a, body) catch return Error.UpstreamNotJson;
        return .{
            .total = v.intAt("cloudCapacityInfo.totalSize") orelse 0,
            .used = v.intAt("cloudCapacityInfo.usedSize") orelse 0,
        };
    }

    // -----------------------------------------------------------------------
    // 上传
    // -----------------------------------------------------------------------

    fn getSessionKey(self: *Cloud189, arena: std.mem.Allocator) ![]const u8 {
        const body = try self.request(arena, path_user_brief, "GET", null, false);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return v.strAt("sessionKey") orelse return Error.InvalidResponse;
    }

    fn getResKey(self: *Cloud189, arena: std.mem.Allocator) !void {
        const now = rt.nowMillis();
        if (self.rsa_expire > now and self.rsa_pub_key.len > 0) return;

        const body = try self.request(arena, path_rsa_key, "GET", null, false);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const new_key = v.strAt("pubKey") orelse return Error.InvalidResponse;
        const id = v.strAt("pkId") orelse return Error.InvalidResponse;

        try self.setStr(&self.rsa_pub_key, new_key);
        try self.setStr(&self.rsa_pk_id, id);
        self.rsa_expire = v.intAt("expire") orelse 0;
    }

    /// 上传域的一次请求。
    ///
    /// 参数整体 AES 加密后base16 放进 query 的 `params`，AES 密钥用 RSA 加密
    /// 放进 `EncryptionText` 头，HMAC 签名放进 `Signature` 头。
    fn uploadRequest(
        self: *Cloud189,
        arena: std.mem.Allocator,
        uri: []const u8,
        entries: []const [2][]const u8,
    ) ![]const u8 {
        var src = std.Random.IoSource{ .io = rt.io() };
        const rnd = src.interface();

        const date = try std.fmt.allocPrint(arena, "{d}", .{rt.nowMillis()});

        const rid = try arena.alloc(u8, uuid_pattern.len);
        randomPattern(rnd, rid, uuid_pattern);

        const l_full = try arena.alloc(u8, l_pattern.len);
        randomPattern(rnd, l_full, l_pattern);
        // `l = l[0 : 16+int(16*rand.Float32())]` —— 16~31 字节。
        const extra: usize = @intFromFloat(16.0 * rnd.float(f32));
        const l = l_full[0 .. 16 + extra];

        const params_hex = try aesEncryptHex(arena, l[0..16], try encodeParam(arena, entries));

        const to_sign = try std.fmt.allocPrint(
            arena,
            "SessionKey={s}&Operate=GET&RequestURI={s}&Date={s}&params={s}",
            .{ self.session_key, uri, date, params_hex },
        );
        // HMAC 的密钥是**整条** l，不是加密用的那 16 字节。
        const signature = try hash.hmacSha1Hex(arena, l, to_sign);

        try self.getResKey(arena);
        const enc_text = try rsaEncode(arena, l, self.rsa_pub_key, rnd, false);

        const url = try std.fmt.allocPrint(arena, "{s}{s}?params={s}", .{ upload_base, uri, params_hex });
        const res = try self.client.send(arena, .{
            .method = "GET",
            .url = url,
            .headers = &.{
                .{ .name = "accept", .value = "application/json;charset=UTF-8" },
                .{ .name = "User-Agent", .value = user_agent },
                .{ .name = "Referer", .value = referer },
                .{ .name = "SessionKey", .value = self.session_key },
                .{ .name = "Signature", .value = signature },
                .{ .name = "X-Request-Date", .value = date },
                .{ .name = "X-Request-ID", .value = rid },
                .{ .name = "EncryptionText", .value = enc_text },
                .{ .name = "PkId", .value = self.rsa_pk_id },
            },
        });

        if (!res.isOk()) {
            log.warn("[189] upload {s} HTTP {d}", .{ uri, res.status });
            return Error.UpstreamHttp;
        }
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        if (!std.mem.eql(u8, v.strAt("code") orelse "", "SUCCESS")) {
            log.warn("[189] upload {s}: {s}", .{ uri, v.strAt("msg") orelse "" });
            return Error.UploadFailed;
        }
        return res.body;
    }

    /// 一次完整的分片上传。
    fn newUpload(self: *Cloud189, a: std.mem.Allocator, dst_dir: Entry, name: []const u8, src: model.Source, ctx: *const driver.Ctx) !void {
        try self.setStr(&self.session_key, try self.getSessionKey(a));

        const size = src.size();
        if (size < 0) return Error.InvalidPath;

        // 第一遍：整文件 MD5 + 每个分片的 MD5（大写十六进制）。
        //
        // 上游先用 `file.GetHash().GetHash(MD5)`（可能已经有），没有才缓存流。
        // 本工程的 `Source` 可随机读，所以直接两遍读，不需要落临时文件 ——
        // 代价是多读一遍，换来的是路由器上不用为 4GB 文件准备 4GB 的缓存。
        // T7：两遍读（先算 MD5，再分片上传）共用**同一个**块缓冲。
        // 修复前 `readAll` 每块新分配，请求 arena 峰值 = 2×文件大小。
        const chunk_buf = try a.alloc(u8, @intCast(slice_size));
        var full = hash.Md5Stream{};
        var md5s = List([]const u8).init(a);
        var off: i64 = 0;
        while (off < size) {
            const len: i64 = @min(slice_size, size - off);
            const data = chunk_buf[0..@intCast(len)];
            try src.readAllInto(@intCast(off), data);
            full.update(data);
            try md5s.append(try hash.hexUpper(a, &hash.md5(data)));
            off += len;
        }
        const file_md5 = try full.finalHexLower(a);

        // `sliceMd5`：大文件是各片 MD5 用 "\n" 连接后再 MD5（小写），
        // 小文件直接就是整文件 MD5。
        const slice_md5: []const u8 = if (size > slice_size and md5s.slice().len > 0) blk: {
            var joined = Buf.init(a);
            for (md5s.slice(), 0..) |m, i| {
                if (i > 0) try joined.appendByte('\n');
                try joined.append(m);
            }
            break :blk try hash.md5Hex(a, joined.slice());
        } else file_md5;

        const enc_name = try urlmod.encode(a, name, .form);
        const size_str = try std.fmt.allocPrint(a, "{d}", .{size});
        const slice_str = try std.fmt.allocPrint(a, "{d}", .{slice_size});

        const init_body = try self.uploadRequest(a, uri_init_upload, &.{
            .{ "parentFolderId", dst_dir.id },
            .{ "fileName", enc_name },
            .{ "fileSize", size_str },
            .{ "sliceSize", slice_str },
            .{ "fileMd5", file_md5 },
            .{ "sliceMd5", slice_md5 },
        });
        const init_v = json.parse(a, init_body) catch return Error.UpstreamNotJson;
        const data = init_v.getPath("data") orelse return Error.InvalidResponse;
        const upload_file_id = data.strAt("uploadFileId") orelse return Error.InvalidResponse;
        const exists = data.intAt("fileDataExists") orelse 0;

        if (exists != 1) {
            var part: i64 = 1;
            var pos: i64 = 0;
            while (pos < size) : (part += 1) {
                const len: i64 = @min(slice_size, size - pos);
                const chunk = chunk_buf[0..@intCast(len)];
                try src.readAllInto(@intCast(pos), chunk);
                pos += len;
                // 每片报一次百分比（0–100，Go `model.UpdateProgress` 语义）。
                if (ctx.progress) |f| {
                    const pct: u64 = @intCast(@min(@divTrunc(pos * 100, @max(size, 1)), 100));
                    f(ctx.progress_userdata, pct);
                }

                const md5_b64 = try hash.base64Std(a, &hash.md5(chunk));
                const part_info = try std.fmt.allocPrint(a, "{d}-{s}", .{ part, md5_b64 });
                const part_no = try std.fmt.allocPrint(a, "{d}", .{part});

                const urls_body = try self.uploadRequest(a, uri_upload_urls, &.{
                    .{ "partInfo", part_info },
                    .{ "uploadFileId", upload_file_id },
                });
                const uv = json.parse(a, urls_body) catch return Error.UpstreamNotJson;
                const key = try std.fmt.allocPrint(a, "uploadUrls.partNumber_{s}", .{part_no});
                const part_node = uv.getPath(key) orelse {
                    log.warn("[189] 第 {s} 片没有上传地址", .{part_no});
                    return Error.InvalidResponse;
                };
                const request_url = part_node.strAt("requestURL") orelse return Error.InvalidResponse;
                const raw_header = part_node.strAt("requestHeader") orelse "";

                // `requestHeader` 是 `k=v&k=v` 的百分号编码串，解出来逐条设头。
                const decoded = try pathUnescape(a, raw_header);
                var hs = List(model.Header).init(a);
                var it = std.mem.splitScalar(u8, decoded, '&');
                while (it.next()) |pair| {
                    if (pair.len == 0) continue;
                    const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
                    try hs.append(.{ .name = pair[0..eq], .value = pair[eq + 1 ..] });
                }
                // ⚠️ 分片 PUT **不**用驱动自己的 UA：Go 这里是 `base.HttpClient`
                // （一个裸 `http.Client`），所以线上发的是 Go 的默认 UA
                // `Go-http-client/1.1`（`drivers/189/util.go:430-438`，只设
                // `requestHeader` 解出来的头，没碰 UA）。我们的 client 在没给 UA
                // 时会自动补 OpenList 的浏览器串，所以必须显式写死成 Go 那个。
                try hs.append(.{ .name = "User-Agent", .value = go_default_ua });

                const put_res = try self.client.send(a, .{
                    .method = "PUT",
                    .url = request_url,
                    .headers = hs.slice(),
                    .body = chunk,
                    .use_cookies = false,
                });
                if (!put_res.isOk()) {
                    log.warn("[189] 第 {s} 片 HTTP {d}", .{ part_no, put_res.status });
                    return Error.UpstreamHttp;
                }
            }
        } else {
            log.info("[189] {s}: 秒传命中", .{name});
        }

        _ = try self.uploadRequest(a, uri_commit_upload, &.{
            .{ "uploadFileId", upload_file_id },
            .{ "fileMd5", file_md5 },
            .{ "sliceMd5", slice_md5 },
            .{ "lazyCheck", "1" },
            .{ "opertype", "3" },
        });
    }

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = lastSegment(dst);
        if (name.len == 0) return Error.InvalidPath;
        const dir = try self.resolve(a, parentOf(dst));
        if (!dir.is_dir) return Error.InvalidPath;

        try self.newUpload(a, dir, name, src, ctx);
    }
};

/// 189 的 id 是数字，但接口收的是字符串。
fn idStr(alloc: std.mem.Allocator, id: i64) ![]const u8 {
    return std.fmt.allocPrint(alloc, "{d}", .{id});
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "189Cloud",
    .label = "天翼云盘（个人版）",
    .secrets = &.{ "password", "cookie" },
    .addition_schema =
    \\{
    \\  "username":       {"type":"string","required":true,"help":"天翼云盘账号（手机号）"},
    \\  "password":       {"type":"string","required":true,"secret":true,"help":"密码。会以 RSA 公钥加密后提交，公钥每次登录现取"},
    \\  "cookie":         {"type":"string","required":false,"secret":true,"help":"保留字段：上游的 _189 包从未读取它（需要验证码时改用 189PC 驱动）"},
    \\  "root_folder_id": {"type":"string","default":"-11","help":"根目录 id，个人云固定是 -11"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(Cloud189, self);
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Cloud189 {
    const self = try alloc.create(Cloud189);
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

    fn source(self: *MemSource) model.Source {
        return .{ .ptr = self, .vtable = &.{ .size = sizeFn, .readAt = readAtFn } };
    }
};

test "noCache reproduces Go's 0.%17v shape" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var src = std.Random.IoSource{ .io = rt.io() };
    const rnd = src.interface();

    // 宽度 17 是右对齐补空格，所以固定长度是 2 + 17 = 19。
    const s = try noCache(a, rnd);
    try testing.expectEqual(@as(usize, 19), s.len);
    try testing.expectEqualStrings("0.", s[0..2]);
    // 十进制数字内部的空格只可能来自填充，且只能在前缀。
    const digits = std.mem.trimStart(u8, s[2..], " ");
    for (digits) |c| try testing.expect(c >= '0' and c <= '9');
    try testing.expect(digits.len >= 1 and digits.len <= 17);
}

test "randomPattern only substitutes x and y" {
    var src = std.Random.IoSource{ .io = rt.io() };
    const rnd = src.interface();

    var out: [uuid_pattern.len]u8 = undefined;
    randomPattern(rnd, &out, uuid_pattern);

    // 骨架上的 '-' 和字面量 '4' 必须留在原位。
    try testing.expectEqual(@as(u8, '-'), out[8]);
    try testing.expectEqual(@as(u8, '-'), out[13]);
    try testing.expectEqual(@as(u8, '4'), out[14]);
    try testing.expectEqual(@as(u8, '-'), out[18]);
    try testing.expectEqual(@as(u8, '-'), out[23]);
    // y 位（下标 19）按 RFC 4122 变体位只能是 8~b。
    const y = std.mem.indexOfScalar(u8, hex_digits, out[19]).?;
    try testing.expect(y >= 8 and y <= 11);
    // 除了四个 '-'（'4' 本身是合法的十六进制字符），其余都是十六进制字符。
    for (out, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) continue;
        try testing.expect(std.mem.indexOfScalar(u8, hex_digits, c) != null);
    }
    // 两次调用必须不同 —— 否则说明随机源没接上。
    var out2: [uuid_pattern.len]u8 = undefined;
    randomPattern(rnd, &out2, uuid_pattern);
    try testing.expect(!std.mem.eql(u8, &out, &out2));
}

test "encodeParam joins with & and escapes nothing" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 上游的 EncodeParam 是裸拼接：转义是调用点的事（fileName 先过
    // url.QueryEscape）。这里把「不转义」钉死，免得有人顺手"修好"它。
    try testing.expectEqualStrings(
        "b=2&a=1 2&c=",
        try encodeParam(a, &.{ .{ "b", "2" }, .{ "a", "1 2" }, .{ "c", "" } }),
    );
    try testing.expectEqualStrings("", try encodeParam(a, &.{}));
}

test "pathUnescape decodes %XX but leaves + alone" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 这是 url.PathUnescape 与 QueryUnescape 唯一的区别，189 的
    // requestHeader 里可能有 Base64 的 '+'，吃掉就废了。
    try testing.expectEqualStrings("a+b/c", try pathUnescape(a, "a+b%2Fc"));
    try testing.expectEqualStrings("100%", try pathUnescape(a, "100%"));
    try testing.expectEqualStrings("%zz", try pathUnescape(a, "%zz"));
    try testing.expectEqualStrings("", try pathUnescape(a, ""));
    // 大写的 %2F 同样要认。
    try testing.expectEqualStrings("/", try pathUnescape(a, "%2f"));
}

test "httpToHttps replaces only the first occurrence, anywhere" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("https://a/b", try httpToHttps(a, "http://a/b"));
    // 第一处不一定在开头 —— strings.Replace 是在整个串里找。
    try testing.expectEqualStrings("x?u=https://a&v=http://b", try httpToHttps(a, "x?u=http://a&v=http://b"));
    try testing.expectEqualStrings("//a/b", try httpToHttps(a, "//a/b"));
}

test "queryPart and resolveUrl" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("", queryPart("https://a/b"));
    try testing.expectEqualStrings("x=1&y=2", queryPart("https://a/b?x=1&y=2"));
    // '#' 之后的片段不算查询串。
    try testing.expectEqualStrings("x=1", queryPart("https://a/b?x=1#frag"));

    try testing.expectEqualStrings("https://b/x", try resolveUrl(a, "https://a/1", "https://b/x"));
    try testing.expectEqualStrings("https://b/x", try resolveUrl(a, "https://a/1", "//b/x"));
    try testing.expectEqualStrings("https://a/x", try resolveUrl(a, "https://a/1/2", "/x"));
    try testing.expectEqualStrings("https://a/1/x", try resolveUrl(a, "https://a/1/2", "x"));
}

test "aesEncryptHex round-trips through ecbDecrypt" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const key = "0123456789abcdef";
    const plain = "parentFolderId=-11&fileName=a.txt";
    const hex = try aesEncryptHex(a, key, plain);
    // 明文 34 字节 → PKCS#7 补到 48 → 96 个十六进制字符。
    try testing.expectEqual(@as(usize, 96), hex.len);

    const ct = try hash.hexDecode(a, hex);
    const back = try aes.ecbDecrypt(a, key, ct);
    try testing.expectEqualStrings(plain, try aes.pkcs7Unpad(back, aes.BLOCK));

    // 密钥不是 16 字节必须报错，而不是静默返回空串。
    try testing.expectError(Error.InvalidKey, aesEncryptHex(a, "short", plain));
}

test "the upload signature covers the whole random string, not just the AES key" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // RFC 2202 的 HMAC-SHA1 测试向量 1。
    try testing.expectEqualStrings(
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        try hash.hmacSha1Hex(a, "key", "The quick brown fox jumps over the lazy dog"),
    );
}

test "slice md5 list follows upstream's uppercase/lowercase split" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 分片 MD5 是大写，拼起来之后再算的 sliceMd5 是小写（GetMD5EncodeStr
    // → HashData → hex.EncodeToString）。已对照 pkg/utils/hash.go 确认。
    try testing.expectEqualStrings(
        "900150983cd24fb0d6963f7d28e17f72",
        try hash.md5Hex(a, "abc"),
    );
    var d = hash.md5("abc");
    try testing.expectEqualStrings(
        "900150983CD24FB0D6963F7D28E17F72",
        try hash.hexUpper(a, &d),
    );
    // 连接符是 "\n"，不是空串也不是逗号。
    try testing.expectEqualStrings(
        "30d54f2ed256b13d538c943cd14d1d2d",
        try hash.md5Hex(a, "A\nB"),
    );
}

test "Addition.parse keeps the documented defaults" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const empty = try Addition.parse(a, null);
    try testing.expectEqualStrings(default_root, empty.root_folder_id);

    var v = try json.parse(a, "{\"username\":\"u\",\"root_folder_id\":\"-11\"}");
    const got = try Addition.parse(a, &v);
    try testing.expectEqualStrings("u", got.username);
    try testing.expectEqualStrings("", got.password);
    try testing.expectEqualStrings("-11", got.root_folder_id);
}

test "createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const self = try createWithId(a, 9, null);
    try testing.expectEqual(@as(i64, 9), self.storage_id);
    try testing.expectEqualStrings("189Cloud", Cloud189.drvName(@ptrCast(self)));
    // 注册 key 必须和 Go 的 config.Name 逐字一致。
    try testing.expectEqualStrings("189Cloud", factory.key);
}

test "T3: real Go addition JSON parses into the driver" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与 Go `drivers/189/meta.go` 完全一致：username / password / cookie /
    // root_folder_id（内嵌 driver.RootID）。cookie 是「需要验证码时手填」的
    // 保留字段，上游 _189 包实际不读它。
    const src =
        \\{"username":"22644212509","password":"pw","cookie":"",
        \\ "root_folder_id":"-11"}
    ;
    const v = try json.parse(a, src);
    const got = try Addition.parse(a, &v);
    try testing.expectEqualStrings("22644212509", got.username);
    try testing.expectEqualStrings("-11", got.root_folder_id);

    const out = try got.toJson(a);
    const v2 = try json.parse(a, out);
    const got2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(got.username, got2.username);
    try testing.expectEqualStrings(got.root_folder_id, got2.root_folder_id);
}

test "lastSegment and parentOf split paths the way the vtable promises" {
    try testing.expectEqualStrings("c.txt", lastSegment("/a/b/c.txt"));
    try testing.expectEqualStrings("c.txt", lastSegment("/a/b/c.txt/"));
    try testing.expectEqualStrings("", lastSegment("/"));
    try testing.expectEqualStrings("/a/b", parentOf("/a/b/c.txt"));
    try testing.expectEqualStrings("/", parentOf("/c.txt"));
    try testing.expectEqualStrings("/", parentOf("/"));
}
