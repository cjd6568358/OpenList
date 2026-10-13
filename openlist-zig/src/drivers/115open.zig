//! 115 开放平台驱动 —— Go 版 `drivers/115_open` 的 Zig 移植。
//!
//! 九个目标驱动里，这个是**唯一一个依赖外部 SDK** 的：上游用
//! `github.com/OpenListTeam/115-sdk-go`（约 43 KB Go）封装开放平台 API，再用
//! `github.com/aliyun/aliyun-oss-go-sdk` 把文件真正写进阿里云 OSS。本工程不引
//! 第三方依赖，所以这两层都得自己实现。难度全在第二层。
//!
//! ## 四个难点
//!
//!   1. **上传根本不走 115 的服务器**。`/open/upload/init` 只返回一个 OSS
//!      `bucket`/`object` 和一段 callback 配置，真正的字节要 PUT 到
//!      `{bucket}.{endpoint}` 上。也就是说 `put()` 里必须内嵌一个 OSS 客户端。
//!   2. **OSS V1 签名**。`aliyun-oss-go-sdk` 默认 `AuthV1`（`oss.New` 不传
//!      `SetAuthVersion` 就是 V1），签名材料是
//!      `method\nContent-MD5\nContent-Type\nDate\nCanonicalizedOSSHeaders + CanonicalizedResource`，
//!      用 `AccessKeySecret` 做 HMAC-SHA1 再 base64。三处细节都是坑：
//!        * `CanonicalizedOSSHeaders` 只收 `x-oss-*` 头，**名字小写、按字节序排序**，
//!          每行 `name:value\n`；临时凭证的 `x-oss-security-token` 就在其中。
//!        * `CanonicalizedResource` 用**未转义的** object key（`/bucket/a/b`），
//!          而 URL 路径用 `url.QueryEscape` 过的（`/bucket/a%2Fb`）—— 服务端
//!          先解码路径再算签名，两边才对得上。
//!        * `Date` 是 RFC1123 GMT，且必须与真正发出去的头**逐字节一致**。
//!      `IsEnableMD5` 默认 false、CRC 只用于校验响应不回传头，所以
//!      `Content-MD5` 恒为空 —— 这让签名输入简单了不少。
//!   3. **三级秒传**。`upload/init` 的 `status` 是状态机：`2` = 秒传命中直接结束；
//!      `6/7/8` = 服务端要"双向校验"，按 `sign_check`（形如 `"2392148-2392298"`）
//!      把该区间的 SHA1 回填再问一次；其余才真上传。`fileid`/`preid` 是
//!      **整文件 SHA1** 与**前 128 KiB SHA1**，都要大写。
//!   4. **临时凭证会过期**。OSS 拒绝时返回 `<Error><Code>SecurityTokenExpired</Code>`，
//!      此时要重新 `upload/get_token` 换一套 AK/ST，**只重放被拒的那一个操作**
//!      （uploadId 保持不变）。Go 用 `retryExpiredToken(refresh, operation)` 包了
//!      这一层；这里在每个 OSS 调用点用同一个两轮循环表达。
//!
//! ## 与 Go 版的有意差异
//!
//!   * **`singleUpload` 没有移植**。它在 Go 版里是死代码 —— `Put()` 只有
//!     分片上传一条路径（`upload.go` 里 `singleUpload` 没有任何调用点）。
//!     把死代码搬过来只会让光猫多背几百字节。
//!   * **`Copy` / 离线下载 / 回收站没有移植**。vtable 里本来就没有 `copy`
//!     槽位；离线下载依赖任务中心，回收站是另一个驱动（`115_open` 的
//!     `meta.go` 也没暴露它们）。属于已知缺口。
//!   * **分片上传串行**。Go 版也是串行（`for i := 1; i <= partNum; i++`），
//!     这里没有改动，只是把 OSS SDK 的 `bucket.UploadPart` 换成手写 PUT。
//!   * **`limit_rate` 实现为最小间隔**。Go 用 `rate.NewLimiter(limit, 1)`；
//!     这里用 `1000/limit` 毫秒的最小请求间隔，稳态速率相同。理由见
//!     `123open.zig` 里 `RateLimiter` 的注释（本工程 HTTP 客户端全局串行）。
//!   * **`order_by` / `order_direction` 给了显式默认值**（`file_name` / `asc`）。
//!     Go 版的 struct tag 没有 `default:`，所以零值是空串 —— 但 OpenList 前端
//!     对 `select` 会取第一个选项提交，实际生效值就是这两个。这里直接写死，
//!     免得用户拿到一个"按上传时间倒序"的意外默认。
//!   * **`request()` 的重试显式收口**。Go 版是递归 `authRequest(..., true, ...)`，
//!     逻辑上只重试一轮但读起来像能无限套娃；这里用一个 `retried` 标志。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const urlmod = @import("../util/url.zig");
const xml = @import("../util/xml.zig");
const timeutil = @import("../util/time.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

/// 开放平台 API（文件、用户、上传票据）。
const api_base = "https://proapi.115.com";
/// 通行证 API（只用来刷新 token）。
const passport_base = "https://passportapi.115.com";

const api_user_info = api_base ++ "/open/user/info";
const api_files = api_base ++ "/open/ufile/files";
const api_folder_info = api_base ++ "/open/folder/get_info";
const api_folder_add = api_base ++ "/open/folder/add";
const api_move = api_base ++ "/open/ufile/move";
const api_update = api_base ++ "/open/ufile/update";
const api_delete = api_base ++ "/open/ufile/delete";
const api_down_url = api_base ++ "/open/ufile/downurl";
const api_upload_init = api_base ++ "/open/upload/init";
const api_upload_token = api_base ++ "/open/upload/get_token";
const api_refresh_token = passport_base ++ "/open/refreshToken";

/// 开放平台 SDK 用 resty 建客户端且没设 User-Agent，于是走 resty 的默认值。
/// 与 `quark_open` 是同一个字符串 —— 两家上游用的是同一个库。
const user_agent = "go-resty/3.0.0-beta.1 (https://resty.dev)";

/// 下载链接的 User-Agent。115 的直链会按 UA 决定给不给 Range，Go 版用的是
/// `base.UserAgent`（OpenList 全局默认值），这里照抄。
const download_user_agent = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) " ++
    "AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";

/// 秒传预检只取前 128 KiB 做 SHA1（Go 的 `PreHashSize`）。
const pre_hash_size: i64 = 128 * 1024;
/// 算整文件哈希时的读取块。
const hash_block = 128 * 1024;

/// 115 的根目录 ID。
const default_root = "0";

const mb: i64 = 1024 * 1024;
const gb: i64 = 1024 * mb;
const tb: i64 = 1024 * gb;

pub const Error = error{
    /// 既没有 RefreshToken 也没有 AccessToken。
    NoToken,
    /// 上游非 200。
    UpstreamHttp,
    /// 上游返回的不是 JSON。
    UpstreamNotJson,
    /// `state=false` 且不是可自愈的鉴权码。
    UpstreamError,
    /// 响应里缺了必需字段。
    InvalidResponse,
    /// 路径为空或缺少文件名。
    InvalidPath,
    /// `sign_check` 不是 `"起-止"` 形状。
    BadSignCheck,
    /// OSS 返回非 2xx。
    OssError,
    /// OSS 拒绝了临时凭证（`SecurityTokenExpired`）。
    OssTokenExpired,
    /// OSS 的 multipart 响应里没有 `UploadId`。
    OssNoUploadId,
};

// ---------------------------------------------------------------------------
// 配置（对应 Go 的 Addition）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    /// 根目录 ID，对应 Go 的 `driver.RootID`（json tag `root_folder_id`）。
    root_folder_id: []const u8 = default_root,
    order_by: []const u8 = "file_name",
    order_direction: []const u8 = "asc",
    /// 全部 API 请求的速率上限（次/秒）。
    limit_rate: f64 = 1,
    page_size: i64 = 200,
    access_token: []const u8 = "",
    refresh_token: []const u8 = "",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;

        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        a.order_by = try dupeOr(alloc, o.strAt("order_by"), "file_name");
        a.order_direction = try dupeOr(alloc, o.strAt("order_direction"), "asc");
        if (o.getPath("limit_rate")) |p| {
            if (p.asFloat()) |f| a.limit_rate = f else if (p.asInt()) |i| {
                a.limit_rate = @floatFromInt(i);
            }
        }
        if (o.getPath("page_size")) |p| {
            if (p.asInt()) |i| a.page_size = i else if (p.asFloat()) |f| {
                a.page_size = @intFromFloat(f);
            }
        }
        a.access_token = try dupeOr(alloc, o.strAt("access_token"), "");
        a.refresh_token = try dupeOr(alloc, o.strAt("refresh_token"), "");
        return a;
    }

    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("root_folder_id", self.root_folder_id);
        try w.str("order_by", self.order_by);
        try w.str("order_direction", self.order_direction);
        try w.key("limit_rate");
        try b.print("{d}", .{self.limit_rate});
        try w.int("page_size", self.page_size);
        try w.str("access_token", self.access_token);
        try w.str("refresh_token", self.refresh_token);
        try w.end();
        return b.toOwned();
    }

    /// 对应 Go 的 `d.Addition.OrderDirection == "asc"`。
    fn ascending(self: Addition) bool {
        return std.mem.eql(u8, self.order_direction, "asc");
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
    fn end(self: *ObjWriter) !void {
        try self.b.appendByte('}');
    }
};

// ---------------------------------------------------------------------------
// 时间
// ---------------------------------------------------------------------------

// 日历格式化（OSS 的 `Date` 头）在 `util/time.zig` 里 —— `aliyundrive_open`
// 和 `123_open` 也要用同一份 `civilFromDays`，抄三遍不如共用一份。

/// Go 的 `parseTime`：`strconv.ParseInt(value, 10, 64)`，失败给 0。
fn parseTime(value: []const u8) i64 {
    return std.fmt.parseInt(i64, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0;
}

/// Go 的 `ParseInt64(json.Number)`：先试整数，再试浮点。
fn parseInt64Flex(v: *const json.Value) i64 {
    if (v.asInt()) |i| return i;
    if (v.asFloat()) |f| return @intFromFloat(f);
    if (v.asStr()) |s| {
        return std.fmt.parseInt(i64, std.mem.trim(u8, s, " \t\r\n"), 10) catch
            @intFromFloat(std.fmt.parseFloat(f64, s) catch 0);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 阿里云 OSS V1 客户端
//
// 只实现 115 用到的四个动作：InitiateMultipartUpload / UploadPart /
// CompleteMultipartUpload（外加错误码解析）。刻意不做 PutObject —— 见文件头
// "singleUpload 没有移植"。
// ---------------------------------------------------------------------------

const OssCreds = struct {
    scheme: []const u8 = "http",
    /// 裸 host，**不含** bucket（虚拟主机风格会把 bucket 拼在前面）。
    host: []const u8 = "",
    bucket: []const u8 = "",
    access_key_id: []const u8 = "",
    access_key_secret: []const u8 = "",
    security_token: []const u8 = "",
};

/// `urlMaker.InitExt`：有 scheme 就用，没有就默认 **http**（不是 https ——
/// 这是 SDK 的实际行为，照抄以免签名/连接方式不一致）。
fn parseEndpoint(endpoint: []const u8) struct { scheme: []const u8, host: []const u8 } {
    if (std.mem.startsWith(u8, endpoint, "http://")) {
        return .{ .scheme = "http", .host = std.mem.trimEnd(u8, endpoint["http://".len..], "/") };
    }
    if (std.mem.startsWith(u8, endpoint, "https://")) {
        return .{ .scheme = "https", .host = std.mem.trimEnd(u8, endpoint["https://".len..], "/") };
    }
    return .{ .scheme = "http", .host = std.mem.trimEnd(u8, endpoint, "/") };
}

/// OSS V1 签名。
///
/// ```
/// Signature = base64(HMAC-SHA1(AccessKeySecret,
///     VERB "\n" Content-MD5 "\n" Content-Type "\n" Date "\n"
///     CanonicalizedOSSHeaders CanonicalizedResource))
/// ```
fn signV1(
    alloc: std.mem.Allocator,
    method: []const u8,
    content_md5: []const u8,
    content_type: []const u8,
    date: []const u8,
    canonical_oss_headers: []const u8,
    canonical_resource: []const u8,
    secret: []const u8,
) ![]u8 {
    const material = try std.fmt.allocPrint(alloc, "{s}\n{s}\n{s}\n{s}\n{s}{s}", .{
        method, content_md5, content_type, date, canonical_oss_headers, canonical_resource,
    });
    const mac = hash.hmacSha1(secret, material);
    return hash.base64Std(alloc, &mac);
}

fn lessHeader(_: void, a: model.Header, b: model.Header) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

/// 发一次 OSS 请求。
///
/// `sub_resource` 同时用作 URL 的查询串和 `CanonicalizedResource` 的
/// subresource —— 在本驱动用到的三个动作里两者**恰好相同**（`sequential&uploads`
/// / `partNumber=1&uploadId=X` / `uploadId=X`），所以只留一个参数。
fn ossSend(
    self: *Open115,
    arena: std.mem.Allocator,
    creds: *const OssCreds,
    method: []const u8,
    object: []const u8,
    sub_resource: []const u8,
    content_type: ?[]const u8,
    extra_oss_headers: []const model.Header,
    body: []const u8,
    source: ?model.Source,
    content_length: ?u64,
) !httpclient.Response {
    // 1. CanonicalizedOSSHeaders：只收 x-oss-*，名字小写、按字节序排序。
    var oss_headers = List(model.Header).init(arena);
    try oss_headers.append(.{ .name = "x-oss-security-token", .value = creds.security_token });
    for (extra_oss_headers) |h| try oss_headers.append(h);
    std.mem.sort(model.Header, oss_headers.sliceMut(), {}, lessHeader);

    var canon = Buf.init(arena);
    for (oss_headers.slice()) |h| try canon.print("{s}:{s}\n", .{ h.name, h.value });

    // 2. Date 头 —— 签名材料和实际头必须是同一个字符串。
    var date_buf = Buf.init(arena);
    try timeutil.formatHttpDate(&date_buf, rt.nowSeconds());
    const date = date_buf.slice();

    // 3. CanonicalizedResource 用**未转义**的 object。
    const resource = if (sub_resource.len > 0)
        try std.fmt.allocPrint(arena, "/{s}/{s}?{s}", .{ creds.bucket, object, sub_resource })
    else
        try std.fmt.allocPrint(arena, "/{s}/{s}", .{ creds.bucket, object });

    const ct = content_type orelse "";
    const signature = try signV1(arena, method, "", ct, date, canon.slice(), resource, creds.access_key_secret);
    const auth = try std.fmt.allocPrint(arena, "OSS {s}:{s}", .{ creds.access_key_id, signature });

    // 4. URL 路径用 `url.QueryEscape` 语义（`/` → `%2F`，空格 → `%20`），
    //    与 SDK 的 `buildURL` 一致。虚拟主机风格：`{bucket}.{host}`。
    const escaped_object = try urlmod.encode(arena, object, .component);
    const host = try std.fmt.allocPrint(arena, "{s}.{s}", .{ creds.bucket, creds.host });
    const url = if (sub_resource.len > 0)
        try std.fmt.allocPrint(arena, "{s}://{s}/{s}?{s}", .{ creds.scheme, host, escaped_object, sub_resource })
    else
        try std.fmt.allocPrint(arena, "{s}://{s}/{s}", .{ creds.scheme, host, escaped_object });

    var headers = List(model.Header).init(arena);
    try headers.append(.{ .name = "Date", .value = date });
    try headers.append(.{ .name = "User-Agent", .value = user_agent });
    try headers.append(.{ .name = "Authorization", .value = auth });
    for (oss_headers.slice()) |h| try headers.append(h);
    if (content_type) |c| try headers.append(.{ .name = "Content-Type", .value = c });

    return self.client.send(arena, .{
        .method = method,
        .url = url,
        .headers = headers.slice(),
        .body = body,
        .source = source,
        .content_length = content_length,
    });
}

/// 从 OSS 的错误 XML 里取 `<Code>`。非 XML（或不是 Error 形状）返回 null。
fn ossErrorCode(arena: std.mem.Allocator, body: []const u8) ?[]const u8 {
    const root = xml.parse(arena, body) catch return null;
    return root.textOf("Code");
}

/// OSS 非 2xx 时的统一出口：`SecurityTokenExpired` 单独成一个可重试的错误。
fn ossCheck(arena: std.mem.Allocator, url: []const u8, res: httpclient.Response) !void {
    if (res.status >= 200 and res.status < 300) return;
    const code = ossErrorCode(arena, res.body);
    log.warn("[115open] OSS {s} HTTP {d} code={s}: {s}", .{
        url, res.status, code orelse "-", res.body[0..@min(res.body.len, 200)],
    });
    if (code) |c| {
        if (std.mem.eql(u8, c, "SecurityTokenExpired")) return Error.OssTokenExpired;
    }
    return Error.OssError;
}

const Multipart = struct {
    upload_id: []const u8,
    key: []const u8,
    bucket: []const u8,
};

/// `POST /{object}?sequential&uploads`
///
/// `sequential` 是 Go 传的 `oss.Sequential()`：它把分片顺序语义打开，115 的
/// callback 依赖它。`uploads` 与 `sequential` 都**没有值**，所以查询串里只有
/// 裸键名 —— 这也是 `getSubResource` 的实际输出。
fn ossInitiate(
    self: *Open115,
    arena: std.mem.Allocator,
    creds: *const OssCreds,
    object: []const u8,
    content_type: []const u8,
) !Multipart {
    const res = try ossSend(self, arena, creds, "POST", object, "sequential&uploads", content_type, &.{}, "", null, null);
    try ossCheck(arena, "InitiateMultipartUpload", res);

    const root = xml.parse(arena, res.body) catch return Error.InvalidResponse;
    const upload_id = root.textOf("UploadId") orelse return Error.OssNoUploadId;
    return .{
        .upload_id = upload_id,
        // 用响应里的 Key 而不是请求的 object —— SDK 也是这么做的
        // （服务端可能对 key 做过规范化）。
        .key = root.textOf("Key") orelse object,
        .bucket = root.textOf("Bucket") orelse creds.bucket,
    };
}

/// `PUT /{object}?partNumber=N&uploadId=X`，返回响应里的 ETag（**带引号**）。
fn ossUploadPart(
    self: *Open115,
    arena: std.mem.Allocator,
    creds: *const OssCreds,
    object: []const u8,
    upload_id: []const u8,
    part_number: u64,
    source: model.Source,
    part_len: u64,
) ![]const u8 {
    // 排序后的键序：`partNumber` < `uploadId`（'p' < 'u'）。
    const sub = try std.fmt.allocPrint(arena, "partNumber={d}&uploadId={s}", .{ part_number, upload_id });
    // UploadPart 不带 Content-Type（SDK 的 options 里没有 ContentType）。
    const res = try ossSend(self, arena, creds, "PUT", object, sub, null, &.{}, "", source, part_len);
    try ossCheck(arena, "UploadPart", res);
    const etag = res.header("ETag") orelse return Error.InvalidResponse;
    return arena.dupe(u8, etag);
}

/// Go 的 `encoding/xml` 对文本节点的转义规则。
///
/// 逐条照抄不是为了好看：ETag 是 `"hex"`（**带引号**），Go 会把它写成
/// `&#34;hex&#34;`，OSS 解回来仍是带引号的字符串。保持一致最省心。
fn writeXmlText(b: *Buf, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try b.append("&#34;"),
        '\'' => try b.append("&#39;"),
        '&' => try b.append("&amp;"),
        '<' => try b.append("&lt;"),
        '>' => try b.append("&gt;"),
        '\t' => try b.append("&#x9;"),
        '\n' => try b.append("&#xA;"),
        '\r' => try b.append("&#xD;"),
        else => try b.appendByte(c),
    };
}

/// `<CompleteMultipartUpload><Part><PartNumber>N</PartNumber><ETag>..</ETag></Part>…`
fn buildCompleteXml(b: *Buf, etags: []const []const u8) !void {
    try b.append("<CompleteMultipartUpload>");
    for (etags, 0..) |etag, i| {
        try b.print("<Part><PartNumber>{d}</PartNumber><ETag>", .{i + 1});
        try writeXmlText(b, etag);
        try b.append("</ETag></Part>");
    }
    try b.append("</CompleteMultipartUpload>");
}

/// `POST /{object}?uploadId=X`，带 115 的 callback 配置。
///
/// `x-oss-callback` / `x-oss-callback-var` 的值是 **base64 过的 JSON**，
/// 由 `upload/init` 下发；OSS 在写完对象后回调 115，115 靠它建文件记录。
/// 没有这两个头，字节写进去了但文件不会出现在网盘里。
fn ossComplete(
    self: *Open115,
    arena: std.mem.Allocator,
    creds: *const OssCreds,
    object: []const u8,
    upload_id: []const u8,
    etags: []const []const u8,
    callback_b64: []const u8,
    callback_var_b64: []const u8,
) !void {
    var body = Buf.init(arena);
    try buildCompleteXml(&body, etags);

    var extra = List(model.Header).init(arena);
    // 排序后：callback < callback-var < security-token（字节序）。
    try extra.append(.{ .name = "x-oss-callback", .value = callback_b64 });
    try extra.append(.{ .name = "x-oss-callback-var", .value = callback_var_b64 });

    const sub = try std.fmt.allocPrint(arena, "uploadId={s}", .{upload_id});
    // CompleteMultipartUpload 也不带 Content-Type（SDK 只透传调用方的 options）。
    const res = try ossSend(self, arena, creds, "POST", object, sub, null, extra.slice(), body.slice(), null, null);
    try ossCheck(arena, "CompleteMultipartUpload", res);
}

// ---------------------------------------------------------------------------
// 驱动本体
// ---------------------------------------------------------------------------

/// 115 的 `folder/get_info` 结果。`data` 既可能是对象也可能是数组（数组时取
/// 第一个；空数组等价于"不存在"）—— SDK 为此专门写了 `UnmarshalJSON`。
const FolderInfo = struct {
    file_id: []const u8 = "",
    file_name: []const u8 = "",
    /// "0" = 文件夹，其它 = 文件。
    file_category: []const u8 = "",
    sha1: []const u8 = "",
    pick_code: []const u8 = "",
    size_byte: i64 = 0,
    utime: []const u8 = "",
    ptime: []const u8 = "",
    paths: []const PathItem = &.{},

    const PathItem = struct { file_id: []const u8, file_name: []const u8 };
};

const UserInfo = struct {
    user_id: i64 = 0,
    total: i64 = 0,
    used: i64 = 0,
};

/// 路径解析结果。115 的一切操作都以 `fid` 为键，所以和 123pan / 夸克一样
/// 需要"路径 → ID"这一层（见 `driver.zig` 关于 vtable 用路径的说明）。
const Entry = struct {
    id: []const u8,
    /// 父目录 ID —— 删除接口要用。
    pid: []const u8 = "",
    name: []const u8 = "",
    is_dir: bool = false,
    size: i64 = 0,
    modified: i64 = 0,
    created: i64 = 0,
    sha1: []const u8 = "",
    thumb: []const u8 = "",
    pick_code: []const u8 = "",
};

/// 一个上传预检/初始化请求。
const UploadInitReq = struct {
    file_name: []const u8,
    file_size: i64,
    /// 目标目录 fid（不含 `U_1_` 前缀）。
    target: []const u8,
    /// 整文件 SHA1，大写。
    file_id: []const u8,
    /// 前 128 KiB 的 SHA1，大写。
    pre_id: []const u8,
    sign_key: []const u8 = "",
    sign_val: []const u8 = "",
};

const UploadInit = struct {
    status: i64 = 0,
    sign_key: []const u8 = "",
    sign_check: []const u8 = "",
    bucket: []const u8 = "",
    object: []const u8 = "",
    callback: []const u8 = "",
    callback_var: []const u8 = "",
};

const UploadToken = struct {
    endpoint: []const u8 = "",
    access_key_id: []const u8 = "",
    access_key_secret: []const u8 = "",
    security_token: []const u8 = "",
};

pub const Open115 = struct {
    alloc: std.mem.Allocator,
    storage_id: i64 = 0,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,
    limiter: RateLimiter = .{},
    /// 挂载根在 115 侧的绝对路径（`root_folder_id` 不是账号根时才有意义）。
    /// 只有 by-path 的 `folder/get_info` 需要它。
    parent_path: []const u8 = "/",
    user_id: []const u8 = "",
    last_saved: []const u8 = "",

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn drvName(_: *anyopaque) []const u8 {
        return "115 Open";
    }

    fn as(ptr: *anyopaque) *Open115 {
        return @ptrCast(@alignCast(ptr));
    }

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        _ = ctx;

        if (self.cfg.page_size <= 0) {
            self.cfg.page_size = 200;
        } else if (self.cfg.page_size > 1150) {
            self.cfg.page_size = 1150;
        }
        self.limiter.qps = if (self.cfg.limit_rate > 0) @intFromFloat(self.cfg.limit_rate) else 0;

        if (self.cfg.refresh_token.len == 0 and self.cfg.access_token.len == 0) {
            log.err("[115open] 需要 RefreshToken（推荐）或 AccessToken", .{});
            return Error.NoToken;
        }

        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const info = try self.userInfo(a);
        var id_buf: [24]u8 = undefined;
        self.user_id = try self.alloc.dupe(u8, std.fmt.bufPrint(&id_buf, "{d}", .{info.user_id}) catch "0");

        // 挂载根不在账号根上时，记下它在 115 侧的绝对路径。
        if (!std.mem.eql(u8, self.cfg.root_folder_id, default_root)) {
            const fi = try self.folderInfo(a, self.cfg.root_folder_id);
            self.parent_path = try buildParentPath(self.alloc, fi);
        }
        log.info("[115open] ready: user={s} root={s} parent_path={s}", .{
            self.user_id, self.cfg.root_folder_id, self.parent_path,
        });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        self.save();
    }

    fn save(self: *Open115) void {
        if (self.storage_id == 0) return;
        const text = self.cfg.toJson(self.alloc) catch return;
        if (text.len == self.last_saved.len and std.mem.eql(u8, text, self.last_saved)) {
            self.alloc.free(text);
            return;
        }
        if (self.last_saved.len > 0) self.alloc.free(self.last_saved);
        self.last_saved = text;
        driver.persist(self.storage_id, self.last_saved);
    }

    // -----------------------------------------------------------------------
    // HTTP：开放平台信封
    // -----------------------------------------------------------------------

    /// `{state: bool, code: int64, message, data}`。
    /// `state` 在开放平台是 bool，在通行证是 int —— 这里两种都认。
    /// （定义在文件末尾的顶层 `Envelope` 上。）

    /// 发一次开放平台请求。
    ///
    /// 成功时返回原始 body（调用方自己解 `data`）。`state=false` 且 code 属于
    /// "token 失效"族时刷新一次并**只重放一轮**；430004 映射成 NotFound
    /// （SDK 的 `Error.Is(ErrObjectNotFound)`）。
    fn request(
        self: *Open115,
        arena: std.mem.Allocator,
        method: []const u8,
        url: []const u8,
        form: ?[]const u8,
        /// D13：覆盖本次请求的 User-Agent。Go 的 `Link` 会把调用方的 UA
        /// 传进 `DownURL`（drivers/115_open/driver.go:139-151），115 会据此
        /// 下发不同形态的下载地址；传 null 用驱动默认值。
        ua: ?[]const u8,
    ) ![]const u8 {
        var retried = false;
        while (true) {
            self.limiter.acquire();

            const auth = try std.fmt.allocPrint(arena, "Bearer {s}", .{self.cfg.access_token});
            var headers = List(model.Header).init(arena);
            try headers.append(.{ .name = "Accept", .value = "application/json, text/plain, */*" });
            try headers.append(.{ .name = "User-Agent", .value = ua orelse user_agent });
            try headers.append(.{ .name = "Authorization", .value = auth });
            if (form != null) {
                try headers.append(.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" });
            }

            const res = try self.client.send(arena, .{
                .method = method,
                .url = url,
                .headers = headers.slice(),
                .body = form orelse "",
            });

            if (res.status != 200) {
                log.warn("[115open] {s} HTTP {d}: {s}", .{
                    url, res.status, res.body[0..@min(res.body.len, 200)],
                });
                return Error.UpstreamHttp;
            }

            const v = json.parse(arena, res.body) catch {
                log.warn("[115open] {s} non-JSON: {s}", .{
                    url, res.body[0..@min(res.body.len, 200)],
                });
                return Error.UpstreamNotJson;
            };

            const env = parseEnvelope(&v);
            if (env.state) return res.body;

            if (!retried and (env.code == 99 or is401Started(env.code))) {
                retried = true;
                log.info("[115open] token 失效 (code={d})，刷新后重放一次", .{env.code});
                try self.refreshToken(arena);
                continue;
            }
            if (env.code == 430004) return driver.Error.NotFound;

            log.warn("[115open] {s} code={d} message={s}", .{ url, env.code, env.message });
            return Error.UpstreamError;
        }
    }

    /// `POST /open/refreshToken`。返回的 access/refresh token 立刻写回配置并持久化
    /// —— 对应 Go 的 `WithOnRefreshToken` → `op.MustSaveDriverStorage`。
    fn refreshToken(self: *Open115, arena: std.mem.Allocator) !void {
        if (self.cfg.refresh_token.len == 0) return Error.NoToken;

        var form = urlmod.Query.init(arena);
        try form.add("refresh_token", self.cfg.refresh_token);

        self.limiter.acquire();
        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = api_refresh_token,
            .headers = &.{
                .{ .name = "Accept", .value = "application/json, text/plain, */*" },
                .{ .name = "User-Agent", .value = user_agent },
                .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            },
            .body = form.slice(),
        });
        if (res.status != 200) {
            log.warn("[115open] refreshToken HTTP {d}: {s}", .{
                res.status, res.body[0..@min(res.body.len, 200)],
            });
            return Error.UpstreamHttp;
        }
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;

        // 通行证接口的 state 是 int，且 code != 0 / error != "" 都算失败。
        const env = parseEnvelope(&v);
        const err_field = v.strAt("error") orelse "";
        if (!env.state or env.code != 0 or err_field.len > 0) {
            log.warn("[115open] refreshToken 失败: code={d} message={s} error={s}", .{
                env.code, env.message, err_field,
            });
            return driver.Error.AuthFailed;
        }

        const at = v.strAt("data.access_token") orelse return Error.InvalidResponse;
        const rt_new = v.strAt("data.refresh_token") orelse "";

        // 换掉旧值。旧值同样是 self.alloc 分配的，不释放就是每次刷新漏一份。
        self.alloc.free(self.cfg.access_token);
        self.cfg.access_token = try self.alloc.dupe(u8, at);
        if (rt_new.len > 0) {
            self.alloc.free(self.cfg.refresh_token);
            self.cfg.refresh_token = try self.alloc.dupe(u8, rt_new);
        }
        self.save();
    }

    // -----------------------------------------------------------------------
    // 开放平台 API
    // -----------------------------------------------------------------------

    fn userInfo(self: *Open115, arena: std.mem.Allocator) !UserInfo {
        const body = try self.request(arena, "GET", api_user_info, null, null);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const d = v.getPath("data") orelse return Error.InvalidResponse;

        var info = UserInfo{};
        if (d.getPath("user_id")) |p| info.user_id = parseInt64Flex(p);
        if (d.getPath("rt_space_info.all_total.size")) |p| info.total = parseInt64Flex(p);
        if (d.getPath("rt_space_info.all_use.size")) |p| info.used = parseInt64Flex(p);
        return info;
    }

    const Page = struct { items: []json.Value, count: i64 };

    /// `GET /open/ufile/files`。注意 `count` 是**顶层**字段（不是 `data.count`）
    /// —— SDK 的 `GetFilesResp` 把它和内嵌的 `Resp` 并列，所以是同级。
    fn listPage(self: *Open115, arena: std.mem.Allocator, cid: []const u8, offset: i64) !Page {
        var size_buf: [24]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{self.cfg.page_size}) catch unreachable;
        var off_buf: [24]u8 = undefined;
        const off_str = std.fmt.bufPrint(&off_buf, "{d}", .{offset}) catch unreachable;

        var q = urlmod.Query.init(arena);
        // 与 SDK 的 `ReqWithQuery(removeEmptyForm(...))` 一样：空值不上送，
        // 且 `url.Values.Encode()` 按 key 排序。
        var pairs = List([2][]const u8).init(arena);
        try pairs.append(.{ "asc", if (self.cfg.ascending()) "1" else "0" });
        try pairs.append(.{ "cid", cid });
        try pairs.append(.{ "cur", "0" });
        try pairs.append(.{ "custom_order", "0" });
        try pairs.append(.{ "limit", size_str });
        if (self.cfg.order_by.len > 0) try pairs.append(.{ "o", self.cfg.order_by });
        try pairs.append(.{ "offset", off_str });
        try pairs.append(.{ "show_dir", "1" });
        try pairs.append(.{ "star", "0" });
        try pairs.append(.{ "stdir", "0" });
        try q.addSorted(pairs.slice());

        const url = try std.fmt.allocPrint(arena, "{s}?{s}", .{ api_files, q.slice() });
        const body = try self.request(arena, "GET", url, null, null);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        return .{ .items = arrAt(&v, "data"), .count = v.intAt("count") orelse 0 };
    }

    /// `GET /open/folder/get_info?file_id=X`
    fn folderInfo(self: *Open115, arena: std.mem.Allocator, file_id: []const u8) !FolderInfo {
        var q = urlmod.Query.init(arena);
        try q.add("file_id", file_id);
        const url = try std.fmt.allocPrint(arena, "{s}?{s}", .{ api_folder_info, q.slice() });
        const body = try self.request(arena, "GET", url, null, null);
        return parseFolderInfo(arena, body);
    }

    /// `POST /open/folder/get_info`（form `path=...`）。
    ///
    /// 路径必须是**从 115 账号根算起**的绝对路径，所以调用方要带上
    /// `parent_path`。
    fn folderInfoByPath(self: *Open115, arena: std.mem.Allocator, path: []const u8) !FolderInfo {
        var form = urlmod.Query.init(arena);
        try form.add("path", path);
        const body = try self.request(arena, "POST", api_folder_info, form.slice(), null);
        return parseFolderInfo(arena, body);
    }

    /// 把 `folder/get_info` 的 body 解成 `FolderInfo`。
    ///
    /// `data` 是数组时取第一个，空数组等价于"不存在"（SDK 的
    /// `UnmarshalJSON` 就是这么写的，也是 115 表达 not-found 的方式之一）。
    fn parseFolderInfo(arena: std.mem.Allocator, body: []const u8) !FolderInfo {
        return parseFolderInfoBody(arena, body);
    }

    /// `POST /open/folder/add`（form）。
    fn mkdir(self: *Open115, arena: std.mem.Allocator, pid: []const u8, name: []const u8) !void {
        var form = urlmod.Query.init(arena);
        try form.add("pid", pid);
        try form.add("file_name", name);
        _ = try self.request(arena, "POST", api_folder_add, form.slice(), null);
    }

    /// `POST /open/ufile/move`（form `file_ids`、`to_cid`）。
    fn apiMove(self: *Open115, arena: std.mem.Allocator, file_ids: []const u8, to_cid: []const u8) !void {
        var form = urlmod.Query.init(arena);
        try form.add("file_ids", file_ids);
        try form.add("to_cid", to_cid);
        _ = try self.request(arena, "POST", api_move, form.slice(), null);
    }

    /// `POST /open/ufile/update`（form `file_id`、`file_name`）。
    fn updateFile(self: *Open115, arena: std.mem.Allocator, file_id: []const u8, new_name: []const u8) !void {
        var form = urlmod.Query.init(arena);
        try form.add("file_id", file_id);
        try form.add("file_name", new_name);
        _ = try self.request(arena, "POST", api_update, form.slice(), null);
    }

    /// `POST /open/ufile/delete`（form `file_ids`、`parent_id`）。
    fn delFile(self: *Open115, arena: std.mem.Allocator, file_ids: []const u8, parent_id: []const u8) !void {
        var form = urlmod.Query.init(arena);
        try form.add("file_ids", file_ids);
        try form.add("parent_id", parent_id);
        _ = try self.request(arena, "POST", api_delete, form.slice(), null);
    }

    /// `POST /open/ufile/downurl`（form `pick_code`）→ `data[fid].url.url`。
    fn downUrl(self: *Open115, arena: std.mem.Allocator, fid: []const u8, pick_code: []const u8, ua: []const u8) ![]const u8 {
        // D13：UA 必须真的发给 downurl 接口。Go 的 `Link` 把调用方 UA 一路传进
        // `DownURL`（drivers/115_open/driver.go:139-151），115 会按 UA 下发不同
        // 形态的下载地址。以前这里 `_ = ua;` 直接丢弃，只在返回的 Link 头里用了
        // 它 —— 请求与返回头用的不是同一个 UA，拿到的地址可能不可直用。
        var form = urlmod.Query.init(arena);
        try form.add("pick_code", pick_code);
        const body = try self.request(arena, "POST", api_down_url, form.slice(), ua);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;

        const data = v.getPath("data") orelse return Error.InvalidResponse;
        const obj = data.asObject() orelse return Error.InvalidResponse;
        const entry = obj.get(fid) orelse return driver.Error.NotFound;
        return entry.strAt("url.url") orelse Error.InvalidResponse;
    }

    // -----------------------------------------------------------------------
    // 上传：预检 → 秒传 → OSS 分片
    // -----------------------------------------------------------------------

    /// `POST /open/upload/init`。
    fn uploadInit(self: *Open115, arena: std.mem.Allocator, req: UploadInitReq) !UploadInit {
        var size_buf: [24]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{req.file_size}) catch unreachable;
        const target = try std.fmt.allocPrint(arena, "U_1_{s}", .{req.target});

        var pairs = List([2][]const u8).init(arena);
        try pairs.append(.{ "file_name", req.file_name });
        try pairs.append(.{ "file_size", size_str });
        try pairs.append(.{ "target", target });
        try pairs.append(.{ "fileid", req.file_id });
        try pairs.append(.{ "preid", req.pre_id });
        if (req.sign_key.len > 0) try pairs.append(.{ "sign_key", req.sign_key });
        if (req.sign_val.len > 0) try pairs.append(.{ "sign_val", req.sign_val });

        var form = urlmod.Query.init(arena);
        try form.addSorted(pairs.slice());

        const body = try self.request(arena, "POST", api_upload_init, form.slice(), null);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const d = v.getPath("data") orelse return Error.InvalidResponse;

        var out = UploadInit{
            .sign_key = d.strAt("sign_key") orelse "",
            .sign_check = d.strAt("sign_check") orelse "",
            .bucket = d.strAt("bucket") orelse "",
            .object = d.strAt("object") orelse "",
        };
        if (d.getPath("status")) |p| out.status = parseInt64Flex(p);

        // `callback` 是 `StructOrArray`：正常是对象，理论上也可能是数组。
        if (d.getPath("callback")) |cb| {
            var c: *const json.Value = cb;
            if (cb.asArray()) |arr| {
                if (arr.len > 0) c = &arr[0];
            }
            out.callback = c.strAt("callback") orelse "";
            out.callback_var = c.strAt("callback_var") orelse "";
        }
        return out;
    }

    /// `GET /open/upload/get_token` —— 一次性的 OSS 临时凭证。
    fn uploadToken(self: *Open115, arena: std.mem.Allocator) !UploadToken {
        const body = try self.request(arena, "GET", api_upload_token, null, null);
        const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
        const d = v.getPath("data") orelse return Error.InvalidResponse;
        return .{
            .endpoint = d.strAt("endpoint") orelse "",
            .access_key_id = d.strAt("AccessKeyId") orelse "",
            .access_key_secret = d.strAt("AccessKeySecret") orelse "",
            .security_token = d.strAt("SecurityToken") orelse "",
        };
    }

    /// 换一套 OSS 临时凭证，bucket 保持不变（bucket 来自 `upload/init`，
    /// 与 get_token 无关）。
    fn refreshOssCreds(self: *Open115, arena: std.mem.Allocator, creds: *OssCreds) !void {
        const tok = try self.uploadToken(arena);
        const ep = parseEndpoint(tok.endpoint);
        creds.scheme = ep.scheme;
        creds.host = ep.host;
        creds.access_key_id = tok.access_key_id;
        creds.access_key_secret = tok.access_key_secret;
        creds.security_token = tok.security_token;
        log.info("[115open] OSS 临时凭证已刷新", .{});
    }

    /// 分片大小。与 Go 的 `calPartSize` 逐档一致 —— 那些魔数（109951163 等）
    /// 是为了让 1 TB 文件正好切成 10000 片以内，不能改成"好看的"取整值。
    fn calPartSize(file_size: i64) i64 {
        var part: i64 = 20 * mb;
        if (file_size > part) {
            if (file_size > 1 * tb) {
                part = 5 * gb;
            } else if (file_size > 768 * gb) {
                part = 109951163;
            } else if (file_size > 512 * gb) {
                part = 82463373;
            } else if (file_size > 384 * gb) {
                part = 54975582;
            } else if (file_size > 256 * gb) {
                part = 41231687;
            } else if (file_size > 128 * gb) {
                part = 27487791;
            }
        }
        return part;
    }

    /// OSS 分片上传。串行（Go 版也是串行）。
    fn ossMultipartUpload(
        self: *Open115,
        arena: std.mem.Allocator,
        creds: *OssCreds,
        src: model.Source,
        file_size: i64,
        init_resp: UploadInit,
    ) !void {
        const part_size = calPartSize(file_size);
        const part_num: u64 = @intCast(@divTrunc(file_size + part_size - 1, part_size));

        // 回调配置是 base64 过的 JSON，必须原样回送，否则 OSS 写完了对象但
        // 115 不会建文件记录。
        const callback_b64 = try hash.base64Std(arena, init_resp.callback);
        const callback_var_b64 = try hash.base64Std(arena, init_resp.callback_var);

        const mpu = ossInitiate(self, arena, creds, init_resp.object, "application/octet-stream") catch |e| blk: {
            if (e != Error.OssTokenExpired) return e;
            try self.refreshOssCreds(arena, creds);
            break :blk try ossInitiate(self, arena, creds, init_resp.object, "application/octet-stream");
        };

        const etags = try arena.alloc([]const u8, @intCast(part_num));
        var offset: u64 = 0;
        var i: u64 = 1;
        while (i <= part_num) : (i += 1) {
            const this_len: u64 = if (i == part_num)
                @as(u64, @intCast(file_size)) - (i - 1) * @as(u64, @intCast(part_size))
            else
                @intCast(part_size);

            // 用窗口而不是把整片读进内存：光猫只有 128 MiB，20 MiB 的片
            // 再乘上 HTTP 层自己的缓冲就太挤了。
            var win = WindowSource{ .inner = src, .base = offset, .len = this_len };
            const etag = while (true) {
                const r = ossUploadPart(self, arena, creds, mpu.key, mpu.upload_id, i, win.source(), this_len);
                if (r) |ok| break ok else |e| {
                    if (e != Error.OssTokenExpired) return e;
                    try self.refreshOssCreds(arena, creds);
                }
            };
            etags[@intCast(i - 1)] = etag;
            offset += this_len;
        }

        while (true) {
            const r = ossComplete(self, arena, creds, mpu.key, mpu.upload_id, etags, callback_b64, callback_var_b64);
            if (r) |_| break else |e| {
                if (e != Error.OssTokenExpired) return e;
                try self.refreshOssCreds(arena, creds);
            }
        }
        log.info("[115open] 分片上传完成: {d} 片，{d} 字节", .{ part_num, file_size });
    }

    /// `sign_check` 形如 `"2392148-2392298"`，两端**都包含**。
    /// 解析实现在文件末尾的顶层 `parseSignCheck`。

    /// 一段区间的 SHA1，**大写十六进制**（顶层 `sha1UpperOfRange`）。

    // -----------------------------------------------------------------------
    // vtable 实现
    // -----------------------------------------------------------------------

    /// 逐级列目录把路径解析成 fid。根路径直接返回 `root_folder_id`。
    fn resolveEntry(self: *Open115, arena: std.mem.Allocator, path: []const u8) !Entry {
        var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
        var it = std.mem.tokenizeAny(u8, path, "/\\");
        while (it.next()) |seg| {
            cur = try self.findChild(arena, cur.id, seg);
        }
        return cur;
    }

    fn findChild(self: *Open115, arena: std.mem.Allocator, parent_id: []const u8, name: []const u8) !Entry {
        var offset: i64 = 0;
        while (true) {
            const page = try self.listPage(arena, parent_id, offset);
            // 索引而不是 `for (page.items) |item|`：后者拿到的是副本，
            // 返回 `&item` 会悬垂。这里虽然只读标量，但保持同一个写法免得
            // 以后加字段时踩坑。
            for (page.items, 0..) |_, i| {
                const item = &page.items[i];
                const fn_ = item.strAt("fn") orelse continue;
                if (!std.mem.eql(u8, fn_, name)) continue;
                if (item.strAt("fid") == null) return Error.InvalidResponse;
                return entryFromRecord(item, parent_id);
            }
            if (page.items.len == 0) return driver.Error.NotFound;
            offset += self.cfg.page_size;
            if (@as(i64, @intCast(offset)) >= page.count) return driver.Error.NotFound;
        }
    }

    /// 解析路径：优先一次 `folder/get_info`（by path），失败再退化成逐级列目录。
    ///
    /// Go 版能免掉这一步是因为 OpenList 内核把带 ID 的 `model.Obj` 缓存下来了；
    /// 本工程的 vtable 只收路径（见 `driver.zig`）。
    fn resolve(self: *Open115, arena: std.mem.Allocator, path: []const u8) !Entry {
        const trimmed = std.mem.trim(u8, path, "/\\");
        if (trimmed.len == 0) {
            const fi = try self.folderInfo(arena, self.cfg.root_folder_id);
            return entryFromFolderInfo(fi, "/");
        }

        const full = try joinClean(arena, &.{ self.parent_path, path });
        if (self.folderInfoByPath(arena, full)) |fi| {
            const is_dir = std.mem.eql(u8, fi.file_category, "0");
            const mtime = parseTime(fi.utime);
            // 115 对"路径存在但不是目录"有时会回一个不含 utime 的壳，
            // 这种就落到下面的逐级列目录去拿完整记录（Go 的 getFromParent）。
            if (is_dir or mtime > 0) return entryFromFolderInfo(fi, urlmod.baseName(path));
        } else |e| {
            if (e != driver.Error.NotFound) return e;
        }
        return self.resolveEntry(arena, path);
    }

    fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(ptr);
        const a = ctx.alloc;

        const e = try self.resolveEntry(a, dir);
        if (!e.is_dir) return driver.Error.NotFound;

        var out = List(model.Obj).init(a);
        var offset: i64 = 0;
        while (true) {
            const page = try self.listPage(a, e.id, offset);
            for (page.items, 0..) |_, i| {
                try out.append(objFromRecord(&page.items[i]));
            }
            // 空页直接收手。Go 版只看 `len(res) >= count`，遇到 count 虚高
            // 会死循环 —— 加这一条既更安全，也不改变正常路径的行为。
            if (page.items.len == 0) break;
            if (@as(i64, @intCast(out.len)) >= page.count) break;
            offset += self.cfg.page_size;
        }
        return out.toOwned();
    }

    fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(ptr);
        const a = ctx.alloc;
        const e = try self.resolve(a, path);
        return .{
            .name = e.name,
            .size = e.size,
            .is_dir = e.is_dir,
            .modified = e.modified,
            .created = e.created,
            .sign = e.id,
            .thumb = e.thumb,
            .hash_info = if (e.sha1.len > 0)
                model.HashInfo{ .hash_name = "sha1", .hash_value = e.sha1 }
            else
                null,
        };
    }

    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: model.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;

        const ua = headerValue(args.headers, "User-Agent") orelse download_user_agent;
        const e = try self.resolve(a, path);
        if (e.pick_code.len == 0) return driver.Error.NotFound;

        const url = try self.downUrl(a, e.id, e.pick_code, ua);
        if (url.len == 0) return driver.Error.NotFound;
        // `header` 必须由 ctx.alloc 持有：写成 `&.{.{...}}` 会返回栈上临时量
        // 的切片，函数返回即悬空（115 的下游拿不到 UA → CDN 拒绝下载）。
        const hdrs = try a.alloc(model.Header, 1);
        hdrs[0] = .{ .name = "User-Agent", .value = ua };
        return .{ .url = url, .header = hdrs };
    }

    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = urlmod.baseName(dir);
        if (name.len == 0) return Error.InvalidPath;
        const parent = try self.resolveEntry(a, urlmod.parentPath(dir));
        if (!parent.is_dir) return driver.Error.NotFound;
        try self.mkdir(a, parent.id, name);
    }

    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const s = try self.resolveEntry(a, src);
        const d = try self.resolveEntry(a, dst_dir);
        try self.apiMove(a, s.id, d.id);
    }

    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        if (new_name.len == 0) return Error.InvalidPath;
        if (std.mem.indexOfAny(u8, new_name, "/\\") != null) return Error.InvalidPath;
        const s = try self.resolveEntry(a, src);
        try self.updateFile(a, s.id, new_name);
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = is_dir; // 115 的删除接口对文件和目录是同一个

        const s = try self.resolveEntry(a, path);
        if (std.mem.eql(u8, s.id, self.cfg.root_folder_id)) return Error.InvalidPath;
        if (s.pid.len == 0) return driver.Error.NotFound;
        try self.delFile(a, s.id, s.pid);
    }

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;

        const name = urlmod.baseName(dst);
        if (name.len == 0) return Error.InvalidPath;

        const target = try self.resolveEntry(a, urlmod.parentPath(dst));
        if (!target.is_dir) return driver.Error.NotFound;

        const size = src.size();
        if (size < 0) return Error.InvalidPath;

        // 1. 整文件 SHA1（大写）与 2. 前 128 KiB 的 SHA1（大写）。
        //    本工程的 `model.Source` 不带哈希，所以这里必须自己过一遍；
        //    Go 版能从上层缓存里拿到已经算好的值。
        const total: u64 = @intCast(size);
        const file_id = try sha1UpperOfRange(a, src, 0, total);
        const pre_len: u64 = @intCast(@min(pre_hash_size, size));
        const pre_id = try sha1UpperOfRange(a, src, 0, pre_len);

        var init_resp = try self.uploadInit(a, .{
            .file_name = name,
            .file_size = size,
            .target = target.id,
            .file_id = file_id,
            .pre_id = pre_id,
        });

        // status 2 = 秒传命中。
        if (init_resp.status == 2) {
            log.info("[115open] {s}: 秒传命中", .{name});
            return;
        }

        // status 6/7/8 = 双向校验：服务端点名一段区间，要它的 SHA1。
        if (init_resp.status == 6 or init_resp.status == 7 or init_resp.status == 8) {
            const range = try parseSignCheck(init_resp.sign_check);
            if (range.start >= total or range.len > total - range.start) return Error.BadSignCheck;
            const sign_val = try sha1UpperOfRange(a, src, range.start, range.len);
            init_resp = try self.uploadInit(a, .{
                .file_name = name,
                .file_size = size,
                .target = target.id,
                .file_id = file_id,
                .pre_id = pre_id,
                .sign_key = init_resp.sign_key,
                .sign_val = sign_val,
            });
            if (init_resp.status == 2) {
                log.info("[115open] {s}: 双向校验后秒传命中", .{name});
                return;
            }
        }

        // 3. 换 OSS 临时凭证，4. 分片上传。
        const tok = try self.uploadToken(a);
        const ep = parseEndpoint(tok.endpoint);
        var creds = OssCreds{
            .scheme = ep.scheme,
            .host = ep.host,
            .bucket = init_resp.bucket,
            .access_key_id = tok.access_key_id,
            .access_key_secret = tok.access_key_secret,
            .security_token = tok.security_token,
        };
        try self.ossMultipartUpload(a, &creds, src, size, init_resp);
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(ptr);
        const a = ctx.alloc;
        const info = try self.userInfo(a);
        return .{ .total = info.total, .used = info.used };
    }

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
};

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// `{state: bool, code: int64, message, data}`。
///
/// `state` 在开放平台是 bool，在通行证接口是 int —— 两种都认，因为
/// `refreshToken` 走的是通行证。
const Envelope = struct {
    state: bool,
    code: i64,
    message: []const u8,
    data: ?*const json.Value,
};

fn parseEnvelope(v: *const json.Value) Envelope {
    var state = false;
    if (v.getPath("state")) |s| {
        if (s.asBool()) |b| state = b else if (s.asInt()) |i| {
            state = i != 0;
        }
    }
    return .{
        .state = state,
        .code = v.intAt("code") orelse 0,
        .message = v.strAt("message") orelse "",
        .data = v.getPath("data"),
    };
}

/// `Is401Started`：把 code 写成十进制字符串后看是否以 "401" 开头。
/// 115 用这一族码表示各种 token 失效（401、4010101、…）。
fn is401Started(code: i64) bool {
    var tmp: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{code}) catch return false;
    return std.mem.startsWith(u8, s, "401");
}

/// 把 `folder/get_info` 的 body 解成 `FolderInfo`。
///
/// `data` 是数组时取第一个，空数组等价于"不存在"（SDK 的 `UnmarshalJSON`
/// 就是这么写的，也是 115 表达 not-found 的方式之一）。
fn parseFolderInfoBody(arena: std.mem.Allocator, body: []const u8) !FolderInfo {
    const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
    const data = v.getPath("data") orelse return driver.Error.NotFound;

    var d: *const json.Value = data;
    if (data.asArray()) |arr| {
        if (arr.len == 0) return driver.Error.NotFound;
        d = &arr[0];
    }
    if (d.asObject() == null) return Error.InvalidResponse;

    var fi = FolderInfo{
        .file_id = d.strAt("file_id") orelse "",
        .file_name = d.strAt("file_name") orelse "",
        .file_category = d.strAt("file_category") orelse "",
        .sha1 = d.strAt("sha1") orelse "",
        .pick_code = d.strAt("pick_code") orelse "",
        .utime = d.strAt("utime") orelse "",
        .ptime = d.strAt("ptime") orelse "",
    };
    if (d.getPath("size_byte")) |p| fi.size_byte = parseInt64Flex(p);

    if (d.getPath("paths")) |p| {
        if (p.asArray()) |arr| {
            const items = try arena.alloc(FolderInfo.PathItem, arr.len);
            for (arr, 0..) |_, i| {
                items[i] = .{
                    .file_id = arr[i].strAt("file_id") orelse "",
                    .file_name = arr[i].strAt("file_name") orelse "",
                };
            }
            fi.paths = items;
        }
    }
    return fi;
}

/// `sign_check` 形如 `"2392148-2392298"`，两端**都包含**。
const SignRange = struct { start: u64, len: u64 };

fn parseSignCheck(s: []const u8) !SignRange {
    const dash = std.mem.indexOfScalar(u8, s, '-') orelse return Error.BadSignCheck;
    const start = std.fmt.parseInt(u64, s[0..dash], 10) catch return Error.BadSignCheck;
    const end = std.fmt.parseInt(u64, s[dash + 1 ..], 10) catch return Error.BadSignCheck;
    if (end < start) return Error.BadSignCheck;
    return .{ .start = start, .len = end - start + 1 };
}

/// 一段区间的 SHA1，**大写十六进制**。
///
/// 115 的 `fileid`（整文件）和 `preid`（前 128 KiB）以及双向校验的 `sign_val`
/// 全都要大写十六进制 —— 小写会被服务端当成不匹配。
fn sha1UpperOfRange(
    alloc: std.mem.Allocator,
    src: model.Source,
    offset: u64,
    len: u64,
) ![]u8 {
    var h = hash.Sha1Stream{};
    const buf = try alloc.alloc(u8, hash_block);
    var done: u64 = 0;
    while (done < len) {
        const want: usize = @intCast(@min(@as(u64, hash_block), len - done));
        const n = try src.readAt(offset + done, buf[0..want]);
        if (n == 0) return error.UnexpectedEof;
        h.update(buf[0..n]);
        done += n;
    }
    return hash.hexUpper(alloc, &h.final());
}

/// `source` 的一个字节窗口。分片上传要按 offset 切片，但 `model.Source`
/// 只有整文件视角，所以在外面套一层而不是把 20 MiB 读进内存。
const WindowSource = struct {
    inner: model.Source,
    base: u64,
    len: u64,

    const vtable = model.Source.VTable{ .size = sizeFn, .readAt = readAtFn };

    fn sizeFn(ptr: *anyopaque) i64 {
        const self: *WindowSource = @ptrCast(@alignCast(ptr));
        return @intCast(self.len);
    }

    fn readAtFn(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
        const self: *WindowSource = @ptrCast(@alignCast(ptr));
        if (offset >= self.len) return 0;
        const want = @min(@as(u64, buf.len), self.len - offset);
        return self.inner.readAt(self.base + offset, buf[0..@intCast(want)]);
    }

    fn source(self: *WindowSource) model.Source {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

fn headerValue(headers: []const model.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Go 的 `path.Join`：用 `/` 拼起来再 clean。
fn joinClean(alloc: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var b = Buf.init(alloc);
    defer b.deinit();
    for (parts) |p| {
        try b.appendByte('/');
        try b.append(p);
    }
    return urlmod.cleanPath(alloc, b.slice());
}

/// 把 `folder/get_info` 的 `paths`（自底向上的祖先链）反着拼成挂载根的
/// 绝对路径 —— 对应 Go 版 `Init` 里那段 `slices.Reverse` 循环。
fn buildParentPath(alloc: std.mem.Allocator, fi: FolderInfo) ![]const u8 {
    var path: []const u8 = "/";
    if (!std.mem.eql(u8, fi.file_id, default_root)) {
        path = try joinClean(alloc, &.{fi.file_name});
    }
    var i = fi.paths.len;
    while (i > 0) {
        i -= 1;
        const p = fi.paths[i];
        if (std.mem.eql(u8, p.file_id, default_root)) {
            path = try joinClean(alloc, &.{path});
        } else {
            path = try joinClean(alloc, &.{ p.file_name, path });
        }
    }
    return path;
}

/// 从 `ufile/files` 的记录构造 `Entry`。
fn entryFromRecord(v: *const json.Value, parent_id: []const u8) Entry {
    const fc = v.strAt("fc") orelse "";
    return .{
        .id = v.strAt("fid") orelse "",
        .pid = parent_id,
        .name = v.strAt("fn") orelse "",
        .is_dir = std.mem.eql(u8, fc, "0"),
        .size = v.intAt("fs") orelse 0,
        .modified = v.intAt("upt") orelse 0,
        .created = v.intAt("uppt") orelse 0,
        .sha1 = v.strAt("sha1") orelse "",
        .thumb = v.strAt("thumb") orelse "",
        .pick_code = v.strAt("pc") orelse "",
    };
}

fn entryFromFolderInfo(fi: FolderInfo, fallback_name: []const u8) Entry {
    const is_dir = std.mem.eql(u8, fi.file_category, "0");
    return .{
        .id = fi.file_id,
        .name = if (fi.file_name.len > 0) fi.file_name else fallback_name,
        .is_dir = is_dir,
        .size = fi.size_byte,
        .modified = parseTime(fi.utime),
        .created = parseTime(fi.ptime),
        .sha1 = fi.sha1,
        .pick_code = fi.pick_code,
    };
}

fn objFromRecord(v: *const json.Value) model.Obj {
    const sha1 = v.strAt("sha1") orelse "";
    return .{
        .name = v.strAt("fn") orelse "",
        .size = v.intAt("fs") orelse 0,
        .is_dir = std.mem.eql(u8, v.strAt("fc") orelse "", "0"),
        .modified = v.intAt("upt") orelse 0,
        .created = v.intAt("uppt") orelse 0,
        .sign = v.strAt("fid") orelse "",
        .thumb = v.strAt("thumb") orelse "",
        .hash_info = if (sha1.len > 0)
            model.HashInfo{ .hash_name = "sha1", .hash_value = sha1 }
        else
            null,
    };
}

/// 每个 API 端点的最小请求间隔限速器。理由见 `123open.zig` 的同名类型。
const RateLimiter = struct {
    qps: u32 = 0,
    last_ms: i64 = 0,
    mu: std.Io.Mutex = .init,

    fn minIntervalMs(qps: u32) i64 {
        if (qps == 0) return 0;
        return @divTrunc(999 + @as(i64, qps), @as(i64, qps));
    }

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

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "115 Open",
    .label = "115 开放平台",
    .secrets = &.{ "AccessToken", "RefreshToken" },
    // 字段名与 Go 版 `Addition` 的 json tag 逐字一致。
    .addition_schema =
    \\{
    \\  "root_folder_id": {"type":"string","default":"0","help":"根目录 ID，115 的账号根是 0"},
    \\  "order_by":       {"type":"select","options":"file_name,file_size,user_utime,file_type","default":"file_name","help":"列表排序字段"},
    \\  "order_direction":{"type":"select","options":"asc,desc","default":"asc","help":"排序方向"},
    \\  "limit_rate":     {"type":"float","default":1,"help":"API 请求速率上限（次/秒）"},
    \\  "page_size":      {"type":"number","default":200,"min":1,"max":1150,"help":"列表每页条数"},
    \\  "AccessToken":    {"type":"string","required":false,"secret":true,"help":"access_token；与 RefreshToken 至少填一个"},
    \\  "RefreshToken":   {"type":"string","required":false,"secret":true,"help":"refresh_token，过期时自动续期并回写"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try createWithId(alloc, storage_id, cfg);
    return driver.asDriver(Open115, self);
}

/// 带 storage id 的入口，供 API 层在配置变化时回写 `addition`。
pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Open115 {
    const self = try alloc.create(Open115);
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

    const src = try json.parse(a,
        \\{"root_folder_id":"12345","order_by":"file_size","order_direction":"desc",
        \\ "limit_rate":2,"page_size":300,"access_token":"AT","refresh_token":"RT"}
    );
    const cfg = try Addition.parse(a, &src);
    try testing.expectEqualStrings("12345", cfg.root_folder_id);
    try testing.expectEqualStrings("file_size", cfg.order_by);
    try testing.expectEqualStrings("desc", cfg.order_direction);
    try testing.expectEqual(@as(f64, 2), cfg.limit_rate);
    try testing.expectEqual(@as(i64, 300), cfg.page_size);
    try testing.expectEqualStrings("AT", cfg.access_token);
    try testing.expectEqualStrings("RT", cfg.refresh_token);
    try testing.expect(!cfg.ascending());

    const text = try cfg.toJson(a);
    const back = try json.parse(a, text);
    const cfg2 = try Addition.parse(a, &back);
    try testing.expectEqualStrings(cfg.root_folder_id, cfg2.root_folder_id);
    try testing.expectEqualStrings(cfg.order_direction, cfg2.order_direction);
    try testing.expectEqual(cfg.page_size, cfg2.page_size);
    try testing.expectEqual(cfg.limit_rate, cfg2.limit_rate);
}

test "addition defaults and tolerates a missing object" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const empty = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", empty.root_folder_id);
    try testing.expectEqualStrings("file_name", empty.order_by);
    try testing.expectEqualStrings("asc", empty.order_direction);
    try testing.expect(empty.ascending());
    try testing.expectEqual(@as(i64, 200), empty.page_size);
    try testing.expectEqual(@as(f64, 1), empty.limit_rate);

    // `limit_rate` 是 float 字段，但用户可能写成整数。
    // `page_size` 用字符串写也能认 —— `json.Value.asInt()` 对数字字符串是宽松的
    // （见 `util/json.zig` 的 "lenient int from string" 用例），这对配置文件
    // 手写场景是好事。
    const intish = try json.parse(a, "{\"limit_rate\":3,\"page_size\":\"500\"}");
    const cfg = try Addition.parse(a, &intish);
    try testing.expectEqual(@as(f64, 3), cfg.limit_rate);
    try testing.expectEqual(@as(i64, 500), cfg.page_size);

    // 真的不是数字时保持默认，而不是崩掉。
    const junk = try json.parse(a, "{\"page_size\":\"lots\",\"limit_rate\":\"fast\"}");
    const cfg2 = try Addition.parse(a, &junk);
    try testing.expectEqual(@as(i64, 200), cfg2.page_size);
    try testing.expectEqual(@as(f64, 1), cfg2.limit_rate);
}

// 日期格式化本身在 `util/time.zig` 里测（那里还有 `formatIsoMillisZ`）。
// 这里只确认本驱动确实用的是那一份，而不是自己又抄了一个。
test "the OSS Date header comes from util/time.zig" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var b = Buf.init(a);
    try timeutil.formatHttpDate(&b, 1_791_604_800);
    try testing.expectEqualStrings("Sat, 10 Oct 2026 04:00:00 GMT", b.slice());
    // 形状必须严格符合 IMF-fixdate（RFC 7231 §7.1.1.1），否则 OSS 会因为
    // Date 不可解析而拒绝整个请求。0.17 的 `std.http.Header` 只是
    // `{name, value}`，没有日期解析器，所以这里逐段核形状。
    const s = b.slice();
    try testing.expectEqual(@as(usize, 29), s.len);
    try testing.expectEqualStrings("GMT", s[26..29]);
    try testing.expectEqual(@as(u8, ','), s[3]);
    try testing.expectEqual(@as(u8, ' '), s[4]);
    try testing.expect(std.ascii.isDigit(s[5]) and std.ascii.isDigit(s[6]));
    try testing.expectEqual(@as(u8, ' '), s[7]);
    try testing.expect(std.ascii.isDigit(s[17]) and std.ascii.isDigit(s[18]));
}

test "signV1 reproduces the OSS V1 HMAC-SHA1 signature" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 三个向量都是用 Python 的 hmac/hashlib 独立算出来的。
    // 1) UploadPart：无 Content-Type，只有 security-token
    try testing.expectEqualStrings("GVqKv6pHl0V0EQcDp8ZdzuMlMRk=", try signV1(
        a,
        "PUT",
        "",
        "",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "x-oss-security-token:STS123\n",
        "/mybucket/path/to/obj?partNumber=1&uploadId=UP1",
        "SECRETKEY",
    ));

    // 2) InitiateMultipartUpload：带 Content-Type，subresource 是两个裸键
    try testing.expectEqualStrings("iEaWdDirdBHwjYw3U2xYpVzEIk8=", try signV1(
        a,
        "POST",
        "",
        "application/octet-stream",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "x-oss-security-token:STS123\n",
        "/mybucket/path/to/obj?sequential&uploads",
        "SECRETKEY",
    ));

    // 3) CompleteMultipartUpload：三个 x-oss-* 头，按字节序排列
    try testing.expectEqualStrings("Dq9rspqGQ49K3MnZClxIdK/BIfc=", try signV1(
        a,
        "POST",
        "",
        "",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "x-oss-callback:eyJjIjoiMSJ9\nx-oss-callback-var:eyJ2IjoiMiJ9\nx-oss-security-token:STS123\n",
        "/mybucket/path/to/obj?uploadId=UP1",
        "SECRETKEY",
    ));

    // 秘密变了签名必须变 —— 这条能挡住"把 secret 忘了"的回归。
    try testing.expect(!std.mem.eql(u8, try signV1(
        a, "PUT", "", "", "Thu, 01 Jan 1970 00:00:00 GMT", "", "/b/o", "OTHER",
    ), try signV1(
        a, "PUT", "", "", "Thu, 01 Jan 1970 00:00:00 GMT", "", "/b/o", "SECRETKEY",
    )));
}

test "oss header sorting is byte order and only x-oss-* participates" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var hs = List(model.Header).init(a);
    try hs.append(.{ .name = "x-oss-security-token", .value = "T" });
    try hs.append(.{ .name = "x-oss-callback", .value = "C" });
    try hs.append(.{ .name = "x-oss-callback-var", .value = "V" });
    std.mem.sort(model.Header, hs.sliceMut(), {}, lessHeader);

    var canon = Buf.init(a);
    for (hs.slice()) |h| try canon.print("{s}:{s}\n", .{ h.name, h.value });
    try testing.expectEqualStrings(
        "x-oss-callback:C\nx-oss-callback-var:V\nx-oss-security-token:T\n",
        canon.slice(),
    );
}

test "parseEndpoint mirrors the SDK's scheme default" {
    // 有 scheme 就用它
    try testing.expectEqualStrings("https", parseEndpoint("https://oss-cn-shenzhen.aliyuncs.com").scheme);
    try testing.expectEqualStrings("oss-cn-shenzhen.aliyuncs.com", parseEndpoint("https://oss-cn-shenzhen.aliyuncs.com").host);
    try testing.expectEqualStrings("http", parseEndpoint("http://oss.example.com").scheme);
    // 没有 scheme 时 SDK 默认 **http**（不是 https）
    const bare = parseEndpoint("oss-cn-shenzhen.aliyuncs.com");
    try testing.expectEqualStrings("http", bare.scheme);
    try testing.expectEqualStrings("oss-cn-shenzhen.aliyuncs.com", bare.host);
    // 尾斜杠要剥掉，否则会拼出 `bucket.host/`
    try testing.expectEqualStrings("oss.example.com", parseEndpoint("https://oss.example.com/").host);
}

test "calPartSize thresholds match the upstream ladder" {
    try testing.expectEqual(@as(i64, 20 * mb), Open115.calPartSize(0));
    try testing.expectEqual(@as(i64, 20 * mb), Open115.calPartSize(20 * mb));
    try testing.expectEqual(@as(i64, 20 * mb), Open115.calPartSize(100 * mb));
    // 一过 20 MiB 就进入阶梯，但 128 GiB 以下仍是 20 MiB
    try testing.expectEqual(@as(i64, 20 * mb), Open115.calPartSize(128 * gb));
    try testing.expectEqual(@as(i64, 27487791), Open115.calPartSize(128 * gb + 1));
    try testing.expectEqual(@as(i64, 41231687), Open115.calPartSize(300 * gb));
    try testing.expectEqual(@as(i64, 54975582), Open115.calPartSize(400 * gb));
    try testing.expectEqual(@as(i64, 82463373), Open115.calPartSize(600 * gb));
    try testing.expectEqual(@as(i64, 109951163), Open115.calPartSize(800 * gb));
    try testing.expectEqual(@as(i64, 5 * gb), Open115.calPartSize(2 * tb));
}

test "parseSignCheck handles the inclusive range form" {
    const r = try parseSignCheck("2392148-2392298");
    try testing.expectEqual(@as(u64, 2392148), r.start);
    try testing.expectEqual(@as(u64, 151), r.len); // 2392298 - 2392148 + 1

    const one = try parseSignCheck("10-10");
    try testing.expectEqual(@as(u64, 1), one.len);

    try testing.expectError(Error.BadSignCheck, parseSignCheck("nope"));
    try testing.expectError(Error.BadSignCheck, parseSignCheck("10-"));
    try testing.expectError(Error.BadSignCheck, parseSignCheck("20-10"));
}

test "sha1UpperOfRange hashes a window and upper-cases the hex" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const BufSource = struct {
        data: []const u8,
        fn size(ptr: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return @intCast(self.data.len);
        }
        fn readAt(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (offset >= self.data.len) return 0;
            const n = @min(buf.len, self.data.len - @as(usize, @intCast(offset)));
            @memcpy(buf[0..n], self.data[@intCast(offset)..][0..n]);
            return n;
        }
        const vtable = model.Source.VTable{ .size = size, .readAt = readAt };
    };

    var s = BufSource{ .data = "hello" };
    const src = model.Source{ .ptr = &s, .vtable = &BufSource.vtable };

    // sha1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    try testing.expectEqualStrings(
        "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D",
        try sha1UpperOfRange(a, src, 0, 5),
    );
    // 窗口 `ell` 的 SHA1，独立算过
    try testing.expectEqualStrings("D027B4C247E6911AC060B71F7A4979B6E52E773B", try sha1UpperOfRange(a, src, 1, 3));
    // 空窗口 = sha1("")
    try testing.expectEqualStrings(
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
        try sha1UpperOfRange(a, src, 0, 0),
    );
}

test "writeXmlText escapes the way encoding/xml does" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var b = Buf.init(a);
    // ETag 自带引号 —— Go 会写成 &#34;，OSS 解回来仍是带引号的字符串。
    try writeXmlText(&b, "\"abc\"");
    try testing.expectEqualStrings("&#34;abc&#34;", b.slice());

    var b2 = Buf.init(a);
    try writeXmlText(&b2, "a&b<c>d");
    try testing.expectEqualStrings("a&amp;b&lt;c&gt;d", b2.slice());
}

test "buildCompleteXml emits one Part per etag in order" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    var b = Buf.init(a);
    try buildCompleteXml(&b, &.{ "\"e1\"", "\"e2\"" });
    try testing.expectEqualStrings(
        "<CompleteMultipartUpload>" ++
            "<Part><PartNumber>1</PartNumber><ETag>&#34;e1&#34;</ETag></Part>" ++
            "<Part><PartNumber>2</PartNumber><ETag>&#34;e2&#34;</ETag></Part>" ++
            "</CompleteMultipartUpload>",
        b.slice(),
    );
}

test "parseEnvelope accepts both bool and int state" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 开放平台：state 是 bool
    const open = try json.parse(a, "{\"state\":true,\"code\":0,\"data\":{\"a\":1}}");
    const e1 = parseEnvelope(&open);
    try testing.expect(e1.state);
    try testing.expectEqual(@as(i64, 0), e1.code);
    try testing.expect(e1.data != null);

    // 通行证：state 是 int
    const passport = try json.parse(a, "{\"state\":1,\"code\":0,\"data\":{}}");
    try testing.expect(parseEnvelope(&passport).state);

    const bad = try json.parse(a, "{\"state\":false,\"code\":4010101,\"message\":\"登录失效\"}");
    const e3 = parseEnvelope(&bad);
    try testing.expect(!e3.state);
    try testing.expectEqual(@as(i64, 4010101), e3.code);
    try testing.expectEqualStrings("登录失效", e3.message);
}

test "is401Started matches the 401 code family" {
    try testing.expect(is401Started(401));
    try testing.expect(is401Started(4010101));
    try testing.expect(is401Started(4010));
    try testing.expect(!is401Started(99));
    try testing.expect(!is401Started(0));
    try testing.expect(!is401Started(430004));
    try testing.expect(!is401Started(1401));
}

test "parseInt64Flex accepts numbers and numeric strings" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const n = try json.parse(a, "{\"a\":123,\"b\":\"456\",\"c\":1.5}");
    try testing.expectEqual(@as(i64, 123), parseInt64Flex(n.getPath("a").?));
    try testing.expectEqual(@as(i64, 456), parseInt64Flex(n.getPath("b").?));
    try testing.expectEqual(@as(i64, 1), parseInt64Flex(n.getPath("c").?));
}

test "parseFolderInfo handles object, array and empty array" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const obj = try json.parse(a,
        \\{"state":true,"data":{"file_id":"f1","file_name":"movies","file_category":"0",
        \\ "size_byte":123,"utime":"1791608400","ptime":"1791604800",
        \\ "paths":[{"file_id":"root","file_name":"/"},{"file_id":"p1","file_name":"video"}]}}
    );
    const fi = try parseFolderInfoBody(a, try json.stringify(a, &obj));
    try testing.expectEqualStrings("f1", fi.file_id);
    try testing.expectEqualStrings("movies", fi.file_name);
    try testing.expectEqual(@as(i64, 1_791_608_400), parseTime(fi.utime));
    try testing.expectEqual(@as(usize, 2), fi.paths.len);
    try testing.expectEqualStrings("video", fi.paths[1].file_name);

    // 数组形状：取第一个
    const arr = try json.parse(a, "{\"state\":true,\"data\":[{\"file_id\":\"f2\",\"file_name\":\"a.mp4\",\"file_category\":\"1\"}]}");
    const fi2 = try parseFolderInfoBody(a, try json.stringify(a, &arr));
    try testing.expectEqualStrings("f2", fi2.file_id);
    try testing.expect(!std.mem.eql(u8, fi2.file_category, "0"));

    // 空数组 = 不存在（SDK 的 UnmarshalJSON 也是这么判的）
    const empty = try json.parse(a, "{\"state\":true,\"data\":[]}");
    try testing.expectError(driver.Error.NotFound, parseFolderInfoBody(a, try json.stringify(a, &empty)));
}

test "objFromRecord maps the 115 file record" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const dir = try json.parse(a,
        \\{"fid":"d1","pid":"0","fc":"0","fn":"movies","fs":0,
        \\ "upt":1791608400,"uppt":1791604800,"pc":""}
    );
    const d = objFromRecord(&dir);
    try testing.expectEqualStrings("movies", d.name);
    try testing.expect(d.is_dir);
    try testing.expectEqual(@as(i64, 1_791_608_400), d.modified);
    try testing.expectEqual(@as(i64, 1_791_604_800), d.created);
    try testing.expect(d.hash_info == null);

    const file = try json.parse(a,
        \\{"fid":"f1","pid":"d1","fc":"1","fn":"a.mp4","fs":12345,
        \\ "upt":1791608400,"uppt":1791604800,"sha1":"ABC","thumb":"https://t/x.jpg","pc":"PC1"}
    );
    const f = objFromRecord(&file);
    try testing.expect(!f.is_dir);
    try testing.expectEqual(@as(i64, 12345), f.size);
    try testing.expectEqualStrings("f1", f.sign);
    try testing.expectEqualStrings("https://t/x.jpg", f.thumb);
    try testing.expectEqualStrings("ABC", f.hash_info.?.hash_value);
    try testing.expectEqualStrings("sha1", f.hash_info.?.hash_name);

    // 列表记录里的 pick_code 在 `pc` 字段
    const e = entryFromRecord(&file, "d1");
    try testing.expectEqualStrings("PC1", e.pick_code);
    try testing.expectEqualStrings("d1", e.pid);
}

test "buildParentPath reverses the ancestor chain and drops the account root" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 挂载根就是账号根 → "/"
    const at_root = try buildParentPath(a, .{ .file_id = "0", .file_name = "根目录" });
    try testing.expectEqualStrings("/", at_root);

    // /a/b/c 下的挂载点。`paths` 是**自顶向下**的祖先链（账号根 → a → b），
    // Go 版 `slices.Reverse` 之后从最靠近自己的祖先开始往前拼，所以顺序不能反。
    const fi = FolderInfo{
        .file_id = "fid_c",
        .file_name = "c",
        .paths = &.{
            .{ .file_id = "0", .file_name = "根目录" },
            .{ .file_id = "fid_a", .file_name = "a" },
            .{ .file_id = "fid_b", .file_name = "b" },
        },
    };
    try testing.expectEqualStrings("/a/b/c", try buildParentPath(a, fi));

    // 顺序反过来会拼出 /b/a/c —— 这正是上面那条注释想挡住的错误。
    const reversed = FolderInfo{
        .file_id = "fid_c",
        .file_name = "c",
        .paths = &.{
            .{ .file_id = "fid_b", .file_name = "b" },
            .{ .file_id = "fid_a", .file_name = "a" },
            .{ .file_id = "0", .file_name = "根目录" },
        },
    };
    try testing.expectEqualStrings("/b/a/c", try buildParentPath(a, reversed));
}

test "joinClean mirrors Go's path.Join" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("/a/b", try joinClean(a, &.{ "a", "b" }));
    try testing.expectEqualStrings("/a/b", try joinClean(a, &.{ "/a/", "/b" }));
    try testing.expectEqualStrings("/a/b", try joinClean(a, &.{ "a", ".", "b" }));
    try testing.expectEqualStrings("/b", try joinClean(a, &.{ "a", "..", "b" }));
    try testing.expectEqualStrings("/", try joinClean(a, &.{"/"}));
    // 挂载根 + 相对路径（details/link 的主用法）
    try testing.expectEqualStrings("/a/b/x.mp4", try joinClean(a, &.{ "/a/b", "x.mp4" }));
}

test "WindowSource reads a sub-range of the underlying source" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const BufSource = struct {
        data: []const u8,
        fn size(ptr: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return @intCast(self.data.len);
        }
        fn readAt(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (offset >= self.data.len) return 0;
            const n = @min(buf.len, self.data.len - @as(usize, @intCast(offset)));
            @memcpy(buf[0..n], self.data[@intCast(offset)..][0..n]);
            return n;
        }
        const vtable = model.Source.VTable{ .size = size, .readAt = readAt };
    };

    var s = BufSource{ .data = "0123456789" };
    var win = WindowSource{ .inner = .{ .ptr = &s, .vtable = &BufSource.vtable }, .base = 3, .len = 4 };
    const src = win.source();

    try testing.expectEqual(@as(i64, 4), src.size());
    const got = try src.readAll(a, 0, 4);
    try testing.expectEqualStrings("3456", got);

    // 越过窗口尾部的读只能拿到窗口内的部分
    const part = try a.alloc(u8, 8);
    try testing.expectEqual(@as(usize, 2), try src.readAt(2, part));
    try testing.expectEqualStrings("56", part[0..2]);
    // 完全出界
    try testing.expectEqual(@as(usize, 0), try src.readAt(4, part));
}

test "RateLimiter computes a minimum interval" {
    try testing.expectEqual(@as(i64, 0), RateLimiter.minIntervalMs(0));
    try testing.expectEqual(@as(i64, 1000), RateLimiter.minIntervalMs(1));
    try testing.expectEqual(@as(i64, 500), RateLimiter.minIntervalMs(2));
    try testing.expectEqual(@as(i64, 334), RateLimiter.minIntervalMs(3));

    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(0, 1_000_000, 3));
    try testing.expectEqual(@as(i64, 334), RateLimiter.waitMs(1_000_000, 1_000_000, 3));
    try testing.expectEqual(@as(i64, 234), RateLimiter.waitMs(1_000_000, 1_000_100, 3));
    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(1_000_000, 1_000_400, 3));
    try testing.expectEqual(@as(i64, 0), RateLimiter.waitMs(1_000_000, 1_000_000, 0));
}

test "createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const cfg = try json.parse(a, "{\"refresh_token\":\"RT\"}");
    const d = try createWithId(a, 7, &cfg);
    try testing.expectEqual(@as(i64, 7), d.storage_id);
    try testing.expectEqualStrings("115 Open", Open115.drvName(@ptrCast(d)));
    try testing.expectEqualStrings("RT", d.cfg.refresh_token);
    try testing.expectEqualStrings("0", d.cfg.root_folder_id);
    try testing.expectEqualStrings("/", d.parent_path);
    try testing.expectEqualStrings("115 Open", factory.key);
    try testing.expectEqualStrings("115 Open", driver.asDriver(Open115, d).name());

    d.jar.deinit();
    d.client.deinit();
    a.destroy(d.jar);
    a.destroy(d);
}
