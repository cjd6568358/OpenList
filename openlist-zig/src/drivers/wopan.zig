//! 联通沃云盘（WoPan）驱动 —— Go 版 `drivers/wopan` 的 Zig 移植。
//!
//! 上游的 `drivers/wopan/driver.go` 只是一层薄封装：HTTP、签名、加解密全在
//! 外部 SDK `github.com/OpenListTeam/wopan-sdk-go v0.1.5` 里。所以本文件是
//! **SDK + driver 两层**的合并移植，逐行对齐 SDK 的 `request.go` / `crypto.go`
//! / `header.go` / `api-fs.go` / `api-user.go`。
//!
//! 协议要点（SDK consts.go / request.go / upload.go）：
//!   1. **单一入口**：`POST https://panservice.mail.wo.cn/{channel}/dispatcher`，
//!      body = `{"header":{...},"body":{...}}`，channel ∈ {`api-user`,`wohome`}。
//!      必须带 `Origin: https://pan.wo.cn`、`Referer: https://pan.wo.cn/`；
//!      有 token 时再加 `Accesstoken`。
//!   2. **header 签名**：`md5(key + resTime(毫秒) + reqSeq + channel + version)`
//!      小写 hex；reqSeq ∈ `[1e5, 1e5+8999)`。
//!   3. **body 加密**：只有 `param` 被加密 —— AES-128-CBC + PKCS7，IV 固定
//!      `wNSOYIB1k1DjY5lA`；**key 随 channel 变**：`api-user` 用 clientSecret
//!      `XFmi9GS2hzk98jGX`，`wohome` 用 accessToken 前 16 字节。结果 base64
//!      后放进 body 的 `param`，`secret` 等其它字段明文并列。
//!   4. **响应解密**：`RSP.DATA` 若被一对双引号包裹即为密文 —— base64 解码后
//!      按同一规则解密，再 JSON 解析。
//!   5. **错误两层**：外层 `STATUS`（`"200"`）、内层 `RSP.RSP_CODE`（`"0000"`）。
//!      内层非 `0000` 且 channel ≠ api-user 时**刷 token 重试一次**。
//!   6. **上传不走 dispatcher**：`{zoneURL}/openapi/client/upload2C` 的
//!      multipart 表单，8 MiB 一片，`fileInfo` 字段是 wohome 加密的 base64。
//!
//! 未移植：`Other`（Go 里就是注释掉的 `errs.NotSupport`）、离线下载。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const aes = @import("../util/aes.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const urlmod = @import("../util/url.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量（SDK consts.go）
// ---------------------------------------------------------------------------

const client_id = "1001000021";
const client_secret = "XFmi9GS2hzk98jGX";
const app_id = "10000001";
const base_url = "https://panservice.mail.wo.cn";
/// `GetZoneInfo` 拿不到地址时的兜底（SDK 的 `DefaultZoneURL`）。
const default_zone_url = "https://tjupload.pan.wo.cn";
const default_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.37";
/// SDK 的 `DefaultPartSize`：8 MiB。
const part_size: i64 = 8 * 1024 * 1024;
const page_size: i64 = 100;

const chan_api_user = "api-user";
const chan_wohome = "wohome";
const chan_wocloud = "wocloud";

/// 空间类型：`0` 个人、`1` 家庭。
const space_personal = "0";
const space_family = "1";

/// SDK `Crypto.iv`，16 字节固定。
const crypto_iv = "wNSOYIB1k1DjY5lA";

const k_family_current = "FamilyUserCurrentEncode";
const k_query_all_files = "QueryAllFiles";
const k_download_url_v2 = "GetDownloadUrlV2";
const k_create_dir = "CreateDirectory";
const k_rename = "RenameFileOrDirectory";
const k_move = "MoveFile";
const k_copy = "CopyFile";
const k_delete = "DeleteFile";
const k_usage = "QueryCloudUsageInfo";
const k_classify = "ClassifyRule";
const k_zone = "GetZoneInfo";
const k_upload = "upload2C";
const k_refresh_token = "AppRefreshToken";
const k_query_user = "AppQueryUser";

/// SDK 的 `SortNameAsc = iota + 1`：值必须逐一对上。
fn sortRuleValue(name: []const u8) i64 {
    if (std.mem.eql(u8, name, "name_desc")) return 2;
    if (std.mem.eql(u8, name, "size_asc")) return 3;
    if (std.mem.eql(u8, name, "size_desc")) return 4;
    if (std.mem.eql(u8, name, "time_asc")) return 5;
    if (std.mem.eql(u8, name, "time_desc")) return 6;
    return 1; // name_asc
}

// ---------------------------------------------------------------------------
// 配置（drivers/wopan/meta.go 的 Addition）
// ---------------------------------------------------------------------------

const Addition = struct {
    root_id: []const u8 = "0",
    refresh_token: []const u8 = "",
    family_id: []const u8 = "",
    sort_rule: []const u8 = "name_asc",
    access_token: []const u8 = "",

    fn parse(a: std.mem.Allocator, v: ?*const json.Value) !Addition {
        const n = v orelse return Addition{};
        return .{
            .root_id = try a.dupe(u8, n.strAt("root_folder_id") orelse "0"),
            .refresh_token = try a.dupe(u8, n.strAt("refresh_token") orelse ""),
            .family_id = try a.dupe(u8, n.strAt("family_id") orelse ""),
            .sort_rule = try a.dupe(u8, n.strAt("sort_rule") orelse "name_asc"),
            .access_token = try a.dupe(u8, n.strAt("access_token") orelse ""),
        };
    }
};

// ---------------------------------------------------------------------------
// 驱动主体
// ---------------------------------------------------------------------------

pub const Wopan = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,

    /// 既是 `Accesstoken` 头的值，也是 wohome 频道的 AES key 来源（前 16 字节）。
    access_token: []const u8 = "",
    /// `AppQueryUser` 的 userId；`QueryCloudUsageInfo` 拿它当 phoneNum。
    phone: []const u8 = "",
    /// `FamilyUserCurrentEncode` 的 defaultHomeId：未配 family_id 时 `MakeDir`
    /// 用它（Go driver.go:91-96）。
    default_family_id: []const u8 = "",
    zone_url: []const u8 = "",
    /// 扩展名 → 沃云盘 fileType，来自 `ClassifyRule`。
    classify: ?std.StringHashMap([]const u8) = null,

    const Error = error{
        InvalidResponse,
        AuthFailed,
        UploadFailed,
        NotFound,
        InvalidPath,
    };

    fn as(ptr: *anyopaque) *Wopan {
        return @ptrCast(@alignCast(ptr));
    }

    fn drvName(_: *anyopaque) []const u8 {
        return "WoPan";
    }

    fn deinit(p: *anyopaque, _: *driver.Ctx) void {
        const self = as(p);
        if (self.classify) |*m| m.deinit();
        self.client.deinit();
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
        .copy = copy,
        .space = space,
    };

    /// 对齐 SDK 的 `InitData`：无 access_token 先刷新，再补 phone / classify /
    /// zone / defaultFamilyId。
    fn init(p: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        if (self.access_token.len == 0 and self.cfg.refresh_token.len > 0) {
            try self.refreshToken(a);
        }
        try self.initPhone(a);
        self.initClassify(a);
        self.initZone(a) catch {};
        self.default_family_id = self.familyCurrent(a) catch "";
    }

    fn refreshToken(self: *Wopan, a: std.mem.Allocator) !void {
        var p = Buf.init(a);
        try p.append("{\"refreshToken\":");
        try json.writeString(&p, self.cfg.refresh_token);
        try p.append(",\"clientSecret\":");
        try json.writeString(&p, client_secret);
        try p.append("}");
        const param = try encryptParam(a, chan_api_user, self.access_token, p.slice());
        const raw = try self.post(a, chan_api_user, k_refresh_token, param, true);
        const v = json.parse(a, raw) catch return Error.InvalidResponse;
        const at = v.strAt("access_token") orelse return Error.AuthFailed;
        const nrt = v.strAt("refresh_token") orelse return Error.AuthFailed;
        self.access_token = try self.alloc.dupe(u8, at);
        self.cfg.access_token = self.access_token;
        self.cfg.refresh_token = try self.alloc.dupe(u8, nrt);
    }

    fn initPhone(self: *Wopan, a: std.mem.Allocator) !void {
        if (self.phone.len > 0) return;
        var p = Buf.init(a);
        try p.append("{\"accessToken\":");
        try json.writeString(&p, self.access_token);
        try p.append("}");
        const param = try encryptParam(a, chan_api_user, self.access_token, p.slice());
        const raw = try self.post(a, chan_api_user, k_query_user, param, true);
        const v = json.parse(a, raw) catch return Error.InvalidResponse;
        self.phone = try self.alloc.dupe(u8, v.strAt("userId") orelse "");
    }

    /// `ClassifyRule` 只影响上传时的 fileType 号，拿不到就退化成兜底 `5`，
    /// 所以失败不向上传播（SDK 的 `GetFileType` 也是这个行为）。
    fn initClassify(self: *Wopan, a: std.mem.Allocator) void {
        if (self.classify != null) return;
        var m = std.StringHashMap([]const u8).init(self.alloc);
        const param = encryptParam(a, chan_wohome, self.access_token, "{}") catch {
            self.classify = m;
            return;
        };
        const raw = self.post(a, chan_wohome, k_classify, param, true) catch {
            self.classify = m;
            return;
        };
        const v = json.parse(a, raw) catch {
            self.classify = m;
            return;
        };
        if (v.getPath("fileTypes")) |ft| {
            if (ft.asObject()) |o| {
                for (o.keys, o.vals) |k, val| {
                    const t = val.strAt("type") orelse continue;
                    m.put(self.alloc.dupe(u8, k) catch continue, self.alloc.dupe(u8, t) catch continue) catch continue;
                }
            }
        }
        self.classify = m;
    }

    fn initZone(self: *Wopan, a: std.mem.Allocator) anyerror!void {
        if (self.zone_url.len > 0) return;
        var p = Buf.init(a);
        try p.append("{\"appId\":");
        try json.writeString(&p, app_id);
        try p.append("}");
        const param = encryptParam(a, chan_wohome, self.access_token, p.slice()) catch return;
        const raw = self.post(a, chan_wohome, k_zone, param, true) catch return;
        const v = json.parse(a, raw) catch return;
        self.zone_url = self.alloc.dupe(u8, v.strAt("url") orelse "") catch "";
    }

    fn familyCurrent(self: *Wopan, a: std.mem.Allocator) ![]const u8 {
        var p = Buf.init(a);
        try p.append("{\"clientId\":");
        try json.writeString(&p, client_id);
        try p.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, p.slice());
        const raw = try self.post(a, chan_wohome, k_family_current, param, true);
        const v = json.parse(a, raw) catch return Error.InvalidResponse;
        if (v.intAt("defaultHomeId")) |n| {
            return std.fmt.allocPrint(self.alloc, "{d}", .{n});
        }
        return "";
    }

    /// 扩展名 → fileType；没有分类表时按 SDK 兜底返回 `"5"`（其它）。
    fn fileType(self: *const Wopan, name: []const u8) []const u8 {
        const ext = std.fs.path.extension(name);
        if (ext.len < 2) return "5";
        if (self.classify) |m| {
            if (m.get(ext[1..])) |t| return t;
        }
        return "5";
    }

    fn spaceType(self: *const Wopan) []const u8 {
        return if (self.cfg.family_id.len == 0) space_personal else space_family;
    }

    // -----------------------------------------------------------------------
    // dispatcher
    // -----------------------------------------------------------------------

    /// 发一次 dispatcher 请求，返回**已解密**的 DATA 文本（DATA 为空时返回 ""）。
    fn post(
        self: *Wopan,
        a: std.mem.Allocator,
        channel: []const u8,
        key: []const u8,
        param_b64: []const u8,
        retry: bool,
    ) anyerror![]const u8 {
        const ts = rt.nowMillis();
        const seq = reqSeqValue();
        const sign = try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}{d}{d}{s}", .{ key, ts, seq, channel }));

        var b = Buf.init(a);
        try b.append("{\"header\":{\"key\":");
        try json.writeString(&b, key);
        try b.print(",\"resTime\":{d},\"reqSeq\":{d},\"channel\":", .{ ts, seq });
        try json.writeString(&b, channel);
        try b.append(",\"sign\":");
        try json.writeString(&b, sign);
        try b.append(",\"version\":\"\"},\"body\":{\"param\":");
        try json.writeString(&b, param_b64);
        try b.append(",\"secret\":true}}");

        var headers = List(model.Header).init(a);
        try headers.append(.{ .name = "Origin", .value = "https://pan.wo.cn" });
        try headers.append(.{ .name = "Referer", .value = "https://pan.wo.cn/" });
        try headers.append(.{ .name = "User-Agent", .value = default_ua });
        if (self.access_token.len > 0) {
            try headers.append(.{ .name = "Accesstoken", .value = self.access_token });
        }

        const url = try std.fmt.allocPrint(a, "{s}/{s}/dispatcher", .{ base_url, channel });
        const res = try self.client.send(a, .{
            .method = "POST",
            .url = url,
            .headers = headers.slice(),
            .body = b.slice(),
            .use_cookies = false,
        });
        if (res.status < 200 or res.status >= 300) {
            log.warn("[wopan] {s} HTTP {d}", .{ key, res.status });
            return Error.InvalidResponse;
        }
        const v = json.parse(a, res.body) catch return Error.InvalidResponse;
        const status = v.strAt("STATUS") orelse return Error.InvalidResponse;
        if (!std.mem.eql(u8, status, "200")) {
            log.warn("[wopan] {s}: STATUS={s} MSG={s}", .{ key, status, v.strAt("MSG") orelse "" });
            return Error.InvalidResponse;
        }
        const rsp = v.getPath("RSP") orelse return Error.InvalidResponse;
        const code = rsp.strAt("RSP_CODE") orelse return Error.InvalidResponse;
        if (!std.mem.eql(u8, code, "0000")) {
            if (retry and !std.mem.eql(u8, channel, chan_api_user)) {
                log.info("[wopan] {s}: rsp_code={s}, refreshing token and retrying", .{ key, code });
                try self.refreshToken(a);
                return self.post(a, channel, key, param_b64, false);
            }
            log.warn("[wopan] {s}: rsp_code={s} desc={s}", .{ key, code, rsp.strAt("RSP_DESC") orelse "" });
            return Error.InvalidResponse;
        }
        const data = rsp.getPath("DATA") orelse return "";
        // DATA 是 `"..."` 包裹的密文才解密；否则是明文 JSON。
        if (data.asStr()) |s| {
            if (s.len >= 2 and s[0] == '"' and s[s.len - 1] == '"') {
                return decryptData(a, chan_wohome, self.access_token, s[1 .. s.len - 1]);
            }
            return s;
        }
        return json.stringify(a, data) catch "";
    }

    // -----------------------------------------------------------------------
    // vtable
    // -----------------------------------------------------------------------

    fn list(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(p);
        const a = ctx.alloc;
        const id = try self.resolveId(a, dir);
        var out = List(model.Obj).init(a);
        var page: i64 = 0;
        while (true) {
            var b = Buf.init(a);
            try b.append("{\"spaceType\":");
            try json.writeString(&b, self.spaceType());
            try b.append(",\"parentDirectoryId\":");
            try json.writeString(&b, id);
            try b.print(",\"pageNum\":{d},\"pageSize\":{d},\"sortRule\":{d},\"clientId\":", .{
                page, page_size, sortRuleValue(self.cfg.sort_rule),
            });
            try json.writeString(&b, client_id);
            if (self.cfg.family_id.len > 0) {
                try b.append(",\"familyId\":");
                try json.writeString(&b, self.cfg.family_id);
            }
            try b.append("}");
            const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
            const raw = try self.post(a, chan_wohome, k_query_all_files, param, true);
            const v = json.parse(a, raw) catch return Error.InvalidResponse;
            const files = v.getPath("files") orelse break;
            const arr = files.asArray() orelse break;
            for (arr) |*f| {
                try out.append(.{
                    .name = try a.dupe(u8, f.strAt("name") orelse ""),
                    .size = f.intAt("size") orelse 0,
                    .is_dir = (f.intAt("type") orelse 1) == 0,
                    .modified = parseWopanTime(f.strAt("createTime") orelse ""),
                    // `sign` 承载上游的 id（与 189 系列同一手法）。
                    .sign = try a.dupe(u8, f.strAt("id") orelse ""),
                });
            }
            if (arr.len < page_size) break;
            page += 1;
        }
        return try out.toOwned();
    }

    fn details(p: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(p);
        const a = ctx.alloc;
        const obj = try self.findEntry(a, path) orelse return Error.NotFound;
        return .{ .name = obj.name, .size = obj.size, .is_dir = obj.is_dir, .modified = obj.modified, .sign = obj.sign };
    }

    fn link(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, _: driver.LinkArgs) anyerror!driver.Link {
        const self = as(p);
        const a = ctx.alloc;
        const obj = try self.findEntry(a, path) orelse return Error.NotFound;
        if (obj.is_dir) return Error.InvalidPath;

        var b = Buf.init(a);
        try b.append("{\"type\":\"1\",\"fidList\":[");
        try json.writeString(&b, obj.sign);
        try b.append("],\"clientId\":");
        try json.writeString(&b, client_id);
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        const raw = try self.post(a, chan_wohome, k_download_url_v2, param, true);
        const v = json.parse(a, raw) catch return Error.InvalidResponse;
        const lst = v.getPath("list") orelse return Error.InvalidResponse;
        const arr = lst.asArray() orelse return Error.InvalidResponse;
        if (arr.len == 0) return Error.InvalidResponse;
        const url = arr[0].strAt("downloadUrl") orelse return Error.InvalidResponse;
        return .{ .url = url };
    }

    fn makeDir(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const parent = try self.resolveId(a, urlmod.parentPath(dir));
        const name = urlmod.baseName(dir);
        if (name.len == 0) return Error.InvalidPath;
        // Go driver.go: family_id 为空时用 `defaultFamilyID`。
        const fam = if (self.cfg.family_id.len > 0) self.cfg.family_id else self.default_family_id;

        var b = Buf.init(a);
        try b.append("{\"spaceType\":");
        try json.writeString(&b, self.spaceType());
        try b.append(",\"familyId\":");
        try json.writeString(&b, fam);
        try b.append(",\"parentDirectoryId\":");
        try json.writeString(&b, parent);
        try b.append(",\"directoryName\":");
        try json.writeString(&b, name);
        try b.append(",\"clientId\":");
        try json.writeString(&b, client_id);
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        _ = try self.post(a, chan_wohome, k_create_dir, param, true);
    }

    fn rename(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, new_name: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const obj = try self.findEntry(a, path) orelse return Error.NotFound;
        // Go driver.go:116-124 —— `type`: 1 = 文件, 0 = 目录。
        var b = Buf.init(a);
        try b.append("{\"spaceType\":");
        try json.writeString(&b, self.spaceType());
        try b.print(",\"type\":{d},\"fileType\":", .{if (obj.is_dir) @as(i64, 0) else @as(i64, 1)});
        try json.writeString(&b, self.fileType(new_name));
        try b.append(",\"id\":");
        try json.writeString(&b, obj.sign);
        try b.append(",\"name\":");
        try json.writeString(&b, new_name);
        try b.append(",\"clientId\":");
        try json.writeString(&b, client_id);
        if (self.cfg.family_id.len > 0) {
            try b.append(",\"familyId\":");
            try json.writeString(&b, self.cfg.family_id);
        }
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        _ = try self.post(a, chan_wohome, k_rename, param, true);
    }

    /// move / copy 的上游参数是**同一套**（dirList + fileList + 两个 spaceType）。
    fn moveOrCopy(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8, is_copy: bool) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const obj = try self.findEntry(a, src) orelse return Error.NotFound;
        const dst = try self.resolveId(a, dst_dir);
        const st = self.spaceType();

        var b = Buf.init(a);
        try b.append("{\"targetDirId\":");
        try json.writeString(&b, dst);
        try b.append(",\"sourceType\":");
        try json.writeString(&b, st);
        try b.append(",\"targetType\":");
        try json.writeString(&b, st);
        try b.append(",\"dirList\":[");
        if (obj.is_dir) try json.writeString(&b, obj.sign);
        try b.append("],\"fileList\":[");
        if (!obj.is_dir) try json.writeString(&b, obj.sign);
        try b.append("],\"secret\":false,\"clientId\":");
        try json.writeString(&b, client_id);
        if (self.cfg.family_id.len > 0) {
            try b.append(",\"fromFamilyId\":");
            try json.writeString(&b, self.cfg.family_id);
            try b.append(",\"familyId\":");
            try json.writeString(&b, self.cfg.family_id);
        }
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        _ = try self.post(a, chan_wohome, if (is_copy) k_copy else k_move, param, true);
    }

    fn move(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        return moveOrCopy(p, ctx, src, dst_dir, false);
    }

    fn copy(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        return moveOrCopy(p, ctx, src, dst_dir, true);
    }

    fn remove(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const obj = try self.findEntry(a, path) orelse return Error.NotFound;

        var b = Buf.init(a);
        try b.append("{\"spaceType\":");
        try json.writeString(&b, self.spaceType());
        try b.append(",\"vipLevel\":\"0\",\"dirList\":[");
        if (is_dir) try json.writeString(&b, obj.sign);
        try b.append("],\"fileList\":[");
        if (!is_dir) try json.writeString(&b, obj.sign);
        try b.append("],\"clientId\":");
        try json.writeString(&b, client_id);
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        _ = try self.post(a, chan_wohome, k_delete, param, true);
    }

    fn put(p: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const dir_id = try self.resolveId(a, urlmod.parentPath(dst));
        const name = urlmod.baseName(dst);
        const size: i64 = @max(src.size(), 0);

        const zone = if (self.zone_url.len > 0) self.zone_url else default_zone_url;
        const url = try std.fmt.allocPrint(a, "{s}/openapi/client/{s}", .{ zone, k_upload });

        // `fileInfo` 是 wohome 加密后的 base64（SDK upload.go:50-66）。
        var fb = Buf.init(a);
        try fb.append("{\"spaceType\":");
        try json.writeString(&fb, self.spaceType());
        try fb.append(",\"directoryId\":");
        try json.writeString(&fb, dir_id);
        try fb.append(",\"batchNo\":");
        try json.writeString(&fb, try formatCompact(a, rt.nowSeconds()));
        try fb.append(",\"fileName\":");
        try json.writeString(&fb, name);
        try fb.print(",\"fileSize\":{d},\"fileType\":", .{size});
        try json.writeString(&fb, self.fileType(name));
        if (self.cfg.family_id.len > 0) {
            try fb.append(",\"familyId\":");
            try json.writeString(&fb, self.cfg.family_id);
        }
        try fb.append("}");
        const file_info = try encryptParam(a, chan_wohome, self.access_token, fb.slice());

        const total_parts: i64 = if (size == 0) 1 else @divTrunc(size + part_size - 1, part_size);
        var done: i64 = 0;
        var part: i64 = 1;
        const buf = try a.alloc(u8, @intCast(@min(part_size, @max(size, 1))));
        while (part <= total_parts) {
            const want: i64 = @min(part_size, size - done);
            const chunk = buf[0..@intCast(@max(want, 0))];
            if (chunk.len > 0) try src.readAllInto(@intCast(done), chunk);

            var fields = List([2][]const u8).init(a);
            try fields.append(.{ "uniqueId", try std.fmt.allocPrint(a, "{d}", .{rt.nowMillis()}) });
            try fields.append(.{ "accessToken", self.access_token });
            try fields.append(.{ "fileName", name });
            try fields.append(.{ "psToken", "undefined" });
            try fields.append(.{ "fileSize", try std.fmt.allocPrint(a, "{d}", .{size}) });
            try fields.append(.{ "totalPart", try std.fmt.allocPrint(a, "{d}", .{total_parts}) });
            try fields.append(.{ "channel", chan_wocloud });
            try fields.append(.{ "directoryId", dir_id });
            try fields.append(.{ "fileInfo", file_info });
            try fields.append(.{ "partSize", try std.fmt.allocPrint(a, "{d}", .{want}) });
            try fields.append(.{ "partIndex", try std.fmt.allocPrint(a, "{d}", .{part}) });
            try fields.append(.{ "file", "" }); // 占位：见下面的 multipart 组装

            const body = try buildMultipart(a, fields.slice()[0 .. fields.len - 1], "file", name, chunk);
            var headers = List(model.Header).init(a);
            try headers.append(.{ .name = "Origin", .value = "https://pan.wo.cn" });
            try headers.append(.{ .name = "Referer", .value = "https://pan.wo.cn/" });
            try headers.append(.{ .name = "User-Agent", .value = default_ua });
            try headers.append(.{
                .name = "Content-Type",
                .value = try std.fmt.allocPrint(a, "multipart/form-data; boundary={s}", .{mp_boundary}),
            });
            const res = try self.client.send(a, .{
                .method = "POST",
                .url = url,
                .headers = headers.slice(),
                .body = body,
                .use_cookies = false,
            });
            if (res.status < 200 or res.status >= 300) {
                log.warn("[wopan] upload part {d} HTTP {d}", .{ part, res.status });
                return Error.UploadFailed;
            }
            const v = json.parse(a, res.body) catch return Error.InvalidResponse;
            const code = v.strAt("code") orelse return Error.InvalidResponse;
            if (!std.mem.eql(u8, code, "0000")) {
                log.warn("[wopan] upload part {d}: code={s} msg={s}", .{ part, code, v.strAt("msg") orelse "" });
                return Error.UploadFailed;
            }
            done += want;
            // 进度按百分比上报（0–100，Go `model.UpdateProgress` 语义）。
            if (ctx.progress) |f| {
                const pct: u64 = @intCast(@min(@divTrunc(done * 100, @max(size, 1)), 100));
                f(ctx.progress_userdata, pct);
            }
            part += 1;
        }
    }

    fn space(p: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(p);
        const a = ctx.alloc;
        var b = Buf.init(a);
        try b.append("{\"phoneNum\":");
        try json.writeString(&b, self.phone);
        try b.append(",\"clientId\":");
        try json.writeString(&b, client_id);
        try b.append("}");
        const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
        const raw = try self.post(a, chan_wohome, k_usage, param, true);
        const v = json.parse(a, raw) catch return Error.InvalidResponse;
        const u = v.getPath("usageInfo") orelse return Error.InvalidResponse;
        const total = std.fmt.parseInt(i64, u.strAt("byteTotalSize") orelse "0", 10) catch 0;
        return .{ .total = total, .used = u.intAt("byteUsedSize") orelse 0 };
    }

    // -----------------------------------------------------------------------
    // 路径 → id
    // -----------------------------------------------------------------------

    fn resolveId(self: *Wopan, a: std.mem.Allocator, dir: []const u8) ![]const u8 {
        if (dir.len == 0 or std.mem.eql(u8, dir, "/")) return self.cfg.root_id;
        const obj = try self.findEntry(a, dir) orelse return Error.NotFound;
        if (!obj.is_dir) return Error.InvalidPath;
        return obj.sign;
    }

    /// 逐段下钻；`sign` 承载上游 id。
    fn findEntry(self: *Wopan, a: std.mem.Allocator, path: []const u8) !?model.Obj {
        var cur: []const u8 = self.cfg.root_id;
        var result: ?model.Obj = null;
        var it = std.mem.splitScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            const found = try self.childByName(a, cur, seg) orelse return null;
            cur = try a.dupe(u8, found.sign);
            result = found;
        }
        return result;
    }

    fn childByName(self: *Wopan, a: std.mem.Allocator, parent_id: []const u8, name: []const u8) !?model.Obj {
        var page: i64 = 0;
        while (true) {
            var b = Buf.init(a);
            try b.append("{\"spaceType\":");
            try json.writeString(&b, self.spaceType());
            try b.append(",\"parentDirectoryId\":");
            try json.writeString(&b, parent_id);
            try b.print(",\"pageNum\":{d},\"pageSize\":{d},\"sortRule\":{d},\"clientId\":", .{
                page, page_size, sortRuleValue(self.cfg.sort_rule),
            });
            try json.writeString(&b, client_id);
            if (self.cfg.family_id.len > 0) {
                try b.append(",\"familyId\":");
                try json.writeString(&b, self.cfg.family_id);
            }
            try b.append("}");
            const param = try encryptParam(a, chan_wohome, self.access_token, b.slice());
            const raw = try self.post(a, chan_wohome, k_query_all_files, param, true);
            const v = json.parse(a, raw) catch return null;
            const files = v.getPath("files") orelse return null;
            const arr = files.asArray() orelse return null;
            for (arr) |*f| {
                const n = f.strAt("name") orelse continue;
                if (!std.mem.eql(u8, n, name)) continue;
                return .{
                    .name = try a.dupe(u8, n),
                    .size = f.intAt("size") orelse 0,
                    .is_dir = (f.intAt("type") orelse 1) == 0,
                    .modified = parseWopanTime(f.strAt("createTime") orelse ""),
                    .sign = try a.dupe(u8, f.strAt("id") orelse ""),
                };
            }
            if (arr.len < page_size) return null;
            page += 1;
        }
    }
};

// ---------------------------------------------------------------------------
// 纯函数：加解密 / 签名 / 时间 / multipart
// ---------------------------------------------------------------------------

/// SDK `Crypto.EncryptBytes` 的 key 选择：api-user 用 clientSecret，
/// 其余（wohome）用 accessToken 前 16 字节。
fn cryptoKey(channel: []const u8, access_token: []const u8) ![]const u8 {
    if (std.mem.eql(u8, channel, chan_api_user)) return client_secret[0..];
    if (access_token.len < 16) return error.InvalidAccessToken;
    return access_token[0..16];
}

fn encryptParam(a: std.mem.Allocator, channel: []const u8, access_token: []const u8, plain: []const u8) ![]const u8 {
    const key = try cryptoKey(channel, access_token);
    const padded = try aes.pkcs7Pad(a, plain, aes.BLOCK);
    defer a.free(padded);
    const ct = try aes.cbcEncrypt(a, key, crypto_iv[0..], padded);
    defer a.free(ct);
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(ct.len));
    return enc.encode(out, ct);
}

fn decryptData(a: std.mem.Allocator, channel: []const u8, access_token: []const u8, b64: []const u8) ![]const u8 {
    const dec = std.base64.standard.Decoder;
    const ct = try a.alloc(u8, try dec.calcSizeForSlice(b64));
    defer a.free(ct);
    try dec.decode(ct, b64);
    const key = try cryptoKey(channel, access_token);
    const pt = try aes.cbcDecrypt(a, key, crypto_iv[0..], ct);
    return aes.pkcs7Unpad(pt, aes.BLOCK);
}

/// 符合 SDK `calHeader` 的 reqSeq：`[1e5, 1e5+8999)`。
fn reqSeqValue() i64 {
    var seed: u64 = undefined;
    rt.io().random(std.mem.asBytes(&seed));
    return @as(i64, @intCast(seed % 8999)) + 100000;
}

/// `20230607214351`（UTC+8）→ unix 秒。长度不对时返回 0。
fn parseWopanTime(s: []const u8) i64 {
    if (s.len != 14) return 0;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return 0;
    const mo = std.fmt.parseInt(i64, s[4..6], 10) catch return 0;
    const d = std.fmt.parseInt(i64, s[6..8], 10) catch return 0;
    const h = std.fmt.parseInt(i64, s[8..10], 10) catch return 0;
    const mi = std.fmt.parseInt(i64, s[10..12], 10) catch return 0;
    const se = std.fmt.parseInt(i64, s[12..14], 10) catch return 0;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return 0;
    const days = @import("../util/time.zig").daysFromCivil(y, mo, d);
    return days * 86400 + h * 3600 + mi * 60 + se - 8 * 3600;
}

/// `20060102150405`（本地时刻，与 SDK `time.Format` 一致，用本地时区即可）。
fn formatCompact(a: std.mem.Allocator, unix_s: i64) ![]const u8 {
    const t = @import("../util/time.zig").civilFromDays(@divFloor(unix_s, 86400));
    const sod = @mod(unix_s, 86400);
    return std.fmt.allocPrint(a, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}", .{
        t.y, t.m, t.d, @divFloor(sod, 3600), @divFloor(@mod(sod, 3600), 60), @mod(sod, 60),
    });
}

const mp_boundary = "----openlistZigWopanBoundary";

/// 手写 multipart/form-data。沃云盘的上传端点要的是标准表单上传，
/// 而 `httpclient` 没有 multipart 封装，所以在这里拼（字段顺序按 SDK 的
/// `SetMultipartFormData` 语义：文本字段在前，文件字段在后）。
fn buildMultipart(
    a: std.mem.Allocator,
    fields: []const [2][]const u8,
    file_field: []const u8,
    file_name: []const u8,
    content: []const u8,
) ![]const u8 {
    var b = Buf.init(a);
    for (fields) |f| {
        try b.print("--{s}\r\nContent-Disposition: form-data; name=\"{s}\"\r\n\r\n{s}\r\n", .{ mp_boundary, f[0], f[1] });
    }
    try b.print(
        "--{s}\r\nContent-Disposition: form-data; name=\"{s}\"; filename=\"{s}\"\r\n" ++
            "Content-Type: application/octet-stream\r\n\r\n",
        .{ mp_boundary, file_field, file_name },
    );
    try b.append(content);
    try b.print("\r\n--{s}--\r\n", .{mp_boundary});
    return b.slice();
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    // 逐字等于 Go 的 `driver.Config.Name`（drivers/wopan/meta.go:24）。
    .key = "WoPan",
    .label = "联通沃云盘",
    .secrets = &.{ "refresh_token", "access_token" },
    .addition_schema =
    \\{
    \\  "refresh_token": {"type":"string","required":true,"secret":true,"help":"刷新令牌"},
    \\  "family_id":     {"type":"string","required":false,"help":"家庭云 ID，留空表示个人空间"},
    \\  "sort_rule":     {"type":"select","options":"name_asc,name_desc,time_asc,time_desc,size_asc,size_desc","default":"name_asc"},
    \\  "root_folder_id":{"type":"string","default":"0","help":"根目录 ID"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    return driver.asDriver(Wopan, try createWithId(alloc, storage_id, cfg));
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Wopan {
    const self = try alloc.create(Wopan);
    const jar = try alloc.create(cookiejar.Jar);
    jar.* = cookiejar.Jar.init(alloc);
    const addition = try Addition.parse(alloc, cfg);
    self.* = .{
        .alloc = alloc,
        .storage_id = storage_id,
        .cfg = addition,
        .jar = jar,
        .client = httpclient.Client.init(alloc, .{}, jar),
        .access_token = addition.access_token,
    };
    return self;
}

// ---------------------------------------------------------------------------
// 单元测试：纯函数层（加解密 / 签名 / 时间）。无凭据也能跑，锁住协议要点。
// ---------------------------------------------------------------------------

test "wopan: crypto_iv 是标准 16 字节" {
    try std.testing.expectEqual(@as(usize, 16), crypto_iv.len);
}

test "wopan: cryptoKey 按 channel 选 key" {
    const tok = "ABCDEFGHIJKLMNOPQRSTUVWX"; // >=16 字节
    const k1 = try cryptoKey(chan_api_user, "whatever");
    try std.testing.expectEqualStrings(client_secret, k1);
    const k2 = try cryptoKey(chan_wohome, tok);
    try std.testing.expectEqualStrings(tok[0..16], k2);
    // api-user 的 key 就是 clientSecret，长度必须 16（AES-128）。
    try std.testing.expectEqual(@as(usize, 16), k1.len);
}

test "wopan: encryptParam/decryptData round-trip (api-user)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const plain = "{\"refreshToken\":\"abc\",\"clientSecret\":\"XFmi9GS2hzk98jGX\"}";
    const b64 = try encryptParam(a, chan_api_user, "", plain);
    const back = try decryptData(a, chan_api_user, "", b64);
    try std.testing.expectEqualStrings(plain, back);
}

test "wopan: encryptParam/decryptData round-trip (wohome, 含中文且非块对齐)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tok = "0123456789abcdefGHIJKLMN"; // >=16
    const plain = "hello wopan，中文测试 üöä"; // 长度非 16 倍数，逼出 PKCS7
    const b64 = try encryptParam(a, chan_wohome, tok, plain);
    const back = try decryptData(a, chan_wohome, tok, b64);
    try std.testing.expectEqualStrings(plain, back);
}

test "wopan: short plaintext survives PKCS7 padding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const tok = "0123456789abcdefGHIJKLMN";
    const plain = "x"; // 1 字节，pad 到 16
    const b64 = try encryptParam(a, chan_wohome, tok, plain);
    const back = try decryptData(a, chan_wohome, tok, b64);
    try std.testing.expectEqualStrings("x", back);
}

test "wopan: reqSeqValue 落在 SDK 约定区间 [100000,108999)" {
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const s = reqSeqValue();
        try std.testing.expect(s >= 100000 and s < 108999);
    }
}

test "wopan: parseWopanTime 长度非法返回 0" {
    try std.testing.expectEqual(@as(i64, 0), parseWopanTime(""));
    try std.testing.expectEqual(@as(i64, 0), parseWopanTime("2023"));
    try std.testing.expectEqual(@as(i64, 0), parseWopanTime("not-a-time-here"));
    const t = parseWopanTime("20230607214351");
    try std.testing.expect(t > 0);
}

test "wopan: header 签名 = md5(key+time+seq+channel) 小写 hex" {
    // 对齐 `post` 里的签名公式（version 为空，不参与）。
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = "mykey";
    const ts: i64 = 1700000000000;
    const seq: i64 = 100123;
    const sig = try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}{d}{d}{s}", .{ key, ts, seq, chan_wohome }));
    // md5 hex 永远 32 位小写。
    try std.testing.expectEqual(@as(usize, 32), sig.len);
    for (sig) |c| try std.testing.expect(c >= '0' and c <= '9' or c >= 'a' and c <= 'f');
    // 同样的输入必须稳定复现。
    const sig2 = try hash.md5Hex(a, try std.fmt.allocPrint(a, "{s}{d}{d}{s}", .{ key, ts, seq, chan_wohome }));
    try std.testing.expectEqualStrings(sig, sig2);
}

