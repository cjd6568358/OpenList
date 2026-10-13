//! 夸克网盘驱动 —— Go 版 `drivers/quark_uc` 的 Zig 移植（T2）。
//!
//! 与已下线的 `quark.zig`（QuarkOpen 开放平台变体）是同一个网盘的两个驱动：
//! 本驱动用 **Cookie 登录**（`drivers/quark_uc/meta.go`，用户备份 id=8 的存储
//! 正是它），key 必须逐字等于 Go 的 `Quark`。
//!
//! Quark 的 API 形态与 open 变体完全不同：
//!   1. 全部请求走 `https://drive.quark.cn/1/clouddrive`，带 `pr=ucpro&fr=pc`
//!      两个固定 query 参数，Cookie 放在头里。
//!   2. 错误判据是 `{status, code, message}`：`status >= 400 || code != 0`
//!      都算失败（util.go:63）。
//!   3. 响应里的 `__puus`（开了转码地址还有 `__pus`）cookie 要写回配置
//!      （Go 调 `op.MustSaveDriverStorage(d)`），否则隔一阵就失效。
//!   4. 上传是「预上传 → hash 秒传 → OSS 分片 → commit → finish」五步，
//!      每一步都要拿 `auth_meta` 换 OSS 的 Authorization（util.go:204-260）。
//!
//! 与 Go 版的差异（有意为之）：UC 变体（同一份 Go 代码注册的第二个 driver
//! 「UC」）不在本工程范围；`Copy` vtable 没有槽位；离线下载未移植。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const hash = @import("../util/hash.zig");
const mime = @import("../util/mime.zig");
const html = @import("../util/html.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const urlmod = @import("../util/url.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量（drivers/quark_uc/meta.go 的 Conf 与 util.go 的端点）
// ---------------------------------------------------------------------------

const api = "https://drive.quark.cn/1/clouddrive";
const referer = "https://pan.quark.cn";
/// `pr` / `fr` 固定 query 参数（util.go:35-36）。
const pr = "ucpro";
const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch";
const oss_ua = "aliyun-sdk-js/6.6.1 Chrome 98.0.4758.80 on Windows 10 64-bit";

const page_size: i64 = 100;
/// 秒传判定用：Go 里 hash 阶段直接看 `data.finish`。
const default_root = "0";

pub const Error = error{
    /// 没配 Cookie。
    AuthFailed,
    UpstreamHttp,
    UpstreamNotJson,
    /// `status >= 400 || code != 0`（util.go:63）。
    UpstreamError,
    InvalidResponse,
    InvalidPath,
    UploadFailed,
};

// ---------------------------------------------------------------------------
// 配置（drivers/quark_uc/meta.go）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    cookie: []const u8 = "",
    /// 内嵌 `driver.RootID` → `root_folder_id`。
    root_folder_id: []const u8 = default_root,
    order_by: []const u8 = "none",
    order_direction: []const u8 = "asc",
    use_transcoding_address: bool = false,
    only_list_video_file: bool = false,
    /// Go 的 `AdditionVersion int` 无 json tag → 键名就是字段名（用户备份实证：
    /// ['AdditionVersion','cookie','only_list_video_file','order_by',
    /// 'order_direction','root_folder_id']）。
    addition_version: i64 = 0,

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        a.cookie = try dupeOr(alloc, o.strAt("cookie"), "");
        a.root_folder_id = try dupeOr(alloc, o.strAt("root_folder_id"), default_root);
        a.order_by = try dupeOr(alloc, o.strAt("order_by"), "none");
        a.order_direction = try dupeOr(alloc, o.strAt("order_direction"), "asc");
        if (boolAt(o, "use_transcoding_address")) |b| a.use_transcoding_address = b;
        if (boolAt(o, "only_list_video_file")) |b| a.only_list_video_file = b;
        if (o.intAt("AdditionVersion")) |n| a.addition_version = n;
        return a;
    }

    /// 键名与 Go 的序列化形态逐字一致（无 tag 字段用字段名）。
    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        try b.append("{\"cookie\":");
        try json.writeString(&b, self.cookie);
        try b.append(",\"root_folder_id\":");
        try json.writeString(&b, self.root_folder_id);
        try b.append(",\"order_by\":");
        try json.writeString(&b, self.order_by);
        try b.append(",\"order_direction\":");
        try json.writeString(&b, self.order_direction);
        try b.print(",\"use_transcoding_address\":{},\"only_list_video_file\":{},\"AdditionVersion\":{d}}}", .{
            self.use_transcoding_address, self.only_list_video_file, self.addition_version,
        });
        return b.toOwned();
    }
};

fn dupeOr(alloc: std.mem.Allocator, v: ?[]const u8, fallback: []const u8) ![]const u8 {
    return alloc.dupe(u8, v orelse fallback);
}

fn boolAt(v: *const json.Value, path: []const u8) ?bool {
    if (v.getPath(path)) |x| return x.asBool();
    return null;
}

fn arrAt(v: *const json.Value, path: []const u8) []json.Value {
    const x = v.getPath(path) orelse return &.{};
    return x.asArray() orelse &.{};
}

/// 在 `k=v; k=v` 形态的 Cookie 串里替换/新增一项（对应 Go 的
/// `cookie.SetStr`）—— Quark 回写的 `__puus` 就是这么更新的。
fn setCookieValue(alloc: std.mem.Allocator, cookie: []const u8, name: []const u8, value: []const u8) ![]const u8 {
    var out = Buf.init(alloc);
    var replaced = false;
    var it = std.mem.splitScalar(u8, cookie, ';');
    while (it.next()) |raw| {
        const pair = std.mem.trim(u8, raw, " \t");
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse {
            if (out.len > 0) try out.append("; ");
            try out.append(pair);
            continue;
        };
        if (std.mem.eql(u8, std.mem.trim(u8, pair[0..eq], " \t"), name)) {
            if (out.len > 0) try out.append("; ");
            try out.print("{s}={s}", .{ name, value });
            replaced = true;
            continue;
        }
        if (out.len > 0) try out.append("; ");
        try out.append(pair);
    }
    if (!replaced) {
        if (out.len > 0) try out.append("; ");
        try out.print("{s}={s}", .{ name, value });
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// 驱动
// ---------------------------------------------------------------------------

pub const Quark = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    client: httpclient.Client,
    /// T6：init 跑在后台线程，请求线程随时可能进来 —— 串行化同一驱动的请求，
    /// 顺带保护 `cfg.cookie` 的并发写（Go 那边是单协程模型下直接改字段）。
    req_mu: std.Io.Mutex = .init,

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
        return "Quark";
    }

    /// 通用请求（util.go:27-67）。`pathname` 以 `/` 开头。
    fn request(self: *Quark, arena: std.mem.Allocator, pathname: []const u8, method: []const u8, query: ?[]const u8, body: []const u8, ua_override: ?[]const u8) ![]const u8 {
        const io = rt.io();
        self.req_mu.lockUncancelable(io);
        defer self.req_mu.unlock(io);

        const url = try std.fmt.allocPrint(arena, "{s}{s}?pr={s}&fr=pc{s}", .{
            api, pathname, pr, if (query) |q| (if (q.len > 0) q else "") else "",
        });
        var hdrs = List(model.Header).init(arena);
        try hdrs.append(.{ .name = "Cookie", .value = self.cfg.cookie });
        try hdrs.append(.{ .name = "Accept", .value = "application/json, text/plain, */*" });
        try hdrs.append(.{ .name = "Referer", .value = referer });
        if (ua_override) |u| try hdrs.append(.{ .name = "User-Agent", .value = u });

        const res = try self.client.send(arena, .{
            .method = method,
            .url = url,
            .headers = hdrs.slice(),
            .body = body,
            .use_cookies = true,
        });

        // 上游回写的会话 cookie 必须落盘，否则隔一阵就 401/403。
        self.absorbCookie(res, "__puus");
        if (self.cfg.use_transcoding_address) self.absorbCookie(res, "__pus");

        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        const status = v.intAt("status") orelse 0;
        const code = v.intAt("code") orelse 0;
        if (status >= 400 or code != 0) {
            const msg = v.strAt("message") orelse "(no message)";
            log.warn("[quark] {s} {s} -> status {d} code {d}: {s}", .{ method, pathname, status, code, msg });
            // 同名冲突在 MakeDir 里是可容忍的特定错误，交给调用方按文案判断。
            return Error.UpstreamError;
        }
        return res.body;
    }

    /// 从响应里捡一个指定 cookie 并写回配置（util.go:49-61）。
    fn absorbCookie(self: *Quark, res: httpclient.Response, name: []const u8) void {
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();
        const all = res.all(a, "Set-Cookie") catch return;
        for (all) |raw| {
            const pair = std.mem.trim(u8, raw, " \t");
            const semi = std.mem.indexOfScalar(u8, pair, ';') orelse pair.len;
            const first = pair[0..semi];
            const eq = std.mem.indexOfScalar(u8, first, '=') orelse continue;
            const k = std.mem.trim(u8, first[0..eq], " \t");
            if (!std.mem.eql(u8, k, name)) continue;
            const v = std.mem.trim(u8, first[eq + 1 ..], " \t");
            if (v.len == 0) continue;
            const next = setCookieValue(self.alloc, self.cfg.cookie, name, v) catch return;
            if (self.cfg.cookie.len > 0) self.alloc.free(self.cfg.cookie);
            self.cfg.cookie = next;
            // Go：op.MustSaveDriverStorage(d)
            const text = self.cfg.toJson(a) catch return;
            driver.persist(self.storage_id, text);
            return;
        }
    }

    fn get(self: *Quark, arena: std.mem.Allocator, pathname: []const u8, query: ?[]const u8) ![]const u8 {
        return self.request(arena, pathname, "GET", query, "", null);
    }

    fn post(self: *Quark, arena: std.mem.Allocator, pathname: []const u8, body: []const u8) ![]const u8 {
        return self.request(arena, pathname, "POST", null, body, null);
    }
};

fn as(p: *anyopaque) *Quark {
    return @ptrCast(@alignCast(p));
}

/// 与 `request` 同样发一次请求，但**不判** `status/code` —— MakeDir 需要看
/// 具体的 message（"file is doloading[同名冲突]" 是可容忍的已存在错误）。
fn requestUnchecked(self: *Quark, arena: std.mem.Allocator, pathname: []const u8, method: []const u8, body: []const u8) ![]const u8 {
    const io = rt.io();
    self.req_mu.lockUncancelable(io);
    defer self.req_mu.unlock(io);
    const url = try std.fmt.allocPrint(arena, "{s}{s}?pr={s}&fr=pc", .{ api, pathname, pr });
    const res = try self.client.send(arena, .{
        .method = method,
        .url = url,
        .headers = &[_]model.Header{
            .{ .name = "Cookie", .value = self.cfg.cookie },
            .{ .name = "Accept", .value = "application/json, text/plain, */*" },
            .{ .name = "Referer", .value = referer },
        },
        .body = body,
        .use_cookies = true,
    });
    self.absorbCookie(res, "__puus");
    if (self.cfg.use_transcoding_address) self.absorbCookie(res, "__pus");
    return res.body;
}

/// Go 用 `html.UnescapeString` —— 文件名里可能是 `&amp;` / `&#39;` / `&mdash;` 之类。
///
/// 以前这里只手写了 5 个实体（amp/lt/gt/quot/#39），`&nbsp;`、`&#x27;`、希腊字母
/// 等等全都还原不出来，路径匹配就会失配。现在走 `util/html.zig` 的完整解码器。
fn unescapeEntities(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    return html.unescape(a, s);
}

const Entry = struct {
    id: []const u8,
    name: []const u8,
    is_dir: bool,
    raw: ?*const json.Value = null,
};

fn objFromJson(a: std.mem.Allocator, item: *const json.Value) !model.Obj {
    const raw_name = item.strAt("file_name") orelse "";
    const name = try unescapeEntities(a, raw_name);
    return .{
        .name = name,
        .size = item.intAt("size") orelse 0,
        // Go: IsDir() = !f.File
        .is_dir = !(boolAt(item, "file") orelse false),
        // 时间戳是毫秒
        .modified = @divTrunc(item.intAt("updated_at") orelse 0, 1000),
        .created = @divTrunc(item.intAt("created_at") orelse 0, 1000),
    };
}

fn listPage(self: *Quark, arena: std.mem.Allocator, parent: []const u8, page: i64) !*const json.Value {
    const sort = if (!std.mem.eql(u8, self.cfg.order_by, "none"))
        try std.fmt.allocPrint(arena, "&_sort=file_type:asc,{s}:{s}", .{ self.cfg.order_by, self.cfg.order_direction })
    else
        "";
    const query = try std.fmt.allocPrint(arena, "&pdir_fid={s}&_size={d}&_fetch_total=1&fetch_all_file=1&fetch_risk_file_name=1{s}&_page={d}", .{ parent, page_size, sort, page });
    const body = try self.get(arena, "/file/sort", query);
    const v = json.parse(arena, body) catch return Error.UpstreamNotJson;
    return v.getPath("data") orelse return Error.InvalidResponse;
}

fn resolveEntry(self: *Quark, arena: std.mem.Allocator, path: []const u8) !Entry {
    var cur = Entry{ .id = self.cfg.root_folder_id, .name = "/", .is_dir = true };
    var it = std.mem.tokenizeAny(u8, path, "/\\");
    while (it.next()) |seg| {
        cur = try findChild(self, arena, cur.id, seg);
    }
    return cur;
}

fn findChild(self: *Quark, arena: std.mem.Allocator, parent: []const u8, name: []const u8) !Entry {
    var page: i64 = 1;
    while (true) {
        const data = try listPage(self, arena, parent, page);
        const children = arrAt(data, "list");
        for (children, 0..) |_, i| {
            const item = &children[i];
            const fn_ = item.strAt("file_name") orelse continue;
            const plain = try unescapeEntities(arena, fn_);
            if (std.mem.eql(u8, plain, name)) {
                return .{
                    .id = item.strAt("fid") orelse return Error.InvalidResponse,
                    .name = plain,
                    .is_dir = !(boolAt(item, "file") orelse false),
                    .raw = item,
                };
            }
        }
        const total = data.intAt("_total") orelse 0;
        if (children.len == 0 or page * page_size >= total) return driver.Error.NotFound;
        page += 1;
    }
}

// ---------------------------------------------------------------------------
// vtable
// ---------------------------------------------------------------------------

fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = try self.get(a, "/config", null);
    // Go: AdditionVersion != 2 时迁移到 2（并按需打开 WebProxy/WebdavPolicy，
    // 那两个字段本工程没有，故只做版本号迁移）。
    if (self.cfg.addition_version != 2) {
        self.cfg.addition_version = 2;
        const text = try self.cfg.toJson(a);
        driver.persist(self.storage_id, text);
    }
}

fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
    const self = as(ptr);
    _ = ctx;
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
        for (arrAt(data, "list")) |item| {
            const o = try objFromJson(a, &item);
            if (self.cfg.only_list_video_file and !o.is_dir and (item.intAt("category") orelse 0) != 1) continue;
            try out.append(o);
        }
        const total = data.intAt("_total") orelse 0;
        if (arrAt(data, "list").len == 0 or page * page_size >= total) break;
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
    const o = try objFromJson(a, raw);
    return .{ .name = o.name, .size = o.size, .is_dir = o.is_dir, .modified = o.modified, .created = o.created };
}

fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = args;
    const entry = try resolveEntry(self, a, path);
    if (entry.is_dir) return driver.Error.NotSupported;
    const raw = entry.raw;

    // 转码地址：仅 Quark、视频分类、且有大小（driver.go:66-71）
    if (self.cfg.use_transcoding_address and (raw != null and (raw.?.intAt("category") orelse 0) == 1) and (raw != null and (raw.?.intAt("size") orelse 0) > 0)) {
        const body = try std.fmt.allocPrint(a, "{{\"fid\":{s},\"resolutions\":\"low,normal,high,super,2k,4k\",\"supports\":\"fmp4_av,m3u8,dolby_vision\"}}", .{try jsonQuote(a, entry.id)});
        const res = try self.request(a, "/file/v2/play/project", "POST", null, body, ua);
        const v = json.parse(a, res) catch return Error.UpstreamNotJson;
        for (arrAt(&v, "data.video_list")) |item| {
            if (item.strAt("video_info.url")) |u| return .{ .url = try a.dupe(u8, u) };
        }
        return Error.InvalidResponse;
    }

    const body = try std.fmt.allocPrint(a, "{{\"fids\":[{s}]}}", .{try jsonQuote(a, entry.id)});
    const res = try self.request(a, "/file/download", "POST", null, body, ua);
    const v = json.parse(a, res) catch return Error.UpstreamNotJson;
    const url = v.strAt("data.0.download_url") orelse return Error.InvalidResponse;
    return .{
        .url = url,
        .header = &[_]model.Header{
            .{ .name = "Cookie", .value = self.cfg.cookie },
            .{ .name = "Referer", .value = referer },
            .{ .name = "User-Agent", .value = ua },
        },
    };
}

fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const name = pathBase(dir) orelse return Error.InvalidPath;
    const parent = try resolveEntry(self, a, pathParent(dir) orelse return Error.InvalidPath);
    const body = try std.fmt.allocPrint(a, "{{\"dir_init_lock\":false,\"dir_path\":\"\",\"file_name\":{s},\"pdir_fid\":{s}}}", .{ try jsonQuote(a, name), try jsonQuote(a, parent.id) });
    const res_body = try requestUnchecked(self, a, "/file", "POST", body);
    const v = json.parse(a, res_body) catch return Error.UpstreamNotJson;
    const status = v.intAt("status") orelse 0;
    const code = v.intAt("code") orelse 0;
    if (status < 400 and code == 0) {
        // Go 的成功路径**也会** sleep 1s 再返回（`driver.go:MakeDir`）——
        // 上游目录要过一会儿才在新父目录下可见，不等等的话紧接着的 list 会扑空。
        rt.sleepMillis(1000);
        return;
    }
    const msg = v.strAt("message") orelse "";
    // 同名冲突：Go 返回 `errs.ObjectAlreadyExists`（Go driver.go:86-87）。Zig 用
    // `error.TargetExists` 对齐（api.zig mapDriverError 映射到 409），不再用
    // `NotSupported`（那会被框架当成「驱动不支持」而非「已存在」）。
    if (std.mem.indexOf(u8, msg, "同名冲突") != null) {
        rt.sleepMillis(1000);
        return error.TargetExists;
    }
    log.warn("[quark] mkdir {s}: {s}", .{ name, msg });
    return Error.UpstreamError;
}

fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const entry = try resolveEntry(self, a, src);
    const dst = try resolveEntry(self, a, dst_dir);
    const body = try std.fmt.allocPrint(a, "{{\"action_type\":1,\"exclude_fids\":[],\"filelist\":[{s}],\"to_pdir_fid\":{s}}}", .{ try jsonQuote(a, entry.id), try jsonQuote(a, dst.id) });
    _ = try self.post(a, "/file/move", body);
}

fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const entry = try resolveEntry(self, a, src);
    const body = try std.fmt.allocPrint(a, "{{\"fid\":{s},\"file_name\":{s}}}", .{ try jsonQuote(a, entry.id), try jsonQuote(a, new_name) });
    _ = try self.post(a, "/file/rename", body);
}

fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    _ = is_dir;
    const entry = try resolveEntry(self, a, path);
    const body = try std.fmt.allocPrint(a, "{{\"action_type\":1,\"exclude_fids\":[],\"filelist\":[{s}]}}", .{try jsonQuote(a, entry.id)});
    _ = try self.post(a, "/file/delete", body);
}

fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
    const self = as(ptr);
    const a = ctx.alloc;
    const body = try self.get(a, "/member", "&fetch_subscribe=false&_ch=home&fetch_identity=false");
    const v = json.parse(a, body) catch return Error.UpstreamNotJson;
    return .{
        .total = v.intAt("data.total_capacity") orelse 0,
        .used = v.intAt("data.use_capacity") orelse 0,
    };
}

fn jsonQuote(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var b = Buf.init(a);
    try json.writeString(&b, s);
    return b.toOwned();
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
// 上传（util.go:170-345）
// ---------------------------------------------------------------------------

/// 整文件哈希的读取块（T7：同一块 buffer 复用）。
const hash_block = 128 * 1024;

const UpPre = struct {
    task_id: []const u8,
    upload_id: []const u8,
    obj_key: []const u8,
    upload_url: []const u8,
    bucket: []const u8,
    auth_info: []const u8,
    part_size: i64,
    /// `data.callback` 的原始 JSON（Go：`pre.Data.Callback`，`util.go:281`）。
    /// commit 阶段要原样 base64 回填 `x-oss-callback`，不能自己造一个空对象。
    callback_json: []const u8,
};

fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
    const self = as(ptr);
    const a = ctx.alloc;
    const size = src.size();
    if (size < 0) return Error.InvalidPath;
    const name = pathBase(dst) orelse return Error.InvalidPath;
    const parent = try resolveEntry(self, a, pathParent(dst) orelse return Error.InvalidPath);

    // 1) MD5 + SHA1（一遍读、一块 buffer）
    var md5 = hash.Md5.init(.{});
    var sha1 = hash.Sha1.init(.{});
    const buf = try a.alloc(u8, @intCast(@min(@as(i64, hash_block), @max(size, 1))));
    {
        var off: u64 = 0;
        while (off < @as(u64, @intCast(size))) {
            const want: usize = @intCast(@min(@as(i64, @intCast(buf.len)), size - @as(i64, @intCast(off))));
            try src.readAllInto(off, buf[0..want]);
            md5.update(buf[0..want]);
            sha1.update(buf[0..want]);
            off += want;
        }
    }
    var d5: [16]u8 = undefined;
    md5.final(&d5);
    var d1: [20]u8 = undefined;
    sha1.final(&d1);
    const md5_hex = try hash.hexLower(a, &d5);
    const sha1_hex = try hash.hexLower(a, &d1);

    // 2) pre
    const now_ms = rt.nowMillis();
    // Go 用 `file.GetMimetype()`（= `utils.GetMimeType(name)`），不是恒定的
    // octet-stream。夸克拿它做上传分类，推错不影响上传本身。
    const content_type = mime.mimeFor(name);
    const pre_body = try std.fmt.allocPrint(a,
        "{{\"ccp_hash_update\":true,\"dir_name\":\"\",\"file_name\":{s},\"format_type\":\"{s}\",\"l_created_at\":{d},\"l_updated_at\":{d},\"pdir_fid\":{s},\"size\":{d}}}",
        .{ try jsonQuote(a, name), content_type, now_ms, now_ms, try jsonQuote(a, parent.id), size },
    );
    const pre_res = try self.post(a, "/file/upload/pre", pre_body);
    const pv = json.parse(a, pre_res) catch return Error.UpstreamNotJson;
    const pre = UpPre{
        .task_id = pv.strAt("data.task_id") orelse return Error.InvalidResponse,
        .upload_id = pv.strAt("data.upload_id") orelse return Error.InvalidResponse,
        .obj_key = pv.strAt("data.obj_key") orelse return Error.InvalidResponse,
        .upload_url = pv.strAt("data.upload_url") orelse return Error.InvalidResponse,
        .bucket = pv.strAt("data.bucket") orelse return Error.InvalidResponse,
        .auth_info = pv.strAt("data.auth_info") orelse return Error.InvalidResponse,
        .part_size = pv.intAt("metadata.part_size") orelse 4 * 1024 * 1024,
        // Go `utils.Json.Marshal(pre.Data.Callback)`：缺省（nil map）序列化成
        // 字面量 `null`，所以这里也回退到 "null" 而不是 "{}"。
        .callback_json = if (pv.getPath("data.callback")) |cv|
            (json.stringify(a, cv) catch return Error.InvalidResponse)
        else
            "null",
    };

    // 3) hash（秒传判定）
    const hash_body = try std.fmt.allocPrint(a, "{{\"md5\":\"{s}\",\"sha1\":\"{s}\",\"task_id\":{s}}}", .{ md5_hex, sha1_hex, try jsonQuote(a, pre.task_id) });
    const hash_res = try self.post(a, "/file/update/hash", hash_body);
    const hv = json.parse(a, hash_res) catch return Error.UpstreamNotJson;
    if (boolAt(&hv, "data.finish") orelse false) {
        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
        return;
    }

    // 4) 逐片上传
    const part_size: i64 = @max(pre.part_size, 1);
    const count: i64 = @divTrunc(size + part_size - 1, part_size);
    const chunk_buf = try a.alloc(u8, @intCast(part_size));
    var etags = try a.alloc([]const u8, @intCast(count));
    {
        var idx: i64 = 1;
        while (idx <= count) : (idx += 1) {
            const off: u64 = @intCast((idx - 1) * part_size);
            const len: usize = @intCast(@min(part_size, size - @as(i64, @intCast(off))));
            try src.readAllInto(off, chunk_buf[0..len]);
            // Go 用 `retry.Do(..., Attempts(3), BackOffDelay, Delay(1s))`
            // （driver.go:193-209）：分片偶发失败要重试，退避递增。
            etags[@intCast(idx - 1)] = blk: {
                var attempt: u8 = 0;
                while (true) : (attempt += 1) {
                    if (upPart(self, a, pre, idx, chunk_buf[0..len], content_type)) |etag| {
                        break :blk etag;
                    } else |e| {
                        if (attempt + 1 >= 3) return e;
                        log.warn("[quark] part {d} attempt {d} failed: {s}; retrying", .{ idx, attempt + 1, @errorName(e) });
                        rt.sleepMillis(1000 * (@as(i64, 1) << @intCast(attempt))); // 1s, 2s
                    }
                }
            };
            const done: u64 = off + @as(u64, len);
            if (ctx.progress) |f| f(ctx.progress_userdata, done * 95 / @max(@as(u64, @intCast(size)), 1));
        }
    }

    // 5) commit + finish
    try upCommit(self, a, pre, etags);
    const fin_body = try std.fmt.allocPrint(a, "{{\"obj_key\":{s},\"task_id\":{s}}}", .{ try jsonQuote(a, pre.obj_key), try jsonQuote(a, pre.task_id) });
    _ = try self.post(a, "/file/upload/finish", fin_body);
    // Go: upFinish 之后固定 sleep 1s（让上游把文件挂进目录）
    rt.sleepMillis(1000);
    if (ctx.progress) |f| f(ctx.progress_userdata, 100);
}

/// OSS 上传域名：Go `fmt.Sprintf("https://%s.%s/%s", bucket, upload_url[7:], obj_key)`
/// （`upload_url` 形如 `https://host`，去掉 7 个字符即 `https://`）。
fn ossUrl(a: std.mem.Allocator, pre: UpPre, extra_query: []const u8) ![]const u8 {
    const host = if (pre.upload_url.len > 7) pre.upload_url[7..] else pre.upload_url;
    if (extra_query.len > 0) {
        return std.fmt.allocPrint(a, "https://{s}.{s}/{s}?{s}", .{ pre.bucket, host, pre.obj_key, extra_query });
    }
    return std.fmt.allocPrint(a, "https://{s}.{s}/{s}", .{ pre.bucket, host, pre.obj_key });
}

/// 拿一次 OSS 授权（util.go:204-225）。`auth_meta` 是要签名的规范串。
fn upAuth(self: *Quark, a: std.mem.Allocator, pre: UpPre, auth_meta: []const u8) ![]const u8 {
    const body = try std.fmt.allocPrint(a, "{{\"auth_info\":{s},\"auth_meta\":{s},\"task_id\":{s}}}", .{
        try jsonQuote(a, pre.auth_info), try jsonQuote(a, auth_meta), try jsonQuote(a, pre.task_id),
    });
    const res = try self.post(a, "/file/upload/auth", body);
    const v = json.parse(a, res) catch return Error.UpstreamNotJson;
    return v.strAt("data.auth_key") orelse return Error.InvalidResponse;
}

fn httpDate(a: std.mem.Allocator) ![]const u8 {
    return cookiejar.httpDate(a, rt.nowSeconds());
}

fn upPart(self: *Quark, a: std.mem.Allocator, pre: UpPre, part_no: i64, chunk: []const u8, content_type: []const u8) ![]const u8 {
    const date = try httpDate(a);
    const path = try std.fmt.allocPrint(a, "/{s}/{s}?partNumber={d}&uploadId={s}", .{ pre.bucket, pre.obj_key, part_no, pre.upload_id });
    // `Content-Type` 必须与签名串里的那个一致 —— Go 传的是 `stream.GetMimetype()`
    // （driver.go:195），不是恒定值。
    const auth_meta = try std.fmt.allocPrint(a, "PUT\n\n{s}\n{s}\nx-oss-date:{s}\nx-oss-user-agent:{s}\n{s}", .{
        content_type, date, date, oss_ua, path,
    });
    const auth_key = try upAuth(self, a, pre, auth_meta);
    const q = try std.fmt.allocPrint(a, "partNumber={d}&uploadId={s}", .{ part_no, pre.upload_id });
    const res = self.client.send(a, .{
        .method = "PUT",
        .url = try ossUrl(a, pre, q),
        .headers = &[_]model.Header{
            .{ .name = "Authorization", .value = auth_key },
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Referer", .value = referer ++ "/" },
            .{ .name = "x-oss-date", .value = date },
            .{ .name = "x-oss-user-agent", .value = oss_ua },
        },
        .body = chunk,
        .use_cookies = false,
    }) catch return Error.UploadFailed;
    if (res.status != 200) {
        log.warn("[quark] part {d} HTTP {d}", .{ part_no, res.status });
        return Error.UploadFailed;
    }
    return res.header("ETag") orelse return Error.InvalidResponse;
}

fn upCommit(self: *Quark, a: std.mem.Allocator, pre: UpPre, etags: [][]const u8) !void {
    // <CompleteMultipartUpload><Part><PartNumber>..</PartNumber><ETag>..</ETag></Part>..
    var xml = Buf.init(a);
    try xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CompleteMultipartUpload>\n");
    for (etags, 0..) |e, i| {
        try xml.print("<Part>\n<PartNumber>{d}</PartNumber>\n<ETag>{s}</ETag>\n</Part>\n", .{ i + 1, e });
    }
    try xml.append("</CompleteMultipartUpload>");

    const xml_md5 = hash.md5(xml.slice());
    var md5_b64_buf: [std.base64.standard.Encoder.calcSize(16)]u8 = undefined;
    const content_md5 = std.base64.standard.Encoder.encode(&md5_b64_buf, &xml_md5);

    // callback JSON → base64（Go: `utils.Json.Marshal(pre.Data.Callback)`，
    // `util.go:281-285`）。这个 JSON 是 pre 阶段上游给的，原样回填；自己造空对象
    // 会让 OSS 回调体对不上，115 侧无法完成入库。
    const cb_json = pre.callback_json;
    const cb_b64_buf = a.alloc(u8, std.base64.standard.Encoder.calcSize(cb_json.len)) catch return Error.UploadFailed;
    const callback_b64 = std.base64.standard.Encoder.encode(cb_b64_buf, cb_json);

    const date = try httpDate(a);
    const path = try std.fmt.allocPrint(a, "/{s}/{s}?uploadId={s}", .{ pre.bucket, pre.obj_key, pre.upload_id });
    const auth_meta = try std.fmt.allocPrint(a, "POST\n{s}\napplication/xml\n{s}\nx-oss-callback:{s}\nx-oss-date:{s}\nx-oss-user-agent:{s}\n{s}", .{
        content_md5, date, callback_b64, date, oss_ua, path,
    });
    const auth_key = try upAuth(self, a, pre, auth_meta);

    const res = self.client.send(a, .{
        .method = "POST",
        .url = try ossUrl(a, pre, try std.fmt.allocPrint(a, "uploadId={s}", .{pre.upload_id})),
        .headers = &[_]model.Header{
            .{ .name = "Authorization", .value = auth_key },
            .{ .name = "Content-MD5", .value = content_md5 },
            .{ .name = "Content-Type", .value = "application/xml" },
            .{ .name = "Referer", .value = referer ++ "/" },
            .{ .name = "x-oss-callback", .value = callback_b64 },
            .{ .name = "x-oss-date", .value = date },
            .{ .name = "x-oss-user-agent", .value = oss_ua },
        },
        .body = xml.slice(),
        .use_cookies = false,
    }) catch return Error.UploadFailed;
    if (res.status != 200) {
        log.warn("[quark] commit HTTP {d}: {s}", .{ res.status, res.body[0..@min(res.body.len, 200)] });
        return Error.UploadFailed;
    }
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    // 逐字等于 Go 的 `driver.Config.Name`（drivers/quark_uc/meta.go:30）。
    .key = "Quark",
    .label = "夸克网盘",
    .secrets = &.{"cookie"},
    .addition_schema =
    \\{
    \\  "cookie":                   {"type":"string","required":true,"secret":true,"help":"浏览器里抓的 Cookie（含 __pus/__puus 等）"},
    \\  "root_folder_id":           {"type":"string","default":"0","help":"根目录 fid，夸克的根是 0"},
    \\  "order_by":                 {"type":"select","default":"none","options":["none","file_type","file_name","updated_at"],"help":"排序字段"},
    \\  "order_direction":          {"type":"select","default":"asc","options":["asc","desc"],"help":"排序方向"},
    \\  "use_transcoding_address":  {"type":"bool","default":false,"help":"视频走转码地址（可 302）"},
    \\  "only_list_video_file":     {"type":"bool","default":false,"help":"只列出视频与目录"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    return driver.asDriver(Quark, try createWithId(alloc, storage_id, cfg));
}

pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Quark {
    const self = try alloc.create(Quark);
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
// 测试 —— 纯逻辑
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testArena() std.heap.ArenaAllocator {
    return std.heap.ArenaAllocator.init(testing.allocator);
}

test "T2/T3: real Go addition JSON (backup shape) parses into the driver" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与用户 Go 备份 storage #8 一致：['AdditionVersion','cookie',
    // 'only_list_video_file','order_by','order_direction','root_folder_id']
    const src =
        \\{"cookie":"__pus=xx; __puus=yy","root_folder_id":"0","order_by":"none",
        \\ "order_direction":"asc","use_transcoding_address":false,
        \\ "only_list_video_file":false,"AdditionVersion":2}
    ;
    const v = try json.parse(a, src);
    const add = try Addition.parse(a, &v);
    try testing.expectEqualStrings("__pus=xx; __puus=yy", add.cookie);
    try testing.expectEqual(@as(i64, 2), add.addition_version);
    try testing.expectEqualStrings("none", add.order_by);

    const out = try add.toJson(a);
    try testing.expect(std.mem.indexOf(u8, out, "\"AdditionVersion\":2") != null);
    const v2 = try json.parse(a, out);
    const add2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(add.cookie, add2.cookie);
}

test "T2: defaults match Go" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const add = try Addition.parse(a, null);
    try testing.expectEqualStrings("0", add.root_folder_id);
    try testing.expectEqualStrings("none", add.order_by);
    try testing.expectEqualStrings("asc", add.order_direction);
    try testing.expect(!add.use_transcoding_address);
}

test "T2: setCookieValue replaces and appends" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const replaced = try setCookieValue(a, "UID=1; __puus=old; CID=2", "__puus", "new");
    try testing.expectEqualStrings("UID=1; __puus=new; CID=2", replaced);

    const appended = try setCookieValue(a, "UID=1", "__puus", "new");
    try testing.expectEqualStrings("UID=1; __puus=new", appended);

    const only = try setCookieValue(a, "", "__puus", "new");
    try testing.expectEqualStrings("__puus=new", only);
}

test "T2: unescapeEntities decodes the full entity set (Go html.UnescapeString)" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    // 基本的五个 + 数字实体 + 十六进制 + 命名实体（以前只认 5 个，其余全漏）。
    try testing.expectEqualStrings("a&b<c>d\"e'f", try unescapeEntities(a, "a&amp;b&lt;c&gt;d&quot;e&#39;f"));
    try testing.expectEqualStrings("a'b", try unescapeEntities(a, "a&#x27;b"));
    try testing.expectEqualStrings("x\u{00A0}y", try unescapeEntities(a, "x&nbsp;y"));
    try testing.expectEqualStrings("A\u{2014}B", try unescapeEntities(a, "A&mdash;B"));
    try testing.expectEqualStrings("\u{03B1}", try unescapeEntities(a, "&alpha;"));
    // 认不出来就原样保留。
    try testing.expectEqualStrings("&nope;", try unescapeEntities(a, "&nope;"));
    // 没有 & 时原样返回（不分配新串的路径也覆盖到）
    try testing.expectEqualStrings("plain.txt", try unescapeEntities(a, "plain.txt"));
}

test "T2: list JSON parses quark file entries (is_dir = !file)" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();

    const body =
        \\{"status":200,"code":0,"data":{"list":[
        \\ {"fid":"f1","file_name":"a.txt","category":0,"size":12,"file":true,"created_at":1700000000000,"updated_at":1700000000000},
        \\ {"fid":"d1","file_name":"sub","category":0,"size":0,"file":false,"created_at":1700000000000,"updated_at":1700000000000}]},
        \\ "metadata":{"_size":100,"_page":1,"_count":2,"_total":2}}
    ;
    const v = try json.parse(a, body);
    const data = v.getPath("data").?;
    const items = arrAt(data, "list");
    try testing.expectEqual(@as(usize, 2), items.len);
    const o1 = try objFromJson(a, &items[0]);
    try testing.expectEqualStrings("a.txt", o1.name);
    try testing.expect(!o1.is_dir);
    try testing.expectEqual(@as(i64, 1700000000), o1.modified); // 毫秒 → 秒
    const o2 = try objFromJson(a, &items[1]);
    try testing.expect(o2.is_dir);
    try testing.expectEqual(@as(i64, 2), v.intAt("metadata._total").?);
}

test "T2: createWithId builds a driver with the expected name" {
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const self = try createWithId(a, 8, null);
    defer self.client.deinit();
    try testing.expectEqual(@as(i64, 8), self.storage_id);
    try testing.expectEqualStrings("Quark", Quark.drvName(@ptrCast(self)));
    try testing.expectEqualStrings("Quark", factory.key);
}



test "T2: copy is NotSupported, matching Go" {
    // Go `drivers/quark_uc/driver.go:116-118` 的 Copy 就是 `return errs.NotSupport`。
    // 夸克服务端没有服务端复制接口，上游因此不做。`Driver.copy` 的默认槽
    // 语义（driver.zig）正好给出同一个错误。
    var arena = testArena();
    defer arena.deinit();
    const a = arena.allocator();
    const self = try createWithId(a, 9, null);
    defer self.client.deinit();
    const d = driver.asDriver(Quark, self);
    var ctx = driver.Ctx{ .alloc = a };
    try testing.expectError(driver.Error.NotSupported, d.copy(&ctx, "/src", "/dst"));
}
