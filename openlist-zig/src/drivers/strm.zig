//! Strm —— 把同一实例里**其他挂载**的媒体目录映射成 `.strm` 虚拟文件。
//!
//! 严格对照 Go `drivers/strm/`（meta.go / driver.go / util.go / hook.go）：
//! - 注册名 `Strm`（meta.go:31 `driver.Config.Name`）；
//! - Addition 字段名与 json tag 逐字节一致（含大写开头的 `PathPrefix`、
//!   `SaveStrmToLocal` 等 —— Go 的 tag 就这么写，配置里存的是它）；
//! - `paths` 每行一条：`key:dst`（key 不含 `/`）或裸 `dst`（key = dst 的
//!   base 名）；只有一条 key 时 autoFlatten —— 根目录直接展开 dst 内容；
//! - 媒体后缀（filterFileTypes）→ 同名 `.strm` 虚拟文件，size = 链接文本长度；
//!   字幕后缀（downloadFileTypes）→ 原样透传；其余丢弃；
//! - `.strm` 的"文件内容" = `getLink(path)`（编码/签名/前缀规则见 getLinkText），
//!   Go 用 RangeReader 返回这段文本，本工程用 `Link.text`；
//! - `OnlyProxy: true` ⇒ 一切下载走服务端代理（Link.proxy = true）；
//! - SaveStrmToLocal：注册 objs-update 钩子，把 `.strm`/字幕按 insert/update/sync
//!   三种模式写到本地目录（Go hook.go 的 UpdateLocalStrm）。
//!
//! Go 侧直接调 `internal/fs` 回到本实例；本工程经 `driver.fs_bridge`（App 安装）。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const urlmod = @import("../util/url.zig");
const log = @import("../log.zig");
const rt = @import("../rt.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const client_mod = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");

pub const save_local_insert = "insert";
pub const save_local_update = "update";
pub const save_local_sync = "sync";

/// Go meta.go:101 / :89 的两个默认清单（Version<5 迁移时用来补全）。
const default_filter_types = "mp4,mkv,flv,avi,wmv,ts,rmvb,webm,mp3,flac,aac,wav,ogg,m4a,wma,alac";
const default_download_types = "ass,srt,vtt,sub,strm";

// ---------------------------------------------------------------------------
// Addition —— json 名与 Go meta.go:14-28 逐字节一致
// ---------------------------------------------------------------------------

pub const Addition = struct {
    paths: []const u8 = "",
    site_url: []const u8 = "",
    path_prefix: []const u8 = "/d",
    download_file_types: []const u8 = default_download_types,
    filter_file_types: []const u8 = default_filter_types,
    min_file_size: i64 = 0,
    encode_path: bool = true,
    without_url: bool = false,
    with_sign: bool = false,
    save_strm_to_local: bool = false,
    save_strm_local_path: []const u8 = "",
    save_local_mode: []const u8 = "",
    version: i64 = 0,

    fn str(v: ?*const json.Value, key: []const u8, default: []const u8) []const u8 {
        const val = (v orelse return default).getPath(key) orelse return default;
        return val.asStr() orelse default;
    }
    fn int(v: ?*const json.Value, key: []const u8, default: i64) i64 {
        const val = (v orelse return default).getPath(key) orelse return default;
        return val.asInt() orelse default;
    }
    fn boolean(v: ?*const json.Value, key: []const u8, default: bool) bool {
        const val = (v orelse return default).getPath(key) orelse return default;
        return val.asBool() orelse default;
    }

    pub fn parse(alloc: std.mem.Allocator, cfg: ?*const json.Value) !Addition {
        // Go 的 driver 框架在存储创建时按 tag 填默认值；配置里缺键 ⇒ 同一默认。
        // Version 缺键：Go int 默认 0 ⇒ 触发 Init 的迁移逻辑。
        return .{
            .paths = try alloc.dupe(u8, str(cfg, "paths", "")),
            .site_url = try alloc.dupe(u8, str(cfg, "siteUrl", "")),
            .path_prefix = try alloc.dupe(u8, str(cfg, "PathPrefix", "/d")),
            .download_file_types = try alloc.dupe(u8, str(cfg, "downloadFileTypes", default_download_types)),
            .filter_file_types = try alloc.dupe(u8, str(cfg, "filterFileTypes", default_filter_types)),
            .min_file_size = int(cfg, "minFileSize", 0),
            .encode_path = boolean(cfg, "encodePath", true),
            .without_url = boolean(cfg, "withoutUrl", false),
            .with_sign = boolean(cfg, "withSign", false),
            .save_strm_to_local = boolean(cfg, "SaveStrmToLocal", false),
            .save_strm_local_path = try alloc.dupe(u8, str(cfg, "SaveStrmLocalPath", "")),
            .save_local_mode = try alloc.dupe(u8, str(cfg, "SaveLocalMode", "")),
            .version = int(cfg, "Version", 0),
        };
    }
};

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// 一条 `paths` 行的解析结果：`key` 是挂载内展示的目录名，`dsts` 是它映射到的
/// 一个或多个本实例路径（同一 key 可出现多行 ⇒ 多源合并，Go driver.go:55）。
const Entry = struct {
    key: []const u8,
    dsts: List([]const u8),
};

pub const Strm = struct {
    alloc: std.mem.Allocator,
    storage_id: i64,
    a: Addition,

    /// 挂载路径（init 时从 ctx.tag 取，SaveStrmToLocal 的本地目录推导要用）。
    mount_path: []const u8 = "/",

    entries: List(Entry),
    one_key: []const u8 = "",
    auto_flatten: bool = false,

    /// 归一化（小写、去空白）后的后缀清单，逗号连接；成员判断用 extInList。
    support_suffix: []const u8 = "",
    download_suffix: []const u8 = "",
    min_size_bytes: i64 = 0,

    pub const vtable = driver.Driver.VTable{
        .name = name,
        .init = init,
        .deinit = deinit,
        .list = list,
        .details = details,
        .link = link,
        .makeDir = unsupportedMkdir,
        .move = unsupportedMove,
        .rename = unsupportedRename,
        .remove = unsupportedRemove,
        .put = unsupportedPut,
        .copy = null,
        .space = null,
    };

    fn name(_: *anyopaque) []const u8 {
        return "Strm";
    }

    fn unsupported(_: *anyopaque, _: *driver.Ctx) anyerror!void {
        return error.NotSupported;
    }
    fn unsupportedMkdir(_: *anyopaque, _: *driver.Ctx, _: []const u8) anyerror!void {
        return error.NotSupported;
    }
    fn unsupportedMove(_: *anyopaque, _: *driver.Ctx, _: []const u8, _: []const u8) anyerror!void {
        return error.NotSupported;
    }
    fn unsupportedRename(_: *anyopaque, _: *driver.Ctx, _: []const u8, _: []const u8) anyerror!void {
        return error.NotSupported;
    }
    fn unsupportedRemove(_: *anyopaque, _: *driver.Ctx, _: []const u8, _: bool) anyerror!void {
        return error.NotSupported;
    }
    fn unsupportedPut(_: *anyopaque, _: *driver.Ctx, _: []const u8, _: model.Source) anyerror!void {
        return error.NotSupported;
    }

    // ---- init / deinit ----------------------------------------------------

    fn init(p: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(p);
        const a = self.alloc;

        // 重入防护（config reload 会再次 init）：先清上一轮的派生状态。
        self.resetDerived();

        self.mount_path = try a.dupe(u8, ctx.tag);

        // Go driver.go:42-47
        if (self.a.paths.len == 0) return error.PathsRequired;
        if (self.a.save_strm_to_local and self.a.save_strm_local_path.len == 0) {
            return error.SaveStrmLocalPathRequired;
        }

        // Go driver.go:48-63：解析 paths（每行一条，trim 后跳过空行）。
        var entries = List(Entry).init(a);
        var it = std.mem.splitScalar(u8, self.a.paths, '\n');
        while (it.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (line.len == 0) continue;
            const pair = getPair(line);
            const dst = try a.dupe(u8, pair.dst);
            var found = false;
            for (entries.sliceMut()) |*slot| {
                if (std.mem.eql(u8, slot.key, pair.key)) {
                    try slot.dsts.append(dst);
                    found = true;
                    break;
                }
            }
            if (!found) {
                var dsts = List([]const u8).init(a);
                try dsts.append(dst);
                try entries.append(.{ .key = try a.dupe(u8, pair.key), .dsts = dsts });
            }
        }
        self.entries = entries;

        // Go driver.go:64-72：恰好一条 key ⇒ autoFlatten。
        if (self.entries.slice().len == 1) {
            self.one_key = self.entries.slice()[0].key;
            self.auto_flatten = true;
        } else {
            self.one_key = "";
            self.auto_flatten = false;
        }

        // Go driver.go:74-98：后缀集合（空 ⇒ 默认清单）。
        self.support_suffix = try a.dupe(u8, if (self.a.filter_file_types.len == 0)
            default_filter_types
        else
            self.a.filter_file_types);
        self.download_suffix = try a.dupe(u8, if (self.a.download_file_types.len == 0)
            default_download_types
        else
            self.a.download_file_types);

        // Go driver.go:100-120：Version != 5 ⇒ 迁移（补全两个清单、强制
        // PathPrefix="/d"、Version=5）。本工程不回写 addition，迁移只在
        // 内存里生效 —— 每次启动结果一致，与 Go 落库后的行为相同。
        if (self.a.version != 5) {
            self.support_suffix = try mergeTypes(a, self.support_suffix, default_filter_types);
            self.download_suffix = try mergeTypes(a, self.download_suffix, default_download_types);
            self.alloc.free(self.a.path_prefix);
            self.a.path_prefix = try a.dupe(u8, "/d");
            self.a.version = 5;
        }
        if (self.a.save_local_mode.len == 0) {
            self.a.save_local_mode = try a.dupe(u8, save_local_insert);
        }
        // Go driver.go:124：MinFileSize * 1024 * 1024（Go 溢出静默回绕，照抄）。
        self.min_size_bytes = self.a.min_file_size *% 1024 *% 1024;

        if (self.a.save_strm_to_local) {
            registerInstance(self);
            // Go 在包 init() 里 op.RegisterObjsUpdateHook(UpdateLocalStrm)；
            // 本工程注册到 driver 层的单槽钩子。
            driver.registerObjsUpdateHook(updateLocalStrmHook, self);
        }
    }

    /// 释放 init 派生的内存（重入与 deinit 共用）。
    fn resetDerived(self: *Strm) void {
        if (self.mount_path.len > 0 and !std.mem.eql(u8, self.mount_path, "/")) {
            self.alloc.free(self.mount_path);
        }
        self.mount_path = "/";
        for (self.entries.slice()) |e| {
            self.alloc.free(e.key);
            for (e.dsts.slice()) |d| self.alloc.free(d);
            var mut = e.dsts;
            mut.deinit();
        }
        var entries = self.entries;
        entries.deinit();
        self.entries = List(Entry).init(self.alloc);
        if (self.support_suffix.len > 0) self.alloc.free(self.support_suffix);
        if (self.download_suffix.len > 0) self.alloc.free(self.download_suffix);
        self.support_suffix = "";
        self.download_suffix = "";
    }

    fn deinit(p: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(p);
        unregisterInstance(self);
        _ = ctx;
        self.resetDerived();
        self.alloc.free(self.a.paths);
        self.alloc.free(self.a.site_url);
        self.alloc.free(self.a.path_prefix);
        self.alloc.free(self.a.download_file_types);
        self.alloc.free(self.a.filter_file_types);
        self.alloc.free(self.a.save_strm_local_path);
        self.alloc.free(self.a.save_local_mode);
        self.alloc.destroy(self);
    }

    // ---- 路径解析（Go util.go:32-53）--------------------------------------

    /// Go `getPair`：`key:dst`（key 不含 `/`）或裸 `dst`（key = Base(dst)）。
    fn getPair(line: []const u8) struct { key: []const u8, dst: []const u8 } {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const k = line[0..colon];
            if (k.len > 0 and std.mem.indexOfScalar(u8, k, '/') == null) {
                return .{ .key = k, .dst = line[colon + 1 ..] };
            }
        }
        return .{ .key = baseName(line), .dst = line };
    }

    /// Go `getRootAndPath`。
    fn getRootAndPath(self: *const Strm, path: []const u8) struct { root: []const u8, sub: []const u8 } {
        if (self.auto_flatten) return .{ .root = self.one_key, .sub = path };
        var p = path;
        if (std.mem.startsWith(u8, p, "/")) p = p[1..];
        if (std.mem.indexOfScalar(u8, p, '/')) |slash| {
            return .{ .root = p[0..slash], .sub = p[slash + 1 ..] };
        }
        return .{ .root = p, .sub = "" };
    }

    fn findEntry(self: *const Strm, key: []const u8) ?*const Entry {
        for (self.entries.slice()) |*e| {
            if (std.mem.eql(u8, e.key, key)) return e;
        }
        return null;
    }

    // ---- list / details / link ---------------------------------------------

    fn list(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(p);
        const a = ctx.alloc;
        const bridge = driver.fs_bridge orelse return error.NotFound;

        // Go driver.go:179-181：非 autoFlatten 时根目录 = key 目录列表。
        if (std.mem.eql(u8, dir, "/") and !self.auto_flatten) {
            var out = List(model.Obj).init(a);
            for (self.entries.slice()) |*e| {
                try out.append(.{ .name = e.key, .is_dir = true, .modified = 0 });
            }
            return out.toOwned();
        }

        const split = self.getRootAndPath(dir);
        const entry = self.findEntry(split.root) orelse return error.NotFound;

        var out = List(model.Obj).init(a);
        for (entry.dsts.slice()) |dst| {
            const req_path = try joinClean(a, dst, split.sub);
            const objs = bridge.list(bridge.ctx, a, req_path) catch |e| {
                // Go driver.go:189-194：单个 dst 失败静默跳过（多源合并语义）。
                log.debug("[strm] list {s} failed: {s}", .{ req_path, @errorName(e) });
                continue;
            };
            try self.appendConverted(a, req_path, objs, &out);
        }
        return out.toOwned();
    }

    fn details(p: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(p);
        const a = ctx.alloc;
        const bridge = driver.fs_bridge orelse return error.NotFound;

        const split = self.getRootAndPath(path);
        const entry = self.findEntry(split.root) orelse return error.NotFound;

        // Go driver.go:142-168：fs.Get 命中 ⇒ 真实对象。
        for (entry.dsts.slice()) |dst| {
            const req_path = try joinClean(a, dst, split.sub);
            const obj = bridge.get(bridge.ctx, a, req_path) catch continue;
            return .{
                .name = obj.name,
                .size = if (obj.is_dir) 0 else obj.size,
                .is_dir = obj.is_dir,
                .modified = obj.modified,
                .created = 0,
                .hash_info = obj.hash_info,
            };
        }

        // Go driver.go:169-173 + op.Get 的 NotSupport 回退：.strm 不在上游，
        // op.Get 会扫父目录列表。这里直接扫父目录找到该虚拟条目。
        if (std.mem.endsWith(u8, split.sub, ".strm")) {
            if (try self.lookupStrmEntry(a, bridge, entry, split.sub)) |f| return f;
        }
        return error.NotFound;
    }

    /// 在父目录列表里找 `.strm` 虚拟条目（details 与 link 共用）。
    fn lookupStrmEntry(
        self: *const Strm,
        a: std.mem.Allocator,
        bridge: driver.FsBridge,
        entry: *const Entry,
        sub: []const u8,
    ) !?model.File {
        const parent = dirnameOf(sub);
        const base = baseName(sub);
        for (entry.dsts.slice()) |dst| {
            const req_path = try joinClean(a, dst, parent);
            const objs = bridge.list(bridge.ctx, a, req_path) catch continue;
            var converted = List(model.Obj).init(a);
            defer converted.deinit();
            try self.appendConverted(a, req_path, objs, &converted);
            for (converted.slice()) |o| {
                if (std.mem.eql(u8, o.name, base)) {
                    return .{
                        .name = o.name,
                        .size = o.size,
                        .is_dir = false,
                        .modified = o.modified,
                        .created = 0,
                        // 携带原始媒体路径，link() 直接用它生成 URL 文本。
                        .sign = o.sign,
                    };
                }
            }
        }
        return null;
    }

    fn link(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: model.LinkArgs) anyerror!model.Link {
        const self = as(p);
        const a = ctx.alloc;
        const bridge = driver.fs_bridge orelse return error.NotFound;

        const split = self.getRootAndPath(path);
        const entry = self.findEntry(split.root) orelse return error.NotFound;

        // 透传文件（字幕等）：返回**目标挂载**的真实链接。Go Down 对
        // OnlyProxy 存储直接走服务端代理（server/handles/down.go 的
        // ShouldProxy 分支），本工程用 `proxy = true` 表达同一语义。
        for (entry.dsts.slice()) |dst| {
            const req_path = try joinClean(a, dst, split.sub);
            const obj = bridge.get(bridge.ctx, a, req_path) catch continue;
            _ = obj;
            var lk = try bridge.link(bridge.ctx, a, req_path, args);
            lk.proxy = true;
            return lk;
        }

        // 虚拟 .strm：内容 = getLink(原始媒体路径)。原始路径无法从
        // "xxx.strm" 反推（原始后缀丢了），与 Go op.Get 的 NotSupport 回退
        // 一样扫父目录列表拿 ID/Path（driver.go:199-204 的 GetID()=="strm"）。
        if (std.mem.endsWith(u8, split.sub, ".strm")) {
            if (try self.lookupStrmEntry(a, bridge, entry, split.sub)) |f| {
                // Go 的 getLink 在**请求上下文**里执行（下载 .strm 时），所以
                // URL 前缀取 scheme://Host —— 把请求头传进去对齐这一行为。
                const content = try self.getLinkTextWithOrigin(a, f.sign, args.headers);
                return .{ .url = "", .text = content, .proxy = true };
            }
        }
        return error.NotFound;
    }

    // ---- getLink（Go util.go:109-137 逐句对照）-----------------------------

    /// 生成 `.strm` 文件内容。`orig_path` 是**原始媒体文件**在本实例里的路径。
    pub fn getLinkText(self: *const Strm, a: std.mem.Allocator, orig_path: []const u8) ![]const u8 {
        return self.getLinkTextWithOrigin(a, orig_path, &.{});
    }

    pub fn getLinkTextWithOrigin(
        self: *const Strm,
        a: std.mem.Allocator,
        orig_path: []const u8,
        req_headers: []const model.Header,
    ) ![]const u8 {
        var final: []const u8 = orig_path;
        if (self.a.encode_path) final = try pathEscape(a, orig_path);
        if (self.a.with_sign) {
            const sig = if (driver.fs_bridge) |b|
                try b.sign(b.ctx, a, orig_path)
            else
                "";
            final = try std.fmt.allocPrint(a, "{s}?sign={s}", .{ final, sig });
        }
        const prefix = self.a.path_prefix;
        if (prefix.len > 0) {
            final = try std.fmt.allocPrint(a, "{s}/{s}", .{
                trimRightOf(prefix, "/"),
                trimLeftOf(final, "/"),
            });
        }
        if (!std.mem.startsWith(u8, final, "/")) {
            final = try std.fmt.allocPrint(a, "/{s}", .{final});
        }
        if (self.a.without_url) return final;
        // Go common.GetApiUrl：SiteUrl 设置优先；否则有请求上下文时用
        // `X-Forwarded-Proto || http` + `Host`；都没有再回落 settings site_url。
        var api_url: []const u8 = "";
        if (self.a.site_url.len > 0) {
            api_url = trimRightOf(self.a.site_url, "/");
        } else {
            var host: []const u8 = "";
            var proto: []const u8 = "";
            for (req_headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "Host")) host = h.value;
                if (std.ascii.eqlIgnoreCase(h.name, "X-Forwarded-Proto")) proto = h.value;
            }
            if (host.len > 0) {
                api_url = try std.fmt.allocPrint(a, "{s}://{s}", .{ if (proto.len > 0) proto else "http", host });
            } else if (driver.fs_bridge) |b| {
                api_url = b.site_url(b.ctx);
            }
        }
        return std.fmt.allocPrint(a, "{s}{s}", .{ api_url, final });
    }

    // ---- convert（Go util.go:64-107）---------------------------------------

    fn appendConverted(
        self: *const Strm,
        a: std.mem.Allocator,
        req_path: []const u8,
        objs: []const model.Obj,
        out: *List(model.Obj),
    ) !void {
        for (objs) |o| {
            if (o.is_dir) {
                try out.append(.{
                    .name = o.name,
                    .size = 0,
                    .is_dir = true,
                    .modified = o.modified,
                    .thumb = o.thumb,
                });
                continue;
            }
            const path = try joinClean(a, req_path, o.name);
            const src_ext = sourceExt(o.name);
            const ext = try lower(a, src_ext);
            if (extInList(ext, self.download_suffix)) {
                // 字幕等：原样透传（可下载）。
                try out.append(.{
                    .name = o.name,
                    .size = o.size,
                    .modified = o.modified,
                    .thumb = o.thumb,
                    // sign = 上游路径（SaveStrmToLocal 钩子取内容要用）。
                    .sign = path,
                });
            } else if (extInList(ext, self.support_suffix)) {
                // 媒体：变 .strm，size = 链接文本长度（Go util.go:81）。
                if (self.min_size_bytes > 0 and o.size < self.min_size_bytes) continue;
                const content = try self.getLinkText(a, path);
                const new_name = try std.fmt.allocPrint(a, "{s}strm", .{o.name[0 .. o.name.len - src_ext.len]});
                try out.append(.{
                    .name = new_name,
                    .size = @intCast(content.len),
                    .modified = o.modified,
                    .thumb = o.thumb,
                    .sign = path, // 原始媒体路径
                });
            }
            // 其余后缀：丢弃（Go util.go:83 continue）。
        }
    }
};

fn as(p: *anyopaque) *Strm {
    return @ptrCast(@alignCast(p));
}

// ---------------------------------------------------------------------------
// 实例注册表（SaveStrmToLocal 钩子用；Go 用 patricia trie，本工程实例极少，
// 定长数组足够 —— 语义等价：按前缀匹配虚拟路径）
// ---------------------------------------------------------------------------

var registry: [8]?*Strm = .{ null, null, null, null, null, null, null, null };

fn registerInstance(self: *Strm) void {
    for (&registry) |*slot| {
        if (slot.* == null) {
            slot.* = self;
            return;
        }
    }
    log.warn("[strm] instance registry full; SaveStrmToLocal disabled for this instance", .{});
}

fn unregisterInstance(self: *Strm) void {
    for (&registry) |*slot| {
        if (slot.* == self) slot.* = null;
    }
}

fn updateLocalStrmHook(_: *anyopaque, alloc: std.mem.Allocator, parent: []const u8, objs: []const model.Obj) void {
    for (&registry) |*slot| {
        const self = slot.* orelse continue;
        if (!self.a.save_strm_to_local) continue;
        updateLocalStrm(self, alloc, parent, objs) catch |e| {
            log.warn("[strm] update local strm for {s} failed: {s}", .{ parent, @errorName(e) });
        };
    }
}

/// Go hook.go:25-54 的 UpdateLocalStrm（trie 前缀匹配 + 本地落盘）。
fn updateLocalStrm(self: *Strm, a: std.mem.Allocator, parent_raw: []const u8, objs: []const model.Obj) !void {
    const io = rt.io();
    const parent = try fixAndCleanPath(a, parent_raw);
    for (self.entries.slice()) |*e| {
        for (e.dsts.slice()) |dst_line_raw| {
            // Go Init 里 InsertStrm 用的是**整行** FixAndCleanPath
            // （driver.go:57，含 "key:" 前缀 —— 上游如此，照抄）。
            const need = try fixAndCleanPath(a, dst_line_raw);
            // Go hook.go:41-47：trie 只返回 path 的真前缀，且 rest 非空时
            // 必须以 '/' 开头才算命中。
            if (!std.mem.startsWith(u8, parent, need)) continue;
            const rest = parent[need.len..];
            if (rest.len > 0 and rest[0] != '/') continue;

            var converted = List(model.Obj).init(a);
            defer converted.deinit();
            try self.appendConverted(a, parent, objs, &converted);

            // Go hook.go:50：basePath = Base(needPath) + rest；
            // relParent = basePath 减去本驱动挂载路径（hook.go:28）。
            const base_path = try joinClean(a, baseName(need), rest);
            const mount_fixed = try fixAndCleanPath(a, self.mount_path);
            const rel_parent = if (std.mem.startsWith(u8, base_path, mount_fixed))
                base_path[mount_fixed.len..]
            else
                base_path;
            const local_parent = try joinLocal(a, self.a.save_strm_local_path, rel_parent);

            std.Io.Dir.cwd().createDirPath(io, local_parent) catch |err| {
                log.warn("[strm] failed to create local strm directory {s}: {s}", .{ local_parent, @errorName(err) });
                continue;
            };
            for (converted.slice()) |o| {
                const local_path = try joinLocal(a, local_parent, o.name);
                try generateStrm(self, a, o, local_path);
            }
            try deleteExtraFiles(self, a, local_parent, converted.slice());
        }
    }
}

/// Go hook.go:99-158 的 generateStrm。
fn generateStrm(self: *Strm, a: std.mem.Allocator, obj: model.Obj, local_path: []const u8) !void {
    const io = rt.io();
    if (obj.is_dir) {
        std.Io.Dir.cwd().createDirPath(io, local_path) catch |err| {
            log.warn("[strm] failed to create local strm directory {s}: {s}", .{ local_path, @errorName(err) });
        };
        return;
    }

    if (exists(local_path) and std.mem.eql(u8, self.a.save_local_mode, save_local_insert)) return;

    // 内容：strm 条目 = URL 文本；透传条目 = 上游文件内容（Go 经
    // Link + RangeReader 读，本地落地的是文件本体）。
    const content: []const u8 = blk: {
        if (obj.sign.len > 0 and std.mem.endsWith(u8, obj.name, ".strm")) {
            break :blk try self.getLinkText(a, obj.sign);
        }
        break :blk fetchContent(a, obj.sign) catch |e| {
            log.warn("[strm] failed to generate strm of obj {s}: failed to link: {s}", .{ local_path, @errorName(e) });
            return;
        };
    };

    // isSameContent（hook.go:164-190）：大小或内容不同才重写。
    if (isSameContent(local_path, content)) return;

    if (std.fs.path.dirname(local_path)) |parent| {
        std.Io.Dir.cwd().createDirPath(io, parent) catch |err| {
            log.warn("[strm] failed to create parent directory {s}: {s}", .{ parent, @errorName(err) });
            return;
        };
    }
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = local_path, .data = content }) catch |err| {
        log.warn("[strm] copy failed: {s}", .{@errorName(err)});
    };
}

/// 透传条目的内容获取：上游虚拟路径 → bridge.link → 本地文件直读 / HTTP 下载。
fn fetchContent(a: std.mem.Allocator, upstream_path: []const u8) ![]const u8 {
    const bridge = driver.fs_bridge orelse return error.NotFound;
    const lk = try bridge.link(bridge.ctx, a, upstream_path, .{});
    if (lk.local_path) |lp| {
        return std.Io.Dir.cwd().readFileAlloc(rt.io(), lp, a, .limited(256 * 1024 * 1024));
    }
    if (lk.text) |t| return t;
    if (lk.url.len == 0) return error.NotFound;
    var jar = cookiejar.Jar.init(a);
    defer jar.deinit();
    var c = client_mod.Client.init(a, .{}, &jar);
    defer c.deinit();
    const res = try c.send(a, .{ .method = "GET", .url = lk.url, .headers = lk.header, .body = "" });
    if (!res.isOk()) return error.UnexpectedResponse;
    return res.body;
}

/// 0.17 的 std.mem 没有 trimRight/trimLeft —— 本文件自备。
fn trimRightOf(s: []const u8, set: []const u8) []const u8 {
    var e = s.len;
    while (e > 0 and std.mem.indexOfScalar(u8, set, s[e - 1]) != null) e -= 1;
    return s[0..e];
}
fn trimLeftOf(s: []const u8, set: []const u8) []const u8 {
    var b: usize = 0;
    while (b < s.len and std.mem.indexOfScalar(u8, set, s[b]) != null) b += 1;
    return s[b..];
}

fn isSameContent(local_path: []const u8, content: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(rt.io(), local_path, .{}) catch return false;
    if (st.size != content.len) return false;
    const existing = std.Io.Dir.cwd().readFileAlloc(rt.io(), local_path, std.heap.page_allocator, .limited(256 * 1024 * 1024)) catch return false;
    defer std.heap.page_allocator.free(existing);
    return std.mem.eql(u8, existing, content);
}

/// Go hook.go:192-234 的 deleteExtraFiles（仅 sync 模式）。
fn deleteExtraFiles(self: *Strm, a: std.mem.Allocator, local_path: []const u8, objs: []const model.Obj) !void {
    if (!std.mem.eql(u8, self.a.save_local_mode, save_local_sync)) return;
    const io = rt.io();
    var dir = std.Io.Dir.cwd().openDir(io, local_path, .{ .iterate = true }) catch return;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        var found = false;
        for (objs) |o| {
            if (std.mem.eql(u8, o.name, entry.name)) {
                found = true;
                break;
            }
        }
        if (found) continue;
        const full = try joinLocal(a, local_path, entry.name);
        const is_dir = if (std.Io.Dir.cwd().statFile(io, full, .{}) catch null) |st| st.kind == .directory else false;
        if (is_dir) {
            // Go os.RemoveAll；本工程没有递归删除原语，尽力删一层。
            std.Io.Dir.cwd().deleteDir(io, full) catch |err| {
                log.warn("[strm] failed to delete directory {s}: {s}", .{ full, @errorName(err) });
            };
        } else {
            std.Io.Dir.cwd().deleteFile(io, full) catch |err| {
                log.warn("[strm] failed to delete file {s}: {s}", .{ full, @errorName(err) });
            };
        }
    }
}

fn exists(path: []const u8) bool {
    _ = std.Io.Dir.cwd().statFile(rt.io(), path, .{}) catch return false;
    return true;
}

// ---------------------------------------------------------------------------
// 小工具（Go pkg/utils 对应物）
// ---------------------------------------------------------------------------

/// Go `utils.SourceExt`：最后一个点之后、不含点（大小写保留）。
fn sourceExt(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    if (dot + 1 >= name.len) return "";
    return name[dot + 1 ..];
}

fn lower(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

/// 逗号分隔、大小写不敏感的后缀成员判断（trim 每项空白）。
fn extInList(ext: []const u8, list: []const u8) bool {
    if (ext.len == 0) return false;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item_raw| {
        const item = std.mem.trim(u8, item_raw, " \t");
        if (std.ascii.eqlIgnoreCase(item, ext)) return true;
    }
    return false;
}

/// Version<5 迁移：把 canonical 清单里缺的后缀并进去（Go driver.go:100-118）。
fn mergeTypes(a: std.mem.Allocator, current: []const u8, canonical: []const u8) ![]const u8 {
    var out = Buf.init(a);
    try out.append(current);
    var it = std.mem.splitScalar(u8, canonical, ',');
    while (it.next()) |item_raw| {
        const item = std.mem.trim(u8, item_raw, " \t");
        if (item.len == 0) continue;
        if (extInList(item, current)) continue;
        try out.append(",");
        try out.append(item);
    }
    return out.toOwned();
}

/// Go `utils.FixAndCleanPath`：反斜杠归一、补前导 `/`、清理 `.`/`..`。
fn fixAndCleanPath(a: std.mem.Allocator, path: []const u8) ![]const u8 {
    var buf = Buf.init(a);
    for (path) |c| try buf.appendByte(if (c == '\\') '/' else c);
    var s: []const u8 = buf.slice();
    if (!std.mem.startsWith(u8, s, "/")) s = try std.fmt.allocPrint(a, "/{s}", .{s});
    return urlmod.cleanPath(a, s);
}

/// `stdpath.Join(base, sub)` 的虚拟路径版：任一为空/根时返回另一方。
fn joinClean(a: std.mem.Allocator, base: []const u8, sub: []const u8) ![]const u8 {
    const b = trimRightOf(base, "/");
    var s = trimLeftOf(sub, "/");
    s = trimRightOf(s, "/");
    if (s.len == 0) return a.dupe(u8, if (b.len == 0) "/" else b);
    if (b.len == 0) return std.fmt.allocPrint(a, "/{s}", .{s});
    return std.fmt.allocPrint(a, "{s}/{s}", .{ b, s });
}

/// 本地绝对路径拼接（SaveStrmLocalPath + 相对目录）。调用方 arena 释放。
fn joinLocal(a: std.mem.Allocator, base: []const u8, rel: []const u8) ![]const u8 {
    const b = trimRightOf(base, "/");
    const r = std.mem.trim(u8, rel, "/");
    if (r.len == 0) return a.dupe(u8, b);
    return std.fmt.allocPrint(a, "{s}/{s}", .{ b, r });
}

/// Go `stdpath.Base`。
fn baseName(path: []const u8) []const u8 {
    const p = trimRightOf(path, "/");
    if (p.len == 0) return "/";
    if (std.mem.lastIndexOfScalar(u8, p, '/')) |idx| {
        return p[idx + 1 ..];
    }
    return p;
}

/// Go `stdpath.Dir`。
fn dirnameOf(path: []const u8) []const u8 {
    const idx = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "/";
    if (idx == 0) return "/";
    return path[0..idx];
}

/// Go `url.PathEscape`（encodePathSegment 模式），`/` 是分隔符按 EncodePath
/// 的逐段调用保留。保留：unreserved（含 `-_.~`）与 `$ & + : = @`；
/// 其余（空格、`!'()*`、`%;?#/,`）转义。注意与 `urlmod.encode(.path)` 不同
/// —— 那个还保留 `!'()*;,`。
fn pathEscape(a: std.mem.Allocator, path: []const u8) ![]const u8 {
    var b = Buf.init(a);
    const hex = "0123456789ABCDEF";
    for (path) |c| {
        const keep = c == '/' or std.ascii.isAlphanumeric(c) or switch (c) {
            '-', '_', '.', '~', '$', '&', '+', ':', '=', '@' => true,
            else => false,
        };
        if (keep) {
            try b.appendByte(c);
        } else {
            try b.appendByte('%');
            try b.appendByte(hex[c >> 4]);
            try b.appendByte(hex[c & 0x0F]);
        }
    }
    return b.toOwned();
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    .key = "Strm",
    .label = "STRM",
    .secrets = &.{},
    // 表单 schema：键名与 Go meta.go:14-28 的 json tag 逐字节一致
    //（包括大写开头的 PathPrefix / SaveStrmToLocal / SaveStrmLocalPath /
    // SaveLocalMode / Version —— Go 的 tag 就这么写）。
    .addition_schema =
    \\{
    \\  "paths":              {"type":"text","required":true,"help":"每行一条：`名称:源路径` 或 `源路径`（映射同一实例内其他挂载）"},
    \\  "siteUrl":            {"type":"text","help":"strm 文件内容的 URL 前缀（留空用站点地址）"},
    \\  "PathPrefix":         {"type":"text","default":"/d","help":"路径前缀"},
    \\  "downloadFileTypes":  {"type":"text","default":"ass,srt,vtt,sub,strm","help":"需要直接下载（不转 strm）的后缀，通常是字幕"},
    \\  "filterFileTypes":    {"type":"text","default":"mp4,mkv,flv,avi,wmv,ts,rmvb,webm,mp3,flac,aac,wav,ogg,m4a,wma,alac","help":"转 strm 的媒体后缀"},
    \\  "minFileSize":        {"type":"number","default":0,"help":"小于该体积(MB)的媒体不转 strm（0 不启用）"},
    \\  "encodePath":         {"type":"bool","default":true,"help":"strm 内容里的路径做 URL 编码"},
    \\  "withoutUrl":         {"type":"bool","default":false,"help":"strm 内容不带 URL 前缀（相对路径）"},
    \\  "withSign":           {"type":"bool","default":false,"help":"strm 内容附加下载签名"},
    \\  "SaveStrmToLocal":    {"type":"bool","default":false,"help":"把 strm 文件写到本地目录"},
    \\  "SaveStrmLocalPath":  {"type":"text","help":"strm 本地保存目录"},
    \\  "SaveLocalMode":      {"type":"select","options":"insert,update,sync","default":"insert","help":"本地写入模式"},
    \\  "Version":            {"type":"number","default":5,"help":"配置版本（自动迁移）"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    const self = try alloc.create(Strm);
    self.* = .{
        .alloc = alloc,
        .storage_id = storage_id,
        .a = try Addition.parse(alloc, cfg),
        .entries = List(Entry).init(alloc),
    };
    return driver.asDriver(Strm, self);
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 假 fs 桥：canned 目录树（虚拟路径 → 条目），测 list/details/link 全链路。
const FakeBridge = struct {
    gpa: std.mem.Allocator,
    dirs: std.StringHashMapUnmanaged([]model.Obj) = .{},
    secret: []const u8 = "test-secret",

    fn add(self: *FakeBridge, path: []const u8, objs: []const model.Obj) !void {
        const copy = try self.gpa.alloc(model.Obj, objs.len);
        for (objs, 0..) |o, i| copy[i] = o;
        try self.dirs.put(self.gpa, try self.gpa.dupe(u8, path), copy);
    }
    fn deinit(self: *FakeBridge) void {
        var it = self.dirs.iterator();
        while (it.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.dirs.deinit(self.gpa);
    }

    fn bridge(self: *FakeBridge) driver.FsBridge {
        return .{
            .ctx = self,
            .get = bGet,
            .list = bList,
            .link = bLink,
            .sign = bSign,
            .site_url = bSiteUrl,
        };
    }

    /// 只有**真实存在**于 canned 树里的对象才 Get 得到（.strm 必须 miss，
    /// 才会走父目录扫描分支）。
    fn bGet(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror!driver.File {
        _ = alloc;
        const fb: *FakeBridge = @ptrCast(@alignCast(ctx));
        const clean = trimRightOf(path, "/");
        if (clean.len == 0) return error.NotFound;
        const slash = std.mem.lastIndexOfScalar(u8, clean, '/') orelse return error.NotFound;
        const parent = if (slash == 0) "/" else clean[0..slash];
        const base = clean[slash + 1 ..];
        const objs = fb.dirs.get(parent) orelse return error.NotFound;
        for (objs) |o| {
            if (std.mem.eql(u8, o.name, base)) {
                return .{ .name = o.name, .size = if (o.is_dir) 0 else o.size, .is_dir = o.is_dir, .modified = o.modified };
            }
        }
        return error.NotFound;
    }
    fn bList(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]model.Obj {
        const fb: *FakeBridge = @ptrCast(@alignCast(ctx));
        const key = trimRightOf(path, "/");
        if (key.len == 0) return error.NotFound;
        const objs = fb.dirs.get(key) orelse return error.NotFound;
        const out = try alloc.alloc(model.Obj, objs.len);
        for (objs, 0..) |o, i| out[i] = o;
        return out;
    }
    fn bLink(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: model.LinkArgs) anyerror!driver.Link {
        return .{ .url = "http://upstream/file" };
    }
    fn bSign(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]const u8 {
        const fb: *FakeBridge = @ptrCast(@alignCast(ctx));
        return std.fmt.allocPrint(alloc, "SIG:{s}:{s}", .{ path, fb.secret });
    }
    fn bSiteUrl(_: *anyopaque) []const u8 {
        return "http://site.example";
    }
};

test "strm getPair mirrors Go's key:dst splitting" {
    // Go util.go:32-41：含 ':' 且 key 不含 '/' ⇒ 按对解析；否则 key = Base。
    try testing.expectEqualStrings("nas", Strm.getPair("nas:/media/movies").key);
    try testing.expectEqualStrings("/media/movies", Strm.getPair("nas:/media/movies").dst);
    try testing.expectEqualStrings("movies", Strm.getPair("/media/movies").key);
    try testing.expectEqualStrings("/media/movies", Strm.getPair("/media/movies").dst);
    // key 里含 '/' ⇒ 不按对解析，落 Base（Go util.go:38-40 的行为，
    // Base("/a/b:c") = "b:c" —— 整段含 ':' 但 key 段含 '/'）。
    try testing.expectEqualStrings("b:c", Strm.getPair("/a/b:c").key);
    try testing.expectEqualStrings("/a/b:c", Strm.getPair("/a/b:c").dst);
}

test "strm pathEscape mirrors Go url.PathEscape (segment mode)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("a%20b+c.mp4", try pathEscape(a, "a b+c.mp4"));
    try testing.expectEqualStrings("x%281%29.mp4", try pathEscape(a, "x(1).mp4"));
    try testing.expectEqualStrings("note%21.mp4", try pathEscape(a, "note!.mp4"));
    // 保留字符：$ & + : = @ 与分隔符 / 原样。
    try testing.expectEqualStrings("a$b&c+d:e=f@g.mp4", try pathEscape(a, "a$b&c+d:e=f@g.mp4"));
    try testing.expectEqualStrings("/media/movies/Movie%20One.mp4", try pathEscape(a, "/media/movies/Movie One.mp4"));
}

test "strm full chain: list root, list dir, .strm conversion, details, link text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fb = FakeBridge{ .gpa = testing.allocator };
    defer fb.deinit();
    try fb.add("/media/movies", &.{
        .{ .name = "Movie One.mp4", .size = 1000, .modified = 100 },
        .{ .name = "Movie One.ass", .size = 55, .modified = 100 },
        .{ .name = "readme.txt", .size = 3, .modified = 100 },
        .{ .name = "Subs", .is_dir = true, .modified = 100 },
    });
    const prev_bridge = driver.fs_bridge;
    driver.fs_bridge = fb.bridge();
    defer driver.fs_bridge = prev_bridge;

    // 两行 paths（JSON 里的 \n 是真实换行转义）：
    // "movies:/media/movies\ntv:/tv"
    const addition = "{\"paths\":\"movies:/media/movies\\ntv:/tv\",\"Version\":0}";
    var parsed = try json.parse(a, addition);
    const drv = try factory.create(a, 1, &parsed);
    var ctx = driver.Ctx{ .alloc = a };
    try drv.init(&ctx);

    // 根：两个 key 目录（非 flatten）。
    {
        const objs = try drv.list(&ctx, "/");
        try testing.expectEqual(@as(usize, 2), objs.len);
        try testing.expectEqualStrings("movies", objs[0].name);
        try testing.expect(objs[0].is_dir);
        try testing.expectEqualStrings("tv", objs[1].name);
    }
    // movies 目录：mp4 → .strm（size = 链接文本长度）、ass 透传、txt 丢弃、目录透传。
    {
        const objs = try drv.list(&ctx, "/movies");
        try testing.expectEqual(@as(usize, 3), objs.len);
        try testing.expectEqualStrings("Movie One.strm", objs[0].name);
        try testing.expect(objs[0].size > 0);
        try testing.expectEqualStrings("Movie One.ass", objs[1].name);
        try testing.expectEqual(@as(i64, 55), objs[1].size);
        try testing.expectEqualStrings("Subs", objs[2].name);
        try testing.expect(objs[2].is_dir);
    }
    // .strm 详情：父目录扫描找到虚拟条目，sign 带原始路径。
    {
        const f = try drv.details(&ctx, "/movies/Movie One.strm");
        try testing.expectEqualStrings("Movie One.strm", f.name);
        try testing.expect(!f.is_dir);
        try testing.expect(f.size > 0);
        try testing.expectEqualStrings("/media/movies/Movie One.mp4", f.sign);
    }
    // 透传文件详情：bridge.get 直接命中。
    {
        const f = try drv.details(&ctx, "/movies/Movie One.ass");
        try testing.expectEqual(@as(i64, 55), f.size);
    }
    // link .strm：内容 = siteUrl + PathPrefix + 编码路径。encodePath 默认 true、
    // withoutUrl=false、withSign=false；Version=0 触发迁移 ⇒ PathPrefix 强制 "/d"。
    {
        const lk = try drv.link(&ctx, "/movies/Movie One.strm", .{});
        try testing.expect(lk.proxy);
        try testing.expect(lk.text != null);
        try testing.expectEqualStrings("http://site.example/d/media/movies/Movie%20One.mp4", lk.text.?);
    }
    // link 透传文件：目标真实链接 + proxy=true（OnlyProxy）。
    {
        const lk = try drv.link(&ctx, "/movies/Movie One.ass", .{});
        try testing.expect(lk.proxy);
        try testing.expectEqualStrings("http://upstream/file", lk.url);
    }
    // link .strm 带请求头：URL 前缀取 scheme://Host（Go common.GetApiUrl 的
    // 请求上下文行为 —— config site_url 为空时）。
    {
        const lk = try drv.link(&ctx, "/movies/Movie One.strm", .{
            .headers = &.{.{ .name = "Host", .value = "192.168.1.1:15344" }},
        });
        try testing.expectEqualStrings(
            "http://192.168.1.1:15344/d/media/movies/Movie%20One.mp4",
            lk.text.?,
        );
    }
    // 单 key flatten：`/` 直接展开 dst 内容。
    {
        const addition2 = "{\"paths\":\"/media/movies\"}";
        var parsed2 = try json.parse(a, addition2);
        const drv2 = try factory.create(a, 2, &parsed2);
        var ctx2 = driver.Ctx{ .alloc = a };
        try drv2.init(&ctx2);
        const root_objs = try drv2.list(&ctx2, "/");
        try testing.expectEqual(@as(usize, 3), root_objs.len);
        try testing.expectEqualStrings("Movie One.strm", root_objs[0].name);
        drv2.deinit(&ctx2);
    }
    // withSign / withoutUrl / siteUrl 组合（Go util.go:109-137 的分支）。
    // 注意：`sign` 字段永远是原始上游路径；链接文本只能从 link() 观察。
    {
        const addition3 =
            \\{"paths":"/media/movies","siteUrl":"http://cfg.example/","withSign":true,"withoutUrl":true}
        ;
        var parsed3 = try json.parse(a, addition3);
        const drv3 = try factory.create(a, 3, &parsed3);
        var ctx3 = driver.Ctx{ .alloc = a };
        try drv3.init(&ctx3);
        const objs = try drv3.list(&ctx3, "/");
        try testing.expectEqualStrings("/media/movies/Movie One.mp4", objs[0].sign);
        // size = 链接文本长度（Go util.go:81）。
        const lk3 = try drv3.link(&ctx3, "/Movie One.strm", .{});
        const expect = "/d/media/movies/Movie%20One.mp4?sign=SIG:/media/movies/Movie One.mp4:test-secret";
        try testing.expectEqualStrings(expect, lk3.text.?);
        try testing.expectEqual(@as(i64, @intCast(expect.len)), objs[0].size);
        drv3.deinit(&ctx3);
    }
    drv.deinit(&ctx);
}

test "strm SaveStrmToLocal writes .strm files locally (insert/sync)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var fb = FakeBridge{ .gpa = testing.allocator };
    defer fb.deinit();
    try fb.add("/media/movies", &.{
        .{ .name = "Film.mp4", .size = 1000, .modified = 100 },
    });
    const prev_bridge = driver.fs_bridge;
    driver.fs_bridge = fb.bridge();
    defer driver.fs_bridge = prev_bridge;

    const save_dir = try std.fmt.allocPrint(a, "{s}/strm-out", .{root});
    const addition = try std.fmt.allocPrint(
        a,
        "{{\"paths\":\"/media/movies\",\"SaveStrmToLocal\":true,\"SaveStrmLocalPath\":\"{s}\",\"SaveLocalMode\":\"sync\"}}",
        .{save_dir},
    );
    var parsed = try json.parse(a, addition);
    const drv = try factory.create(a, 4, &parsed);
    var ctx = driver.Ctx{ .alloc = a, .tag = "/strm" };
    try drv.init(&ctx);

    // 模拟 op 写后钩子：源目录的条目更新 → 本地落盘。
    // Go hook.go:50：本地目录 = SaveStrmLocalPath + Base(源路径) = <save>/movies。
    const objs = [_]model.Obj{.{ .name = "Film.mp4", .size = 1000, .modified = 100 }};
    driver.notifyObjsUpdate(a, "/media/movies", &objs);

    const written_path = try std.fmt.allocPrint(a, "{s}/movies/Film.strm", .{save_dir});
    const content = try std.Io.Dir.cwd().readFileAlloc(rt.io(), written_path, a, .limited(1024 * 1024));
    // encodePath=true + PathPrefix=/d + siteUrl 空 ⇒ 用 bridge 的 site_url。
    try testing.expectEqualStrings("http://site.example/d/media/movies/Film.mp4", content);

    // sync 模式：本地多余文件被删（Go hook.go:192-234）。
    const extra = try std.fmt.allocPrint(a, "{s}/movies/stale.strm", .{save_dir});
    try std.Io.Dir.cwd().writeFile(rt.io(), .{ .sub_path = extra, .data = "old" });
    driver.notifyObjsUpdate(a, "/media/movies", &objs);
    try testing.expect(!exists(extra));

    drv.deinit(&ctx);
}
