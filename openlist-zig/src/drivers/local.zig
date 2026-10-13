//! Local filesystem driver.
//!
//! The simplest of the nine target drivers, and the one that exercises the
//! parts of the skeleton that are *not* about cloud protocols: path sandboxing,
//! streaming a file straight out of the page cache, and atomic writes.
//!
//! Security note that matters more here than anywhere else: this driver runs
//! on a 光猫 whose root filesystem is the user's own, but the *mount path* is
//! exposed over HTTP. Every incoming path is normalised and then re-checked
//! against the configured root, so `/local/../../etc/shadow` cannot escape.
//! `std.Io.Dir` handles (`openDir` on the root, then relative paths) do the
//! real work — the string check is a belt-and-braces second line, not the
//! primary defence.

const std = @import("std");
const builtin = @import("builtin");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const urlmod = @import("../util/url.zig");
const timeutil = @import("../util/time.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

pub const Addition = struct {
    /// Directory this mount is rooted at.
    root_folder: []const u8 = "/data",
    /// Also show hidden (dot) entries.
    ///
    /// 默认 **true**，对齐 Go `drivers/local/meta.go:10` 的 `default:"true"`。
    /// （此前这里是 false —— 用户备份里显式写了 `show_hidden:true` 才没暴露。）
    show_hidden: bool = true,
    /// Follow symlinks. Off by default: on a device where the mount path is
    /// exposed over HTTP, following links turns any writable directory into a
    /// full-filesystem read primitive.
    follow_symlinks: bool = false,

    /// Go `directory_size`：列表/详情时**递归**统计子目录大小。
    /// 默认关 —— 每个目录都要走一遍子树，很费 IO。
    directory_size: bool = false,
    /// Go `mkdir_perm`：新建目录的八进制权限串（默认 `"777"`）。
    mkdir_perm: []const u8 = "777",
    /// Go `recycle_bin_path`：删除时把文件**移动**到这里而不是真删；
    /// 空串或 `"delete permanently"` 表示永久删除。
    recycle_bin_path: []const u8 = "delete permanently",
    // ---- 缩略图相关（见文件头：本工程只解析+回写，不生成）----
    thumbnail: bool = false,
    pdf_thumbnail: bool = false,
    thumb_cache_folder: []const u8 = "",
    thumb_concurrency: []const u8 = "16",
    video_thumb_pos: []const u8 = "20%",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        // C01 / T3：Go 的 Local 内嵌 `driver.RootPath`，字段名是 `root_folder_path`
        // （local/meta.go:9 → internal/driver/item.go:31），不是 Zig 这边的
        // `root_folder`。直接把一份真实 Go addition JSON 喂进来时，旧代码读不到
        // 根目录就回落到默认 `/data`，启动即失败或展示错误目录。
        //
        // 用户备份 storage #13 的键集实证：
        // ['directory_size','mkdir_perm','pdf_thumbnail','recycle_bin_path',
        //  'root_folder_path','show_hidden','thumb_cache_folder',
        //  'thumb_concurrency','thumbnail','video_thumb_pos']。
        // **Go 名优先**，本工程旧名只作兜底。
        if (o.strAt("root_folder_path")) |s| {
            a.root_folder = try alloc.dupe(u8, s);
        } else if (o.strAt("root_folder")) |s| {
            a.root_folder = try alloc.dupe(u8, s);
        }
        if (o.getPath("show_hidden")) |x| {
            if (x.asBool()) |b| a.show_hidden = b;
        }
        if (o.getPath("follow_symlinks")) |x| {
            if (x.asBool()) |b| a.follow_symlinks = b;
        }
        if (o.getPath("directory_size")) |x| {
            if (x.asBool()) |b| a.directory_size = b;
        }
        if (o.getPath("thumbnail")) |x| {
            if (x.asBool()) |b| a.thumbnail = b;
        }
        if (o.getPath("pdf_thumbnail")) |x| {
            if (x.asBool()) |b| a.pdf_thumbnail = b;
        }
        // Go 里这几个是**字符串**字段（`string`，不是 number）—— 老配置里可能是
        // 数字，两种都收。
        if (strOrNum(alloc, o, "mkdir_perm")) |s| a.mkdir_perm = try alloc.dupe(u8, s);
        if (strOrNum(alloc, o, "recycle_bin_path")) |s| a.recycle_bin_path = try alloc.dupe(u8, s);
        if (strOrNum(alloc, o, "thumb_cache_folder")) |s| a.thumb_cache_folder = try alloc.dupe(u8, s);
        if (strOrNum(alloc, o, "thumb_concurrency")) |s| a.thumb_concurrency = try alloc.dupe(u8, s);
        if (strOrNum(alloc, o, "video_thumb_pos")) |s| a.video_thumb_pos = try alloc.dupe(u8, s);
        return a;
    }

    /// `mkdir_perm` → 八进制 mode。非法值退回 Go 的默认 `0o777`。
    pub fn mkdirMode(self: Addition) u32 {
        const s = std.mem.trim(u8, self.mkdir_perm, " \t");
        if (s.len == 0) return 0o777;
        return std.fmt.parseInt(u32, s, 8) catch 0o777;
    }

    /// 是否真的永久删除（空串或 `"delete permanently"` 都是）。
    pub fn permanentDelete(self: Addition) bool {
        const s = std.mem.trim(u8, self.recycle_bin_path, " \t");
        return s.len == 0 or std.mem.eql(u8, s, "delete permanently");
    }
};

/// 取一个字段，字符串或数字都接受（Go 那边声明成 string，但老配置里见过数字）。
/// 数字形态会格式化进 `alloc`。
fn strOrNum(alloc: std.mem.Allocator, o: *const json.Value, key: []const u8) ?[]const u8 {
    const x = o.getPath(key) orelse return null;
    if (x.asStr()) |s| return s;
    if (x.asInt()) |n| return std.fmt.allocPrint(alloc, "{d}", .{n}) catch null;
    return null;
}

/// 进程内单调递增，用来给 `put` 的临时文件生成唯一后缀。见 D09：固定的
/// 临时名会让并发写同一目标的两条请求互相 truncate。
var tmp_seq = std.atomic.Value(u64).init(0);

pub const Local = struct {
    alloc: std.mem.Allocator,
    cfg: Addition,

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
        return "Local";
    }

    fn as(p: *anyopaque) *Local {
        return @ptrCast(@alignCast(p));
    }

    fn init(p: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(p);
        _ = ctx;
        if (self.cfg.root_folder.len == 0) return error.InvalidConfig;
        // Go 的 Init 会先 `filepath.Abs`（drivers/local/driver.go:47-52）。相对 root
        // 不转绝对的话，`link.local_path` 就是相对路径，而 HTTP 层是拿它直接
        // `open()` 的 —— 一旦进程 CWD 变化（或请求线程的 CWD 不同）就找不到文件。
        //
        // ⚠️ Zig 的 `std.fs.path.resolve`（= `resolveAlloc`）**不查 CWD**，只做纯
        // 词法归一化 —— `resolve(&.{"."})` 会原样返回 `"."`。所以必须自己把 CWD
        // 拼进去，这才是 Go `filepath.Abs` 的语义（join(CWD, path) + Clean）。
        if (!std.fs.path.isAbsolute(self.cfg.root_folder)) {
            const cwd: ?[:0]u8 = std.Io.Dir.cwd().realPathFileAlloc(rt.io(), ".", self.alloc) catch null;
            const abs = if (cwd) |c|
                std.fs.path.resolveAlloc(self.alloc, &.{ c, self.cfg.root_folder }) catch self.cfg.root_folder
            else
                self.cfg.root_folder;
            log.warn("[local] relative root {s} resolved to {s}", .{ self.cfg.root_folder, abs });
            self.cfg.root_folder = abs;
        }
        // Fail loudly at startup rather than on the first browse.
        var d = std.Io.Dir.cwd().openDir(rt.io(), self.cfg.root_folder, .{}) catch |e| {
            log.err("[local] cannot open root {s}: {s}", .{ self.cfg.root_folder, @errorName(e) });
            return e;
        };
        d.close(rt.io());
    }

    fn deinit(p: *anyopaque, ctx: *driver.Ctx) void {
        _ = p;
        _ = ctx;
    }

    // -----------------------------------------------------------------------
    // Path sandboxing
    // -----------------------------------------------------------------------

    /// Map a virtual path to a path relative to the root, rejecting escapes.
    ///
    /// Returns a path with no leading '/' (except "" for the root itself),
    /// suitable for passing to the root `std.Io.Dir`.
    fn relPath(self: *Local, alloc: std.mem.Allocator, virt: []const u8) ![]const u8 {
        const cleaned = try urlmod.cleanPath(alloc, virt);
        // cleanPath already resolved "." and "..", so anything still containing
        // a ".." segment would have been collapsed. Assert that anyway: this is
        // the one function where being wrong is a security bug.
        //
        // 按**段**判断，不能子串匹配 ".."。D07：`v1..2.tar`、`..cache` 都是
        // 合法文件名，子串匹配会把它们一并拒掉。
        var segs = std.mem.splitScalar(u8, cleaned, '/');
        while (segs.next()) |seg| {
            if (std.mem.eql(u8, seg, "..")) return error.InvalidPath;
        }
        if (std.mem.eql(u8, cleaned, "/")) return "";
        const rel = cleaned[1..];
        try self.rejectSymlinks(alloc, rel);
        return rel;
    }

    /// D08：`follow_symlinks` 以前只是被解析出来，从来没有消费过 —— 声明的
    /// "默认关闭" 安全契约没有兑现：挂载目录里放一条指向 root 外的符号链接，
    /// 就能越 root 读写。
    ///
    /// 现在沿路径逐段 lstat，任何一段是符号链接就拒绝。`relPath` 是 list /
    /// details / link / put / remove / move / rename 的唯一入口，所以这里
    /// 一道闸就覆盖了全部操作。
    ///
    /// 已知残留：段与段之间存在 TOCTOU 窗口（检查完再打开之间链接可被替换）。
    /// 彻底消除要用 `openat` + `O_NOFOLLOW` 逐段打开，留作后续加固；当前
    /// 实现至少让声明的行为与真实行为一致。
    fn rejectSymlinks(self: *Local, alloc: std.mem.Allocator, rel: []const u8) !void {
        if (self.cfg.follow_symlinks) return;
        if (rel.len == 0) return;

        const io = rt.io();
        var root = std.Io.Dir.cwd().openDir(io, self.cfg.root_folder, .{}) catch return;
        defer root.close(io);

        // 逐个前缀：a、a/b、a/b/c.txt
        var it = std.mem.splitScalar(u8, rel, '/');
        var prefix = Buf.init(alloc);
        defer prefix.deinit();
        while (it.next()) |seg| {
            if (seg.len == 0) continue;
            if (prefix.len > 0) try prefix.appendByte('/');
            try prefix.append(seg);
            const st = root.statFile(io, prefix.slice(), .{ .follow_symlinks = false }) catch continue;
            if (st.kind == .sym_link) {
                log.warn("[local] refusing symlink component {s} (follow_symlinks=false)", .{prefix.slice()});
                return error.InvalidPath;
            }
        }
    }

    fn openRoot(self: *Local) !std.Io.Dir {
        return std.Io.Dir.cwd().openDir(rt.io(), self.cfg.root_folder, .{ .iterate = true });
    }

    fn shouldSkip(self: *Local, entry_name: []const u8) bool {
        if (self.cfg.show_hidden) return false;
        return entry_name.len > 0 and entry_name[0] == '.';
    }

    // -----------------------------------------------------------------------
    // vtable
    // -----------------------------------------------------------------------

    fn list(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(p);
        const a = ctx.alloc;
        const rel = try self.relPath(a, dir);
        // Normalise for the `sign` we hand back. `dir` may carry `.`/`..`
        // segments (the API passes the request path straight through), and
        // echoing them back would produce a URL that only resolves because
        // the driver re-normalises it on the way in.
        const base = try urlmod.cleanPath(a, dir);

        var root = try self.openRoot();
        defer root.close(rt.io());
        var d = if (rel.len == 0) root else try root.openDir(rt.io(), rel, .{ .iterate = true });
        defer if (rel.len != 0) d.close(rt.io());

        var out = List(model.Obj).init(a);
        var it = d.iterate();
        while (try it.next(rt.io())) |entry| {
            if (self.shouldSkip(entry.name)) continue;
            // 不把 `put` 写到一半的临时文件当成目录内容返回（D09）。
            if (std.mem.indexOf(u8, entry.name, ".openlist_tmp-") != null) continue;

            // `Dir.statFile` **fails on directories on Windows** (`error.IsDir`:
            // opening a directory as a file needs FILE_FLAG_BACKUP_SEMANTICS,
            // which std does not pass). `entry.kind` is populated correctly
            // there, so fall back to it instead of dropping the entry —
            // silently hiding every subdirectory is a far worse failure than
            // reporting a size of 0.
            const st: ?std.Io.File.Stat = d.statFile(rt.io(), entry.name, .{}) catch null;
            const is_dir = if (st) |s| kindOf(s) == .directory else entry.kind == .directory;

            var size: i64 = if (st) |s| @intCast(s.size) else 0;
            if (is_dir and self.cfg.directory_size) {
                // Go 在 `directory_size=true` 时用 DirectoryMap 给出子目录的
                // 递归大小；这里现算（见 dirSizeAbs 的注释）。
                const abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, rel, entry.name });
                size = dirSizeAbs(a, abs);
            }

            const full = try urlmod.joinPath(a, if (base.len == 1) "" else base, entry.name);
            try out.append(.{
                .name = try a.dupe(u8, entry.name),
                .size = size,
                .is_dir = is_dir,
                .modified = if (st) |s| mtimeSeconds(s) else 0,
                .sign = try a.dupe(u8, full),
            });
        }
        // Go 的 `readDir` 按名字升序排（`drivers/local/util.go:112`）；目录迭代
        // 顺序本身是文件系统给的，不排序前端列表就会与 Go 版不一致。
        std.mem.sort(model.Obj, out.sliceMut(), {}, struct {
            fn lt(_: void, x: model.Obj, y: model.Obj) bool {
                return std.mem.order(u8, x.name, y.name) == .lt;
            }
        }.lt);
        return out.toOwned();
    }

    fn details(p: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(p);
        const a = ctx.alloc;
        const rel = try self.relPath(a, path);
        const name = try a.dupe(u8, urlmod.baseName(path));

        if (rel.len == 0) {
            return .{ .name = "/", .is_dir = true };
        }
        var root = try self.openRoot();
        defer root.close(rt.io());
        if (root.statFile(rt.io(), rel, .{})) |st| {
            const is_dir = kindOf(st) == .directory;
            var size: i64 = @intCast(st.size);
            if (is_dir and self.cfg.directory_size) {
                const abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, rel });
                size = dirSizeAbs(a, abs);
            }
            return .{
                .name = name,
                .size = size,
                .is_dir = is_dir,
                .modified = mtimeSeconds(st),
            };
        } else |_| {
            // Same Windows caveat as `list`: `statFile` refuses directories.
            // Confirm it really is one before reporting it as missing.
            var probe = root.openDir(rt.io(), rel, .{}) catch return driver.Error.NotFound;
            probe.close(rt.io());
            var size: i64 = 0;
            if (self.cfg.directory_size) {
                const abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, rel });
                size = dirSizeAbs(a, abs);
            }
            return .{ .name = name, .is_dir = true, .size = size };
        }
    }

    /// Local files never leave the machine: hand the absolute path to the HTTP
    /// layer, which streams it directly. No redirect, no upstream request.
    fn link(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(p);
        const a = ctx.alloc;
        _ = args;
        const rel = try self.relPath(a, path);
        if (rel.len == 0) return driver.Error.NotFound;

        var root = try self.openRoot();
        defer root.close(rt.io());
        const st = root.statFile(rt.io(), rel, .{}) catch return driver.Error.NotFound;
        if (kindOf(st) == .directory) return driver.Error.NotSupported;

        const abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, rel });
        return .{
            .local_path = abs,
            .local_size = @intCast(st.size),
            .proxy = true,
        };
    }

    fn makeDir(p: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const rel = try self.relPath(a, dir);
        if (rel.len == 0) return; // root always exists
        var root = try self.openRoot();
        defer root.close(rt.io());
        // Go：`os.MkdirAll(fullPath, os.FileMode(d.mkdirPerm))` —— 权限来自
        // `mkdir_perm`（八进制串，默认 "777"）。`Dir.createDirPath` 不接受权限
        // 参数，所以这里逐级 createDir。
        try mkdirAllRel(root, a, rel, self.cfg.mkdirMode());
    }

    fn rename(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        // A bare name, not a path — reject anything that could escape.
        if (new_name.len == 0 or std.mem.indexOfScalar(u8, new_name, '/') != null) return error.InvalidPath;
        const src_rel = try self.relPath(a, src);
        if (src_rel.len == 0) return driver.Error.NotSupported;
        const dst_rel = try urlmod.joinPath(a, urlmod.parentPath(src), new_name);
        return self.moveRels(src_rel, try self.relPath(a, dst_rel));
    }

    fn move(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const src_rel = try self.relPath(a, src);
        if (src_rel.len == 0) return driver.Error.NotSupported;
        const dst_rel = try urlmod.joinPath(a, dst_dir, urlmod.baseName(src));
        return self.moveRels(src_rel, try self.relPath(a, dst_rel));
    }

    fn moveRels(self: *Local, src_rel: []const u8, dst_rel: []const u8) !void {
        if (dst_rel.len == 0) return error.InvalidPath;
        // 目标在源之下（或就是源）→ 拒绝。对齐 Go drivers/local/driver.go:293，
        // 避免把目录移进自己的子树导致 rename 行为异常 / 无限递归。
        if (isSubPath(src_rel, dst_rel)) return error.InvalidPath;
        var root = try self.openRoot();
        defer root.close(rt.io());
        // Make sure the destination directory exists, then rename.
        if (std.fs.path.dirname(dst_rel)) |d| {
            if (d.len > 0) root.createDirPath(rt.io(), d) catch {};
        }
        try root.rename(src_rel, root, dst_rel, rt.io());
    }

    fn remove(p: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const rel = try self.relPath(a, path);
        if (rel.len == 0) return error.InvalidPath; // never delete the root
        var root = try self.openRoot();
        defer root.close(rt.io());

        if (self.cfg.permanentDelete()) {
            if (is_dir) {
                try root.deleteTree(rt.io(), rel);
            } else {
                try root.deleteFile(rt.io(), rel);
            }
            return;
        }
        try self.moveToRecycleBin(a, root, rel, is_dir);
    }

    /// `recycle_bin_path`：把条目**移动**到 `<recycle>/<相对目录>/<原名>`，
    /// 重名时追加 `_YYYYMMDDhhmmss`（Go `drivers/local/driver.go:365-386`）。
    ///
    /// 与 Go 的差异（有意）：Go 用 `os.MkdirAll(bin, 0o755)` 建回收站目录，
    /// 这里用 `createDirPath`（默认权限）—— 平台无关；回收站与 root 跨文件系统
    /// 时 Go 的 `os.Rename` 会直接失败，这里退回「复制 + 删除」。
    fn moveToRecycleBin(self: *Local, a: std.mem.Allocator, root: std.Io.Dir, rel: []const u8, is_dir: bool) !void {
        const io = rt.io();
        const src_abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, rel });
        const sub = std.fs.path.dirname(rel) orelse "";
        const name = std.fs.path.basename(rel);

        const bin = std.mem.trim(u8, self.cfg.recycle_bin_path, " \t");
        const bin_dir = if (sub.len > 0)
            try std.fs.path.join(a, &.{ bin, sub })
        else
            try a.dupe(u8, bin);
        try std.Io.Dir.cwd().createDirPath(io, bin_dir);

        var dst_abs = try std.fs.path.join(a, &.{ bin_dir, name });
        if (pathExists(dst_abs)) {
            var b = Buf.init(a);
            defer b.deinit();
            try formatStamp(&b, rt.nowSeconds());
            dst_abs = try std.fs.path.join(a, &.{ bin_dir, try std.fmt.allocPrint(a, "{s}_{s}", .{ name, b.slice() }) });
        }

        std.Io.Dir.renameAbsolute(src_abs, dst_abs, io) catch |e| {
            if (e != error.RenameAcrossMountPoints) return e;
            try self.copyEntry(a, src_abs, dst_abs);
            if (is_dir) {
                try root.deleteTree(io, rel);
            } else {
                try root.deleteFile(io, rel);
            }
        };
    }

    // -----------------------------------------------------------------------
    // 复制（Go 的 `tryCopy`）
    // -----------------------------------------------------------------------

    /// `Driver.copy`：把 `src` 复制到 `dst_dir` 下（保持原名）。
    fn copy(p: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const src_rel = try self.relPath(a, src);
        if (src_rel.len == 0) return driver.Error.NotSupported; // 根不能复制
        // ⚠️ dst 也要过 `relPath`（和 `move` 一样）：`joinPath` 出的路径带前导
        // '/'，而 `relPath` 剥掉了它 —— 两端格式不一致时 `isSubPath` 会漏判，
        // `copy /a /a` 就会退化成「边建边遍历」的无限递归直到爆栈。
        const joined = try urlmod.joinPath(a, dst_dir, urlmod.baseName(src));
        const dst_rel = try self.relPath(a, joined);
        if (dst_rel.len == 0) return error.InvalidPath;
        // 目标在源之下 → 会无限递归。Go 用 `utils.IsSubPath` 拦同样的情形。
        if (isSubPath(src_rel, dst_rel)) return error.InvalidPath;

        const src_abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, src_rel });
        const dst_abs = try std.fs.path.join(a, &.{ self.cfg.root_folder, dst_rel });
        try self.copyEntry(a, src_abs, dst_abs);
    }

    /// 递归复制。
    ///
    /// Go 对**普通文件**走 `tryReflinkCopy`（CoW reflink），文件系统不支持时
    /// 返回 `NotImplement` 交给任务系统；本工程没有任务系统，所以这里退回普通
    /// 字节复制 —— 是 Go 行为的**超集**（Go 在不支持 reflink 的 FS 上根本复制
    /// 不了）。目录递归、软链重建、FIFO/设备的行为与 Go 对齐。
    fn copyEntry(self: *Local, a: std.mem.Allocator, src_abs: []const u8, dst_abs: []const u8) !void {
        const io = rt.io();
        const st = try std.Io.Dir.cwd().statFile(io, src_abs, .{});
        switch (st.kind) {
            .directory => {
                try mkdirAllAbs(a, dst_abs, self.cfg.mkdirMode());
                var d = try std.Io.Dir.cwd().openDir(io, src_abs, .{ .iterate = true });
                defer d.close(io);
                var it = d.iterate();
                while (try it.next(io)) |entry| {
                    const s = try std.fs.path.join(a, &.{ src_abs, entry.name });
                    const dd = try std.fs.path.join(a, &.{ dst_abs, entry.name });
                    try self.copyEntry(a, s, dd);
                }
            },
            .sym_link => {
                // 原样复制链接目标。Go 的 `copySymlink` 会把**相对**链接重写成
                // 「相对新位置」的等价形式；整棵树一起复制时两者等价（相对链接在
                // 新树里指向同一个兄弟节点），只有「只复制子树」才会不同。
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const n = try std.Io.Dir.cwd().readLink(io, src_abs, &buf);
                try mkdirAllAbs(a, std.fs.path.dirname(dst_abs) orelse ".", self.cfg.mkdirMode());
                try std.Io.Dir.cwd().symLink(io, buf[0..n], dst_abs, .{});
            },
            .named_pipe, .block_device, .character_device, .unix_domain_socket => return driver.Error.NotSupported,
            else => {
                try mkdirAllAbs(a, std.fs.path.dirname(dst_abs) orelse ".", self.cfg.mkdirMode());
                try std.Io.Dir.copyFileAbsolute(src_abs, dst_abs, io, .{ .replace = true });
            },
        }
    }

    /// Atomic write: stream into `<name>.openlist_tmp` in the same directory,
    /// then rename over the target. A power cut leaves either the old file or
    /// the new one, never a half-written one — which matters on a device whose
    /// storage is the same flash the OS runs from.
    fn put(p: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(p);
        const a = ctx.alloc;
        const rel = try self.relPath(a, dst);
        if (rel.len == 0) return error.InvalidPath;

        var root = try self.openRoot();
        defer root.close(rt.io());
        if (std.fs.path.dirname(rel)) |d| {
            if (d.len > 0) root.createDirPath(rt.io(), d) catch {};
        }

        // D09：临时名必须唯一。原来是 `{目标名}.openlist_tmp`，并发写同一个
        // 目标（或重试叠加）会拿到同一个临时文件互相 truncate。
        const seq = tmp_seq.fetchAdd(1, .monotonic);
        const tmp_rel = try std.fmt.allocPrint(a, "{s}.openlist_tmp-{d}-{d}", .{
            rel, rt.nowSeconds(), seq,
        });
        const f = try root.createFile(rt.io(), tmp_rel, .{ .truncate = true });
        // D09：rename 失败原来会走到这里再 close 一次已经关掉的句柄
        // （double close）。用 `closed` 把两种清理路径分开。
        var closed = false;
        errdefer {
            if (!closed) f.close(rt.io());
            root.deleteFile(rt.io(), tmp_rel) catch {};
        }

        const total: u64 = @intCast(@max(src.size(), 0));
        var off: u64 = 0;
        var buf: [128 * 1024]u8 = undefined;
        while (off < total) {
            const want: usize = @intCast(@min(@as(u64, buf.len), total - off));
            const n = try src.readAt(off, buf[0..want]);
            if (n == 0) break;
            try f.writeStreamingAll(rt.io(), buf[0..n]);
            off += n;
            if (ctx.progress) |cb| cb(ctx.progress_userdata, off);
        }
        // D09：`Source` 的契约是 size 已知。声明长度大于真实内容时必须判失败
        // —— 以前这里只 `break` 然后照样 rename，把一个被截断的文件原子地
        // 盖到目标上，原文件就这么没了。
        if (off != total) {
            log.err("[local] upload {s}: source declared {d} bytes, produced {d}", .{ rel, total, off });
            return error.UnexpectedEof;
        }

        try f.sync(rt.io());
        f.close(rt.io());
        closed = true;
        try root.rename(tmp_rel, root, rel, rt.io());
    }

    fn space(p: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        const self = as(p);
        _ = ctx;
        return statvfsUsage(self.cfg.root_folder);
    }
};

/// `struct statvfs`, LP64 layout (aarch64/x86_64, glibc *and* musl — the two
/// agree through `f_bfree`, which is all this reads).
///
/// Zig 0.14's `std.posix` carries no `statvfs`/`statfs` wrapper (only raw
/// syscall numbers in `std.os.linux`), and re-deriving the per-arch syscall
/// struct would be worse than declaring the stable libc ABI entry point. The
/// declaration is only *reachable* on Linux: the guard below is comptime, so
/// on the Windows dev host the call is never analysed and the symbol is never
/// referenced.
const Statvfs = extern struct {
    f_bsize: c_ulong,
    f_frsize: c_ulong,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: c_ulong,
    f_flag: c_ulong,
    f_namemax: c_ulong,
    __f_spare: [6]c_int,
};

extern "c" fn statvfs(path: [*:0]const u8, buf: *Statvfs) c_int;

/// Reports the filesystem holding `path`. On non-Linux hosts (the dev box)
/// this returns zeros: the API layer renders that as "unknown", which is
/// honest.
fn statvfsUsage(path: []const u8) driver.DiskUsage {
    if (builtin.os.tag != .linux) return .{};
    const z = std.heap.page_allocator.dupeSentinel(u8, path, 0) catch return .{};
    defer std.heap.page_allocator.free(z);
    var st: Statvfs = undefined;
    if (statvfs(z.ptr, &st) != 0) return .{};
    const bsize: u64 = @intCast(st.f_frsize);
    return .{
        .total = @intCast(@as(u64, @intCast(st.f_blocks)) * bsize),
        .used = @intCast((@as(u64, @intCast(st.f_blocks)) - @as(u64, @intCast(st.f_bfree))) * bsize),
    };
}

fn kindOf(st: std.Io.File.Stat) std.Io.File.Kind {
    return st.kind;
}

/// Unix seconds from the platform stat. Zig exposes mtime in nanoseconds as
/// `i128` on Linux; older stds used a different field name, hence the
/// `@hasField` guard rather than a hard-coded field access.
fn mtimeSeconds(st: std.Io.File.Stat) i64 {
    // 0.17 carries mtime as an `Io.Timestamp` (i96 nanoseconds) rather than a
    // bare `i128`, so the conversion is a method call now.
    return st.mtime.toSeconds();
}

// ---------------------------------------------------------------------------
// 目录创建 / 回收站辅助
// ---------------------------------------------------------------------------

/// 逐级建目录并套用 `mkdir_perm`。`Dir.createDirPath` 不接受权限参数，而 Go 的
/// MakeDir 是 `os.MkdirAll(fullPath, os.FileMode(d.mkdirPerm))`。
/// **已存在算成功**（MkdirAll 语义）—— 真机上这里踩过坑：对已存在的目录 MKCOL，
/// `createDirPath` 抛 `error.Unexpected`，WebDAV 层把它映射成 502。
fn mkdirAllRel(root: std.Io.Dir, a: std.mem.Allocator, rel: []const u8, mode: u32) !void {
    var prefix = Buf.init(a);
    defer prefix.deinit();
    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        // ⚠️ **不能**加前导 '/'：`rel` 是相对 root 句柄的，`createDir("/x")` 在
        // POSIX 下会忽略 dirfd 去创建**文件系统根**下的 /x。
        if (prefix.len > 0) try prefix.appendByte('/');
        try prefix.append(seg);
        try mkdirOne(root, prefix.slice(), mode);
    }
}

/// 同 `mkdirAllRel`，但接受**绝对路径**（回收站/复制用）。
/// 用 `dirname` 自底向上收集前缀、再自顶向下创建 —— 平台无关（不假设 '/' 分隔）。
fn mkdirAllAbs(a: std.mem.Allocator, abs: []const u8, mode: u32) !void {
    var chain = List([]const u8).init(a);
    defer chain.deinit();
    var cur: []const u8 = abs;
    while (true) {
        try chain.append(cur);
        const parent = std.fs.path.dirname(cur) orelse break;
        if (parent.len == 0 or parent.len >= cur.len) break;
        cur = parent;
    }
    var i = chain.len;
    while (i > 0) {
        i -= 1;
        try mkdirOne(std.Io.Dir.cwd(), chain.slice()[i], mode);
    }
}

fn mkdirOne(dir: std.Io.Dir, sub: []const u8, mode: u32) !void {
    const io = rt.io();
    dir.createDir(io, sub, @enumFromInt(mode)) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => {
            // 已存在但报的是别的错（某些平台/FS）也要算成功。
            var probe = dir.openDir(io, sub, .{}) catch return e;
            probe.close(io);
        },
    };
}

fn pathExists(abs: []const u8) bool {
    _ = std.Io.Dir.cwd().statFile(rt.io(), abs, .{}) catch return false;
    return true;
}

/// `child` 是否在 `parent` 之下（或就是它）。按**段**比较，避免 `a` vs `ab` 误判。
fn isSubPath(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, child)) return true;
    if (!std.mem.startsWith(u8, child, parent)) return false;
    return child.len > parent.len and child[parent.len] == '/';
}

/// 递归目录大小（字节）。Go 用 `DirectoryMap` 缓存同样的值；这里每次现算 ——
/// `directory_size` 是 opt-in 的，默认关。
fn dirSizeAbs(a: std.mem.Allocator, abs: []const u8) i64 {
    const io = rt.io();
    var total: i64 = 0;
    var d = std.Io.Dir.cwd().openDir(io, abs, .{ .iterate = true }) catch return 0;
    defer d.close(io);
    var it = d.iterate();
    while (it.next(io) catch null) |entry| {
        const st = d.statFile(io, entry.name, .{}) catch continue;
        switch (st.kind) {
            .directory => {
                const sub = std.fs.path.join(a, &.{ abs, entry.name }) catch continue;
                total += dirSizeAbs(a, sub);
            },
            .file => total += @intCast(st.size),
            else => {},
        }
    }
    return total;
}

/// Go 的 `time.Now().Format("20060102150405")`（本地时间；部署在 +08）。
fn formatStamp(b: *Buf, unix_s: i64) !void {
    const t = unix_s + 8 * 3600;
    const days = @divFloor(t, 86400);
    const secs = t - days * 86400;
    const c = timeutil.civilFromDays(days);
    try b.print("{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}", .{
        c.y, c.m, c.d, @divTrunc(secs, 3600), @divTrunc(@rem(secs, 3600), 60), @rem(secs, 60),
    });
}

pub const factory = driver.Factory{
    .key = "Local",
    .label = "本地存储",
    .secrets = &.{},
    // 表单 schema：键名与 Go `drivers/local/meta.go` 的 json tag 一致
    // （`root_folder_path` 来自内嵌的 `driver.RootPath`）。
    // `follow_symlinks` 是本工程的安全扩展字段，Go 的 Addition 里没有。
    .addition_schema =
    \\{
    \\  "root_folder_path":   {"type":"string","default":"/data","required":true,"help":"本地根目录，所有路径都被限制在此目录内"},
    \\  "show_hidden":        {"type":"bool","default":true,"help":"显示以点开头的隐藏文件"},
    \\  "follow_symlinks":    {"type":"bool","default":false,"help":"跟随符号链接（默认关闭：开启后任意可写目录都会变成全盘读取的入口）"},
    \\  "directory_size":     {"type":"bool","default":false,"help":"列表时递归统计子目录大小（很费 IO，默认关）"},
    \\  "mkdir_perm":         {"type":"string","default":"777","help":"新建目录的八进制权限"},
    \\  "recycle_bin_path":   {"type":"string","default":"delete permanently","help":"删除时移到此目录；留空或写 'delete permanently' 表示永久删除"},
    \\  "thumbnail":          {"type":"bool","default":false,"help":"[未实现] 缩略图：本工程不生成缩略图，字段仅为配置兼容"},
    \\  "pdf_thumbnail":      {"type":"bool","default":false,"help":"[未实现] PDF 首页缩略图"},
    \\  "thumb_cache_folder": {"type":"string","help":"[未实现] 缩略图缓存目录"},
    \\  "thumb_concurrency":  {"type":"string","default":"16","help":"[未实现] 缩略图并发生成数"},
    \\  "video_thumb_pos":    {"type":"string","default":"20%","help":"[未实现] 视频缩略图位置"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    // Local 没有需要回写的会话状态，用不到 storage id。
    _ = storage_id;
    const self = try alloc.create(Local);
    self.* = .{ .alloc = alloc, .cfg = try Addition.parse(alloc, cfg) };
    return driver.asDriver(Local, self);
}

// ---------------------------------------------------------------------------

const testing = std.testing;

fn testLocal(arena: std.mem.Allocator, root: []const u8) Local {
    return .{ .alloc = arena, .cfg = .{ .root_folder = root } };
}

test "relPath collapses dot segments and rejects escapes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = testLocal(a, "/data");

    try testing.expectEqualStrings("", try l.relPath(a, "/"));
    try testing.expectEqualStrings("a", try l.relPath(a, "/a"));
    try testing.expectEqualStrings("a/b", try l.relPath(a, "/a//b/"));
    // `..` is resolved by cleanPath, so this stays inside the root
    try testing.expectEqualStrings("b", try l.relPath(a, "/a/../b"));
    // ...and a path that tries to climb above the root collapses to ""
    try testing.expectEqualStrings("", try l.relPath(a, "/../../../.."));
}

test "list/put/link/remove round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    try d.makeDir(&ctx, "/sub");

    // Regression: a directory must show up in its parent's listing even where
    // `statFile` refuses directories (Windows returns `error.IsDir`). The
    // original code did `statFile(...) catch continue`, which silently hid
    // every subdirectory.
    {
        const top = try d.list(&ctx, "/");
        try testing.expectEqual(@as(usize, 1), top.len);
        try testing.expectEqualStrings("sub", top[0].name);
        try testing.expect(top[0].is_dir);
        // ...and `details` must find it, which is what `/api/fs/remove` stats
        // before deciding file-vs-directory.
        try testing.expect((try d.details(&ctx, "/sub")).is_dir);
    }

    // Build a seekable source over some bytes and upload it.
    var payload = [_]u8{ 'h', 'e', 'l', 'l', 'o', ' ', 'z', 'i', 'g' };
    var body = @import("../http.zig").Body{ .memory = &payload };
    try d.put(&ctx, "/sub/hello.txt", body.source());

    const objs = try d.list(&ctx, "/sub");
    try testing.expectEqual(@as(usize, 1), objs.len);
    try testing.expectEqualStrings("hello.txt", objs[0].name);
    try testing.expectEqual(@as(i64, 9), objs[0].size);
    try testing.expect(!objs[0].is_dir);

    const f = try d.details(&ctx, "/sub/hello.txt");
    try testing.expectEqual(@as(i64, 9), f.size);

    const lnk = try d.link(&ctx, "/sub/hello.txt", .{});
    try testing.expect(lnk.local_path != null);
    try testing.expectEqual(@as(u64, 9), lnk.local_size);
    const on_disk = try std.Io.Dir.cwd().readFileAlloc(rt.io(), lnk.local_path.?, a, .limited(1024));
    try testing.expectEqualStrings("hello zig", on_disk);

    try d.rename(&ctx, "/sub/hello.txt", "renamed.txt");
    _ = try d.details(&ctx, "/sub/renamed.txt");

    try d.remove(&ctx, "/sub/renamed.txt", false);
    try testing.expectEqual(@as(usize, 0), (try d.list(&ctx, "/sub")).len);

    try d.remove(&ctx, "/sub", true);
    try testing.expectEqual(@as(usize, 0), (try d.list(&ctx, "/")).len);
}

test "show_hidden defaults to true (matches Go's default:\"true\")" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 缺省 / 空对象都必须给 true —— Go `drivers/local/meta.go:10` 是 default:"true"。
    try testing.expect((try Addition.parse(a, null)).show_hidden);
    const empty = try json.parse(a, "{}");
    try testing.expect((try Addition.parse(a, &empty)).show_hidden);

    // 显式 false 仍要被尊重。
    const off = try json.parse(a, "{\"show_hidden\":false}");
    try testing.expect(!(try Addition.parse(a, &off)).show_hidden);
}

test "list returns entries sorted by name (Go sorts in readDir)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    // 故意按**非字母序**创建，确保测的是排序而不是文件系统的返回顺序。
    for ([_][]const u8{ "c.txt", "a.txt", "b.txt" }) |n| {
        var f = try tmp.dir.createFile(rt.io(), n, .{});
        f.close(rt.io());
    }

    var l = testLocal(a, root);
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    const objs = try d.list(&ctx, "/");
    try testing.expectEqual(@as(usize, 3), objs.len);
    try testing.expectEqualStrings("a.txt", objs[0].name);
    try testing.expectEqualStrings("b.txt", objs[1].name);
    try testing.expectEqualStrings("c.txt", objs[2].name);
}

test "init resolves a relative root to an absolute path" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // `.` 一定存在，且是相对的；init 之后必须变成绝对路径，否则
    // `link.local_path` 会相对进程 CWD。
    var l = testLocal(a, ".");
    try testing.expect(!std.fs.path.isAbsolute(l.cfg.root_folder));
    var ctx = driver.Ctx{ .alloc = a };
    try Local.init(@ptrCast(&l), &ctx);
    try testing.expect(std.fs.path.isAbsolute(l.cfg.root_folder));
}

test "mkdir_perm is applied to created directories (POSIX only)" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    l.cfg.mkdir_perm = "700"; // 默认是 777
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };
    try d.makeDir(&ctx, "/perm");

    const abs = try std.fs.path.join(a, &.{ root, "perm" });
    const st = try std.Io.Dir.cwd().statFile(rt.io(), abs, .{});
    const mode: u32 = @intCast(@intFromEnum(st.permissions));
    // 700：owner rwx，group/other 全 0。默认 777 会留下 755，所以这条能真正区分。
    try testing.expectEqual(@as(u32, 0o700), mode & 0o777);
}

test "mkdir_perm parsing falls back to 777 on garbage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const add = try Addition.parse(a, null);
    try testing.expectEqual(@as(u32, 0o777), add.mkdirMode());
    const v = try json.parse(a, "{\"mkdir_perm\":\"750\"}");
    try testing.expectEqual(@as(u32, 0o750), (try Addition.parse(a, &v)).mkdirMode());
    const bad = try json.parse(a, "{\"mkdir_perm\":\"not-octal\"}");
    try testing.expectEqual(@as(u32, 0o777), (try Addition.parse(a, &bad)).mkdirMode());
    // Go 那边声明成 string，但老配置里见过数字。
    const num = try json.parse(a, "{\"mkdir_perm\":755}");
    try testing.expectEqual(@as(u32, 0o755), (try Addition.parse(a, &num)).mkdirMode());
}

test "recycle_bin_path moves the entry instead of deleting it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(base);
    const root = try std.fs.path.join(a, &.{ base, "root" });
    const bin = try std.fs.path.join(a, &.{ base, "bin" });
    try std.Io.Dir.cwd().createDirPath(rt.io(), root);

    var l = testLocal(a, root);
    l.cfg.recycle_bin_path = bin; // 非 "delete permanently" → 进回收站
    try testing.expect(!l.cfg.permanentDelete());
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    try d.makeDir(&ctx, "/sub");
    var payload = [_]u8{ 'h', 'i' };
    var body = @import("../http.zig").Body{ .memory = &payload };
    try d.put(&ctx, "/sub/gone.txt", body.source());

    try d.remove(&ctx, "/sub/gone.txt", false);

    // 原位置没了……
    try testing.expectEqual(@as(usize, 0), (try d.list(&ctx, "/sub")).len);
    // ……但回收站里 <bin>/sub/gone.txt 在（相对目录结构被保留）。
    const moved = try std.fs.path.join(a, &.{ bin, "sub", "gone.txt" });
    const on_disk = try std.Io.Dir.cwd().readFileAlloc(rt.io(), moved, a, .limited(16));
    try testing.expectEqualStrings("hi", on_disk);
}

test "directory_size reports the recursive size of a subdirectory" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    l.cfg.directory_size = true;
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    try d.makeDir(&ctx, "/sub");
    var p3 = [_]u8{ 'a', 'b', 'c' };
    var p4 = [_]u8{ 'd', 'e', 'f', 'g' };
    var b3 = @import("../http.zig").Body{ .memory = &p3 };
    var b4 = @import("../http.zig").Body{ .memory = &p4 };
    try d.put(&ctx, "/sub/a.bin", b3.source());
    try d.put(&ctx, "/sub/b.bin", b4.source());

    const top = try d.list(&ctx, "/");
    try testing.expectEqual(@as(usize, 1), top.len);
    try testing.expect(top[0].is_dir);
    try testing.expectEqual(@as(i64, 7), top[0].size); // 3 + 4

    // details 也要给同样的值。
    try testing.expectEqual(@as(i64, 7), (try d.details(&ctx, "/sub")).size);
}

test "copy duplicates a file and recurses into a directory" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    try d.makeDir(&ctx, "/src");
    try d.makeDir(&ctx, "/dst");
    var payload = [_]u8{ 'c', 'o', 'p', 'y', 'm', 'e' };
    var body = @import("../http.zig").Body{ .memory = &payload };
    try d.put(&ctx, "/src/one.txt", body.source());

    // 单文件复制
    try d.copy(&ctx, "/src/one.txt", "/dst");
    const got = try d.details(&ctx, "/dst/one.txt");
    try testing.expectEqual(@as(i64, 6), got.size);

    // 目录递归复制（含子文件）
    try d.copy(&ctx, "/src", "/dst");
    try testing.expectEqual(@as(i64, 6), (try d.details(&ctx, "/dst/src/one.txt")).size);

    // 目标在源之下 → 拒绝（否则无限递归）
    try testing.expectError(error.InvalidPath, d.copy(&ctx, "/src", "/src"));
}

test "remove refuses the root" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = testLocal(a, "/tmp");
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };
    try testing.expectError(error.InvalidPath, d.remove(&ctx, "/", true));
}

test "rename rejects a name containing a slash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = testLocal(a, "/tmp");
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };
    try testing.expectError(error.InvalidPath, d.rename(&ctx, "/a", "../b"));
}

test "put is atomic — the temp file is renamed over the target" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    var first = [_]u8{ 'o', 'l', 'd' };
    var b1 = @import("../http.zig").Body{ .memory = &first };
    try d.put(&ctx, "/f.txt", b1.source());

    var second = [_]u8{ 'n', 'e', 'w', 'e', 'r' };
    var b2 = @import("../http.zig").Body{ .memory = &second };
    try d.put(&ctx, "/f.txt", b2.source());

    const got = try std.Io.Dir.cwd().readFileAlloc(rt.io(), try std.fs.path.join(a, &.{ root, "f.txt" }), a, .limited(1024));
    try testing.expectEqualStrings("newer", got);
    // no temp files left behind
    const objs = try d.list(&ctx, "/");
    try testing.expectEqual(@as(usize, 1), objs.len);
}

test "relPath does not reject legal names containing a double dot" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = testLocal(a, "/data");

    // D07 回归：以前 `relPath` 用子串匹配 `..`，这些完全合法的文件名会被
    // 一起拒掉（`v1..2.tar` 是常见版本号写法，`..cache` 也是合法名字）。
    try testing.expectEqualStrings("v1..2.tar", try l.relPath(a, "/v1..2.tar"));
    try testing.expectEqualStrings("..cache", try l.relPath(a, "/..cache"));
    try testing.expectEqualStrings("a/..hidden", try l.relPath(a, "/a/..hidden"));
}

/// 一个"说谎"的 Source：声明的长度大于它真能给出的字节数。
const ShortSource = struct {
    data: []const u8,
    declared: i64,

    fn sizeFn(ptr: *anyopaque) i64 {
        const s: *ShortSource = @ptrCast(@alignCast(ptr));
        return s.declared;
    }
    fn readAtFn(ptr: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
        const s: *ShortSource = @ptrCast(@alignCast(ptr));
        if (offset >= s.data.len) return 0;
        const n = @min(buf.len, s.data.len - offset);
        @memcpy(buf[0..n], s.data[offset..][0..n]);
        return n;
    }
    fn source(self: *ShortSource) driver.Source {
        return .{ .ptr = self, .vtable = &.{ .size = sizeFn, .readAt = readAtFn } };
    }
};

test "put refuses a source shorter than its declared size" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var l = testLocal(a, root);
    const d = driver.asDriver(Local, &l);
    var ctx = driver.Ctx{ .alloc = a };

    // 先把目标写成一个已知内容的文件。
    var good = [_]u8{ 'G', 'O', 'O', 'D' };
    var gb = @import("../http.zig").Body{ .memory = &good };
    try d.put(&ctx, "/target.bin", gb.source());

    // D09 回归：声明 4096 字节但只给得出 2 字节。以前这里只 `break` 就照样
    // rename，把 2 字节的残缺内容原子地盖到目标上 —— 原文件静默丢失。
    var payload = [_]u8{ 'h', 'i' };
    var src = ShortSource{ .data = &payload, .declared = 4096 };
    try testing.expectError(error.UnexpectedEof, d.put(&ctx, "/target.bin", src.source()));

    // 目标文件必须原封不动，且临时文件已清理。
    const still = try d.details(&ctx, "/target.bin");
    try testing.expectEqual(@as(i64, 4), still.size);
    try testing.expectEqual(@as(usize, 1), (try d.list(&ctx, "/")).len);
}

test "Addition.parse accepts Go's root_folder_path alias" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // C01 / T3 回归：键集与用户 Go 备份 storage #13 一致；Go 的 Local addition
    // 只有 `root_folder_path`，没有 Zig 这边的 `root_folder`。以前这里读不到，
    // 静默回落到 `/data`。
    var parsed = std.heap.ArenaAllocator.init(testing.allocator);
    defer parsed.deinit();
    const pa = parsed.allocator();

    const go_v = try json.parse(pa,
        \\{"root_folder_path":"/mnt/usb","show_hidden":true,"mkdir_perm":"777"}
    );
    const add = try Addition.parse(a, &go_v);
    try testing.expectEqualStrings("/mnt/usb", add.root_folder);
    try testing.expect(add.show_hidden);

    // T3：两者并存时**以 Go 名为准**（修复前这里断言的正是相反的方向）。
    const both = try json.parse(pa,
        \\{"root_folder":"/native","root_folder_path":"/go"}
    );
    const add2 = try Addition.parse(a, &both);
    try testing.expectEqualStrings("/go", add2.root_folder);

    // 本工程旧名（`root_folder`）仍要认，别把早期配置读坏。
    const legacy = try json.parse(pa, "{\"root_folder\":\"/legacy\"}");
    const add3 = try Addition.parse(a, &legacy);
    try testing.expectEqualStrings("/legacy", add3.root_folder);
}
