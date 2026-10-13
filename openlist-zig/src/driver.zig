//! Driver interface (hand-rolled vtable) + registry.
//!
//! Zig has no interfaces, so each driver is a struct with a `driver() Driver`
//! method returning a type-erased `{ptr, vtable}` pair. This is the same shape
//! as `std.mem.Allocator` and costs one indirect call per operation — nothing
//! measurable next to the network round-trip every one of these performs.
//!
//! The method set is a deliberate subset of OpenList's `driver.Driver`
//! interface: only what `local / webdav / itvsh / 189 / 189pc / 123_open /
//! aliyundrive_open / quark_open / 115_open` actually need, plus `put`, which
//! most of them override. Deliberately absent: `copy`, `putURL`, `getArchive`,
//! `extractArchive`, `mkdir`-with-recursion, and every optional capability
//! interface (`ObjThumb`, `ObjUpload`, `ObjReader`, `ArchiveReader`, ...).
//! Each of those is a documented, budgeted extension point rather than a
//! blank check.

const std = @import("std");
const model = @import("model.zig");
const json = @import("util/json.zig");

pub const Obj = model.Obj;
pub const File = model.File;
pub const Link = model.Link;
pub const LinkArgs = model.LinkArgs;
pub const Source = model.Source;

/// Per-call context. The allocator is a request-scoped arena: drivers allocate
/// freely and nothing is freed individually.
pub const Ctx = struct {
    alloc: std.mem.Allocator,
    /// Prefix used in log lines, e.g. `[/nas]` or `[itvsh:家庭共享]`.
    tag: []const u8 = "",
    /// Optional upload progress sink. Mirrors OpenList's
    /// `driver.UpdateProgress` so the frontend's chunked upload can show a bar.
    /// `null` means "caller does not care about progress".
    progress: ?ProgressFn = null,
    /// Opaque per-request state handed back to `progress`.
    progress_userdata: ?*anyopaque = null,
};

/// Signature for the upload progress callback.
///
/// `percentage` is **0–100**, matching Go's `model.UpdateProgress`
/// (`internal/model/obj.go:59` → `func(percentage float64)`). This is *not* a
/// byte count: the Go frontend scales it straight into its upload progress bar.
///
/// ⚠️ 曾经这里签名是 `bytes: u64`、文档写"累计字节数"，而 4 个驱动里 3 个
/// 传的是百分比 —— 语义分裂。现已统一为百分比；传字节的 pan115 已改。
pub const ProgressFn = *const fn (userdata: ?*anyopaque, percentage: u64) void;

pub const Driver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,

        /// One-time setup after construction: validate config, log in, restore
        /// cookies. Called once at startup and again on config reload.
        init: *const fn (ptr: *anyopaque, ctx: *Ctx) anyerror!void,

        /// Release driver-owned resources. Must tolerate being called after a
        /// failed `init`.
        deinit: *const fn (ptr: *anyopaque, ctx: *Ctx) void,

        list: *const fn (ptr: *anyopaque, ctx: *Ctx, dir: []const u8) anyerror![]Obj,

        details: *const fn (ptr: *anyopaque, ctx: *Ctx, path: []const u8) anyerror!File,

        link: *const fn (ptr: *anyopaque, ctx: *Ctx, path: []const u8, args: LinkArgs) anyerror!Link,

        makeDir: *const fn (ptr: *anyopaque, ctx: *Ctx, dir: []const u8) anyerror!void,

        /// `dst_dir` is the destination *directory*; the entry keeps its name.
        move: *const fn (ptr: *anyopaque, ctx: *Ctx, src: []const u8, dst_dir: []const u8) anyerror!void,

        /// `new_name` is a bare name, not a path — the entry stays in its
        /// current directory. This mirrors OpenList's `Rename(srcObj, newName)`
        /// and, importantly, the itvsh API, whose rename method takes
        /// (directory, filename, newFilename).
        rename: *const fn (ptr: *anyopaque, ctx: *Ctx, src: []const u8, new_name: []const u8) anyerror!void,

        /// `is_dir` is passed in rather than probed: itvsh needs a different
        /// upstream method for files and directories, and every caller
        /// (WebDAV DELETE, /api/fs/remove) already knows the answer from the
        /// entry it just looked up.
        remove: *const fn (ptr: *anyopaque, ctx: *Ctx, path: []const u8, is_dir: bool) anyerror!void,

        put: *const fn (ptr: *anyopaque, ctx: *Ctx, dst: []const u8, src: Source) anyerror!void,

        /// Copy `src` into `dst_dir`, keeping the entry's name (same shape as
        /// `move`). Optional: `null` means the driver cannot copy (itvsh /
        /// 123Pan / Quark are `NotSupport` upstream too) and `Driver.copy`
        /// returns `NotSupported`.
        copy: ?*const fn (ptr: *anyopaque, ctx: *Ctx, src: []const u8, dst_dir: []const u8) anyerror!void = null,

        /// Optional. Null means "no quota information"; the API then reports
        /// zeroes rather than an error, matching OpenList's behaviour for
        /// drivers that do not implement `GetDetails`.
        space: ?*const fn (ptr: *anyopaque, ctx: *Ctx) anyerror!DiskUsage = null,
    };

    pub fn name(self: Driver) []const u8 {
        return self.vtable.name(self.ptr);
    }
    pub fn init(self: Driver, ctx: *Ctx) !void {
        return self.vtable.init(self.ptr, ctx);
    }
    pub fn deinit(self: Driver, ctx: *Ctx) void {
        self.vtable.deinit(self.ptr, ctx);
    }
    pub fn list(self: Driver, ctx: *Ctx, dir: []const u8) ![]Obj {
        return self.vtable.list(self.ptr, ctx, dir);
    }
    pub fn details(self: Driver, ctx: *Ctx, path: []const u8) !File {
        return self.vtable.details(self.ptr, ctx, path);
    }
    pub fn link(self: Driver, ctx: *Ctx, path: []const u8, args: LinkArgs) !Link {
        return self.vtable.link(self.ptr, ctx, path, args);
    }
    pub fn makeDir(self: Driver, ctx: *Ctx, dir: []const u8) !void {
        return self.vtable.makeDir(self.ptr, ctx, dir);
    }
    pub fn move(self: Driver, ctx: *Ctx, src: []const u8, dst_dir: []const u8) !void {
        return self.vtable.move(self.ptr, ctx, src, dst_dir);
    }
    pub fn rename(self: Driver, ctx: *Ctx, src: []const u8, new_name: []const u8) !void {
        return self.vtable.rename(self.ptr, ctx, src, new_name);
    }
    pub fn remove(self: Driver, ctx: *Ctx, path: []const u8, is_dir: bool) !void {
        return self.vtable.remove(self.ptr, ctx, path, is_dir);
    }
    pub fn put(self: Driver, ctx: *Ctx, dst: []const u8, src: Source) !void {
        return self.vtable.put(self.ptr, ctx, dst, src);
    }
    /// `dst_dir` is the destination *directory*; the entry keeps its name.
    /// Drivers without a copy capability report `NotSupported`.
    pub fn copy(self: Driver, ctx: *Ctx, src: []const u8, dst_dir: []const u8) !void {
        const f = self.vtable.copy orelse return Error.NotSupported;
        return f(self.ptr, ctx, src, dst_dir);
    }
    /// Never fails: an unsupported driver reports zero capacity.
    pub fn space(self: Driver, ctx: *Ctx) DiskUsage {
        const f = self.vtable.space orelse return .{};
        return f(self.ptr, ctx) catch .{};
    }
};

pub const DiskUsage = struct {
    total: i64 = 0,
    used: i64 = 0,
};

/// Installed by `main.zig`. Drivers call `persist()` when they have mutated
/// their own `addition` blob (itvsh stores its session cookies and the
/// per-user `forwardUrl` there) so the change survives a reboot.
///
/// A hook rather than a direct call into `config.zig`, because `driver.zig`
/// must stay importable by drivers without dragging the whole config layer in.
pub var persist_hook: ?*const fn (storage_id: i64, addition_json: []const u8) void = null;

pub fn persist(storage_id: i64, addition_json: []const u8) void {
    if (persist_hook) |h| h(storage_id, addition_json);
}

// ---------------------------------------------------------------------------
// fs bridge —— Strm 驱动回调本实例其他挂载的通道
// ---------------------------------------------------------------------------

/// Strm（`drivers/strm`）的特殊之处：它不做任何自己的存储 IO，而是把**同一
/// OpenList 实例里其他挂载**的目录映射成 `.strm` 虚拟文件。Go 侧直接调
/// `internal/fs`（`fs.List` / `fs.Get`）和 `op.Link` / `common.GetApiUrl` /
/// `sign.Sign`；本工程的驱动层不能反向依赖 App，所以由 App 在启动时安装
/// 这组函数指针（`api.installFsBridge`），驱动经全局单例调用。
pub const FsBridge = struct {
    ctx: *anyopaque,

    /// Go `fs.Get`：解析虚拟路径到具体挂载并取对象详情。不存在 → error.NotFound。
    get: *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror!File,
    /// Go `fs.List`（NoLog、按需 Refresh；本实现无缓存层，语义等价）。
    list: *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]Obj,
    /// Go `op.Link`：目标挂载的真实下载链接（不经过 Strm 的 OnlyProxy 包装）。
    link: *const fn (
        ctx: *anyopaque,
        alloc: std.mem.Allocator,
        path: []const u8,
        args: LinkArgs,
    ) anyerror!Link,
    /// Go `sign.Sign(path)`（expire=0，永不过期），secret 用实例 jwt_secret。
    sign: *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]const u8,
    /// Go `common.GetApiUrl(ctx)` 的无请求回退形态：settings 里的 site_url。
    site_url: *const fn (ctx: *anyopaque) []const u8,
};

/// 由 `main.zig`（经 `api.installFsBridge`）在 App 构造后安装。为 null 时
/// Strm 驱动的 list/get 返回 NotFound —— 与 Go 在无存储时 `op.GetStorageAndActualPath`
/// 失败的行为一致。
pub var fs_bridge: ?FsBridge = null;

// ---------------------------------------------------------------------------
// objs-update hook —— Go `op.RegisterObjsUpdateHook` 的对应物
// ---------------------------------------------------------------------------

/// Go `internal/op/hook.go` 的 `ObjsUpdateHook = func(ctx, parent, objs)`。
/// 本工程只有 Strm 的 `UpdateLocalStrm` 这一个使用者，所以用单槽而不是列表；
/// 将来出现第二个钩子再扩成列表。
pub const ObjsUpdateHook = *const fn (
    ctx: *anyopaque,
    alloc: std.mem.Allocator,
    parent: []const u8,
    objs: []const Obj,
) void;

var objs_update_hook: ?struct {
    func: ObjsUpdateHook,
    ctx: *anyopaque,
} = null;

/// 由驱动注册（幂等：后注册者覆盖 —— 本工程只有一个使用者）。
pub fn registerObjsUpdateHook(func: ObjsUpdateHook, ctx: *anyopaque) void {
    objs_update_hook = .{ .func = func, .ctx = ctx };
}

/// Go `op.HandleObjsUpdateHook`。写操作处理层在配置开关
/// `zig.handle_hook_after_writing`（对齐 Go settings `handle_hook_after_writing`，
/// 默认 false）打开时调用。
pub fn notifyObjsUpdate(alloc: std.mem.Allocator, parent: []const u8, objs: []const Obj) void {
    const h = objs_update_hook orelse return;
    h.func(h.ctx, alloc, parent, objs);
}

/// Ergonomic wrapper: `drv.list(ctx, path)` on a concrete `*T`.
pub fn asDriver(comptime T: type, ptr: *T) Driver {
    return .{ .ptr = ptr, .vtable = &T.vtable };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub const Factory = struct {
    /// Value stored in `Storage.driver`.
    ///
    /// 必须与 Go `driver.Config.Name` **逐字节相同** —— Go 把驱动名直接写进
    /// 配置的 `Storage.driver`，改名就等于读不懂已有配置。例如 itvsh 的 Go 名
    /// 是「上海电信智家硬盘」（drivers/itvsh/meta.go:34），不是 "Itvsh"。
    key: []const u8,
    /// 额外可接受的写法（本工程历史名等）。只用于查找，不用于写出。
    aliases: []const []const u8 = &.{},
    /// One-line description shown in the admin UI.
    label: []const u8,
    /// JSON text of the `addition` schema (field name -> default/type), served
    /// to the frontend so it can render the storage form without a rebuild.
    addition_schema: []const u8,
    /// Config keys that must be redacted before echoing config back.
    secrets: []const []const u8,
    /// `storage_id` is the real id of the `Storage` row being constructed.
    ///
    /// 驱动用它把刷新后的 token / cookie / forwardUrl 写回配置文件（见
    /// `persist`）。以前这个参数不存在，所有驱动内部都以 id=0 构造，
    /// `persistStorage(0)` 在 `storageById(0)` 查无记录 —— 会话只在进程内
    /// 有效，重启就丢，refresh token 轮换后可能彻底失效。
    ///
    /// `cfg` is the parsed `addition` object, or null when the storage has an
    /// empty/missing `addition` — drivers must tolerate both.
    create: *const fn (alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) anyerror!Driver,
};

/// Built-in driver table. Explicit rather than self-registering: Zig has no
/// static initialisers, and an explicit list makes the size cost of each
/// driver visible in one place — which is the whole point of this exercise.
pub const builtin = [_]Factory{
    @import("drivers/local.zig").factory,
    @import("drivers/webdav.zig").factory,
    @import("drivers/itvsh.zig").factory,
    @import("drivers/aliyundrive.zig").factory,
    @import("drivers/cloud189.zig").factory,
    @import("drivers/cloud189pc.zig").factory,
    // T2（2026-10-12）：补上的三个正确变体（用户配置 + build_sqfs.yml
    // 默认清单用的是这些，不是 `_open` 系列）。
    @import("drivers/pan123.zig").factory, // 123Pan（用户名+密码）
    @import("drivers/quarkuc.zig").factory, // Quark（Cookie）
    @import("drivers/pan115.zig").factory, // 115 Cloud（Cookie）
    @import("drivers/wopan.zig").factory, // WoPan（联通沃云盘，refresh_token）
    @import("drivers/strm.zig").factory, // Strm（把其他挂载映射成 .strm，2026-10-14）

    // ---------------------------------------------------------------------
    // 暂时下线的入口 —— 这几个是**做错了变体**的驱动，代码保留、不删，
    // 只是不注册进 `builtin`，所以不会出现在驱动列表里，也不会被配置命中。
    //
    // OpenList 里同一个网盘常有两个互不兼容的驱动：
    //   `123`/`123Pan`(用户名+密码)      vs `123_open`/`123 Open`(开放平台)
    //   `quark_uc`/`Quark`(Cookie)       vs `quark_open`/`QuarkOpen`(refresh_token)
    //   `115`/`115 Cloud`(Cookie)        vs `115_open`/`115 Open`(开放平台)
    //
    // T2 已补齐前者，后者按用户 2026-10-12 的指示保留代码但不注册。
    // ---------------------------------------------------------------------
    // @import("drivers/123open.zig").factory,   // 123 Open
    // @import("drivers/quark.zig").factory,     // QuarkOpen
    // @import("drivers/115open.zig").factory,   // 115 Open
};

pub fn find(key: []const u8) ?*const Factory {
    for (&builtin) |*f| {
        if (std.ascii.eqlIgnoreCase(f.key, key)) return f;
    }
    // 第二遍才查别名：正式名永远优先，避免别名遮蔽同名的其它驱动。
    for (&builtin) |*f| {
        for (f.aliases) |alias| {
            if (std.ascii.eqlIgnoreCase(alias, key)) return f;
        }
    }
    return null;
}

/// Keys of all compiled-in drivers, for `/api/admin/driver/list`.
pub fn keys(alloc: std.mem.Allocator) ![][]const u8 {
    var out = try alloc.alloc([]const u8, builtin.len);
    for (&builtin, 0..) |*f, i| out[i] = f.key;
    return out;
}

// ---------------------------------------------------------------------------
// Shared driver errors — mapped to HTTP status by the API layer
// ---------------------------------------------------------------------------

pub const Error = error{
    /// Credentials rejected, or session token expired and re-login failed.
    AuthFailed,
    /// Path does not exist.
    NotFound,
    /// Operation not supported by this driver.
    NotSupported,
    /// Upstream rate-limited us; caller should back off.
    RateLimited,
    /// Upstream returned a well-formed response we could not interpret.
    UnexpectedResponse,
};
