//! HTTP API surface, shaped to match OpenList's `/api/*` so the existing web
//! frontend works against this binary unchanged.
//!
//! Implemented (the subset the frontend actually calls for browsing,
//! downloading and uploading):
//!   GET  /ping                         liveness
//!   GET  /api/public/settings          site config + whether setup is done
//!   POST /api/auth/login               -> JWT
//!   GET  /api/public/init_status       whether the system is initialised
//!   POST /api/public/init/setup        first-run admin creation
//!   POST /api/fs/list                  browse a directory
//!   POST /api/fs/get                   stat a path
//!   POST /api/fs/dirs                  list mount points
//!   POST /api/fs/mkdir                 create a directory
//!   POST /api/fs/rename                rename in place
//!   POST /api/fs/move                  move across directories
//!   POST /api/fs/remove                delete
//!   PUT  /api/fs/put                   upload (body = raw bytes, File-Path header)
//!   GET  /d/* and /p/*                 download / proxied download (Range-aware)
//!
//! Admin surface (single-admin build: every authenticated user is the admin):
//!   GET  /api/me                       current user
//!   GET  /api/admin/storage/list       mount list (settings UI)
//!   GET  /api/admin/driver/{list,names} driver metadata and names
//!   GET  /api/admin/setting/{list,get,default}
//!   POST /api/admin/setting/save       persist config-backed settings
//!   GET  /api/task/<kind>/{undone,done} empty lists (no job queue in this build)
//!   GET  /api/admin/setting + PUT      compact compatibility alias
//!
//! Deliberately absent, with reasons in docs/STATUS.md: search (needs
//! bleve), share links, and the full task-centre CRUD (the tasks listed above
//! are read-only admin lookups; there is no background job queue yet). SSO
//! admin, archives browsing, and offline download are also not implemented.
//! (A WebDAV server is served at /dav — see webdav.zig.)

const std = @import("std");
const http = @import("http.zig");
const model = @import("model.zig");
const driver = @import("driver.zig");
const json = @import("util/json.zig");
const urlmod = @import("util/url.zig");
const config = @import("config.zig");
const log = @import("log.zig");
const client_mod = @import("client.zig");
const cookiejar = @import("cookiejar.zig");
const frontend_mod = @import("frontend.zig");
const webdav = @import("webdav.zig");
const archive = @import("archive.zig");
const Buf = @import("util/buf.zig").Buf;
const List = @import("util/buf.zig").List;
const rt = @import("rt.zig");

pub const Header = model.Header;

/// One configured storage, paired with its live driver instance.
pub const Mount = struct {
    storage: model.Storage,
    driver: driver.Driver,
    /// Normalised: always starts with '/', never ends with one (except "/").
    mount_path: []const u8,
    /// Human-readable driver label, for `/api/fs/dirs`.
    label: []const u8,
};

pub const App = struct {
    alloc: std.mem.Allocator,
    /// T6：mounts 由**后台线程一次性发布**（对齐 Go 的 LoadStorages goroutine
    /// + 立即监听），所以读写需要闸门。契约：
    ///   * 写方（main.zig 的 buildMountsWorker）只做**整 slice 替换**，
    ///     替换前完成所有驱动 init，替换后内容永不再变；
    ///   * 读方只取**快照**（持锁拷一个 slice 头，16 字节）；
    ///   * 拿到快照后**绝不持锁调用驱动** —— 那会串行化所有请求。
    /// 0.17：`std.Thread.Mutex` 并入 `std.Io.Mutex`，lock/unlock 都要 io。
    mounts_lock: std.Io.Mutex = .init,
    mounts: []Mount,
    /// `sha256(sha256(pw + "-" + StaticHashSalt) + "-" + salt)` —— 与 Go
    /// `User.PwdHash` 同形（`model.TwoHashPwd`）。空 = 还没建管理员。
    admin_hash: []const u8,
    /// 每用户随机 salt（Go `User.Salt`）；没有它就算不出 PwdHash。
    /// 给默认值是为了让那些只关心路由的测试构造（`App{...}`）不必逐个补字段。
    admin_salt: []const u8 = "",
    admin_user: []const u8,
    /// A03：口令版本时间戳。签发令牌时写进 claim，校验时比对；改密就把它推到
    /// 当前时间，于是所有旧令牌立刻失效。对应 Go 的 `model.User.PwdTS`
    /// （server/common/auth.go:19 与 server/middlewares/auth.go:62-66）。
    admin_pwd_ts: i64,
    jwt_secret: []const u8,
    site_url: []const u8,
    cdn: []const u8,
    token_expires_in_hours: i64,
    /// Frontend serving: the SPA shell, the four asset prefixes and the PWA
    /// manifest. Built once during `init`, so a CDN misconfiguration fails at
    /// startup rather than on the first page load.
    frontend: frontend_mod.Frontend,

    pub fn init(alloc: std.mem.Allocator) !App {
        const cfg = config.get();

        var app = App{
            .alloc = alloc,
            .mounts = &.{},
            .admin_hash = try readSecret(alloc, cfg, "admin_password_hash"),
            .admin_user = try readSecretDefault(alloc, cfg, "admin_user", "admin"),
            .admin_salt = try readSecret(alloc, cfg, "admin_salt"),
            .admin_pwd_ts = readSecretInt(cfg, "admin_pwd_ts", 0),
            .jwt_secret = try alloc.dupe(u8, cfg.jwt_secret),
            .site_url = try alloc.dupe(u8, cfg.site_url),
            .cdn = try alloc.dupe(u8, cfg.cdn),
            .token_expires_in_hours = cfg.token_expires_in,
            // Assigned immediately below; `Frontend` owns a pointer, so the
            // struct cannot be built inline in the literal.
            .frontend = undefined,
        };
        app.frontend = try frontend_mod.init(alloc, .{
            .site_url = cfg.site_url,
            .cdn = cfg.cdn,
            .dist_dir = cfg.dist_dir,
            .web_version = cfg.web_version,
            .settings = .{
                .site_title = cfg.site_title,
                .main_color = cfg.main_color,
                .logo = cfg.logo,
                .favicon = cfg.favicon,
                .customize_head = cfg.customize_head,
                .customize_body = cfg.customize_body,
            },
        });
        return app;
    }

    /// 从磁盘重读 config.json，只把管理员凭据（user / hash / pwd_ts）换成新值。
    ///
    /// 供 `/api/admin/user/del_cache` 用：CLI（`openlist admin set` / `admin random`）
    /// 是**独立进程**，它只写配置文件；在线服务的凭据是启动时读进内存的副本，
    /// 不重载的话改完密码旧令牌照样能用。对齐 Go 的 `DelAdminCacheOnline`
    /// （`cmd/user.go:15`：改完库再 HTTP 通知在线服务清缓存）。
    pub fn reloadAdminCredentials(self: *App) !void {
        const cfg = config.get();
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();
        const text = try std.Io.Dir.cwd().readFileAlloc(rt.io(), cfg.path, a, .limited(8 * 1024 * 1024));
        const doc = try json.parse(a, text);
        const zig = doc.getPath("zig") orelse return error.MalformedConfig;

        const user = if (zig.getPath("admin_user")) |v| (v.asStr() orelse "admin") else "admin";
        const salt = if (zig.getPath("admin_salt")) |v| (v.asStr() orelse "") else "";
        const hash = if (zig.getPath("admin_password_hash")) |v| (v.asStr() orelse "") else "";
        const pwd_ts = if (zig.getPath("admin_pwd_ts")) |v| (v.asInt() orelse 0) else 0;

        self.admin_user = try self.alloc.dupe(u8, user);
        self.admin_salt = try self.alloc.dupe(u8, salt);
        self.admin_hash = try self.alloc.dupe(u8, hash);
        self.admin_pwd_ts = pwd_ts;
    }

    /// Releases the frontend arena. The remaining fields are process-lifetime
    /// and are deliberately not tracked; this exists so the largest single
    /// allocation is still accounted for when the server shuts down.
    pub fn deinit(self: *App) void {
        self.frontend.deinit();
    }

    /// Strm 驱动的 fs 回调桥（Go 侧直接调 `internal/fs` + `op.Link` +
    /// `sign.Sign` + `common.GetApiUrl`）。在 `main.zig` 的 App 构造后调用；
    /// 测试里也可以对局部 App 调用（bridge 只借 ctx 指针，不持有）。
    pub fn installFsBridge(self: *App) void {
        driver.fs_bridge = .{
            .ctx = self,
            .get = bridgeGet,
            .list = bridgeList,
            .link = bridgeLink,
            .sign = bridgeSign,
            .site_url = bridgeSiteUrl,
        };
    }

    /// T6：取当前 mounts 快照。只锁「拷 slice 头」这一下，绝不拿着锁做别的。
    pub fn mountsSnapshot(self: *App) []Mount {
        const io = rt.io();
        self.mounts_lock.lockUncancelable(io);
        defer self.mounts_lock.unlock(io);
        return self.mounts;
    }

    /// T6：后台初始化线程专用的发布入口。整 slice 替换，替换前所有驱动的
    /// init 都已完成；替换之后 `mounts` 内容永不再变（只读快照才安全）。
    pub fn publishMounts(self: *App, mounts: []Mount) void {
        const io = rt.io();
        self.mounts_lock.lockUncancelable(io);
        defer self.mounts_lock.unlock(io);
        self.mounts = mounts;
    }

    /// Longest-prefix mount lookup. Mounts are matched at segment boundaries:
    /// `/nas` matches `/nas` and `/nas/a` but NOT `/nas2`.
    ///
    /// T6：返回的指针指向**已发布**的 slice —— 发布后内容永不再变，所以
    /// 调用方可以安全地拿着它去调驱动（不在持锁状态下）。后台初始化完成前
    /// 这里返回 null（请求拿到 404，与 Go 的「存储还没加载完」行为一致）。
    pub fn resolve(self: *App, path: []const u8) ?struct { mount: *Mount, rel: []const u8 } {
        var best: ?*Mount = null;
        var best_len: usize = 0;
        for (self.mountsSnapshot()) |*m| {
            const mp = m.mount_path;
            if (!std.mem.startsWith(u8, path, mp)) continue;
            const boundary = path.len == mp.len or mp.len == 1 or path[mp.len] == '/';
            if (!boundary) continue;
            // `>=` so that a later mount wins ties; config order is the
            // tie-breaker, which is what OpenList does too.
            if (mp.len >= best_len) {
                best = m;
                best_len = mp.len;
            }
        }
        const m = best orelse return null;
        // The root mount passes the whole path through unchanged.
        if (std.mem.eql(u8, m.mount_path, "/")) return .{ .mount = m, .rel = path };
        var rel = path[m.mount_path.len..];
        if (rel.len == 0) rel = "/";
        return .{ .mount = m, .rel = rel };
    }
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Strm 的 fs 桥实现（Go `internal/fs` 的最小等价面）。
fn bridgeCtx(ctx: *anyopaque) *App {
    return @ptrCast(@alignCast(ctx));
}

fn bridgeGet(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) !driver.File {
    const app = bridgeCtx(ctx);
    const r = app.resolve(path) orelse return error.NotFound;
    var c = driver.Ctx{ .alloc = alloc, .tag = r.mount.mount_path };
    return r.mount.driver.details(&c, r.rel);
}

fn bridgeList(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) ![]model.Obj {
    const app = bridgeCtx(ctx);
    const r = app.resolve(path) orelse return error.NotFound;
    var c = driver.Ctx{ .alloc = alloc, .tag = r.mount.mount_path };
    return r.mount.driver.list(&c, r.rel);
}

fn bridgeLink(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8, args: driver.LinkArgs) !driver.Link {
    const app = bridgeCtx(ctx);
    const r = app.resolve(path) orelse return error.NotFound;
    var c = driver.Ctx{ .alloc = alloc, .tag = r.mount.mount_path };
    return r.mount.driver.link(&c, r.rel, args);
}

fn bridgeSign(ctx: *anyopaque, alloc: std.mem.Allocator, path: []const u8) ![]const u8 {
    const app = bridgeCtx(ctx);
    // Go `sign.Sign(path)` = SignWithExpire(path, 0)（永不过期）。
    return signValue(alloc, app.jwt_secret, path, 0);
}

fn bridgeSiteUrl(ctx: *anyopaque) []const u8 {
    return bridgeCtx(ctx).site_url;
}

/// 取虚拟路径的父目录（Go `stdpath.Dir`）。
fn dirnameRel(path: []const u8) []const u8 {
    const idx = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "/";
    if (idx == 0) return "/";
    return path[0..idx];
}

/// Go `internal/op/hook.go` 的写后钩子开关：settings 表的
/// `handle_hook_after_writing`（默认 false）。本工程没有 settings 表，
/// 落到 `zig.handle_hook_after_writing`。
fn hookAfterWritingEnabled() bool {
    const cfg = config.getOpt() orelse return false;
    const v = cfg.raw("zig.handle_hook_after_writing") orelse return false;
    const s = v.asStr() orelse return false;
    return std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1");
}

/// Go `op.objsUpdateHook`：写操作成功后重列目标目录并广播。
/// 失败只记日志 —— 钩子永远不能让写操作本身报错（Go 在 goroutine 里做）。
fn notifyObjsUpdateAfterWrite(app: *App, a: std.mem.Allocator, mount: *Mount, parent_rel: []const u8) void {
    _ = app;
    if (!hookAfterWritingEnabled()) return;
    var c = driver.Ctx{ .alloc = a, .tag = mount.mount_path };
    const objs = mount.driver.list(&c, parent_rel) catch return;
    const parent = urlmod.joinPath(a, if (std.mem.eql(u8, mount.mount_path, "/")) "" else mount.mount_path, parent_rel) catch return;
    driver.notifyObjsUpdate(a, parent, objs);
}

pub fn handle(app: *App, req: *http.Request, res: *http.Response) !void {
    // CORS preflight, so the frontend can be served from another origin.
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        try setCors(res);
        const p = req.path;
        // WebDAV capability advertisement needs the DAV header and must not be
        // collapsed into the generic 204 preflight answer.
        if (std.mem.eql(u8, p, "/dav") or std.mem.startsWith(u8, p, "/dav/")) {
            return webdav.options(res);
        }
        res.setStatus(204);
        return;
    }
    try setCors(res);

    const p = req.path;

    if (std.mem.eql(u8, p, "/ping")) return handlePing(res);
    if (std.mem.eql(u8, p, "/api/public/settings")) return handlePublicSettings(app, res);
    // Go 路由把这个接口放在 public 组；即使 Zig 当前没有离线下载任务管理器，
    // 也必须返回成功的空工具列表，不能把前端能力探测打成 404。
    if (std.mem.startsWith(u8, p, "/api/public/offline_download_tools")) return res.jsonOk("[]");
    if (std.mem.eql(u8, p, "/api/public/archive_extensions")) return res.jsonOk("[\"zip\",\"tar\"]");
    // Go 用 `/public/init_status` + `/public/init/setup` 做首次安装向导
    // （server/router.go:105-106），**没有** `/auth/register`。前端 App.tsx
    // 靠 `init_status` 决定是否跳 `/@init`，缺了它永远不会引导注册。
    if (std.mem.eql(u8, p, "/api/public/init_status")) return handleInitStatus(app, req, res);
    if (std.mem.eql(u8, p, "/api/public/init/setup")) return handleInitSetup(app, req, res);
    if (std.mem.eql(u8, p, "/api/auth/login")) return handleLogin(app, req, res);
    if (std.mem.eql(u8, p, "/api/auth/login/hash")) return handleLoginHash(app, req, res);
    // ⚠️ Go **没有** `/api/auth/register` —— `server/router.go` 的 public 组只有
    // settings / archive_extensions / init_status / init/setup。这里曾自造过一个，
    // 现已删除：首次建管理员走 `/api/public/init/setup`，忘记密码走 CLI
    // `openlist admin set NEW_PASSWORD` / `admin random`（见 docs/STATUS.md §11）。

    // ---- frontend -------------------------------------------------------
    //
    // Everything here is unauthenticated, and deliberately so: the shell
    // *contains* the login page, so requiring a token to fetch it would make
    // the site unreachable. That is why this block sits before the auth gate in
    // `handleAuthed`, mirroring how OpenList's `noRoute` handler sits outside
    // its authenticated route group.
    if (frontend_mod.isAssetPath(p)) return handleAsset(app, req, res);
    if (std.mem.eql(u8, p, "/manifest.json")) return handleManifest(app, res);
    // Upstream mounts a WebDAV server at /dav/. This build implements it — see
    // webdav.zig — so route there instead of letting the catch-all answer a
    // PROPFIND with the SPA shell (a 200 carrying HTML is far harder to
    // diagnose than a proper multistatus).
    if (std.mem.eql(u8, p, "/dav") or std.mem.startsWith(u8, p, "/dav/")) {
        return webdav.handle(app, req, res);
    }

    // ---- authenticated API ----------------------------------------------
    // Only the known authenticated prefixes reach `handleAuthed`; any other
    // /api/* path falls through to the 404 catch-all below (matching upstream,
    // which answers an unregistered API route with JSON 404, not 401).
    // CLI（`openlist admin set/random`）改完配置文件后调它做热重载。它用
    // `zig.token`（`openlist admin token` 可查）认证、**不是** JWT，所以必须
    // 拦在 `handleAuthed` 前面 —— 对齐 Go：`cmd/user.go:DelUserCacheOnline`
    // 也是拿 settings 表的 token 去 POST `/api/admin/user/del_cache`。
    if (std.mem.eql(u8, p, "/api/admin/user/del_cache")) return handleDelUserCache(app, req, res);

    if (std.mem.startsWith(u8, p, "/api/fs/")) return handleAuthed(app, req, res);
    if (std.mem.eql(u8, p, "/api/me")) return handleAuthed(app, req, res);
    if (std.mem.startsWith(u8, p, "/api/admin/")) return handleAuthed(app, req, res);
    if (std.mem.startsWith(u8, p, "/api/task/")) return handleAuthed(app, req, res);
    // ⚠️ 下载路由**不能**走 `handleAuthed`：那里面第一件事就是 `checkAuth`，
    // 而 `?sign=` 下载压根不带 `Authorization` 头 —— 会在进到
    // `handleDownload` 里的签名校验之前就被 401 拦下（真机实测：sign 生成了、
    // 也正确，但 /d/ 恒 401，日志里连一条 "sign rejected" 都没有）。
    //
    // 对齐 Go：`/d/`、`/p/` 挂在 Down 中间件（`server/middlewares/down.go`）
    // 上，与 auth 中间件是两条独立的链；sign 通过即放行，失败才回落 token。
    if (std.mem.startsWith(u8, p, "/d/")) return handleDownload(app, req, res, false);
    if (std.mem.startsWith(u8, p, "/p/")) return handleDownload(app, req, res, true);

    // Catch-all, mirroring OpenList: 405 for anything that is not GET or POST,
    // otherwise 200 + text/html so a deep link such as /@manage/storage still
    // boots the frontend's router. One deviation: an unregistered path under
    // /api/ gets a JSON 404 instead of the shell. The frontend only ever calls
    // registered endpoints, so nothing depends on the upstream behaviour, and
    // returning HTML to a mistyped API call is a debugging trap.
    if (std.mem.startsWith(u8, p, "/api/")) return res.jsonError(404, "not found");
    if (!std.mem.eql(u8, req.method, "GET") and !std.mem.eql(u8, req.method, "POST")) {
        res.setStatus(405);
        return;
    }
    try res.set("Content-Type", "text/html; charset=utf-8");
    try res.write(app.frontend.htmlFor(p));
}

/// The authenticated API surface. Reached only through `handle`, which has
/// already dealt with the frontend and the public endpoints.
fn handleAuthed(app: *App, req: *http.Request, res: *http.Response) !void {
    const p = req.path;

    // The download routes also accept a per-file sign rather than a token; see
    // `checkAuth` and docs/STATUS.md.
    const authed = try checkAuth(app, req);
    if (!authed) return res.jsonError(401, "not logged in");

    if (std.mem.eql(u8, p, "/api/fs/list")) return handleFsList(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/get")) return handleFsGet(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/dirs")) return handleFsDirs(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/mkdir")) return handleFsMkdir(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/rename")) return handleFsRename(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/move")) return handleFsMove(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/copy")) return handleFsCopy(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/remove")) return handleFsRemove(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/put")) return handleFsPut(app, req, res);
    if (std.mem.eql(u8, p, "/api/fs/archive/list")) return handleFsArchiveList(app, req, res);

    // Admin surface (single-admin build: every authenticated user is the admin).
    if (std.mem.eql(u8, p, "/api/me")) return handleMe(app, req, res);
    if (std.mem.eql(u8, p, "/api/admin/storage") or std.mem.eql(u8, p, "/api/admin/storage/list")) return handleAdminStorage(app, req, res);
    if (std.mem.eql(u8, p, "/api/admin/driver/names")) return handleDriverNames(req, res);
    if (std.mem.eql(u8, p, "/api/admin/driver/list")) return handleDriverList(req, res);
    if (std.mem.eql(u8, p, "/api/admin/setting")) {
        if (std.mem.eql(u8, req.method, "GET")) return handleAdminSettingGet(app, req, res);
        if (std.mem.eql(u8, req.method, "PUT") or std.mem.eql(u8, req.method, "POST")) {
            return handleAdminSettingPut(app, req, res);
        }
        return res.jsonError(405, "method not allowed");
    }
    if (std.mem.startsWith(u8, p, "/api/admin/setting/")) return handleSettingRoute(app, req, res, p["/api/admin/setting/".len..]);
    if (std.mem.startsWith(u8, p, "/api/task/")) return handleTaskRoute(req, res, p["/api/task/".len..]);

    if (std.mem.startsWith(u8, p, "/d/")) return handleDownload(app, req, res, false);
    if (std.mem.startsWith(u8, p, "/p/")) return handleDownload(app, req, res, true);

    return res.jsonError(404, "not found");
}

/// Serve one of the four frontend asset prefixes, either from `dist_dir` or by
/// redirecting to the CDN. See `frontend.zig` for the branch selection.
fn handleAsset(app: *App, req: *http.Request, res: *http.Response) !void {
    if (!std.mem.eql(u8, req.method, "GET") and !std.mem.eql(u8, req.method, "HEAD")) {
        res.setStatus(405);
        return;
    }
    // M03：传请求级 arena，别让静态资源请求往进程级 arena 里堆东西。
    switch (app.frontend.asset(req.arena, req.path, req.target)) {
        .redirect => |to| {
            res.setStatus(302);
            try res.set("Location", to);
        },
        .local => |f| {
            const file = std.Io.Dir.cwd().openFile(rt.io(), f.path, .{}) catch |e| {
                log.warn("frontend: cannot open {s}: {s}", .{ f.path, @errorName(e) });
                return res.jsonError(404, "not found");
            };
            try res.set("Content-Type", mimeFor(f.path));
            // Six months, as upstream sets for these four prefixes: the
            // frontend build content-hashes the filenames.
            try res.set("Cache-Control", "public, max-age=15552000");
            res.sendFile(file, f.size);
        },
        // No `dist_dir` and no `cdn`: nothing backs these prefixes. Returning
        // the shell here would turn a missing asset into an HTML parse error
        // buried in the browser console, so say what is wrong instead.
        .missing => {
            res.setStatus(404);
            try res.set("Content-Type", "text/plain; charset=utf-8");
            try res.write("no frontend build available: set dist_dir or cdn in config.json\n");
        },
    }
}

fn handleManifest(app: *App, res: *http.Response) !void {
    try res.set("Content-Type", "application/json");
    try res.set("Cache-Control", "public, max-age=3600");
    try res.write(app.frontend.manifest_json);
}

fn setCors(res: *http.Response) !void {
    try res.set("Access-Control-Allow-Origin", "*");
    try res.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,PROPFIND");
    try res.set("Access-Control-Allow-Headers", "Authorization,Content-Type,File-Path,File-Modified");
}

fn handlePing(res: *http.Response) !void {
    try res.set("Content-Type", "text/plain");
    try res.write("pong");
}

// ---------------------------------------------------------------------------
// Public settings / auth
// ---------------------------------------------------------------------------

/// Go `db.GetPublicSettingItems()` 返回的是 `flag IN (PUBLIC, READONLY)` 的项
/// （`internal/db/settingitem.go:34`），默认值全部取自 `InitialSettings()`
/// （`internal/bootstrap/data/setting.go`）。本工程没有 settings 数据库，所以这里
/// 内联同一张表：**键名与默认值照抄 Go**，其中 4 项改从实时 settings 读
/// （见 `publicSettingValue`），可被 `/api/admin/setting` 改写。
///
/// ⚠️ 值一律是**字符串**。Go 返回 `map[string]string`，前端用
/// `t === 'true' || t === '1'` 判布尔、`Number(t)` 判数字 —— 给原生 bool/int
/// 会让判断恒为 false（`true === 'true'` 不成立），页面静默走错分支。
const PublicSetting = struct { key: []const u8, value: []const u8 };

/// 与 `main.version` 保持一致（api.zig 不能 import main.zig —— 会成环）。
const server_version = "0.1.0-zig";

const public_setting_defaults = [_]PublicSetting{
    // ---- SITE ----
    .{ .key = "version", .value = "" }, // 由 publicSettingValue 填
    .{ .key = "site_title", .value = "OpenList" },
    .{ .key = "announcement", .value = "" },
    .{ .key = "pagination_type", .value = "all" },
    .{ .key = "default_page_size", .value = "30" },
    .{ .key = "allow_indexed", .value = "false" },
    .{ .key = "allow_mounted", .value = "true" },
    .{ .key = "robots_txt", .value = "User-agent: *\nAllow: /" },
    // ---- STYLE ----
    .{ .key = "logo", .value = "https://res.oplist.org/logo/logo.svg" },
    .{ .key = "favicon", .value = "https://res.oplist.org/logo/logo.svg" },
    .{ .key = "main_color", .value = "#1890ff" },
    .{ .key = "home_icon", .value = "🏠" },
    .{ .key = "share_icon", .value = "🎁" },
    .{ .key = "home_container", .value = "max_980px" },
    .{ .key = "settings_layout", .value = "list" },
    .{ .key = "show_disk_usage_in_plain_text", .value = "false" },
    // ---- PREVIEW ----
    .{ .key = "external_previews", .value = "{}" },
    .{ .key = "iframe_previews", .value =
        \\{"doc,docx,xls,xlsx,ppt,pptx":{"Microsoft":"https://view.officeapps.live.com/op/view.aspx?src=$e_url","Google":"https://docs.google.com/gview?url=$e_url&embedded=true"},"pdf":{"PDF.js":"https://res.oplist.org/pdf.js/web/viewer.html?file=$e_url"},"epub":{"EPUB.js":"https://res.oplist.org/epub.js/viewer.html?url=$e_url"}}
    },
    .{ .key = "audio_cover", .value = "https://res.oplist.org/logo/logo.svg" },
    .{ .key = "audio_autoplay", .value = "true" },
    .{ .key = "video_autoplay", .value = "true" },
    .{ .key = "preview_download_by_default", .value = "false" },
    .{ .key = "preview_archives_by_default", .value = "true" },
    .{ .key = "share_preview_download_by_default", .value = "true" },
    .{ .key = "share_preview_archives_by_default", .value = "false" },
    .{ .key = "readme_autorender", .value = "true" },
    .{ .key = "filter_readme_scripts", .value = "true" },
    .{ .key = "non_efs_zip_encoding", .value = "IBM437" },
    // ---- GLOBAL ----
    .{ .key = "hide_files", .value = "/\\/README.md/i" },
    .{ .key = "package_download", .value = "true" },
    .{ .key = "ocr_api", .value = "https://openlistteam-ocr-api-server.hf.space/ocr/file/json" },
    .{ .key = "filename_char_mapping", .value = "{\"/\": \"|\"}" },
    .{ .key = "forward_direct_link_params", .value = "false" },
    .{ .key = "ignore_direct_link_params", .value = "sign,openlist_ts,raw" },
    .{ .key = "webauthn_login_enabled", .value = "false" },
    .{ .key = "share_preview", .value = "false" },
    .{ .key = "share_archive_preview", .value = "false" },
    .{ .key = "share_summary_content", .value =
        \\@{{creator}} shared {{#each files}}{{#if @first}}"{{filename this}}"{{/if}}{{#if @last}}{{#unless (eq @index 0)}} and {{@index}} more files{{/unless}}{{/if}}{{/each}} from {{site_title}}: {{base_url}}/@s/{{id}}{{#if pwd}} , the share code is {{pwd}}{{/if}}{{#if expires}}, please access before {{dateLocaleString expires}}.{{/if}}
    },
    // ---- INDEX ----
    .{ .key = "search_index", .value = "none" },
    .{ .key = "auto_update_index", .value = "false" },
    // ---- SSO ----
    .{ .key = "sso_login_enabled", .value = "false" },
    .{ .key = "sso_login_platform", .value = "" },
    .{ .key = "sso_compatibility_mode", .value = "false" },
    // ---- LDAP ----
    .{ .key = "ldap_login_enabled", .value = "false" },
    .{ .key = "ldap_login_tips", .value = "login with ldap" },
    // ---- TRAFFIC ----
    .{ .key = "multipart_enabled", .value = "true" },
    .{ .key = "multipart_chunk_size", .value = "10" },
};

/// 4 个键有实时来源（`/api/admin/setting` 改得动），其余走表里的默认值。
/// 读 `app.frontend.settings` 而不是 `config.get()`：前者由 `App` 持有、
/// 测试里无需初始化 config 单例，且 PUT 处理器会同时更新两者。
fn publicSettingValue(app: *const App, item: PublicSetting) []const u8 {
    const s = app.frontend.settings;
    if (std.mem.eql(u8, item.key, "version")) return server_version;
    if (std.mem.eql(u8, item.key, "site_title")) return s.site_title;
    if (std.mem.eql(u8, item.key, "logo")) return s.logo;
    if (std.mem.eql(u8, item.key, "favicon")) return s.favicon;
    if (std.mem.eql(u8, item.key, "main_color")) return s.main_color;
    return item.value;
}

/// `GET /api/public/settings` —— 对齐 Go `handles.PublicSettings`
/// （`server/handles/setting.go:145` → `op.GetPublicSettingsMap()`）。
/// 之前只返回 10 个自造字段（`initial_done`/`api`/`cdn`/`token_expires_in`…），
/// 前端真正读的 30 多个键一个都没有 —— 表现就是首页 `logo` 拿到空串、
/// `<img src="">`。现在按 Go 的字段集补齐。
fn handlePublicSettings(app: *App, res: *http.Response) !void {
    const a = res.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{");
    for (public_setting_defaults, 0..) |item, i| {
        if (i != 0) try b.appendByte(',');
        try json.writeString(&b, item.key);
        try b.appendByte(':');
        try json.writeString(&b, publicSettingValue(app, item));
    }
    // `append` 写原始字节，不做 `print` 那样的 `{{`/`}}` 转义 —— 这里必须是
    // "}}"（关闭 data 与信封）。曾误写成 "}}}"，多出的 `}` 让整个 body 非法，
    // axios 静默把 JSON.parse 失败降级成字符串，前端只报「获取设置失败： Undefined」。
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// `GET /api/public/init_status` —— 对齐 Go `server/handles/setup.go:15`
/// （`server/router.go:105` 注册为 `Any`）。
///
/// 前端 `App.tsx` 靠它决定是否跳 `/@init` 安装向导：
///   `if (initialized() === false && !pathname().startsWith("/@init")) to("/@init")`
/// 而这个请求的**失败回调在源码里被注释掉了**（静默吞错），`initialized` 于是
/// 保持 `createSignal(true)` 的默认值 —— 端点缺失（404）时前端**永远不会**引导
/// 注册，表现就是"没有注册入口，只能用已有账号登录"。
fn handleInitStatus(app: *App, req: *http.Request, res: *http.Response) !void {
    if (!std.mem.eql(u8, req.method, "GET") and !std.mem.eql(u8, req.method, "POST")) {
        return res.jsonError(405, "method not allowed");
    }
    // Go 的判据是"管理员是否已存在"（`op.GetAdmin()` 取不到记录 ⇒ 未初始化）。
    try res.jsonOk(if (app.admin_hash.len > 0) "{\"initialized\":true}" else "{\"initialized\":false}");
}

/// `POST /api/public/init/setup` —— 对齐 Go `server/handles/setup.go:37`。
/// 只在未初始化时可调；成功后**不签发 token**（Go 只回 `data:null`，前端注册完
/// 会自己再走一次登录）。
fn handleInitSetup(app: *App, req: *http.Request, res: *http.Response) !void {
    if (!std.mem.eql(u8, req.method, "POST")) return res.jsonError(405, "method not allowed");
    // 已初始化 ⇒ 拒绝（Go：`system has already been initialized`）。
    if (app.admin_hash.len > 0) return res.jsonError(400, "system has already been initialized");

    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const username = v.strAt("username") orelse "";
    const password = v.strAt("password") orelse "";
    if (username.len == 0 or password.len == 0) {
        return res.jsonError(400, "username and password are required");
    }
    // Go 这里是 `< 4`（setup.go:56），比 `/auth/register` 的 6 更宽松 —— 逐字对齐。
    if (password.len < 4) return res.jsonError(400, "password must be at least 4 characters");

    const cfg = config.get();
    const ca = cfg.allocator();
    // 对齐 Go `User.SetPassword`（internal/model/user.go:96）：现生成 16 位 salt，
    // 存的是 `TwoHashPwd(pwd, salt)` —— 不是裸 sha256。前端登录页发的是
    // `StaticHash(pwd)`，服务端再套一层 `HashPwd(·, salt)` 比对，所以缺了 salt
    // 这一层就永远对不上。
    const salt = try randomSalt(ca);
    const hash = try twoHashPwd(ca, password, salt);
    try cfg.putZig("admin_user", .{ .string = try ca.dupe(u8, username) });
    try cfg.putZig("admin_salt", .{ .string = salt });
    try cfg.putZig("admin_password_hash", .{ .string = hash });
    // 口令版本：让随后签发的令牌带上它（改密/重置时推进即可失效旧令牌）。
    app.admin_pwd_ts = rt.nowSeconds();
    try cfg.putZig("admin_pwd_ts", .{ .int = app.admin_pwd_ts });
    // 可选的站点名（Go：`if req.SiteTitle != ""` 才写）。
    if (v.strAt("site_title")) |title| {
        if (title.len > 0) {
            const owned = try ca.dupe(u8, title);
            cfg.site_title = owned;
            try cfg.putZig("site_title", .{ .string = owned });
        }
    }
    cfg.save() catch |e| {
        log.warn("api: could not persist init setup: {s}", .{@errorName(e)});
        return res.jsonError(500, "could not save setup");
    };
    app.admin_user = try app.alloc.dupe(u8, username);
    app.admin_salt = try app.alloc.dupe(u8, salt);
    app.admin_hash = try app.alloc.dupe(u8, hash);
    app.frontend.settings.site_title = try app.alloc.dupe(u8, cfg.site_title);
    log.info("api: initialised by {s}", .{username});
    try res.jsonOk("null");
}

/// `POST /api/admin/user/del_cache` —— 对齐 Go `server/handles/user.go`
/// （路由见 `server/router.go:136`），由 CLI 在改完管理员凭据后调用，让在线
/// 服务丢掉内存里的凭据副本、无需重启。认证用 `zig.token`
/// （`openlist admin token` 可查看），语义对齐 Go 用 settings 表里的 token。
fn handleDelUserCache(app: *App, req: *http.Request, res: *http.Response) !void {
    if (!std.mem.eql(u8, req.method, "POST")) return res.jsonError(405, "method not allowed");
    const cfg = config.get();
    const expected = if (cfg.raw("zig.token")) |v| (v.asStr() orelse "") else "";
    const given = req.header("Authorization") orelse "";
    if (expected.len == 0 or !std.mem.eql(u8, expected, given)) {
        return res.jsonError(401, "invalid token");
    }
    app.reloadAdminCredentials() catch |e| {
        log.warn("api: del_cache could not reload config: {s}", .{@errorName(e)});
        return res.jsonError(500, "could not reload config");
    };
    log.info("api: admin credentials reloaded from config (del_cache)", .{});
    try res.jsonOk("null");
}

/// `POST /api/auth/login` —— 收**明文**口令（Go 里标了 Deprecated 但仍可用）。
fn handleLogin(app: *App, req: *http.Request, res: *http.Response) !void {
    return loginCommon(app, req, res, false);
}

/// `POST /api/auth/login/hash` —— **前端登录页实际调用的就是这个**
/// （`server/router.go:75` → `handles.LoginHash`）。body 里的 `password`
/// 已经是 `StaticHash(明文)`，服务端只需再套一层 `HashPwd(·, salt)` 比对。
///
/// ⚠️ 这个端点曾经缺失，导致前端登录恒失败 —— curl 直接打 `/auth/login`
/// 是通的，所以「用 curl 验证过」并不等于「前端能登录」。
fn handleLoginHash(app: *App, req: *http.Request, res: *http.Response) !void {
    return loginCommon(app, req, res, true);
}

/// `already_static` = 收到的 password 是否已经过 `StaticHash`。
fn loginCommon(app: *App, req: *http.Request, res: *http.Response, already_static: bool) !void {
    if (app.admin_hash.len == 0) return res.jsonError(400, "no administrator yet; run setup first");
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const username = v.strAt("username") orelse "";
    const password = v.strAt("password") orelse "";
    if (!std.mem.eql(u8, username, app.admin_user)) {
        return res.jsonError(400, "wrong username or password");
    }
    // Go `User.ValidatePwd` / `ValidatePwdStaticHash`（internal/model/user.go:83-94）：
    //     PwdHash == HashPwd(<static hash>, Salt)
    // 明文接口先做一次 StaticHash；`/login/hash` 直接拿收到的 static hash 用。
    const static = if (already_static) password else try staticHash(a, password);
    const expect = try hashPwd(a, static, app.admin_salt);
    // Constant-time compare. A plain `std.mem.eql` would leak the position of
    // the first differing byte; a length check first would leak the length.
    if (!ctEqual(expect, app.admin_hash)) {
        return res.jsonError(400, "wrong username or password");
    }
    return issueToken(app, a, res, username);
}

/// A04：签发**标准三段式 HS256 JWT**，与 Go `common.GenerateToken`
/// （server/common/auth.go:25-40）逐字段对齐：
///
///   header  = {"alg":"HS256","typ":"JWT"}
///   payload = {"username":..,"pwd_ts":..,"exp":..,"iat":..,"nbf":..}
///   sig     = base64url(HMAC-SHA256("<header_b64>.<payload_b64>", secret))
///
/// 以前这里签的是私有的两段 `payload.signature`，浏览器/第三方按标准 JWT 解不开，
/// 也不能把私有两段格式称作 JWT。
fn issueToken(app: *App, a: std.mem.Allocator, res: *http.Response, username: []const u8) !void {
    const now = rt.nowSeconds();
    const exp = now + app.token_expires_in_hours * 3600;

    const h64 = try b64Url(a, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

    var payload = Buf.init(a);
    try payload.append("{\"username\":");
    try json.writeString(&payload, username);
    try payload.print(",\"pwd_ts\":{d},\"exp\":{d},\"iat\":{d},\"nbf\":{d}}}", .{
        app.admin_pwd_ts, exp, now, now,
    });
    const p64 = try b64Url(a, payload.slice());

    // 签名覆盖 "header.payload"（不含末尾的点），这是 JWT 的规定。
    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ h64, p64 });
    const sig = try hmacSha256(a, app.jwt_secret, signing_input);
    const s64 = try b64Url(a, &sig);
    const token = try std.fmt.allocPrint(a, "{s}.{s}", .{ signing_input, s64 });

    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"token\":");
    try json.writeString(&b, token);
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// Accepts either `Authorization: Bearer <jwt>` or a `?token=` query param
/// (the browser needs the latter for `<video src>`).
fn checkAuth(app: *App, req: *http.Request) !bool {
    var token: []const u8 = "";
    if (req.header("Authorization")) |h| {
        const prefix = "Bearer ";
        if (h.len > prefix.len and std.ascii.eqlIgnoreCase(h[0..prefix.len], prefix)) {
            token = h[prefix.len..];
        } else {
            token = h;
        }
    } else if (req.queryGet("token")) |t| {
        token = t;
    }
    if (token.len == 0) return false;

    // A04：标准三段式 `header.payload.signature`。以前按最后一个点切两段，
    // 结构对不上标准 JWT。
    var parts = std.mem.splitScalar(u8, token, '.');
    const h64 = parts.next() orelse return false;
    const p64 = parts.next() orelse return false;
    const s64 = parts.next() orelse return false;
    if (parts.next() != null) return false; // 多于三段：拒绝
    if (h64.len == 0 or p64.len == 0 or s64.len == 0) return false;

    // 签名覆盖 "header.payload"。
    const signing_input = try std.fmt.allocPrint(req.arena, "{s}.{s}", .{ h64, p64 });
    const expected = try hmacSha256(req.arena, app.jwt_secret, signing_input);
    const got_raw = b64UrlDecode(req.arena, s64) catch return false;

    // A02：长度先判，绝不把长度差窄化进 u8；再常量时间比较。
    if (got_raw.len != expected.len) return false;
    if (!ctEqual(got_raw, &expected)) return false;

    const payload = b64UrlDecode(req.arena, p64) catch return false;
    const v = json.parse(req.arena, payload) catch return false;

    // A03：令牌必须绑在「当前管理员 + 当前口令版本」上。
    // Go 在 server/middlewares/auth.go:55-68 做同样两件事：按 username 取用户，
    // 再比对 user.PwdTS。改密后旧令牌在这里被拒，而不是继续有效到过期。
    const uname = v.strAt("username") orelse return false;
    if (!std.mem.eql(u8, uname, app.admin_user)) return false;

    const pwd_ts = v.intAt("pwd_ts") orelse 0;
    if (pwd_ts != app.admin_pwd_ts) {
        log.warn("api: token rejected: password changed since it was issued", .{});
        return false;
    }

    const exp = v.intAt("exp") orelse return false;
    return rt.nowSeconds() < exp;
}

// ---------------------------------------------------------------------------
// /api/fs/*
// ---------------------------------------------------------------------------

fn handleFsDirs(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"content\":[");
    const mounts = app.mountsSnapshot();
    for (mounts, 0..) |m, i| {
        if (i != 0) try b.appendByte(',');
        try b.print("{{\"name\":", .{});
        try json.writeString(&b, m.mount_path);
        try b.append(",\"path\":");
        try json.writeString(&b, m.mount_path);
        try b.append(",\"driver\":");
        try json.writeString(&b, m.storage.driver);
        try b.append(",\"label\":");
        try json.writeString(&b, m.label);
        try b.print(",\"order\":{d}", .{m.storage.order});
        try b.appendByte('}');
    }
    try b.append("]}}");
    try res.jsonOkRaw(b.slice());
}

fn handleFsList(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const path = v.strAt("path") orelse "/";

    if (std.mem.eql(u8, path, "/")) {
        return listRoot(app, res);
    }
    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");

    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
    const objs = r.mount.driver.list(&ctx, r.rel) catch |e| {
        return mapDriverError(res, e);
    };

    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"content\":[");
    for (objs, 0..) |o, i| {
        if (i != 0) try b.appendByte(',');
        // 规范化列目录路径再 join，和 Go 的 `utils.FixAndCleanPath(dirParam)`
        // 一致 —— 否则 `//a`、`/a/./` 会签出与请求路径不同的签名。
        const dir_clean = urlmod.cleanPath(a, path) catch path;
        const child = try urlmod.joinPath(a, if (dir_clean.len == 1) "" else dir_clean, o.name);
        try writeObj(app, &b, o, child);
    }
    try b.append("],\"total\":");
    try b.print("{d}", .{objs.len});
    try appendFsListTail(&b);
    try res.jsonOkRaw(b.slice());
}

/// `FsListResp` 的尾部字段 —— Go `server/handles/fsread.go:49-58`。
/// **不能省**：前端 store 用 `setWrite(e.write)` 决定是否渲染上传/新建/删除按钮，
/// 字段缺失会让 `write` 变 `undefined`、目录被判成只读（按钮整片消失）。
///   * `readme` / `header` —— 来自 meta；本工程没有 meta，恒空串；
///   * `write` —— 单管理员构建，认证用户一律可写；
///   * `write_content_bypass` —— 无 meta 权限模型，恒 false；
///   * `provider` —— Go 侧也是硬编码 `"unknown"`（fsread.go:110 赋值后再没改过）；
///   * `direct_upload_tools` —— Go 标了 `omitempty`，驱动未实现 `DirectUploader`
///     就不发这个键，这里同样省略。
fn appendFsListTail(b: *Buf) !void {
    try b.append(",\"readme\":\"\",\"header\":\"\",\"write\":true,\"write_content_bypass\":false,\"provider\":\"unknown\"}}");
}

/// The virtual root shows one entry per mount, exactly like OpenList.
fn listRoot(app: *App, res: *http.Response) !void {
    const a = res.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"content\":[");
    const mounts = app.mountsSnapshot();
    for (mounts, 0..) |m, i| {
        if (i != 0) try b.appendByte(',');
        try b.append("{\"name\":");
        try json.writeString(&b, std.mem.trim(u8, m.mount_path, "/"));
        // Go 的 time.Time 零值 JSON 是 RFC3339 的 year-1，而不是空串；空串
        // 进入前端 `new Date(...).getTime()` 就会变成 NaN。
        try b.append(",\"size\":0,\"is_dir\":true,\"modified\":\"0001-01-01T00:00:00Z\",\"created\":\"0001-01-01T00:00:00Z\"");
        // 挂载点都是目录 → Go 的 FOLDER = 1（以前这里写的是自造的 2）。
        try b.append(",\"sign\":\"\",\"thumb\":\"\",\"type\":1,\"hash_info\":null}");
    }
    try b.append("],\"total\":");
    try b.print("{d}", .{mounts.len});
    try appendFsListTail(&b);
    try res.jsonOkRaw(b.slice());
}

fn handleFsGet(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const path = v.strAt("path") orelse "/";

    // 对齐 Go `internal/fs/get.go:25-30`：`/` 不属于任何挂载，但 Go 对它返回一个
    // **虚拟根对象**（`name:"root", is_dir:true, Mask:ReadOnly|Virtual`），而不是
    // "storage not found"。前端 Layout 进首页第一个请求就是 `fs/get /`，此前这里
    // 回了 404，首页直接显示 404（管理后台走的是 storage/list 所以看起来正常）。
    // provider 也对齐 Go：虚拟根取不到 storage ⇒ 空串（fsread.go:309-311 的
    // `!ok && err == nil` 分支不成立）。
    if (std.mem.eql(u8, path, "/")) {
        return res.jsonOk("{\"name\":\"root\",\"size\":0,\"is_dir\":true,\"modified\":\"0001-01-01T00:00:00Z\",\"created\":\"0001-01-01T00:00:00Z\",\"sign\":\"\",\"thumb\":\"\",\"type\":1,\"hash_info\":null,\"raw_url\":\"\",\"readme\":\"\",\"header\":\"\",\"provider\":\"\",\"related\":[]}");
    }

    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");
    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
    const f = r.mount.driver.details(&ctx, r.rel) catch |e| return mapDriverError(res, e);

    // 与 Go `server/common/sign.go` 一致：目录 sign 为空串；文件在
    // `sign_all` 开（或 meta 加密）时签完整路径。fs/get 的 `sign` 字段与
    // raw_url 上带的 `?sign=` 必须是同一个值 —— 前端音频/视频播放器直接用
    // raw_url，不带 sign 的 `/p` 在 sign_all 部署下会被 401（实测踩过）。
    const sign_val = try signForObj(app, a, f.is_dir, path);

    var raw_url: []const u8 = "";
    if (!f.is_dir) {
        // A05：把调用方的请求头交给驱动。115 按 User-Agent 下发下载链接，部分
        // 网盘要求 Referer —— 空 LinkArgs 拿到的 URL 前端直接用不了。
        const lk = r.mount.driver.link(&ctx, r.rel, .{ .headers = req.headers }) catch |e| {
            log.warn("api: link {s} failed: {s}", .{ path, @errorName(e) });
            return mapDriverError(res, e);
        };
        // 与 Go `server/handles/fsread.go:318-339` 一致：需要服务端代理的
        // （或本地文件）给出本站 `/p` 可鉴权 URL，不能把带 Cookie 才能用的
        // CDN 地址直接丢给浏览器；只有真正可直链的才回上游 URL。
        // 带 sign 的方式对齐 Go `common.GenerateDownProxyURL`
        // （server/common/proxy.go:31-33：`?sign=` + `sign.Sign(reqPath)`）；
        // 路径编码对齐 `utils.EncodePath(reqPath, true)`（`.path` 保留 `/`）。
        if (lk.proxy or lk.local_path != null) {
            const enc = try urlmod.encode(a, path, .path);
            raw_url = if (sign_val.len == 0)
                try std.fmt.allocPrint(a, "/p{s}", .{enc})
            else
                try std.fmt.allocPrint(a, "/p{s}?sign={s}", .{ enc, sign_val });
        } else {
            raw_url = lk.url;
        }
    }

    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{");
    try b.print("\"name\":", .{});
    try json.writeString(&b, f.name);
    try b.print(",\"size\":{d},\"is_dir\":{s}", .{ f.size, if (f.is_dir) "true" else "false" });
    try b.append(",\"modified\":");
    try json.writeString(&b, try fmtTime(a, f.modified));
    try b.append(",\"created\":");
    try json.writeString(&b, try fmtTime(a, if (f.created == 0) f.modified else f.created));
    try b.append(",\"sign\":");
    // 对齐 Go `server/common/sign.go`：非目录且 `sign_all` 开时给一个可拼到
    // `/p`、`/d` 后的下载签名（否则空串）。此前这里透传驱动给的 `f.sign`
    // （恒为空），前端拿到的是空 sign，`sign_all=true` 的部署下点不开文件。
    try json.writeString(&b, sign_val);
    try b.append(",\"type\":");
    // A06：按 Go 的 `GetObjType` 输出（FOLDER=1、VIDEO=2、AUDIO=3、TEXT=4、
    // IMAGE=5），不再是自造的 file=1/folder=2。
    try b.print("{d}", .{@backingInt(model.objTypeFor(f.name, f.is_dir))});
    try b.append(",\"raw_url\":");
    try json.writeString(&b, raw_url);
    // Go 的 `FsGetResp` = `ObjResp` + raw_url/readme/header/provider/related
    // （server/handles/fsread.go:249-255）。`provider` 取驱动名 —— 对齐
    // fsread.go:309-311（`model.GetProvider` 拿不到就回落 `storage.Config().Name`）。
    // header/related 前端当前不读，一并补齐，免得再漏。
    try b.append(",\"readme\":\"\",\"header\":\"\",\"provider\":");
    try json.writeString(&b, r.mount.storage.driver);
    try b.append(",\"related\":[]}}");
    try res.jsonOkRaw(b.slice());
}

fn handleFsMkdir(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const path = v.strAt("path") orelse return res.jsonError(400, "path is required");
    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");
    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
    r.mount.driver.makeDir(&ctx, r.rel) catch |e| return mapDriverError(res, e);
    try res.jsonOk("null");
}

/// `POST /api/fs/copy` —— 与 `move` 同形，但把条目**复制**到目标目录（保留原名）。
/// 驱动没有 copy 能力时返回 501（`NotSupported`）。
fn handleFsCopy(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const src_dir = v.strAt("src_dir") orelse return res.jsonError(400, "src_dir is required");
    const dst_dir = v.strAt("dst_dir") orelse return res.jsonError(400, "dst_dir is required");
    const names = v.getPath("names") orelse return res.jsonError(400, "names is required");
    const arr = names.asArray() orelse return res.jsonError(400, "names must be an array");

    for (arr) |*n| {
        const name = n.asStr() orelse continue;
        const src = try urlmod.joinPath(a, src_dir, name);
        const sr = app.resolve(src) orelse return res.jsonError(404, "storage not found");
        const dr = app.resolve(dst_dir) orelse return res.jsonError(404, "storage not found");
        // 跨挂载点复制需要「下载 + 上传」，本工程没有；明确拒绝好过静默做错。
        if (sr.mount != dr.mount) return res.jsonError(400, "copying between storages is not supported yet");
        var ctx = driver.Ctx{ .alloc = a, .tag = sr.mount.mount_path };
        sr.mount.driver.copy(&ctx, sr.rel, dr.rel) catch |e| return mapDriverError(res, e);
        notifyObjsUpdateAfterWrite(app, a, dr.mount, dst_dir);
    }
    try res.jsonOk("null");
}

fn handleFsRename(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const path = v.strAt("path") orelse return res.jsonError(400, "path is required");
    const name = v.strAt("name") orelse return res.jsonError(400, "name is required");
    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");
    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
    r.mount.driver.rename(&ctx, r.rel, name) catch |e| return mapDriverError(res, e);
    notifyObjsUpdateAfterWrite(app, a, r.mount, dirnameRel(path));
    try res.jsonOk("null");
}

fn handleFsMove(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const src_dir = v.strAt("src_dir") orelse return res.jsonError(400, "src_dir is required");
    const dst_dir = v.strAt("dst_dir") orelse return res.jsonError(400, "dst_dir is required");
    const names = v.getPath("names") orelse return res.jsonError(400, "names is required");
    const arr = names.asArray() orelse return res.jsonError(400, "names must be an array");

    for (arr) |*n| {
        const name = n.asStr() orelse continue;
        const src = try urlmod.joinPath(a, src_dir, name);
        const sr = app.resolve(src) orelse return res.jsonError(404, "storage not found");
        const dr = app.resolve(dst_dir) orelse return res.jsonError(404, "storage not found");
        // Cross-mount moves would need a copy+delete the skeleton does not
        // implement; refusing is better than silently doing the wrong thing.
        if (sr.mount != dr.mount) return res.jsonError(400, "moving between storages is not supported yet");
        var ctx = driver.Ctx{ .alloc = a, .tag = sr.mount.mount_path };
        sr.mount.driver.move(&ctx, sr.rel, dr.rel) catch |e| return mapDriverError(res, e);
        notifyObjsUpdateAfterWrite(app, a, dr.mount, dst_dir);
    }
    try res.jsonOk("null");
}

fn handleFsRemove(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const dir = v.strAt("dir") orelse return res.jsonError(400, "dir is required");
    const names = v.getPath("names") orelse return res.jsonError(400, "names is required");
    const arr = names.asArray() orelse return res.jsonError(400, "names must be an array");

    for (arr) |*n| {
        const name = n.asStr() orelse continue;
        const full = try urlmod.joinPath(a, dir, name);
        const r = app.resolve(full) orelse return res.jsonError(404, "storage not found");
        var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
        // Stat first: itvsh needs to know file vs directory, and guessing from
        // the name is exactly the kind of shortcut that deletes the wrong thing.
        const f = r.mount.driver.details(&ctx, r.rel) catch |e| return mapDriverError(res, e);
        r.mount.driver.remove(&ctx, r.rel, f.is_dir) catch |e| return mapDriverError(res, e);
        notifyObjsUpdateAfterWrite(app, a, r.mount, dir);
    }
    try res.jsonOk("null");
}

/// `PUT /api/fs/put` with the target in the `File-Path` header and the bytes
/// as the raw body — this is the shape OpenList's frontend uses.
fn handleFsPut(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const raw_path = req.header("File-Path") orelse return res.jsonError(400, "File-Path header is required");
    const path = urlmod.decode(a, raw_path) catch return res.jsonError(400, "bad File-Path");
    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");

    var body = req.body;
    // A single-put upload reports progress inline; the frontend's chunked upload
    // (many small PUTs) is what surfaces a live bar via this same callback.
    var prog = PutProgress{ .pct = 0 };
    var ctx = driver.Ctx{
        .alloc = a,
        .tag = r.mount.mount_path,
        .progress = putProgressCb,
        .progress_userdata = &prog,
    };
    r.mount.driver.put(&ctx, r.rel, body.source()) catch |e| return mapDriverError(res, e);
    try res.jsonOk("null");
}

// ---------------------------------------------------------------------------
// Archive browsing (read-only ZIP/TAR virtual directories)
// ---------------------------------------------------------------------------

const ArchiveFileSource = struct {
    file: std.Io.File,
    size: i64,

    fn getSize(p: *anyopaque) i64 {
        const self: *ArchiveFileSource = @ptrCast(@alignCast(p));
        return self.size;
    }
    fn readAt(p: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
        const self: *ArchiveFileSource = @ptrCast(@alignCast(p));
        return std.Io.File.readPositionalAll(self.file, rt.io(), buf, offset);
    }
    const vtable = model.Source.VTable{ .size = getSize, .readAt = readAt };

    fn source(self: *ArchiveFileSource) model.Source {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

/// `POST /api/fs/archive/list` — browse one level inside a local ZIP/TAR. Like
/// upstream this is a virtual read-only filesystem; no archive bytes are copied
/// into RAM. ZIP reads just its end record and central directory; TAR scans
/// 512-byte headers by offset. Remote archives are rejected until the upstream
/// client has a response-stream API (buffering a large archive is unsafe on the
/// router's 128 MiB RAM budget).
fn handleFsArchiveList(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const path = v.strAt("path") orelse return res.jsonError(400, "path is required");
    const inner = v.strAt("inner_path") orelse "";
    const page: usize = @intCast(@max(v.intAt("page") orelse 1, 1));
    const per_page: usize = @intCast(@max(v.intAt("per_page") orelse 1000000, 1));

    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");
    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };
    const f = r.mount.driver.details(&ctx, r.rel) catch |e| return mapDriverError(res, e);
    if (f.is_dir) return res.jsonError(400, "archive path is a directory");
    const format = archive.detect(f.name) orelse return res.jsonError(415, "only ZIP and TAR archives are supported");
    const lk = r.mount.driver.link(&ctx, r.rel, .{ .redirect = false }) catch |e| return mapDriverError(res, e);
    const local_path = lk.local_path orelse return res.jsonError(501, "remote archive browsing is not available yet");
    const file = std.Io.Dir.cwd().openFile(rt.io(), local_path, .{}) catch |e| {
        log.warn("api: open archive {s} failed: {s}", .{ local_path, @errorName(e) });
        return res.jsonError(404, "archive file not found");
    };
    defer file.close(rt.io());
    var src_ctx = ArchiveFileSource{ .file = file, .size = @intCast(lk.local_size) };
    const entries = archive.list(a, src_ctx.source(), format, inner) catch |e| {
        log.warn("api: list archive {s} failed: {s}", .{ path, @errorName(e) });
        return res.jsonError(400, "invalid or unsupported archive");
    };

    const start = @min((page - 1) *| per_page, entries.len);
    const end = @min(start +| per_page, entries.len);
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"content\":[");
    for (entries[start..end], 0..) |entry, i| {
        if (i != 0) try b.appendByte(',');
        const o = model.Obj{
            .name = entry.name,
            .size = entry.size,
            .is_dir = entry.is_dir,
            .modified = entry.modified,
        };
        // 归档内条目的虚拟路径 = `<压缩包路径>/<inner>/<name>`，与 Go 的
        // `archive.go` 一致（`archiver` 包把包内路径挂在真实路径下）。
        const inner_clean = if (inner.len == 0) "" else inner;
        const child = try urlmod.joinPath(a, path, try urlmod.joinPath(a, inner_clean, entry.name));
        try writeObj(app, &b, o, child);
    }
    try b.append("],\"total\":");
    try b.print("{d}", .{entries.len});
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

// ---------------------------------------------------------------------------
// Admin surface (/api/admin/* and /api/me)
//
// This is a single-admin build, so every authenticated caller is the admin.
// The frontend's settings page and the storage/task-centre management UI hang
// off these endpoints; they were the last unimplemented part of the /api/*
// surface. The handlers below mirror the upstream shapes closely enough that
// the stock OpenList frontend loads and saves without a shim.
// ---------------------------------------------------------------------------

/// `GET /api/me` — the current user record. Mirrors OpenList's contract:
/// `role: 2` is admin, `base_path: "/"` is the web root.
fn handleMe(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{");
    try b.print("\"id\":{d},", .{1});
    try b.append("\"username\":");
    try json.writeString(&b, app.admin_user);
    try b.append(",\"password\":\"\",\"base_path\":\"/\",\"role\":2,\"disabled\":false,\"permission\":0,\"otp_secret\":\"\",\"token\":null");
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// `GET /api/admin/storage` — the mount list the management UI renders. Each
/// entry carries the live status (a failed `init` surfaces as "errored" with a
/// non-empty `error_msg`, exactly as the Go build marks broken storages).
fn handleAdminStorage(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{\"content\":[");
    const mounts = app.mountsSnapshot();
    for (mounts, 0..) |m, i| {
        if (i != 0) try b.appendByte(',');
        try b.append("{\"id\":");
        try b.print("{d}", .{m.storage.id});
        try b.append(",\"mount_path\":");
        try json.writeString(&b, m.mount_path);
        try b.print(",\"order\":{d},", .{m.storage.order});
        try b.append("\"driver\":");
        try json.writeString(&b, m.storage.driver);
        try b.append(",\"status\":");
        try json.writeString(&b, if (m.storage.error_msg.len > 0) "errored" else m.storage.status);
        try b.append(",\"remark\":");
        try json.writeString(&b, m.storage.remark);
        try b.print(",\"disabled\":{},", .{m.storage.disabled});
        try b.append("\"addition\":");
        try json.writeString(&b, m.storage.addition);
        try b.append(",\"error_msg\":");
        try json.writeString(&b, m.storage.error_msg);
        try b.appendByte('}');
    }
    try b.append("],\"total\":");
    try b.print("{d}", .{mounts.len});
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// `GET /api/admin/driver/list` — map of driver key to its addition-schema
/// object, matching upstream's metadata endpoint.
fn handleDriverList(req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{");
    for (driver.builtin, 0..) |f, i| {
        if (i != 0) try b.appendByte(',');
        try json.writeString(&b, f.key);
        try b.appendByte(':');
        const schema = json.parse(a, f.addition_schema) catch .null;
        try json.write(&b, &schema);
    }
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// `GET /api/admin/driver/names` — keys for the storage driver's selector.
fn handleDriverNames(req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    var b = Buf.init(a);
    try b.appendByte('[');
    for (driver.builtin, 0..) |f, i| {
        if (i != 0) try b.appendByte(',');
        try json.writeString(&b, f.key);
    }
    try b.appendByte(']');
    try res.jsonOk(b.slice());
}

/// `GET /api/admin/setting` — reads site + presentation settings. The frontend
/// reads this shape and re-POSTs an edited copy, so GET and PUT stay symmetric.
fn handleAdminSettingGet(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const cfg = config.get();
    var b = Buf.init(a);
    try b.append("{\"code\":200,\"message\":\"success\",\"data\":{");
    try b.append("\"username\":");
    try json.writeString(&b, app.admin_user);
    try b.append(",\"password\":\"\",\"base_path\":\"/\"");
    try b.append(",\"site_url\":");
    try json.writeString(&b, app.site_url);
    try b.append(",\"cdn\":");
    try json.writeString(&b, app.cdn);
    try b.print(",\"token_expires_in\":{d}", .{app.token_expires_in_hours});
    try b.append(",\"web_version\":");
    try json.writeString(&b, cfg.web_version);
    try b.append(",\"title\":");
    try json.writeString(&b, cfg.site_title);
    try b.append(",\"logo\":");
    try json.writeString(&b, cfg.logo);
    try b.append(",\"favicon\":");
    try json.writeString(&b, cfg.favicon);
    try b.append(",\"main_color\":");
    try json.writeString(&b, cfg.main_color);
    try b.append(",\"customize_head\":");
    try json.writeString(&b, cfg.customize_head);
    try b.append(",\"customize_body\":");
    try json.writeString(&b, cfg.customize_body);
    try b.append("}}");
    try res.jsonOkRaw(b.slice());
}

/// `PUT /api/admin/setting` — writes the settings the frontend edited. Only the
/// fields this build models are persisted; the rest of the upstream payload is
/// ignored (the frontend re-sends the whole form, so nothing the UI shows is
/// lost — we simply do not store keys we have no backing config for). The cheap
/// runtime fields (`site_url`, `cdn`, `token_expires_in`) take effect
/// immediately; presentation fields (`title`, `logo`, ...) need a frontend
/// rebuild, which happens on the next restart because the SPA shell is built
/// once at startup.
fn handleAdminSettingPut(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const v = try parseBodyJson(a, req, res) orelse return;
    const cfg = config.get();
    const ca = cfg.allocator();

    if (v.strAt("site_url")) |s| {
        cfg.site_url = try ca.dupe(u8, s);
        try cfg.setTopLevel("site_url", .{ .string = cfg.site_url });
    }
    if (v.strAt("cdn")) |s| {
        cfg.cdn = try ca.dupe(u8, s);
        try cfg.setTopLevel("cdn", .{ .string = cfg.cdn });
    }
    if (v.intAt("token_expires_in")) |n| {
        cfg.token_expires_in = n;
        try cfg.setTopLevel("token_expires_in", .{ .int = n });
    }

    if (v.strAt("web_version")) |s| {
        cfg.web_version = try ca.dupe(u8, s);
        try cfg.putZig("web_version", .{ .string = cfg.web_version });
    }
    if (v.strAt("title")) |s| {
        cfg.site_title = try ca.dupe(u8, s);
        try cfg.putZig("site_title", .{ .string = cfg.site_title });
    }
    if (v.strAt("logo")) |s| {
        cfg.logo = try ca.dupe(u8, s);
        try cfg.putZig("logo", .{ .string = cfg.logo });
    }
    if (v.strAt("favicon")) |s| {
        cfg.favicon = try ca.dupe(u8, s);
        try cfg.putZig("favicon", .{ .string = cfg.favicon });
    }
    if (v.strAt("main_color")) |s| {
        cfg.main_color = try ca.dupe(u8, s);
        try cfg.putZig("main_color", .{ .string = cfg.main_color });
    }
    if (v.strAt("customize_head")) |s| {
        cfg.customize_head = try ca.dupe(u8, s);
        try cfg.putZig("customize_head", .{ .string = cfg.customize_head });
    }
    if (v.strAt("customize_body")) |s| {
        cfg.customize_body = try ca.dupe(u8, s);
        try cfg.putZig("customize_body", .{ .string = cfg.customize_body });
    }

    if (v.strAt("username")) |u| {
        const uname = if (u.len == 0) app.admin_user else u;
        try cfg.putZig("admin_user", .{ .string = try ca.dupe(u8, uname) });
        app.admin_user = try app.alloc.dupe(u8, uname);
    }
    // Password is write-only: an empty field means "keep the current one", so
    // we only act on a genuine new value (>= 6 chars, same floor as the Go build).
    if (v.strAt("password")) |pw| {
        if (pw.len >= 6) {
            // 对齐 Go `User.SetPassword`：改密就换 salt，重算 TwoHashPwd。
            const salt = try randomSalt(ca);
            const hash = try twoHashPwd(ca, pw, salt);
            try cfg.putZig("admin_salt", .{ .string = salt });
            try cfg.putZig("admin_password_hash", .{ .string = hash });
            app.admin_salt = try app.alloc.dupe(u8, salt);
            app.admin_hash = try app.alloc.dupe(u8, hash);

            // A03：改密必须让**已签发**的令牌立刻失效。Go 靠推进 `user.PwdTS`
            // 做到（server/middlewares/auth.go:62-66）；这里把 `admin_pwd_ts`
            // 推到当前时间，checkAuth 比对不上就直接 401。
            // 以前改密只换哈希，旧令牌照样能用 —— 口令泄露后"改密"形同虚设。
            app.admin_pwd_ts = rt.nowSeconds();
            try cfg.putZig("admin_pwd_ts", .{ .int = app.admin_pwd_ts });
            log.info("api: password changed, existing tokens invalidated", .{});
        }
    }

    cfg.save() catch |e| {
        log.warn("api: could not persist settings: {s}", .{@errorName(e)});
        return res.jsonError(500, "could not save settings");
    };

    // Reflect the cheap runtime-applicable fields now.
    app.site_url = try app.alloc.dupe(u8, cfg.site_url);
    app.cdn = try app.alloc.dupe(u8, cfg.cdn);
    app.token_expires_in_hours = cfg.token_expires_in;
    app.frontend.settings.site_title = try app.alloc.dupe(u8, cfg.site_title);
    app.frontend.settings.logo = try app.alloc.dupe(u8, cfg.logo);
    app.frontend.settings.favicon = try app.alloc.dupe(u8, cfg.favicon);
    app.frontend.settings.main_color = try app.alloc.dupe(u8, cfg.main_color);
    app.frontend.settings.customize_head = try app.alloc.dupe(u8, cfg.customize_head);
    app.frontend.settings.customize_body = try app.alloc.dupe(u8, cfg.customize_body);

    try res.jsonOk("null");
}

// OpenList stores settings as SettingItem records. This build has no settings
// database, so expose the config-backed subset with the same item shape and
// persist edits into config.json. Keys without a config representation remain
// intentionally absent instead of appearing editable-but-ignored.
const SettingDef = struct {
    key: []const u8,
    default: []const u8,
    kind: []const u8,
    group: i64,
    flag: i64 = 0,
};

const setting_defs = [_]SettingDef{
    .{ .key = "site_title", .default = "OpenList", .kind = "string", .group = 1 },
    .{ .key = "logo", .default = "https://res.oplist.org/logo/logo.svg", .kind = "text", .group = 2 },
    .{ .key = "favicon", .default = "https://res.oplist.org/logo/logo.svg", .kind = "string", .group = 2 },
    .{ .key = "main_color", .default = "#1890ff", .kind = "string", .group = 2 },
    .{ .key = "customize_head", .default = "", .kind = "text", .group = 4, .flag = 1 },
    .{ .key = "customize_body", .default = "", .kind = "text", .group = 4, .flag = 1 },
    // 下载签名。Go 侧这两项存在数据库 settings 表（key `sign_all` /
    // `link_expiration`），本工程没有库，落到 `zig.*` 块并立即生效。
    .{ .key = "sign_all", .default = "false", .kind = "bool", .group = 4 },
    .{ .key = "link_expiration", .default = "0", .kind = "number", .group = 4 },
};

fn handleSettingRoute(app: *App, req: *http.Request, res: *http.Response, action: []const u8) !void {
    if (std.mem.eql(u8, action, "list") and std.mem.eql(u8, req.method, "GET")) {
        return renderSettingItems(req, res, false, null);
    }
    if (std.mem.eql(u8, action, "default") and (std.mem.eql(u8, req.method, "POST") or std.mem.eql(u8, req.method, "GET"))) {
        return renderSettingItems(req, res, true, null);
    }
    if (std.mem.eql(u8, action, "get") and std.mem.eql(u8, req.method, "GET")) {
        const key = req.queryGet("key");
        const keys = req.queryGet("keys");
        if (key) |one| return renderSettingItems(req, res, false, one);
        if (keys) |many| return renderSettingItems(req, res, false, many);
        return res.jsonError(400, "key or keys is required");
    }
    if (std.mem.eql(u8, action, "save") and std.mem.eql(u8, req.method, "POST")) {
        return handleSettingSave(app, req, res);
    }
    return res.jsonError(404, "setting endpoint not found");
}

fn renderSettingItems(req: *http.Request, res: *http.Response, defaults: bool, only_keys: ?[]const u8) !void {
    const a = req.arena;
    const cfg = config.get();
    var b = Buf.init(a);
    try b.append("[");
    var wrote: usize = 0;
    for (setting_defs, 0..) |def, index| {
        if (!settingGroupIncluded(req, def.group)) continue;
        if (only_keys) |raw_keys| if (!keyListContains(raw_keys, def.key)) continue;
        if (wrote != 0) try b.appendByte(',');
        const value = if (defaults) def.default else settingValue(cfg, def.key);
        try b.append("{\"key\":");
        try json.writeString(&b, def.key);
        try b.append(",\"value\":");
        try json.writeString(&b, value);
        try b.append(",\"help\":\"\",\"type\":");
        try json.writeString(&b, def.kind);
        try b.append(",\"options\":\"\"");
        try b.print(",\"group\":{d},\"flag\":{d},\"index\":{d}}}", .{ def.group, def.flag, index });
        wrote += 1;
    }
    try b.append("]");
    try res.jsonOk(b.slice());
}

fn settingValue(cfg: *const config.Config, key: []const u8) []const u8 {
    if (std.mem.eql(u8, key, "site_title")) return cfg.site_title;
    if (std.mem.eql(u8, key, "logo")) return cfg.logo;
    if (std.mem.eql(u8, key, "favicon")) return cfg.favicon;
    if (std.mem.eql(u8, key, "main_color")) return cfg.main_color;
    if (std.mem.eql(u8, key, "customize_head")) return cfg.customize_head;
    if (std.mem.eql(u8, key, "customize_body")) return cfg.customize_body;
    // 非字符串字段：转成 setting 的字符串形态回给前端（前端表单按 kind 解析）。
    if (std.mem.eql(u8, key, "sign_all")) return if (cfg.sign_all) "true" else "false";
    if (std.mem.eql(u8, key, "link_expiration")) {
        // 调用方给的是一个 arena 里活的 Buf，这里用固定缓冲转十进制。
        var buf: [24]u8 = undefined;
        return std.fmt.bufPrint(&buf, "{d}", .{cfg.link_expiration}) catch "0";
    }
    return "";
}

fn settingGroupIncluded(req: *const http.Request, group: i64) bool {
    const list = req.queryGet("groups") orelse req.queryGet("group") orelse return true;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| {
        if (std.fmt.parseInt(i64, item, 10) catch continue == group) return true;
    }
    return false;
}

fn keyListContains(list: []const u8, key: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| if (std.mem.eql(u8, item, key)) return true;
    return false;
}

fn handleSettingSave(app: *App, req: *http.Request, res: *http.Response) !void {
    const a = req.arena;
    const payload = try parseBodyJson(a, req, res) orelse return;
    const items = payload.asArray() orelse return res.jsonError(400, "expected an array of setting items");
    const cfg = config.get();
    const ca = cfg.allocator();
    for (items) |item| {
        const key = item.strAt("key") orelse continue;
        const value_node = item.getPath("value") orelse continue;
        const value = switch (value_node.*) {
            .string => |s| s,
            .bool => |v| if (v) "true" else "false",
            .int => |v| try std.fmt.allocPrint(a, "{d}", .{v}),
            else => continue,
        };
        if (!isConfigBackedSetting(key)) continue;
        const owned = try ca.dupe(u8, value);
        try cfg.putZig(key, .{ .string = owned });
        if (std.mem.eql(u8, key, "site_title")) cfg.site_title = owned;
        if (std.mem.eql(u8, key, "logo")) cfg.logo = owned;
        if (std.mem.eql(u8, key, "favicon")) cfg.favicon = owned;
        if (std.mem.eql(u8, key, "main_color")) cfg.main_color = owned;
        if (std.mem.eql(u8, key, "customize_head")) cfg.customize_head = owned;
        if (std.mem.eql(u8, key, "customize_body")) cfg.customize_body = owned;
        // 下载签名两项：存的是字符串形态，写回结构体时要转类型。
        if (std.mem.eql(u8, key, "sign_all")) cfg.sign_all = std.mem.eql(u8, value, "true");
        if (std.mem.eql(u8, key, "link_expiration")) {
            cfg.link_expiration = std.fmt.parseInt(i64, value, 10) catch 0;
        }
    }
    cfg.save() catch |e| {
        log.warn("api: could not persist settings: {s}", .{@errorName(e)});
        return res.jsonError(500, "could not save settings");
    };
    // Mirror the live settings used by the public-settings response. The
    // substituted SPA HTML and manifest were built once at startup; those
    // presentation changes become visible in the page after a restart.
    app.frontend.settings.site_title = try app.alloc.dupe(u8, cfg.site_title);
    app.frontend.settings.logo = try app.alloc.dupe(u8, cfg.logo);
    app.frontend.settings.favicon = try app.alloc.dupe(u8, cfg.favicon);
    app.frontend.settings.main_color = try app.alloc.dupe(u8, cfg.main_color);
    app.frontend.settings.customize_head = try app.alloc.dupe(u8, cfg.customize_head);
    app.frontend.settings.customize_body = try app.alloc.dupe(u8, cfg.customize_body);
    try res.jsonOk("null");
}

fn isConfigBackedSetting(key: []const u8) bool {
    for (setting_defs) |def| if (std.mem.eql(u8, key, def.key)) return true;
    return false;
}

/// This binary has no background task manager (and deliberately does not add
/// offline-download workers). Returning the real empty-list envelope lets the
/// stock task-centre view render accurately; task actions are not advertised.
fn handleTaskRoute(req: *http.Request, res: *http.Response, suffix: []const u8) !void {
    var it = std.mem.splitScalar(u8, suffix, '/');
    const kind = it.next() orelse return res.jsonError(404, "task route not found");
    const action = it.next() orelse return res.jsonError(404, "task route not found");
    if (it.next() != null) return res.jsonError(404, "task route not found");
    const allowed = [_][]const u8{ "upload", "copy", "move", "offline_download", "offline_download_transfer", "decompress", "decompress_upload" };
    var known = false;
    for (allowed) |candidate| if (std.mem.eql(u8, kind, candidate)) {
        known = true;
        break;
    };
    if (!known) return res.jsonError(404, "task route not found");
    if (!std.mem.eql(u8, action, "undone") and !std.mem.eql(u8, action, "done")) return res.jsonError(404, "task action not found");
    if (!std.mem.eql(u8, req.method, "GET")) return res.jsonError(405, "method not allowed");
    try res.jsonOk("[]");
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

fn handleDownload(app: *App, req: *http.Request, res: *http.Response, force_proxy: bool) !void {
    const a = req.arena;
    const prefix: usize = 3; // "/d/" or "/p/"
    const raw = req.path[prefix..];
    const path = std.fmt.allocPrint(a, "/{s}", .{raw}) catch return res.jsonError(500, "oom");

    // 鉴权：`?sign=` 优先（`sign_all` 打开时的唯一途径），否则回落到 token。
    // 对齐 Go `server/middlewares/down.go` 的 Down + needSign 组合。
    const ctx_path = path;
    const ok = downloadAuthorized(app, req, ctx_path) catch false;
    if (!ok) return res.jsonError(401, "not logged in");

    const r = app.resolve(path) orelse return res.jsonError(404, "storage not found");
    var ctx = driver.Ctx{ .alloc = a, .tag = r.mount.mount_path };

    const f = r.mount.driver.details(&ctx, r.rel) catch |e| return mapDriverError(res, e);
    if (f.is_dir) return res.jsonError(400, "is a directory");

    // A05：同样把调用方的头透传给驱动（Go fsread.go 传的是 c.Request.Header）。
    const lk = r.mount.driver.link(&ctx, r.rel, .{
        .redirect = !force_proxy,
        .headers = req.headers,
    }) catch |e| {
        return mapDriverError(res, e);
    };

    // `total` is what we advertise in `Content-Range`. For local files it is the
    // on-disk size; for in-memory content (Strm 的 `.strm` 文本) it is the text
    // length; for remote it comes from `details`.
    const total: u64 = if (lk.local_path) |_| lk.local_size else if (lk.text) |t| t.len else @intCast(@max(f.size, 0));

    // A single byte range, if the client asked for one. Malformed/unknown
    // range syntax is ignored (normal 200); a syntactically valid but
    // unsatisfiable range must be 416, never a silent full-file response.
    const range_result = if (req.header("Range")) |rh| parseRange(rh, total) else ParsedRange.ignore;
    if (range_result == .unsatisfiable) {
        res.setStatus(416);
        try res.set("Accept-Ranges", "bytes");
        try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes */{d}", .{total}));
        return;
    }
    const range: ?RangeBounds = switch (range_result) {
        .valid => |rg| rg,
        else => null,
    };

    // Local files: stream straight off disk, range-supported.
    if (lk.local_path) |lp| {
        const file = std.Io.Dir.cwd().openFile(rt.io(), lp, .{}) catch |e| {
            log.warn("api: open {s} failed: {s}", .{ lp, @errorName(e) });
            return res.jsonError(500, "cannot open file");
        };
        try res.set("Content-Type", mimeFor(f.name));
        try res.set("Accept-Ranges", "bytes");
        if (range) |rg| {
            if (rg.start >= total) {
                res.setStatus(416);
                try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes */{d}", .{total}));
                return;
            }
            const len = rg.end - rg.start + 1;
            res.setStatus(206);
            try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes {d}-{d}/{d}", .{ rg.start, rg.end, total }));
            // Stream only the requested window; never buffer it.
            const rs = a.create(RangeSrc) catch return res.jsonError(500, "oom");
            rs.* = .{ .file = file, .cursor = rg.start, .end = rg.end + 1 };
            res.stream = .{ .ctx = rs, .read = rangeRead, .len = len, .cleanup = rangeCleanup };
        } else {
            res.sendFile(file, total);
        }
        return;
    }

    // In-memory content (`Link.text` — Strm 的 `.strm` 虚拟文件，内容是 URL
    // 文本；Go `drivers/strm/driver.go:200-204` 用 RangeReader 返回它）。
    // Content-Type 对齐 Go `http.ServeContent` 对 URL 文本的内容嗅探结果。
    if (lk.text) |txt| {
        try res.set("Content-Type", "text/plain; charset=utf-8");
        try res.set("Accept-Ranges", "bytes");
        if (range) |rg| {
            if (rg.start >= total) {
                res.setStatus(416);
                try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes */{d}", .{total}));
                return;
            }
            res.setStatus(206);
            try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes {d}-{d}/{d}", .{ rg.start, rg.end, total }));
            try res.write(txt[rg.start..rg.end + 1]);
        } else {
            res.setStatus(200);
            try res.write(txt);
        }
        return;
    }

    // Remote, no proxy needed: a 302 is cheaper for everyone (the client talks
    // to the upstream directly and negotiates range there).
    if (!lk.proxy and !force_proxy) {
        try res.redirect(lk.url, 302);
        return;
    }

    // Remote with proxy: forward Range to upstream. When the provider honours
    // Range, only that window is buffered by the current std.http client. If it
    // ignores Range (or the caller omits it), the client still buffers the full
    // upstream response; a streaming response reader remains a known follow-up.
    var hdrs = List(Header).init(a);
    for (lk.header) |h| try hdrs.append(h);
    if (range) |rg| {
        try hdrs.append(.{ .name = "Range", .value = try std.fmt.allocPrint(a, "bytes={d}-{d}", .{ rg.start, rg.end }) });
    }
    var jar = cookiejar.Jar.init(a);
    var client = client_mod.Client.init(a, .{}, &jar);
    defer client.deinit();
    const up = client.send(a, .{
        .method = "GET",
        .url = lk.url,
        .headers = hdrs.slice(),
        // N02：回源必须跟随 3xx。CDN 普遍用 302 把请求转到实际边缘节点，
        // 不跟随就会把 302 当成上游错误、回一个 502 给用户。
        // 注意：只在这个**代理回源**点开启；天翼/itvsh 那些把 302 当业务
        // 状态的调用点保持原样，所以不能改 `Request` 的默认值。
        .follow_redirects = true,
    }) catch |e| {
        log.warn("api: proxy fetch {s} failed: {s}", .{ lk.url, @errorName(e) });
        return res.jsonError(502, "upstream fetch failed");
    };
    if (up.status != 200 and up.status != 206) return res.jsonError(502, "upstream returned an error");

    try res.set("Content-Type", mimeFor(f.name));
    try res.set("Accept-Ranges", "bytes");
    if (up.status == 206) {
        res.setStatus(206);
        if (up.header("Content-Range")) |cr| try res.set("Content-Range", cr);
        try res.write(up.body);
    } else if (range) |rg| {
        // Upstream ignored the Range and sent the whole file: slice to the window.
        if (rg.start >= up.body.len) {
            res.setStatus(416);
            try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes */{d}", .{total}));
            return;
        }
        const end_ex = @min(rg.end + 1, up.body.len);
        res.setStatus(206);
        try res.set("Content-Range", try std.fmt.allocPrint(a, "bytes {d}-{d}/{d}", .{ rg.start, end_ex - 1, total }));
        try res.write(up.body[rg.start..end_ex]);
    } else {
        try res.write(up.body);
    }
}

// ---------------------------------------------------------------------------
// Range streaming + progress
// ---------------------------------------------------------------------------

const RangeSrc = struct {
    file: std.Io.File,
    cursor: u64,
    end: u64,
};

fn rangeRead(ctx: *anyopaque, out: []u8) anyerror!usize {
    const s: *RangeSrc = @ptrCast(@alignCast(ctx));
    if (s.cursor >= s.end) return 0;
    const want = @min(out.len, s.end - s.cursor);
    var got: usize = 0;
    while (got < want) {
        const n = std.Io.File.readPositionalAll(s.file, rt.io(), out[got..want], s.cursor + got) catch |e| return e;
        if (n == 0) break;
        got += n;
    }
    s.cursor += got;
    return got;
}

fn rangeCleanup(ctx: *anyopaque) void {
    const s: *RangeSrc = @ptrCast(@alignCast(ctx));
    s.file.close(rt.io());
}

/// Inclusive byte range bounds, parsed from an HTTP `Range` header. A named
/// type rather than an anonymous struct so the parser's return type and the
/// caller's variable unify — Zig treats identical anonymous structs at two
/// sites as distinct types.
const RangeBounds = struct { start: u64, end: u64 };

const ParsedRange = union(enum) {
    ignore,
    unsatisfiable,
    valid: RangeBounds,
};

/// Parse a single `bytes=START-END` (or `START-`, or `-SUFFIX`) range. Multiple
/// ranges are intentionally ignored; unsupported/malformed syntax falls back
/// to a normal response, but a valid range outside the resource yields 416.
fn parseRange(hdr: []const u8, total: u64) ParsedRange {
    const eq = std.mem.indexOfScalar(u8, hdr, '=') orelse return .ignore;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, hdr[0..eq], " "), "bytes")) return .ignore;
    const spec = std.mem.trim(u8, hdr[eq + 1 ..], " ");
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return .ignore;
    const dash_at = std.mem.indexOfScalar(u8, spec, '-') orelse return .ignore;
    if (std.mem.indexOfScalarPos(u8, spec, dash_at + 1, '-') != null) return .ignore;
    const start_s = spec[0..dash_at];
    const end_s = spec[dash_at + 1 ..];
    if (start_s.len == 0) {
        const n = std.fmt.parseInt(u64, end_s, 10) catch return .ignore;
        if (n == 0 or total == 0) return .unsatisfiable;
        const start = if (n >= total) 0 else total - n;
        return .{ .valid = .{ .start = start, .end = total - 1 } };
    }
    const start = std.fmt.parseInt(u64, start_s, 10) catch return .ignore;
    const end_parsed: ?u64 = if (end_s.len == 0) null else std.fmt.parseInt(u64, end_s, 10) catch return .ignore;
    if (total == 0 or start >= total) return .unsatisfiable;
    var end = end_parsed orelse (total - 1);
    if (start > end) return .unsatisfiable;
    if (end >= total) end = total - 1;
    return .{ .valid = .{ .start = start, .end = end } };
}

/// 上传进度。`pct` 是 **0–100**（`driver.ProgressFn` 的语义，
/// 对应 Go `model.UpdateProgress`）。目前 sink 还只是记录下来 —— 前端轮询
/// 上传状态的接口尚未接线（见 TODO）。
const PutProgress = struct { pct: u64 = 0 };

fn putProgressCb(ud: ?*anyopaque, pct: u64) void {
    if (ud) |p| {
        const s: *PutProgress = @ptrCast(@alignCast(p));
        // 只有 0–100 才收，防上游驱动乱报。
        if (pct <= 100) s.pct = pct;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `path` 是该条目的完整虚拟路径（`dir/name`）—— 下载签名签的就是它，
/// 对应 Go `server/common/sign.go` 的 `join(parent, name)`。
///
/// ⚠️ 不能用 `o.sign` 代替：绝大多数驱动不填那个字段（Go 是在 op 层统一填
/// 路径的），拿空串当数据会签出一个"对空路径有效"的签名。
fn writeObj(app: *App, b: *Buf, o: model.Obj, path: []const u8) !void {
    try b.append("{\"name\":");
    try json.writeString(b, o.name);
    try b.print(",\"size\":{d},\"is_dir\":{s}", .{ o.size, if (o.is_dir) "true" else "false" });
    try b.append(",\"modified\":");
    try json.writeString(b, try fmtTime(b.alloc, o.modified));
    try b.append(",\"created\":");
    // Go `Object.CreateTime()` 在 Ctime 为零时回退到 ModTime；不能把零值
    // 直接输出为空串，否则前端日期格式化会得到 NaN。
    try json.writeString(b, try fmtTime(b.alloc, if (o.created == 0) o.modified else o.created));
    try b.append(",\"sign\":");
    try json.writeString(b, try signForObj(app, b.alloc, o.is_dir, path));
    try b.append(",\"thumb\":");
    try json.writeString(b, o.thumb);
    try b.print(",\"type\":{d},\"hash_info\":null", .{@backingInt(o.typeEnum())});
    try b.appendByte('}');
}

/// OpenList serialises timestamps as RFC3339. We emit the same shape so the
/// frontend's date formatting works.
fn fmtTime(a: std.mem.Allocator, ts: i64) ![]const u8 {
    // Go `time.Time{}` JSON 序列化为 RFC3339 零值；空串会让前端日期
    // 格式化器得到 NaN。保留协议形状，所有 Obj 都输出可解析时间。
    if (ts == 0) return "0001-01-01T00:00:00Z";
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(ts, 0)) };
    const day = es.getEpochDay();
    const ds = es.getDaySeconds();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.allocPrint(a, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    });
}

fn parseBodyJson(a: std.mem.Allocator, req: *http.Request, res: *http.Response) !?json.Value {
    // The frontend sends JSON; a few endpoints also accept form-encoded.
    if (req.body.len() == 0) return json.Value{ .object = .{} };
    const text = req.body.readAll(a) catch return null;
    return json.parse(a, text) catch {
        res.jsonError(400, "invalid JSON body") catch {};
        return null;
    };
}

fn mapDriverError(res: *http.Response, e: anyerror) !void {
    return switch (e) {
        error.AuthFailed, error.ConfiguredTokenExpired => res.jsonError(401, @errorName(e)),
        error.NotFound => res.jsonError(404, "not found"),
        error.NotSupported => res.jsonError(501, "operation not supported by this driver"),
        error.RateLimited => res.jsonError(429, "upstream rate limited"),
        error.WafBlocked => res.jsonError(502, "blocked by upstream WAF"),
        error.UnexpectedResponse, error.UpstreamError, error.UpstreamHttp, error.UpstreamNotJson => res.jsonError(502, "upstream error"),
        error.TokenUnavailable => res.jsonError(502, "could not obtain an upstream token"),
        error.ForwardUrlMissing => res.jsonError(500, "storage is misconfigured (forwardUrl missing)"),
        error.MissingCredentials => res.jsonError(500, "storage credentials are missing"),
        error.InvalidPath => res.jsonError(400, "invalid path"),
        error.TargetExists => res.jsonError(409, "target already exists"),
        error.DirectoryNotEmpty => res.jsonError(409, "directory is not empty"),
        error.InsufficientStorage => res.jsonError(507, "insufficient storage"),
        else => res.jsonError(500, @errorName(e)),
    };
}

fn sha256Hex(a: std.mem.Allocator, s: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(s, &digest, .{});
    const out = try a.alloc(u8, 64);
    const hex = "0123456789abcdef";
    for (digest, 0..) |c, i| {
        out[i * 2] = hex[c >> 4];
        out[i * 2 + 1] = hex[c & 0x0F];
    }
    return out;
}

/// Go `model.StaticHashSalt`（`internal/model/user.go:24`）。
/// 前端登录页会先用它把明文口令算成 "static hash"，再 POST 到
/// `/api/auth/login/hash` —— 所以这个常量必须与 Go **逐字节**一致，
/// 否则前端永远登不上（这正是 2026-10-13 那次「登录失败」的根因）。
pub const static_hash_salt = "https://github.com/alist-org/alist";

/// Go `model.StaticHash` = `sha256(password + "-" + StaticHashSalt)`。
pub fn staticHash(a: std.mem.Allocator, pwd: []const u8) ![]const u8 {
    const s = try std.fmt.allocPrint(a, "{s}-{s}", .{ pwd, static_hash_salt });
    return sha256Hex(a, s);
}

/// Go `model.HashPwd(static, salt)` = `sha256(static + "-" + salt)`。
pub fn hashPwd(a: std.mem.Allocator, static: []const u8, salt: []const u8) ![]const u8 {
    const s = try std.fmt.allocPrint(a, "{s}-{s}", .{ static, salt });
    return sha256Hex(a, s);
}

/// Go `model.TwoHashPwd(pwd, salt)` = `HashPwd(StaticHash(pwd), salt)`。
/// **这才是 Go 存进库里的形态**（`User.SetPassword`，`internal/model/user.go:96`）。
pub fn twoHashPwd(a: std.mem.Allocator, pwd: []const u8, salt: []const u8) ![]const u8 {
    const st = try staticHash(a, pwd);
    return hashPwd(a, st, salt);
}

/// Go `random.String(16)` —— `User.SetPassword` 给每个用户现生成 16 位随机 salt。
pub fn randomSalt(a: std.mem.Allocator) ![]const u8 {
    const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const out = try a.alloc(u8, 16);
    var raw: [1]u8 = undefined;
    for (out) |*c| {
        rt.io().random(&raw);
        c.* = letters[raw[0] % letters.len];
    }
    return out;
}

fn hmacSha256(a: std.mem.Allocator, key: []const u8, msg: []const u8) ![32]u8 {    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, msg, key);
    _ = a;
    return mac;
}

fn b64Url(a: std.mem.Allocator, data: []const u8) ![]const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const out = try a.alloc(u8, enc.calcSize(data.len));
    return enc.encode(out, data);
}

// ---------------------------------------------------------------------------
// 下载签名（对齐 Go `pkg/sign/hmac.go` + `server/common/sign.go`）
// ---------------------------------------------------------------------------

/// 与上游逐字段一致的四个错误（`pkg/sign/sign.go:12-17`）。
pub const SignError = error{
    SignExpired,
    SignInvalid,
    ExpireInvalid,
    ExpireMissing,
};

/// `Sign(data, expire)` = `base64url(HMAC-SHA256(secret, data + ":" + expire))`
/// 拼上 `":" + expire`。
///
/// ⚠️ 编码用**带 padding 的 URL-safe base64**（`std.base64.url_safe`）—— Go 是
/// `base64.URLEncoding`（`pkg/sign/hmac.go:26`），而 JWT 那边的
/// `base64.RawURLEncoding` 是无 padding 的。两者差一个 `=`，混用会让签名对不上。
/// `b64Url`（无 padding）留给 JWT 用，不要在这里复用。
fn signValue(a: std.mem.Allocator, secret: []const u8, data: []const u8, expire: i64) ![]const u8 {
    const expire_str = try std.fmt.allocPrint(a, "{d}", .{expire});
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, try std.fmt.allocPrint(a, "{s}:{s}", .{ data, expire_str }), secret);
    const b64 = std.base64.url_safe.Encoder;
    const raw = try a.alloc(u8, b64.calcSize(mac.len));
    return std.fmt.allocPrint(a, "{s}:{s}", .{ b64.encode(raw, &mac), expire_str });
}

/// 给 `fs/list` / `fs/get` 的对象签一个下载签名。
///
/// 对齐 Go `server/common/sign.go:13-18`：目录不签；非目录时
/// `!encrypt && !sign_all` 也不签（本工程没有 meta 加密，所以只看 `sign_all`）。
fn signForObj(app: *App, a: std.mem.Allocator, is_dir: bool, path: []const u8) ![]const u8 {
    if (is_dir) return "";
    // 没有加载配置（单元测试 / 极早期启动）时按「不签」处理 —— 与 Go 的
    // `setting.GetBool` 在 settings 表未初始化时返回零值同形。
    const cfg = config.getOpt() orelse return "";
    if (!cfg.sign_all) return "";
    const expire_hours = cfg.link_expiration;
    if (expire_hours == 0) return signValue(a, app.jwt_secret, path, 0);
    // 溢出防护：`link_expiration` 是用户可配的，配个巨大值不能让服务崩在
    // 一次列目录上。算不出来就按「不过期」处理。
    const expire = std.math.mul(i64, expire_hours, 3600) catch {
        log.warn("[api] link_expiration={d} overflows; signing without expiry", .{expire_hours});
        return signValue(a, app.jwt_secret, path, 0);
    };
    return signValue(a, app.jwt_secret, path, rt.nowSeconds() + expire);
}

/// `Verify(data, sign)` —— 逐条对齐 Go `pkg/sign/hmac.go:34-56`。
fn verifySign(app: *App, a: std.mem.Allocator, data: []const u8, sign: []const u8) !void {
    // sign 形如 `<b64url>:<expire>`，expire 在最后一个 ':' 之后。
    const colon = std.mem.lastIndexOfScalar(u8, sign, ':') orelse return SignError.ExpireMissing;
    const exp_str = sign[colon + 1 ..];
    if (exp_str.len == 0) return SignError.ExpireMissing;
    const expires = std.fmt.parseInt(i64, exp_str, 10) catch return SignError.ExpireInvalid;
    // 0 表示「永不过期」；负数视为已过期。
    if (expires != 0 and expires < rt.nowSeconds()) return SignError.SignExpired;
    const expect = try signValue(a, app.jwt_secret, data, expires);
    if (!std.mem.eql(u8, expect, sign)) return SignError.SignInvalid;
}

/// `/d/` 与 `/p/` 的鉴权入口：有 `?sign=` 就走签名校验，
/// 否则回落到 token（与 Go `server/middlewares/down.go:27-40` 同构）。
fn downloadAuthorized(app: *App, req: *http.Request, raw_path: []const u8) !bool {
    if (req.queryGet("sign")) |s| {
        if (s.len == 0) return false;
        verifySign(app, req.arena, raw_path, s) catch |e| {
            log.warn("[api] /d/ sign rejected for {s}: {s}", .{ raw_path, @errorName(e) });
            return false;
        };
        return true;
    }
    // 没有 sign：`sign_all` 开着就必须验签（Go 在 `needSign` 里先查 sign_all，
    // 拿不到 sign 即 401）。配置没加载时视为关闭，回落到 token。
    const cfg = config.getOpt() orelse return checkAuth(app, req);
    if (cfg.sign_all and !authorizedByStorageSign(raw_path)) return false;
    return checkAuth(app, req);
}

/// 存储级 sign 开关（Go 的 `common.IsStorageSignEnabled`）—— 本工程的存储配置
/// 没有这个字段，恒为 false。留函数是为了让 `downloadAuthorized` 的分支与
/// Go 的 `needSign` 一一对应，将来加存储级开关只改这一处。
fn authorizedByStorageSign(_: []const u8) bool {
    return false;
}

fn b64UrlDecode(a: std.mem.Allocator, s: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const out = try a.alloc(u8, try dec.calcSizeForSlice(s));
    try dec.decode(out, s);
    return out;
}

/// Content type by file extension.
///
/// The web-asset entries are not decoration: a browser refuses to execute a
/// `<script type="module">` unless it is served with a JavaScript MIME type, so
/// a frontend build served as `application/octet-stream` would load the shell
/// and then die with a console error. `.ts` is mapped to `video/mp2t` rather
/// than TypeScript because on a file-browsing server the media reading wins —
/// and no build ships raw TypeScript.
pub fn mimeFor(name: []const u8) []const u8 {
    const ext = std.fs.path.extension(name);
    const map = .{
        // Web assets (served from `dist_dir`).
        .{ ".js", "text/javascript; charset=utf-8" },
        .{ ".mjs", "text/javascript; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".htm", "text/html; charset=utf-8" },
        .{ ".svg", "image/svg+xml" },
        .{ ".ico", "image/x-icon" },
        .{ ".webmanifest", "application/manifest+json" },
        .{ ".map", "application/json" },
        .{ ".wasm", "application/wasm" },
        .{ ".woff", "font/woff" },
        .{ ".woff2", "font/woff2" },
        .{ ".ttf", "font/ttf" },
        .{ ".otf", "font/otf" },
        // Documents and data.
        .{ ".txt", "text/plain; charset=utf-8" },
        .{ ".md", "text/markdown; charset=utf-8" },
        .{ ".csv", "text/csv; charset=utf-8" },
        .{ ".json", "application/json" },
        .{ ".xml", "application/xml" },
        .{ ".pdf", "application/pdf" },
        // Images.
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".png", "image/png" },
        .{ ".gif", "image/gif" },
        .{ ".webp", "image/webp" },
        .{ ".avif", "image/avif" },
        .{ ".bmp", "image/bmp" },
        // Audio / video. ⚠️ 这里不能省：浏览器 `<audio>`/`<video>` 只接受
        // `audio/*`、`video/*` 的响应，`application/octet-stream` 会直接报
        // "no supported source"。Go 版在 Linux 上靠 mime.TypeByExtension 读
        // /etc/mime.types 拿到这些类型（Debian 自带），本工程是固定表，必须
        // 把常见音视频扩展名列全 —— 尤其 .mp3。
        .{ ".mp3", "audio/mpeg" },
        .{ ".m4a", "audio/mp4" },
        .{ ".wma", "audio/x-ms-wma" },
        .{ ".mka", "audio/x-matroska" },
        .{ ".mid", "audio/midi" },
        .{ ".midi", "audio/midi" },
        .{ ".amr", "audio/amr" },
        .{ ".ape", "audio/x-ape" },
        .{ ".m3u", "audio/x-mpegurl" },
        .{ ".avi", "video/x-msvideo" },
        .{ ".wmv", "video/x-ms-wmv" },
        .{ ".asf", "video/x-ms-asf" },
        .{ ".flv", "video/x-flv" },
        .{ ".rmvb", "application/vnd.rn-realmedia-vbr" },
        .{ ".rm", "application/vnd.rn-realmedia" },
        .{ ".3gp", "video/3gpp" },
        .{ ".ogv", "video/ogg" },
        .{ ".m4v", "video/x-m4v" },
        .{ ".mpg", "video/mpeg" },
        .{ ".mpeg", "video/mpeg" },
        .{ ".mp4", "video/mp4" },
        .{ ".mkv", "video/x-matroska" },
        .{ ".webm", "video/webm" },
        .{ ".mov", "video/quicktime" },
        .{ ".ts", "video/mp2t" },
        .{ ".m3u8", "application/vnd.apple.mpegurl" },
        .{ ".mp3", "audio/mpeg" },
        .{ ".m4a", "audio/mp4" },
        .{ ".aac", "audio/aac" },
        .{ ".ogg", "audio/ogg" },
        .{ ".wav", "audio/wav" },
        .{ ".flac", "audio/flac" },
        // Archives.
        .{ ".zip", "application/zip" },
        .{ ".7z", "application/x-7z-compressed" },
        .{ ".rar", "application/vnd.rar" },
        .{ ".gz", "application/gzip" },
        .{ ".tar", "application/x-tar" },
    };
    inline for (map) |m| {
        if (std.ascii.eqlIgnoreCase(ext, m[0])) return m[1];
    }
    return "application/octet-stream";
}

fn readSecret(a: std.mem.Allocator, cfg: *config.Config, key: []const u8) ![]const u8 {
    const path = try std.fmt.allocPrint(a, "zig.{s}", .{key});
    const v = cfg.raw(path) orelse return "";
    return a.dupe(u8, v.asStr() orelse "");
}

fn readSecretInt(cfg: *config.Config, key: []const u8, default: i64) i64 {
    const path = std.fmt.allocPrint(std.heap.page_allocator, "zig.{s}", .{key}) catch return default;
    defer std.heap.page_allocator.free(path);
    const v = cfg.raw(path) orelse return default;
    return v.asInt() orelse default;
}

fn readSecretDefault(a: std.mem.Allocator, cfg: *config.Config, key: []const u8, default: []const u8) ![]const u8 {
    const path = try std.fmt.allocPrint(a, "zig.{s}", .{key});
    const v = cfg.raw(path) orelse return a.dupe(u8, default);
    return a.dupe(u8, v.asStr() orelse default);
}

/// Constant-time byte comparison. Written out rather than pulled from
/// `std.crypto.utils.timingSafeEql`, whose module path has moved between Zig
/// releases; this is six lines and cannot drift.
fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) {
        // Touch both buffers so the timing does not depend on length alone,
        // then fail.
        //
        // 不能把 `a.len ^ b.len`（usize）`@intCast` 成 u8：长度差超过 255 时
        // 安全构建会 panic，ReleaseSmall 下静默截断 —— 畸形签名长度会变成
        // 一条“要么崩进程、要么不可信”的路径。长度差只需参与 OR 累积，用
        // usize 自己的宽度就够了，最后只取低位。
        var acc: usize = a.len ^ b.len;
        for (a) |c| acc |= c;
        for (b) |c| acc |= c;
        // 长度已不等 → 结果恒为 false。写成 `acc != 0 and a.len == b.len`
        // 而不是直接 `return false`，是为了让 `acc` 真正被使用，上面的两次
        // 循环不会被优化掉（否则时序就只取决于长度差了）。
        return acc != 0 and a.len == b.len;
    }
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

// The SPA shell that used to live here as `INDEX_HTML` is now built at startup
// from the configured frontend source — see `frontend.zig`. What this file
// serves is `app.frontend.htmlFor(path)`.

// ---------------------------------------------------------------------------

const testing = std.testing;

test "mount resolution matches on segment boundaries" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var mounts = try a.alloc(Mount, 2);
    mounts[0] = .{ .storage = .{ .driver = "Itvsh" }, .driver = undefined, .mount_path = "/nas", .label = "" };
    mounts[1] = .{ .storage = .{ .driver = "Local" }, .driver = undefined, .mount_path = "/", .label = "" };

    var app = App{
        .alloc = a,
        .mounts = mounts,
        .admin_hash = "",
        .admin_user = "admin",
        .admin_pwd_ts = 0,
        .jwt_secret = "s",
        .site_url = "",
        .cdn = "",
        .token_expires_in_hours = 48,
        // `resolve` touches nothing else; building a real frontend here would
        // need a config file and possibly the network.
        .frontend = undefined,
    };

    try testing.expectEqualStrings("/nas", app.resolve("/nas").?.mount.mount_path);
    try testing.expectEqualStrings("/", app.resolve("/nas").?.rel);
    try testing.expectEqualStrings("/a/b", app.resolve("/nas/a/b").?.rel);
    // "/nas2" must NOT match the "/nas" mount
    try testing.expectEqualStrings("/", app.resolve("/nas2").?.mount.mount_path);
    try testing.expectEqualStrings("/x", app.resolve("/x").?.rel);
}

test "mime mapping" {
    try testing.expectEqualStrings("video/mp4", mimeFor("a.MP4"));
    try testing.expectEqualStrings("image/jpeg", mimeFor("x.jpg"));
    try testing.expectEqualStrings("application/octet-stream", mimeFor("x.bin"));
    try testing.expectEqualStrings("application/octet-stream", mimeFor("noext"));
    // A module script with a non-JS content type is refused by the browser, so
    // these two carry the frontend.
    try testing.expectEqualStrings("text/javascript; charset=utf-8", mimeFor("assets/index-abc123.js"));
    try testing.expectEqualStrings("text/javascript; charset=utf-8", mimeFor("chunk.MJS"));
    try testing.expectEqualStrings("text/css; charset=utf-8", mimeFor("assets/index-abc.css"));
    try testing.expectEqualStrings("image/svg+xml", mimeFor("logo.svg"));
    try testing.expectEqualStrings("font/woff2", mimeFor("inter.woff2"));
    try testing.expectEqualStrings("application/wasm", mimeFor("mod.wasm"));
    // HLS segments, not TypeScript.
    try testing.expectEqualStrings("video/mp2t", mimeFor("seg000.ts"));
}

test "sha256 hex and base64url round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const h = try sha256Hex(a, "abc");
    try testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", h);

    const enc = try b64Url(a, "hello\xff");
    const dec = try b64UrlDecode(a, enc);
    try testing.expectEqualStrings("hello\xff", dec);
}

test "time formatting matches RFC3339" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("0001-01-01T00:00:00Z", try fmtTime(a, 0));
    try testing.expectEqualStrings("1994-11-06T08:49:37Z", try fmtTime(a, 784111777));
}

test "mimeFor gives media types the browser audio/video elements accept" {
    // 回归：浏览器 `<audio>` 拒绝 `application/octet-stream` 的源（报
    // "no supported source"），所以常见音视频扩展名必须映射到 audio/*、
    // video/*，对齐 Go 在 Linux 上读 /etc/mime.types 的行为。
    try testing.expectEqualStrings("audio/mpeg", mimeFor("陶晶莹 - 太委屈.mp3"));
    try testing.expectEqualStrings("audio/x-ms-wma", mimeFor("萧亚轩 - 下一次恋爱.wma"));
    try testing.expectEqualStrings("audio/mp4", mimeFor("a.m4a"));
    try testing.expectEqualStrings("audio/flac", mimeFor("a.flac"));
    try testing.expectEqualStrings("video/mp4", mimeFor("a.mp4"));
    try testing.expectEqualStrings("video/x-msvideo", mimeFor("a.avi"));
    try testing.expectEqualStrings("video/x-ms-wmv", mimeFor("a.wmv"));
    try testing.expectEqualStrings("video/x-flv", mimeFor("a.flv"));
    // 大小写不敏感（浏览器发来的扩展名大小写不可控）。
    try testing.expectEqualStrings("audio/mpeg", mimeFor("A.MP3"));
    // 真正的未知类型才回落 octet-stream。
    try testing.expectEqualStrings("application/octet-stream", mimeFor("a.unknownext"));
}

test "raw_url from fs/get is directly playable: carries sign and a media content-type" {
    // 回归（2026-10-14 光猫实测两个坑）：
    // ① raw_url 不带 `?sign=` → 前端播放器直接用它，sign_all 部署下必 401；
    //    Go 的 `GenerateDownProxyURL`（proxy.go:31-33）生成 /p 链接时是带 sign 的。
    // ② Content-Type 回落 octet-stream → 浏览器 `<audio>` 报 "no supported source"。
    // 这条测试把"fs/get 返回的 raw_url 无凭据即可取回且类型可播"整个链路钉死。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fe = try frontend_mod.initFromHtml(a, .{}, "");
    defer fe.deinit();
    var app = routingApp(a, fe);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "song one.mp3", .data = "0123456789abcdef" });
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var local_drv = @import("drivers/local.zig").Local{
        .alloc = a,
        .cfg = .{ .root_folder = root },
    };
    const mounts = try a.alloc(Mount, 1);
    mounts[0] = .{
        .storage = .{ .id = 1, .mount_path = "/local", .driver = "Local", .addition = "{}" },
        .driver = driver.asDriver(@import("drivers/local.zig").Local, &local_drv),
        .mount_path = "/local",
        .label = "Local",
    };
    app.publishMounts(mounts);

    // sign_all=true 的独立 config（与本文件其他 sign 测试同模式）。
    // ⚠️ `prev` 必须在 `config.load` **之前**取：load 自己就会把单例指到新对象，
    // 在 load 之后取 prev 等于把单例还原成已 deinit 的对象，后面的测试必 segfault。
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{root});
    defer testing.allocator.free(cfg_path);
    const prev = config.getOpt();
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    config.setForTest(tcfg);
    defer config.setForTest(prev);
    tcfg.sign_all = true;
    tcfg.link_expiration = 0;

    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const hdrs = try a.alloc(Header, 1);
    hdrs[0] = .{ .name = "Authorization", .value = try std.fmt.allocPrint(a, "Bearer {s}", .{token}) };

    var req = http.Request{
        .arena = a,
        .method = "POST",
        .path = "/api/fs/get",
        .target = "/api/fs/get",
        .headers = hdrs,
        .body = .{ .memory = "{\"path\":\"/local/song one.mp3\"}" },
    };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(&app, &req, res);
    try testing.expectEqual(@as(u16, 200), res.status);
    const parsed = try json.parse(a, res.buf.slice());
    const data = parsed.getPath("data").?;
    const sign_field = data.getPath("sign").?.asStr().?;
    const raw_url = data.getPath("raw_url").?.asStr().?;

    // ① sign 字段非空且 raw_url 必须带上同一个 sign（前端不再自己拼）。
    try testing.expect(sign_field.len > 0);
    try testing.expect(std.mem.startsWith(u8, raw_url, "/p/local/song%20one.mp3?sign="));
    try testing.expectEqualStrings(sign_field, raw_url["/p/local/song%20one.mp3?sign=".len..]);

    // ② 无凭据 + Range 直接取 raw_url：必须放行且 Content-Type 可播。
    // 服务器收到请求后会把路径 percent-decode（http.zig 的 `url.decode`），
    // 签名也是对**解码后**的路径校验的 —— 所以这里 .path 必须是解码形态。
    const qmark = std.mem.indexOfScalar(u8, raw_url, '?').?;
    var play = http.Request{
        .arena = a,
        .method = "GET",
        .path = "/p/local/song one.mp3",
        .target = "/p/local/song%20one.mp3",
        .query = raw_url[qmark + 1 ..],
        .headers = try a.dupe(Header, &.{.{ .name = "Range", .value = "bytes=0-3" }}),
    };
    const play_res = try a.create(http.Response);
    play_res.* = http.Response.init(a);
    try handle(&app, &play, play_res);
    try testing.expectEqual(@as(u16, 206), play_res.status);
    var ctype: ?[]const u8 = null;
    for (play_res.headers.slice()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) ctype = h.value;
    }
    try testing.expectEqualStrings("audio/mpeg", ctype.?);
}

test "Range parser supports closed, open-ended and suffix forms" {
    const closed = parseRange("bytes=10-19", 100);
    try testing.expect(closed == .valid);
    try testing.expectEqual(@as(u64, 10), closed.valid.start);
    try testing.expectEqual(@as(u64, 19), closed.valid.end);

    const open_ended = parseRange("bytes=90-", 100);
    try testing.expect(open_ended == .valid);
    try testing.expectEqual(@as(u64, 99), open_ended.valid.end);

    const suffix = parseRange("bytes=-10", 100);
    try testing.expect(suffix == .valid);
    try testing.expectEqual(@as(u64, 90), suffix.valid.start);
    try testing.expectEqual(@as(u64, 99), suffix.valid.end);

    try testing.expect(parseRange("bytes=100-", 100) == .unsatisfiable);
    try testing.expect(parseRange("bytes=8-3", 100) == .unsatisfiable);
    try testing.expect(parseRange("bytes=x-y", 100) == .ignore);
    try testing.expect(parseRange("items=0-1", 100) == .ignore);
    try testing.expect(parseRange("bytes=0-1,4-5", 100) == .ignore);
}

test "upload progress callback keeps a percentage in 0..100" {
    var progress = PutProgress{};
    putProgressCb(@ptrCast(&progress), 42);
    try testing.expectEqual(@as(u64, 42), progress.pct);

    // 越界的值必须被丢掉 —— 维度错了（字节 vs 百分比）比没进度更糟。
    putProgressCb(@ptrCast(&progress), 1024);
    try testing.expectEqual(@as(u64, 42), progress.pct);
    putProgressCb(@ptrCast(&progress), 100);
    try testing.expectEqual(@as(u64, 100), progress.pct);
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------
//
// These drive `handle` directly rather than through a socket. The property
// worth pinning down is ordering: the shell and the assets are unauthenticated
// (the login page lives inside the shell), while everything under /api/fs and
// the download prefixes is not. Getting that backwards produces a site that
// serves a login page nobody can load.

const ROUTING_SHELL =
    \\<title>Loading...</title>
    \\<script>window.OPENLIST_CONFIG = { cdn: undefined, base_path: undefined, main_color: undefined }</script>
    \\<!-- customize head -->
    \\<!-- customize body -->
;

fn routingApp(a: std.mem.Allocator, fe: frontend_mod.Frontend) App {
    return .{
        .alloc = a,
        .mounts = &.{},
        .admin_hash = "",
        .admin_user = "admin",
        .admin_pwd_ts = 0,
        .jwt_secret = "s",
        .site_url = "",
        .cdn = "",
        .token_expires_in_hours = 48,
        .frontend = fe,
    };
}

fn doRequest(app: *App, a: std.mem.Allocator, method: []const u8, path: []const u8) !*http.Response {
    var req = http.Request{ .arena = a, .method = method, .path = path, .target = path };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(app, &req, res);
    return res;
}

/// Like `doRequest`, but lets a test set the query string and headers, so one
/// sweep can reach every registered endpoint.
fn doRequestWith(app: *App, a: std.mem.Allocator, method: []const u8, path: []const u8, query: []const u8, headers: []Header) !*http.Response {
    var req = http.Request{ .arena = a, .method = method, .path = path, .query = query, .target = path, .headers = headers };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(app, &req, res);
    return res;
}

test "routing: the shell and the manifest need no token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const home = try doRequest(&app, a, "GET", "/");
    try testing.expectEqual(@as(u16, 200), home.status);
    try testing.expect(std.mem.indexOf(u8, home.buf.slice(), "cdn: ''") != null);

    try testing.expectEqual(@as(u16, 200), (try doRequest(&app, a, "GET", "/manifest.json")).status);

    // GET and POST both reach the shell, so a deep link boots the router.
    try testing.expectEqual(@as(u16, 200), (try doRequest(&app, a, "GET", "/@manage/storage")).status);
    try testing.expectEqual(@as(u16, 200), (try doRequest(&app, a, "POST", "/@manage/storage")).status);
    // Anything else is 405, as upstream.
    try testing.expectEqual(@as(u16, 405), (try doRequest(&app, a, "PUT", "/x")).status);
    try testing.expectEqual(@as(u16, 405), (try doRequest(&app, a, "DELETE", "/x")).status);
}

test "routing: /@manage gets the admin shell, everything else the public one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{ .settings = .{ .customize_head = "<meta name=x>" } }, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const public = (try doRequest(&app, a, "GET", "/")).buf.slice();
    const admin = (try doRequest(&app, a, "GET", "/@manage/storage")).buf.slice();

    try testing.expect(std.mem.indexOf(u8, public, "<meta name=x>") != null);
    try testing.expect(std.mem.indexOf(u8, admin, "<meta name=x>") == null);
    try testing.expect(std.mem.indexOf(u8, admin, "<!-- customize head -->") != null);
}

test "routing: /api/fs and the download prefixes still require a token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    for ([_][]const u8{ "/api/fs/list", "/api/fs/get", "/api/fs/dirs", "/api/fs/put" }) |p| {
        const res = try doRequest(&app, a, "POST", p);
        try testing.expectEqual(@as(u16, 401), res.status);
    }
    try testing.expectEqual(@as(u16, 401), (try doRequest(&app, a, "GET", "/d/a/b")).status);
    try testing.expectEqual(@as(u16, 401), (try doRequest(&app, a, "GET", "/p/a/b")).status);
}

test "routing: /dav now serves WebDAV (auth-gated, OPTIONS open)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    // Without a credential the server answers 401 rather than 501.
    const dav = try doRequest(&app, a, "PROPFIND", "/dav/");
    try testing.expectEqual(@as(u16, 401), dav.status);
    try testing.expectEqual(@as(u16, 401), (try doRequest(&app, a, "GET", "/dav")).status);

    // OPTIONS advertises WebDAV capability without auth.
    const opt = try doRequest(&app, a, "OPTIONS", "/dav");
    try testing.expectEqual(@as(u16, 200), opt.status);
    var dav_hdr: ?[]const u8 = null;
    for (opt.headers.slice()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "DAV")) dav_hdr = h.value;
    }
    try testing.expectEqualStrings("1", dav_hdr.?);

    const typo = try doRequest(&app, a, "GET", "/api/nope");
    try testing.expectEqual(@as(u16, 404), typo.status);
    try testing.expect(std.mem.indexOf(u8, typo.buf.slice(), "\"code\":404") != null);
}

test "routing: assets with no dist_dir answer 404 rather than the shell" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const res = try doRequest(&app, a, "GET", "/assets/a.js");
    try testing.expectEqual(@as(u16, 404), res.status);
    // Explicitly not HTML: a shell here would surface as a MIME error.
    try testing.expect(std.mem.indexOf(u8, res.buf.slice(), "dist_dir") != null);
}

test "routing: a configured CDN redirects assets and keeps the query" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{ .cdn = "https://c.example.com/4.2.6/dist" }, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    var req = http.Request{
        .arena = a,
        .method = "GET",
        .path = "/assets/index-abc123.js",
        .target = "/assets/index-abc123.js?v=9",
    };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(&app, &req, res);

    try testing.expectEqual(@as(u16, 302), res.status);
    var found: ?[]const u8 = null;
    for (res.headers.slice()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Location")) found = h.value;
    }
    try testing.expectEqualStrings("https://c.example.com/4.2.6/dist/assets/index-abc123.js?v=9", found.?);
}

/// Test helper: mint a JWT with the same shape `issueToken` emits, so an
/// admin-route test can pass the auth gate. Lives at file scope because Zig does
/// not allow `fn` declarations inside a `test` block.
/// 测试用：签一个和 `issueToken` 同格式的标准三段 JWT。
fn mintTestToken(a: std.mem.Allocator, secret: []const u8, user: []const u8, pwd_ts: i64) ![]u8 {
    const exp: i64 = 4102444800; // 2100-01-01, comfortably in the future
    const h64 = try b64Url(a, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    var payload = Buf.init(a);
    try payload.append("{\"username\":");
    try json.writeString(&payload, user);
    try payload.print(",\"pwd_ts\":{d},\"exp\":{d}}}", .{ pwd_ts, exp });
    const p64 = try b64Url(a, payload.slice());
    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ h64, p64 });
    const sig = try hmacSha256(a, secret, signing_input);
    const s64 = try b64Url(a, &sig);
    return std.fmt.allocPrint(a, "{s}.{s}", .{ signing_input, s64 });
}

test "local download Range streams only the requested byte window" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(rt.io(), .{ .sub_path = "bytes.txt", .data = "0123456789" });
    const root = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(root);

    var local_drv = @import("drivers/local.zig").Local{
        .alloc = a,
        .cfg = .{ .root_folder = root },
    };
    const mounts = try a.alloc(Mount, 1);
    mounts[0] = .{
        .storage = .{ .id = 1, .mount_path = "/local", .driver = "Local", .addition = "{}" },
        .driver = driver.asDriver(@import("drivers/local.zig").Local, &local_drv),
        .mount_path = "/local",
        .label = "Local",
    };
    app.mounts = mounts;

    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    const range_headers = try a.alloc(Header, 2);
    range_headers[0] = .{ .name = "Authorization", .value = auth };
    range_headers[1] = .{ .name = "Range", .value = "bytes=2-5" };
    var req = http.Request{ .arena = a, .method = "GET", .path = "/d/local/bytes.txt", .target = "/d/local/bytes.txt", .headers = range_headers };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(&app, &req, res);
    try testing.expectEqual(@as(u16, 206), res.status);
    try testing.expectEqual(@as(u64, 4), res.stream.?.len.?);

    var buf: [8]u8 = undefined;
    const n = try res.stream.?.read(res.stream.?.ctx, &buf);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualStrings("2345", buf[0..n]);
    res.stream.?.cleanup.?(res.stream.?.ctx);

    range_headers[1].value = "bytes=10-";
    var bad_req = http.Request{ .arena = a, .method = "GET", .path = "/d/local/bytes.txt", .target = "/d/local/bytes.txt", .headers = range_headers };
    const bad_res = try a.create(http.Response);
    bad_res.* = http.Response.init(a);
    try handle(&app, &bad_req, bad_res);
    try testing.expectEqual(@as(u16, 416), bad_res.status);
    var unsatisfied: ?[]const u8 = null;
    for (bad_res.headers.slice()) |h| if (std.ascii.eqlIgnoreCase(h.name, "Content-Range")) {
        unsatisfied = h.value;
    };
    try testing.expectEqualStrings("bytes */10", unsatisfied.?);
}

test "routing: authed admin endpoints return data, unauthed is 401" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    // Mint a token with the same secret/shape `issueToken` uses, so the auth
    // gate in `handleAuthed` accepts it.
    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    const hdrs = try a.alloc(Header, 1);
    hdrs[0] = .{ .name = "Authorization", .value = auth };

    // /api/me
    {
        var req = http.Request{ .arena = a, .method = "GET", .path = "/api/me", .target = "/api/me", .headers = hdrs };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(std.mem.indexOf(u8, res.buf.slice(), app.admin_user) != null);
    }

    // /api/admin/storage — empty mounts => total 0, content []
    {
        var req = http.Request{ .arena = a, .method = "GET", .path = "/api/admin/storage", .target = "/api/admin/storage", .headers = hdrs };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = res.buf.slice();
        try testing.expect(std.mem.indexOf(u8, body, "\"total\":0") != null);
        try testing.expect(std.mem.indexOf(u8, body, "\"content\":[]") != null);
    }

    // /api/admin/driver/list — the compiled-in drivers
    {
        var req = http.Request{ .arena = a, .method = "GET", .path = "/api/admin/driver/list", .target = "/api/admin/driver/list", .headers = hdrs };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = res.buf.slice();
        try testing.expect(std.mem.indexOf(u8, body, "Local") != null);
        // 驱动名必须与 Go `driver.Config.Name` 一致 —— itvsh 的 Go 名是
        // 「上海电信智家硬盘」（drivers/itvsh/meta.go:34），配置里存的就是它。
        try testing.expect(std.mem.indexOf(u8, body, "上海电信智家硬盘") != null);
    }

    // Task centre knows these categories but accurately reports no active or
    // completed background jobs in this no-queue build.
    {
        var req = http.Request{ .arena = a, .method = "GET", .path = "/api/task/upload/undone", .target = "/api/task/upload/undone", .headers = hdrs };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(std.mem.indexOf(u8, res.buf.slice(), "\"data\":[]") != null);
    }

    // No token => 401
    {
        var req = http.Request{ .arena = a, .method = "GET", .path = "/api/me", .target = "/api/me" };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 401), res.status);
    }
}

test "public settings body is strict JSON (regression: stray closing brace)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    var req = http.Request{ .arena = a, .method = "GET", .path = "/api/public/settings", .target = "/api/public/settings" };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(&app, &req, res);
    try testing.expectEqual(@as(u16, 200), res.status);

    // 回归：收尾的 `append("}}}")` 是笔误。`append` 写**原始字节**，不做 `print`
    // 那样的 `{{`/`}}` 转义，于是 body 末尾多出一个 `}`（337 字节里只有前 336 是
    // 合法 JSON）。后果不是 500，而是前端静默出错：axios 的 `JSON.parse` 抛错后
    // 被 `silentJSONParsing` 降级成字符串，`e.code === 200` 永远为假，首页直接
    // 显示「获取设置失败： Undefined」。`json.parse` 对尾随内容报 `InvalidSyntax`，
    // 正好把这个 bug 钉死。
    const body = res.buf.slice();
    const parsed = try json.parse(a, body);
    try testing.expectEqual(@as(i64, 200), parsed.getPath("code").?.asInt().?);
    switch (parsed.getPath("data").?.*) {
        .object => {},
        else => return error.TestUnexpectedResult,
    }
}

test "every JSON endpoint emits strict, parseable JSON" {
    // 系统性补丁：本工程的 API 响应是**手拼字符串**（不像 Go 版走 struct/map
    // 序列化），一处括号写错就产出非法 JSON；而 axios 会把 `JSON.parse` 的失败
    // 静默降级成字符串，前端于是只报一句毫无线索的「获取设置失败： Undefined」。
    // 这里把**所有**已注册的 JSON 端点跑一遍，逐个用严格解析器校验（`json.parse`
    // 对尾随内容报 InvalidSyntax，正是它抓出了 public/settings 多出的那个 '}'）。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    // /api/admin/setting* 会读 config 单例；测试里没 load 过就直接 panic。
    // 按 sign 测试的做法 load 一份临时配置再注入，退出时还原进入前的单例。
    // 注意 `config.load` **自己就会**把单例指到新对象，所以必须在 load 之前
    // 取 `prev`，否则还原的是新对象、`deinit` 之后单例悬空，后面读 config 的
    // 测试会 segfault。
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg_dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(cfg_dir);
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{cfg_dir});
    defer testing.allocator.free(cfg_path);
    const prev_cfg = config.getOpt();
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    config.setForTest(tcfg);
    defer config.setForTest(prev_cfg);

    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    const hdrs = try a.alloc(Header, 1);
    hdrs[0] = .{ .name = "Authorization", .value = auth };

    // 1) 公共 GET
    for ([_][]const u8{
        "/api/public/settings",
        "/api/public/archive_extensions",
    }) |p| {
        const res = try doRequest(&app, a, "GET", p);
        try testing.expectEqual(@as(u16, 200), res.status);
        _ = try json.parse(a, res.buf.slice());
    }
    {
        const res = try doRequestWith(&app, a, "GET", "/api/public/offline_download_tools", "path=%2F", &.{});
        try testing.expectEqual(@as(u16, 200), res.status);
        _ = try json.parse(a, res.buf.slice());
    }

    // 2) 认证 GET
    for ([_][]const u8{
        "/api/me",
        "/api/admin/storage",
        "/api/admin/storage/list",
        "/api/admin/driver/names",
        "/api/admin/driver/list",
        "/api/admin/setting",
        "/api/admin/setting/list",
        "/api/admin/setting/default",
        "/api/task/upload/undone",
        "/api/task/upload/done",
        "/api/task/copy/undone",
        "/api/task/copy/done",
        "/api/task/move/undone",
        "/api/task/offline_download/undone",
    }) |p| {
        const res = try doRequestWith(&app, a, "GET", p, "", hdrs);
        try testing.expectEqual(@as(u16, 200), res.status);
        _ = try json.parse(a, res.buf.slice());
    }

    // 3) setting/get 与 setting/list 都走 query 参数。`group=0` 在 Go
    // `handles.ListSettings` 中是有效筛选值；本构建当前没有 group 0 的配置项，
    // 因而应得到合法的空数组，而不是 404 或忽略筛选。
    {
        const res = try doRequestWith(&app, a, "GET", "/api/admin/setting/get", "key=site_title", hdrs);
        try testing.expectEqual(@as(u16, 200), res.status);
        _ = try json.parse(a, res.buf.slice());
    }
    {
        const res = try doRequestWith(&app, a, "GET", "/api/admin/setting/list", "group=0", hdrs);
        try testing.expectEqual(@as(u16, 200), res.status);
        const parsed = try json.parse(a, res.buf.slice());
        const items = parsed.getPath("data").?.asArray().?;
        try testing.expectEqual(@as(usize, 0), items.len);
    }

    // 4) 认证 POST（空 body ⇒ 空对象 ⇒ 无挂载 ⇒ JSON 错误包，也必须是合法 JSON）
    for ([_][]const u8{
        "/api/fs/list",
        "/api/fs/get",
        "/api/fs/dirs",
        "/api/fs/mkdir",
        "/api/fs/rename",
        "/api/fs/move",
        "/api/fs/copy",
        "/api/fs/remove",
        "/api/fs/put",
        "/api/fs/archive/list",
    }) |p| {
        const res = try doRequestWith(&app, a, "POST", p, "", hdrs);
        _ = try json.parse(a, res.buf.slice());
    }

    // 5) 未注册的 /api/* ⇒ JSON 404
    {
        const res = try doRequest(&app, a, "GET", "/api/nope");
        try testing.expectEqual(@as(u16, 404), res.status);
        _ = try json.parse(a, res.buf.slice());
    }
}

test "public settings carries the keys the frontend actually reads" {
    // 回归：曾经只返回 10 个自造字段（initial_done / api / cdn / token_expires_in …），
    // 前端真正读的键一个都没有 —— 表现就是首页 logo 拿到空串、`<img src="">`。
    // 这里把前端代码实际引用的键逐个钉住（清单来自 4.2.6 的 dist：把每个
    // `(\`key\`)` 取值点扫出来），并强制值必须是字符串。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const res = try doRequest(&app, a, "GET", "/api/public/settings");
    try testing.expectEqual(@as(u16, 200), res.status);
    const parsed = try json.parse(a, res.buf.slice());
    const data = parsed.getPath("data").?.object;

    const required = [_][]const u8{
        "version",              "site_title",             "announcement",
        "pagination_type",      "logo",                   "favicon",
        "main_color",           "home_icon",              "share_icon",
        "home_container",       "settings_layout",        "show_disk_usage_in_plain_text",
        "audio_cover",          "audio_autoplay",         "video_autoplay",
        "preview_download_by_default", "preview_archives_by_default",
        "share_preview_download_by_default", "share_preview_archives_by_default",
        "readme_autorender",    "filter_readme_scripts",  "hide_files",
        "package_download",     "share_preview",          "share_archive_preview",
        "share_summary_content", "search_index",          "sso_login_enabled",
        "sso_login_platform",   "sso_compatibility_mode", "ldap_login_enabled",
        "ldap_login_tips",      "multipart_enabled",
    };
    for (required) |k| {
        const v = data.get(k) orelse return error.MissingPublicSettingKey;
        switch (v.*) {
            .string => {},
            // Go 侧是 `map[string]string`；前端按字符串判布尔/数字
            // （`t === 'true'`、`Number(t)`），给原生 bool/int 会静默判错。
            else => return error.PublicSettingValueMustBeString,
        }
    }

    // logo 尤其不能为空 —— 空串渲染出来就是 `<img src="">`。
    try testing.expect(data.get("logo").?.asStr().?.len > 0);
    try testing.expect(data.get("site_title").?.asStr().?.len > 0);
}

test "fs list carries the envelope fields the frontend reads" {
    // 回归：`readme`/`header`/`write`/`write_content_bypass`/`provider` 少一个，
    // 前端 `setWrite(undefined)` 就会把目录判成只读 —— 上传/新建按钮整片消失。
    // （测试环境无挂载，"/" 走 `listRoot`，信封字段与挂载目录完全一致。）
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    const hdrs = try a.alloc(Header, 1);
    hdrs[0] = .{ .name = "Authorization", .value = auth };

    const res = try doRequestWith(&app, a, "POST", "/api/fs/list", "", hdrs);
    try testing.expectEqual(@as(u16, 200), res.status);
    const parsed = try json.parse(a, res.buf.slice());
    const data = parsed.getPath("data").?.object;
    for ([_][]const u8{
        "content", "total", "readme", "header",
        "write",   "write_content_bypass", "provider",
    }) |k| {
        if (data.get(k) == null) return error.MissingFsListField;
    }
    // 单管理员构建 ⇒ 目录可写，前端据此显示上传/新建。
    try testing.expect(data.get("write").?.asBool() != null and data.get("write").?.asBool().?);
}

test "init_status drives the first-run wizard and init/setup creates the admin" {
    // 回归：`/api/public/init_status` 缺失时前端**永远**不跳 `/@init` ——
    // App.tsx 里这个请求的失败回调被注释掉了（静默吞错），`initialized` 保持
    // 默认 true，用户看不到任何注册入口，只能拿已有账号登录。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    // init/setup 会写 config 单例；`prev` 必须在 load **之前**取
    // （`config.load` 自己就会把单例指过去）。
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const cfg_dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(cfg_dir);
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{cfg_dir});
    defer testing.allocator.free(cfg_path);
    const prev_cfg = config.getOpt();
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    config.setForTest(tcfg);
    defer config.setForTest(prev_cfg);

    // 1) 未初始化（admin_hash 为空）⇒ initialized:false
    {
        const res = try doRequest(&app, a, "GET", "/api/public/init_status");
        try testing.expectEqual(@as(u16, 200), res.status);
        const parsed = try json.parse(a, res.buf.slice());
        try testing.expectEqual(false, parsed.getPath("data.initialized").?.asBool().?);
    }

    // 2) init/setup 建管理员（Go 侧密码下限是 4）
    {
        var req = http.Request{
            .arena = a,
            .method = "POST",
            .path = "/api/public/init/setup",
            .target = "/api/public/init/setup",
            .body = .{ .memory = "{\"username\":\"admin\",\"password\":\"test-pw-1234\",\"site_title\":\"Zig Site\"}" },
        };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 200), res.status);
        try testing.expect(app.admin_hash.len > 0);
        try testing.expectEqualStrings("admin", app.admin_user);
    }

    // 3) 已初始化后再调 ⇒ 400（Go：`system has already been initialized`）
    {
        var req = http.Request{
            .arena = a,
            .method = "POST",
            .path = "/api/public/init/setup",
            .target = "/api/public/init/setup",
            .body = .{ .memory = "{\"username\":\"x\",\"password\":\"1234\"}" },
        };
        const res = try a.create(http.Response);
        res.* = http.Response.init(a);
        try handle(&app, &req, res);
        try testing.expectEqual(@as(u16, 400), res.status);
    }

    // 4) 现在 init_status 应报 initialized:true
    {
        const res = try doRequest(&app, a, "GET", "/api/public/init_status");
        const parsed = try json.parse(a, res.buf.slice());
        try testing.expectEqual(true, parsed.getPath("data.initialized").?.asBool().?);
    }
}

test "login/hash accepts the static hash the frontend actually sends" {
    // 回归：前端登录页 POST 的是 `/api/auth/login/hash`（server/router.go:75），
    // body 里的 password 是 `StaticHash(明文)`。这个端点曾经缺失 ⇒ 前端恒登不上，
    // 而 curl 直接打 `/auth/login` 却是通的 —— 「curl 通过」不等于「前端能登录」。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    // 造一个与 Go 同形的管理员：salt + `TwoHashPwd`。
    const salt = "abcdefghijklmnop";
    app.admin_user = "admin";
    app.admin_salt = salt;
    app.admin_hash = try twoHashPwd(a, "hunter2", salt);

    const post = struct {
        fn call(app_: *App, a_: std.mem.Allocator, path: []const u8, body: []const u8) !*http.Response {
            var req = http.Request{ .arena = a_, .method = "POST", .path = path, .target = path, .body = .{ .memory = body } };
            const res = try a_.create(http.Response);
            res.* = http.Response.init(a_);
            try handle(app_, &req, res);
            return res;
        }
    }.call;

    // 1) 前端路径：发 StaticHash，必须换到 token
    const static = try staticHash(a, "hunter2");
    const body_hash = try std.fmt.allocPrint(a, "{{\"username\":\"admin\",\"password\":\"{s}\",\"otp_code\":\"\"}}", .{static});
    const res_hash = try post(&app, a, "/api/auth/login/hash", body_hash);
    try testing.expectEqual(@as(u16, 200), res_hash.status);
    try testing.expect((try json.parse(a, res_hash.buf.slice())).getPath("data.token") != null);

    // 2) 明文接口（Go 的 `ValidatePwd` 会先做一次 StaticHash）
    const res_plain = try post(&app, a, "/api/auth/login", "{\"username\":\"admin\",\"password\":\"hunter2\"}");
    try testing.expectEqual(@as(u16, 200), res_plain.status);

    // 3) 错口令 / 错用户名必须 400
    try testing.expectEqual(@as(u16, 400), (try post(&app, a, "/api/auth/login", "{\"username\":\"admin\",\"password\":\"nope\"}")).status);
    try testing.expectEqual(@as(u16, 400), (try post(&app, a, "/api/auth/login/hash", "{\"username\":\"root\",\"password\":\"x\"}")).status);
}

test "fs/get / returns the virtual root like Go" {
    // 回归：Go `internal/fs/get.go:25-30` 对 `/` 返回虚拟根对象而不是报错。
    // 前端 Layout 进首页第一个请求就是 `fs/get /`；此前我们回 404
    // "storage not found"，首页直接显示 404（管理后台走 storage/list 所以正常）。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try frontend_mod.initFromHtml(a, .{}, ROUTING_SHELL);
    defer fe.deinit();
    var app = routingApp(a, fe);

    const token = try mintTestToken(a, app.jwt_secret, app.admin_user, app.admin_pwd_ts);
    const auth = try std.fmt.allocPrint(a, "Bearer {s}", .{token});
    const hdrs = try a.alloc(Header, 1);
    hdrs[0] = .{ .name = "Authorization", .value = auth };

    // `doRequestWith` 的第 5 参是 **query** 不是 body，所以这里直接构造 Request
    // （带 JSON body）—— 之前把 body 塞进了 query，fs/get 收到空 body 直接 return，
    // 响应体为空，测试在 getPath 处 null panic。
    var req = http.Request{
        .arena = a,
        .method = "POST",
        .path = "/api/fs/get",
        .target = "/api/fs/get",
        .headers = hdrs,
        .body = .{ .memory = "{\"path\":\"/\"}" },
    };
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(&app, &req, res);
    try testing.expectEqual(@as(u16, 200), res.status);
    const parsed = try json.parse(a, res.buf.slice());
    try testing.expectEqualStrings("root", parsed.getPath("data.name").?.asStr().?);
    try testing.expectEqual(true, parsed.getPath("data.is_dir").?.asBool().?);
    try testing.expectEqualStrings("", parsed.getPath("data.provider").?.asStr().?);
}

test "ctEqual rejects mismatched lengths without narrowing the difference" {
    // A02 回归：旧实现在长度不等时执行 `@intCast(a.len ^ b.len)`，把一个
    // usize 窄化成 u8。长度差超过 255（这里 600^32 = 632）时安全构建 panic、
    // small 构建静默截断 —— 畸形签名长度会变成“要么崩进程、要么不可信”的
    // 路径。现在长度差用 usize 自己的宽度参与累积，只返回 false。
    const long = try testing.allocator.alloc(u8, 600);
    defer testing.allocator.free(long);
    @memset(long, 'a');
    const expected = try testing.allocator.alloc(u8, 32);
    defer testing.allocator.free(expected);
    @memset(expected, 'a');

    // 600 vs 32：差 632，旧代码会 panic/截断
    try testing.expect(!ctEqual(long, expected));
    // 反过来也一样
    try testing.expect(!ctEqual(expected, long));
    // 长度相同但内容不同仍然 false
    var other = try testing.allocator.dupe(u8, expected);
    defer testing.allocator.free(other);
    other[0] ^= 0xff;
    try testing.expect(!ctEqual(other, expected));
    // 长度内容都相同才是 true
    try testing.expect(ctEqual(expected, expected));
}

/// 测试辅助：带 Authorization 头调一次 checkAuth。
fn authWith(a: std.mem.Allocator, app: *App, token: []const u8) !bool {
    const hdrs = try a.dupe(Header, &.{.{
        .name = "Authorization",
        .value = try std.fmt.allocPrint(a, "Bearer {s}", .{token}),
    }});
    var req = http.Request{
        .arena = a,
        .method = "GET",
        .path = "/api/me",
        .target = "/api/me",
        .headers = hdrs,
    };
    return checkAuth(app, &req);
}

test "tokens are standard three-part JWTs bound to the password version" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var app = App{
        .alloc = a,
        .mounts = &.{},
        .admin_hash = "x",
        .admin_user = "admin",
        .admin_pwd_ts = 1000,
        .jwt_secret = "s3cret",
        .site_url = "",
        .cdn = "",
        .token_expires_in_hours = 1,
        .frontend = undefined,
    };

    const token = try mintTestToken(a, app.jwt_secret, "admin", 1000);

    // A04：必须是**三段**标准 JWT，头部是 {"alg":"HS256","typ":"JWT"}。
    // 以前是私有两段 `payload.signature`，标准 JWT 解析器打不开。
    var parts = std.mem.splitScalar(u8, token, '.');
    const h64 = parts.next().?;
    const p64 = parts.next().?;
    const s64 = parts.next().?;
    try testing.expect(parts.next() == null);

    const hdr = try b64UrlDecode(a, h64);
    try testing.expectEqualStrings("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", hdr);

    // 签名必须覆盖 "header.payload"（JWT 的规定），而不是只覆盖 payload。
    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ h64, p64 });
    const expect_sig = try hmacSha256(a, app.jwt_secret, signing_input);
    const got_sig = try b64UrlDecode(a, s64);
    try testing.expectEqualSlices(u8, &expect_sig, got_sig);

    // 有效令牌通过。
    try testing.expect(try authWith(a, &app, token));

    // A03：口令版本推进（= 改密）后，**已签发**的旧令牌立刻失效。
    app.admin_pwd_ts = 2000;
    try testing.expect(!(try authWith(a, &app, token)));
}

test "tokens are rejected for a different user or a tampered signature" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var app = App{
        .alloc = a,
        .mounts = &.{},
        .admin_hash = "x",
        .admin_user = "admin",
        .admin_pwd_ts = 1000,
        .jwt_secret = "s3cret",
        .site_url = "",
        .cdn = "",
        .token_expires_in_hours = 1,
        .frontend = undefined,
    };

    // 换用户名 → 拒
    try testing.expect(!(try authWith(a, &app, try mintTestToken(a, app.jwt_secret, "root", 1000))));
    // 换口令版本 → 拒
    try testing.expect(!(try authWith(a, &app, try mintTestToken(a, app.jwt_secret, "admin", 999))));

    // 篡改签名（用别的密钥签）→ 拒
    try testing.expect(!(try authWith(a, &app, try mintTestToken(a, "wrong-secret", "admin", 1000))));

    // 结构不对（只有两段）→ 拒
    try testing.expect(!(try authWith(a, &app, "aaaa.bbbb")));
    // 多一段 → 拒
    try testing.expect(!(try authWith(a, &app, "aaaa.bbbb.cccc.dddd")));
}

// ---------------------------------------------------------------------------
// 下载签名（对齐 Go pkg/sign/hmac.go）
// ---------------------------------------------------------------------------

test "sign: Sign matches the Go HMAC format byte for byte" {
    // 期望值由 Python 的 `hmac`+`base64.urlsafe_b64encode` 独立算出
    // （算法逐字抄自 Go pkg/sign/hmac.go），不是拿本实现的输出当基准。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const secret = "test-jwt-secret-1234567890";

    try testing.expectEqualStrings(
        "m2Ujh34JCH5bNVHL36HjwKmbmg1HKeQZ8fEViuD4xlA=:0",
        try signValue(a, secret, "/local/a.txt", 0),
    );
    try testing.expectEqualStrings(
        "3o7DsCxwWhzlnSDZRENsu9rfNU38tdVFhu84CULfHPc=:0",
        try signValue(a, secret, "/itvsh/dir/f.bin", 0),
    );
    // 未来与过去的时间戳都只是字符串的一部分，签名本身都能算出来。
    const future = try signValue(a, secret, "/local/a.txt", 4102444800);
    try testing.expect(std.mem.endsWith(u8, future, ":4102444800"));
}

test "sign: verifySign accepts a valid signature and rejects tampering" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var app = routingApp(a, try frontend_mod.initFromHtml(a, .{}, ""));

    const good = try signValue(a, app.jwt_secret, "/local/a.txt", 0);
    try verifySign(&app, a, "/local/a.txt", good);

    // 路径被改一个字节 → ErrSignInvalid。
    try testing.expectError(SignError.SignInvalid, verifySign(&app, a, "/local/b.txt", good));
    // secret 不对 → 同样 ErrSignInvalid。
    try testing.expectError(SignError.SignInvalid, verifySign(&app, a, "/local/a.txt", try signValue(a, "other", "/local/a.txt", 0)));
}

test "sign: verifySign reports Go's four expiry errors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var app = routingApp(a, try frontend_mod.initFromHtml(a, .{}, ""));

    // 没有 ':' → ErrExpireMissing（Go 的 sign[LastIndex+1:] 为空）。
    try testing.expectError(SignError.ExpireMissing, verifySign(&app, a, "/x", "no-colon-here"));
    // ':' 在末尾 → 空 exp 串 → 同样 ErrExpireMissing。
    try testing.expectError(SignError.ExpireMissing, verifySign(&app, a, "/x", "abc:"));
    // exp 不是数字 → ErrExpireInvalid。
    try testing.expectError(SignError.ExpireInvalid, verifySign(&app, a, "/x", "abc:notanumber"));
    // exp 已过期（非 0）→ ErrSignExpired。
    try testing.expectError(SignError.SignExpired, verifySign(&app, a, "/x", try signValue(a, app.jwt_secret, "/x", 1000000000)));
    // exp == 0 表示永不过期：远古时间戳也要能过。
    try verifySign(&app, a, "/x", try signValue(a, app.jwt_secret, "/x", 0));
}

test "sign: fs/get and fs/list fill a usable sign when sign_all is on" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fe = try frontend_mod.initFromHtml(a, .{}, "");
    defer fe.deinit();
    var app = routingApp(a, fe);

    // sign_all 默认 false：目录与文件都不签。
    try testing.expectEqualStrings("", try signForObj(&app, a, false, "/local/a.txt"));
    try testing.expectEqualStrings("", try signForObj(&app, a, true, "/local/dir"));

    // 打开开关。config 单例在测试里没有 load 过（可能是 null，也可能被别的
    // 测试 deinit 成悬空指针），所以 load 一份临时配置再注入。
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(dir);
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{dir});
    defer testing.allocator.free(cfg_path);
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    // 恢复**进入前的**单例，而不是设 null —— 后面的测试（local download 等）
    // 仍要读 config，设 null 会让它们 panic。
    const prev = config.getOpt();
    config.setForTest(tcfg);
    defer config.setForTest(prev);
    tcfg.sign_all = true;
    tcfg.link_expiration = 0;

    const s = try signForObj(&app, a, false, "/local/a.txt");
    try testing.expect(s.len > 0);
    try testing.expect(std.mem.endsWith(u8, s, ":0")); // link_expiration=0 → 不过期
    // 目录永远不签（Go common.Sign 的 obj.IsDir() 分支）。
    try testing.expectEqualStrings("", try signForObj(&app, a, true, "/local/dir"));
    // 签出来的东西必须能验过 —— 否则前端拼上去也打不开。
    try verifySign(&app, a, "/local/a.txt", s);
}

test "sign: /d/ rejects a bad sign and accepts a good one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fe = try frontend_mod.initFromHtml(a, .{}, "");
    defer fe.deinit();
    var app = routingApp(a, fe);
    // 独立 config：sign_all=true，不让测试依赖全局单例的状态。
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(dir);
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{dir});
    defer testing.allocator.free(cfg_path);
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    const prev = config.getOpt();
    config.setForTest(tcfg);
    defer config.setForTest(prev);
    tcfg.sign_all = true;

    const good = try signValue(a, app.jwt_secret, "/local/a.txt", 0);
    const mk = struct {
        fn f(al: std.mem.Allocator, q: []const u8) http.Request {
            const hdrs = al.dupe(Header, &.{}) catch unreachable;
            return http.Request{
                .arena = al,
                .method = "GET",
                .path = "/d/local/a.txt",
                .target = "/d/local/a.txt",
                .headers = hdrs,
                .query = if (q.len == 0) "" else q,
            };
        }
    }.f;

    var req_good = mk(a, try std.fmt.allocPrint(a, "sign={s}", .{good}));
    try testing.expect(try downloadAuthorized(&app, &req_good, "/local/a.txt"));
    var req_bad = mk(a, "sign=tampered");
    try testing.expect(!try downloadAuthorized(&app, &req_bad, "/local/a.txt"));
    var req_other = mk(a, try std.fmt.allocPrint(a, "sign={s}", .{try signValue(a, app.jwt_secret, "/local/other.txt", 0)}));
    try testing.expect(!try downloadAuthorized(&app, &req_other, "/local/a.txt"));
    var req_none = mk(a, "");
    try testing.expect(!try downloadAuthorized(&app, &req_none, "/local/a.txt"));
}

test "sign: /d/ is reachable without a token when the sign is valid" {
    // 回归：曾经 `/d/` 挂在 `handleAuthed` 下，而它开头就是 `checkAuth` ——
    // 只带 `?sign=`（没有 Authorization 头）的请求会在进到签名校验前就被
    // 401 拦掉，sign 体系形同虚设。这里走完整路由 `handle()` 钉住修复。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fe = try frontend_mod.initFromHtml(a, .{}, "");
    defer fe.deinit();
    var app = routingApp(a, fe);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(dir);
    const cfg_path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{dir});
    defer testing.allocator.free(cfg_path);
    const tcfg = try config.load(testing.allocator, cfg_path);
    defer tcfg.deinit();
    const prev = config.getOpt();
    config.setForTest(tcfg);
    defer config.setForTest(prev);
    tcfg.sign_all = true;

    // 造一个带 sign 的 /d/ 请求（无任何 Authorization 头）。
    const good = try signValue(a, app.jwt_secret, "/local/a.txt", 0);
    const qs = try std.fmt.allocPrint(a, "sign={s}", .{good});
    const hdrs = try a.dupe(Header, &.{});
    var req = http.Request{
        .arena = a,
        .method = "GET",
        .path = "/d/local/a.txt",
        .target = "/d/local/a.txt",
        .headers = hdrs,
        .query = qs,
    };
    // 路由层的判据：合法 sign 时**不会**在鉴权阶段就被拒。本测试没有真实
    // 存储，所以 resolve 会走到 404 —— 那说明鉴权确实放行了。
    const res = try doRequestRaw(&app, a, &req);
    try testing.expectEqual(@as(u16, 404), res.status);

    // 对照：没有 sign 也没有 token → 401（鉴权层拦截）。
    var req2 = http.Request{
        .arena = a,
        .method = "GET",
        .path = "/d/local/a.txt",
        .target = "/d/local/a.txt",
        .headers = try a.dupe(Header, &.{}),
        .query = "",
    };
    const res2 = try doRequestRaw(&app, a, &req2);
    try testing.expectEqual(@as(u16, 401), res2.status);
}

/// 直接驱动 `handle()`（含路由分发），返回响应。
fn doRequestRaw(app: *App, a: std.mem.Allocator, req: *http.Request) !*http.Response {
    const res = try a.create(http.Response);
    res.* = http.Response.init(a);
    try handle(app, req, res);
    return res;
}
