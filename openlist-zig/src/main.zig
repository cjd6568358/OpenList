//! Entry point.
//!
//! Deliberately small: parse args, load config, construct one driver per
//! configured storage, start the listener, wait. Everything interesting lives
//! in the modules it calls.
//!
//! Command line (a superset of what the Go build accepts, so the same
//! supervisor script works):
//!   -c, --config <path>   config file (default: data/config.json)
//!   --data <dir>          shorthand for --config <dir>/config.json
//!   --port <n>            override scheme.http_port
//!   --log-level <level>   debug | info | warn | error | off
//!   --version             print the version and exit

const std = @import("std");
const builtin = @import("builtin");

const config = @import("config.zig");
const driver = @import("driver.zig");
const log = @import("log.zig");
const http = @import("http.zig");
const api = @import("api.zig");
const client = @import("client.zig");
const cookiejar = @import("cookiejar.zig");
const model = @import("model.zig");
const json = @import("util/json.zig");
const hashmod = @import("util/hash.zig");
const urlmod = @import("util/url.zig");
const Buf = @import("util/buf.zig").Buf;
const List = @import("util/buf.zig").List;
const rt = @import("rt.zig");

pub const version = "0.1.0-zig";

/// `openlist admin [random | set <pwd> | token]` —— 对齐 Go `cmd/admin.go`
/// （官方 FAQ「忘记密码怎么办」给的就是这两个命令）。无参数等价于 Go 的
/// `openlist admin`：只打印账号信息与提示。
const AdminCmd = union(enum) {
    info,
    random,
    set: []const u8,
    token,
};

const Options = struct {
    config_path: []const u8 = "data/config.json",
    port_override: ?u16 = null,
    log_level: ?log.Level = null,
    /// 非 null 时走管理命令分支，**不**启动 HTTP 服务（对齐 Go 的 CLI 子命令）。
    admin: ?AdminCmd = null,
};

/// 0.17 changed the entry point: instead of a zero-argument `main` plus global
/// accessors, the startup code hands over a `std.process.Init` carrying the
/// process's allocator, its `Io` backend, the environment and the arguments.
///
/// That replaces three things this file used to do by hand:
///   * `std.heap.GeneralPurposeAllocator` — `Init.gpa` is already a
///     thread-safe general purpose allocator (with leak checking under Debug),
///     which is what the one-thread-per-connection server needs. The old type
///     is now called `std.heap.DebugAllocator` anyway.
///   * `std.process.getEnvVarOwned` — the environment is pre-parsed into
///     `Init.environ_map`.
///   * `std.process.argsWithAllocator` — the argv is in `Init.minimal.args`.
pub fn main(init: std.process.Init) !void {
    // Park the process-wide handles first: every filesystem and network call in
    // this codebase reads the `Io` backend from here (see src/rt.zig for why
    // it is not threaded through every signature).
    rt.set(init.io, init.gpa);
    const gpa = init.gpa;

    const opts = parseArgs(init) catch |e| {
        std.debug.print("bad arguments: {s}\n", .{@errorName(e)});
        return e;
    };

    // 管理命令（`openlist admin …`）：只读写 config.json，**不**起 HTTP 服务。
    // 对齐 Go `cmd/admin.go` —— 它也是 bootstrap.Init() 后直接改库再退出。
    if (opts.admin) |act| {
        const acfg = config.load(gpa, opts.config_path) catch |e| {
            std.debug.print("cannot load config {s}: {s}\n", .{ opts.config_path, @errorName(e) });
            return e;
        };
        defer acfg.deinit();
        return runAdmin(acfg, gpa, act);
    }

    const cfg = config.load(gpa, opts.config_path) catch |e| {
        std.debug.print("cannot load config {s}: {s}\n", .{ opts.config_path, @errorName(e) });
        return e;
    };

    // 对齐 Go `internal/bootstrap/data/user.go:initAdmin`：无管理员时**只有**
    // 设了 `OPENLIST_ADMIN_PASSWORD` 才自动创建 `admin`，否则保持未初始化、
    // 交给 Web 安装向导（`POST /api/public/init/setup`）。
    initAdminFromEnv(init, cfg) catch |e| {
        std.debug.print("cannot initialise admin from OPENLIST_ADMIN_PASSWORD: {s}\n", .{@errorName(e)});
        return e;
    };
    ensureToken(cfg) catch |e| {
        std.debug.print("cannot persist admin token: {s}\n", .{@errorName(e)});
        return e;
    };

    log.setLevel(opts.log_level orelse blk: {
        // config.json has no log-level field in the Go build either; honour
        // OPENLIST_LOG_LEVEL so the supervisor can turn debug on without a
        // rebuild, then fall back to info. The map borrows the environment, so
        // there is nothing to free.
        const env = init.environ_map.get("OPENLIST_LOG_LEVEL") orelse break :blk log.Level.info;
        break :blk log.Level.parse(env);
    });

    log.info("OpenList (zig) {s} — built with Zig {s}, target {s}", .{
        version,
        builtin.zig_version_string,
        @tagName(builtin.os.tag),
    });

    // Let drivers write their own `addition` back to config.json. itvsh needs
    // this for session cookies and the per-user forwardUrl.
    driver.persist_hook = persistStorage;

    var app = try api.App.init(gpa);
    // Strm 驱动要回调本实例其他挂载（Go 直接调 internal/fs）—— 装上桥接。
    app.installFsBridge();
    // The frontend arena is the one large allocation worth accounting for; the
    // rest of `App` is process-lifetime.
    defer app.deinit();

    // T3 / T6：驱动名归一（别名 → Go 名）在**主线程、任何请求出现之前**完成。
    // 纯字符串操作、零网络 —— `syncStorages` 保存配置时要读 `s.driver`，
    // 后台初始化线程改它就是数据竞争，所以这一步绝不能进后台线程。
    normalizeDriverNames(cfg);

    switch (app.frontend.source) {
        .cdn => log.info("frontend: shell from CDN {s}", .{app.frontend.site.cdn}),
        .dist_dir => log.info("frontend: shell and assets from {s}", .{cfg.dist_dir}),
        .builtin => log.warn(
            "frontend: serving the built-in placeholder page — set \"dist_dir\" to an OpenList frontend build, or \"cdn\", for the real UI",
            .{},
        ),
    }
    if (app.frontend.source == .cdn) {
        log.info("frontend: /assets /images /streamer /static redirect to {s}", .{app.frontend.site.cdn});
    } else if (!app.frontend.has_dist) {
        log.warn("frontend: asset requests will 404 (no dist_dir, no cdn)", .{});
    }

    const port: u16 = opts.port_override orelse @intCast(@max(cfg.http_port, 0));
    const spool_dir = if (cfg.temp_dir.len > 0) cfg.temp_dir else "data/temp";

    var server = try http.Server.init(gpa, .{
        .address = cfg.address,
        .port = port,
        .spool_dir = spool_dir,
        .max_body_memory = 4 * 1024 * 1024,
        // 设备上正文是落盘的，8 GiB 远超可写分区；但仍要允许大文件上传，
        // 所以保持较大上限，改由 `max_connections` 提供真正的资源闸门。
        .max_body = 8 * 1024 * 1024 * 1024,
        .read_timeout_s = 300,
        // H04：把配置里的 max_connections 真正接到 accept 循环。
        // 以前这两个值被解析出来却从未传入，等于没有保护。
        .max_connections = @intCast(@max(cfg.max_connections, 0)),
    }, handleRequest, &app);
    if (cfg.max_connections > 0) {
        log.info("http: connection limit = {d}", .{cfg.max_connections});
    }
    if (cfg.max_concurrency > 0) {
        // 并发闸门目前只覆盖连接数；`max_concurrency` 是每请求内的并发度，
        // 云驱动各自的 limiter 已经在管，这里只记录一下不静默吞掉。
        log.info("http: max_concurrency = {d} (enforced per-driver)", .{cfg.max_concurrency});
    }
    defer server.deinit();

    installSignalHandlers(&server);

    log.info("listening on http://{s}:{d}", .{ cfg.address, port });

    // T6：存储初始化放到**后台线程**，监听立即开始。
    //
    // 对齐 Go：`internal/bootstrap/run.go` 的 `LoadStorages()` 把逐个
    // `op.LoadStorage` 跑在一个 detached goroutine 里，HTTP 服务器随后
    // **立即**监听。慢上游（189pc 登录）拖慢的只是「这个存储什么时候
    // 可用」，不再是「端口什么时候打开」—— 真机实测旧顺序被拖了约 48 秒，
    // 期间连 /api/public/settings 都连不上。
    //
    // spawn 失败时退回同步初始化：宁可晚几秒监听，也不能没有存储。
    const mount_thread = std.Thread.spawn(.{}, buildMountsWorker, .{ gpa, &app, cfg }) catch |e| {
        log.err("storage: could not spawn init thread ({s}); initialising synchronously", .{@errorName(e)});
        buildMountsWorker(gpa, &app, cfg);
        return;
    };
    mount_thread.detach();

    log.info("admin: {s} ({s})", .{
        app.admin_user,
        if (app.admin_hash.len > 0)
            "configured"
        else
            "NOT configured — open the Web setup wizard, or run `openlist admin set NEW_PASSWORD`",
    });

    try server.run();
    log.info("shutting down", .{});
    // T6：等后台初始化收尾再让 defer 跑 —— 否则 app.deinit() 会在某个驱动
    // init 还在飞的时候释放它脚下的内存。驱动的每个上游请求都有超时兜底
    // （N01），正常几秒内就会置位。
    waitForMountsReady();
}

fn handleRequest(ctx: *anyopaque, req: *http.Request, res: *http.Response) anyerror!void {
    const app: *api.App = @ptrCast(@alignCast(ctx));
    return api.handle(app, req, res);
}

// ---------------------------------------------------------------------------
// Storage construction
// ---------------------------------------------------------------------------

fn buildMounts(gpa: std.mem.Allocator, app: *api.App, cfg: *config.Config) !void {
    var mounts = List(api.Mount).init(gpa);
    var seen_paths = List([]const u8).init(gpa);

    for (cfg.storages) |*s| {
        if (s.disabled) {
            log.info("storage #{d} {s}: disabled, skipping", .{ s.id, s.driver });
            continue;
        }
        // T6：这里可能是后台线程。归一化已由主线程的 normalizeDriverNames
        // 完成，find 必然命中；仍保留 find 是为了在同步回退路径上也安全。
        const f = driver.find(s.driver) orelse {
            log.err("storage #{d}: no driver named {s} in this build (compiled in: see /api/fs/dirs)", .{ s.id, s.driver });
            continue;
        };

        // Parse `addition` — a JSON *string*, exactly as the Go build stores it.
        const add_text = if (s.addition.len > 0) s.addition else "{}";
        const add_val = json.parse(gpa, add_text) catch |e| {
            log.err("storage #{d} {s}: addition is not valid JSON ({s})", .{ s.id, s.driver, @errorName(e) });
            continue;
        };

        // C02：把真实 storage id 传进工厂。驱动靠它把刷新后的 token/cookie
        // 经 `persist` 写回配置；传 0 会让回写落到不存在的记录上。
        const drv = f.create(gpa, s.id, &add_val) catch |e| {
            log.err("storage #{d} {s}: create failed: {s}", .{ s.id, s.driver, @errorName(e) });
            continue;
        };

        var init_ctx = driver.Ctx{ .alloc = gpa, .tag = s.mount_path };
        drv.init(&init_ctx) catch |e| {
            // One broken storage must not take the process down: the Go build
            // marks it "disabled" and keeps serving the others, and a 光猫
            // that refuses to boot because a phone number changed is worse
            // than one with a red row in the UI.
            log.err("storage #{d} {s}: init failed: {s} — marking as errored", .{ s.id, s.driver, @errorName(e) });
            s.error_msg = gpa.dupe(u8, @errorName(e)) catch "";
            // S03：init 失败的驱动也要释放，否则每次配置重载都漏一个驱动
            // （它持有的 jar / client 都在 gpa 上）。
            drv.deinit(&init_ctx);
            continue;
        };

        const mp = try normalizeMountPath(gpa, s.mount_path);
        for (seen_paths.slice()) |p| {
            if (std.mem.eql(u8, p, mp)) {
                log.err("storage #{d}: mount path {s} is already taken, skipping", .{ s.id, mp });
                break;
            }
        } else {
            try seen_paths.append(mp);
            try mounts.append(.{
                .storage = s.*,
                .driver = drv,
                .mount_path = mp,
                .label = f.label,
            });
            log.info("storage #{d} {s} -> {s} ({s})", .{ s.id, s.driver, mp, f.label });
        }
    }

    // Longest mount path first, so `/nas/photos` wins over `/nas`.
    std.mem.sort(api.Mount, mounts.sliceMut(), {}, struct {
        fn gt(_: void, a: api.Mount, b: api.Mount) bool {
            return a.mount_path.len > b.mount_path.len;
        }
    }.gt);

    // T6：一次性发布。发布后内容永不再变，读方拿快照即可安全用（含调用驱动）。
    app.publishMounts(try mounts.toOwned());
}

/// T3 / 用户 2026-10-12 定的规则：**写回一律用 Go 名**。
///
/// `driver.find` 允许别名与忽略大小写（只为读得进老配置），但配置一旦解析
/// 成功，`Storage.driver` 就归一成 `factory.key` —— 它逐字节等于 Go 的
/// `driver.Config.Name`，这样 `cfg.save()`（token/cookie 回写、设置修改）
/// 落盘的永远是 Go 认识的名字，不会再扩散别名。
///
/// ⚠️ 必须在**主线程**调用：`save()` → `syncStorages()` 会读 `s.driver`，
/// 后台初始化线程写它会数据竞争（撕裂的 slice 头 → 配置里出现野指针）。
fn normalizeDriverNames(cfg: *config.Config) void {
    for (cfg.storages) |*s| {
        if (s.disabled) continue;
        const f = driver.find(s.driver) orelse {
            log.err("storage #{d}: no driver named {s} in this build (compiled in: see /api/fs/dirs)", .{ s.id, s.driver });
            continue;
        };
        if (!std.mem.eql(u8, s.driver, f.key)) {
            log.info("storage #{d}: driver {s} normalised to Go name {s}", .{ s.id, s.driver, f.key });
            s.driver = f.key;
        }
    }
}

/// T6：后台线程入口 —— 构造 + init 所有存储，然后一次性发布挂载表。
/// 绝不传播异常：init 失败的存储被跳过（记 `error_msg`），其余照常服务。
fn buildMountsWorker(gpa: std.mem.Allocator, app: *api.App, cfg: *config.Config) void {
    buildMounts(gpa, app, cfg) catch |e| {
        log.err("storage: background init failed: {s}", .{@errorName(e)});
    };
    if (app.mountsSnapshot().len == 0) {
        log.warn("no usable storages configured — the API will only serve /api/public/settings", .{});
    }
    log.info("storage: init finished, {d} mount(s) published", .{app.mountsSnapshot().len});
    g_mounts_ready.store(true, .release);
}

var g_mounts_ready = std.atomic.Value(bool).init(false);

/// T6：退出前等后台初始化收尾。
///
/// 不等的后果不是「慢一点」而是**进程退出时 defer app.deinit() 在驱动 init
/// 还在飞的时候释放内存**（UAF）。驱动每个上游请求都有超时兜底（N01，
/// 60s），所以预算取 65s；真超时了就 `exit(0)` 跳过 defer，交给 OS 回收 ——
/// 宁可跳过清理也不能在它脚下拆内存。
fn waitForMountsReady() void {
    if (g_mounts_ready.load(.acquire)) return;
    log.info("storage: waiting for background init to finish before exit", .{});
    var waited_ms: i64 = 0;
    const budget_ms: i64 = 65 * 1000;
    while (!g_mounts_ready.load(.acquire) and waited_ms < budget_ms) {
        rt.sleepMillis(100);
        waited_ms += 100;
    }
    if (!g_mounts_ready.load(.acquire)) {
        log.warn("storage: init still running after 65s; exiting without deferred cleanup", .{});
        std.process.exit(0);
    }
}

fn normalizeMountPath(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const cleaned = try urlmod.cleanPath(a, if (raw.len == 0) "/" else raw);
    return if (cleaned.len == 0) try a.dupe(u8, "/") else cleaned;
}

/// Called by drivers when they mutate their own `addition` blob.
fn persistStorage(storage_id: i64, addition_json: []const u8) void {
    if (!config.isLoaded()) return;
    const cfg = config.get();
    const s = cfg.storageById(storage_id) orelse return;
    const a = cfg.allocator();
    s.addition = a.dupe(u8, addition_json) catch return;
    cfg.save() catch |e| {
        log.warn("could not persist storage #{d}: {s}", .{ storage_id, @errorName(e) });
    };
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

var g_server: ?*http.Server = null;

fn installSignalHandlers(server: *http.Server) void {
    g_server = server;
    // `comptime` so the branch below is not even analysed on Windows, where
    // `std.posix.SIG` is `void` and `sigaction` does not exist.
    if (comptime builtin.os.tag == .windows) return; // no SIGTERM; the supervisor kills us

    const act = std.posix.Sigaction{
        .handler = .{ .handler = onSignal },
        // 0.17 dropped the `empty_sigset` constant in favour of the function.
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

// 0.17 types the handler's argument as the `SIG` enum rather than a bare
// `c_int`, so the signature has to say so.
fn onSignal(_: std.posix.SIG) callconv(.c) void {
    // Async-signal-safe: one atomic store. The accept loop notices and unwinds.
    if (g_server) |s| s.shutdown();
}

// ---------------------------------------------------------------------------
// CLI 子命令（对齐 Go `cmd/admin.go` + `internal/bootstrap/data/user.go`）
// ---------------------------------------------------------------------------

/// 字母数字字符集，与 Go `pkg/utils/random/random.go` 的 `letterBytes` 逐字一致。
const rand_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Go `random.String(n)`：n 位字母数字，取自 `crypto/rand`。
/// 0.17 移除了 `std.crypto.random`，熵改从 `Io` 句柄取（`rt.io().random`，
/// ChaCha CSPRNG，种子来自 OS）—— 与 config.zig 的 `randomSecret` 同一套做法。
fn randomString(buf: []u8) []const u8 {
    var raw: [1]u8 = undefined;
    for (buf) |*c| {
        rt.io().random(&raw);
        c.* = rand_letters[raw[0] % rand_letters.len];
    }
    return buf;
}

/// RFC 4122 v4 UUID，小写带连字符 —— 与 Go `google/uuid` 的 `NewString()` 同形。
fn formatUuidV4(out: *[36]u8) void {
    var b: [16]u8 = undefined;
    rt.io().random(&b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    const hex = "0123456789abcdef";
    var i: usize = 0;
    var j: usize = 0;
    while (i < 16) : (i += 1) {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            out[j] = '-';
            j += 1;
        }
        out[j] = hex[b[i] >> 4];
        out[j + 1] = hex[b[i] & 0x0f];
        j += 2;
    }
}

/// Go `random.Token()` = `"openlist-" + uuid.NewString() + String(64)`。
/// `buf` 至少要 9 + 36 + 64 = 109 字节。
fn randomToken(buf: []u8) []const u8 {
    var uuid: [36]u8 = undefined;
    formatUuidV4(&uuid);
    const head = std.fmt.bufPrint(buf, "openlist-{s}", .{uuid}) catch return buf[0..0];
    const n = head.len;
    _ = randomString(buf[n .. n + 64]);
    return buf[0 .. n + 64];
}

/// 对齐 Go `internal/bootstrap/data/user.go:initAdmin`。
///
/// 无管理员时：设了 `OPENLIST_ADMIN_PASSWORD` 就以 `admin` 为用户名建管理员，
/// 并把密码打印到**控制台**（Go 明确要求不写进日志文件）；没设就什么都不做，
/// 保持未初始化，交给 Web 安装向导（`POST /api/public/init/setup`）。
fn initAdminFromEnv(init: std.process.Init, cfg: *config.Config) !void {
    if (cfg.raw("zig.admin_password_hash") != null) return; // 已有管理员
    const pwd = init.environ_map.get("OPENLIST_ADMIN_PASSWORD") orelse return;
    if (pwd.len == 0) return;

    const ca = cfg.allocator();
    // 对齐 Go `User.SetPassword`：现生成 16 位 salt，存 `TwoHashPwd(pwd, salt)`。
    const salt = try api.randomSalt(ca);
    const hash = try api.twoHashPwd(ca, pwd, salt);
    try cfg.putZig("admin_user", .{ .string = try ca.dupe(u8, "admin") });
    try cfg.putZig("admin_salt", .{ .string = salt });
    try cfg.putZig("admin_password_hash", .{ .string = hash });
    try cfg.putZig("admin_pwd_ts", .{ .int = rt.nowSeconds() });
    try cfg.save();
    // Go: `DO NOT output the password to log file. Only output to console.`
    std.debug.print("Successfully created the admin user and the initial password is: {s}\n", .{pwd});
}

/// 首次启动生成 `zig.token` —— 对齐 Go：`random.Token()` 在 `InitialSettings()`
/// 里就写进了 settings 表，服务与 CLI 共用同一个串（`cmd/user.go` 的
/// `DelUserCacheOnline` 正是拿它做认证）。缺了它，CLI 改完密码就没法通知
/// 在线服务热重载。
fn ensureToken(cfg: *config.Config) !void {
    if (cfg.raw("zig.token") != null) return;
    var buf: [128]u8 = undefined;
    const gen = randomToken(&buf);
    try cfg.putZig("token", .{ .string = try cfg.allocator().dupe(u8, gen) });
    try cfg.save();
}

/// `openlist admin [random | set <pwd> | token]` —— 对齐 Go `cmd/admin.go`。
fn runAdmin(cfg: *config.Config, gpa: std.mem.Allocator, act: AdminCmd) !void {
    const ca = cfg.allocator();
    const username = if (cfg.raw("zig.admin_user")) |v| (v.asStr() orelse "admin") else "admin";
    const has_admin = cfg.raw("zig.admin_password_hash") != null;

    switch (act) {
        .info => {
            if (!has_admin) {
                std.debug.print("no administrator yet — use the Web setup wizard, or set OPENLIST_ADMIN_PASSWORD\n", .{});
                return;
            }
            std.debug.print("Admin user's username: {s}\n", .{username});
            std.debug.print("The password can only be output at the first startup, and then stored as a hash value, which cannot be reversed\n", .{});
            std.debug.print("You can reset the password with a random string by running [openlist admin random]\n", .{});
            std.debug.print("You can also set a new password by running [openlist admin set NEW_PASSWORD]\n", .{});
        },
        .random => {
            if (!has_admin) return error.NoAdministrator;
            var buf: [8]u8 = undefined;
            const pwd = randomString(&buf);
            try setAdminPassword(cfg, pwd);
            std.debug.print("admin user has been updated:\nusername: {s}\npassword: {s}\n", .{ username, pwd });
            notifyReload(cfg, gpa);
        },
        .set => |pwd| {
            if (!has_admin) return error.NoAdministrator;
            try setAdminPassword(cfg, pwd);
            std.debug.print("admin user has been updated:\nusername: {s}\npassword: {s}\n", .{ username, pwd });
            notifyReload(cfg, gpa);
        },
        .token => {
            // Go 的 token 存在 settings 表（供 WebDAV / API 的静态 token 认证）。
            // 本工程没有那张表，改用 `zig.token`：首次读取时生成并落盘，之后稳定。
            var tok: []const u8 = "";
            if (cfg.raw("zig.token")) |v| tok = v.asStr() orelse "";
            if (tok.len == 0) {
                var buf: [128]u8 = undefined;
                const gen = randomToken(&buf);
                const owned = try ca.dupe(u8, gen);
                try cfg.putZig("token", .{ .string = owned });
                try cfg.save();
                tok = owned;
            }
            std.debug.print("Admin token: {s}\n", .{tok});
        },
    }
}

/// 改完凭据后通知**在线**服务热重载 —— 对齐 Go `DelAdminCacheOnline`
/// （`cmd/user.go:15`：改完库再 POST `/api/admin/user/del_cache`）。
/// 服务没起、还没 token、或请求失败都只提示一句：重启同样能生效，
/// 不该让一次 CLI 操作因为服务不在而报错。
fn notifyReload(cfg: *config.Config, gpa: std.mem.Allocator) void {
    const port = cfg.http_port;
    if (port <= 0 or port > 65535) return;
    const tok = if (cfg.raw("zig.token")) |v| (v.asStr() orelse "") else "";
    if (tok.len == 0) {
        std.debug.print("note: restart the server for the change to take effect\n", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var jar = cookiejar.Jar.init(gpa);
    defer jar.deinit();
    var c = client.Client.init(gpa, .{ .timeout_s = 3 }, &jar);
    defer c.deinit();

    const url = std.fmt.allocPrint(a, "http://127.0.0.1:{d}/api/admin/user/del_cache", .{@as(u16, @intCast(port))}) catch return;
    const res = c.send(a, .{
        .method = "POST",
        .url = url,
        .headers = &.{.{ .name = "Authorization", .value = tok }},
        .body = "",
    }) catch {
        std.debug.print("note: could not reach the running server — restart it for the change to take effect\n", .{});
        return;
    };
    if (res.isOk()) {
        std.debug.print("running server notified (del_cache) — the new password is already in effect\n", .{});
    } else {
        std.debug.print("note: server answered {d} — restart it for the change to take effect\n", .{res.status});
    }
}

fn setAdminPassword(cfg: *config.Config, pwd: []const u8) !void {
    const ca = cfg.allocator();
    // 对齐 Go `User.SetPassword`：改密就换 salt，重算 `TwoHashPwd`。
    const salt = try api.randomSalt(ca);
    const hash = try api.twoHashPwd(ca, pwd, salt);
    try cfg.putZig("admin_salt", .{ .string = salt });
    try cfg.putZig("admin_password_hash", .{ .string = hash });
    // 推进口令版本：所有**已签发**的旧令牌立即失效（对齐 Go 的 `user.PwdTS`）。
    try cfg.putZig("admin_pwd_ts", .{ .int = rt.nowSeconds() });
    try cfg.save();
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// `argsWithAllocator` is gone in 0.17; the argv arrives pre-split as
/// `Init.minimal.args`, and the process-lifetime arena is the natural home for
/// the strings we keep.
fn parseArgs(init: std.process.Init) !Options {
    const a = init.arena.allocator();
    // `Iterator.init` is POSIX-only in 0.17: on Windows argv has to be split out
    // of a single command-line string, which needs an allocator.
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, a);

    var out = Options{};
    _ = args.next(); // argv[0]

    // 第一遍：吃 flag、收集 positional。flag 与 positional 可以交错
    // （`openlist server --config X`），所以不能边扫边解释子命令。
    var positionals = List([]const u8).init(a);
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            out.config_path = try a.dupe(u8, args.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--data")) {
            const dir = args.next() orelse return error.MissingValue;
            out.config_path = try std.fmt.allocPrint(a, "{s}/config.json", .{std.mem.trimEnd(u8, dir, "/")});
        } else if (std.mem.eql(u8, arg, "--port")) {
            const p = args.next() orelse return error.MissingValue;
            out.port_override = std.fmt.parseInt(u16, p, 10) catch return error.BadPort;
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            const l = args.next() orelse return error.MissingValue;
            out.log_level = log.Level.parse(l);
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            std.debug.print("{s}\n", .{version});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print(USAGE, .{});
            std.process.exit(0);
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownFlag;
        } else {
            try positionals.append(arg);
        }
    }

    // 第二遍：解释 positional。第一个词是子命令（Go 用 cobra，`server` /
    // `admin` 都是子命令）；都不是时沿用旧行为当成 config path
    // （`openlist [config]`）。
    var i: usize = 0;
    const items = positionals.slice();
    if (i < items.len and std.mem.eql(u8, items[i], "server")) {
        i += 1; // 与默认行为一致：起服务
    } else if (i < items.len and std.mem.eql(u8, items[i], "admin")) {
        i += 1;
        out.admin = blk: {
            if (i >= items.len) break :blk AdminCmd.info;
            const act = items[i];
            if (std.mem.eql(u8, act, "random")) {
                i += 1;
                break :blk AdminCmd.random;
            }
            if (std.mem.eql(u8, act, "token")) {
                i += 1;
                break :blk AdminCmd.token;
            }
            if (std.mem.eql(u8, act, "set")) {
                i += 1;
                // Go：`if len(args) == 0 { return fmt.Errorf("Please enter the new password") }`
                if (i >= items.len) return error.MissingValue;
                const pwd = items[i];
                i += 1;
                break :blk .{ .set = pwd };
            }
            // 未知 action：按 Go 的裸 `openlist admin` 处理（只打印信息）。
            break :blk AdminCmd.info;
        };
    }
    if (i < items.len) out.config_path = items[i];
    return out;
}

const USAGE =
    \\OpenList (zig) — a minimal OpenList-compatible server
    \\
    \\Usage: openlist [command] [options] [config.json]
    \\
    \\Commands:
    \\  server                   start the server (default)
    \\  admin                    show the admin user's info and password hints
    \\  admin random             reset the admin password to a random string
    \\  admin set NEW_PASSWORD   set a new admin password
    \\  admin token              show the admin token
    \\
    \\Options:
    \\  -c, --config <path>     config file (default: data/config.json)
    \\      --data <dir>        use <dir>/config.json
    \\      --port <n>          override scheme.http_port
    \\      --log-level <l>     debug | info | warn | error | off
    \\  -v, --version           print version and exit
    \\  -h, --help              print this help and exit
    \\
    \\Environment:
    \\  OPENLIST_LOG_LEVEL      default log level when --log-level is absent
    \\  OPENLIST_ADMIN_PASSWORD first run only: create `admin` with this password
    \\                          (otherwise the Web setup wizard does it)
    \\
;

// ---------------------------------------------------------------------------

const testing = std.testing;

test "normalizeMountPath" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/", try normalizeMountPath(a, ""));
    try testing.expectEqualStrings("/", try normalizeMountPath(a, "/"));
    try testing.expectEqualStrings("/nas", try normalizeMountPath(a, "/nas/"));
    try testing.expectEqualStrings("/a/b", try normalizeMountPath(a, "//a//b"));
}

test "version string is non-empty" {
    try testing.expect(version.len > 0);
}

test "randomString / randomToken match Go's alphabet and shape" {
    var buf: [8]u8 = undefined;
    const s = randomString(&buf);
    try testing.expectEqual(@as(usize, 8), s.len);
    for (s) |c| try testing.expect(std.mem.indexOfScalar(u8, rand_letters, c) != null);

    // Go `random.Token()` = "openlist-" + uuid(36) + String(64)
    var tbuf: [128]u8 = undefined;
    const t = randomToken(&tbuf);
    try testing.expect(std.mem.startsWith(u8, t, "openlist-"));
    try testing.expectEqual(@as(usize, "openlist-".len + 36 + 64), t.len);
    const uuid = t["openlist-".len..][0..36];
    try testing.expectEqual(@as(u8, '-'), uuid[8]);
    try testing.expectEqual(@as(u8, '-'), uuid[13]);
    try testing.expectEqual(@as(u8, '-'), uuid[18]);
    try testing.expectEqual(@as(u8, '-'), uuid[23]);
    try testing.expectEqual(@as(u8, '4'), uuid[14]); // version nibble
}

test "admin set/random persist a verifiable hash and bump the password version" {
    // 对齐官方 FAQ「忘记密码怎么办」：`openlist admin set NEW_PASSWORD` /
    // `admin random`。两个命令都必须落 sha256 hash 并推进 `admin_pwd_ts`
    // （否则改完密码，旧令牌还能继续用）。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.Io.Dir.realPathFileAlloc(tmp.dir, rt.io(), ".", testing.allocator);
    defer testing.allocator.free(dir);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/config.json", .{dir});
    defer testing.allocator.free(path);
    const prev_cfg = config.getOpt();
    const cfg = try config.load(testing.allocator, path);
    defer cfg.deinit();
    config.setForTest(cfg);
    defer config.setForTest(prev_cfg);

    // 无管理员时两个命令都必须拒绝（Go：`op.GetAdmin()` 失败就 return）。
    try testing.expectError(error.NoAdministrator, runAdmin(cfg, testing.allocator, .{ .set = "x" }));
    try testing.expectError(error.NoAdministrator, runAdmin(cfg, testing.allocator, .random));

    try cfg.putZig("admin_user", .{ .string = try cfg.allocator().dupe(u8, "admin") });
    try cfg.putZig("admin_salt", .{ .string = try cfg.allocator().dupe(u8, "0123456789abcdef") });
    try cfg.putZig("admin_password_hash", .{ .string = "placeholder" });

    const before = rt.nowSeconds();
    try runAdmin(cfg, testing.allocator, .{ .set = "new-password" });
    // 存的必须是 Go 形态 `TwoHashPwd(pwd, salt)`，不是裸 sha256。
    const salt = cfg.raw("zig.admin_salt").?.asStr().?;
    try testing.expectEqual(@as(usize, 16), salt.len);
    try testing.expectEqualStrings(
        try api.twoHashPwd(a, "new-password", salt),
        cfg.raw("zig.admin_password_hash").?.asStr().?,
    );
    try testing.expect(cfg.raw("zig.admin_pwd_ts").?.asInt().? >= before);

    try runAdmin(cfg, testing.allocator, .random);
    try testing.expectEqual(@as(usize, 64), cfg.raw("zig.admin_password_hash").?.asStr().?.len);
}

test "staticHash reproduces the exact hash the frontend sends" {
    // 向量由 Python 独立算出：sha256("verify-pass-2" + "-" + StaticHashSalt)，
    // 与用户 2026-10-13 从浏览器抓到的那条 `/api/auth/login/hash` 请求体
    // **逐字节**一致。这条钉住的是「前端登录页的哈希算法」，不是我们自己的输出。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        "7f3de24cc533f6ab126704856bec0e499b323e106e7f9dbf53f476d0ae26ec6b",
        try api.staticHash(a, "verify-pass-2"),
    );
    // Go `model.StaticHashSalt`（internal/model/user.go:24）必须逐字节一致。
    try testing.expectEqualStrings("https://github.com/alist-org/alist", api.static_hash_salt);
}
