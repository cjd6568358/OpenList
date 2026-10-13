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
const model = @import("model.zig");
const json = @import("util/json.zig");
const urlmod = @import("util/url.zig");
const Buf = @import("util/buf.zig").Buf;
const List = @import("util/buf.zig").List;
const rt = @import("rt.zig");

pub const version = "0.1.0-zig";

const Options = struct {
    config_path: []const u8 = "data/config.json",
    port_override: ?u16 = null,
    log_level: ?log.Level = null,
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

    const cfg = config.load(gpa, opts.config_path) catch |e| {
        std.debug.print("cannot load config {s}: {s}\n", .{ opts.config_path, @errorName(e) });
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
        if (app.admin_hash.len > 0) "configured" else "NOT configured — POST /api/auth/register",
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
            // Bare positional argument: treat as the config path, matching the
            // Go build's `openlist [config]` form.
            out.config_path = try a.dupe(u8, arg);
        }
    }
    return out;
}

const USAGE =
    \\OpenList (zig) — a minimal OpenList-compatible server
    \\
    \\Usage: openlist [options] [config.json]
    \\
    \\  -c, --config <path>     config file (default: data/config.json)
    \\      --data <dir>        use <dir>/config.json
    \\      --port <n>          override scheme.http_port
    \\      --log-level <l>     debug | info | warn | error | off
    \\  -v, --version           print version and exit
    \\  -h, --help              print this help and exit
    \\
    \\Environment:
    \\  OPENLIST_LOG_LEVEL      default log level when --log-level is absent
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
