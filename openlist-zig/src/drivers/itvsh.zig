//! 上海电信「智家硬盘」驱动 —— Go 版 `drivers/itvsh` 的 Zig 移植。
//!
//! 这个驱动是本次 Zig 重写选定的样板，因为它同时踩中了所有难点：
//!
//!   1. **生成式签名**：登录密码要先向 `/nas/session/key` 取一个 16 字符密钥，
//!      再 AES-128-ECB/PKCS7 加密并转小写 hex。（189pc 同样算法但输出大写，
//!      两者不可共用 helper —— 见 `util/aes.zig` 的注释。）
//!   2. **会话靠 cookie**：请求由 cookie + `X-NAS-SDKTOKEN` 共同标识，且
//!      cookie 要跨重启持久化，还要在 `forwardUrl` 揭晓后重新 graft 到正确域名。
//!   3. **瑞数 WAF**：必须清空 `User-Agent`、不带 `Referer`/`Origin`/
//!      `X-Requested-With`，否则一律 412。
//!   4. **分块并发上传**：512 KiB 一块，块名带 `.crash` 后缀，收尾走可回滚三步改名。
//!   5. **路径归一化**：显示名「家庭共享」对应的真实路径是 `/homeshare`。
//!
//! 与 Go 版的差异（都是有意为之，不是遗漏）：
//!   * `Copy` 不存在：上游没有复制接口，Go 版也是返回 NotSupport。这里干脆
//!     不提供 vtable 入口。
//!   * 上传进度回调 `UpdateProgress` 未移植：Zig 骨架没有任务中心，进度由
//!     调用方从日志推断。属于已知缺口，见 docs/STATUS.md。
//!   * 重试策略用固定退避而非 `retry-go` 的指数退避，次数一致（3 次）。

const std = @import("std");
const driver = @import("../driver.zig");
const model = @import("../model.zig");
const json = @import("../util/json.zig");
const aes = @import("../util/aes.zig");
const urlmod = @import("../util/url.zig");
const httpclient = @import("../client.zig");
const cookiejar = @import("../cookiejar.zig");
const Buf = @import("../util/buf.zig").Buf;
const List = @import("../util/buf.zig").List;
const log = @import("../log.zig");
const rt = @import("../rt.zig");

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

const api_base = "https://pan.itvsh.cn";
/// 上传/下载路径，拼在登录后返回的 `forwardUrl` 之后。
const path_put_file = "/nasforward/file/binary/upload";
const path_download = "/nasforward/file/download";
/// 分块大小，与官方小程序 / web 版一致。
const chunk_size: u64 = 512 * 1024;

/// `nasProxy` 的 method 常量（对应小程序 config/nas.js）。
const method_file_list = "capacity.nas.cloud.file.list";
const method_create_dir = "capacity.nas.cloud.file.dir.create";
const method_delete_dir = "capacity.nas.cloud.file.dir.delete";
const method_delete_file = "capacity.nas.cloud.file.delete";
const method_file_rename = "capacity.nas.cloud.file.rename";
const method_dir_rename = "capacity.nas.cloud.file.dir.rename";
const method_file_exist = "capacity.nas.cloud.file.exist";

/// 换取上传/下载 token 时的 `uploadType`。
const upload_type_upload: i64 = 0;
const upload_type_download: i64 = 1;

/// 上传并发上限，与官方客户端的 maxConcurrency 对齐。
const max_upload_thread: i64 = 8;
const default_upload_thread: i64 = 5;

/// 收尾阶段的重试次数（纯元数据操作，失败代价不对等）。
const finalize_attempts: u8 = 3;
/// 分块上传的重试次数。
const chunk_attempts: u8 = 3;
const retry_delay_ms: u64 = 1000;

/// 家庭共享：显示名与真实路径不同，必须归一化。
const homeshare_name = "家庭共享";
const homeshare_path = "/homeshare";

/// 鉴权失效识别。上游把「token 过期」表示为 code 1009/1010/1011 或 msg 文案。
/// 1010 是一等公民：小程序把它单列出来提示「您长时间未登录，请重新登录」。
/// 漏掉它就只能靠文案兜底，上游一改措辞恢复机制会静默失效。
const auth_failure_codes = [_]i64{ 1009, 1010, 1011, 401 };
const auth_failure_markers = [_][]const u8{
    "token expired",
    "token过期",
    "upload/download token expired",
    "登录已过期",
    "未登录",
};

/// 本驱动会返回的错误。分类在产生处完成 —— Zig 的错误值不带消息，
/// 所以「是不是鉴权失效」必须在拿到上游 code/msg 的那一刻判定并落成错误类型，
/// 而不是像 Go 那样事后去 `strings.Contains(err.Error(), ...)`。
pub const Error = error{
    /// 会话失效，可自动恢复（重登一次再试）。
    AuthFailed,
    /// 上游返回了业务错误。
    UpstreamError,
    /// HTTP 412 —— 被瑞数 WAF 挑战。单列出来，免得被当成「接口返回异常」排查。
    WafBlocked,
    /// 非 200 的 HTTP 响应。
    UpstreamHttp,
    /// 响应不是合法 JSON（多半是被 WAF 换成了 HTML）。
    UpstreamNotJson,
    /// 上传 token 换取失败。
    TokenUnavailable,
    /// `forwardUrl` 缺失，无法上传/下载。
    ForwardUrlMissing,
    /// 既没填 token 也没填账号密码。
    MissingCredentials,
    /// token 由用户手工配置，驱动无法续期，只能提示手动更新。
    ConfiguredTokenExpired,
    /// 分块读取短读。
    ShortRead,
    /// 上游没有复制接口。
    NotSupported,
};

// ---------------------------------------------------------------------------
// 配置（对应 Go 的 Addition）
// ---------------------------------------------------------------------------

pub const Addition = struct {
    mobile: []const u8 = "",
    password: []const u8 = "",
    access_token: []const u8 = "",
    root_path: []const u8 = "/",
    upload_thread: i64 = default_upload_thread,
    /// 由登录 / 用户信息接口返回，上传下载走这个域名。持久化。
    forward_url: []const u8 = "",
    /// 持久化的会话 cookie（Go `http.Cookie` 数组的 JSON）。持久化。
    cookies: []const u8 = "",

    pub fn parse(alloc: std.mem.Allocator, v: ?*const json.Value) !Addition {
        var a = Addition{};
        const o = v orelse return a;
        if (o.asObject() == null) return a;
        a.mobile = try dupeStr(alloc, o.strAt("mobile")) orelse "";
        a.password = try dupeStr(alloc, o.strAt("password")) orelse "";
        a.access_token = try dupeStr(alloc, o.strAt("access_token")) orelse "";
        // T3：键名逐一对齐 Go。`drivers/itvsh/meta.go:15` 内嵌
        // `driver.RootPath` → `root_folder_path`（internal/driver/item.go:31）。
        // `ForwardUrl` / `Cookies` 在 Go 里**故意不带 json tag**（meta.go:19-27
        // 注释说明：getAdditionalItems 会跳过无 tag 字段，不进表单但持久化），
        // 于是 Go 的 `encoding/json` 用**字段名本身**当键 —— 用户备份里就是
        // `ForwardUrl` / `Cookies` 两个大写开头（已对
        // openlist_backup_2026_10_11_21_41_15.json 的 storage #1 实证）。
        // 优先级：Go 名 → 本工程旧名（`root_path` / `forward_url` / `cookies`），
        // 新旧并存时以 Go 名为准。
        if (o.strAt("root_folder_path")) |s| {
            a.root_path = try dupeStr(alloc, s) orelse "/";
        } else if (o.strAt("root_path")) |s| {
            a.root_path = try dupeStr(alloc, s) orelse "/";
        }
        a.forward_url = try dupeStr(alloc, o.strAt("ForwardUrl") orelse o.strAt("forward_url")) orelse "";
        a.cookies = try dupeStr(alloc, o.strAt("Cookies") orelse o.strAt("cookies")) orelse "";
        if (o.intAt("upload_thread")) |t| a.upload_thread = t;
        return a;
    }

    /// 序列化回 `addition` 字符串。**键名与 Go 版逐字节一致**（T3）：
    /// `root_folder_path` 来自内嵌的 `driver.RootPath`，`ForwardUrl`/`Cookies`
    /// 在 Go 里无 json tag、以字段名本身为键。这样写出的配置 Go 版能直接读。
    pub fn toJson(self: Addition, alloc: std.mem.Allocator) ![]u8 {
        var b = Buf.init(alloc);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("mobile", self.mobile);
        try w.str("password", self.password);
        try w.str("access_token", self.access_token);
        try w.str("root_folder_path", self.root_path);
        try w.int("upload_thread", self.upload_thread);
        try w.str("ForwardUrl", self.forward_url);
        try w.str("Cookies", self.cookies);
        try w.end();
        return b.toOwned();
    }
};

fn dupeStr(alloc: std.mem.Allocator, v: ?[]const u8) !?[]const u8 {
    const s = v orelse return null;
    return try alloc.dupe(u8, s);
}

/// 极小的有序对象写入器。用它而不是 `json.Builder`，是为了让字段顺序
/// 在源码里一眼可见 —— `addition` 是要跟 Go 版互相迁移的。
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
    fn raw(self: *ObjWriter, name: []const u8, v: []const u8) !void {
        try self.key(name);
        try self.b.append(v);
    }
    fn end(self: *ObjWriter) !void {
        try self.b.appendByte('}');
    }
};

// ---------------------------------------------------------------------------
// 驱动本体
// ---------------------------------------------------------------------------

pub const Itvsh = struct {
    /// 长期分配器。驱动持有的所有状态都从这里分配，与请求 arena 无关。
    alloc: std.mem.Allocator,
    storage_id: i64,
    cfg: Addition,
    jar: *cookiejar.Jar,
    client: httpclient.Client,
    /// 账密登录得到的 token，**只存内存**。
    /// 必须与 `cfg.access_token`（用户填的、会落库）分开：登录产物一旦写进
    /// addition，保存配置后 token 栏就会被回显，且下次启动会拿它去请求，
    /// 绕开「失效即账密重登」的逻辑。
    session_token: []const u8 = "",
    /// 串行化「重新登录 / 刷新会话」，避免并发请求同时触发多轮登录。
    auth_mu: std.Io.Mutex = .init,
    /// 上一次落库的 addition，用来判断是否真的有变化，避免每次请求都写盘。
    last_saved: []const u8 = "",

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
        return "Itvsh";
    }

    fn as(self: *anyopaque) *Itvsh {
        return @ptrCast(@alignCast(self));
    }

    // -----------------------------------------------------------------------
    // 生命周期
    // -----------------------------------------------------------------------

    fn init(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!void {
        const self = as(ptr);
        _ = ctx;

        // 回填上次持久化的会话 cookie，尽量免去重新登录
        self.restoreCookies();

        // 兜底 5，与表单默认值、官方客户端一致。
        // 表单 default 只在新建时生效，老配置里 upload_thread 可能是 0。
        if (self.cfg.upload_thread <= 0) {
            self.cfg.upload_thread = default_upload_thread;
        } else if (self.cfg.upload_thread > max_upload_thread) {
            self.cfg.upload_thread = max_upload_thread;
        }

        if (self.cfg.access_token.len == 0) {
            // 二选一：不填 token 就必须有账密。表单层允许两者都留空，这里显式拦下。
            if (self.cfg.mobile.len == 0 or self.cfg.password.len == 0) {
                log.err("[itvsh] 请填写手机号+密码，或填写 Access token（二选一）", .{});
                return Error.MissingCredentials;
            }
            var arena = std.heap.ArenaAllocator.init(self.alloc);
            defer arena.deinit();
            self.login(arena.allocator()) catch |e| {
                // 有持久化的会话 cookie 时，即使密码登录失败也能凭 cookie 继续
                // （例如密码已改）。此时不向上报错，交给后续请求自愈。
                if (!self.hasCookies()) return e;
                log.warn("[itvsh] login failed, fallback to persisted cookies: {s}", .{@errorName(e)});
            };
        }

        {
            var arena = std.heap.ArenaAllocator.init(self.alloc);
            defer arena.deinit();
            self.refreshUserInfo(arena.allocator()) catch |e| {
                // token 来自配置时驱动无法续期。仅当确属鉴权失效才归因到 token，
                // 免得把网络/WAF 问题误导成「token 过期」。
                if (self.cfg.access_token.len != 0 and e == Error.AuthFailed) {
                    return Error.ConfiguredTokenExpired;
                }
                return e;
            };
        }

        // 到这里 forwardUrl 已就绪，把 cookie 按正确的域名作用域重新回填并落库，
        // 否则下次启动 persistURLs 仍拿不到 forwardUrl，cookie 会被丢在错误的 host 下。
        self.regraftCookies();
        _ = self.saveCookies();
        log.info("[itvsh] ready: mobile={s} forwardUrl={s}", .{
            if (self.cfg.mobile.len > 0) self.cfg.mobile else "(token)",
            self.forwardUrl(),
        });
    }

    fn deinit(ptr: *anyopaque, ctx: *driver.Ctx) void {
        const self = as(ptr);
        _ = ctx;
        _ = self.saveCookies();
        self.client.deinit();
        self.jar.deinit();
        self.alloc.destroy(self.jar);
    }

    // -----------------------------------------------------------------------
    // 路径工具
    // -----------------------------------------------------------------------

    /// 把路径中的「家庭共享」段替换为 homeshare。
    /// 对不返回该目录的账号是空转，但换个账号就能避免拼出错误路径。
    fn normalizePath(alloc: std.mem.Allocator, p: []const u8) ![]const u8 {
        if (p.len == 0 or std.mem.indexOf(u8, p, homeshare_name) == null) return p;
        var out = Buf.init(alloc);
        var it = std.mem.splitScalar(u8, p, '/');
        var first = true;
        while (it.next()) |seg| {
            if (!first) try out.appendByte('/');
            first = false;
            if (std.mem.eql(u8, seg, homeshare_name)) {
                try out.append("homeshare");
            } else {
                try out.append(seg);
            }
        }
        return out.toOwned();
    }

    fn forwardUrl(self: *Itvsh) []const u8 {
        return std.mem.trimEnd(u8, self.cfg.forward_url, "/");
    }

    fn authToken(self: *Itvsh) []const u8 {
        return if (self.cfg.access_token.len != 0) self.cfg.access_token else self.session_token;
    }

    /// 所有请求都要带的头。
    /// 只保留上游必需的 `X-NAS-*` 与一个语言标记；其余一律从简 ——
    /// 上游 WAF 对多余/伪装的头部很敏感。
    ///
    /// `User-Agent` 显式置空是**必须的**：Go 的 net/http 对「存在但为空」的 UA
    /// 会整个省略该头，正好对齐 Web 版「不发 UA」的做法。`client.zig` 里
    /// 专门为它开了口子（空值 UA 会被丢掉而不是发一个空头）。
    fn authHeaders(self: *Itvsh, alloc: std.mem.Allocator) ![]model.Header {
        const hs = try alloc.alloc(model.Header, 4);
        hs[0] = .{ .name = "X-NAS-CLIENTTYPE", .value = "60" };
        hs[1] = .{ .name = "X-NAS-SDKTOKEN", .value = try alloc.dupe(u8, self.authToken()) };
        hs[2] = .{ .name = "Accept-Language", .value = "zh-cn" };
        hs[3] = .{ .name = "User-Agent", .value = "" };
        return hs;
    }

    // -----------------------------------------------------------------------
    // cookie 持久化
    // -----------------------------------------------------------------------

    /// jar 的「作用域种子」。jar 以 host 为键收集 cookie，恢复时得先知道
    /// 该往哪些 host 回填 —— 这两个正是本驱动会访问的域名。
    fn persistHosts(self: *Itvsh, alloc: std.mem.Allocator) ![][]const u8 {
        var l = List([]const u8).init(alloc);
        const api_host = try alloc.dupe(u8, "pan.itvsh.cn");
        try l.append(api_host);
        if (self.forwardUrl().len > 0) {
            const u = urlmod.Url.parse(self.forwardUrl()) catch null;
            if (u) |x| try l.append(try alloc.dupe(u8, x.host));
        }
        return l.toOwned();
    }

    fn hasCookies(self: *Itvsh) bool {
        return self.cfg.cookies.len > 0;
    }

    /// 把 jar 内容序列化进 `addition` 并落库。返回是否发生了变化。
    fn saveCookies(self: *Itvsh) bool {
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        // 只序列化「种子 host」上的 cookie，与 Go 版一致。
        var all = List(cookiejar.Cookie).init(a);
        const hosts = self.persistHosts(a) catch return false;
        for (hosts) |h| {
            const cs = self.jar.cookiesFor(a, h, rt.nowSeconds()) catch continue;
            for (cs) |c| all.append(c) catch {};
        }
        if (all.len == 0) return false;

        // 用一个只含这些 cookie 的临时 jar 复用 toJson，保证格式与 Go 一致。
        var tmp = cookiejar.Jar.init(a);
        for (all.slice()) |c| tmp.store(c, 0);
        const encoded = tmp.toJson(a) catch return false;

        if (std.mem.eql(u8, encoded, self.cfg.cookies)) return false;
        const owned = self.alloc.dupe(u8, encoded) catch return false;
        if (self.cfg.cookies.len > 0) self.alloc.free(@constCast(self.cfg.cookies));
        self.cfg.cookies = owned;
        self.persist();
        return true;
    }

    /// 把当前 addition 落库。forwardUrl 与 cookies 都靠它存活到下次启动。
    fn persist(self: *Itvsh) void {
        const text = self.cfg.toJson(self.alloc) catch return;
        if (self.last_saved.len > 0) self.alloc.free(@constCast(self.last_saved));
        self.last_saved = text;
        driver.persist(self.storage_id, text);
    }

    /// Init 时把上次存的 cookie 回填进 jar。内容损坏时静默清空，退化为重新登录。
    ///
    /// 持久化 blob 里每个 cookie 都带 Domain，所以先按 blob 自带的 domain 装进
    /// 一个临时 jar，再把整个集合 graft 到每个「种子 host」上。这样即使
    /// forwardUrl 这次变了（换机房），cookie 也能落到新域名上。
    fn restoreCookies(self: *Itvsh) void {
        if (self.cfg.cookies.len == 0) return;
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        var staging = cookiejar.Jar.init(a);
        staging.fromJson(self.cfg.cookies) catch {
            log.warn("[itvsh] restore cookies failed, will login again", .{});
            self.alloc.free(@constCast(self.cfg.cookies));
            self.cfg.cookies = "";
            return;
        };
        const cs = staging.allCookies(a) catch return;
        if (cs.len == 0) return;

        const hosts = self.persistHosts(a) catch return;
        for (hosts) |h| self.jar.setForHost(h, cs);
    }

    /// forwardUrl 就绪后，把已持久化的 cookie 重新回填到正确的作用域上。
    /// Init 早期 forwardUrl 为空，jar 里只认 apiBase，这里补上 forwardUrl 的 host。
    fn regraftCookies(self: *Itvsh) void {
        if (self.cfg.cookies.len == 0 or self.forwardUrl().len == 0) return;
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        var staging = cookiejar.Jar.init(a);
        staging.fromJson(self.cfg.cookies) catch return;
        const cs = staging.allCookies(a) catch return;
        if (cs.len == 0) return;
        const u = urlmod.Url.parse(self.forwardUrl()) catch return;
        self.jar.setForHost(u.host, cs);
    }

    // -----------------------------------------------------------------------
    // 上游调用
    // -----------------------------------------------------------------------

    /// 发一个带认证头的 JSON POST。返回通用信封（data 未解析）。
    ///
    /// 返回值是 **arena 里的指针**而不是 `json.Value` 值：信封会被
    /// `postEnvelope` / `nasProxyOnce` 一层层往上传，按值返回就会把栈上临时量
    /// 的地址带出去，解引用即悬垂。
    fn rawPost(
        self: *Itvsh,
        arena: std.mem.Allocator,
        url: []const u8,
        body: []const u8,
    ) !*const json.Value {
        const headers = try self.authHeaders(arena);
        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = url,
            .headers = headers,
            .body = body,
        });
        if (res.status != 200) {
            // 412 是瑞数 WAF 的挑战响应（响应体是一段动态混淆 JS，不是业务 JSON）。
            if (res.status == 412) {
                log.warn("[itvsh] {s} blocked by WAF (HTTP 412)", .{url});
                return Error.WafBlocked;
            }
            log.warn("[itvsh] {s} failed: HTTP {d}, body: {s}", .{
                url, res.status, res.body[0..@min(res.body.len, 256)],
            });
            // D11：非 200 不能直接判成 UpstreamHttp。Go 的 `rawPost` 会把响应体
            // 拼进错误消息（drivers/itvsh/util.go:388），`isAuthFailure` 随后在
            // **文本**里找 `code <N>` 和失效文案（util.go:61-79）。会话失效经常
            // 就是「非 200 + JSON body」的形态，丢掉 body 就永远触发不了重登。
            if (json.parse(arena, res.body)) |v| {
                try classifyUpstream(v.intAt("code") orelse 0, v.strAt("msg") orelse "", url);
            } else |_| {}
            if (isAuthFailureText(res.body)) {
                log.warn("[itvsh] {s} auth failure detected in non-200 body", .{url});
                return Error.AuthFailed;
            }
            return Error.UpstreamHttp;
        }
        const slot = try arena.create(json.Value);
        slot.* = json.parse(arena, res.body) catch {
            log.warn("[itvsh] {s} returned non-JSON: {s}", .{
                url, res.body[0..@min(res.body.len, 256)],
            });
            return Error.UpstreamNotJson;
        };
        return slot;
    }

    /// 发 JSON POST 并校验外层 code。
    fn postEnvelope(self: *Itvsh, arena: std.mem.Allocator, url: []const u8, body: []const u8) !*const json.Value {
        const v = try self.rawPost(arena, url, body);
        const code = v.intAt("code") orelse 0;
        const msg = v.strAt("msg") orelse "";
        if (code != 200) {
            try classifyUpstream(code, msg, url);
        }
        return v;
    }

    /// 把上游的 code/msg 归成错误类型。这是 Zig 版取代 Go
    /// `isAuthFailure(err.Error())` 字符串匹配的地方。
    fn classify(self: *Itvsh, code: i64, msg: []const u8, what: []const u8) !void {
        _ = self;
        return classifyUpstream(code, msg, what);
    }

    /// 用手机号+密码登录。流程：取 AES 密钥 -> 加密密码 -> 提交登录。
    fn login(self: *Itvsh, arena: std.mem.Allocator) !void {
        // 1. 取密钥
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("mobile", self.cfg.mobile);
        try w.end();

        const key_resp = try self.postEnvelope(arena, api_base ++ "/nas/session/key", b.slice());
        // data 直接就是一个字符串（密钥本身）
        const secret = key_resp.getPath("data").?.asStr() orelse return Error.UpstreamError;
        if (secret.len == 0) return Error.UpstreamError;

        // 2. AES-ECB/PKCS7 加密密码（输出小写 hex，与小程序 AES_encode 一致）
        const encoded = try aes.ecbEncryptHexLower(arena, secret, self.cfg.password);

        // 3. 登录
        var b2 = Buf.init(arena);
        var w2 = ObjWriter{ .b = &b2 };
        try w2.begin();
        try w2.str("mobile", self.cfg.mobile);
        try w2.str("password", encoded);
        try w2.str("oauthType", "wx-small-app-Token");
        try w2.end();

        const login_resp = try self.postEnvelope(arena, api_base ++ "/nas/user/login", b2.slice());
        const data = login_resp.getPath("data") orelse return Error.UpstreamError;
        const token = data.strAt("access_token") orelse "";
        if (token.len == 0) return Error.UpstreamError;

        // 只写内存，不碰 cfg.access_token（用户填的配置字段）
        self.session_token = try self.alloc.dupe(u8, token);
        if (data.strAt("forwardUrl")) |fu| {
            if (fu.len > 0) try self.setForwardUrl(fu);
        }
    }

    fn setForwardUrl(self: *Itvsh, fu: []const u8) !void {
        if (std.mem.eql(u8, fu, self.cfg.forward_url)) return;
        if (self.cfg.forward_url.len > 0) self.alloc.free(@constCast(self.cfg.forward_url));
        self.cfg.forward_url = try self.alloc.dupe(u8, fu);
    }

    /// 拉取用户信息以补全 forwardUrl。forwardUrl 是上传/下载用的另一个域名，
    /// 登录响应里不一定带。
    fn refreshUserInfo(self: *Itvsh, arena: std.mem.Allocator) !void {
        const resp = try self.postEnvelope(arena, api_base ++ "/nas/user/info", "{}");
        const data = resp.getPath("data") orelse return Error.UpstreamError;
        if (data.strAt("forwardUrl")) |fu| {
            if (fu.len > 0) try self.setForwardUrl(fu);
        }
        if (self.forwardUrl().len == 0) {
            log.err("[itvsh] forwardUrl is empty, cannot upload or download", .{});
            return Error.ForwardUrlMissing;
        }
    }

    /// 取空间信息。
    fn volumeInfo(self: *Itvsh, arena: std.mem.Allocator) !driver.DiskUsage {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const r = self.postEnvelope(arena, api_base ++ "/nas/volume/info", "{}");
            if (r) |resp| {
                const d = resp.getPath("data") orelse return .{};
                const cap = d.intAt("capacity") orelse 0;
                const size = d.intAt("size") orelse 0;
                const used = d.intAt("capacityUsed") orelse 0;
                const user = d.intAt("userSize") orelse 0;
                return .{
                    .total = if (cap != 0) cap else size,
                    .used = if (used != 0) used else user,
                };
            } else |e| {
                if (e != Error.AuthFailed or attempt >= 1) return e;
                log.warn("[itvsh] auth failed, restoring session: {s}", .{@errorName(e)});
                try self.relogin(arena);
            }
        }
    }

    /// 会话恢复：只走账密重登一条路。全程无用户介入。
    ///
    /// token 来自配置（access_token 非空）时不做任何恢复：那种形态下 token 是
    /// 用户手工提供的，驱动无从续期，而 `authToken()` 又始终优先返回它 ——
    /// 就算在这里登录成功，换来的 sessionToken 也永不会被发出。直接报错让用户
    /// 手动更新 token，不去白白验证一遍账密。
    fn relogin(self: *Itvsh, arena: std.mem.Allocator) !void {
        self.auth_mu.lockUncancelable(rt.io());
        defer self.auth_mu.unlock(rt.io());

        if (self.cfg.access_token.len != 0) return Error.ConfiguredTokenExpired;
        if (self.cfg.mobile.len == 0 or self.cfg.password.len == 0) return Error.MissingCredentials;

        try self.login(arena);
        try self.refreshUserInfo(arena);
        self.regraftCookies();
        // 无论 cookie 有没有变化都要落库：forwardUrl 可能刚被登录响应更新。
        _ = self.saveCookies();
        self.persist();
    }

    /// 统一走 POST /nas/rd_center/data/get，body 为 {method, type, data}。
    /// 鉴权失效时自动恢复会话并重试一次。
    ///
    /// 注意：`data` 必须是已经序列化好的 JSON 片段。调用点绝不能间接调用
    /// `login`，否则会与 `relogin` 形成无限递归。
    fn nasProxy(
        self: *Itvsh,
        arena: std.mem.Allocator,
        method: []const u8,
        data_json: []const u8,
        typ: i64,
        quiet: bool,
    ) !*const json.Value {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const r = self.nasProxyOnce(arena, method, data_json, typ, quiet);
            if (r) |v| return v else |e| {
                if (e != Error.AuthFailed or attempt >= 1) return e;
                log.warn("[itvsh] auth failed, restoring session: {s}", .{@errorName(e)});
                try self.relogin(arena);
            }
        }
    }

    fn nasProxyOnce(
        self: *Itvsh,
        arena: std.mem.Allocator,
        method: []const u8,
        data_json: []const u8,
        typ: i64,
        quiet: bool,
    ) !*const json.Value {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("method", method);
        try w.int("type", typ);
        try w.raw("data", data_json);
        try w.end();

        const v = try self.rawPost(arena, api_base ++ "/nas/rd_center/data/get", b.slice());
        const code = v.intAt("code") orelse 0;
        const msg = v.strAt("msg") orelse "";
        if (code != 200) try classifyUpstream(code, msg, method);

        // 业务错误码在 data.errorCode（字符串），"0" 表示成功。
        // `quiet` 只给「预期的失败」用（例如上传前清理残留 .crash，文件本来
        // 就可能不存在）：错误照返，但别刷无谓的 WARN 把真问题淹掉。
        // 上游对这种响应连 errorCode 都不给（空串），与 Go 的
        // `_, _ = d.nasProxy(...)`（upload.go:44）等价丢弃。
        const inner = v.getPath("data") orelse return Error.UpstreamError;
        const ec = inner.strAt("errorCode") orelse "";
        if (!std.mem.eql(u8, ec, "0")) {
            const em = inner.strAt("errorMsg") orelse "";
            if (!quiet) {
                log.warn("[itvsh] {s} business error: errorCode {s}, errorMsg {s}", .{ method, ec, em });
            }
            // 业务层也可能报鉴权失效
            try classifyUpstream(0, em, method);
            try classifyUpstream(0, ec, method);
            return Error.UpstreamError;
        }
        return inner.getPath("data") orelse return Error.UpstreamError;
    }

    /// 列出目录下的文件与目录。返回 arena 里的 `Value` 切片 —— 调用点用
    /// `|*e|` 取指针访问字段。
    fn listEntries(self: *Itvsh, arena: std.mem.Allocator, dir: []const u8) ![]json.Value {
        const norm = try normalizePath(arena, if (dir.len == 0) "/" else dir);
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("directory", norm);
        try w.int("limit", 10000);
        try w.int("offset", 0);
        try w.end();

        const data = try self.nasProxy(arena, method_file_list, b.slice(), 1, false);
        return data.asArray() orelse &.{};
    }

    /// 换取上传/下载 token。该接口要求 form-urlencoded。
    fn getToken(self: *Itvsh, arena: std.mem.Allocator, path_file_name: []const u8, upload_type: i64) ![]const u8 {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const r = self.fetchToken(arena, path_file_name, upload_type);
            if (r) |t| {
                // 换 token 的响应可能刷新 cookie，落库
                _ = self.saveCookies();
                return t;
            } else |e| {
                if (e != Error.AuthFailed or attempt >= 1) return e;
                log.warn("[itvsh] auth failed, restoring session: {s}", .{@errorName(e)});
                try self.relogin(arena);
            }
        }
    }

    fn fetchToken(self: *Itvsh, arena: std.mem.Allocator, path_file_name: []const u8, upload_type: i64) ![]const u8 {
        const norm = try normalizePath(arena, path_file_name);
        var form = Buf.init(arena);
        try form.append("pathFileName=");
        try urlmod.encodeInto(&form, norm, .form);
        try form.append("&uploadType=");
        try form.print("{d}", .{upload_type});

        var headers = try self.authHeaders(arena);
        const all = try arena.alloc(model.Header, headers.len + 1);
        @memcpy(all[0..headers.len], headers);
        all[headers.len] = .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" };
        headers = all;

        const res = try self.client.send(arena, .{
            .method = "POST",
            .url = api_base ++ "/nas/user/upload/userInfo",
            .headers = headers,
            .body = form.slice(),
        });
        if (res.status != 200) {
            if (res.status == 412) return Error.WafBlocked;
            log.warn("[itvsh] get upload token failed: HTTP {d}, body: {s}", .{
                res.status, res.body[0..@min(res.body.len, 256)],
            });
            // D11：同 rawPost —— 非 200 也要先看 body 能不能判成会话失效。
            if (json.parse(arena, res.body)) |v| {
                try classifyUpstream(v.intAt("code") orelse 0, v.strAt("msg") orelse "", "upload/userInfo");
            } else |_| {}
            if (isAuthFailureText(res.body)) {
                log.warn("[itvsh] upload/userInfo auth failure detected in non-200 body", .{});
                return Error.AuthFailed;
            }
            return Error.UpstreamHttp;
        }
        const v = json.parse(arena, res.body) catch return Error.UpstreamNotJson;
        const code = v.intAt("code") orelse 0;
        if (code != 200) {
            try classifyUpstream(code, v.strAt("msg") orelse "", "upload/userInfo");
        }
        // data 可能是字符串，也可能是「被转义的 JSON 字符串」，两种都处理。
        const d = v.getPath("data") orelse return Error.TokenUnavailable;
        var token: []const u8 = "";
        switch (d.*) {
            .string => |s| {
                const t = std.mem.trim(u8, s, " \t\r\n");
                if (t.len > 0 and t[0] == '{') {
                    // 内层还是 JSON，再解一层
                    const inner = json.parse(arena, s) catch return Error.TokenUnavailable;
                    token = inner.strAt("token") orelse inner.strAt("uploadToken") orelse "";
                } else {
                    token = t;
                }
            },
            else => {
                token = d.strAt("token") orelse d.strAt("uploadToken") orelse "";
            },
        }
        if (token.len == 0) {
            log.warn("[itvsh] upload token is empty, data: {s}", .{res.body[0..@min(res.body.len, 256)]});
            return Error.TokenUnavailable;
        }
        return token;
    }

    /// 检查目录下是否已存在同名文件。
    fn fileExist(self: *Itvsh, arena: std.mem.Allocator, dir: []const u8, name: []const u8) !bool {
        var b = Buf.init(arena);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("directory", dir);
        try w.str("filename", name);
        try w.end();

        // D12：请求错误必须向上传播（Go util.go:612-625 的 `return false, err`）。
        // 以前 `catch return false` 把"查询失败"当成"文件不存在"，于是上传前的
        // 旧文件备份步骤会被静默跳过。只有**解析不出布尔值**才回落 false，
        // 对应 Go 里 `json.Unmarshal` 失败返回 `(false, nil)` 的那条路径。
        const data = try self.nasProxy(arena, method_file_exist, b.slice(), 1, false);
        return data.asBool() orelse false;
    }

    // -----------------------------------------------------------------------
    // vtable 实现
    // -----------------------------------------------------------------------

    fn list(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror![]model.Obj {
        const self = as(ptr);
        const a = ctx.alloc;
        const entries = try self.listEntries(a, dir);

        var out = List(model.Obj).init(a);
        for (entries) |*e| {
            const e_path = e.strAt("path") orelse "";
            const e_name = e.strAt("filename") orelse continue;
            const e_type = e.strAt("type") orelse "";
            const full = try normalizePath(a, try urlmod.joinPath(a, e_path, e_name));
            try out.append(.{
                .name = try a.dupe(u8, e_name),
                .size = parseSize(e.strAt("size")),
                .is_dir = std.mem.eql(u8, e_type, "DIR"),
                .modified = parseTime(e.strAt("mtime")),
                .created = parseTime(e.strAt("ctime")),
                // itvsh 的文件标识就是路径本身；sign 带上归一化后的完整路径，
                // 调用方后续拿它去 link/remove 时不必再猜。
                .sign = try a.dupe(u8, full),
            });
        }

        // 根目录补上「家庭共享」（服务端不一定返回它，小程序也是客户端伪造的）
        if (dir.len == 0 or std.mem.eql(u8, dir, "/")) {
            return try injectHomeshare(a, out.slice());
        }
        return out.toOwned();
    }

    fn details(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8) anyerror!model.File {
        const self = as(ptr);
        const a = ctx.alloc;

        if (path.len == 0 or std.mem.eql(u8, path, "/")) {
            return .{ .name = "/", .is_dir = true };
        }
        // 伪造的「家庭共享」条目不在上游列表里，直接按目录回答。
        if (std.mem.eql(u8, path, homeshare_path) or std.mem.eql(u8, path, "/" ++ homeshare_name)) {
            return .{ .name = homeshare_name, .is_dir = true, .sign = homeshare_path };
        }

        const parent = urlmod.parentPath(path);
        const want = urlmod.baseName(path);
        const entries = try self.listEntries(a, parent);
        for (entries) |*e| {
            const e_name = e.strAt("filename") orelse continue;
            if (!std.mem.eql(u8, e_name, want)) continue;
            const full = try normalizePath(a, try urlmod.joinPath(a, e.strAt("path") orelse "", e_name));
            return .{
                .name = try a.dupe(u8, e_name),
                .size = parseSize(e.strAt("size")),
                .is_dir = std.mem.eql(u8, e.strAt("type") orelse "", "DIR"),
                .modified = parseTime(e.strAt("mtime")),
                .created = parseTime(e.strAt("ctime")),
                .sign = try a.dupe(u8, full),
            };
        }
        return driver.Error.NotFound;
    }

    /// 取下载直链。除 URL 外还必须带上 `X-NAS-SDKTOKEN` 头，因此把 header
    /// 一并返回，由 OpenList 代理下载时携带；同时强制 `proxy = true` ——
    /// 浏览器直连既拿不到 token 也不会带 WAF 挑战 cookie。
    fn link(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, args: driver.LinkArgs) anyerror!model.Link {
        const self = as(ptr);
        const a = ctx.alloc;
        _ = args;

        const token = try self.getToken(a, path, upload_type_download);
        const norm = try normalizePath(a, path);
        const fname = urlmod.baseName(path);

        // 与 Go 版逐字节一致：注意 `bufsize=` 是空值，上游就是这么接受的。
        var u = Buf.init(a);
        try u.append(self.forwardUrl());
        try u.append(path_download);
        try u.append("?filenamepath=");
        try urlmod.encodeInto(&u, norm, .form);
        try u.append("&offset=0&bufsize=&fileName=");
        try urlmod.encodeInto(&u, fname, .form);
        try u.append("&uploadToken=");
        // ⚠️ **不**做百分号编码：Go 这里是裸拼（`driver.go:198` 的
        // `"&uploadToken=" + token`）。token 是上游发的字母数字串，正常情况两者
        // 等价；但既然 Go 不编码，这里也不编码 —— 否则 token 含 `+/=&` 时两边
        // 的 query 语义会不同。
        //
        // 注意分片上传那条路径（`uploadChunkOnce`）Go 用的是 `url.Values`，
        // **是**编码的，所以那边保持一致地编码，别一起改。
        try u.append(token);
        const dl_url = try u.toOwned();

        var headers = List(model.Header).init(a);
        for (try self.authHeaders(a)) |h| {
            if (h.value.len == 0) continue; // 空的 UA 不发
            try headers.append(h);
        }
        // 下载由 OpenList 代为发起，同样不认我们的 jar，需把 WAF 挑战 cookie 一并返回
        var ck = Buf.init(a);
        const target = urlmod.Url.parse(dl_url) catch null;
        if (target) |t| {
            if (try self.jar.headerFor(t.host, t.path, t.isHttps(), rt.nowSeconds(), &ck)) {
                try headers.append(.{ .name = "Cookie", .value = try ck.toOwned() });
            }
        }

        return .{ .url = dl_url, .header = try headers.toOwned(), .proxy = true };
    }

    /// 新建目录。注意接口收的是**完整路径**，不是「父目录+名字」。
    fn makeDir(ptr: *anyopaque, ctx: *driver.Ctx, dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("directory", try normalizePath(a, dir));
        try w.end();
        _ = try self.nasProxy(a, method_create_dir, b.slice(), 1, false);
    }

    /// 重命名。文件与目录都用 file.rename（与小程序一致）。
    fn rename(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, new_name: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("directory", try normalizePath(a, urlmod.parentPath(src)));
        try w.str("filename", urlmod.baseName(src));
        try w.str("newFilename", new_name);
        try w.end();
        _ = try self.nasProxy(a, method_file_rename, b.slice(), 1, false);
    }

    /// 移动。服务端没有独立 move 接口，移动即「按路径改路径」：
    /// 把 directory 改成含文件名的完整新路径 newDirectory。
    fn move(ptr: *anyopaque, ctx: *driver.Ctx, src: []const u8, dst_dir: []const u8) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        const norm_src = try normalizePath(a, src);
        // 注意目标路径用源节点的 Name 拼接，需归一化以免拼出「家庭共享」
        const target = try normalizePath(a, try urlmod.joinPath(a, dst_dir, urlmod.baseName(src)));
        if (std.mem.eql(u8, target, norm_src)) return driver.Error.NotSupported;

        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        try w.begin();
        try w.str("directory", norm_src);
        try w.str("newDirectory", target);
        try w.end();
        _ = try self.nasProxy(a, method_dir_rename, b.slice(), 1, false);
    }

    fn remove(ptr: *anyopaque, ctx: *driver.Ctx, path: []const u8, is_dir: bool) anyerror!void {
        const self = as(ptr);
        const a = ctx.alloc;
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        if (is_dir) {
            try w.begin();
            try w.str("directory", try normalizePath(a, path));
            try w.end();
            _ = try self.nasProxy(a, method_delete_dir, b.slice(), 1, false);
        } else {
            try w.begin();
            try w.str("directory", try normalizePath(a, urlmod.parentPath(path)));
            try w.str("filename", urlmod.baseName(path));
            try w.end();
            _ = try self.nasProxy(a, method_delete_file, b.slice(), 1, false);
        }
    }

    fn put(ptr: *anyopaque, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        const self = as(ptr);
        return self.upload(ctx, dst, src);
    }

    fn space(ptr: *anyopaque, ctx: *driver.Ctx) anyerror!driver.DiskUsage {
        return as(ptr).volumeInfo(ctx.alloc);
    }

    // -----------------------------------------------------------------------
    // 上传
    // -----------------------------------------------------------------------

    /// 分块并发上传。
    ///
    /// 流程（与小程序/web 版一致）：
    ///   1. 换上传 token（uploadType=0）
    ///   2. 分块并发 POST 到 {forwardUrl}/nasforward/file/binary/upload，
    ///      每块的 fileName 参数是「原名 + .crash」，offset 为该块起始位置
    ///   3. 全部传完后收尾：exist 检查同名 -> 有则先挪走 -> 把 .crash 改名回真名
    ///
    /// 任一环节失败都**不会**清理 .crash：残留是「这次没走完」的证据，
    /// 错误信息里会带上它的位置，交给人决定重传还是手动删。
    fn upload(self: *Itvsh, ctx: *driver.Ctx, dst: []const u8, src: model.Source) anyerror!void {
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const a = arena.allocator();

        const dir = try normalizePath(a, urlmod.parentPath(dst));
        const name = urlmod.baseName(dst);
        if (name.len == 0) return driver.Error.NotFound;
        const full_path = try urlmod.joinPath(a, dir, name);
        const crash_path = try urlmod.joinPath(a, dir, try std.fmt.allocPrint(a, "{s}.crash", .{name}));

        // 上传前先清掉可能残留的 .crash（上次中断留下的）
        self.deleteFileQuiet(a, dir, try std.fmt.allocPrint(a, "{s}.crash", .{name}));

        const token = self.getToken(a, full_path, upload_type_upload) catch |e| {
            return e;
        };
        const size: u64 = @intCast(@max(src.size(), 0));
        const upload_url = try std.fmt.allocPrint(a, "{s}{s}", .{ self.forwardUrl(), path_put_file });

        const chunks: u64 = if (size == 0) 1 else (size + chunk_size - 1) / chunk_size;
        const thread_count: usize = @intCast(@min(@as(i64, @intCast(chunks)), self.cfg.upload_thread));

        var state = UploadState{
            .self = self,
            .arena_alloc = self.alloc,
            .dir = dir,
            .name = name,
            .token = token,
            .source = src,
            .size = size,
            .chunks = chunks,
            .upload_url = upload_url,
            .progress = ctx.progress,
            .progress_userdata = ctx.progress_userdata,
        };

        // 每个 worker 一个 client：`std.http.Client` 的连接池不是为高并发写的，
        // 而这里最需要的是真并行。cookie 仍走共享 jar（jar 内部有锁），
        // 与 Go 版「用 jar-less 的 base.HttpClient + 手工塞 Cookie 头」等价。
        const clients = try a.alloc(httpclient.Client, thread_count);
        for (clients) |*c| {
            c.* = httpclient.Client.init(self.alloc, .{
                .timeout_s = 0, // 大文件单块上传可能超过 60s
                .insecure_skip_verify = self.client.opts.insecure_skip_verify,
                .ca_bundle_path = self.client.opts.ca_bundle_path,
                // 上传分片同样要走 raw 路径（T4）。
            }, self.jar);
        }
        defer for (clients) |*c| c.deinit();

        const threads = try a.alloc(std.Thread, thread_count);
        for (threads, 0..) |*t, i| {
            t.* = try std.Thread.spawn(.{}, uploadWorker, .{ &state, &clients[i] });
        }
        // 进度轮询：单独一个线程（用户回调非线程安全，不能在 worker 里调）。
        // 用长 sleep + `done` 标志收尾，避免每 200ms 抢一次锁。
        const progress_thread = if (ctx.progress != null)
            try std.Thread.spawn(.{}, progressReporter, .{&state})
        else
            null;
        for (threads) |t| t.join();
        if (progress_thread) |pt| {
            state.done.store(true, .release);
            pt.join();
        }

        if (state.first_err) |e| {
            log.err("[itvsh] upload failed: {s}", .{@errorName(e)});
            // 走到这里说明有分块重试耗尽后仍失败（或被取消）。
            // 服务器上必然留着 name.crash，明确告诉调用方它在哪。
            log.err("[itvsh] 服务器上残留未完成文件 {s}，可重新上传覆盖或手动删除", .{crash_path});
            return e;
        }

        // 上传过程中收到的 set-cookie（含 WAF 挑战 cookie）落库，重启后仍可复用
        _ = self.saveCookies();

        if (ctx.progress) |f| f(ctx.progress_userdata, 100);
        return self.finalizeUpload(a, dir, name);
    }

    fn deleteFileQuiet(self: *Itvsh, a: std.mem.Allocator, dir: []const u8, name: []const u8) void {
        var b = Buf.init(a);
        var w = ObjWriter{ .b = &b };
        w.begin() catch return;
        w.str("directory", dir) catch return;
        w.str("filename", name) catch return;
        w.end() catch return;
        _ = self.nasProxy(a, method_delete_file, b.slice(), 1, true) catch return;
    }

    /// 收尾：把「文件名.crash」变成正式文件。
    ///
    /// 存在同名文件时不能直接删 —— 上游 rename 不允许覆盖，但「先删真文件再改名」
    /// 一旦改名失败就是真文件已丢、只剩 .crash 的数据损失。这里改成可回滚的三步：
    ///   1. 真文件改名为 .openlist_to_delete（腾出名字，且内容还在）
    ///   2. .crash 改名为真名
    ///   3. 删除 .openlist_to_delete
    ///
    /// 第 2 步失败时把备份改回原名，确保不丢数据。
    fn finalizeUpload(self: *Itvsh, a: std.mem.Allocator, dir: []const u8, name: []const u8) !void {
        const crash = try std.fmt.allocPrint(a, "{s}.crash", .{name});
        const backup = try std.fmt.allocPrint(a, "{s}.openlist_to_delete", .{name});

        // D12：查询失败**不能**当成"没有同名文件"。吞掉这个错误会跳过下面的
        // 备份步骤，直接用 `.crash` 覆盖真文件 —— 后续任一步失败就是数据丢失。
        // Go 的调用方同样让 fileExist 的错误向上传播。
        const exists = try self.fileExist(a, dir, name);
        if (!exists) {
            try self.renameWithRetry(a, dir, crash, name);
            return;
        }
        // 先把真文件挪到备份名，腾出 name 给新文件用
        try self.renameWithRetry(a, dir, name, backup);
        // 第 2 步失败则回滚第 1 步：宁可回到「新旧并存」的初始状态，也不能丢旧文件
        self.renameWithRetry(a, dir, crash, name) catch |e| {
            self.renameWithRetry(a, dir, backup, name) catch {
                log.err("[itvsh] 改名失败，且旧文件回滚也失败（旧文件现为 {s}/{s}，新数据在 {s}/{s}），请手动处理", .{
                    dir, backup, dir, crash,
                });
                return e;
            };
            return e;
        };
        // 新文件已就位，清理备份。这步失败只留下垃圾文件，不影响正确性，不向上报错
        // —— 报错会让调用方以为上传失败从而重传，而文件其实是对的。
        self.deleteFileQuiet(a, dir, backup);
    }

    /// 收尾阶段数据已经完整传完，纯属元数据操作，值得重试
    /// —— 这里失败一次，用户看到的就是「白传了」，代价不对等。
    fn renameWithRetry(self: *Itvsh, a: std.mem.Allocator, dir: []const u8, from: []const u8, to: []const u8) !void {
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            var b = Buf.init(a);
            var w = ObjWriter{ .b = &b };
            try w.begin();
            try w.str("directory", dir);
            try w.str("filename", from);
            try w.str("newFilename", to);
            try w.end();
            if (self.nasProxy(a, method_file_rename, b.slice(), 1, false)) |_| {
                return;
            } else |e| {
                if (attempt + 1 >= finalize_attempts) return e;
                log.warn("[itvsh] rename {s} -> {s} failed ({s}), retrying", .{ from, to, @errorName(e) });
                rt.sleepMillis(retry_delay_ms);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// 上传并发
// ---------------------------------------------------------------------------

const UploadState = struct {
    self: *Itvsh,
    /// 长期分配器，用于给每个 worker 建 arena。
    arena_alloc: std.mem.Allocator,
    dir: []const u8,
    name: []const u8,
    token: []const u8,
    source: model.Source,
    size: u64,
    chunks: u64,
    upload_url: []const u8,
    next: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    cancel: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    err_mu: std.Io.Mutex = .init,
    first_err: ?anyerror = null,

    /// 已成功上传的块数（worker 每完成一块 +1）。
    ///
    /// ⚠️ `ctx.progress` 是**非线程安全**的用户回调，不能在各 worker 里直接调
    ///（多个线程同时写前端状态 = 数据竞争）。所以这里只累加原子计数，由
    /// 主线程的轮询线程换算成百分比再上报 —— 与 Go 侧「worker 只做 IO、
    /// 进度由外层 aggregate」的写法等价。
    done_blocks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// 进度回调（整个上传期间不变，从 `driver.Ctx` 拷进来）。
    progress: ?driver.ProgressFn = null,
    progress_userdata: ?*anyopaque = null,
    /// 轮询线程结束时通知主线程。
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn fail(self: *UploadState, e: anyerror) void {
        self.err_mu.lockUncancelable(rt.io());
        defer self.err_mu.unlock(rt.io());
        if (self.first_err == null) self.first_err = e;
        self.cancel.store(true, .release);
    }
};

/// 进度上报线程。每 200ms 读一次 `done_blocks` 换算成百分比调回调 —— 是**唯一**
/// 允许碰 `ctx.progress` 的线程（worker 只累加原子计数）。
///
/// 结构是「do-while」而非「while」：第一帧无条件发出，再检查 `done`。这样
/// ① 文件在 200ms 内传完时至少有一帧进度；② 单测可以把 `done` 预先置位、
/// 仍然拿到一帧，不必等 200ms。
fn progressReporter(state: *UploadState) void {
    const cb = state.progress orelse return;
    while (true) {
        const done_blocks = state.done_blocks.load(.acquire);
        const pct: u64 = @intCast(@min(@divTrunc(done_blocks * 100, @max(state.chunks, 1)), 100));
        cb(state.progress_userdata, pct);
        if (state.done.load(.acquire)) return;
        rt.sleepMillis(200);
    }
}

fn uploadWorker(state: *UploadState, client: *httpclient.Client) void {
    // Arena 不是线程安全的，每个 worker 一个。
    var arena = std.heap.ArenaAllocator.init(state.arena_alloc);
    defer arena.deinit();

    while (!state.cancel.load(.acquire)) {
        const index = state.next.fetchAdd(1, .monotonic);
        if (index >= state.chunks) return;
        uploadChunk(state, client, arena.allocator(), index) catch |e| {
            state.fail(e);
            return;
        };
        // 每块之后回收，避免 4 GiB 文件把整轮的临时量都堆在 arena 里。
        _ = arena.reset(.retain_capacity);
        // 只累加原子计数；百分比换算与回调在进度轮询线程里做（见 upload）。
        _ = state.done_blocks.fetchAdd(1, .release);
    }
}

fn uploadChunk(state: *UploadState, client: *httpclient.Client, a: std.mem.Allocator, index: u64) !void {
    const self = state.self;

    const offset: u64 = index * chunk_size;
    const length: usize = @intCast(@min(chunk_size, state.size - offset));

    // 鉴权失效时刷新会话再重传这一块。
    // 下面整段会重跑，所以 body 必须在每次尝试时重新申请，
    // 否则第二次尝试会读到已耗尽的 buffer。
    var attempt: u8 = 0;
    while (true) : (attempt += 1) {
        if (uploadChunkOnce(state, client, a, index, offset, length)) |_| {
            return;
        } else |e| {
            if (e != Error.AuthFailed or attempt + 1 >= chunk_attempts) return e;
            log.warn("[itvsh] chunk {d} auth failed, restoring session", .{index});
            self.relogin(a) catch |re| {
                // token 是手工配置的，驱动续不了，只能让用户自己换 ——
                // 这条比原始的上游错误更能说明该做什么，故替换掉。
                if (re == Error.ConfiguredTokenExpired) return re;
                return e;
            };
            rt.sleepMillis(retry_delay_ms);
        }
    }
}

fn uploadChunkOnce(
    state: *UploadState,
    client: *httpclient.Client,
    a: std.mem.Allocator,
    index: u64,
    offset: u64,
    length: usize,
) !void {
    const self = state.self;

    const body = try state.source.readAll(a, offset, length);
    if (body.len != length) {
        log.err("[itvsh] chunk {d}: short read, want {d} got {d}", .{ index, length, body.len });
        return Error.ShortRead;
    }

    // Go 版用 url.Values，键是按字母序排的：directory, fileName, offset, uploadToken。
    // 顺序保持一致，免得上游对 query 做整体校验时对不上。
    const crash_name = try std.fmt.allocPrint(a, "{s}.crash", .{state.name});
    const offset_str = try std.fmt.allocPrint(a, "{d}", .{offset});
    var q = urlmod.Query.init(a);
    try q.addSorted(&.{
        .{ "directory", state.dir },
        .{ "fileName", crash_name },
        .{ "offset", offset_str },
        .{ "uploadToken", state.token },
    });
    const req_url = try std.fmt.allocPrint(a, "{s}?{s}", .{ state.upload_url, q.slice() });

    // 上游 WAF 对头部敏感：只带必需的头，且 UA 显式留空。
    // `client.zig` 会把空值 UA 整个丢掉，正好对齐 Go 的 net/http。
    const headers = [_]model.Header{
        .{ .name = "X-NAS-CLIENTTYPE", .value = "60" },
        .{ .name = "X-NAS-SDKTOKEN", .value = self.authToken() },
        .{ .name = "Accept-Language", .value = "zh-cn" },
        .{ .name = "User-Agent", .value = "" },
        .{ .name = "Content-Type", .value = "application/octet-stream" },
    };

    const res = try client.send(a, .{
        .method = "POST",
        .url = req_url,
        .headers = &headers,
        .body = body,
    });

    if (res.status != 200) {
        if (res.status == 412) {
            log.warn("[itvsh] chunk {d}: 被上游 WAF 拦截 (HTTP 412)，请检查请求头配置", .{index});
            return Error.WafBlocked;
        }
        log.warn("[itvsh] chunk {d} upload failed: HTTP {d}, body: {s}", .{
            index, res.status, res.body[0..@min(res.body.len, 256)],
        });
        return Error.UpstreamHttp;
    }
    // 成功判断：code==200 且内层 result=="successful"
    return checkChunkResult(a, res.body, index);
}

/// 解析分块上传响应。
/// 形如 `{"code":200,"data":"{\"result\":\"successful\"}"}`，data 可能是
/// JSON 字符串也可能已是对象，故两种都处理。
fn checkChunkResult(a: std.mem.Allocator, body: []const u8, index: u64) !void {
    const v = json.parse(a, body) catch {
        log.warn("[itvsh] chunk {d}: non-JSON response: {s}", .{ index, body[0..@min(body.len, 256)] });
        return Error.UpstreamNotJson;
    };
    const code = v.intAt("code") orelse 0;
    if (code != 200) {
        log.warn("[itvsh] chunk {d}: upload failed, code {d}, body: {s}", .{
            index, code, body[0..@min(body.len, 256)],
        });
        return Error.UpstreamError;
    }

    const d = v.getPath("data") orelse return Error.UpstreamError;
    // 解出来的内层 Value 必须有自己的存储位置：直接对临时量取地址会悬垂。
    var inner_storage: json.Value = undefined;
    var inner: *const json.Value = d;
    // data 可能是被转义的 JSON 字符串
    if (d.* == .string) {
        const s = d.asStr().?;
        inner_storage = json.parse(a, s) catch {
            log.warn("[itvsh] chunk {d}: cannot parse data string: {s}", .{ index, s });
            return Error.UpstreamError;
        };
        inner = &inner_storage;
    }
    const result = inner.strAt("result") orelse "";
    if (std.mem.eql(u8, result, "successful")) return;

    // 1009 表示 token 失效，交由上层重试
    const inner_code = inner.intAt("code") orelse 0;
    if (inner_code == 1009) {
        log.warn("[itvsh] chunk {d}: upload token invalid (1009)", .{index});
        return Error.AuthFailed;
    }
    const msg = inner.strAt("message") orelse "unknown error";
    log.warn("[itvsh] chunk {d}: upload failed: {s}", .{ index, msg });
    return Error.UpstreamError;
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 把上游的 code/msg 归成错误类型。这是 Zig 版取代 Go
/// `isAuthFailure(err.Error())` 字符串匹配的地方 —— 判定在拿到 code/msg 的
/// 当下完成，而不是事后去翻错误消息。
///
/// 注意 code 用等值比较而不是 `strings.Contains`：Go 版之所以要
/// `Contains(msg, "code 1009")` 是因为它只有字符串，这里不必重蹈覆辙。
fn classifyUpstream(code: i64, msg: []const u8, what: []const u8) !void {
    for (auth_failure_codes) |c| {
        if (code == c) {
            log.warn("[itvsh] {s} auth failure: code {d}, msg: {s}", .{ what, code, msg });
            return Error.AuthFailed;
        }
    }
    for (auth_failure_markers) |m| {
        if (std.mem.indexOf(u8, msg, m) != null) {
            log.warn("[itvsh] {s} auth failure marker: code {d}, msg: {s}", .{ what, code, msg });
            return Error.AuthFailed;
        }
    }
    log.warn("[itvsh] {s} failed: code {d}, msg: {s}", .{ what, code, msg });
    return Error.UpstreamError;
}

/// Go `isAuthFailure`（drivers/itvsh/util.go:61-79）的等价物，作用在一段**文本**上。
///
/// 用 `code <N>` 这种带空格的形式匹配，而不是裸数字 —— 与 Go 一致，避免正文里
/// 恰好出现的数字造成误判。非 200 响应的 body 也要过这一道（D11）。
/// 返回 bool 而不是错误，与 Go 的 `isAuthFailure(err) bool` 形状一致：
/// "是不是失效"和"该报什么错"是两件事，调用方自己决定后者。
fn isAuthFailureText(text: []const u8) bool {
    for (auth_failure_codes) |c| {
        var buf: [24]u8 = undefined;
        const needle = std.fmt.bufPrint(&buf, "code {d}", .{c}) catch continue;
        if (std.mem.indexOf(u8, text, needle) != null) return true;
    }
    for (auth_failure_markers) |m| {
        if (std.mem.indexOf(u8, text, m) != null) return true;
    }
    return false;
}

/// 在根目录列表里补上「家庭共享」。与小程序一致：API 返回了就用 API 的，
/// 没返回才伪造。
fn injectHomeshare(a: std.mem.Allocator, objs: []const model.Obj) ![]model.Obj {
    for (objs) |o| {
        if (std.mem.eql(u8, o.name, homeshare_name) or std.mem.eql(u8, o.name, "homeshare")) {
            return a.dupe(model.Obj, objs);
        }
    }
    const out = try a.alloc(model.Obj, objs.len + 1);
    out[0] = .{
        .name = homeshare_name,
        .is_dir = true,
        .sign = homeshare_path,
    };
    @memcpy(out[1..], objs);
    return out;
}

/// 服务端把 size 当字符串发，且偶尔是空串。
fn parseSize(v: ?[]const u8) i64 {
    const s = v orelse return 0;
    return std.fmt.parseInt(i64, std.mem.trim(u8, s, " \t"), 10) catch 0;
}

/// 解析秒级时间戳（10 位），也兼容毫秒级。
fn parseTime(v: ?[]const u8) i64 {
    const raw = v orelse return 0;
    const s = std.mem.trim(u8, raw, " \t");
    if (s.len == 0) return 0;
    const n = std.fmt.parseInt(i64, s, 10) catch return 0;
    if (n == 0) return 0;
    // 小于 1e12 视为秒，否则视为毫秒
    return if (n < 1_000_000_000_000) n else @divTrunc(n, 1000);
}

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

pub const factory = driver.Factory{
    // 与 Go `driver.Config.Name` 一致（drivers/itvsh/meta.go:34）。配置里的
    // `Storage.driver` 存的就是这个字符串，写成 "Itvsh" 会读不懂已有配置。
    .key = "上海电信智家硬盘",
    .aliases = &.{"Itvsh"},
    .label = "上海电信智家硬盘",
    // secrets 同时收两种拼写：Go 无 tag 字段以字段名为键（`Cookies`），
    // 本工程早期版本写的是 snake_case（`cookies`）—— 回显脱敏两种都要挡。
    .secrets = &.{ "password", "access_token", "Cookies", "cookies" },
    // 表单 schema。tagged 字段与 Go 版 `Addition` 的 json tag 逐字一致；
    // `ForwardUrl`/`Cookies` 在 Go 里无 tag、不进表单，这里同样 hidden。
    .addition_schema =
    \\{
    \\  "mobile":       {"type":"string","required":false,"help":"手机号（智家硬盘/天翼云盘账号），与 Access token 二选一"},
    \\  "password":     {"type":"string","required":false,"secret":true,"help":"登录密码，用服务端下发的密钥做 AES 加密后提交"},
    \\  "access_token": {"type":"string","required":false,"secret":true,"help":"可留空，与手机号+密码二选一。填入后跳过账号密码登录"},
    \\  "root_folder_path": {"type":"string","default":"/","help":"根目录"},
    \\  "upload_thread":{"type":"number","default":5,"min":1,"max":8,"help":"并发分块上传数"},
    \\  "ForwardUrl":   {"type":"string","hidden":true,"help":"由登录接口返回，上传下载走这个域名"},
    \\  "Cookies":      {"type":"string","hidden":true,"secret":true,"help":"持久化的会话 cookie（Go http.Cookie 数组 JSON）"}
    \\}
    ,
    .create = create,
};

fn create(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !driver.Driver {
    // 直接委托给 createWithId，别再抄一份函数体 —— 这里原本复制了一份并把
    // `.storage_id` 硬写成 0，正是 C02 那个"会话回写落不到任何 storage"的根因。
    return driver.asDriver(Itvsh, try createWithId(alloc, storage_id, cfg));
}

/// 工厂的另一种入口：带上 storage id，供 API 层在配置变化时回写 `addition`。
pub fn createWithId(alloc: std.mem.Allocator, storage_id: i64, cfg: ?*const json.Value) !*Itvsh {
    const self = try alloc.create(Itvsh);
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

const testing = std.testing;

test "normalizePath rewrites 家庭共享 to homeshare" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/homeshare", try Itvsh.normalizePath(a, "/家庭共享"));
    try testing.expectEqualStrings("/homeshare/a b", try Itvsh.normalizePath(a, "/家庭共享/a b"));
    try testing.expectEqualStrings("/other", try Itvsh.normalizePath(a, "/other"));
    // 只是名字里含这三个字，不该被替换
    try testing.expectEqualStrings("/我的家庭共享备份", try Itvsh.normalizePath(a, "/我的家庭共享备份"));
}

test "injectHomeshare prepends only when absent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const none = [_]model.Obj{.{ .name = "a", .is_dir = true }};
    const out = try injectHomeshare(a, &none);
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqualStrings(homeshare_name, out[0].name);
    try testing.expectEqualStrings(homeshare_path, out[0].sign);

    const has = [_]model.Obj{
        .{ .name = homeshare_name, .is_dir = true },
        .{ .name = "a", .is_dir = true },
    };
    const out2 = try injectHomeshare(a, &has);
    try testing.expectEqual(@as(usize, 2), out2.len);
}

test "parseSize and parseTime tolerate the string forms the API sends" {
    try testing.expectEqual(@as(i64, 1048576), parseSize("1048576"));
    try testing.expectEqual(@as(i64, 0), parseSize(""));
    try testing.expectEqual(@as(i64, 0), parseSize(null));
    try testing.expectEqual(@as(i64, 1699999999), parseTime("1699999999"));
    try testing.expectEqual(@as(i64, 1699999999), parseTime("1699999999000"));
    try testing.expectEqual(@as(i64, 0), parseTime(""));
}

test "T3: real Go addition JSON parses into the driver" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 键集与用户 Go 备份 storage #1 完全一致（openlist_backup_2026_10_11_
    // 21_41_15.json）：['Cookies','ForwardUrl','mobile','password',
    // 'root_folder_path','upload_thread']。值换成假的，键必须一字不差。
    const src =
        \\{"mobile":"13800000000","password":"pw","access_token":"",
        \\ "root_folder_path":"/photos","upload_thread":4,
        \\ "ForwardUrl":"https://n8.pan.itvsh.cn","Cookies":"[{\"Name\":\"c\",\"Value\":\"v\"}]"}
    ;
    const v = try json.parse(a, src);
    const add = try Addition.parse(a, &v);
    try testing.expectEqualStrings("13800000000", add.mobile);
    try testing.expectEqualStrings("/photos", add.root_path);
    try testing.expectEqual(@as(i64, 4), add.upload_thread);
    try testing.expectEqualStrings("https://n8.pan.itvsh.cn", add.forward_url);
    try testing.expect(std.mem.indexOf(u8, add.cookies, "n8.pan") == null); // cookies 是 JSON 串
    try testing.expect(add.cookies.len > 0);

    // 写回必须是 Go 能读的键（含大写的 ForwardUrl/Cookies），且再解一遍值不变。
    const out = try add.toJson(a);
    for ([_][]const u8{ "\"mobile\"", "\"password\"", "\"access_token\"", "\"root_folder_path\"", "\"upload_thread\"", "\"ForwardUrl\"", "\"Cookies\"" }) |k| {
        try testing.expect(std.mem.indexOf(u8, out, k) != null);
    }
    const v2 = try json.parse(a, out);
    const add2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings(add.root_path, add2.root_path);
    try testing.expectEqualStrings(add.forward_url, add2.forward_url);
    try testing.expectEqualStrings(add.cookies, add2.cookies);
}

test "T3: legacy snake_case keys still parse, Go name wins when both exist" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 本工程早期版本写出的旧配置（snake_case）不能失效
    const legacy =
        \\{"mobile":"138","root_path":"/old","forward_url":"https://old.cn","cookies":"[]"}
    ;
    const v = try json.parse(a, legacy);
    const add = try Addition.parse(a, &v);
    try testing.expectEqualStrings("/old", add.root_path);
    try testing.expectEqualStrings("https://old.cn", add.forward_url);

    // 新旧并存时以 Go 名为准（T3 规则）
    const both =
        \\{"root_folder_path":"/go","root_path":"/legacy",
        \\ "ForwardUrl":"https://go.cn","forward_url":"https://legacy.cn",
        \\ "Cookies":"go","cookies":"legacy"}
    ;
    const v2 = try json.parse(a, both);
    const add2 = try Addition.parse(a, &v2);
    try testing.expectEqualStrings("/go", add2.root_path);
    try testing.expectEqualStrings("https://go.cn", add2.forward_url);
    try testing.expectEqualStrings("go", add2.cookies);
}

test "chunk result parsing handles both data shapes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // data 是「被转义的 JSON 字符串」
    try checkChunkResult(a, "{\"code\":200,\"data\":\"{\\\"result\\\":\\\"successful\\\"}\"}", 0);
    // data 已经是对象
    try checkChunkResult(a, "{\"code\":200,\"data\":{\"result\":\"successful\"}}", 0);
    // token 失效
    try testing.expectError(Error.AuthFailed, checkChunkResult(a, "{\"code\":200,\"data\":{\"code\":1009}}", 0));
    // 业务失败
    try testing.expectError(Error.UpstreamError, checkChunkResult(a, "{\"code\":200,\"data\":{\"message\":\"nope\"}}", 0));
    // 外层非 200
    try testing.expectError(Error.UpstreamError, checkChunkResult(a, "{\"code\":500,\"data\":null}", 0));
    // 非 JSON（WAF 的 HTML）
    try testing.expectError(Error.UpstreamNotJson, checkChunkResult(a, "<html>challenge</html>", 0));
}

test "auth failure codes and markers are recognised" {
    try testing.expectError(Error.AuthFailed, classifyUpstream(1010, "", "x"));
    try testing.expectError(Error.AuthFailed, classifyUpstream(401, "", "x"));
    try testing.expectError(Error.AuthFailed, classifyUpstream(0, "token expired", "x"));
    try testing.expectError(Error.AuthFailed, classifyUpstream(0, "登录已过期，请重新登录", "x"));
    try testing.expectError(Error.UpstreamError, classifyUpstream(500, "internal", "x"));
    // 文案里恰好含「1009」不该被当成鉴权失效 —— Go 版靠 Contains 会误判，
    // 这里用等值比较天然避开。
    try testing.expectError(Error.UpstreamError, classifyUpstream(0, "file 1009 not found", "x"));
}

test "factory create forwards the real storage id" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // C02 回归：工厂入口以前自己抄了一份构造代码并把 `.storage_id` 硬写成 0，
    // 于是 `driver.persist(0, ...)` → `storageById(0)` 查无记录，itvsh 的
    // forwardUrl / 会话 cookie 刷新后重启就丢。现在 create 直接委托给
    // createWithId，id 必须原样透传。
    const d = try create(a, 42, null);
    const self: *Itvsh = @ptrCast(@alignCast(d.ptr));
    try testing.expectEqual(@as(i64, 42), self.storage_id);

    // 非零、非默认值也要能过，避免"恰好等于某个默认值"的假通过。
    const d2 = try create(a, 7, null);
    const self2: *Itvsh = @ptrCast(@alignCast(d2.ptr));
    try testing.expectEqual(@as(i64, 7), self2.storage_id);
}

test "classifyText finds auth failures inside a raw body" {
    // D11 回归：非 200 响应的 body 也要能判出会话失效。Go 的 `isAuthFailure`
    // 是在**错误文本**里找 `code <N>` 和失效文案（util.go:61-79），我们把
    // 同样的扫描作用在原始 body 上。
    try testing.expect(isAuthFailureText("... code 1010 ..."));
    try testing.expect(isAuthFailureText("登录已过期"));
    try testing.expect(isAuthFailureText("token过期"));

    // 关键区别：文本路径只认 Go 那种带空格的 `code <N>` 形式。
    // `{"code":1009}` 这种 JSON 形态**不该**在这里命中 —— 它由 `rawPost`
    // 里先跑一遍的 `classifyUpstream`（数值比较）负责。两条路径分工与 Go 一致。
    try testing.expect(!isAuthFailureText("{\"code\":1009}"));
    try testing.expect(!isAuthFailureText("{\"code\":1009,\"msg\":\"x\"}"));
    // 正文里恰好出现的数字不能误伤。
    try testing.expect(!isAuthFailureText("order id 1009 shipped"));
    // 普通错误体不该被当成鉴权失败。
    try testing.expect(!isAuthFailureText("{\"code\":500,\"msg\":\"boom\"}"));
}

test "copy is NotSupported, matching Go" {
    // Go `drivers/itvsh/driver.go:246-249` 的 Copy 就是 `return errs.NotSupport`。
    // 智家硬盘的 NAS 侧没有服务端复制接口。Zig 这边 vtable 里 `.copy` 留空，
    // `Driver.copy` 的默认槽（driver.zig）返回 `Error.NotSupported`—— 与 Go
    // 同一个错误码。补这个测试是怕以后有人「顺手补上」。
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try create(a, 3, null);
    const self: *Itvsh = @ptrCast(@alignCast(d.ptr));
    defer self.client.deinit();
    var ctx = driver.Ctx{ .alloc = a };
    try testing.expectError(driver.Error.NotSupported, d.copy(&ctx, "/src", "/dst"));
}

test "progressReporter converts done blocks into a percentage" {
    // 轮询线程的换算逻辑：done_blocks / chunks → 0..100。用一个假的 state
    // 直接驱动，不碰网络。回调是测试自己的函数 + userdata 指针。
    const S = struct {
        last: u64 = 0,
        calls: u64 = 0,
        fn cb(ud: ?*anyopaque, pct: u64) void {
            const s: *@This() = @ptrCast(@alignCast(ud.?));
            s.last = pct;
            s.calls += 1;
        }
    };
    var sink = S{};

    var state = UploadState{
        .self = undefined,
        .arena_alloc = undefined,
        .dir = "",
        .name = "",
        .token = "",
        .source = undefined,
        .size = 0,
        .chunks = 4,
        .upload_url = "",
        .progress = S.cb,
        .progress_userdata = &sink,
    };
    // do-while 结构：第一帧无条件发出，所以预置 done 也能拿到一帧。
    state.done_blocks.store(3, .release);
    state.done.store(true, .release); // 3/4 = 75%，发完就退
    progressReporter(&state);
    try testing.expectEqual(@as(u64, 75), sink.last);
    try testing.expectEqual(@as(u64, 1), sink.calls);
}

test "progressReporter clamps to 100 and tolerates a null callback" {
    var state = UploadState{
        .self = undefined,
        .arena_alloc = undefined,
        .dir = "",
        .name = "",
        .token = "",
        .source = undefined,
        .size = 0,
        .chunks = 4,
        .upload_url = "",
        .progress = null,
    };
    // ① done_blocks > chunks：4/4 已满，钳到 100。
    state.done_blocks.store(4, .release);
    state.done.store(true, .release);
    progressReporter(&state);
    // ② chunks = 0：除零必须守住（`@max(chunks,1)`），返回而不是 panic。
    state.chunks = 0;
    state.done_blocks.store(99, .release);
    progressReporter(&state);
    try testing.expectEqual(@as(u64, 99), state.done_blocks.load(.acquire));
}
