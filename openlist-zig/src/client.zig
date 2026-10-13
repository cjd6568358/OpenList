//! HTTP client used by drivers to talk to upstream cloud APIs.
//!
//! ---------------------------------------------------------------------------
//! VERSION SENSITIVITY — read before editing
//! ---------------------------------------------------------------------------
//! Everything below `Client.send` is the ONLY place in this project that
//! touches `std.http`, and 0.17 rewrote that module a second time:
//!
//!   * the entry point is `Client.request(method, uri, RequestOptions)` — the
//!     old `open()` and its `server_header_buffer` are gone;
//!   * sending is explicit: `sendBodiless()` for no body, `sendBody(buf)` to get
//!     a `BodyWriter` for one, and `receiveHead(redirect_buf)` to get the
//!     response *before* its body;
//!   * `Request.Headers` gained typed slots (`user_agent`, `accept_encoding`, …)
//!     each of which can be `.default`, `.omit` or `.override(v)`. That matters
//!     here: std would otherwise inject `user-agent: zig/<ver> (std.http)` and
//!     an empty `accept-encoding`, and itvsh's WAF rejects any request that
//!     carries a User-Agent at all — so both slots are explicitly `.omit` and
//!     the real values travel through `extra_headers`.
//!
//! This is the file most likely to need a touch-up when bumping Zig again.
//!
//! The public surface — `Client.send(Request) Response` — is deliberately
//! version-stable so that drivers never change.
//!
//! ---------------------------------------------------------------------------
//! Why not `std.http.Client.fetch`?
//! ---------------------------------------------------------------------------
//! `fetch` swallows response headers we cannot live without: itvsh's session
//! lives in `Set-Cookie`, and the WAF challenge cookie must be captured on
//! *every* response including 412s. `fetch` also follows redirects
//! automatically, which is wrong for the itvsh download endpoint (a 302 there
//! means "token rejected", not "follow me"). So we drive the request
//! explicitly.

const std = @import("std");
const builtin = @import("builtin");
const Buf = @import("util/buf.zig").Buf;
const List = @import("util/buf.zig").List;
const model = @import("model.zig");
const json = @import("util/json.zig");
const Jar = @import("cookiejar.zig").Jar;
const urlmod = @import("util/url.zig");
const log = @import("log.zig");
const rt = @import("rt.zig");

pub const Header = model.Header;

pub const Request = struct {
    method: []const u8 = "GET",
    url: []const u8,
    headers: []const Header = &.{},
    /// In-memory body. Mutually exclusive with `source`.
    body: []const u8 = "",
    /// Streaming body. Preferred for uploads: a 4 GiB WebDAV PUT must not be
    /// materialised in RAM, and `itvsh` already hands us a seekable source.
    source: ?model.Source = null,
    /// Total length of `source`. Required — HTTP/1.1 needs either this or
    /// chunked encoding, and `std.http.Client` only does the former.
    content_length: ?u64 = null,
    /// Follow 3xx automatically. Off by default: see the note above.
    follow_redirects: bool = false,
    /// Maximum redirect hops when `follow_redirects` is set.
    max_redirects: u8 = 5,
    /// When false, the cookie jar is neither read nor written for this call.
    use_cookies: bool = true,
    /// 只读响应头，**不读响应体**，直接返回空 body。
    ///
    /// 对齐 Go 的 gowebdav：`pkg/gowebdav/requests.go` 的 `req()` 返回
    /// `*http.Response` 后，调用方（Delete / Mkdir / Rename）**只看 StatusCode，
    /// 从不读 body**。这不是偷懒，而是必要的：
    ///
    /// 坚果云（`dav.jianguoyun.com`）对 DELETE 返回 **204 且不带 Content-Length
    /// 也不带 chunked** —— 响应体没有定界。keep-alive 下谁去读正文谁就会
    /// 一直阻塞到超时（真机：60 秒后 `ReadFailed`，但**删除其实已经成功了**，
    /// API 却返回 500，用户以为没删掉）。不读 body 就没有这个问题。
    ///
    /// 只给「结果完全由状态码决定」的操作用（DELETE / MKCOL / MOVE / COPY）。
    skip_body: bool = false,
    /// 完全不发 `Content-Type` 头。
    ///
    /// 默认策略是「有 body 就补一个 `Content-Type`」，但这条规则对**预签名 URL**
    /// 是错的：阿里云 OSS 的预签名 URL 把 `Content-Type` 算进了签名串
    /// （OSS V1 签名 = VERB + Content-MD5 + Content-Type + Expires + ...），
    /// 多一个头就 403 `SignatureDoesNotMatch`。
    /// 上游 `drivers/aliyundrive_open/upload.go` 用的是裸 `http.Client`，
    /// 一个额外头都不加。
    omit_content_type: bool = false,
};

pub const Response = struct {
    status: u16,
    /// Response headers, in arrival order. Multiple `Set-Cookie` values are
    /// all present — never collapsed into one comma-joined value, which would
    /// corrupt cookies containing commas in their Expires attribute.
    headers: []Header,
    body: []const u8,

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn all(self: Response, alloc: std.mem.Allocator, name: []const u8) ![]const []const u8 {
        var l = List([]const u8).init(alloc);
        defer l.deinit();
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) try l.append(h.value);
        }
        return l.toOwned();
    }

    pub fn isOk(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }
};

pub const Options = struct {
    /// socket 收发超时（秒）。0 = 不超时。
    ///
    /// **N01 已修**：这个值现在**真的生效** —— 以 SO_RCVTIMEO / SO_SNDTIMEO
    /// 挂在连接上，是**每次系统调用**的上限，不是整个请求的上限。
    /// 所以分片上传不会被误杀（每次 write 都很快），而「上游不响应」的读
    /// 最多阻塞这么多秒就失败。
    timeout_s: u32 = 60,
    /// Accept invalid TLS certificates. Mirrors OpenList's
    /// `tls_insecure_skip_verify`; users behind a TLS-inspecting middlebox
    /// need it, and so do we for local debugging.
    insecure_skip_verify: bool = false,
    /// Path to a PEM bundle. Empty means "use the built-in roots".
    ca_bundle_path: []const u8 = "",
    /// 对齐 Go 的 `base.UserAgent`（internal/base/client.go）：Go 的
    /// `base.NewRestyClient()` 会 `SetHeader("user-agent", UserAgent)`，所以
    /// 所有驱动默认发的都是这个伪装成浏览器的串，而不是 "openlist/xxx"。
    /// 部分网盘的 WAF 只认浏览器形态的 UA，用标识性 UA 会被直接丢包。
    /// 个别驱动（itvsh）会显式传空串覆盖它 —— 那是**对齐 Go 的做法**，
    /// Go 那边也是用 pre-request hook 把 UA 清空的。
    user_agent: []const u8 = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30",
    /// M02：响应体上限（字节）。0 = 不限制。
    ///
    /// 当前实现把整个响应读进内存，大文件下载走的是"先整体缓冲再切窗口"，
    /// 所以默认必须保持不限制，否则会打断正常下载。这个旋钮是给部署方兜底的：
    /// 在内存很小的设备上，可以设一个上限，让失控的上游响应以
    /// `error.ResponseTooLarge` 明确失败，而不是把设备吃光。
    max_response_bytes: usize = 0,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    jar: *Jar,
    inner: std.http.Client,
    /// Guards `inner`: `std.http.Client` shares one connection pool and is
    /// documented as not thread-safe, but uploads run N chunk workers in
    /// parallel. Serialising at this level keeps the pool usable; the
    /// alternative (one Client per worker) throws away every TLS session.
    lock: std.Io.Mutex = .init,
    /// N01：被配置了、但本实现无法兑现的选项名。非 null 时 `send()` 直接
    /// 返回 `error.UnsupportedOption`。
    ///
    /// 以前 `timeout_s` / `insecure_skip_verify` / `ca_bundle_path` 三个字段
    /// 只是被解析出来，`init`/`send` 一个都没消费 —— 配置存在，保护却没生效。
    /// 尤其是 `insecure_skip_verify`：用户以为关掉了证书校验，实际仍在校验，
    /// 排障时只会看到莫名的证书错误。宁可直接报错，也不要静默忽略。
    unsupported: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, opts: Options, jar: *Jar) Client {
        var c = Client{
            .allocator = allocator,
            .opts = opts,
            .jar = jar,
            // `std.http.Client` must be told which `Io` opens its sockets now.
            .inner = .{ .allocator = allocator, .io = rt.io() },
        };

        // 自定义 CA bundle：这个是能真正兑现的，加载进 std 的证书包。
        //
        // ⚠️ 顺序很关键：必须先扫系统根、再加自定义证书。`ensureCaBundle()` 会
        // 在首次 TLS 请求前把系统根扫进 `ca_bundle`；如果这里只加自定义证书而不
        // 先把系统根准备好，`ensureCaBundle` 就会**用一份全新的系统 bundle 覆盖
        // 掉它**，自定义 CA 静默丢失（本工程真机复现过：配了 `ca_bundle_path`
        // 仍然 `TlsInitializationFailed`）。所以这里扫完系统根、加上自定义证书，
        // 再置 `now`，让 `ensureCaBundle` 直接跳过。
        if (opts.ca_bundle_path.len > 0) {
            const now = std.Io.Clock.real.now(rt.io());
            c.inner.ca_bundle.rescan(allocator, rt.io(), now) catch |e| {
                log.warn("client: cannot load system root certificates: {s}", .{@errorName(e)});
            };
            c.inner.ca_bundle.addCertsFromFilePathAbsolute(
                allocator,
                rt.io(),
                now,
                opts.ca_bundle_path,
            ) catch |e| {
                log.err("client: cannot load ca_bundle_path {s}: {s}", .{ opts.ca_bundle_path, @errorName(e) });
                c.unsupported = "ca_bundle_path";
            };
            c.inner.now = now;
        }

        // `std.http.Client` 没有"跳过证书校验"的开关。
        //
        // 这里**只告警、不硬失败**：忽略这个开关时，证书校验是**开着**的 ——
        // 那是更安全的状态，不是更危险的。硬失败反而会让本来能用的配置（自签
        // 证书但证书其实有效）整个不可用，而且用户只会看到"驱动挂了"，很难
        // 联想到是这个字段引起的。所以：日志里说清楚，然后照常走校验 ——
        // 证书真有问题时，用户会看到明确的 TLS 错误。
        if (opts.insecure_skip_verify) {
            log.warn("client: `insecure_skip_verify` cannot be honoured by this build " ++
                "(std.http.Client has no TLS-verification opt-out); requests will still " ++
                "verify certificates and may fail with a TLS error", .{});
        }

        return c;
    }

    pub fn deinit(self: *Client) void {
        self.inner.deinit();
    }

    /// Send one request. The returned `Response` borrows from `arena`, so the
    /// arena must outlive it — which it does, since callers pass the
    /// per-request arena.
    pub fn send(self: *Client, arena: std.mem.Allocator, req: Request) !Response {
        // N01：配置了做不到的选项就明确失败，不要静默按默认行为跑。
        if (self.unsupported) |name| {
            log.err("client: refusing request: unsupported option `{s}` is configured", .{name});
            return error.UnsupportedOption;
        }
        var current_url = req.url;
        var method = req.method;
        var hops: u8 = 0;
        var body = req.body;
        var source = req.source;
        var content_length = req.content_length;
        var retried_fresh = false;

        while (true) {
            const maybe = self.sendOnce(arena, method, current_url, req, body, source, content_length);

            const res = maybe catch |e| {
                // 连接池里的空闲连接被服务端回收之后，复用它只会读到 **0 字节**
                // 就 EOF，std 报 `HttpConnectionClosing`（见 std/http.zig:403，
                // 注释自己写着「happens when a keep-alive connection is finally
                // closed」）。Go 的 net/http 对这种情况会在**新连接**上重试一次
                // —— idle 连接被上游回收是常态，不是错误。
                //
                // 不重试的后果在真机上非常隐蔽：189/itvsh 这类会主动回收长连接的
                // 上游会**随机**失败，且报错看起来和网络无关。
                if (e == error.HttpConnectionClosing and !retried_fresh) {
                    retried_fresh = true;
                    log.debug("client: pooled connection was closed by the peer; retrying on a fresh connection", .{});
                    self.dropPooledConnections();
                    continue;
                }
                // N01：socket 超时在 std 里只表现为笼统的 `ReadFailed`，对运维
                // 完全没有指向性。这里补一条带上下文的日志 —— 真机上
                // `/aliyun` 挂死时日志里一个字都没有，排查全靠猜。
                if (self.opts.timeout_s > 0 and
                    (e == error.ReadFailed or e == error.WriteFailed or e == error.Timeout))
                {
                    log.warn("client: {s} {s} failed after at most {d}s: {s} " ++
                        "(upstream did not respond; raise Options.timeout_s if this is a slow call)", .{
                        method, current_url, self.opts.timeout_s, @errorName(e),
                    });
                }
                return e;
            };
            if (!req.follow_redirects) return res;
            switch (res.status) {
                301, 302, 303, 307, 308 => {
                    if (hops >= req.max_redirects) return error.TooManyRedirects;
                    const loc = res.header("Location") orelse return res;
                    current_url = try absolutize(arena, current_url, loc);
                    hops += 1;
                    // 303, and the de-facto behaviour for 301/302 on POST,
                    // downgrade to GET and drop the body.
                    if (res.status == 303 or (method.len == 4 and std.mem.eql(u8, method, "POST") and res.status != 307 and res.status != 308)) {
                        method = "GET";
                        body = "";
                        source = null;
                        content_length = null;
                    }
                    continue;
                },
                else => return res,
            }
        }
    }

    /// 统一的「组头」逻辑，`sendOnce`（std 路径）与 `sendRawOnce`（自写路径）
    /// 共用同一份 —— 两条路径的默认头必须完全一致，否则 T4 那种「换条路径就
    /// 变行为」的问题会再次出现，而且极难发现。
    fn buildHeaders(
        self: *Client,
        arena: std.mem.Allocator,
        parsed: urlmod.Url,
        req: Request,
        body: []const u8,
        source: ?model.Source,
    ) ![]const Header {
        var hdrs = List(Header).init(arena);
        // Caller headers first so they can override our defaults.
        for (req.headers) |h| try hdrs.append(h);
        const has = struct {
            fn f(hs: []const Header, name: []const u8) bool {
                for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
                return false;
            }
        }.f;
        if (!has(hdrs.slice(), "User-Agent")) {
            // An EMPTY User-Agent is meaningful for itvsh: its WAF rejects any
            // request that carries a UA, so the driver passes "" explicitly
            // and we must not overwrite it with our default.
            try hdrs.append(.{ .name = "User-Agent", .value = self.opts.user_agent });
        }
        if (!has(hdrs.slice(), "Accept-Encoding")) {
            try hdrs.append(.{ .name = "Accept-Encoding", .value = "identity" });
        }
        // `omit_content_type`：预签名 URL 场景下一个 Content-Type 都不能带，
        // 否则签名不匹配（见 Request.omit_content_type 的注释）。
        if (body.len > 0 and !req.omit_content_type and !has(hdrs.slice(), "Content-Type")) {
            try hdrs.append(.{ .name = "Content-Type", .value = "application/json" });
        }
        if (source != null and !has(hdrs.slice(), "Content-Type")) {
            try hdrs.append(.{ .name = "Content-Type", .value = "application/octet-stream" });
        }
        if (req.use_cookies) {
            var cbuf = Buf.init(arena);
            if (try self.jar.headerFor(parsed.host, parsed.path, parsed.isHttps(), rt.nowSeconds(), &cbuf)) {
                try hdrs.append(.{ .name = "Cookie", .value = try cbuf.toOwned() });
            }
        }
        return hdrs.slice();
    }

    /// 把响应里的 `Set-Cookie` 写回 cookie jar。两条路径共用。
    fn captureCookies(self: *Client, parsed: urlmod.Url, headers: []const Header) void {
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "Set-Cookie")) {
                self.jar.setFromResponse(parsed.host, parsed.path, h.value, rt.nowSeconds()) catch {};
            }
        }
    }

    fn sendOnce(
        self: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        raw_url: []const u8,
        req: Request,
        body: []const u8,
        source: ?model.Source,
        content_length: ?u64,
    ) !Response {
        const parsed = try urlmod.Url.parse(raw_url);
        const hdrs = try self.buildHeaders(arena, parsed, req, body, source);

        const m = try parseMethod(method);

        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());

        var http_req = self.inner.request(m, try toStdUri(raw_url), .{
            .extra_headers = try stdHeaders(arena, hdrs),
            // `skip_body` 的请求必须**不用 keep-alive**：
            // `Request.deinit()` 为了复用连接会调 `discardRemaining()` 把没读的
            // 正文排空（std/http/Client.zig:891-897）。坚果云 DELETE 返回的 204
            // **没有任何定界头**，这个排空会一直阻塞到 socket 超时 —— 真机实测
            // 每次删除都要 60 秒，而且看不到任何超时日志（因为错误发生在
            // deinit 里，不在 sendOnce 里）。发 `connection: close` 后服务端
            // 关连接，排空立刻 EOF 返回。
            //
            // 这也和 Go 的实际效果一致：gowebdav 从不读 body，Go 的 transport
            // 也就不会复用那条连接。
            .keep_alive = !req.skip_body,
            // `send()` 自己实现重定向策略：它要看到状态码才能决定「POST 是否
            // 降级成 GET」。
            //
            // ⚠️ 必须是 `.unhandled`，**不能**是 `.not_allowed`。Zig 0.17 的
            // 语义反直觉：`.not_allowed` 遇到任何 3xx 会直接 **`return
            // error.TooManyHttpRedirects`**（std/http/Client.zig:1177-1184），
            // 而不是把 3xx 响应交回来；只有 `.unhandled` 才会原样返回响应。
            // 189pc 的登录要自己跟跳并读 `Location`，走 `.not_allowed` 会在
            // 第一步就失败（真机：`init failed: TooManyHttpRedirects`）。
            .redirect_behavior = .unhandled,
            // See the file header: std's own UA would be a duplicate at best
            // and a WAF trip at worst, and std's empty `accept-encoding` is
            // useless to us (we send `identity` explicitly).
            .headers = .{ .user_agent = .omit, .accept_encoding = .omit },
        }) catch |e| {
            log.debug("client: request {s} {s} failed: {s}", .{ method, raw_url, @errorName(e) });
            return e;
        };
        defer http_req.deinit();

        // N01：std 的 request 路径没有超时入口，必须自己挂到 socket 上，
        // 否则上游不响应就会永久阻塞。详见 applySocketTimeout 的注释。
        if (http_req.connection) |c| applySocketTimeout(c, self.opts.timeout_s);

        const total_len: u64 = if (source) |_| (content_length orelse 0) else body.len;
        if (total_len > 0) {
            http_req.transfer_encoding = .{ .content_length = total_len };
            var send_buf: [16 * 1024]u8 = undefined;
            var bw = try http_req.sendBody(&send_buf);
            if (source) |src| {
                try writeSource(arena, &bw.writer, src, total_len);
            } else {
                try bw.writer.writeAll(body);
            }
            try bw.end();
            // ⚠️ **T4 根因**：`BodyWriter.end()` 只 flush 到 `http_protocol_output`
            // （TLS 情况下是 `tls.client.writer`），**不 flush 底层的 stream
            // writer**。明文连接下 writer 是直写 socket 的，看不出问题；TLS 下
            // 加密后的记录就留在 stream 缓冲里永远发不出去 —— 服务端只收到
            // 头、`Content-Length` 却等不到正文，最后超时断开，我们这边表现为
            // `HttpConnectionClosing`（读到 0 字节即 EOF）。
            //
            // 实测证据：本地 TLS 监听器收到的请求是 175 字节、**只有头没有
            // `{}`**；同一份代码换成明文连接，正文正常发出。
            // std 自己的 `sendBodyComplete` 也是这么做的：`bw.end()` 之后
            // 再补一次 `r.connection.?.flush()`。
            try http_req.connection.?.flush();
        } else if (methodRequestHasBody(m)) {
            // POST/PUT/PATCH with an empty body still needs the body code path:
            // `std.http.Request.sendBodiless` asserts `!method.requestHasBody()`,
            // so routing these through it is a debug-mode panic and undefined
            // behaviour in release builds. An explicit `Content-Length: 0` is
            // also what Go's net/http sends for a nil body, so this matches the
            // upstream drivers' wire format exactly.
            http_req.transfer_encoding = .{ .content_length = 0 };
            var send_buf: [16 * 1024]u8 = undefined;
            var bw = try http_req.sendBody(&send_buf);
            try bw.end();
        } else {
            try http_req.sendBodiless();
        }

        var redirect_buf: [8 * 1024]u8 = undefined;
        var resp = try http_req.receiveHead(&redirect_buf);

        const status: u16 = @intFromEnum(resp.head.status);

        // Capture Set-Cookie before reading the body: a WAF can close the
        // connection early and we still want the challenge cookie. The head
        // bytes are invalidated the moment the body reader is created, so the
        // copies below are not merely a convenience.
        var out_headers = List(Header).init(arena);
        var it = resp.head.iterateHeaders();
        while (it.next()) |h| {
            try out_headers.append(.{
                .name = try arena.dupe(u8, h.name),
                .value = try arena.dupe(u8, h.value),
            });
        }
        if (req.use_cookies) self.captureCookies(parsed, out_headers.slice());

        if (self.opts.max_response_bytes > 0) {
            const n = resp.head.content_length orelse 0;
            if (n > self.opts.max_response_bytes) {
                log.warn("client: {s} declares {d} bytes, over max_response_bytes={d}", .{
                    raw_url, n, self.opts.max_response_bytes,
                });
                return error.ResponseTooLarge;
            }
        }

        var body_buf = Buf.init(arena);

        // `skip_body`：结果只看状态码，不读正文（见 Request.skip_body 的注释）。
        // 对齐 Go 的 gowebdav —— 它能挂在「响应体没有定界」的上游上不阻塞，
        // 就是因为从来不读 body。
        if (req.skip_body) {
            return .{
                .status = status,
                .headers = try out_headers.toOwned(),
                .body = "",
            };
        }

        // M02：读失败必须上抛。以前只记一条 debug，然后把**残缺的 body 当作
        // 成功响应**返回（状态码还是上游那个 200）—— 调用方会对半截 JSON 做
        // 解析，得到静默错误的结果：截断的目录列表被当成完整列表、截断的
        // token 被当成有效 token。Go 的 `io.ReadAll` 会把错误交给调用方。
        //
        // 正常读到 EOF 不会走这里（`readBody` 以 `n == 0` 正常收尾）。
        readBody(&resp, &body_buf, self.opts.max_response_bytes) catch |e| {
            log.warn("client: body read failed for {s}: {s}", .{ raw_url, @errorName(e) });
            return e;
        };

        return .{
            .status = status,
            .headers = try out_headers.toOwned(),
            .body = try body_buf.toOwned(),
        };
    }

    // -----------------------------------------------------------------------
    // 自定义 HTTP 方法（WebDAV）
    // -----------------------------------------------------------------------

    /// 发送一个**非标准 HTTP 方法**的请求：WebDAV 的 `PROPFIND` / `MKCOL` /
    /// `MOVE` / `COPY` / `PROPPATCH` 等。
    ///
    /// 为什么必须单开一条路：`std.http.Method` 是一个**固定枚举**
    /// （GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH/QUERY），
    /// 而 `std.http.Client` 用 `@tagName(r.method)` 序列化方法名，没有传自定义
    /// 方法字符串的口子。以前 `parseMethod` 写的是 `stringToEnum(...) orelse .GET`，
    /// 于是**所有 WebDAV 方法都被静默降级成 GET**。
    ///
    /// 真机证据（2026-10-11）：`PROPFIND https://app.koofr.net/dav/Koofr/ -> HTTP 405`，
    /// 而 curl 用同样的凭据发真 PROPFIND 得到的是 207、不带凭据是 401 —— 405 只可能
    /// 来自「方法不对」。
    ///
    /// 实现上直接拿 `Connection` 的裸读写接口自己拼 HTTP/1.1，并强制
    /// `Connection: close`：服务端关连接之后「读到 EOF」就是完整响应，不必处理
    /// keep-alive 的边界。
    /// 公开入口：给 WebDAV 这类需要**自定义 HTTP 方法**的调用方用。
    /// 它只是 `sendRawOnce` 的一层薄包装 —— 组头、cookie、响应解析全在那边，
    /// 与 `send()` 走同一份实现。
    pub fn sendRaw(
        self: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        raw_url: []const u8,
        headers: []const Header,
        body: []const u8,
    ) !Response {
        return self.sendRawOnce(arena, method, raw_url, .{
            .method = method,
            .url = raw_url,
            .headers = headers,
            .body = body,
            // WebDAV 走 Basic 认证，不需要 cookie jar。
            .use_cookies = false,
        }, body, null, null);
    }

    /// 自己拼 HTTP/1.1 的实现。
    ///
    /// 存在的唯一理由：`std.http.Method` 是固定枚举，不含 WebDAV 的
    /// PROPFIND/MKCOL/MOVE/COPY/PROPPATCH，而 `std.http.Client` 用
    /// `@tagName(r.method)` 序列化方法名，没有传自定义方法的口子。
    ///
    /// 注意：它**不再**是 itvsh / 189pc 的绕行方案 —— 那条路上真正的问题是
    /// `BodyWriter.end()` 之后没 flush 底层 stream，导致 TLS 下正文发不出去，
    /// 已在本文件 `sendOnce` 里修掉（见那里的注释）。
    ///
    /// 强制 `Connection: close`：服务端关连接后「读到 EOF」就是完整响应，
    /// 不必处理 keep-alive 的边界。代价是放弃连接复用 —— **这是权宜之计，
    /// 不是终局设计**，根因查清后应当撤掉。
    fn sendRawOnce(
        self: *Client,
        arena: std.mem.Allocator,
        method: []const u8,
        raw_url: []const u8,
        req: Request,
        body: []const u8,
        source: ?model.Source,
        content_length: ?u64,
    ) !Response {
        if (self.unsupported) |name| {
            log.err("client: refusing request: unsupported option `{s}` is configured", .{name});
            return error.UnsupportedOption;
        }

        const parsed = try urlmod.Url.parse(raw_url);
        const is_https = parsed.isHttps();
        const hdrs = try self.buildHeaders(arena, parsed, req, body, source);

        var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const host = std.Io.net.HostName.fromUri(try toStdUri(raw_url), &host_buf) catch
            return error.InvalidUrl;

        const io = rt.io();

        // 与 `sendOnce` 一致：`std.http.Client` 的连接池不是线程安全的。
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);

        // ⚠️ `connectTcpOptions` **不会**替你准备 CA bundle —— std 是在
        // `request()` 里按需 rescan 的。走这条路就必须自己加载，否则
        // `ca_bundle` 是空的，TLS 校验直接失败（真机表现为
        // `TlsInitializationFailed`，且只在「第一次 HTTPS 请求走这条路」时出现）。
        if (is_https) try self.ensureCaBundle();

        const conn = try self.inner.connectTcpOptions(.{
            .host = host,
            .port = parsed.port,
            .protocol = if (is_https) .tls else .plain,
        });
        // ⚠️ `connectTcpOptions` 会把连接登记进连接池的 used 表，所以**不能**
        // 另外再 `conn.destroy()` —— 那样池里会留下悬空指针，下一个请求复用到
        // 就直接段错误（本机复现过：第二个 URL 崩）。我们发 `Connection: close`，
        // 这条连接不可能被复用，所以正解是结束时把整个池子清掉。
        // 这里不重新加锁 —— 本函数全程已持有 `self.lock`。
        defer {
            self.inner.connection_pool.deinit(io);
            self.inner.connection_pool = .{};
        }

        // N01：自写路径同样要挂超时，否则「上游不响应」在这里也是永久阻塞。
        applySocketTimeout(conn, self.opts.timeout_s);

        const w = conn.writer();
        try w.writeAll(method);
        try w.writeAll(" ");
        try w.writeAll(parsed.path);
        if (parsed.query.len > 0) {
            try w.writeAll("?");
            try w.writeAll(parsed.query);
        }
        try w.writeAll(" HTTP/1.1\r\n");

        try w.writeAll("Host: ");
        var hp_buf: [300]u8 = undefined;
        try w.writeAll(try parsed.hostPort(&hp_buf));
        try w.writeAll("\r\n");

        for (hdrs) |h| {
            // 定界头由下面统一给出；调用方重复提供会造出两个 Content-Length。
            if (std.ascii.eqlIgnoreCase(h.name, "Content-Length")) continue;
            if (std.ascii.eqlIgnoreCase(h.name, "Connection")) continue;
            try w.writeAll(h.name);
            try w.writeAll(": ");
            try w.writeAll(h.value);
            try w.writeAll("\r\n");
        }

        const total_len: u64 = if (source) |_| (content_length orelse 0) else body.len;
        if (total_len > 0) {
            var cl_buf: [24]u8 = undefined;
            const cl = std.fmt.bufPrint(&cl_buf, "Content-Length: {d}\r\n", .{total_len}) catch unreachable;
            try w.writeAll(cl);
        }
        try w.writeAll("Connection: close\r\n\r\n");

        if (source) |src| {
            // 流式发送，绝不把整个 body 读进内存（上传路径要用）。
            var remaining = total_len;
            var off: u64 = 0;
            var buf: [64 * 1024]u8 = undefined;
            while (remaining > 0) {
                const want: usize = @intCast(@min(remaining, buf.len));
                const n = try src.readAt(off, buf[0..want]);
                if (n == 0) return error.UnexpectedEof;
                try w.writeAll(buf[0..n]);
                off += n;
                remaining -= n;
            }
        } else if (body.len > 0) {
            try w.writeAll(body);
        }
        try conn.flush();

        // ---- 响应：读到 EOF ----
        var raw = Buf.init(arena);
        const r = conn.reader();
        var chunk: [16 * 1024]u8 = undefined;
        while (true) {
            const n = r.readSliceShort(&chunk) catch |e| switch (e) {
                error.ReadFailed => return error.ReadFailed,
            };
            if (n == 0) break;
            try raw.append(chunk[0..n]);
            if (raw.len > 64 * 1024 * 1024) return error.ResponseTooLarge;
        }
        if (raw.len == 0) return error.ConnectionClosed;

        const res = try parseRawResponse(arena, raw.slice());
        if (req.use_cookies) self.captureCookies(parsed, res.headers);
        return res;
    }

    /// 丢掉连接池里的**全部**连接，强制下一次请求新建连接。
    /// 只在 `HttpConnectionClosing` 的恢复路径上调用。
    fn dropPooledConnections(self: *Client) void {
        const io = rt.io();
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        self.inner.connection_pool.deinit(io);
        self.inner.connection_pool = .{};
    }

    /// 按需加载系统根证书。语义与 `std.http.Client.request()` 里那段
    /// `if (protocol == .tls) tls:` 完全一致：`now` 非空说明已经扫过了。
    fn ensureCaBundle(self: *Client) !void {
        if (comptime std.http.Client.disable_tls) return;
        const io = rt.io();
        {
            try self.inner.ca_bundle_lock.lockShared(io);
            defer self.inner.ca_bundle_lock.unlockShared(io);
            if (self.inner.now != null) return;
        }
        var bundle: std.crypto.Certificate.Bundle = .empty;
        defer bundle.deinit(self.inner.allocator);
        const now = std.Io.Clock.real.now(io);
        bundle.rescan(self.inner.allocator, io, now) catch return error.CertificateBundleLoadFailure;
        try self.inner.ca_bundle_lock.lock(io);
        defer self.inner.ca_bundle_lock.unlock(io);
        self.inner.now = now;
        std.mem.swap(std.crypto.Certificate.Bundle, &self.inner.ca_bundle, &bundle);
    }
};

/// 给连接的 socket 设置收发超时（秒）。`0` = 不设置。
///
/// **N01**：`std.http.Client` 的 request 路径**没有任何超时入口**
/// （`ConnectTcpOptions.timeout` 只管 connect），上游一旦不响应，调用线程就永久
/// 阻塞。真机证据：`/aliyun` 的 list 挂死 —— 40 秒 0 字节、日志里一个字都没有，
/// 只能重启进程。在只有 512 MB 内存的光猫上，几个这样的挂死就能把服务拖垮。
///
/// 这里设的是 **SO_RCVTIMEO / SO_SNDTIMEO**，即**每次系统调用**的上限，而不是
/// 整个请求的上限。这一点很关键：分片上传的每次 write 都很快，不会被误杀；
/// 而「上游一声不吭」的 read 最多阻塞 `timeout_s` 秒就会失败。
///
/// 服务端的 `http.applyTimeouts()` 用的是同一套写法，两边保持一致。
fn applySocketTimeout(conn: *std.http.Client.Connection, seconds: u32) void {
    if (seconds == 0) return;
    // `comptime`：Windows 上 `std.posix.setsockopt` 是编译错误，分支不能被分析。
    if (comptime builtin.os.tag == .windows) return;
    const tv = std.posix.timeval{ .sec = @intCast(seconds), .usec = 0 };
    const handle = conn.stream_reader.stream.socket.handle;
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

/// 解析一个「已读到 EOF」的完整 HTTP/1.1 响应。
fn parseRawResponse(arena: std.mem.Allocator, raw: []const u8) !Response {
    const head_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidResponse;
    const head = raw[0..head_end];
    var body: []const u8 = raw[head_end + 4 ..];

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.InvalidResponse;

    // "HTTP/1.1 207 Multi-Status"
    var sp = std.mem.splitScalar(u8, status_line, ' ');
    _ = sp.next() orelse return error.InvalidResponse; // 版本
    const code_str = sp.next() orelse return error.InvalidResponse;
    const status = std.fmt.parseInt(u16, code_str, 10) catch return error.InvalidResponse;

    var out_headers = List(Header).init(arena);
    var chunked = false;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") and
            std.mem.indexOf(u8, value, "chunked") != null)
        {
            chunked = true;
        }
        try out_headers.append(.{
            .name = try arena.dupe(u8, name),
            .value = try arena.dupe(u8, value),
        });
    }

    if (chunked) body = try dechunk(arena, body);

    return .{
        .status = status,
        .headers = try out_headers.toOwned(),
        .body = try arena.dupe(u8, body),
    };
}

/// 解 chunked 编码。遇到畸形输入就停，把已解出的部分交出去（上层按 XML
/// 解析失败处理，不会静默当成完整响应）。
fn dechunk(arena: std.mem.Allocator, src: []const u8) ![]const u8 {
    var out = Buf.init(arena);
    var i: usize = 0;
    while (i < src.len) {
        const nl = std.mem.indexOfPos(u8, src, i, "\r\n") orelse break;
        const size_line = src[i..nl];
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_line[0..semi], " \t"), 16) catch break;
        if (size == 0) break;
        const start = nl + 2;
        if (start + size > src.len) break;
        try out.append(src[start .. start + size]);
        i = start + size + 2; // 跳过块尾 CRLF
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// std.http shims — the version-sensitive part
// ---------------------------------------------------------------------------

/// 把方法名映射到 `std.http.Method`。
///
/// ⚠️ `std.http.Method` 是固定枚举，**不含 WebDAV 的方法**。以前这里静默回落
/// 到 `.GET`，于是 PROPFIND/MKCOL/MOVE/COPY 全被当成 GET 发出去，而且一点痕迹
/// 都没有。现在改成：非标准方法必须走 `Client.sendRaw`，走错路就直接报错。
fn parseMethod(m: []const u8) !std.http.Method {
    return std.meta.stringToEnum(std.http.Method, m) orelse {
        log.err("client: `{s}` is not a std.http.Method — use Client.sendRaw for custom methods", .{m});
        return error.UnsupportedMethod;
    };
}

/// Mirrors `std.http.Method.requestHasBody` — spelled out here because that
/// method is a private-ish detail of `std.http.Client.Request`, and this file
/// is the one place allowed to know about `std.http`.
fn methodRequestHasBody(m: std.http.Method) bool {
    return switch (m) {
        .POST, .PUT, .PATCH => true,
        else => false,
    };
}

fn stdHeaders(arena: std.mem.Allocator, hs: []const Header) ![]const std.http.Header {
    const out = try arena.alloc(std.http.Header, hs.len);
    for (hs, 0..) |h, i| out[i] = .{ .name = h.name, .value = h.value };
    return out;
}

fn toStdUri(raw: []const u8) !std.Uri {
    return std.Uri.parse(raw);
}

/// Stream a seekable source into an already-open request body writer without
/// ever materialising the whole payload. The staging buffer comes from the
/// per-request arena rather than the stack: the 光猫's connection threads have
/// small stacks, and this is a per-request cost either way.
fn writeSource(arena: std.mem.Allocator, w: *std.Io.Writer, src: model.Source, total: u64) !void {
    const chunk = try arena.alloc(u8, 64 * 1024);
    var off: u64 = 0;
    while (off < total) {
        const want: usize = @intCast(@min(@as(u64, chunk.len), total - off));
        const n = try src.readAt(off, chunk[0..want]);
        if (n == 0) return error.UnexpectedEof;
        try w.writeAll(chunk[0..n]);
        off += n;
    }
}

/// Drain the response body into `out`.
///
/// `readSliceShort` folds `EndOfStream` into a short read, so a 0 return *is*
/// the clean end-of-body signal — there is no separate error case to catch.
/// 读完整个响应体。`limit > 0` 时超过即报 `error.ResponseTooLarge`。
fn readBody(resp: *std.http.Client.Response, out: *Buf, limit: usize) !void {
    var transfer_buf: [16 * 1024]u8 = undefined;
    const r = resp.reader(&transfer_buf);
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const n = r.readSliceShort(&chunk) catch |e| switch (e) {
            // `ReadFailed` hides the real cause; `bodyErr` recovers it.
            error.ReadFailed => return error.ReadFailed,
        };
        if (n == 0) break;
        try out.append(chunk[0..n]);
        // 上游没给 Content-Length 时，边读边算，防止无界缓冲。
        if (limit > 0 and out.len > limit) return error.ResponseTooLarge;
    }
}

// ---------------------------------------------------------------------------

fn absolutize(arena: std.mem.Allocator, base: []const u8, location: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, location, "http://") or std.mem.startsWith(u8, location, "https://")) {
        return arena.dupe(u8, location);
    }
    const b = try urlmod.Url.parse(base);
    if (location.len > 0 and location[0] == '/') {
        return std.fmt.allocPrint(arena, "{s}://{s}{s}", .{ b.scheme, b.host, location });
    }
    // Relative to the base directory.
    const dir = urlmod.parentPath(b.path);
    return std.fmt.allocPrint(arena, "{s}://{s}{s}/{s}", .{ b.scheme, b.host, dir, location });
}

// ---------------------------------------------------------------------------
// JSON convenience — every upstream API here is JSON in / JSON out
// ---------------------------------------------------------------------------

/// POST a JSON body and parse the JSON response. Returns the parsed value and
/// the raw response so callers can log the body on a parse failure — which is
/// exactly what happens when a WAF replaces the JSON with an HTML page.
pub fn postJson(
    client: *Client,
    arena: std.mem.Allocator,
    raw_url: []const u8,
    headers: []const Header,
    body_json: []const u8,
) !struct { value: json.Value, res: Response } {
    const res = try client.send(arena, .{
        .method = "POST",
        .url = raw_url,
        .headers = headers,
        .body = body_json,
    });
    if (!res.isOk()) return error.UpstreamHttpError;
    const v = json.parse(arena, res.body) catch return error.UpstreamNotJson;
    return .{ .value = v, .res = res };
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "absolutize handles absolute, root-relative and relative" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("https://x/y", try absolutize(a, "https://a/b", "https://x/y"));
    try testing.expectEqualStrings("https://a/c", try absolutize(a, "https://a/b/d", "/c"));
    try testing.expectEqualStrings("https://a/b/c", try absolutize(a, "https://a/b/d", "c"));
}

test "response header helpers" {
    var hs = [_]Header{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Set-Cookie", .value = "b=2" },
        .{ .name = "Content-Type", .value = "application/json" },
    };
    const r = Response{ .status = 200, .headers = &hs, .body = "" };
    try testing.expect(r.isOk());
    try testing.expectEqualStrings("application/json", r.header("content-type").?);
    const all = try r.all(testing.allocator, "set-cookie");
    defer testing.allocator.free(all);
    try testing.expectEqual(@as(usize, 2), all.len);
}

test "parseRawResponse parses a WebDAV 207 multistatus reply" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw =
        "HTTP/1.1 207 Multi-Status\r\n" ++
        "Content-Type: text/xml; charset=utf-8\r\n" ++
        "Content-Length: 11\r\n" ++
        "\r\n" ++
        "<multistat>";
    const r = try parseRawResponse(a, raw);
    try testing.expectEqual(@as(u16, 207), r.status);
    try testing.expectEqualStrings("text/xml; charset=utf-8", r.header("content-type").?);
    try testing.expectEqualStrings("<multistat>", r.body);
}

test "dechunk reassembles a chunked body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // "Wiki" + "pedia" + 结尾 0 块
    const src = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    try testing.expectEqualStrings("Wikipedia", try dechunk(a, src));

    // 带扩展的块大小（`;ext`）也要能解
    try testing.expectEqualStrings("abc", try dechunk(a, "3;foo=bar\r\nabc\r\n0\r\n\r\n"));
}

test "parseRawResponse dechunks a chunked WebDAV reply" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const raw =
        "HTTP/1.1 207 Multi-Status\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n0\r\n\r\n";
    const r = try parseRawResponse(a, raw);
    try testing.expectEqual(@as(u16, 207), r.status);
    try testing.expectEqualStrings("hello", r.body);
}

test "parseMethod rejects non-std methods instead of silently using GET" {
    // 这一条是 T1 的防回归闸门：以前 `stringToEnum(...) orelse .GET` 会把
    // PROPFIND 静默变成 GET，真机上表现为服务端回 405，一点痕迹都没有。
    try testing.expectError(error.UnsupportedMethod, parseMethod("PROPFIND"));
    try testing.expectError(error.UnsupportedMethod, parseMethod("MKCOL"));
    try testing.expectError(error.UnsupportedMethod, parseMethod("MOVE"));
    // 标准方法照常。
    try testing.expectEqual(std.http.Method.GET, try parseMethod("GET"));
    try testing.expectEqual(std.http.Method.PUT, try parseMethod("PUT"));
}

test "raw path and std path share the same cookie jar and header rules" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var jar = Jar.init(a);
    var cl = Client.init(a, .{}, &jar);
    defer cl.deinit();

    const parsed = try urlmod.Url.parse("https://example.com/x");

    // 响应里带 Set-Cookie → 必须写回 jar（T4 切换后 cookie 不能丢）
    const resp_headers = [_]Header{
        .{ .name = "Set-Cookie", .value = "sid=abc; Path=/; Max-Age=3600" },
    };
    cl.captureCookies(parsed, &resp_headers);

    // 下一次请求要把它带上。两条路径共用 buildHeaders，所以这里同时覆盖了
    // 「send() 走 raw」和「sendRaw() 直连」两种情况。
    const hdrs = try cl.buildHeaders(a, parsed, .{ .url = "https://example.com/x" }, "", null);
    var found = false;
    for (hdrs) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Cookie")) {
            try testing.expect(std.mem.indexOf(u8, h.value, "sid=abc") != null);
            found = true;
        }
    }
    try testing.expect(found);

    // `use_cookies = false`（189pc 的解跳转探测用）必须不带 cookie。
    const hdrs2 = try cl.buildHeaders(a, parsed, .{
        .url = "https://example.com/x",
        .use_cookies = false,
    }, "", null);
    for (hdrs2) |h| try testing.expect(!std.ascii.eqlIgnoreCase(h.name, "Cookie"));
}

test "headers for a pre-signed upload URL carry no Content-Type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var jar = Jar.init(a);
    var cl = Client.init(a, .{}, &jar);
    defer cl.deinit();

    const parsed = try urlmod.Url.parse("https://cn-beijing-data.aliyundrive.net/x");

    // 默认策略：有 body 就补 Content-Type（普通 JSON 接口需要它）。
    const normal = try cl.buildHeaders(a, parsed, .{
        .url = "https://cn-beijing-data.aliyundrive.net/x",
    }, "{}", null);
    var seen_ct = false;
    for (normal) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) seen_ct = true;
    }
    try testing.expect(seen_ct);

    // 阿里云 OSS 预签名 URL：一个 Content-Type 都不能带，
    // 否则签名串算出来对不上，OSS 回 403 SignatureDoesNotMatch。
    const presigned = try cl.buildHeaders(a, parsed, .{
        .url = "https://cn-beijing-data.aliyundrive.net/x",
        .omit_content_type = true,
    }, "binary-blob", null);
    for (presigned) |h| {
        try testing.expect(!std.ascii.eqlIgnoreCase(h.name, "Content-Type"));
    }

    // 调用方显式给了 Content-Type 时仍以调用方为准（omit 只挡自动补的那个）。
    const explicit = try cl.buildHeaders(a, parsed, .{
        .url = "https://cn-beijing-data.aliyundrive.net/x",
        .omit_content_type = true,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }, "x", null);
    var found = false;
    for (explicit) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) {
            try testing.expectEqualStrings("text/plain", h.value);
            found = true;
        }
    }
    try testing.expect(found);
}
