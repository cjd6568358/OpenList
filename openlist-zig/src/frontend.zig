//! OpenList-compatible frontend serving.
//!
//! A port of OpenList's `server/static/config.go` + `server/static/static.go`.
//! The behaviour worth preserving is the *default* one, because that is what an
//! existing deployment already relies on:
//!
//!   * `cdn` empty — assets are served by this process out of `dist_dir`, and
//!     the SPA shell is read from `dist_dir/index.html`.
//!   * `cdn` set   — `/assets|images|streamer|static/*` answer 302 into the
//!     CDN, and the shell itself is fetched from `{cdn}/index.html` once at
//!     startup, so the served HTML and the assets it references come from the
//!     same build. See `loadRawIndex` for the one place this diverges from
//!     upstream's branch condition.
//!
//! `$version` inside the `cdn` value expands to `web_version` with a leading
//! `"v"` stripped — `"v4.2.6"` -> `"4.2.6"`, `"rolling"` -> `"rolling"`. That is
//! how OpenList's own `build.sh` feeds the frontend release tag into a CDN
//! template, so a value like
//! `https://cdn.example.com/openlist/$version/dist` pins to one release and
//! `https://cdn.example.com/openlist/rolling/dist` tracks the edge build.
//!
//! ## The one deliberate divergence
//!
//! Upstream compiles the ~20 MB frontend into the Go binary via
//! `//go:embed public/dist`. Avoiding exactly that is the point of this
//! rewrite, so when there is neither a `dist_dir` nor a `cdn` we serve
//! `BUILTIN_INDEX`: a small self-contained diagnostic page. It is not a
//! frontend. It carries the same placeholder tokens as the real `index.html`
//! so that `replaceFirstEach` is exercised identically no matter where the
//! shell came from.
//!
//! Getting the real UI is therefore a config change, not a rebuild — see
//! `docs/STATUS.md`.

const std = @import("std");
const log = @import("log.zig");
const rt = @import("rt.zig");
const urlmod = @import("util/url.zig");
const client_mod = @import("client.zig");
const cookiejar = @import("cookiejar.zig");
const Buf = @import("util/buf.zig").Buf;

/// The four path prefixes OpenList treats as frontend assets. Anything under
/// them is either served from `dist_dir` or redirected to the CDN; everything
/// else falls through to the SPA shell.
pub const asset_folders = [_][]const u8{ "assets", "images", "streamer", "static" };

/// Largest `index.html` we will read. The real one is ~1.3 KB; 4 MiB leaves
/// room for a heavily customised build without letting a hostile `dist_dir`
/// exhaust memory at startup.
const max_index_bytes: usize = 4 * 1024 * 1024;

/// Presentation defaults, copied from OpenList's
/// `internal/bootstrap/data/setting.go`. These are the values a *fresh*
/// install has, i.e. what the placeholder substitution does when the operator
/// overrides nothing.
pub const Settings = struct {
    site_title: []const u8 = "OpenList",
    main_color: []const u8 = "#1890ff",
    /// Both default to the same asset upstream; note the placeholders they
    /// replace are the `.png` and `.svg` variants respectively.
    logo: []const u8 = "https://res.oplist.org/logo/logo.svg",
    favicon: []const u8 = "https://res.oplist.org/logo/logo.svg",
    customize_head: []const u8 = "",
    customize_body: []const u8 = "",
};

/// Everything the frontend needs from `config.json`, passed in rather than
/// read from the global config so that this module is testable in isolation.
pub const Input = struct {
    /// `site_url`. Only its path component matters — OpenList derives the base
    /// path from it.
    site_url: []const u8 = "",
    /// `cdn`, verbatim. Empty means "serve assets ourselves".
    cdn: []const u8 = "",
    /// `dist_dir`. Empty means "no on-disk frontend build".
    dist_dir: []const u8 = "",
    /// The frontend release this deployment targets. OpenList bakes this in
    /// with `-ldflags`; we read it from config.
    web_version: []const u8 = "rolling",
    settings: Settings = .{},
};

/// Port of OpenList's `SiteConfig`.
///
/// `cdn` here is the *normalised* value: trailing slash trimmed, `$version`
/// expanded, and — when unset — fallen back to the base path. It is what goes
/// into the `cdn:` placeholder and into the 302 targets. The local-vs-CDN
/// routing decision uses the raw config value instead; see `Frontend.cdn_raw`.
pub const SiteConfig = struct {
    base_path: []const u8,
    cdn: []const u8,
};

/// Where the served shell came from. Reported at startup, and used by tests to
/// assert which branch ran.
pub const Source = enum { cdn, dist_dir, builtin };

pub const Frontend = struct {
    /// Owns every string in this struct.
    ///
    /// Behind a pointer, not inline: `ArenaAllocator.allocator()` hands out an
    /// interface whose `ptr` is the arena's own address, so moving the arena
    /// after that call would dangle every allocator derived from it. Keeping it
    /// on the heap lets this struct be returned and copied by value.
    arena: *std.heap.ArenaAllocator,

    site: SiteConfig,
    /// Raw `cdn` from config. Upstream branches on *this*, not on `site.cdn`.
    cdn_raw: []const u8,
    dist_dir: []const u8,
    /// True when `dist_dir` names a directory that exists, i.e. when assets
    /// can actually be served locally.
    has_dist: bool,
    settings: Settings,
    source: Source,

    /// Fully substituted, customisations applied. Served for every non-asset
    /// path that is not `/@manage*`.
    index_html: []const u8,
    /// Favicon/logo/title/colour applied but *not* the custom head and body
    /// blocks. Served for `/@manage*` so operator-supplied HTML is not
    /// injected into the admin SPA.
    manage_html: []const u8,
    /// `/manifest.json`, the PWA manifest.
    manifest_json: []const u8,

    pub fn deinit(self: *Frontend) void {
        const child = self.arena.child_allocator;
        self.arena.deinit();
        child.destroy(self.arena);
        self.arena = undefined;
    }

    pub fn allocator(self: *Frontend) std.mem.Allocator {
        return self.arena.allocator();
    }

    /// Which shell to serve for `path`. Mirrors the catch-all handler: the
    /// `/@manage` prefix is the admin SPA.
    pub fn htmlFor(self: *const Frontend, path: []const u8) []const u8 {
        return if (std.mem.startsWith(u8, path, "/@manage")) self.manage_html else self.index_html;
    }

    /// What to do with a request for a frontend asset.
    ///
    /// `path` is the percent-decoded path (used for local file lookup);
    /// `raw_target` is the still-encoded request target (used for the redirect
    /// URL). They differ for any asset whose name needs escaping, and the CDN
    /// needs the encoded form.
    /// M03：`a` 必须是**请求级** allocator。
    ///
    /// 以前这里用 `self.arena`（进程生命周期）来拼重定向 URL 和本地文件路径，
    /// 每个公开静态资源请求都往里面堆一份，直到进程结束才释放；并发请求还
    /// 共用同一个 arena（不是线程安全的分配器）。
    pub fn asset(self: *Frontend, a: std.mem.Allocator, path: []const u8, raw_target: []const u8) Asset {
        if (self.cdn_raw.len > 0) {
            var b = Buf.init(a);
            // `site.cdn` has no trailing slash and `raw_target` starts with
            // one, so this cannot produce a doubled slash.
            b.append(self.site.cdn) catch return .missing;
            b.append(if (raw_target.len > 0 and raw_target[0] == '/') raw_target else path) catch return .missing;
            return .{ .redirect = b.toOwned() catch return .missing };
        }

        if (!self.has_dist) return .missing;

        const rel = stripLeadingSlash(path);
        if (!isSafeRelative(rel)) return .missing;

        const full = std.fs.path.join(a, &.{ self.dist_dir, rel }) catch return .missing;
        const st = std.Io.Dir.cwd().statFile(rt.io(), full, .{}) catch return .missing;
        if (st.kind != .file) return .missing;
        return .{ .local = .{ .path = full, .size = st.size } };
    }
};

pub const Asset = union(enum) {
    /// Serve this file from disk.
    local: LocalFile,
    /// 302 the client at this URL.
    redirect: []const u8,
    /// No local build and no CDN configured.
    missing,

    pub const LocalFile = struct {
        path: []const u8,
        size: u64,
    };
};

/// True when `path` is one of the four asset prefixes. Requires the trailing
/// slash so that a storage mounted at `/static` is not shadowed by the
/// `/static/` asset prefix.
pub fn isAssetPath(path: []const u8) bool {
    for (asset_folders) |folder| {
        if (path.len > folder.len + 1 and path[0] == '/') {
            if (std.mem.startsWith(u8, path[1..], folder) and path[1 + folder.len] == '/') return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Build the frontend, fetching `{cdn}/index.html` if the configuration calls
/// for it. Does blocking network I/O at startup.
pub fn init(alloc: std.mem.Allocator, in: Input) !Frontend {
    const arena = try newArena(alloc);
    errdefer freeArena(arena);

    const a = arena.allocator();
    const site = try siteConfig(a, in);
    const raw = try loadRawIndex(a, in, site);
    return build(arena, in, site, raw.html, raw.source);
}

/// Build the frontend from an already-obtained shell. No I/O. Tests use this.
pub fn initFromHtml(alloc: std.mem.Allocator, in: Input, raw_index: []const u8) !Frontend {
    const arena = try newArena(alloc);
    errdefer freeArena(arena);

    const site = try siteConfig(arena.allocator(), in);
    return build(arena, in, site, raw_index, if (in.dist_dir.len > 0) .dist_dir else .builtin);
}

fn newArena(alloc: std.mem.Allocator) !*std.heap.ArenaAllocator {
    const arena = try alloc.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(alloc);
    return arena;
}

fn freeArena(arena: *std.heap.ArenaAllocator) void {
    const child = arena.child_allocator;
    arena.deinit();
    child.destroy(arena);
}

fn build(arena: *std.heap.ArenaAllocator, in: Input, site: SiteConfig, raw_index: []const u8, source: Source) !Frontend {
    const a = arena.allocator();
    // Duplicate everything the caller owns so the returned value is
    // self-contained and the caller's strings may be freed.
    const settings = Settings{
        .site_title = try a.dupe(u8, in.settings.site_title),
        .main_color = try a.dupe(u8, in.settings.main_color),
        .logo = try a.dupe(u8, in.settings.logo),
        .favicon = try a.dupe(u8, in.settings.favicon),
        .customize_head = try a.dupe(u8, in.settings.customize_head),
        .customize_body = try a.dupe(u8, in.settings.customize_body),
    };
    const dist_dir = try a.dupe(u8, in.dist_dir);
    const cdn_raw = try a.dupe(u8, in.cdn);

    const has_dist = blk: {
        if (dist_dir.len == 0) break :blk false;
        const st = std.Io.Dir.cwd().statFile(rt.io(), dist_dir, .{}) catch break :blk false;
        break :blk st.kind == .directory;
    };

    // Pass 1 — site configuration. These are the tokens `initIndex` fills in.
    const manifest_path = if (std.mem.eql(u8, site.base_path, "/"))
        "/manifest.json"
    else
        try std.fmt.allocPrint(a, "{s}/manifest.json", .{site.base_path});

    const pass1 = try replaceFirstEach(a, raw_index, &[_]Pair{
        .{ .needle = "cdn: undefined", .replacement = try std.fmt.allocPrint(a, "cdn: '{s}'", .{site.cdn}) },
        .{ .needle = "base_path: undefined", .replacement = try std.fmt.allocPrint(a, "base_path: '{s}'", .{site.base_path}) },
        .{ .needle = "href=\"/manifest.json\"", .replacement = try std.fmt.allocPrint(a, "href=\"{s}\"", .{manifest_path}) },
    });

    // Pass 2 — presentation settings. This is `UpdateIndex`.
    const manage_html = try replaceFirstEach(a, pass1, &[_]Pair{
        .{ .needle = "https://res.oplist.org/logo/logo.svg", .replacement = settings.favicon },
        .{ .needle = "https://res.oplist.org/logo/logo.png", .replacement = settings.logo },
        .{ .needle = "Loading...", .replacement = settings.site_title },
        .{ .needle = "main_color: undefined", .replacement = try std.fmt.allocPrint(a, "main_color: '{s}'", .{settings.main_color}) },
    });

    // Pass 3 — operator HTML injection. Only the public shell gets it.
    const index_html = try replaceFirstEach(a, manage_html, &[_]Pair{
        .{ .needle = "<!-- customize head -->", .replacement = settings.customize_head },
        .{ .needle = "<!-- customize body -->", .replacement = settings.customize_body },
    });

    return .{
        .arena = arena,
        .site = site,
        .cdn_raw = cdn_raw,
        .dist_dir = dist_dir,
        .has_dist = has_dist,
        .settings = settings,
        .source = source,
        .index_html = index_html,
        .manage_html = manage_html,
        .manifest_json = try manifestJson(a, site.base_path, settings),
    };
}

// ---------------------------------------------------------------------------
// Site configuration
// ---------------------------------------------------------------------------

/// Port of OpenList's `getSiteConfig`.
pub fn siteConfig(a: std.mem.Allocator, in: Input) !SiteConfig {
    const base_path = try basePathFrom(a, in.site_url);
    const cdn = try expandVersion(a, in.cdn, in.web_version);

    if (cdn.len == 0) {
        // Upstream quirk, preserved deliberately: with no CDN configured the
        // *normalised* cdn becomes the base path with its trailing slash
        // removed. For the default base path "/" that is the empty string, so
        // the shell reads `cdn: ''` and the frontend resolves assets against
        // the base path. For a non-root base path it reads `cdn: '/sub'`.
        return .{ .base_path = base_path, .cdn = trimTrailingSlash(base_path) };
    }
    return .{ .base_path = base_path, .cdn = cdn };
}

fn basePathFrom(a: std.mem.Allocator, site_url: []const u8) ![]const u8 {
    const p = pathOfUrl(site_url);
    if (p.len == 0) return "/";
    // `fixAndCleanPath` mirrors `utils.FixAndCleanPath`: force a leading
    // slash, collapse duplicates, resolve `.`/`..`. `cleanPath` already drops
    // a trailing slash except at the root, so nothing more is needed here.
    return fixAndCleanPath(a, p);
}

/// Extract the path component of a URL without pulling in a URI parser.
///
/// `std.Uri` would work, but it returns components in a raw-or-percent-encoded
/// union that then needs normalising; the path is all we need and it is
/// unambiguous.
fn pathOfUrl(u: []const u8) []const u8 {
    if (u.len == 0) return "";
    var rest = u;
    if (std.mem.indexOf(u8, rest, "://")) |i| rest = rest[i + 3 ..];
    // The authority ends at the first '/', '?' or '#'.
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse return "";
    if (end >= rest.len) return "";
    var p = rest[end..];
    if (std.mem.indexOfAny(u8, p, "?#")) |i| p = p[0..i];
    return p;
}

fn fixAndCleanPath(a: std.mem.Allocator, p: []const u8) ![]const u8 {
    if (p.len == 0) return "/";
    var b = Buf.init(a);
    defer b.deinit();
    if (p[0] != '/') try b.appendByte('/');
    try b.append(p);
    return urlmod.cleanPath(a, b.slice());
}

/// `strings.TrimSuffix(p, "/")`, including the "/" -> "" case that makes the
/// default CDN fallback come out empty.
fn trimTrailingSlash(p: []const u8) []const u8 {
    if (p.len > 0 and p[p.len - 1] == '/') return p[0 .. p.len - 1];
    return p;
}

/// `strings.ReplaceAll(strings.TrimSuffix(cdn, "/"), "$version", strings.TrimPrefix(web_version, "v"))`.
fn expandVersion(a: std.mem.Allocator, cdn: []const u8, web_version: []const u8) ![]const u8 {
    const trimmed = trimTrailingSlash(cdn);
    if (std.mem.indexOf(u8, trimmed, "$version") == null) return trimmed;

    const ver = if (web_version.len > 0 and web_version[0] == 'v') web_version[1..] else web_version;
    var b = Buf.init(a);
    defer b.deinit();
    var rest = trimmed;
    while (std.mem.indexOf(u8, rest, "$version")) |i| {
        try b.append(rest[0..i]);
        try b.append(ver);
        rest = rest[i + "$version".len ..];
    }
    try b.append(rest);
    return b.toOwned();
}

// ---------------------------------------------------------------------------
// Shell loading
// ---------------------------------------------------------------------------

const RawIndex = struct { html: []const u8, source: Source };

/// Where the shell will come from. Split out of `loadRawIndex` so the branch
/// selection is testable without a network round trip.
pub fn sourceFor(in: Input) Source {
    if (in.dist_dir.len == 0 and in.cdn.len > 0) return .cdn;
    if (in.dist_dir.len > 0) return .dist_dir;
    return .builtin;
}

/// Port of OpenList's `initIndex` branch selection.
///
/// One divergence, forced by the fact that nothing is embedded here. Upstream
/// also requires a rolling-style `web_version` (`""`, `beta`, `dev`, `rolling`)
/// before it will fetch the shell from the CDN, because its *pinned* releases
/// carry a copy of the frontend inside the binary and prefer that. With no
/// embedded copy, honouring that condition would mean a deployment that pins
/// `web_version` — which is precisely what `$version` exists for — silently
/// dropped through to the placeholder page. So: a configured `cdn` is always
/// the source of truth when there is no `dist_dir`.
fn loadRawIndex(a: std.mem.Allocator, in: Input, site: SiteConfig) !RawIndex {
    switch (sourceFor(in)) {
        .cdn => {
            log.info("frontend: fetching index.html from CDN: {s}/index.html", .{site.cdn});
            const html = fetchIndex(a, site.cdn) catch |e| {
                // Upstream calls Fatalf here and so do we, in effect: starting
                // up with an unreachable CDN would serve a shell whose every
                // asset 302s into nowhere, which is harder to diagnose than
                // refusing to start.
                log.err("frontend: cannot fetch index.html from CDN {s}: {s}", .{ site.cdn, @errorName(e) });
                return error.CdnIndexFetchFailed;
            };
            log.info("frontend: fetched {d} bytes of index.html from CDN", .{html.len});
            return .{ .html = html, .source = .cdn };
        },
        .dist_dir => {
            const path = try std.fs.path.join(a, &.{ in.dist_dir, "index.html" });
            const html = std.Io.Dir.cwd().readFileAlloc(rt.io(), path, a, .limited(max_index_bytes)) catch |e| {
                log.err("frontend: cannot read {s}: {s}", .{ path, @errorName(e) });
                return error.MissingIndexHtml;
            };
            log.info("frontend: using custom dist directory {s}", .{in.dist_dir});
            return .{ .html = html, .source = .dist_dir };
        },
        .builtin => return .{ .html = BUILTIN_INDEX, .source = .builtin },
    }
}

fn fetchIndex(a: std.mem.Allocator, cdn: []const u8) ![]const u8 {
    const url = try std.fmt.allocPrint(a, "{s}/index.html", .{cdn});

    // A throwaway jar: the CDN is not expected to set cookies, and sharing the
    // storage drivers' jar would leak its contents into the frontend fetch.
    var jar = cookiejar.Jar.init(a);
    defer jar.deinit();
    var cl = client_mod.Client.init(a, .{
        .timeout_s = 30,
        .user_agent = "OpenList-Zig",
        .insecure_skip_verify = false,
    }, &jar);
    defer cl.deinit();

    const res = try cl.send(a, .{
        .url = url,
        .headers = &.{.{ .name = "Accept", .value = "text/html" }},
        .use_cookies = false,
    });
    if (res.status != 200) {
        log.err("frontend: CDN returned HTTP {d} for {s}", .{ res.status, url });
        return error.CdnIndexFetchError;
    }
    if (res.body.len > max_index_bytes) return error.CdnIndexTooLarge;
    return res.body;
}

// ---------------------------------------------------------------------------
// Placeholder substitution
// ---------------------------------------------------------------------------

const Pair = struct { needle: []const u8, replacement: []const u8 };

/// Port of OpenList's `replaceStrings`: replace at most the *first* occurrence
/// of each needle.
///
/// Two deliberate differences from the Go original, both removing
/// nondeterminism it has:
///   * needles are tried in a fixed order, not Go's randomised map order;
///   * the scan never re-examines inserted text, so a replacement whose value
///     happens to contain another needle — a logo URL ending in `.png`, say —
///     cannot cascade into a second replacement.
fn replaceFirstEach(a: std.mem.Allocator, content: []const u8, pairs: []const Pair) ![]const u8 {
    if (pairs.len == 0) return content;

    const done = try a.alloc(bool, pairs.len);
    @memset(done, false);

    var out = Buf.init(a);
    defer out.deinit();

    var i: usize = 0;
    while (i < content.len) {
        var matched = false;
        for (pairs, 0..) |p, pi| {
            if (done[pi] or p.needle.len == 0) continue;
            if (std.mem.startsWith(u8, content[i..], p.needle)) {
                try out.append(p.replacement);
                i += p.needle.len;
                done[pi] = true;
                matched = true;
                break;
            }
        }
        if (!matched) {
            try out.appendByte(content[i]);
            i += 1;
        }
    }
    return out.toOwned();
}

/// The PWA manifest. Upstream marshals a struct with `json.Encoder`, which
/// emits the fields in declaration order and appends a newline; both are
/// reproduced so a cached manifest stays byte-identical across the two builds.
fn manifestJson(a: std.mem.Allocator, base_path: []const u8, settings: Settings) ![]const u8 {
    const logo_url = firstLine(settings.logo);

    var b = Buf.init(a);
    defer b.deinit();
    try b.append("{\"display\":\"standalone\",\"scope\":");
    try writeJsonString(&b, base_path);
    try b.append(",\"start_url\":");
    try writeJsonString(&b, base_path);
    try b.append(",\"name\":");
    try writeJsonString(&b, settings.site_title);
    try b.append(",\"icons\":[{\"src\":");
    try writeJsonString(&b, logo_url);
    try b.append(",\"sizes\":\"512x512\",\"type\":\"image/png\"}]}\n");
    return b.toOwned();
}

/// `strings.Split(s, "\n")[0]`. OpenList stores the logo as a multi-line text
/// setting (light and dark variants); the manifest takes the light one.
fn firstLine(s: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, s, '\n')) |i| return s[0..i];
    return s;
}

/// JSON string escaping, matching Go's `encoding/json` for the subset that can
/// appear here: `"` `\` and the C0 controls. `<`, `>` and `&` are escaped as
/// `\u003c`/`\u003e`/`\u0026` by Go's default `SetEscapeHTML(true)`, and the
/// site title and logo URL are both operator-controlled, so they get the same
/// treatment rather than being emitted raw into an HTML-adjacent document.
fn writeJsonString(b: *Buf, s: []const u8) !void {
    try b.appendByte('"');
    for (s) |c| switch (c) {
        '"' => try b.append("\\\""),
        '\\' => try b.append("\\\\"),
        '\n' => try b.append("\\n"),
        '\r' => try b.append("\\r"),
        '\t' => try b.append("\\t"),
        '<' => try b.append("\\u003c"),
        '>' => try b.append("\\u003e"),
        '&' => try b.append("\\u0026"),
        else => {
            if (c < 0x20) {
                try b.print("\\u{x:0>4}", .{c});
            } else {
                try b.appendByte(c);
            }
        },
    };
    try b.appendByte('"');
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn stripLeadingSlash(p: []const u8) []const u8 {
    if (p.len > 0 and p[0] == '/') return p[1..];
    return p;
}

/// Reject anything that could escape `dist_dir`. `http.Request.path` is
/// percent-decoded, so `%2e%2e%2f` arrives here as `../` and has to be caught
/// by name; the caller has already collapsed nothing.
fn isSafeRelative(rel: []const u8) bool {
    if (rel.len == 0) return false;
    if (std.mem.indexOfScalar(u8, rel, 0) != null) return false;
    var it = std.mem.splitScalar(u8, rel, '/');
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

/// Stand-in for OpenList's embedded `public/dist`.
///
/// Not a frontend: a diagnostic page that proves the server is up and names
/// the two ways to get the real UI. It deliberately reuses the upstream
/// placeholder tokens (`Loading...`, both `res.oplist.org` logo URLs,
/// `cdn:`/`base_path:`/`main_color: undefined`, `href="/manifest.json"`, and
/// both customisation comments) so that the substitution pipeline is exercised
/// identically whether the shell came from here, from `dist_dir`, or from a
/// CDN.
const BUILTIN_INDEX =
    \\<!doctype html>
    \\<html lang="zh-CN">
    \\  <head>
    \\    <!-- customize head -->
    \\    <meta charset="utf-8" />
    \\    <meta name="viewport" content="width=device-width, initial-scale=1" />
    \\    <meta name="color-scheme" content="light dark" />
    \\    <meta name="generator" content="OpenList" />
    \\    <link href="/manifest.json" rel="manifest" />
    \\    <link rel="apple-touch-icon" href="https://res.oplist.org/logo/logo.png" />
    \\    <link rel="shortcut icon" type="image/svg+xml" href="https://res.oplist.org/logo/logo.svg" />
    \\    <title>Loading...</title>
    \\    <script>
    \\      window.OPENLIST_CONFIG = {
    \\        cdn: undefined,
    \\        base_path: undefined,
    \\        api: undefined,
    \\        main_color: undefined,
    \\      }
    \\      window.__dynamic_base__ = window.OPENLIST_CONFIG.cdn || ""
    \\    </script>
    \\    <style>
    \\      :root { --fg:#1f2328; --bg:#ffffff; --dim:#59636e; --line:#d1d9e0; --code:#f6f8fa; }
    \\      @media (prefers-color-scheme: dark) {
    \\        :root { --fg:#e6edf3; --bg:#0d1117; --dim:#9198a1; --line:#30363d; --code:#161b22; }
    \\      }
    \\      body { font:15px/1.65 system-ui,-apple-system,"Segoe UI","Noto Sans CJK SC",sans-serif;
    \\             background:var(--bg); color:var(--fg); max-width:760px; margin:0 auto; padding:40px 20px; }
    \\      h1 { font-size:1.5rem; margin:0 0 .25rem; }
    \\      .sub { color:var(--dim); margin:0 0 2rem; }
    \\      h2 { font-size:1rem; margin:2rem 0 .5rem; border-bottom:1px solid var(--line); padding-bottom:.35rem; }
    \\      code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.875em; }
    \\      code { background:var(--code); padding:.15em .4em; border-radius:4px; }
    \\      pre { background:var(--code); border:1px solid var(--line); border-radius:6px; padding:12px 14px; overflow-x:auto; }
    \\      ul { padding-left:1.3rem; } li { margin:.3rem 0; }
    \\      a { color:var(--accent,#1890ff); }
    \\      .pill { display:inline-block; border:1px solid var(--line); border-radius:999px;
    \\              padding:.1em .7em; font-size:.78em; color:var(--dim); }
    \\    </style>
    \\  </head>
    \\  <body>
    \\    <h1 id="title">OpenList</h1>
    \\    <p class="sub">Zig 重写版已启动。当前提供的是内置占位页，不是完整前端。</p>
    \\    <p class="pill" id="mode"></p>
    \\
    \\    <h2>为什么不是完整前端</h2>
    \\    <p>原版把编译好的前端（完整版约 20&nbsp;MB，lite 版约 2.9&nbsp;MB）用
    \\    <code>//go:embed</code> 编进 Go 二进制。本项目存在的意义正是去掉这部分体积，
    \\    因此这里改为在运行时从外部加载，行为与原版一致。</p>
    \\
    \\    <h2>方式一：本地 dist 目录（推荐）</h2>
    \\    <p>下载官方 lite 前端并解压，然后把 <code>dist_dir</code> 指向该目录：</p>
    \\    <pre>curl -L -o fe.tar.gz \\
    \\  https://github.com/OpenListTeam/OpenList-Frontend/releases/latest/download/openlist-frontend-dist-lite.tar.gz
    \\mkdir -p data/dist &amp;&amp; tar -xzf fe.tar.gz -C data/dist</pre>
    \\    <p>在 <code>config.json</code> 中设置：</p>
    \\    <pre>{ "dist_dir": "data/dist" }</pre>
    \\
    \\    <h2>方式二：CDN</h2>
    \\    <p>把 dist 目录挂到任意静态托管上，然后在 <code>config.json</code> 中设置
    \\    <code>cdn</code>。其中 <code>$version</code> 会替换为
    \\    <code>web_version</code>（去掉前导 <code>v</code>）：</p>
    \\    <pre>{ "cdn": "https://your-cdn.example.com/openlist/$version/dist",
    \\  "zig": { "web_version": "v4.2.6" } }</pre>
    \\    <p>启动时会从 <code>{cdn}/index.html</code> 拉取页面外壳，
    \\    <code>/assets/</code>、<code>/images/</code>、<code>/streamer/</code>、
    \\    <code>/static/</code> 四个前缀则 302 跳转到 CDN。</p>
    \\
    \\    <h2>接口</h2>
    \\    <ul>
    \\      <li><code>GET /ping</code> — 存活探测</li>
    \\      <li><code>GET /api/public/settings</code> — 站点配置</li>
    \\      <li><code>POST /api/auth/login</code> — 登录换取 JWT</li>
    \\      <li><code>POST /api/fs/list</code> — 列目录</li>
    \\      <li><code>GET /d/*</code> — 下载</li>
    \\    </ul>
    \\    <p class="sub">接口是 OpenList 的子集，完整前端只会有部分功能可用，
    \\    详见 <code>docs/STATUS.md</code>。</p>
    \\
    \\    <script>
    \\      // The tokens above are substituted at startup; reflect the two that
    \\      // are visible so a misconfiguration is obvious from the page itself.
    \\      var c = window.OPENLIST_CONFIG;
    \\      if (c.main_color) {
    \\        document.documentElement.style.setProperty("--accent", c.main_color);
    \\      }
    \\      var parts = [];
    \\      if (c.base_path &amp;&amp; c.base_path !== "/") parts.push("base_path " + c.base_path);
    \\      parts.push(c.cdn ? "assets → CDN" : "assets → 本地");
    \\      document.getElementById("mode").textContent = parts.join(" · ");
    \\    </script>
    \\    <!-- customize body -->
    \\  </body>
    \\</html>
;

// ---------------------------------------------------------------------------

const testing = std.testing;

/// The upstream frontend's `index.html`, verbatim (`OpenList-Frontend` @ main,
/// v4.2.6). Kept here so the substitution tests run against the real artefact
/// rather than a paraphrase of it — the whole point of the exercise is that
/// the shipped HTML is what gets rewritten at startup.
const UPSTREAM_INDEX_HTML =
    \\<!doctype html>
    \\<html lang="en" translate="no">
    \\  <head>
    \\    <!-- customize head -->
    \\    <meta charset="utf-8" />
    \\    <meta name="viewport" content="width=device-width, initial-scale=1" />
    \\    <meta name="referrer" content="same-origin" />
    \\    <meta name="color-scheme" content="light dark" />
    \\    <meta name="generator" content="OpenList" />
    \\    <meta name="theme-color" content="#000000" />
    \\    <meta name="google" content="notranslate" />
    \\    <link href="/manifest.json" rel="manifest" />
    \\    <meta name="apple-mobile-web-app-capable" content="yes" />
    \\    <meta name="apple-mobile-web-app-title" content="OpenList" />
    \\    <link rel="apple-touch-icon" href="https://res.oplist.org/logo/logo.png" />
    \\    <link
    \\      rel="shortcut icon"
    \\      type="image/ico"
    \\      href="https://res.oplist.org/logo/logo.svg"
    \\    />
    \\    <title>Loading...</title>
    \\    <script>
    \\      window.OPENLIST_CONFIG = {
    \\        cdn: undefined,
    \\        base_path: undefined,
    \\        api: undefined,
    \\        main_color: undefined,
    \\      }
    \\      window.__dynamic_base__ = window.OPENLIST_CONFIG.cdn || ""
    \\    </script>
    \\  </head>
    \\  <body>
    \\    <noscript>You need to enable JavaScript to run this app.</noscript>
    \\    <div id="root"></div>
    \\
    \\    <script src="/src/main.tsx" type="module"></script>
    \\    <!-- customize body -->
    \\  </body>
    \\</html>
;

test "pathOfUrl extracts the path component" {
    try testing.expectEqualStrings("", pathOfUrl(""));
    try testing.expectEqualStrings("", pathOfUrl("https://example.com"));
    try testing.expectEqualStrings("/", pathOfUrl("https://example.com/"));
    try testing.expectEqualStrings("/sub", pathOfUrl("https://example.com/sub"));
    // The trailing slash is part of the path; `basePathFrom` is what trims it.
    try testing.expectEqualStrings("/sub/", pathOfUrl("https://example.com/sub/"));
    try testing.expectEqualStrings("/sub/", pathOfUrl("https://example.com/sub/?a=1"));
    try testing.expectEqualStrings("/sub", pathOfUrl("https://example.com/sub#frag"));
    try testing.expectEqualStrings("/sub", pathOfUrl("http://example.com:5244/sub"));
    // A bare path is accepted too.
    try testing.expectEqualStrings("/sub", pathOfUrl("/sub"));
}

test "expandVersion substitutes every occurrence and strips a leading v" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings(
        "https://c.example.com/4.2.6/dist",
        try expandVersion(a, "https://c.example.com/$version/dist/", "v4.2.6"),
    );
    try testing.expectEqualStrings(
        "https://c.example.com/rolling/dist",
        try expandVersion(a, "https://c.example.com/$version/dist", "rolling"),
    );
    // No placeholder: the trailing slash is still trimmed.
    try testing.expectEqualStrings(
        "https://c.example.com/dist",
        try expandVersion(a, "https://c.example.com/dist/", "v1.0.0"),
    );
    // Empty stays empty, which is what makes the default fallback work.
    try testing.expectEqualStrings("", try expandVersion(a, "", "rolling"));
}

test "sourceFor picks the CDN whenever no dist_dir is set" {
    try testing.expectEqual(Source.builtin, sourceFor(.{}));
    try testing.expectEqual(Source.cdn, sourceFor(.{ .cdn = "https://c.example.com/dist" }));
    // The divergence from upstream: a *pinned* web_version must still fetch from
    // the CDN, because there is no embedded frontend to prefer. Upstream would
    // fall back to its embedded copy here.
    try testing.expectEqual(Source.cdn, sourceFor(.{
        .cdn = "https://c.example.com/$version/dist",
        .web_version = "v4.2.6",
    }));
    // A dist_dir wins over the CDN, as upstream.
    try testing.expectEqual(Source.dist_dir, sourceFor(.{ .cdn = "https://c/x", .dist_dir = "/fe" }));
    try testing.expectEqual(Source.dist_dir, sourceFor(.{ .dist_dir = "/fe" }));
}

test "siteConfig follows OpenList's getSiteConfig" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Default install: no site_url, no cdn. base_path "/" and the normalised
    // cdn falls back to TrimSuffix("/", "/") == "".
    {
        const s = try siteConfig(a, .{});
        try testing.expectEqualStrings("/", s.base_path);
        try testing.expectEqualStrings("", s.cdn);
    }
    // Non-root base path with no cdn: the normalised cdn becomes the base path
    // minus its trailing slash, so the shell asks for assets under /sub.
    {
        const s = try siteConfig(a, .{ .site_url = "https://example.com/sub/" });
        try testing.expectEqualStrings("/sub", s.base_path);
        try testing.expectEqualStrings("/sub", s.cdn);
    }
    // Real cdn wins over the fallback.
    {
        const s = try siteConfig(a, .{
            .site_url = "https://example.com/sub",
            .cdn = "https://c.example.com/$version/dist",
            .web_version = "v4.2.6",
        });
        try testing.expectEqualStrings("/sub", s.base_path);
        try testing.expectEqualStrings("https://c.example.com/4.2.6/dist", s.cdn);
    }
}

test "placeholder substitution rewrites the real upstream index.html" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try initFromHtml(a, .{
        .cdn = "https://cdn.example.com/rolling/dist",
        .web_version = "rolling",
        .settings = .{ .site_title = "My 光猫", .main_color = "#ff0000" },
    }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();

    const html = fe.index_html;
    try testing.expect(std.mem.indexOf(u8, html, "cdn: 'https://cdn.example.com/rolling/dist'") != null);
    try testing.expect(std.mem.indexOf(u8, html, "base_path: '/'") != null);
    try testing.expect(std.mem.indexOf(u8, html, "main_color: '#ff0000'") != null);
    try testing.expect(std.mem.indexOf(u8, html, "<title>My 光猫</title>") != null);
    // `api: undefined` is left alone, matching upstream.
    try testing.expect(std.mem.indexOf(u8, html, "api: undefined") != null);
    // Every placeholder was consumed.
    try testing.expect(std.mem.indexOf(u8, html, "undefined'") == null);
    try testing.expect(std.mem.indexOf(u8, html, "Loading...") == null);
    // `href="/manifest.json"` is a no-op at the root, and must stay intact.
    try testing.expect(std.mem.indexOf(u8, html, "href=\"/manifest.json\"") != null);
}

test "base path rewrites the manifest href and the cdn fallback" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try initFromHtml(a, .{ .site_url = "https://example.com/openlist" }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();

    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"/openlist/manifest.json\"") != null);
    // No CDN configured, so the normalised value falls back to the base path.
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "cdn: '/openlist'") != null);
    try testing.expectEqualStrings("/openlist", fe.site.base_path);
}

test "customize blocks reach the public shell but not the admin shell" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try initFromHtml(a, .{
        .settings = .{ .customize_head = "<script>1</script>", .customize_body = "<div>2</div>" },
    }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();

    try testing.expect(std.mem.indexOf(u8, fe.index_html, "<script>1</script>") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "<div>2</div>") != null);
    // The admin shell keeps the raw comments instead of the injected HTML.
    try testing.expect(std.mem.indexOf(u8, fe.manage_html, "<!-- customize head -->") != null);
    try testing.expect(std.mem.indexOf(u8, fe.manage_html, "<script>1</script>") == null);

    try testing.expectEqualStrings(fe.index_html, fe.htmlFor("/"));
    try testing.expectEqualStrings(fe.manage_html, fe.htmlFor("/@manage/storage"));
}

test "a replacement value containing another needle does not cascade" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // The favicon value itself contains the `.png` needle. Go's randomised map
    // order makes the result depend on iteration order here; ours cannot.
    var fe = try initFromHtml(a, .{
        .settings = .{ .favicon = "https://x/logo.png", .logo = "https://x/logo.svg" },
    }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();

    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"https://x/logo.png\"") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"https://x/logo.svg\"") != null);
}

test "asset paths are recognised and cannot escape dist_dir" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expect(isAssetPath("/assets/index-abc.js"));
    try testing.expect(isAssetPath("/images/bg.png"));
    try testing.expect(isAssetPath("/streamer/hls.m3u8"));
    try testing.expect(isAssetPath("/static/logo.svg"));
    // Needs the trailing slash: a storage mounted at /static is not an asset.
    try testing.expect(!isAssetPath("/static"));
    try testing.expect(!isAssetPath("/staticx/a"));
    try testing.expect(!isAssetPath("/@manage"));
    try testing.expect(!isAssetPath("/"));
    // The four names are not allowed to be matched as bare prefixes.
    try testing.expect(!isAssetPath("/assetsx/a.js"));

    try testing.expect(isSafeRelative("assets/a.js"));
    try testing.expect(!isSafeRelative("../etc/passwd"));
    try testing.expect(!isSafeRelative("assets/../../etc/passwd"));
    try testing.expect(!isSafeRelative(""));
    try testing.expect(!isSafeRelative("a/\x00b"));

    // With a CDN configured the asset is a redirect, and the encoded target is
    // what gets appended — not the decoded path.
    var fe = try initFromHtml(a, .{ .cdn = "https://c.example.com/dist" }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();
    const r = fe.asset(a, "/assets/a b.js", "/assets/a%20b.js?v=1");
    try testing.expectEqualStrings("https://c.example.com/dist/assets/a%20b.js?v=1", r.redirect);

    // With neither a CDN nor a dist dir there is nothing to serve.
    var fe2 = try initFromHtml(a, .{}, UPSTREAM_INDEX_HTML);
    defer fe2.deinit();
    try testing.expect(std.meta.activeTag(fe2.asset(a, "/assets/a.js", "/assets/a.js")) == .missing);
}

test "manifest matches upstream's shape" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fe = try initFromHtml(a, .{
        .site_url = "https://example.com/sub",
        .settings = .{ .site_title = "Home", .logo = "https://x/logo.svg\nhttps://x/dark.svg" },
    }, UPSTREAM_INDEX_HTML);
    defer fe.deinit();

    // Scope and start_url follow the base path; the logo is the first line only.
    try testing.expectEqualStrings(
        "{\"display\":\"standalone\",\"scope\":\"/sub\",\"start_url\":\"/sub\",\"name\":\"Home\"," ++
            "\"icons\":[{\"src\":\"https://x/logo.svg\",\"sizes\":\"512x512\",\"type\":\"image/png\"}]}\n",
        fe.manifest_json,
    );
}

test "the builtin shell carries every token the pipeline looks for" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const tokens = [_][]const u8{
        "cdn: undefined",
        "base_path: undefined",
        "main_color: undefined",
        "Loading...",
        "https://res.oplist.org/logo/logo.svg",
        "https://res.oplist.org/logo/logo.png",
        "href=\"/manifest.json\"",
        "<!-- customize head -->",
        "<!-- customize body -->",
    };
    // A typo in the constant would show up as a missing token.
    for (tokens) |tok| try testing.expect(std.mem.indexOf(u8, BUILTIN_INDEX, tok) != null);

    // Every replacement is given a value distinct from its token, so "the token
    // is gone" really does mean it was substituted. With the *defaults* two of
    // these are identity replacements — favicon is literally the logo.svg URL,
    // and the manifest href is unchanged at the root — and the token would
    // legitimately survive.
    var fe = try initFromHtml(a, .{
        .site_url = "https://example.com/sub",
        .settings = .{
            .site_title = "T",
            .favicon = "https://x/f.ico",
            .logo = "https://x/l.png",
            .main_color = "#123456",
            .customize_head = "<!--h-->",
            .customize_body = "<!--b-->",
        },
    }, BUILTIN_INDEX);
    defer fe.deinit();

    try testing.expectEqual(Source.builtin, fe.source);
    for (tokens) |tok| {
        try testing.expect(std.mem.indexOf(u8, fe.index_html, tok) == null);
    }
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "<title>T</title>") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "cdn: '/sub'") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "base_path: '/sub'") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "main_color: '#123456'") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"/sub/manifest.json\"") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"https://x/f.ico\"") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "href=\"https://x/l.png\"") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "<!--h-->") != null);
    try testing.expect(std.mem.indexOf(u8, fe.index_html, "<!--b-->") != null);
}
