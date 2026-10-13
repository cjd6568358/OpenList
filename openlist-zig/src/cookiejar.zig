//! Cookie jar with Go-compatible persistence.
//!
//! Two things make this more than a `HashMap(name, value)`:
//!
//!  1. **Scoping.** itvsh hands out a WAF challenge cookie on `pan.itvsh.cn`
//!     and a session cookie on the *per-user* `forwardUrl` host, which is only
//!     discovered after login. Cookies must therefore be matched by
//!     domain/path/secure rather than kept in one flat bag, and the driver
//!     needs a "re-graft" operation to move them onto the real host once it is
//!     known (see `setForHost`).
//!
//!  2. **Wire compatibility.** `toJson` emits the exact shape Go's
//!     `encoding/json` produces for `[]*http.Cookie`, so an existing
//!     OpenList `config.json` can be dropped in front of this binary and the
//!     stored session keeps working. That is a migration requirement, not a
//!     nicety: users upgrading in place must not be forced to re-login.
//!
//! **Ownership invariant:** every cookie inside a `Jar` is a deep copy made
//! from `Jar.alloc`; callers may pass borrowed slices (header text, request
//! arenas, parsed JSON) and keep using their own memory afterwards. All
//! mutation funnels through `store`, which copies on the way in and frees the
//! previous occupant on replace/expire; `deinit` frees the rest. This
//! invariant is load-bearing: it once existed only as a convention, and the
//! gap between "caller dupes" and "jar takes what it is given" made
//! `restoreCookies` store pointers into a request arena that was freed on
//! return — the next request then read recycled heap pages as cookie names
//! (garbage cookies got persisted into config.json) and, once the arena was
//! big enough to be mmap'd, died with SIGSEGV inside `pathMatches`.

const std = @import("std");
const Buf = @import("util/buf.zig").Buf;
const List = @import("util/buf.zig").List;
const json = @import("util/json.zig");
const log = @import("log.zig");
const rt = @import("rt.zig");

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    path: []const u8 = "/",
    /// Empty for host-only cookies.
    domain: []const u8 = "",
    /// Unix seconds; 0 means "session cookie".
    expires: i64 = 0,
    /// Max-Age in seconds; 0 means "not specified".
    max_age: i64 = 0,
    secure: bool = false,
    http_only: bool = false,
    /// Go `http.SameSite`: 0 unset, 1 Default, 2 Lax, 3 Strict, 4 None.
    same_site: u8 = 0,
    /// True when the cookie came from a `Set-Cookie` without a Domain attr.
    host_only: bool = true,

    pub fn isExpired(self: Cookie, now: i64) bool {
        if (self.max_age < 0) return true;
        if (self.max_age > 0 and self.expires != 0 and now >= self.expires) return true;
        if (self.expires != 0 and now >= self.expires) return true;
        return false;
    }

    /// RFC 6265 §5.1.3 domain matching, Go's `jar` semantics.
    pub fn domainMatches(self: Cookie, host: []const u8) bool {
        if (self.domain.len == 0) return false;
        if (self.host_only) return std.ascii.eqlIgnoreCase(host, self.domain);
        if (std.ascii.eqlIgnoreCase(host, self.domain)) return true;
        // host must end with "." ++ domain
        if (host.len <= self.domain.len) return false;
        const tail = host[host.len - self.domain.len - 1 ..];
        if (tail[0] != '.') return false;
        return std.ascii.eqlIgnoreCase(tail[1..], self.domain);
    }

    /// RFC 6265 §5.1.4 path matching.
    pub fn pathMatches(self: Cookie, req_path: []const u8) bool {
        const cp = if (self.path.len == 0) "/" else self.path;
        if (std.mem.eql(u8, cp, req_path)) return true;
        if (!std.mem.startsWith(u8, req_path, cp)) return false;
        if (cp[cp.len - 1] == '/') return true;
        return req_path.len > cp.len and req_path[cp.len] == '/';
    }
};

pub const Jar = struct {
    alloc: std.mem.Allocator,
    cookies: List(Cookie),
    lock: std.Io.Mutex = .init,

    pub fn init(alloc: std.mem.Allocator) Jar {
        return .{ .alloc = alloc, .cookies = List(Cookie).init(alloc) };
    }

    pub fn deinit(self: *Jar) void {
        for (self.cookies.data[0..self.cookies.len]) |c| freeCookie(self.alloc, c);
        self.cookies.deinit();
    }

    pub fn count(self: *Jar) usize {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());
        return self.cookies.len;
    }

    /// Feed one `Set-Cookie` header value. `host` is the host of the request
    /// that produced it (no scheme, no port).
    ///
    /// All string fields of the built cookie are *borrowed* (slices of the
    /// header or of `req_path`); `store` deep-copies them into the jar.
    /// Garbage is rejected rather than stored: a non-token cookie name,
    /// control characters, invalid UTF-8, or oversized fields mean the
    /// upstream is not speaking cookie grammar at us — RFC 6265 §5.2 says to
    /// ignore such a Set-Cookie entirely. Storing it anyway is how a JSON
    /// response fragment ends up masquerading as a session cookie.
    pub fn setFromResponse(self: *Jar, host: []const u8, req_path: []const u8, header: []const u8, now: i64) !void {
        if (header.len == 0 or header.len > max_header_len) return;
        var c = Cookie{
            .name = "",
            .value = "",
            .path = defaultPath(req_path),
        };

        var it = std.mem.splitScalar(u8, header, ';');
        const first = it.next() orelse return;
        const eq = std.mem.indexOfScalar(u8, first, '=') orelse return;
        const name = std.mem.trim(u8, first[0..eq], " \t");
        const value = std.mem.trim(u8, first[eq + 1 ..], " \t");
        if (name.len == 0 or name.len > max_name_len) return;
        if (value.len > max_value_len) return;
        if (!std.unicode.utf8ValidateSlice(name) or !std.unicode.utf8ValidateSlice(value)) return;
        if (hasControlChars(name) or hasControlChars(value)) return;
        if (!isToken(name)) return;
        c.name = name;
        c.value = value;

        var has_domain = false;
        var max_age_seen = false;
        while (it.next()) |raw| {
            const attr = std.mem.trim(u8, raw, " \t");
            if (attr.len == 0) continue;
            const aeq = std.mem.indexOfScalar(u8, attr, '=');
            const key = if (aeq) |i| std.mem.trim(u8, attr[0..i], " \t") else attr;
            const val = if (aeq) |i| std.mem.trim(u8, attr[i + 1 ..], " \t") else "";

            if (std.ascii.eqlIgnoreCase(key, "Domain")) {
                var d = val;
                if (d.len > 0 and d[0] == '.') d = d[1..];
                if (d.len == 0) continue;
                // Reject cookies scoped to a public suffix or unrelated host:
                // this is the difference between "works" and "leaks the
                // session to whatever the WAF redirects us to".
                if (!domainIsAcceptable(host, d)) continue;
                c.domain = d;
                c.host_only = false;
                has_domain = true;
            } else if (std.ascii.eqlIgnoreCase(key, "Path")) {
                if (val.len > 0 and val[0] == '/') c.path = val;
            } else if (std.ascii.eqlIgnoreCase(key, "Max-Age")) {
                c.max_age = std.fmt.parseInt(i64, val, 10) catch 0;
                max_age_seen = true;
                if (c.max_age > 0) c.expires = now + c.max_age;
                if (c.max_age <= 0) c.expires = now - 1; // delete
            } else if (std.ascii.eqlIgnoreCase(key, "Expires")) {
                if (!max_age_seen) {
                    if (parseHttpDate(val)) |t| c.expires = t;
                }
            } else if (std.ascii.eqlIgnoreCase(key, "Secure")) {
                c.secure = true;
            } else if (std.ascii.eqlIgnoreCase(key, "HttpOnly")) {
                c.http_only = true;
            } else if (std.ascii.eqlIgnoreCase(key, "SameSite")) {
                c.same_site = if (std.ascii.eqlIgnoreCase(val, "Strict")) 3 else if (std.ascii.eqlIgnoreCase(val, "None")) 4 else if (std.ascii.eqlIgnoreCase(val, "Lax")) 2 else 1;
            }
        }
        if (!has_domain) c.domain = host;

        self.store(c, now);
    }

    /// Insert or replace, matching Go's `cookiejar` identity (name, domain, path).
    ///
    /// Takes a deep copy of every string field (see the ownership invariant in
    /// the module docs), so `c` may reference memory the caller frees right
    /// after the call. Replacing an existing cookie frees the old strings;
    /// an expired replacement removes the entry instead.
    pub fn store(self: *Jar, c_in: Cookie, now: i64) void {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());

        var i: usize = 0;
        while (i < self.cookies.len) {
            const e = self.cookies.data[i];
            if (std.mem.eql(u8, e.name, c_in.name) and
                std.ascii.eqlIgnoreCase(e.domain, c_in.domain) and
                std.mem.eql(u8, e.path, c_in.path))
            {
                if (c_in.isExpired(now)) {
                    // remove: swap-with-last, order is irrelevant here
                    freeCookie(self.alloc, e);
                    self.cookies.data[i] = self.cookies.data[self.cookies.len - 1];
                    self.cookies.len -= 1;
                    return;
                }
                const fresh = self.dupeCookie(c_in) catch |err| {
                    log.warn("cookiejar: store failed: {s}", .{@errorName(err)});
                    return;
                };
                freeCookie(self.alloc, e);
                self.cookies.data[i] = fresh;
                return;
            }
            i += 1;
        }
        if (c_in.isExpired(now)) return;
        const fresh = self.dupeCookie(c_in) catch |err| {
            log.warn("cookiejar: store failed: {s}", .{@errorName(err)});
            return;
        };
        self.cookies.append(fresh) catch |err| {
            freeCookie(self.alloc, fresh);
            log.warn("cookiejar: store failed: {s}", .{@errorName(err)});
        };
    }

    /// Deep-copy a caller-supplied cookie. Only ever fails on OOM; the caller
    /// then must not use the partially copied result.
    fn dupeCookie(self: *Jar, c: Cookie) !Cookie {
        return Cookie{
            .name = try self.alloc.dupe(u8, c.name),
            .value = try self.alloc.dupe(u8, c.value),
            .path = try self.alloc.dupe(u8, c.path),
            .domain = try self.alloc.dupe(u8, c.domain),
            .expires = c.expires,
            .max_age = c.max_age,
            .secure = c.secure,
            .http_only = c.http_only,
            .same_site = c.same_site,
            .host_only = c.host_only,
        };
    }

    /// Graft a batch of cookies onto `host`, ignoring their stored domain.
    /// Used by itvsh's `regraftCookies`: before login the jar only knows
    /// `apiBase`, so persisted cookies land on the wrong host and must be
    /// re-scoped once `forwardUrl` is known.
    ///
    /// `cookies` is borrowed (it typically points into a request arena that
    /// dies on return) — `store` deep-copies everything, so the grafted
    /// cookies outlive the caller's memory.
    pub fn setForHost(self: *Jar, host: []const u8, cookies: []const Cookie) void {
        for (cookies) |c| {
            var c2 = c;
            c2.domain = host;
            c2.host_only = true;
            self.store(c2, rt.nowSeconds());
        }
    }

    /// Append a `Cookie:` header value for the given target. Returns false if
    /// there is nothing to send.
    pub fn headerFor(self: *Jar, host: []const u8, path: []const u8, secure: bool, now: i64, out: *Buf) !bool {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());

        var any = false;
        for (self.cookies.data[0..self.cookies.len]) |c| {
            if (c.isExpired(now)) continue;
            if (c.secure and !secure) continue;
            if (!c.domainMatches(host)) continue;
            if (!c.pathMatches(path)) continue;
            if (any) try out.append("; ");
            try out.append(c.name);
            try out.appendByte('=');
            try out.append(c.value);
            any = true;
        }
        return any;
    }

    /// Cookies that would be sent to `host`, as **deep copies** owned by the
    /// caller's allocator. Deep (not borrowed) so the result stays valid after
    /// the jar mutates or is cleared — the borrowed variant is what let the
    /// itvsh re-graft read freed memory.
    pub fn cookiesFor(self: *Jar, alloc: std.mem.Allocator, host: []const u8, now: i64) ![]Cookie {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());
        var l = List(Cookie).init(alloc);
        errdefer {
            for (l.slice()) |x| freeCookie(alloc, x);
            l.deinit();
        }
        for (self.cookies.data[0..self.cookies.len]) |c| {
            if (c.isExpired(now)) continue;
            if (!c.domainMatches(host)) continue;
            try l.append(try dupeInto(alloc, c));
        }
        return l.toOwned();
    }

    /// Every stored cookie, ignoring scope, as deep copies owned by `alloc`.
    /// Used by itvsh's cookie re-graft, which must move the whole persisted
    /// set onto a newly discovered host.
    pub fn allCookies(self: *Jar, alloc: std.mem.Allocator) ![]Cookie {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());
        var l = List(Cookie).init(alloc);
        errdefer {
            for (l.slice()) |x| freeCookie(alloc, x);
            l.deinit();
        }
        for (self.cookies.data[0..self.cookies.len]) |c| {
            try l.append(try dupeInto(alloc, c));
        }
        return l.toOwned();
    }

    pub fn clear(self: *Jar) void {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());
        for (self.cookies.data[0..self.cookies.len]) |c| freeCookie(self.alloc, c);
        self.cookies.len = 0;
    }

    // -----------------------------------------------------------------------
    // Go-compatible persistence
    // -----------------------------------------------------------------------

    /// Serialize as Go's `json.Marshal([]*http.Cookie)`.
    /// Field names/types match `net/http.Cookie` exactly so the same blob can
    /// be read by the Go build and vice versa.
    pub fn toJson(self: *Jar, alloc: std.mem.Allocator) ![]u8 {
        self.lock.lockUncancelable(rt.io());
        defer self.lock.unlock(rt.io());
        var b = Buf.init(alloc);
        try b.appendByte('[');
        var first = true;
        for (self.cookies.data[0..self.cookies.len]) |c| {
            if (!first) try b.appendByte(',');
            first = false;
            try b.append("{\"Name\":");
            try json.writeString(&b, c.name);
            try b.append(",\"Value\":");
            try json.writeString(&b, c.value);
            try b.append(",\"Path\":");
            try json.writeString(&b, c.path);
            try b.append(",\"Domain\":");
            try json.writeString(&b, c.domain);
            if (c.expires != 0) {
                try b.append(",\"Expires\":");
                try json.writeString(&b, try httpDate(alloc, c.expires));
            }
            try b.append(",\"RawExpires\":\"\"");
            try b.print(",\"MaxAge\":{d}", .{c.max_age});
            try b.append(",\"Secure\":");
            try b.append(if (c.secure) "true" else "false");
            try b.append(",\"HttpOnly\":");
            try b.append(if (c.http_only) "true" else "false");
            try b.print(",\"SameSite\":{d}", .{c.same_site});
            try b.append(",\"Partitioned\":false,\"Raw\":\"\"");
            try b.append(",\"Unparsed\":null}");
        }
        try b.appendByte(']');
        return b.toOwned();
    }

    /// Parse the blob produced by `toJson` (or by the Go build).
    ///
    /// The JSON tree is parsed into a scratch arena and dropped on return;
    /// `store` keeps deep copies in the jar's own allocator, so the jar never
    /// points into parser scratch.
    pub fn fromJson(self: *Jar, text: []const u8) !void {
        if (text.len == 0) return;
        var arena = std.heap.ArenaAllocator.init(self.alloc);
        defer arena.deinit();
        const v = json.parse(arena.allocator(), text) catch |e| {
            log.warn("cookiejar: corrupt cookie blob ({s}), starting clean", .{@errorName(e)});
            return;
        };
        const arr = v.asArray() orelse return;
        for (arr) |*item| {
            const name = item.strAt("Name") orelse continue;
            const value = item.strAt("Value") orelse "";
            const path = item.strAt("Path") orelse "/";
            const domain = item.strAt("Domain") orelse "";
            if (domain.len == 0) continue; // cannot scope it, drop
            // Same gate as setFromResponse: a blob written by a buggy build
            // (or hand-edited) can contain response-body fragments — skipping
            // them keeps the jar usable instead of sending junk upstream.
            if (name.len == 0 or name.len > max_name_len) continue;
            if (value.len > max_value_len) continue;
            if (!std.unicode.utf8ValidateSlice(name)) continue;
            if (!std.unicode.utf8ValidateSlice(value)) continue;
            if (hasControlChars(name) or hasControlChars(value)) continue;
            if (!isToken(name)) continue;
            const c = Cookie{
                .name = name,
                .value = value,
                .path = if (path.len == 0) "/" else path,
                .domain = domain,
                .expires = if (item.strAt("Expires")) |s| (parseHttpDate(s) orelse 0) else 0,
                .max_age = item.intAt("MaxAge") orelse 0,
                .secure = item.getPath("Secure").?.asBool() orelse false,
                .http_only = item.getPath("HttpOnly").?.asBool() orelse false,
                .same_site = @intCast(std.math.clamp(item.intAt("SameSite") orelse 0, 0, 4)),
                .host_only = false,
            };
            self.store(c, rt.nowSeconds());
        }
    }
};

fn defaultPath(req_path: []const u8) []const u8 {
    if (req_path.len == 0 or req_path[0] != '/') return "/";
    const last = std.mem.lastIndexOfScalar(u8, req_path, '/') orelse return "/";
    if (last == 0) return "/";
    return req_path[0..last];
}

/// Free the strings of a jar-owned cookie (see the ownership invariant).
/// Every stored cookie's strings are deep copies from the jar allocator —
/// including the ones that were literal "/" before `store` copied them.
fn freeCookie(alloc: std.mem.Allocator, c: Cookie) void {
    alloc.free(@constCast(c.name));
    alloc.free(@constCast(c.value));
    alloc.free(@constCast(c.path));
    alloc.free(@constCast(c.domain));
}

/// Deep-copy a cookie into `alloc`. Caller owns the result and frees it with
/// `freeCookie`.
fn dupeInto(alloc: std.mem.Allocator, c: Cookie) !Cookie {
    return Cookie{
        .name = try alloc.dupe(u8, c.name),
        .value = try alloc.dupe(u8, c.value),
        .path = try alloc.dupe(u8, c.path),
        .domain = try alloc.dupe(u8, c.domain),
        .expires = c.expires,
        .max_age = c.max_age,
        .secure = c.secure,
        .http_only = c.http_only,
        .same_site = c.same_site,
        .host_only = c.host_only,
    };
}

/// RFC 7230 token: cookie names are tokens, and a Set-Cookie whose name is
/// not one is malformed (it is usually a response body or an HTML fragment
/// that leaked into the header stream). Ignoring it is what browsers do.
fn isToken(s: []const u8) bool {
    for (s) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
        else => return false,
    };
    return true;
}

fn hasControlChars(s: []const u8) bool {
    for (s) |ch| {
        if (ch < 0x20 or ch == 0x7f) return true;
    }
    return false;
}

/// Sanity ceilings for Set-Cookie fields. Real cookies are far below these;
/// a header that exceeds them is a broken upstream or an attack, and storing
/// it would both poison the jar and bloat config.json.
const max_header_len = 8 * 1024;
const max_name_len = 512;
const max_value_len = 4096;

/// Go's `cookiejar` rejects a Domain that is not a suffix-match of the host.
fn domainIsAcceptable(host: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, domain)) return true;
    if (host.len <= domain.len) return false;
    const tail = host[host.len - domain.len - 1 ..];
    if (tail[0] != '.') return false;
    if (!std.ascii.eqlIgnoreCase(tail[1..], domain)) return false;
    // Reject single-label domains like "com" — a bare public suffix.
    if (std.mem.indexOfScalar(u8, domain, '.') == null) return false;
    return true;
}

// ---------------------------------------------------------------------------
// HTTP date (RFC 7231 IMF-fixdate)
// ---------------------------------------------------------------------------

const DAYS = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const MONTHS = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// Format unix seconds as `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn httpDate(alloc: std.mem.Allocator, ts: i64) ![]u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(ts, 0)) };
    const day = es.getEpochDay();
    const ds = es.getDaySeconds();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const wd = @mod(day.day + 4, 7); // 1970-01-01 was a Thursday
    return std.fmt.allocPrint(alloc, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        DAYS[@intCast(wd)],
        md.day_index + 1,
        MONTHS[@intCast(md.month.numeric() - 1)],
        yd.year,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    });
}

/// Parse the three date formats `http.ParseTime` accepts: IMF-fixdate
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`)
/// and asctime (`Sun Nov  6 08:49:37 1994`).
pub fn parseHttpDate(s: []const u8) ?i64 {
    var t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return null;
    // Trailing zone. asctime has none.
    for ([_][]const u8{ "GMT", "UTC", "UT" }) |z| {
        if (std.mem.endsWith(u8, t, z)) {
            t = std.mem.trimEnd(u8, t[0 .. t.len - z.len], " \t");
            break;
        }
    }

    // Tokenising on space/comma/dash flattens all three layouts into the same
    // bag of parts, but the *order* differs between them:
    //   IMF-fixdate  Sun, 06 Nov 1994 08:49:37 GMT  -> day month YEAR TIME
    //   RFC 850      Sunday, 06-Nov-94 08:49:37 GMT  -> day month YEAR TIME
    //   asctime      Sun Nov  6 08:49:37 1994        -> month day TIME YEAR
    // So classify each part by *shape*, never by position:
    //   * a month name          -> month
    //   * HH:MM:SS              -> time
    //   * 3+ digit number       -> year
    //   * 1-2 digit number      -> day if not yet seen, otherwise year
    var parts: [8][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, t, " \t,-");
    while (it.next()) |p| {
        if (n == parts.len) return null;
        parts[n] = p;
        n += 1;
    }
    if (n < 4) return null;

    var hh: u8 = 0;
    var mm: u8 = 0;
    var ss: u8 = 0;
    var have_time = false;
    var month: ?u8 = null;
    var day: u8 = 0;
    var year: i64 = 0;
    var have_year = false;

    for (parts[0..n]) |p| {
        if (monthOf(p)) |m| {
            month = m;
            continue;
        }
        if (p.len == 8 and p[2] == ':' and p[5] == ':') {
            hh = std.fmt.parseInt(u8, p[0..2], 10) catch return null;
            mm = std.fmt.parseInt(u8, p[3..5], 10) catch return null;
            ss = std.fmt.parseInt(u8, p[6..8], 10) catch return null;
            if (hh > 23 or mm > 59 or ss > 60) return null;
            have_time = true;
            continue;
        }
        const num = std.fmt.parseInt(u32, p, 10) catch continue;
        if (p.len >= 3) {
            // 1994, or a stray 4-digit field. Last one wins.
            year = num;
            have_year = true;
        } else if (day == 0 and num >= 1 and num <= 31) {
            day = @intCast(num);
        } else {
            // Two-digit year (RFC 850): 70..99 -> 19xx, 00..69 -> 20xx, per
            // RFC 6265.
            year = @as(i64, num) + if (num >= 70) @as(i64, 1900) else @as(i64, 2000);
            have_year = true;
        }
    }

    const m = month orelse return null;
    if (!have_time or !have_year) return null;
    if (day == 0 or year < 1970) return null;
    return daysFromCivil(year, m, day) * 86400 + @as(i64, hh) * 3600 + @as(i64, mm) * 60 + ss;
}

fn monthOf(s: []const u8) ?u8 {
    for (MONTHS, 0..) |m, i| {
        if (std.ascii.eqlIgnoreCase(s, m)) return @intCast(i + 1);
    }
    return null;
}

/// Howard Hinnant's days_from_civil.
fn daysFromCivil(y_in: i64, m: u8, d: u8) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const mp: i64 = @mod(@as(i64, @intCast(@as(u16, m) + 9)), 12);
    const doy = @divTrunc(153 * mp + 2, 5) + @as(i64, d) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "host-only cookie is scoped to its host" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());
    try jar.setFromResponse("pan.itvsh.cn", "/nas/user/login", "SESSION=abc; Path=/; HttpOnly", 1000);

    var out = Buf.init(arena.allocator());
    try testing.expect(try jar.headerFor("pan.itvsh.cn", "/nas/rd_center/data/get", true, 1001, &out));
    try testing.expectEqualStrings("SESSION=abc", out.slice());

    var out2 = Buf.init(arena.allocator());
    try testing.expect(!try jar.headerFor("evil.example.com", "/", true, 1001, &out2));
}

test "domain cookie matches subdomains" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());
    try jar.setFromResponse("a.itvsh.cn", "/", "T=1; Domain=.itvsh.cn; Path=/", 1000);

    var out = Buf.init(arena.allocator());
    try testing.expect(try jar.headerFor("cdn.itvsh.cn", "/x", true, 1001, &out));

    var out2 = Buf.init(arena.allocator());
    try testing.expect(!try jar.headerFor("itvsh.cn.evil.com", "/x", true, 1001, &out2));
}

test "public-suffix domain is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());
    try jar.setFromResponse("pan.itvsh.cn", "/", "T=1; Domain=.com; Path=/", 1000);
    // stored as host-only because the Domain attr was rejected
    var out = Buf.init(arena.allocator());
    try testing.expect(try jar.headerFor("pan.itvsh.cn", "/", true, 1001, &out));
    var out2 = Buf.init(arena.allocator());
    try testing.expect(!try jar.headerFor("other.com", "/", true, 1001, &out2));
}

test "path scoping" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());
    try jar.setFromResponse("h", "/nas/user/login", "S=1", 1000);
    var a = Buf.init(arena.allocator());
    try testing.expect(try jar.headerFor("h", "/nas/user/info", true, 1001, &a));
    var b = Buf.init(arena.allocator());
    try testing.expect(!try jar.headerFor("h", "/nasforward/file/download", true, 1001, &b));
}

test "max-age=0 deletes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());
    try jar.setFromResponse("h", "/", "S=1; Path=/", 1000);
    try testing.expectEqual(@as(usize, 1), jar.count());
    try jar.setFromResponse("h", "/", "S=; Path=/; Max-Age=0", 1001);
    try testing.expectEqual(@as(usize, 0), jar.count());
}

test "go-format roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var jar = Jar.init(a);
    try jar.setFromResponse("pan.itvsh.cn", "/nas/user/login", "SESSION=abc; Path=/; HttpOnly; Secure", 1000);
    try jar.setFromResponse("cdn.itvsh.cn", "/", "WAF=xyz; Domain=.itvsh.cn; Path=/", 1000);
    const blob = try jar.toJson(a);

    // Go writes these keys; verify we produce them verbatim.
    for ([_][]const u8{ "\"Name\"", "\"Value\"", "\"Path\"", "\"Domain\"", "\"RawExpires\"", "\"MaxAge\"", "\"Secure\"", "\"HttpOnly\"", "\"SameSite\"", "\"Unparsed\"" }) |k| {
        try testing.expect(std.mem.indexOf(u8, blob, k) != null);
    }

    var jar2 = Jar.init(a);
    try jar2.fromJson(blob);
    try testing.expectEqual(@as(usize, 2), jar2.count());

    var out = Buf.init(a);
    try testing.expect(try jar2.headerFor("cdn.itvsh.cn", "/", true, 1001, &out));
    try testing.expect(std.mem.indexOf(u8, out.slice(), "WAF=xyz") != null);
}

test "regraft moves cookies onto a new host" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var jar = Jar.init(a);
    try jar.setFromResponse("pan.itvsh.cn", "/", "S=1; Path=/", 1000);

    const grafted = try jar.cookiesFor(a, "pan.itvsh.cn", 1001);
    jar.clear();
    jar.setForHost("nas-12345.itvsh.cn", grafted);

    var out = Buf.init(a);
    try testing.expect(try jar.headerFor("nas-12345.itvsh.cn", "/nasforward/file/download", true, 1002, &out));
    try testing.expectEqualStrings("S=1", out.slice());
}

test "http date format and parse" {
    const a = testing.allocator;
    const s = try httpDate(a, 784111777); // Sun, 06 Nov 1994 08:49:37 GMT
    defer a.free(s);
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", s);
    try testing.expectEqual(@as(i64, 784111777), parseHttpDate(s).?);
    // obsolete RFC 850
    try testing.expectEqual(@as(i64, 784111777), parseHttpDate("Sunday, 06-Nov-94 08:49:37 GMT").?);
    // asctime
    try testing.expectEqual(@as(i64, 784111777), parseHttpDate("Sun Nov  6 08:49:37 1994").?);
}

test "regraft survives the arena the cookies came from (use-after-free)" {
    // Regression for the SIGSEGV that took the ONT service down: itvsh's
    // restoreCookies used to graft arena-allocated cookies into the long-lived
    // jar, the arena died on return, and the next request read recycled heap
    // pages as cookie names — garbage got persisted into config.json and,
    // once the arena was large enough to be mmap'd, headerFor crashed.
    var jar = Jar.init(testing.allocator);
    defer jar.deinit();

    var stale_name: [*]const u8 = undefined;
    var stale_value: [*]const u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    {
        var staging = Jar.init(arena.allocator());
        try staging.setFromResponse("pan.itvsh.cn", "/nas/session", "SESSION=abc; Path=/", 1000);
        const cs = try staging.allCookies(arena.allocator());
        stale_name = cs[0].name.ptr;
        stale_value = cs[0].value.ptr;
        jar.setForHost("n8.pan.itvsh.cn", cs);
    }
    arena.deinit(); // the old code left the jar pointing in here

    // Deterministic: the jar must hold its own copies, not the arena's.
    try testing.expect(jar.cookies.data[0].name.ptr != stale_name);
    try testing.expect(jar.cookies.data[0].value.ptr != stale_value);

    var out = Buf.init(testing.allocator);
    defer out.deinit();
    try testing.expect(try jar.headerFor("n8.pan.itvsh.cn", "/nas/user", true, 1001, &out));
    try testing.expectEqualStrings("SESSION=abc", out.slice());
}

test "setFromResponse refuses things that are not cookies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());

    // A JSON body fragment that leaked into a header position: the name is
    // not a token (contains quotes/commas) — must be ignored, not stored.
    try jar.setFromResponse("pan.itvsh.cn", "/nas/rd_center/data", "ame\":\"x\"}=y", 1000);
    try testing.expectEqual(@as(usize, 0), jar.count());

    // Control characters in the value.
    try jar.setFromResponse("h", "/", "S=va\x01lue; Path=/", 1000);
    try testing.expectEqual(@as(usize, 0), jar.count());

    // Invalid UTF-8 in the value (this is what poisoned the real config:
    // a truncated multi-byte sequence, E7 9B with the third byte missing).
    try jar.setFromResponse("h", "/", "S=\xe7\x9b; Path=/", 1000);
    try testing.expectEqual(@as(usize, 0), jar.count());

    // Absurdly long value.
    var big: [9000]u8 = undefined;
    @memset(&big, 'a');
    try jar.setFromResponse("h", "/", try std.fmt.allocPrint(arena.allocator(), "S={s}; Path=/", .{big}), 1000);
    try testing.expectEqual(@as(usize, 0), jar.count());

    // A well-formed cookie still goes through.
    try jar.setFromResponse("pan.itvsh.cn", "/nas/session", "SESSION=abc; Path=/; HttpOnly", 1000);
    try testing.expectEqual(@as(usize, 1), jar.count());
}

test "fromJson skips garbage entries and keeps good ones" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(arena.allocator());

    // The shape the poisoned config.json actually had: JSON fragments that
    // leaked into cookie fields, one real session cookie among them.
    const blob =
        "[" ++
        "{\"Name\":\"SESSION\",\"Value\":\"abc\",\"Path\":\"/\",\"Domain\":\"pan.itvsh.cn\",\"RawExpires\":\"\",\"MaxAge\":0,\"Secure\":false,\"HttpOnly\":true,\"SameSite\":0,\"Partitioned\":false,\"Raw\":\"\",\"Unparsed\":null}," ++
        "{\"Name\":\"ame\\\":\\\"\x9b\",\"Value\":\"\x9b\xb8\xe5\x86\x8c\",\"Path\":\"/nas/user\",\"Domain\":\"pan.itvsh.cn\",\"RawExpires\":\"\",\"MaxAge\":0,\"Secure\":false,\"HttpOnly\":false,\"SameSite\":0,\"Partitioned\":false,\"Raw\":\"\",\"Unparsed\":null}," ++
        "{\"Name\":\"\\\",\\\"t\",\"Value\":\"y\",\"Path\":\"/\",\"Domain\":\"pan.itvsh.cn\",\"RawExpires\":\"\",\"MaxAge\":0,\"Secure\":false,\"HttpOnly\":false,\"SameSite\":0,\"Partitioned\":false,\"Raw\":\"\",\"Unparsed\":null}" ++
        "]";
    try jar.fromJson(blob);
    try testing.expectEqual(@as(usize, 1), jar.count());

    var out = Buf.init(arena.allocator());
    try testing.expect(try jar.headerFor("pan.itvsh.cn", "/nas/session", true, 4242, &out));
    try testing.expectEqualStrings("SESSION=abc", out.slice());
}

test "store takes a deep copy of borrowed fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var jar = Jar.init(testing.allocator);
    defer jar.deinit();

    // Feed a cookie whose fields point into memory we free immediately.
    {
        var scratch = std.heap.ArenaAllocator.init(testing.allocator);
        const c = Cookie{
            .name = "SESSION",
            .value = try scratch.allocator().dupe(u8, "abc"),
            .path = "/",
            .domain = "pan.itvsh.cn",
        };
        jar.store(c, 1000);
        scratch.deinit();
    }

    var out = Buf.init(testing.allocator);
    defer out.deinit();
    try testing.expect(try jar.headerFor("pan.itvsh.cn", "/nas/user", true, 1001, &out));
    try testing.expectEqualStrings("SESSION=abc", out.slice());
}
