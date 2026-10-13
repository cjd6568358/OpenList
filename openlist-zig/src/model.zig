//! Shared data model. Field names and JSON shapes deliberately mirror
//! OpenList's `internal/model` so the existing web frontend keeps working
//! against this binary without a shim.

const std = @import("std");

/// 与 Go `internal/conf/const.go:171-178` 的
/// `UNKNOWN / FOLDER / VIDEO / AUDIO / TEXT / IMAGE` 一一对应。
///
/// A06：以前这里是 `file=1, folder=2`。前端按 `type` 分支选图标和预览器，
/// 编号对不上时目录会被当成视频、文本文件会被当成目录 —— 即使 `is_dir`
/// 是对的，基于 `type` 的分支照样错。
pub const ObjType = enum(i64) {
    unknown = 0,
    folder = 1,
    video = 2,
    audio = 3,
    text = 4,
    image = 5,
};

// 扩展名列表取 Go `internal/bootstrap/data/setting.go:130-133` 的默认值，
// 判定顺序与 `pkg/utils/file.go:142-163` 的 `GetFileType` 一致：
// AUDIO → VIDEO → IMAGE → TEXT。
const audio_exts = "mp3,flac,ogg,m4a,wav,opus,wma";
const video_exts = "mp4,mkv,avi,mov,rmvb,webm,flv,m3u8";
const image_exts = "jpg,tiff,jpeg,png,gif,bmp,svg,ico,swf,webp,avif";
const text_exts = "txt,htm,html,xml,java,properties,sql,js,md,json,conf,ini,vue,php,py,bat,gitignore,yml,go,sh,c,cpp,h,hpp,tsx,vtt,srt,ass,rs,lrc,strm";

/// 等价于 Go 的 `utils.Ext`（`pkg/utils/path.go:46`）：取最后一个点之后的部分，
/// 去掉前导点。`.gitignore` → `gitignore`（Go 的列表里确实有这一项）。
fn extOf(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    if (dot + 1 >= name.len) return "";
    return name[dot + 1 ..];
}

fn extInList(ext: []const u8, list: []const u8) bool {
    if (ext.len == 0) return false;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |item| {
        if (std.ascii.eqlIgnoreCase(item, ext)) return true;
    }
    return false;
}

/// 等价于 Go 的 `utils.GetObjType`（`pkg/utils/file.go:161`）。
pub fn objTypeFor(name: []const u8, is_dir: bool) ObjType {
    if (is_dir) return .folder;
    const ext = extOf(name);
    if (ext.len == 0) return .unknown;
    if (extInList(ext, audio_exts)) return .audio;
    if (extInList(ext, video_exts)) return .video;
    if (extInList(ext, image_exts)) return .image;
    if (extInList(ext, text_exts)) return .text;
    return .unknown;
}

pub const HashInfo = struct {
    hash_name: []const u8,
    hash_value: []const u8,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// A directory entry as returned by `Driver.list`.
pub const Obj = struct {
    name: []const u8,
    size: i64 = 0,
    is_dir: bool = false,
    /// Unix seconds. Drivers that only expose milliseconds must convert.
    modified: i64 = 0,
    created: i64 = 0,
    /// Opaque per-entry token echoed back on link/put calls.
    sign: []const u8 = "",
    thumb: []const u8 = "",
    hash_info: ?HashInfo = null,
    /// Driver-private payload. `itvsh` uses this to carry the server-side
    /// path of an entry, which is NOT always `<parent>/<name>` (the
    /// synthetic "家庭共享" root entry is the motivating case).
    priv: ?*const anyopaque = null,

    pub fn typeEnum(self: Obj) ObjType {
        return objTypeFor(self.name, self.is_dir);
    }
};

/// A single path resolved by `Driver.details` / `Driver.link`.
pub const File = struct {
    name: []const u8,
    size: i64 = 0,
    is_dir: bool = false,
    modified: i64 = 0,
    created: i64 = 0,
    sign: []const u8 = "",
    thumb: []const u8 = "",
    hash_info: ?HashInfo = null,

    pub fn fromObj(o: Obj) File {
        return .{
            .name = o.name,
            .size = o.size,
            .is_dir = o.is_dir,
            .modified = o.modified,
            .created = o.created,
            .sign = o.sign,
            .thumb = o.thumb,
            .hash_info = o.hash_info,
        };
    }
};

pub const Link = struct {
    url: []const u8 = "",
    header: []const Header = &.{},
    /// True when the driver demands server-side streaming instead of a 302.
    /// `itvsh` sets this because the download URL is bound to the session
    /// cookie and the `X-NAS-SDKTOKEN` header, neither of which the browser
    /// will send.
    proxy: bool = false,
    /// Set by drivers whose content already lives on this machine (`local`).
    /// The HTTP layer opens this path and streams it, skipping the upstream
    /// round-trip entirely. Explicit field rather than a `file://` URL so that
    /// there is exactly one code path that touches the filesystem, and it is
    /// obviously one.
    local_path: ?[]const u8 = null,
    /// Size of `local_path`, so the response can carry Content-Length.
    local_size: u64 = 0,
};

pub const LinkArgs = struct {
    /// Method the caller intends to use against the returned URL.
    method: []const u8 = "GET",
    /// Client headers the driver may fold into the upstream request.
    headers: []const Header = &.{},
    /// Caller cannot follow redirects (e.g. it is itself a WebDAV client);
    /// prefer a server-side proxy over a 302.
    redirect: bool = false,
};

/// Persistent storage record. `addition` stays a raw JSON *string* exactly as
/// in OpenList — it is what the frontend round-trips and what migrations touch.
pub const Storage = struct {
    id: i64 = 0,
    mount_path: []const u8 = "/",
    order: i64 = 0,
    driver: []const u8 = "",
    cache_expiration: i64 = 0,
    status: []const u8 = "work",
    addition: []const u8 = "{}",
    remark: []const u8 = "",
    disabled: bool = false,
    /// Runtime-only: set when `init` failed, so the API can report it without
    /// taking the whole process down (OpenList shows these as "disabled").
    /// Named `error_msg` because `error` is a Zig keyword.
    error_msg: []const u8 = "",

    pub fn isWork(self: Storage) bool {
        return !self.disabled and self.error_msg.len == 0;
    }
};

// ---------------------------------------------------------------------------
// Seekable upload source
// ---------------------------------------------------------------------------

/// Random-access byte source handed to `Driver.put`.
///
/// `readAt` (not a forward-only reader) is the required primitive because
/// itvsh — like most Chinese cloud drives — uploads in parallel chunks at
/// explicit offsets. Non-seekable inputs (an HTTP request body) are spooled
/// to a temp file by the API layer before reaching a driver; see
/// `api/spool.zig`.
pub const Source = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        size: *const fn (*anyopaque) i64,
        /// Fills `buf` from `offset`. Returns bytes written; short reads are
        /// only allowed at EOF.
        readAt: *const fn (*anyopaque, offset: u64, buf: []u8) anyerror!usize,
    };

    pub fn size(self: Source) i64 {
        return self.vtable.size(self.ptr);
    }

    pub fn readAt(self: Source, offset: u64, buf: []u8) anyerror!usize {
        return self.vtable.readAt(self.ptr, offset, buf);
    }

    /// Read exactly `len` bytes at `offset` into a fresh allocation.
    ///
    /// ⚠️ 上传路径**不要**用它：每块一次新分配，请求 arena 会随文件大小
    /// 线性增长（1 GB 文件 → arena 峰值 1 GB，直到请求结束才释放）。
    /// 上传请用 `readAllInto` + 调用方持有的块缓冲（T7）。
    pub fn readAll(self: Source, alloc: std.mem.Allocator, offset: u64, len: usize) ![]u8 {
        const buf = try alloc.alloc(u8, len);
        var got: usize = 0;
        while (got < len) {
            const n = try self.readAt(offset + got, buf[got..]);
            if (n == 0) return error.UnexpectedEof;
            got += n;
        }
        return buf;
    }

    /// Read exactly `buf.len` bytes at `offset` into a **caller-provided**
    /// buffer（T7：块级可复用 buffer）。
    ///
    /// 上传驱动自己持有一个块大小的 buffer，逐块读进去 → 算哈希 → 发请求 →
    /// 覆盖复用同一块。内存从 O(文件大小) 降到 O(块大小)，且不受并发块数
    /// 影响之外的因素支配。短读只在 EOF 时报错。
    pub fn readAllInto(self: Source, offset: u64, buf: []u8) !void {
        var got: usize = 0;
        while (got < buf.len) {
            const n = try self.readAt(offset + got, buf[got..]);
            if (n == 0) return error.UnexpectedEof;
            got += n;
        }
    }
};

/// 测试用的内存 Source：`ptr` 指向一个 `[]const u8`。
const MemSource = struct {
    data: []const u8,
    const vtable = Source.VTable{
        .size = struct {
            fn f(p: *anyopaque) i64 {
                const s: *const MemSource = @ptrCast(@alignCast(p));
                return @intCast(s.data.len);
            }
        }.f,
        .readAt = struct {
            fn f(p: *anyopaque, offset: u64, buf: []u8) anyerror!usize {
                const s: *const MemSource = @ptrCast(@alignCast(p));
                if (offset >= s.data.len) return 0;
                const n = @min(buf.len, s.data.len - offset);
                @memcpy(buf[0..n], s.data[offset..][0..n]);
                return n;
            }
        }.f,
    };
};

test "T7: readAllInto reuses the caller's buffer and detects short EOF" {
    var backing = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var ms = MemSource{ .data = &backing };
    const src = Source{ .ptr = &ms, .vtable = &MemSource.vtable };

    // 一块 buffer 反复用 —— 这就是上传路径省内存的关键。
    const buf = try std.testing.allocator.alloc(u8, 4);
    defer std.testing.allocator.free(buf);

    try src.readAllInto(2, buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 3, 4, 5 }, buf);

    try src.readAllInto(0, buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 1, 2, 3 }, buf);

    // 尾巴不足：报 EOF，而不是像 readAll 那样分配一个短 buffer。
    try std.testing.expectError(error.UnexpectedEof, src.readAllInto(7, buf));

    // 零长度是合法的 no-op（上游 sliceSize 对齐的场景）。
    try src.readAllInto(0, buf[0..0]);
}

test "objTypeFor mirrors Go's GetObjType" {
    const t = std.testing;

    // 目录恒为 FOLDER=1（Go internal/conf/const.go:173）
    try t.expectEqual(ObjType.folder, objTypeFor("anything", true));
    try t.expectEqual(@as(i64, 1), @backingInt(objTypeFor("anything", true)));

    // 与 Go 的编号对齐：VIDEO=2、AUDIO=3、TEXT=4、IMAGE=5、UNKNOWN=0
    try t.expectEqual(@as(i64, 2), @backingInt(objTypeFor("movie.mp4", false)));
    try t.expectEqual(@as(i64, 3), @backingInt(objTypeFor("song.mp3", false)));
    try t.expectEqual(@as(i64, 4), @backingInt(objTypeFor("notes.txt", false)));
    try t.expectEqual(@as(i64, 5), @backingInt(objTypeFor("pic.png", false)));
    try t.expectEqual(@as(i64, 0), @backingInt(objTypeFor("blob.bin", false)));
    try t.expectEqual(@as(i64, 0), @backingInt(objTypeFor("noext", false)));

    // 大小写不敏感，等价于 Go 的 `strings.ToLower(Ext(...))`
    try t.expectEqual(ObjType.video, objTypeFor("MOVIE.MP4", false));
    // 前导点文件名：Go 的 Ext(".gitignore") 去点后是 "gitignore"，在 TEXT 列表里
    try t.expectEqual(ObjType.text, objTypeFor(".gitignore", false));
    // 判定顺序 AUDIO → VIDEO → IMAGE → TEXT：.mp3 只可能在 AUDIO
    try t.expectEqual(ObjType.audio, objTypeFor("x.wav", false));
}
