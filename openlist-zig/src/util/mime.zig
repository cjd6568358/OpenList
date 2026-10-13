//! 扩展名 → MIME 类型。
//!
//! 为什么需要一个模块而不是各驱动自己写一份：Go 侧统一走
//! `pkg/utils/file.go:170 GetMimeType`，它 = `extraMimeTypes`（只有 `.apk` 一条）
//! → `mime.TypeByExtension` → 兜底 `application/octet-stream`。
//!
//! ⚠️ **Go 的 `mime.TypeByExtension` 是平台相关的**：Linux 上它会把
//! `/etc/mime.types` 读进来（几百条），Windows 上则读注册表。同一份 Go 代码在
//! 编译机（Debian）和光猫（BusyBox 根文件系统，通常没有 `/etc/mime.types`）上
//! 会给出**不同**的 MIME。所以"逐字复刻 Go"在这里做不到，也不该做。
//!
//! 本模块取一个固定表：覆盖 Go 内置表 + `/etc/mime.types` 里最常用的那些，
//! 保证**同一份输入在任何平台上都给同一个结果**。对夸克来说 MIME 只用于
//! 上传分类（`format_type`）和分片 `Content-Type`，推错不影响上传能否成功。

const std = @import("std");

/// Go 的 `extraMimeTypes`（`pkg/utils/file.go:166-168`）。
const extra = [_][2][]const u8{
    .{ "apk", "application/vnd.android.package-archive" },
};

/// Go `mime.TypeByExtension` 的内置表（`mime/type.go` 的 `builtinTypesLower`）
/// 加上 `/etc/mime.types` 里云端最常遇到的那些。文本类带 `; charset=utf-8`，
/// 与 Go 对 `text/*` 的处理一致。
const table = [_][2][]const u8{
    // ---- Go builtinTypesLower ----
    .{ "avif", "image/avif" },
    .{ "css", "text/css; charset=utf-8" },
    .{ "gif", "image/gif" },
    .{ "htm", "text/html; charset=utf-8" },
    .{ "html", "text/html; charset=utf-8" },
    .{ "jpeg", "image/jpeg" },
    .{ "jpg", "image/jpeg" },
    .{ "js", "text/javascript; charset=utf-8" },
    .{ "json", "application/json" },
    .{ "mjs", "text/javascript; charset=utf-8" },
    .{ "pdf", "application/pdf" },
    .{ "png", "image/png" },
    .{ "svg", "image/svg+xml" },
    .{ "wasm", "application/wasm" },
    .{ "webp", "image/webp" },
    .{ "xml", "text/xml; charset=utf-8" },
    // ---- /etc/mime.types 常用项 ----
    .{ "txt", "text/plain; charset=utf-8" },
    .{ "md", "text/markdown; charset=utf-8" },
    .{ "csv", "text/csv; charset=utf-8" },
    .{ "bmp", "image/bmp" },
    .{ "tif", "image/tiff" },
    .{ "tiff", "image/tiff" },
    .{ "ico", "image/x-icon" },
    .{ "heic", "image/heic" },
    .{ "mp4", "video/mp4" },
    .{ "m4v", "video/x-m4v" },
    .{ "mkv", "video/x-matroska" },
    .{ "webm", "video/webm" },
    .{ "avi", "video/x-msvideo" },
    .{ "mov", "video/quicktime" },
    .{ "wmv", "video/x-ms-wmv" },
    .{ "flv", "video/x-flv" },
    .{ "mpg", "video/mpeg" },
    .{ "mpeg", "video/mpeg" },
    .{ "ts", "video/mp2t" },
    .{ "3gp", "video/3gpp" },
    .{ "mp3", "audio/mpeg" },
    .{ "m4a", "audio/mp4" },
    .{ "aac", "audio/aac" },
    .{ "flac", "audio/flac" },
    .{ "wav", "audio/x-wav" },
    .{ "ogg", "audio/ogg" },
    .{ "oga", "audio/ogg" },
    .{ "opus", "audio/opus" },
    .{ "wma", "audio/x-ms-wma" },
    .{ "ape", "audio/x-ape" },
    .{ "zip", "application/zip" },
    .{ "rar", "application/vnd.rar" },
    .{ "7z", "application/x-7z-compressed" },
    .{ "tar", "application/x-tar" },
    .{ "gz", "application/gzip" },
    .{ "bz2", "application/x-bzip2" },
    .{ "xz", "application/x-xz" },
    .{ "iso", "application/x-iso9660-image" },
    .{ "doc", "application/msword" },
    .{ "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    .{ "xls", "application/vnd.ms-excel" },
    .{ "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    .{ "ppt", "application/vnd.ms-powerpoint" },
    .{ "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    .{ "epub", "application/epub+zip" },
    .{ "rtf", "application/rtf" },
};

/// Go 的兜底值。
pub const fallback = "application/octet-stream";

/// 取最后一个 `.` 之后的扩展名（不含点）。与 Go 的 `path.Ext` + 去点等价。
fn extOf(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return "";
    if (dot + 1 >= name.len) return "";
    return name[dot + 1 ..];
}

/// `pkg/utils/file.go:170 GetMimeType` 的固定表版本。大小写不敏感。
pub fn mimeFor(name: []const u8) []const u8 {
    const ext = extOf(name);
    if (ext.len == 0) return fallback;
    inline for (extra) |e| {
        if (std.ascii.eqlIgnoreCase(ext, e[0])) return e[1];
    }
    inline for (table) |e| {
        if (std.ascii.eqlIgnoreCase(ext, e[0])) return e[1];
    }
    return fallback;
}

const testing = std.testing;

test "mimeFor mirrors Go's GetMimeType for the common cases" {
    // Go builtinTypesLower 里的值必须逐字一致。
    try testing.expectEqualStrings("image/png", mimeFor("a.png"));
    try testing.expectEqualStrings("application/pdf", mimeFor("a.pdf"));
    try testing.expectEqualStrings("text/html; charset=utf-8", mimeFor("index.html"));
    try testing.expectEqualStrings("text/javascript; charset=utf-8", mimeFor("app.js"));
    try testing.expectEqualStrings("application/json", mimeFor("data.json"));
    try testing.expectEqualStrings("image/svg+xml", mimeFor("icon.svg"));
    // extraMimeTypes 的特例。
    try testing.expectEqualStrings("application/vnd.android.package-archive", mimeFor("app.apk"));
    // 常见媒体（Go 在有 /etc/mime.types 的机器上也是这些）。
    try testing.expectEqualStrings("video/mp4", mimeFor("movie.mp4"));
    try testing.expectEqualStrings("audio/mpeg", mimeFor("song.mp3"));
    try testing.expectEqualStrings("application/zip", mimeFor("x.zip"));
}

test "mimeFor is case-insensitive and falls back for unknown/absent extensions" {
    try testing.expectEqualStrings("video/mp4", mimeFor("MOVIE.MP4"));
    try testing.expectEqualStrings("image/jpeg", mimeFor("Photo.JPEG"));
    try testing.expectEqualStrings(fallback, mimeFor("noext"));
    try testing.expectEqualStrings(fallback, mimeFor("weird.zzz"));
    try testing.expectEqualStrings(fallback, mimeFor("trailingdot."));
}
