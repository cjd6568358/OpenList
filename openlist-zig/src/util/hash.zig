//! Digest and text-encoding helpers shared by the cloud-storage drivers.
//!
//! Scope is exactly what the ported drivers call, no more:
//!
//!   | driver            | needs                                                  |
//!   |-------------------|--------------------------------------------------------|
//!   | 189               | md5, sha1, hmac-sha1 (lower hex), base64 std            |
//!   | 189pc             | sha1, hmac-sha1 (UPPER hex), base64 std                 |
//!   | 123_open          | md5, base64 std                                         |
//!   | aliyundrive_open  | base64 std                                              |
//!   | quark_open        | md5, sha1, sha256 (lower hex), base64 std               |
//!   | 115_open          | sha1 over the first 128 KiB and over the whole file     |
//!
//! The digest cores come from `std.crypto.hash`; hand-rolling MD5 or SHA-1
//! would be the wrong kind of "no dependency". What lives here is the
//! hex/base64 plumbing so a driver writes `sha1Hex(arena, body)` instead of
//! five lines of encoder boilerplate, plus a streaming wrapper for the two
//! places a file is hashed without being held in memory (115_open's
//! `sha1128k` second-pass check and the whole-file SHA-1 used as a file id).
//!
//! Case matters and is therefore explicit in the API: `189`, `123_open` and
//! `quark_open` compare digests as lowercase strings, while `189pc`'s HMAC
//! signature and `115_open`'s `FileID`/`PreID` are uppercase. A single
//! case-agnostic `hex()` would compile everywhere and fail at runtime on two
//! of the six drivers.
//!
//! The hex codecs live here rather than in `aes.zig` (which re-exports them
//! unchanged for its existing callers) because hashing is the main consumer —
//! AES only needs hex because itvsh/189pc print ciphertext as hex.

const std = @import("std");

pub const Error = error{
    /// Odd number of hex digits, or a digit outside `[0-9a-fA-F]`.
    InvalidHex,
    /// Base64 input whose length cannot decode, or an illegal character.
    InvalidBase64,
};

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

const HEX_LOWER = "0123456789abcdef";
const HEX_UPPER = "0123456789ABCDEF";

/// Encode `data` as lowercase hex (2 chars per byte).
pub fn hexLower(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, data.len * 2);
    for (data, 0..) |c, i| {
        out[i * 2] = HEX_LOWER[c >> 4];
        out[i * 2 + 1] = HEX_LOWER[c & 0x0F];
    }
    return out;
}

/// Encode `data` as uppercase hex (2 chars per byte).
pub fn hexUpper(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, data.len * 2);
    for (data, 0..) |c, i| {
        out[i * 2] = HEX_UPPER[c >> 4];
        out[i * 2 + 1] = HEX_UPPER[c & 0x0F];
    }
    return out;
}

/// Decode hex, accepting either case. Rejects odd length and non-hex digits
/// rather than silently truncating — a truncated digest would be sent to the
/// server as a valid-looking but wrong value, which is much harder to debug
/// than a hard error.
pub fn hexDecode(alloc: std.mem.Allocator, s: []const u8) (error{InvalidHex} || std.mem.Allocator.Error)![]u8 {
    if (s.len % 2 != 0) return error.InvalidHex;
    const out = try alloc.alloc(u8, s.len / 2);
    // A malformed digit mid-string would otherwise strand the allocation.
    errdefer alloc.free(out);
    for (out, 0..) |*b, i| {
        const hi = hexNibble(s[i * 2]) orelse return error.InvalidHex;
        const lo = hexNibble(s[i * 2 + 1]) orelse return error.InvalidHex;
        b.* = hi << 4 | lo;
    }
    return out;
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// Re-exported so drivers write `hash.Md5.init(.{})` instead of reaching into
/// `std.crypto.hash` and pinning themselves to its module layout.
pub const Md5 = std.crypto.hash.Md5;
pub const Sha1 = std.crypto.hash.Sha1;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const MD5_LEN = Md5.digest_length; // 16
pub const SHA1_LEN = Sha1.digest_length; // 20
pub const SHA256_LEN = Sha256.digest_length; // 32

pub fn md5(data: []const u8) [MD5_LEN]u8 {
    var out: [MD5_LEN]u8 = undefined;
    Md5.hash(data, &out, .{});
    return out;
}

pub fn sha1(data: []const u8) [SHA1_LEN]u8 {
    var out: [SHA1_LEN]u8 = undefined;
    Sha1.hash(data, &out, .{});
    return out;
}

pub fn sha256(data: []const u8) [SHA256_LEN]u8 {
    var out: [SHA256_LEN]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

pub fn md5Hex(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    return hexLower(alloc, &md5(data));
}

pub fn sha1Hex(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    return hexLower(alloc, &sha1(data));
}

/// 115_open compares `FileID`/`PreID` against an uppercase server value, so
/// this is not interchangeable with `sha1Hex`.
pub fn sha1HexUpper(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    return hexUpper(alloc, &sha1(data));
}

pub fn sha256Hex(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    return hexLower(alloc, &sha256(data));
}

// ---------------------------------------------------------------------------
// HMAC-SHA1 — the signature primitive of the 189 family
// ---------------------------------------------------------------------------

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub fn hmacSha1(key: []const u8, msg: []const u8) [SHA1_LEN]u8 {
    var out: [SHA1_LEN]u8 = undefined;
    HmacSha1.create(&out, msg, key);
    return out;
}

/// 189 `hmacSha1()` — lowercase hex over a query string.
pub fn hmacSha1Hex(alloc: std.mem.Allocator, key: []const u8, msg: []const u8) ![]u8 {
    return hexLower(alloc, &hmacSha1(key, msg));
}

/// 189pc `signatureOfHmac()` — `strings.ToUpper(hex.EncodeToString(...))`.
pub fn hmacSha1HexUpper(alloc: std.mem.Allocator, key: []const u8, msg: []const u8) ![]u8 {
    return hexUpper(alloc, &hmacSha1(key, msg));
}

// ---------------------------------------------------------------------------
// Base64 — Go's `encoding/base64.StdEncoding` (standard alphabet, padded)
// ---------------------------------------------------------------------------

const std_enc = std.base64.standard.Encoder;
const std_dec = std.base64.standard.Decoder;

/// Length of the base64 encoding of `n` raw bytes, padding included.
pub fn base64StdSize(n: usize) usize {
    return std_enc.calcSize(n);
}

pub fn base64Std(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, std_enc.calcSize(data.len));
    // `Encoder.encode` hands back a const slice of the caller's own buffer.
    return @constCast(std_enc.encode(out, data));
}

pub fn base64StdDecode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    const n = std_dec.calcSizeForSlice(s) catch return error.InvalidBase64;
    const out = try alloc.alloc(u8, n);
    // `decode` can still reject the padding/characters after the size check.
    errdefer alloc.free(out);
    std_dec.decode(out, s) catch return error.InvalidBase64;
    return out;
}

/// 189's `b64tohex()`: re-encode a base64 string as lowercase hex.
///
/// The upstream Go version is a hand-written bit-shuffler with a degenerate
/// branch that fires only when the input is a single base64 character. Every
/// caller feeds it the output of `base64.StdEncoding.EncodeToString`, i.e. a
/// whole number of 4-character groups, for which decode-then-hex is
/// bit-for-bit identical (verified against the Go algorithm on `Zg==` → `66`
/// and `Zm8=` → `666f`). Implementing it this way keeps the code obviously
/// correct instead of transcribing a bit-twiddling loop.
pub fn base64ToHex(alloc: std.mem.Allocator, b64: []const u8) ![]u8 {
    const raw = try base64StdDecode(alloc, b64);
    defer alloc.free(raw);
    return hexLower(alloc, raw);
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// Streaming wrapper so a file can be hashed without being materialised.
///
/// 115_open hashes the whole upload as a file id and separately hashes the
/// first 128 KiB as a "pre-id"; `quark_open` and `123_open` hash whole files
/// for instant-upload (秒传) lookups. Those streams come from a `model.Source`
/// that is read at random offsets, so the driver feeds chunks in rather than
/// handing over one slice.
pub fn Hasher(comptime H: type) type {
    return struct {
        const Self = @This();

        inner: H = H.init(.{}),

        pub const digest_length = H.digest_length;

        pub fn update(self: *Self, data: []const u8) void {
            self.inner.update(data);
        }

        pub fn final(self: *Self) [H.digest_length]u8 {
            var out: [H.digest_length]u8 = undefined;
            self.inner.final(&out);
            return out;
        }

        pub fn finalHexLower(self: *Self, alloc: std.mem.Allocator) ![]u8 {
            return hexLower(alloc, &self.final());
        }

        pub fn finalHexUpper(self: *Self, alloc: std.mem.Allocator) ![]u8 {
            return hexUpper(alloc, &self.final());
        }
    };
}

pub const Md5Stream = Hasher(Md5);
pub const Sha1Stream = Hasher(Sha1);
pub const Sha256Stream = Hasher(Sha256);

// ---------------------------------------------------------------------------
// Tests — published vectors, so a std.crypto API or behaviour change is loud
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Every helper below returns freshly allocated memory, and `testing.allocator`
/// fails the test on a leak. Comparing through this wrapper keeps the tests
/// free of `defer` noise without pretending the allocation is not there.
fn expectHex(expected: []const u8, actual: []u8) !void {
    defer testing.allocator.free(actual);
    try testing.expectEqualStrings(expected, actual);
}

test "md5 vectors" {
    const a = testing.allocator;
    try expectHex("d41d8cd98f00b204e9800998ecf8427e", try md5Hex(a, ""));
    try expectHex("900150983cd24fb0d6963f7d28e17f72", try md5Hex(a, "abc"));
    try expectHex("c3fcd3d76192e4007dfb496cca67e13b", try md5Hex(a, "abcdefghijklmnopqrstuvwxyz"));
}

test "sha1 vectors" {
    const a = testing.allocator;
    try expectHex("da39a3ee5e6b4b0d3255bfef95601890afd80709", try sha1Hex(a, ""));
    try expectHex("a9993e364706816aba3e25717850c26c9cd0d89d", try sha1Hex(a, "abc"));
    // Case is part of the contract, not cosmetic.
    try expectHex("A9993E364706816ABA3E25717850C26C9CD0D89D", try sha1HexUpper(a, "abc"));
}

test "sha256 vector" {
    const a = testing.allocator;
    try expectHex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        try sha256Hex(a, "abc"),
    );
}

test "hmac-sha1 vectors" {
    const a = testing.allocator;
    try expectHex("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d", try hmacSha1Hex(a, "", ""));
    try expectHex(
        "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        try hmacSha1Hex(a, "key", "The quick brown fox jumps over the lazy dog"),
    );
    try expectHex(
        "DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9",
        try hmacSha1HexUpper(a, "key", "The quick brown fox jumps over the lazy dog"),
    );
}

test "base64 std matches Go StdEncoding" {
    const a = testing.allocator;
    // RFC 4648 §10 test vectors — these are the exact strings Go produces.
    const cases = [_][2][]const u8{
        .{ "", "" },
        .{ "f", "Zg==" },
        .{ "fo", "Zm8=" },
        .{ "foo", "Zm9v" },
        .{ "foob", "Zm9vYg==" },
        .{ "fooba", "Zm9vYmE=" },
        .{ "foobar", "Zm9vYmFy" },
    };
    for (cases) |c| {
        const enc = try base64Std(a, c[0]);
        defer a.free(enc);
        try testing.expectEqualStrings(c[1], enc);

        const dec = try base64StdDecode(a, c[1]);
        defer a.free(dec);
        try testing.expectEqualStrings(c[0], dec);
    }
}

test "base64ToHex reproduces 189's b64tohex" {
    const a = testing.allocator;
    // Traced through the upstream Go loop by hand:
    //   "Zg=="     → 'Z' emits '6' with carry 1, 'g' emits '6', padding skipped → "66"
    //   "Zm8="     → "666f"
    //   "Zm9v"     → "666f6f"
    //   "Zm9vYmFy" → "666f6f626172"
    try expectHex("66", try base64ToHex(a, "Zg=="));
    try expectHex("666f", try base64ToHex(a, "Zm8="));
    try expectHex("666f6f", try base64ToHex(a, "Zm9v"));
    try expectHex("666f6f626172", try base64ToHex(a, "Zm9vYmFy"));
}

test "base64ToHex round-trips arbitrary bytes" {
    const a = testing.allocator;
    // 128 bytes is the size of a 1024-bit RSA ciphertext; 256 is 2048-bit.
    var buf: [256]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i * 7 + 13);

    for ([_]usize{ 128, 256 }) |n| {
        const b64 = try base64Std(a, buf[0..n]);
        defer a.free(b64);
        const hex = try base64ToHex(a, b64);
        defer a.free(hex);
        const expected = try hexLower(a, buf[0..n]);
        defer a.free(expected);
        try testing.expectEqualStrings(expected, hex);
        try testing.expectEqual(n * 2, hex.len);
    }
}

test "hex codecs" {
    const a = testing.allocator;
    try expectHex("00ff10", try hexLower(a, &[_]u8{ 0x00, 0xff, 0x10 }));
    try expectHex("00FF10", try hexUpper(a, &[_]u8{ 0x00, 0xff, 0x10 }));

    const raw = try hexDecode(a, "00Ff10");
    defer a.free(raw);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xff, 0x10 }, raw);

    try testing.expectError(error.InvalidHex, hexDecode(a, "abc"));
    try testing.expectError(error.InvalidHex, hexDecode(a, "zz"));
}

test "base64StdDecode rejects malformed input" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidBase64, base64StdDecode(a, "!!!!"));
    try testing.expectError(error.InvalidBase64, base64StdDecode(a, "A"));
}

test "streaming hasher matches one-shot digest" {
    const a = testing.allocator;

    // Chunk boundaries must not change the result — the drivers feed 128 KiB
    // blocks that are not aligned to the hash block size.
    const payload = "The quick brown fox jumps over the lazy dog";

    var md5s = Md5Stream{};
    md5s.update(payload[0..4]);
    md5s.update(payload[4..]);
    try expectHex("9e107d9d372bb6826bd81d3542a419d6", try md5s.finalHexLower(a));

    var sha1s = Sha1Stream{};
    for (payload) |*c| sha1s.update(std.mem.asBytes(c));
    try expectHex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12", try sha1s.finalHexLower(a));

    var sha256s = Sha256Stream{};
    sha256s.update(payload);
    try expectHex(
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        try sha256s.finalHexLower(a),
    );
}

test "streaming hasher supports the 128 KiB prefix pattern" {
    const a = testing.allocator;
    // 115_open's `sha1128k`: SHA-1 over exactly the first 128 KiB.
    const block = 128 * 1024;
    var data: [block + 64]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);

    var s = Sha1Stream{};
    s.update(data[0..block]);
    const prefix = try s.finalHexUpper(a);
    defer a.free(prefix);

    const whole = try sha1HexUpper(a, data[0..block]);
    defer a.free(whole);
    try testing.expectEqualStrings(whole, prefix);
    try testing.expectEqual(40, prefix.len);

    // …and it must differ from hashing one byte more.
    const more = try sha1HexUpper(a, data[0 .. block + 1]);
    defer a.free(more);
    try testing.expect(!std.mem.eql(u8, prefix, more));
}
