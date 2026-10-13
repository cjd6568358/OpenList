//! AES helpers: ECB / CBC block modes, PKCS#7 padding, hex codecs.
//!
//! Scope is driven by the actual driver requirements:
//!   * itvsh  — AES-ECB/PKCS7, key = server-issued 16-char secret, hex output
//!              is LOWERCASE (189pc's is uppercase; do not share a helper).
//!   * 189pc  — AES-CBC/PKCS7 + uppercase hex.
//!   * aliyundrive_open / quark_open — AES-CBC, no padding, used as a KDF-ish
//!              transform over signatures.
//!
//! The block cipher itself comes from `std.crypto.core.aes` — hand-rolling AES
//! would be the wrong kind of "no dependency". `encryptBlock`/`decryptBlock`
//! below are the ONLY places that touch the std API, so a signature change in
//! a future Zig is a two-line fix rather than a rewrite.

const std = @import("std");
const Buf = @import("buf.zig").Buf;
const hash = @import("hash.zig");

pub const Error = error{
    InvalidKeyLength,
    /// Key length valid for AES but not provided by `std.crypto.core.aes`
    /// (only 128 and 256 are implemented there).
    UnsupportedKeyLength,
    InvalidBlockLength,
    InvalidPadding,
    OutOfMemory,
};

pub const BLOCK = 16;

// ---------------------------------------------------------------------------
// std adapter — keep all std.crypto surface confined here
// ---------------------------------------------------------------------------

fn key16(key: []const u8, comptime n: usize) ![n]u8 {
    if (key.len != n) return error.InvalidKeyLength;
    var k: [n]u8 = undefined;
    @memcpy(&k, key[0..n]);
    return k;
}

fn encryptBlock(key: []const u8, dst: *[BLOCK]u8, src: *const [BLOCK]u8) Error!void {
    switch (key.len) {
        16 => {
            const c = std.crypto.core.aes.Aes128.initEnc(try key16(key, 16));
            c.encrypt(dst, src);
        },
        24 => {
            // Zig's std only ships Aes128 and Aes256 (`std.crypto.core.aes`).
            // AES-192 is unreachable from every driver in scope — itvsh derives
            // a 16-char secret (AES-128) and the 189 family uses a fixed
            // 128-bit key — so rather than carry ~200 lines of key-schedule
            // tables for a case nothing exercises, it is an explicit error.
            return error.UnsupportedKeyLength;
        },
        32 => {
            const c = std.crypto.core.aes.Aes256.initEnc(try key16(key, 32));
            c.encrypt(dst, src);
        },
        else => return error.InvalidKeyLength,
    }
}

fn decryptBlock(key: []const u8, dst: *[BLOCK]u8, src: *const [BLOCK]u8) Error!void {
    switch (key.len) {
        16 => {
            const c = std.crypto.core.aes.Aes128.initDec(try key16(key, 16));
            c.decrypt(dst, src);
        },
        24 => return error.UnsupportedKeyLength, // see encryptBlock
        32 => {
            const c = std.crypto.core.aes.Aes256.initDec(try key16(key, 32));
            c.decrypt(dst, src);
        },
        else => return error.InvalidKeyLength,
    }
}

fn xorBlock(dst: *[BLOCK]u8, src: *const [BLOCK]u8) void {
    for (dst, src) |*d, s| d.* ^= s;
}

// ---------------------------------------------------------------------------
// PKCS#7
// ---------------------------------------------------------------------------

/// Pad to a multiple of `block` (default 16). Always adds 1..block bytes.
pub fn pkcs7Pad(alloc: std.mem.Allocator, data: []const u8, block: usize) ![]u8 {
    const rem = data.len % block;
    const pad = if (rem == 0) block else block - rem;
    const out = try alloc.alloc(u8, data.len + pad);
    @memcpy(out[0..data.len], data);
    @memset(out[data.len..], @intCast(pad));
    return out;
}

/// Strip PKCS#7 padding, validating every pad byte.
pub fn pkcs7Unpad(data: []const u8, block: usize) Error![]const u8 {
    if (data.len == 0 or data.len % block != 0) return error.InvalidPadding;
    const pad = data[data.len - 1];
    if (pad == 0 or pad > block or pad > data.len) return error.InvalidPadding;
    for (data[data.len - pad ..]) |c| {
        if (c != pad) return error.InvalidPadding;
    }
    return data[0 .. data.len - pad];
}

// ---------------------------------------------------------------------------
// ECB
// ---------------------------------------------------------------------------

pub fn ecbEncrypt(alloc: std.mem.Allocator, key: []const u8, plain: []const u8) Error![]u8 {
    if (plain.len % BLOCK != 0) return error.InvalidBlockLength;
    const out = try alloc.alloc(u8, plain.len);
    var i: usize = 0;
    while (i < plain.len) : (i += BLOCK) {
        try encryptBlock(key, out[i..][0..BLOCK], plain[i..][0..BLOCK]);
    }
    return out;
}

pub fn ecbDecrypt(alloc: std.mem.Allocator, key: []const u8, cipher: []const u8) Error![]u8 {
    if (cipher.len % BLOCK != 0) return error.InvalidBlockLength;
    const out = try alloc.alloc(u8, cipher.len);
    var i: usize = 0;
    while (i < cipher.len) : (i += BLOCK) {
        try decryptBlock(key, out[i..][0..BLOCK], cipher[i..][0..BLOCK]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// CBC
// ---------------------------------------------------------------------------

pub fn cbcEncrypt(alloc: std.mem.Allocator, key: []const u8, iv: []const u8, plain: []const u8) Error![]u8 {
    if (plain.len % BLOCK != 0) return error.InvalidBlockLength;
    if (iv.len != BLOCK) return error.InvalidBlockLength;
    const out = try alloc.alloc(u8, plain.len);
    var prev: [BLOCK]u8 = undefined;
    @memcpy(&prev, iv[0..BLOCK]);
    var i: usize = 0;
    while (i < plain.len) : (i += BLOCK) {
        var blk: [BLOCK]u8 = undefined;
        @memcpy(&blk, plain[i..][0..BLOCK]);
        xorBlock(&blk, &prev);
        try encryptBlock(key, out[i..][0..BLOCK], &blk);
        @memcpy(&prev, out[i..][0..BLOCK]);
    }
    return out;
}

pub fn cbcDecrypt(alloc: std.mem.Allocator, key: []const u8, iv: []const u8, cipher: []const u8) Error![]u8 {
    if (cipher.len % BLOCK != 0) return error.InvalidBlockLength;
    if (iv.len != BLOCK) return error.InvalidBlockLength;
    const out = try alloc.alloc(u8, cipher.len);
    var prev: [BLOCK]u8 = undefined;
    @memcpy(&prev, iv[0..BLOCK]);
    var i: usize = 0;
    while (i < cipher.len) : (i += BLOCK) {
        var blk: [BLOCK]u8 = undefined;
        try decryptBlock(key, &blk, cipher[i..][0..BLOCK]);
        xorBlock(&blk, &prev);
        @memcpy(out[i..][0..BLOCK], &blk);
        @memcpy(&prev, cipher[i..][0..BLOCK]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Convenience wrappers matching the Go drivers
// ---------------------------------------------------------------------------

/// itvsh `aesEncodeHex`: AES-ECB + PKCS7, lowercase hex, no separator.
pub fn ecbEncryptHexLower(alloc: std.mem.Allocator, key: []const u8, plaintext: []const u8) ![]u8 {
    const padded = try pkcs7Pad(alloc, plaintext, BLOCK);
    const ct = try ecbEncrypt(alloc, key, padded);
    return hexLower(alloc, ct);
}

pub fn ecbDecryptHexLower(alloc: std.mem.Allocator, key: []const u8, hex: []const u8) ![]u8 {
    const raw = try hexDecode(alloc, hex);
    const pt = try ecbDecrypt(alloc, key, raw);
    return @constCast(try pkcs7Unpad(pt, BLOCK));
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------
//
// The codecs themselves live in `hash.zig`, which is where every other caller
// looks for them. They are re-exported here because AES is why the original
// versions existed (itvsh/189pc print ciphertext as hex) and callers should
// not have to know that. `hexDecode` keeps returning `InvalidBlockLength` —
// the error `ecbDecryptHexLower` has always surfaced — so moving the
// implementation is invisible to callers.

pub const hexLower = hash.hexLower;
pub const hexUpper = hash.hexUpper;

pub fn hexDecode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    return hash.hexDecode(alloc, s) catch |e| switch (e) {
        error.InvalidHex => error.InvalidBlockLength,
        error.OutOfMemory => error.OutOfMemory,
    };
}

// ---------------------------------------------------------------------------
// Tests — FIPS-197 / NIST vectors, so a std.crypto API change is caught loudly
// ---------------------------------------------------------------------------

const testing = std.testing;

test "FIPS-197 C.1 AES-128 ECB single block" {
    const key = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const pt = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const want = [_]u8{ 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    var got: [BLOCK]u8 = undefined;
    try encryptBlock(&key, &got, &pt);
    try testing.expectEqualSlices(u8, &want, &got);
    var back: [BLOCK]u8 = undefined;
    try decryptBlock(&key, &back, &want);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "NIST SP800-38A AES-128 ECB multi-block" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const pt = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const want = [_]u8{
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
    };
    const got = try ecbEncrypt(a, &key, &pt);
    try testing.expectEqualSlices(u8, &want, got);
    const back = try ecbDecrypt(a, &key, got);
    try testing.expectEqualSlices(u8, &pt, back);
}

test "NIST SP800-38A AES-128 CBC" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const pt = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    };
    const want = [_]u8{
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    };
    const got = try cbcEncrypt(a, &key, &iv, &pt);
    try testing.expectEqualSlices(u8, &want, got);
    const back = try cbcDecrypt(a, &key, &iv, got);
    try testing.expectEqualSlices(u8, &pt, back);
}

test "pkcs7 pad/unpad" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try pkcs7Pad(a, "abc", BLOCK);
    try testing.expectEqual(@as(usize, 16), p.len);
    try testing.expectEqual(@as(u8, 13), p[15]);
    const u = try pkcs7Unpad(p, BLOCK);
    try testing.expectEqualStrings("abc", u);

    // exact multiple adds a whole extra block
    const p2 = try pkcs7Pad(a, "0123456789abcdef", BLOCK);
    try testing.expectEqual(@as(usize, 32), p2.len);
    try testing.expectEqual(@as(u8, 16), p2[31]);
    // corrupt padding must be rejected
    var bad = try a.dupe(u8, p2);
    bad[31] = 3;
    try testing.expectError(error.InvalidPadding, pkcs7Unpad(bad, BLOCK));
}

test "hex codecs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const lo = try hexLower(a, "\x00\xAB\xff");
    try testing.expectEqualStrings("00abff", lo);
    const up = try hexUpper(a, "\x00\xAB\xff");
    try testing.expectEqualStrings("00ABFF", up);
    try testing.expectEqualStrings("\x00\xAB\xff", try hexDecode(a, "00aBfF"));
}

test "itvsh style password encryption roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key = "0123456789abcdef";
    const enc = try ecbEncryptHexLower(a, key, "hunter2!");
    try testing.expectEqual(@as(usize, 32), enc.len); // 8 bytes -> 16 with pad -> 32 hex
    const dec = try ecbDecryptHexLower(a, key, enc);
    try testing.expectEqualStrings("hunter2!", dec);
}
