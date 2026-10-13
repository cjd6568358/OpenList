//! ec115 —— 115 网盘**上传**链路的会话口令（`115driver/pkg/crypto/ec115`）。
//!
//! 三件事，都在这里：
//!   1. **P-224 ECDH**：客户端临时生成一对密钥，与 115 服务器固定公钥算出
//!      28 字节共享密钥；前 16 字节当 AES-128 密钥、后 16 字节（`[12..28]`）
//!      当 IV。客户端公钥再编码成 30 字节 `[0x1d, 0x02|0x03, X(28)]` 发给
//!      服务端（注意**不是**标准 SEC1 的 29 字节）。
//!   2. **EncodeToken**：把上面的公钥 + 时间戳 + 两个随机字节混成 48 字节
//!      base64（`k_ec` query 参数），带 CRC32 校验。
//!   3. **Encrypt / Decrypt**：`Encrypt` 就是 PKCS#7 + AES-128-CBC；`Decrypt`
//!      是 AES-128-CBC 解出后再 LZ4 block 解压（服务端回包被压缩过）。
//!
//! ## 为什么自己写 P-224
//!
//! Zig 0.17 std 只有 P256 / P384 / secp256k1（`std.crypto.pcurves`），**没有
//! P-224**。曲线运算因此建在 `std.crypto.ff.Modulus(224)` 之上：域元素用
//! 仿射坐标 + 费马小定理求逆，标量乘用最朴素的 double-and-add。这是一次
//! 上传才跑一次的路径，慢一点无所谓，正确性优先。
//!
//! ## 测试向量
//!
//! 全部由 `tools/gen_115_vectors.py` 用 Python `cryptography` 独立算出的，
//! 见本文件末尾。私钥标量在测试里固定，所以公钥/共享密钥/口令都是确定的。

const std = @import("std");
const hash = @import("hash.zig");
const aes = @import("aes.zig");
const Buf = @import("buf.zig").Buf;

pub const Error = error{
    /// `Decrypt` 拿到的密文长度不足或长度前缀越界。
    InvalidCiphertext,
    /// LZ4 block 结构损坏。
    InvalidLz4,
    OutOfMemory,
};

/// P-224 基域元素字节数（28）。
const base_len = 28;

/// 115 服务器固定公钥：X(28) || Y(28)，`ec115/cipher.go:20-28`。
const remote_pub = [56]u8{
    0x57, 0xA2, 0x92, 0x57, 0xCD, 0x23, 0x20, 0xE5,
    0xD6, 0xD1, 0x43, 0x32, 0x2F, 0xA4, 0xBB, 0x8A,
    0x3C, 0xF9, 0xD3, 0xCC, 0x62, 0x3E, 0xF5, 0xED,
    0xAC, 0x62, 0xB7, 0x67, 0x8A, 0x89, 0xC9, 0x1A,
    0x83, 0xBA, 0x80, 0x0D, 0x61, 0x29, 0xF5, 0x22,
    0xD0, 0x34, 0xC8, 0x95, 0xDD, 0x24, 0x65, 0x24,
    0x3A, 0xDD, 0xC2, 0x50, 0x95, 0x3B, 0xEE, 0xBA,
};

/// `ec115/cipher.go:crcSalt`。
const crc_salt = "^j>WD3Kr?J2gLFjD4W2y@";

// ---------------------------------------------------------------------------
// P-224（secp224r1）参数，SEC 2 / FIPS 186-4
// ---------------------------------------------------------------------------

const P_HEX = "ffffffffffffffffffffffffffffffff000000000000000000000001";
const N_HEX = "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d";
const GX_HEX = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
const GY_HEX = "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";

fn hexBytes(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch @compileError("bad hex constant");
    return out;
}

const P_BYTES = hexBytes(28, P_HEX);
const N_BYTES = hexBytes(28, N_HEX);
const GX_BYTES = hexBytes(28, GX_HEX);
const GY_BYTES = hexBytes(28, GY_HEX);

const Mod = std.crypto.ff.Modulus(224);
const Fe = Mod.Fe;

fn modulus() Mod {
    return Mod.fromBytes(&P_BYTES, .big) catch unreachable;
}

fn fe(b: []const u8) Fe {
    return Fe.fromBytes(modulus(), b, .big) catch unreachable;
}

fn feFromInt(comptime v: u8) Fe {
    return Fe.fromPrimitive(u8, modulus(), v) catch unreachable;
}

/// 模逆：费马小定理 `x^(p-2)`。
fn inv(m: Mod, x: Fe) Fe {
    const one = m.one();
    const minus_one = m.sub(m.zero, one); // p-1
    const p_minus_2 = m.sub(minus_one, one); // p-2
    return m.pow(x, p_minus_2) catch unreachable;
}

const Point = struct {
    x: Fe,
    y: Fe,
    infinity: bool = false,
};

fn pointDouble(m: Mod, p: Point) Point {
    if (p.infinity or p.y.isZero()) return .{ .x = m.zero, .y = m.zero, .infinity = true };
    // a = -3 → λ = (3x² - 3) / (2y)
    const x2 = m.sq(p.x);
    const three_x2 = m.add(m.add(x2, x2), x2);
    const a = m.sub(m.zero, feFromInt(3));
    const num = m.add(three_x2, a);
    const den = m.add(p.y, p.y);
    const lam = m.mul(num, inv(m, den));
    const x3 = m.sub(m.sq(lam), m.add(p.x, p.x));
    const y3 = m.sub(m.mul(lam, m.sub(p.x, x3)), p.y);
    return .{ .x = x3, .y = y3 };
}

fn pointAdd(m: Mod, p: Point, q: Point) Point {
    if (p.infinity) return q;
    if (q.infinity) return p;
    if (p.x.eql(q.x)) {
        if (p.y.eql(q.y)) return pointDouble(m, p);
        return .{ .x = m.zero, .y = m.zero, .infinity = true }; // P + (-P) = O
    }
    const lam = m.mul(m.sub(q.y, p.y), inv(m, m.sub(q.x, p.x)));
    const x3 = m.sub(m.sub(m.sq(lam), p.x), q.x);
    const y3 = m.sub(m.mul(lam, m.sub(p.x, x3)), p.y);
    return .{ .x = x3, .y = y3 };
}

/// 标量乘（double-and-add，MSB 优先）。`k` 是大端标量字节。
fn scalarMul(m: Mod, p: Point, k: []const u8) Point {
    var r = Point{ .x = m.zero, .y = m.zero, .infinity = true };
    for (k) |byte| {
        var bit: u4 = 8;
        while (bit > 0) {
            bit -= 1;
            r = pointDouble(m, r);
            if ((byte >> @intCast(bit)) & 1 == 1) r = pointAdd(m, r, p);
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// Cipher
// ---------------------------------------------------------------------------

pub const Cipher = struct {
    key: [16]u8,
    iv: [16]u8,
    /// `[0x1d, 0x02|0x03, X(28)]` —— 115 的**非标准**公钥编码（30 字节）。
    pub_key: [30]u8,
};

/// 用给定的大端私钥标量派生一个 Cipher（与服务器的 ECDH）。
pub fn deriveCipher(d: []const u8) Cipher {
    const m = modulus();
    const g = Point{ .x = fe(&GX_BYTES), .y = fe(&GY_BYTES) };
    const q = scalarMul(m, g, d);

    const r = Point{ .x = fe(remote_pub[0..28]), .y = fe(remote_pub[28..56]) };
    const s = scalarMul(m, r, d);

    var secret: [28]u8 = undefined;
    s.x.toBytes(&secret, .big) catch unreachable;

    var c: Cipher = undefined;
    @memcpy(&c.key, secret[0..16]);
    @memcpy(&c.iv, secret[12..28]);
    c.pub_key[0] = 0x1d; // base_len + 1
    c.pub_key[1] = if (q.y.isOdd()) 0x03 else 0x02;
    q.x.toBytes(c.pub_key[2..30], .big) catch unreachable;
    return c;
}

fn validScalar(d: *const [28]u8) bool {
    var acc: u8 = 0;
    for (d) |b| acc |= b;
    if (acc == 0) return false;
    return std.mem.order(u8, d, &N_BYTES) == .lt;
}

/// `ec115.NewEcdhCipher`：随机私钥 + ECDH。
pub fn newCipher(random: std.Random) Cipher {
    while (true) {
        var d: [28]u8 = undefined;
        random.bytes(&d);
        if (validScalar(&d)) return deriveCipher(&d);
    }
}

// ---------------------------------------------------------------------------
// EncodeToken
// ---------------------------------------------------------------------------

/// `ec115.EncodeToken`，`r1`/`r2` 显式传入以便测试复现。
pub fn encodeToken(c: Cipher, timestamp: u32, r1: u8, r2: u8) [64]u8 {
    var tmp: [48]u8 = undefined;
    var i: usize = 0;
    const t = [4]u8{
        @truncate(timestamp >> 24),
        @truncate(timestamp >> 16),
        @truncate(timestamp >> 8),
        @truncate(timestamp),
    };
    for (0..15) |j| {
        tmp[i] = c.pub_key[j] ^ r1;
        i += 1;
    }
    tmp[i] = r1;
    i += 1;
    tmp[i] = 0x73 ^ r1;
    i += 1;
    for (0..3) |_| {
        tmp[i] = r1;
        i += 1;
    }
    for (0..4) |j| {
        tmp[i] = r1 ^ t[3 - j];
        i += 1;
    }
    for (15..30) |j| {
        tmp[i] = c.pub_key[j] ^ r2;
        i += 1;
    }
    tmp[i] = r2;
    i += 1;
    tmp[i] = 0x01 ^ r2;
    i += 1;
    for (0..3) |_| {
        tmp[i] = r2;
        i += 1;
    }
    std.debug.assert(i == 44);

    var crc_in: [crc_salt.len + 44]u8 = undefined;
    @memcpy(crc_in[0..crc_salt.len], crc_salt);
    @memcpy(crc_in[crc_salt.len..], tmp[0..44]);
    const crc = std.hash.Crc32.hash(&crc_in);
    const crc_be = [4]u8{
        @truncate(crc >> 24),
        @truncate(crc >> 16),
        @truncate(crc >> 8),
        @truncate(crc),
    };
    for (0..4) |j| tmp[44 + j] = crc_be[3 - j]; // 小端追加

    var out: [64]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &tmp);
    return out;
}

/// 随机 `r1`/`r2` 的 `EncodeToken`（线上用这个）。
pub fn encodeTokenRandom(c: Cipher, timestamp: u32, random: std.Random) [64]u8 {
    var rs: [2]u8 = undefined;
    random.bytes(&rs);
    return encodeToken(c, timestamp, rs[0], rs[1]);
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

/// `ec115.Encrypt`：PKCS#7 + AES-128-CBC（见文件头：Go 的 ECB 逐块异或链
/// 等价于标准 CBC）。
pub fn encrypt(alloc: std.mem.Allocator, c: Cipher, plain: []const u8) ![]u8 {
    const padded = try aes.pkcs7Pad(alloc, plain, aes.BLOCK);
    defer alloc.free(padded);
    return aes.cbcEncrypt(alloc, &c.key, &c.iv, padded);
}

/// `ec115.Decrypt`：AES-128-CBC 解密 → `[u16 LE 长度][LZ4 block]` → 解压。
pub fn decrypt(alloc: std.mem.Allocator, c: Cipher, cipher_text: []const u8) ![]u8 {
    const n = cipher_text.len - (cipher_text.len % aes.BLOCK);
    if (n == 0) return Error.InvalidCiphertext;
    const pt = try aes.cbcDecrypt(alloc, &c.key, &c.iv, cipher_text[0..n]);
    defer alloc.free(pt);
    if (pt.len < 2) return Error.InvalidCiphertext;
    const length = @as(usize, pt[0]) | (@as(usize, pt[1]) << 8);
    if (2 + length > pt.len) return Error.InvalidCiphertext;
    return lz4DecompressBlock(alloc, pt[2 .. 2 + length]);
}

/// LZ4 block 格式解压（无 frame 头）。
///
/// 只实现解压：客户端发请求时 `Encrypt` 不压缩，只有服务端回包是压缩的。
/// 语法：`token(高4位=字面量长度, 低4位=匹配长度-4)` → 字面量 → 2 字节小端
/// offset → 匹配（从已解出的输出里回抄，允许重叠）。最后一个块只有字面量。
pub fn lz4DecompressBlock(alloc: std.mem.Allocator, src: []const u8) ![]u8 {
    var out = Buf.init(alloc);
    defer out.deinit(); // toOwned() copies; the scratch buffer always goes
    var i: usize = 0;
    while (i < src.len) {
        const token = src[i];
        i += 1;
        var lit_len: usize = token >> 4;
        if (lit_len == 15) {
            while (true) {
                if (i >= src.len) return Error.InvalidLz4;
                const b = src[i];
                i += 1;
                lit_len += b;
                if (b != 255) break;
            }
        }
        if (i + lit_len > src.len) return Error.InvalidLz4;
        try out.append(src[i .. i + lit_len]);
        i += lit_len;
        if (i >= src.len) break; // 收尾字面量，后面没有匹配

        if (i + 2 > src.len) return Error.InvalidLz4;
        const offset = @as(usize, src[i]) | (@as(usize, src[i + 1]) << 8);
        i += 2;
        if (offset == 0 or offset > out.len) return Error.InvalidLz4;

        var match_len: usize = token & 0x0f;
        if (match_len == 15) {
            while (true) {
                if (i >= src.len) return Error.InvalidLz4;
                const b = src[i];
                i += 1;
                match_len += b;
                if (b != 255) break;
            }
        }
        match_len += 4; // MINMATCH
        const start = out.len - offset;
        var j: usize = 0;
        while (j < match_len) : (j += 1) {
            try out.appendByte(out.slice()[start + j]);
        }
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// 测试 —— 向量来自 tools/gen_115_vectors.py（Python `cryptography` 独立实现）
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 固定的 192-bit 私钥标量（< n，可被 Python `cryptography` 接受）。
const TEST_D_HEX = "1234567890abcdef1234567890abcdef1234567890abcdef";
const TEST_PUBKEY_HEX = "1d03b6bac4e0d8328017be5fa88c2c9d97a98a792fcf2a24cce8d8cedfdd";
const TEST_KEY_HEX = "0e5d0658fc04c22a2c84b40b1ff9bc98";
const TEST_IV_HEX = "1ff9bc982194cc0c3391b9e9b0b62425";

test "ec115 P-224 ECDH reproduces the reference pubkey and shared secret" {
    const a = testing.allocator;
    const d = try hash.hexDecode(a, TEST_D_HEX);
    defer a.free(d);

    const c = deriveCipher(d);
    const pk = try hash.hexLower(a, &c.pub_key);
    defer a.free(pk);
    try testing.expectEqualStrings(TEST_PUBKEY_HEX, pk);

    const key = try hash.hexLower(a, &c.key);
    defer a.free(key);
    try testing.expectEqualStrings(TEST_KEY_HEX, key);

    const iv = try hash.hexLower(a, &c.iv);
    defer a.free(iv);
    try testing.expectEqualStrings(TEST_IV_HEX, iv);
}

test "ec115 EncodeToken matches the reference for pinned r1/r2" {
    const a = testing.allocator;
    const d = try hash.hexDecode(a, TEST_D_HEX);
    defer a.free(d);
    const c = deriveCipher(d);

    try testing.expectEqualStrings(
        "t6kcEG5KcpgqvRT1AiaGqtmqqqp4qDzjJiwSMcKUdJGfd1NjdWRmu7q7u7sP09nw",
        &encodeToken(c, 1234567890, 0xAA, 0xBB),
    );
    try testing.expectEqualStrings(
        "DBKnq9XxySORBq9OuZ09EWIRERHDE4dYv7WLqFsN7QgG7sr67P3/IiMiIiIM/nzv",
        &encodeToken(c, 1234567890, 0x11, 0x22),
    );
    try testing.expectEqualStrings(
        "HQO2usTg2DKAF75fqIwsAHMAAADSApZJYmhWdYbQMNXbMxcnMSAi//7////IZxvg",
        &encodeToken(c, 1234567890, 0x00, 0xFF),
    );
}

test "ec115 Encrypt is AES-128-CBC and matches the reference ciphertext" {
    const a = testing.allocator;
    const d = try hash.hexDecode(a, TEST_D_HEX);
    defer a.free(d);
    const c = deriveCipher(d);

    const ct = try encrypt(a, c, "hello ec115");
    defer a.free(ct);
    const got = try hash.hexLower(a, ct);
    defer a.free(got);
    try testing.expectEqualStrings("ea0075ec8dff025c961c0829341d3ce8", got);

    // 空明文 → 一整个填充块
    const ct_empty = try encrypt(a, c, "");
    defer a.free(ct_empty);
    const got_empty = try hash.hexLower(a, ct_empty);
    defer a.free(got_empty);
    try testing.expectEqualStrings("27a0a0a72aa8b79fb974684d73b87bb5", got_empty);
}

test "ec115 lz4DecompressBlock handles literals and an overlapping match" {
    const a = testing.allocator;
    const target = [_]u8{ 'h', 'e', 'l', 'l', 'o', ' ', 'e', 'c', '1', '1', '5' };

    // 纯字面量块：token=0xB0（11 个字节）+ "hello ec115"
    const lit = [_]u8{0xB0} ++ target;
    const out = try lz4DecompressBlock(a, &lit);
    defer a.free(out);
    try testing.expectEqualStrings("hello ec115", out);

    // token=0x22：字面量 2 字节 "ab"，匹配长度 2+4=6，offset=2 → 回抄出 "ababab"，
    // 合起来 "abababab"（覆盖 offset < match_len 的重叠拷贝）。
    const rep = [_]u8{ 0x22, 'a', 'b', 0x02, 0x00 };
    const out2 = try lz4DecompressBlock(a, &rep);
    defer a.free(out2);
    try testing.expectEqualStrings("abababab", out2);
}

test "ec115 Decrypt inverts a hand-built LZ4 payload" {
    const a = testing.allocator;
    const d = try hash.hexDecode(a, TEST_D_HEX);
    defer a.free(d);
    const c = deriveCipher(d);

    // 明文 = [len LE][lz4 block("hello ec115")]
    const target = [_]u8{ 'h', 'e', 'l', 'l', 'o', ' ', 'e', 'c', '1', '1', '5' };
    const lz4 = [_]u8{0xB0} ++ target;
    const payload = [_]u8{ @intCast(lz4.len), 0 } ++ lz4;

    const ct = try encrypt(a, c, &payload);
    defer a.free(ct);

    const got = try decrypt(a, c, ct);
    defer a.free(got);
    try testing.expectEqualStrings("hello ec115", got);
}

test "ec115 Decrypt rejects a payload whose length prefix overruns" {
    const a = testing.allocator;
    const d = try hash.hexDecode(a, TEST_D_HEX);
    defer a.free(d);
    const c = deriveCipher(d);

    // 长度前缀 0xFFFF=65535，远超实际明文 → InvalidCiphertext
    const payload = [_]u8{ 0xFF, 0xFF };
    const ct = try encrypt(a, c, &payload);
    defer a.free(ct);
    try testing.expectError(Error.InvalidCiphertext, decrypt(a, c, ct));
}
