//! m115 —— 115 网盘**下载**链路的请求/响应口令（`115driver/pkg/crypto/m115`）。
//!
//! 与 ec115（上传）是两套完全独立的密码学：这里用 **RSA-1024 + 多层异或**，
//! 而且 RSA 用的是「裸模数」而不是 DER/PEM —— 公钥 (N, E) 直接硬编码在
//! `m115/rsa.go:11-19`，指数 E = 0x10001。
//!
//! ## 下载 URL 请求为什么要加密
//!
//! `POST https://proapi.115.com/app/chrome/downurl?t=<秒>` 的 body 是
//! `data=<base64>`，其中 base64 是 `Encode(json, key)` 的结果；服务端返回的
//! `data` 字段再交给 `Decode(..., key)` 解出真正的下载地址。客户端持有一个
//! 每次请求新生成的 16 字节随机 `key`，它被塞进密文最前面，服务端用私钥
//! 「解密」后拿回来。
//!
//! ## ⚠️ Encode 与 Decode 不对称（重要）
//!
//! Go 的 `rsaEncryptSlice`/`rsaDecryptSlice` **都用同一个指数 E**
//! （`big.NewInt(0).Exp(msg, _E, _N)`）—— 服务端用私钥「解」客户端用公钥
//! 「加」的东西。这意味着**客户端无法自己完成 Encode→Decode 回环**
//! （那样算出来是 x^(E²) mod N，不是 x）。所以单测里：
//!   * `Encode` 用独立实现（Python `pow`）算出的向量逐字节比对；
//!   * `Decode` 用「任意 128 字节密文 → pow(x,E,N) → 异或分层」的完整
//!     向量比对，而不是回环。
//! 两套向量都由 `tools/gen_115_vectors.py` 生成。
//!
//! ## RSA 实现选择
//!
//! 模幂直接用 `std.crypto.ff.Modulus(1024)` —— 与 `util/rsa.zig`（PKCS#1 v1.5
//! + DER 解析）不同，这里的模数不是 DER，填充规则也略有差别
//! （`buf[2+i] = pad[i] % 0xff + 1`，保证非零），所以不能复用那边的入口，
//! 但底层用的是同一套 std 有限域原语。

const std = @import("std");
const hash = @import("hash.zig");
const Buf = @import("buf.zig").Buf;

pub const Error = error{
    InvalidBase64,
    /// `input.len > KEY_LEN - 11`（单个 RSA 块塞不下）。
    MessageTooLong,
    /// 模数/元素不被 `ff.Modulus` 接受（理论上只可能是常量写错）。
    InvalidKey,
    Internal,
    OutOfMemory,
};

/// RSA-1024 模长（字节）。`rsa.go:_KeyLength = _N.BitLen() / 8`。
pub const KEY_LEN = 128;
/// 单个 RSA 块能承载的明文上限（PKCS#1 v1.5：k - 11）。
pub const MAX_SLICE = KEY_LEN - 11;

/// `Encode`/`Decode` 用的 16 字节会话密钥。
pub const Key = [16]u8;

// ---------------------------------------------------------------------------
// 硬编码常量（m115/rsa.go、m115/xor.go）
// ---------------------------------------------------------------------------

const N_HEX =
    "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b86021" ++
    "36477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad633" ++
    "8c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f1" ++
    "0a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683";

const N_BYTES: [KEY_LEN]u8 = blk: {
    var out: [KEY_LEN]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, N_HEX) catch unreachable;
    break :blk out;
};

/// E = 0x10001，大端。
const E_BYTES = [_]u8{ 0x01, 0x00, 0x01 };

const Modulus = std.crypto.ff.Modulus(1024);
const Fe = Modulus.Fe;

/// `m115/xor.go:xorKeySeed`（144 字节）。
const xor_key_seed = [144]u8{
    0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x8a,
    0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0xb8,
    0xde, 0x8f, 0xe7, 0xc4, 0x45, 0xda, 0x86, 0xc4,
    0x9b, 0x64, 0x8b, 0x14, 0x6a, 0xb4, 0xf1, 0xaa,
    0x38, 0x01, 0x35, 0x9e, 0x26, 0x69, 0x2c, 0x86,
    0x00, 0x6b, 0x4f, 0xa5, 0x36, 0x34, 0x62, 0xa6,
    0x2a, 0x96, 0x68, 0x18, 0xf2, 0x4a, 0xfd, 0xbd,
    0x6b, 0x97, 0x8f, 0x4d, 0x8f, 0x89, 0x13, 0xb7,
    0x6c, 0x8e, 0x93, 0xed, 0x0e, 0x0d, 0x48, 0x3e,
    0xd7, 0x2f, 0x88, 0xd8, 0xfe, 0xfe, 0x7e, 0x86,
    0x50, 0x95, 0x4f, 0xd1, 0xeb, 0x83, 0x26, 0x34,
    0xdb, 0x66, 0x7b, 0x9c, 0x7e, 0x9d, 0x7a, 0x81,
    0x32, 0xea, 0xb6, 0x33, 0xde, 0x3a, 0xa9, 0x59,
    0x34, 0x66, 0x3b, 0xaa, 0xba, 0x81, 0x60, 0x48,
    0xb9, 0xd5, 0x81, 0x9c, 0xf8, 0x6c, 0x84, 0x77,
    0xff, 0x54, 0x78, 0x26, 0x5f, 0xbe, 0xe8, 0x1e,
    0x36, 0x9f, 0x34, 0x80, 0x5c, 0x45, 0x2c, 0x9b,
    0x76, 0xd5, 0x1b, 0x8f, 0xcc, 0xc3, 0xb8, 0xf5,
};

/// `m115/xor.go:xorClientKey`（12 字节）。
const xor_client_key = [12]u8{
    0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18,
    0x4c, 0x01, 0x3f, 0x46,
};

// ---------------------------------------------------------------------------
// XOR 层
// ---------------------------------------------------------------------------

/// `m115/xor.go:xorDeriveKey`。`seed` 至少 `size` 字节；结果写进 `out[0..size]`。
fn xorDeriveKey(seed: []const u8, size: usize, out: []u8) void {
    std.debug.assert(out.len >= size and seed.len >= size);
    for (0..size) |i| {
        out[i] = seed[i] +% xor_key_seed[size * i];
        out[i] ^= xor_key_seed[size * (size - i - 1)];
    }
}

/// `m115/xor.go:xorTransform`（就地异或）。`mod = len % 4` 的前几字节用
/// `key[i]`，其余用 `key[(i-mod) % key_len]` —— 这是 Go 的原样行为，不是笔误。
fn xorTransform(data: []u8, key: []const u8) void {
    const key_size = key.len;
    std.debug.assert(key_size > 0);
    const mod = data.len % 4;
    if (mod > 0) {
        for (0..mod) |i| data[i] ^= key[i % key_size];
    }
    var i = mod;
    while (i < data.len) : (i += 1) {
        data[i] ^= key[(i - mod) % key_size];
    }
}

fn reverseBytes(data: []u8) void {
    std.mem.reverse(u8, data);
}

// ---------------------------------------------------------------------------
// RSA（裸模数）
// ---------------------------------------------------------------------------

fn modulus() Modulus {
    return Modulus.fromBytes(&N_BYTES, .big) catch unreachable;
}

/// `rsaEncryptSlice`：单块 PKCS#1 v1.5 填充 + `m^E mod N`，输出恒为 128 字节。
fn rsaEncryptSlice(out: *Buf, input: []const u8, random: std.Random) !void {
    if (input.len > MAX_SLICE) return error.MessageTooLong;
    var em: [KEY_LEN]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x02;
    const pad_size = KEY_LEN - input.len - 3;
    var pad: [KEY_LEN]u8 = undefined;
    random.bytes(pad[0..pad_size]);
    for (0..pad_size) |i| em[2 + i] = (pad[i] % 0xff) +% 1; // 恒 ∈ [1,255]
    em[pad_size + 2] = 0x00;
    @memcpy(em[pad_size + 3 ..], input);

    const m = modulus();
    const fe = Fe.fromBytes(m, &em, .big) catch return error.InvalidKey;
    const c = m.powWithEncodedPublicExponent(fe, &E_BYTES, .big) catch return error.InvalidKey;
    var ct: [KEY_LEN]u8 = undefined;
    c.toBytes(&ct, .big) catch return error.Internal;
    try out.append(&ct);
}

/// `rsaEncrypt`：按 `MAX_SLICE` 分块，逐块 RSA 后拼接。
fn rsaEncrypt(alloc: std.mem.Allocator, input: []const u8, random: std.Random) ![]u8 {
    var out = Buf.init(alloc);
    defer out.deinit(); // toOwned() copies; the scratch buffer always goes
    var rest = input;
    while (rest.len > 0) {
        const n = @min(rest.len, MAX_SLICE);
        try rsaEncryptSlice(&out, rest[0..n], random);
        rest = rest[n..];
    }
    return out.toOwned();
}

/// `rsaDecryptSlice`：`x^E mod N`，然后**丢掉第一个 0x00 之前的全部字节**
/// （含那个 0x00）。注意用的仍是 E，见文件头说明。
fn rsaDecryptSlice(out: *Buf, input: []const u8) !void {
    const m = modulus();
    const fe = Fe.fromBytes(m, input, .big) catch return error.InvalidKey;
    const r = m.powWithEncodedPublicExponent(fe, &E_BYTES, .big) catch return error.InvalidKey;
    var ret: [KEY_LEN]u8 = undefined;
    r.toBytes(&ret, .big) catch return error.Internal;
    for (ret, 0..) |b, i| {
        if (b == 0 and i != 0) {
            try out.append(ret[i + 1 ..]);
            return;
        }
    }
}

fn rsaDecrypt(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = Buf.init(alloc);
    defer out.deinit(); // see rsaEncrypt
    var rest = input;
    while (rest.len > 0) {
        const n = @min(rest.len, KEY_LEN);
        try rsaDecryptSlice(&out, rest[0..n]);
        rest = rest[n..];
    }
    return out.toOwned();
}

// ---------------------------------------------------------------------------
// 公开入口
// ---------------------------------------------------------------------------

/// `m115.GenerateKey`：16 字节随机会话密钥。
pub fn generateKey(random: std.Random) Key {
    var k: Key = undefined;
    random.bytes(&k);
    return k;
}

/// `m115.Encode`：`key || input` → 异或分层 → RSA → base64（含 `=` 填充）。
pub fn encode(alloc: std.mem.Allocator, input: []const u8, key: Key, random: std.Random) ![]u8 {
    const buf = try alloc.alloc(u8, 16 + input.len);
    defer alloc.free(buf);
    @memcpy(buf[0..16], &key);
    @memcpy(buf[16..], input);

    var dk: [4]u8 = undefined;
    xorDeriveKey(&key, 4, &dk);
    const tail = buf[16..];
    xorTransform(tail, &dk);
    reverseBytes(tail);
    xorTransform(tail, &xor_client_key);

    const ct = try rsaEncrypt(alloc, buf, random);
    defer alloc.free(ct);
    return hash.base64Std(alloc, ct);
}

/// `m115.Decode`：base64 → RSA(`x^E mod N`) → 异或分层 → 明文。
pub fn decode(alloc: std.mem.Allocator, input_b64: []const u8, key: Key) ![]u8 {
    const raw = hash.base64StdDecode(alloc, input_b64) catch return error.InvalidBase64;
    defer alloc.free(raw);

    const data = try rsaDecrypt(alloc, raw);
    defer alloc.free(data);
    if (data.len < 16) return error.Internal;

    const out = try alloc.alloc(u8, data.len - 16);
    errdefer alloc.free(out);
    @memcpy(out, data[16..]);

    var dk12: [12]u8 = undefined;
    xorDeriveKey(data[0..16], 12, &dk12);
    xorTransform(out, &dk12);
    reverseBytes(out);
    var dk4: [4]u8 = undefined;
    xorDeriveKey(&key, 4, &dk4);
    xorTransform(out, &dk4);
    return out;
}

// ---------------------------------------------------------------------------
// 测试 —— 向量来自 tools/gen_115_vectors.py（Python `pow()` 独立实现）
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 固定字节序列的假随机源，让 RSA 填充可复现（字节 i = i & 0xff）。
const PatternRandom = struct {
    pos: usize = 0,
    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        for (buf) |*b| {
            b.* = @intCast(self.pos & 0xff);
            self.pos += 1;
        }
    }
    fn interface(self: *@This()) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

const XOR_DERIVE_4_HEX = "8ddaa370";
const XOR_DERIVE_12_HEX = "ac81271bc54352d81c587497";

test "m115 xorDeriveKey matches the reference for sizes 4 and 12" {
    const a = testing.allocator;
    var seed: [16]u8 = undefined;
    for (0..16) |i| seed[i] = @intCast(i);

    var k4: [4]u8 = undefined;
    xorDeriveKey(&seed, 4, &k4);
    const h4 = try hash.hexLower(a, &k4);
    defer a.free(h4);
    try testing.expectEqualStrings(XOR_DERIVE_4_HEX, h4);

    var k12: [12]u8 = undefined;
    xorDeriveKey(&seed, 12, &k12);
    const h12 = try hash.hexLower(a, &k12);
    defer a.free(h12);
    try testing.expectEqualStrings(XOR_DERIVE_12_HEX, h12);
}

test "m115 xorTransform is an involution and honours the mod-4 prefix" {
    var data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const key = [_]u8{ 0xaa, 0xbb, 0xcc };
    const orig = data;
    xorTransform(&data, &key);
    try testing.expect(!std.mem.eql(u8, &orig, &data));
    xorTransform(&data, &key);
    try testing.expectEqualSlices(u8, &orig, &data);
}

test "m115 RSA modExp reproduces the Python reference ciphertexts" {
    const a = testing.allocator;

    // 消息 8 字节 → pad_size = 128-8-3 = 117
    const m1_m = try hash.hexDecode(a, "1234567890abcdef");
    defer a.free(m1_m);
    const m1_c = try hash.hexDecode(a,
        "388f4e6c12384958076d8e560318db7b26108c98d6a8df1c540582874c8554e6" ++
        "acce76fc866d5fac10db9019967856f460ae55250829805609b8d9144551106e" ++
        "b3893c180abf80263d7435beb9b547bf36a4a91448aaae53a5c004f3d9c58106" ++
        "afbd5f7546958bb66de67788b08ebf72b0a9c0c10a69d1e19c7dc3d6c872d724");
    defer a.free(m1_c);
    var prng1 = PatternRandom{};
    var out1 = Buf.init(a);
    defer out1.deinit();
    try rsaEncryptSlice(&out1, m1_m, prng1.interface());
    try testing.expectEqualSlices(u8, m1_c, out1.slice());

    // 消息 16 字节 → pad_size = 109，覆盖另一条填充长度
    const m2_m = try hash.hexDecode(a, "deadbeefcafebabe1234567890abcdef");
    defer a.free(m2_m);
    const m2_c = try hash.hexDecode(a,
        "58a6e5c0cdada5becf179d34e3c9a849027992612a8b53156a3bf8a731c425f9" ++
        "43837384dd6822bac3a83aba8281faf939709fadeaccd783d8ce2f54af2751b8" ++
        "df08b87aca457b74455612d045de00b52b5aeeef627598c175b7aaa709edafbf" ++
        "9ff7dc855ef846c218828a76a15052a1d4517a827295f4c89501ea5787de9897");
    defer a.free(m2_c);
    var prng2 = PatternRandom{};
    var out2 = Buf.init(a);
    defer out2.deinit();
    try rsaEncryptSlice(&out2, m2_m, prng2.interface());
    try testing.expectEqualSlices(u8, m2_c, out2.slice());
}

test "m115 encode produces a 128-byte block that base64 round-trips" {
    const a = testing.allocator;
    var key: [16]u8 = undefined;
    for (0..16) |i| key[i] = @intCast(i);
    const input = try hash.hexDecode(a, "7069636b636f64653a616263313233");
    defer a.free(input);

    var prng = PatternRandom{};
    const b64 = try encode(a, input, key, prng.interface());
    defer a.free(b64);
    try testing.expectEqual(@as(usize, 172), b64.len); // ceil(128/3)*4
    const raw = try hash.base64StdDecode(a, b64);
    defer a.free(raw);
    try testing.expectEqual(@as(usize, KEY_LEN), raw.len);
}

test "m115 encode is deterministic for a fixed RNG and pins the Python vector" {
    const a = testing.allocator;
    var key: [16]u8 = undefined;
    for (0..16) |i| key[i] = @intCast(i);
    const input = try hash.hexDecode(a, "7069636b636f64653a616263313233");
    defer a.free(input);

    var prng = PatternRandom{};
    const b64 = try encode(a, input, key, prng.interface());
    defer a.free(b64);
    try testing.expectEqualStrings(
        "GMz/t6RFtHjWkshBp5eHF4hvJBIFRZ9Dtd1NZTZH/qkcQa0bOz2mikg6xqyaPQjPEfuVjcx9xIJ7PhkyuYmbjH2x5xLQ3R/RLHhj+amjpM3KHMxGcVCtVWIWOPjR9xMl/oVjzDpvgyuItnGITfc30T3v6Ux+Cg/93F1eSiPvbRo=",
        b64,
    );
}

test "m115 decode reproduces the Python reference plaintext" {
    const a = testing.allocator;
    var key: [16]u8 = undefined;
    for (0..16) |i| key[i] = @intCast(i);

    // 输入 = 128 个 0x03 字节的 base64；Python 端跑完整 Decode 得到下面这串明文。
    const raw_in: [128]u8 = @splat(0x03);
    const in_b64 = try hash.base64Std(a, &raw_in);
    defer a.free(in_b64);

    const got = try decode(a, in_b64, key);
    defer a.free(got);
    const want = try hash.hexDecode(a,
        "d059627b26d94471a14b5619250d9e63dd1c544773c1224406c7fd812ebc9aad" ++
        "ec44e160b2370f6140dd9f47a352411f5e9da655133118fc2af7a631f133103c" ++
        "953d802ea9acdb7478e050bfc82e81bc302b62a4e595226d0c688d77365604b1" ++
        "22fa3ea00dd3be4d3484");
    defer a.free(want);
    try testing.expectEqualSlices(u8, want, got);
}

test "m115 decode rejects invalid base64" {
    const a = testing.allocator;
    const key: [16]u8 = @splat(0);
    try testing.expectError(error.InvalidBase64, decode(a, "!!!!not base64!!!!", key));
}
