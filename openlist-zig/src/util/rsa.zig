//! RSA PKCS#1 v1.5 public-key encryption — the login primitive of the 189 family.
//!
//! Why this is hand-written
//! ------------------------
//! `std.crypto.Certificate.rsa` already parses public keys and even contains an
//! `encrypt()` — but that function is private, and it implements the *signature*
//! padding (`EM = 0x00 || 0x01 || PS || 0x00 || T`), not the encryption padding
//! this driver needs (`EM = 0x00 || 0x02 || PS || 0x00 || M`). What std does
//! expose is everything required to build the encryption path ourselves:
//!
//!   * `rsa.PublicKey.parseDer`            — walks the PKIX RSAPublicKey
//!   * `rsa.PublicKey.{n, e}`              — public fields
//!   * `ff.Modulus.powWithEncodedPublicExponent` — the modular exponentiation
//!   * `Certificate.der.Element.parse`     — the ASN.1 walker
//!
//! So the missing piece is ~40 lines of padding plus the PEM unwrap. Vendoring
//! a bignum implementation instead would cost far more than it saves.
//!
//! `ff.Modulus(4096)` looks like it would force every key to 4096 bits, but it
//! does not: `Modulus.fromBytes` normalises away leading zero limbs, so
//! `bits()`/`encodedLen()` report the *actual* modulus size and a 1024-bit key
//! yields a 128-byte ciphertext. 4096 is just the ceiling — the same one
//! `std.crypto.Certificate.rsa` uses internally, so the two can never disagree
//! about what is representable.
//!
//! Callers
//! -------
//!   * `189`   — `RsaEncode(pw, pubKey, hex=true)`: the API hands back a bare
//!               base64 body (no PEM armor), and the result is lowercase hex
//!               that then gets prefixed with a server-supplied string.
//!   * `189pc` — `RsaEncrypt(pem, value)`: a full `-----BEGIN PUBLIC KEY-----`
//!               block in, UPPERCASE hex out.
//!
//! Both shapes are accepted by `parsePem`; the case of the hex is explicit in
//! the function name because getting it wrong produces a login failure that
//! looks like a wrong password.

const std = @import("std");
const hash = @import("hash.zig");

pub const Error = error{
    /// `-----BEGIN` with no matching `-----END`, or an unreadable first line.
    InvalidPem,
    /// Base64 body that does not decode.
    InvalidKeyBase64,
    /// DER that is not a PKIX SubjectPublicKeyInfo holding an RSAPublicKey.
    InvalidKeyEncoding,
    /// Modulus/exponent that `ff.Modulus` refuses (even, too small, too big).
    InvalidPublicKey,
    /// `msg.len > modulus.len - 11`; PKCS#1 v1.5 needs at least 8 bytes of
    /// non-zero padding plus the two 0x00/0x02 separator octets.
    MessageTooLong,
    /// The caller's output buffer is not exactly `modulus.len` bytes.
    OutputLengthMismatch,
    /// The modular exponentiation produced something that does not fit the
    /// modulus — only reachable if the key is corrupt.
    Internal,
    OutOfMemory,
};

/// Largest modulus accepted, matching `std.crypto.Certificate.rsa`.
const max_modulus_bits = 4096;
pub const MAX_MODULUS_BYTES = max_modulus_bits / 8;

const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;
const der = std.crypto.Certificate.der;

/// A public key. The slices borrow from the DER buffer they were parsed out of,
/// so they are only valid while that buffer lives — see `OwnedKey`, which is
/// what callers should normally hold.
pub const PublicKey = struct {
    /// Big-endian modulus, leading zero bytes already stripped.
    modulus: []const u8,
    /// Big-endian public exponent (65537 → `{0x01, 0x00, 0x01}`).
    exponent: []const u8,

    /// Ciphertext length for this key: 128 for RSA-1024, 256 for RSA-2048.
    pub fn ciphertextLen(self: PublicKey) usize {
        return self.modulus.len;
    }

    /// Parse the contents of a PKIX `RSAPublicKey`:
    /// `SEQUENCE { INTEGER modulus, INTEGER exponent }`.
    ///
    /// Delegates the ASN.1 walking to std, which already handles the leading
    /// zero byte that DER puts in front of a modulus whose top bit is set —
    /// a detail that silently produces a one-byte-too-long ciphertext if you
    /// write the walker yourself.
    pub fn parseRsaPublicKey(body: []const u8) Error!PublicKey {
        const comps = std.crypto.Certificate.rsa.PublicKey.parseDer(body) catch
            return error.InvalidKeyEncoding;
        if (comps.modulus.len == 0 or comps.exponent.len == 0) return error.InvalidKeyEncoding;
        if (comps.modulus.len > MAX_MODULUS_BYTES) return error.InvalidPublicKey;
        return .{ .modulus = comps.modulus, .exponent = comps.exponent };
    }

    /// Parse a PKIX `SubjectPublicKeyInfo`:
    ///
    ///     SEQUENCE {
    ///       SEQUENCE { OID rsaEncryption, NULL }   -- AlgorithmIdentifier
    ///       BIT STRING { SEQUENCE { INTEGER n, INTEGER e } }
    ///     }
    ///
    /// The OID is not checked: the 189 API hands us whatever it hands us, and a
    /// key that is not RSA fails the integer walk below anyway.
    pub fn parseSpki(spki: []const u8) Error!PublicKey {
        const outer = der.Element.parse(spki, 0) catch return error.InvalidKeyEncoding;
        if (outer.identifier.tag != .sequence) return error.InvalidKeyEncoding;

        const alg = der.Element.parse(spki, outer.slice.start) catch
            return error.InvalidKeyEncoding;
        if (alg.identifier.tag != .sequence) return error.InvalidKeyEncoding;

        const bits = der.Element.parse(spki, alg.slice.end) catch
            return error.InvalidKeyEncoding;
        if (bits.identifier.tag != .bitstring) return error.InvalidKeyEncoding;

        const content = spki[bits.slice.start..bits.slice.end];
        // A BIT STRING is prefixed with its count of unused trailing bits; a
        // DER integer sequence is byte-aligned, so it must be zero.
        if (content.len == 0 or content[0] != 0) return error.InvalidKeyEncoding;
        return parseRsaPublicKey(content[1..]);
    }
};

/// A public key together with the DER buffer it borrows from.
pub const OwnedKey = struct {
    der_bytes: []u8,
    key: PublicKey,

    pub fn deinit(self: *OwnedKey, alloc: std.mem.Allocator) void {
        alloc.free(self.der_bytes);
        self.* = undefined;
    }
};

/// Parse a public key from either shape the 189 APIs produce: a complete PEM
/// block, or the bare base64 body with no armor at all.
pub fn parsePem(alloc: std.mem.Allocator, pem_or_body: []const u8) Error!OwnedKey {
    const b64 = try stripPemArmor(alloc, pem_or_body);
    defer alloc.free(b64);

    const der_bytes = hash.base64StdDecode(alloc, b64) catch return error.InvalidKeyBase64;
    errdefer alloc.free(der_bytes);

    return .{
        .der_bytes = der_bytes,
        .key = try PublicKey.parseSpki(der_bytes),
    };
}

/// Reduce a PEM document (or a bare base64 body) to one base64 string with all
/// whitespace removed. Handles CRLF as well as LF — the 189 API's JSON has
/// embedded `\n`, but a hand-copied key will have `\r\n`.
fn stripPemArmor(alloc: std.mem.Allocator, text: []const u8) Error![]u8 {
    var body = std.mem.trim(u8, text, " \t\r\n");

    if (std.mem.startsWith(u8, body, "-----BEGIN")) {
        const first_nl = std.mem.indexOfScalar(u8, body, '\n') orelse return error.InvalidPem;
        const end = std.mem.indexOf(u8, body, "-----END") orelse return error.InvalidPem;
        if (end <= first_nl) return error.InvalidPem;
        body = body[first_nl + 1 .. end];
    }

    var n: usize = 0;
    for (body) |c| {
        if (!std.ascii.isWhitespace(c)) n += 1;
    }
    if (n == 0) return error.InvalidPem;

    const out = try alloc.alloc(u8, n);
    var i: usize = 0;
    for (body) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        out[i] = c;
        i += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// PKCS#1 v1.5
// ---------------------------------------------------------------------------

/// RFC 3447 §7.2.1 step 2 — build the encoded message
/// `EM = 0x00 || 0x02 || PS || 0x00 || M`.
///
/// Exposed rather than inlined into `encryptPkcs1v15` for two reasons: the
/// padding is the only part of this file with a decision to get wrong (the
/// `PS` octets must be non-zero, or the block becomes ambiguous), so it is
/// worth testing directly; and when a 189 login fails it is useful to see the
/// exact bytes that were about to be sent.
///
/// `out.len` is the modulus length; `out` is fully overwritten.
pub fn encodePkcs1v15(out: []u8, msg: []const u8, random: std.Random) Error!void {
    const k = out.len;
    if (k < 11) return error.MessageTooLong;
    if (msg.len > k - 11) return error.MessageTooLong;

    out[0] = 0x00;
    out[1] = 0x02;

    const ps = out[2 .. k - msg.len - 1];
    for (ps) |*b| {
        // Redraw until non-zero. A zero here would end the padding string
        // early and make the plaintext boundary ambiguous — Bleichenbacher's
        // attack lives in exactly that ambiguity.
        while (true) {
            random.bytes(b[0..1]);
            if (b.* != 0) break;
        }
    }

    out[k - msg.len - 1] = 0x00;
    @memcpy(out[k - msg.len ..], msg);
}

/// RFC 3447 §7.2.1 RSAES-PKCS1-v1_5 encryption: `c = EM^e mod n`.
///
/// `out.len` must equal `key.modulus.len` — the ciphertext is exactly as long
/// as the modulus, and the 189 API is sensitive to that length.
pub fn encryptPkcs1v15(
    out: []u8,
    msg: []const u8,
    key: PublicKey,
    random: std.Random,
) Error!void {
    const k = key.modulus.len;
    if (out.len != k) return error.OutputLengthMismatch;

    var em_buf: [MAX_MODULUS_BYTES]u8 = undefined;
    const em = em_buf[0..k];
    try encodePkcs1v15(em, msg, random);

    // `fromBytes` normalises to the modulus's real limb count and rejects a
    // value >= n. EM starts with 0x00 while n's top byte is non-zero, so EM < n
    // always holds — a failure here means a malformed modulus.
    const n = Modulus.fromBytes(key.modulus, .big) catch return error.InvalidPublicKey;
    const m = Fe.fromBytes(n, em, .big) catch return error.InvalidPublicKey;
    const c = n.powWithEncodedPublicExponent(m, key.exponent, .big) catch
        return error.InvalidPublicKey;
    c.toBytes(out, .big) catch return error.Internal;
}

/// Encrypt and return lowercase hex. This is the 189 `RsaEncode(..., hex=true)`
/// shape: upstream computes base64 and then runs it through `b64tohex`, which
/// is by construction the same string as hex-encoding the raw ciphertext, so
/// the base64 round trip is skipped.
pub fn encryptToHexLower(
    alloc: std.mem.Allocator,
    msg: []const u8,
    key: PublicKey,
    random: std.Random,
) Error![]u8 {
    var ct: [MAX_MODULUS_BYTES]u8 = undefined;
    try encryptPkcs1v15(ct[0..key.ciphertextLen()], msg, key, random);
    return hash.hexLower(alloc, ct[0..key.ciphertextLen()]);
}

/// Encrypt and return UPPERCASE hex — 189pc's `RsaEncrypt`, which ends with
/// `strings.ToUpper(hex.EncodeToString(...))`.
pub fn encryptToHexUpper(
    alloc: std.mem.Allocator,
    msg: []const u8,
    key: PublicKey,
    random: std.Random,
) Error![]u8 {
    var ct: [MAX_MODULUS_BYTES]u8 = undefined;
    try encryptPkcs1v15(ct[0..key.ciphertextLen()], msg, key, random);
    return hash.hexUpper(alloc, ct[0..key.ciphertextLen()]);
}

/// Parse + encrypt in one call, for the common driver case.
pub fn encryptPemToHex(
    alloc: std.mem.Allocator,
    msg: []const u8,
    pem_or_body: []const u8,
    random: std.Random,
    comptime upper: bool,
) Error![]u8 {
    var owned = try parsePem(alloc, pem_or_body);
    defer owned.deinit(alloc);
    return if (upper)
        encryptToHexUpper(alloc, msg, owned.key, random)
    else
        encryptToHexLower(alloc, msg, owned.key, random);
}

// ---------------------------------------------------------------------------
// Tests
//
// The key below is a real RSA-1024 key generated by `tools/gen_rsa_vector.py`.
// The expected ciphertext was computed in that script with Python's `pow()`,
// so the test pins padding, modular exponentiation and byte order against an
// independent implementation rather than against Zig's own opinion.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Bare base64 body, exactly as the 189 API returns it in `encryptConf.pubKey`.
const TEST_PEM_BODY =
    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHzNVsHL4ARsrrvz2SkykOTmUwRB" ++
    "MLTY+gEpIJk4Puojw59TiMCQGYf6ChOE6S52xqqIizU13/dtwqJVtTY4hwjoAwQt" ++
    "jMeBss/muGoL4tAAa28m1DsRut+tP0CgBbdW29vWApn7CmA9AA24+UQ8mw3Twtsy" ++
    "eOz+S7ZrAgSTs8aTAgMBAAE=";

/// The same key wrapped the way 189pc passes it.
const TEST_PEM_FULL =
    "-----BEGIN PUBLIC KEY-----\n" ++
    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHzNVsHL4ARsrrvz2SkykOTmUwRB\n" ++
    "MLTY+gEpIJk4Puojw59TiMCQGYf6ChOE6S52xqqIizU13/dtwqJVtTY4hwjoAwQt\n" ++
    "jMeBss/muGoL4tAAa28m1DsRut+tP0CgBbdW29vWApn7CmA9AA24+UQ8mw3Twtsy\n" ++
    "eOz+S7ZrAgSTs8aTAgMBAAE=\n" ++
    "-----END PUBLIC KEY-----\n";

const TEST_MSG = "hunter2";

/// PS = 0x01,0x02,…,0xFF,0x01,… (never zero), so the redraw loop never fires
/// and the sequence is exactly what the Python generator used.
const TEST_PS_LEN = 118;
const TEST_EM_HEX =
    "00020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" ++
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" ++
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" ++
    "606162636465666768696a6b6c6d6e6f707172737475760068756e74657232";

const TEST_CIPHERTEXT_HEX =
    "32e61c1ab0cccbd06ceeaee6185056e8045905cc92f38ca947ef4a20cb7c3ce7" ++
    "0ca12f278572dc4d0bef65e9e65f490efd8e28675f1fc433a88a7e365fa5af1e" ++
    "ea212a9a2d236135808767ab9489da7623b0b5d7cb7554fcbb582ebbeec413a3" ++
    "03e710f59a86816ff483f334e68f79dc84bdc5909821a8c3e64818acada96ce5";

/// A `std.Random` that replays a fixed byte pattern, so a test can pin down
/// exactly which padding string was drawn.
const PatternRandom = struct {
    pos: usize = 0,
    /// When true, every third byte drawn is 0x00 — which must be rejected and
    /// redrawn, letting the test observe the rejection loop.
    inject_zeroes: bool = false,

    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        for (buf) |*b| {
            const i = self.pos;
            self.pos += 1;
            if (self.inject_zeroes and i % 3 == 0) {
                b.* = 0x00;
            } else {
                // 1,2,…,255,1,… — the generator's sequence, skipping zero.
                b.* = @intCast((i % 255) + 1);
            }
        }
    }

    fn interface(self: *@This()) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

test "parseSpki reads a real RSA-1024 SubjectPublicKeyInfo" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_BODY);
    defer owned.deinit(a);

    try testing.expectEqual(@as(usize, 128), owned.key.modulus.len);
    try testing.expectEqual(@as(usize, 128), owned.key.ciphertextLen());
    // 65537, big-endian.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, owned.key.exponent);
    // DER pads a modulus whose top bit is set with a leading 0x00; the parser
    // must have stripped it or the ciphertext would be 129 bytes.
    try testing.expect(owned.key.modulus[0] == 0x7c);
}

test "parsePem accepts the armored form 189pc passes" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_FULL);
    defer owned.deinit(a);
    try testing.expectEqual(@as(usize, 128), owned.key.modulus.len);
}

test "parsePem tolerates CRLF and surrounding whitespace" {
    const a = testing.allocator;
    // `replaceOwned(T, allocator, input, needle, replacement)` — the allocator
    // comes second, not first.
    const crlf = try std.mem.replaceOwned(u8, a, TEST_PEM_FULL, "\n", "\r\n");
    defer a.free(crlf);
    const padded = try std.mem.concat(a, u8, &.{ "  \r\n", crlf, "\n\n  " });
    defer a.free(padded);

    var owned = try parsePem(a, padded);
    defer owned.deinit(a);
    try testing.expectEqual(@as(usize, 128), owned.key.modulus.len);
}

test "parsePem rejects malformed input" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidPem, parsePem(a, "-----BEGIN PUBLIC KEY-----\nAAAA"));
    try testing.expectError(error.InvalidPem, parsePem(a, "   \n  "));
    try testing.expectError(error.InvalidKeyBase64, parsePem(a, "!!!!not base64!!!!"));
    // Valid base64, but not a SubjectPublicKeyInfo.
    try testing.expectError(error.InvalidKeyEncoding, parsePem(a, "Zm9vYmFy"));
}

test "encodePkcs1v15 reproduces the reference EM byte for byte" {
    const a = testing.allocator;
    var out: [128]u8 = undefined;
    var prng = PatternRandom{};
    try encodePkcs1v15(&out, TEST_MSG, prng.interface());

    const expected = try hash.hexDecode(a, TEST_EM_HEX);
    defer a.free(expected);
    try testing.expectEqualSlices(u8, expected, &out);
}

test "encodePkcs1v15 never leaves a zero inside the padding string" {
    var out: [128]u8 = undefined;
    var prng = PatternRandom{ .inject_zeroes = true };
    try encodePkcs1v15(&out, TEST_MSG, prng.interface());

    try testing.expectEqual(@as(u8, 0x00), out[0]);
    try testing.expectEqual(@as(u8, 0x02), out[1]);
    const ps = out[2 .. 128 - TEST_MSG.len - 1];
    try testing.expectEqual(@as(usize, TEST_PS_LEN), ps.len);
    for (ps) |b| try testing.expect(b != 0);
    try testing.expectEqual(@as(u8, 0x00), out[128 - TEST_MSG.len - 1]);
    try testing.expectEqualStrings(TEST_MSG, out[128 - TEST_MSG.len ..]);
}

test "encodePkcs1v15 enforces the 11-byte overhead" {
    var prng = PatternRandom{};

    // k = 11 is the documented minimum and *does* allow an empty message:
    // RFC 3447 requires mLen <= k - 11, and 0 <= 0. The padding string is then
    // the full 8 bytes, which is exactly the PS minimum.
    var minimum: [11]u8 = undefined;
    try encodePkcs1v15(&minimum, "", prng.interface());
    try testing.expectEqual(@as(u8, 0x00), minimum[0]);
    try testing.expectEqual(@as(u8, 0x02), minimum[1]);
    try testing.expectEqual(@as(u8, 0x00), minimum[10]);
    for (minimum[2..10]) |b| try testing.expect(b != 0);

    // One byte below the minimum leaves no room for PS.
    var too_small: [10]u8 = undefined;
    try testing.expectError(error.MessageTooLong, encodePkcs1v15(&too_small, "", prng.interface()));

    // And the same block cannot carry a message.
    try testing.expectError(error.MessageTooLong, encodePkcs1v15(&minimum, "x", prng.interface()));

    // k = 128 admits at most 117 bytes of plaintext.
    var big: [128]u8 = undefined;
    var fits: [117]u8 = @splat('x');
    try encodePkcs1v15(&big, &fits, prng.interface());

    var over: [118]u8 = @splat('x');
    try testing.expectError(error.MessageTooLong, encodePkcs1v15(&big, &over, prng.interface()));
}

test "encryptPkcs1v15 matches the reference ciphertext" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_BODY);
    defer owned.deinit(a);

    var ct: [128]u8 = undefined;
    var prng = PatternRandom{};
    try encryptPkcs1v15(&ct, TEST_MSG, owned.key, prng.interface());

    const expected = try hash.hexDecode(a, TEST_CIPHERTEXT_HEX);
    defer a.free(expected);
    try testing.expectEqualSlices(u8, expected, &ct);
}

test "encryptToHexLower is 189's RsaEncode(hex=true) output" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_BODY);
    defer owned.deinit(a);

    var prng = PatternRandom{};
    const got = try encryptToHexLower(a, TEST_MSG, owned.key, prng.interface());
    defer a.free(got);
    try testing.expectEqualStrings(TEST_CIPHERTEXT_HEX, got);
    try testing.expectEqual(@as(usize, 256), got.len);
}

test "encryptToHexUpper is 189pc's RsaEncrypt output" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_FULL);
    defer owned.deinit(a);

    var prng = PatternRandom{};
    const got = try encryptToHexUpper(a, TEST_MSG, owned.key, prng.interface());
    defer a.free(got);

    const lower = try std.ascii.allocLowerString(a, got);
    defer a.free(lower);
    try testing.expectEqualStrings(TEST_CIPHERTEXT_HEX, lower);
    try testing.expect(!std.mem.eql(u8, lower, got)); // it really is uppercase
}

test "encryptPemToHex picks the case the caller asked for" {
    const a = testing.allocator;

    // Two independent PRNGs: `PatternRandom` advances its position, so sharing
    // one would give the second call a different (still valid) padding string
    // and make the comparison below meaningless.
    var prng_lower = PatternRandom{};
    var prng_upper = PatternRandom{};

    const lower = try encryptPemToHex(a, TEST_MSG, TEST_PEM_BODY, prng_lower.interface(), false);
    defer a.free(lower);
    const upper = try encryptPemToHex(a, TEST_MSG, TEST_PEM_BODY, prng_upper.interface(), true);
    defer a.free(upper);

    try testing.expectEqualStrings(TEST_CIPHERTEXT_HEX, lower);
    const expect_upper = try std.ascii.allocUpperString(a, TEST_CIPHERTEXT_HEX);
    defer a.free(expect_upper);
    try testing.expectEqualStrings(expect_upper, upper);
}

test "encryptPkcs1v15 rejects a wrong-sized output buffer" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_BODY);
    defer owned.deinit(a);

    var short: [127]u8 = undefined;
    var prng = PatternRandom{};
    try testing.expectError(
        error.OutputLengthMismatch,
        encryptPkcs1v15(&short, TEST_MSG, owned.key, prng.interface()),
    );
}

test "a real CSPRNG produces a different ciphertext each time" {
    const a = testing.allocator;
    var owned = try parsePem(a, TEST_PEM_BODY);
    defer owned.deinit(a);

    // Two encryptions of the same message must differ — otherwise the padding
    // is not random and the scheme is deterministic, which is a real break.
    var src: std.Random.IoSource = .{ .io = std.testing.io };
    const rnd = src.interface();

    const first = try encryptToHexLower(a, TEST_MSG, owned.key, rnd);
    defer a.free(first);
    const second = try encryptToHexLower(a, TEST_MSG, owned.key, rnd);
    defer a.free(second);

    try testing.expectEqual(@as(usize, 256), first.len);
    try testing.expect(!std.mem.eql(u8, first, second));
}
