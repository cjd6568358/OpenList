#!/usr/bin/env python3
"""Generate cross-implementation test vectors for the 115 driver's two ciphers.

Two independent ciphers are involved in talking to 115:

  * ec115 (upload)  -- P-224 ECDH + AES + LZ4, and a hand-rolled "token" blob.
  * m115  (download) -- RSA-1024 + layered XOR.

Neither can be exercised end-to-end against the live server from a unit test, so
the Zig unit tests pin their behaviour against vectors produced here by an
independent implementation (Python `cryptography` + plain `pow()`). If the Zig
port and this script ever disagree, one of them is wrong.

Output is a block of Zig `const`s printed to stdout, ready to paste into the
test section of `src/util/ec115.zig` / `src/util/m115.zig`.

Run:
    C:/Users/Administrator/.workbuddy-ai/binaries/python/versions/3.13.12/python.exe \
        tools/gen_115_vectors.py
"""

import base64
import hashlib
import zlib

from cryptography.hazmat.primitives.asymmetric import ec

# ---------------------------------------------------------------------------
# P-224 (secp224r1) parameters, straight from SEC 2 / FIPS 186-4.
# ---------------------------------------------------------------------------

P224_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
P224_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
P224_B = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
P224_GX = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
P224_GY = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34

# The 115 server's static public point (ec115/cipher.go:20-28): X || Y, 28 bytes each.
REMOTE_PUB = bytes([
    0x57, 0xA2, 0x92, 0x57, 0xCD, 0x23, 0x20, 0xE5,
    0xD6, 0xD1, 0x43, 0x32, 0x2F, 0xA4, 0xBB, 0x8A,
    0x3C, 0xF9, 0xD3, 0xCC, 0x62, 0x3E, 0xF5, 0xED,
    0xAC, 0x62, 0xB7, 0x67, 0x8A, 0x89, 0xC9, 0x1A,
    0x83, 0xBA, 0x80, 0x0D, 0x61, 0x29, 0xF5, 0x22,
    0xD0, 0x34, 0xC8, 0x95, 0xDD, 0x24, 0x65, 0x24,
    0x3A, 0xDD, 0xC2, 0x50, 0x95, 0x3B, 0xEE, 0xBA,
])
REMOTE_X = int.from_bytes(REMOTE_PUB[:28], "big")
REMOTE_Y = int.from_bytes(REMOTE_PUB[28:], "big")

CRC_SALT = b"^j>WD3Kr?J2gLFjD4W2y@"


def hx(b: bytes) -> str:
    return b.hex()


def ec115_pubkey_encode(priv: int) -> bytes:
    """The 30-byte blob ec115 puts in EncodeToken: [0x1d, 0x02|0x03, X(28)]."""
    pk = ec.derive_private_key(priv, ec.SECP224R1())
    nums = pk.public_key().public_numbers()
    x = nums.x.to_bytes(28, "big")
    parity = 0x03 if (nums.y & 1) else 0x02
    return bytes([0x1D, parity]) + x


def ec115_shared_secret(priv: int) -> bytes:
    pk = ec.derive_private_key(priv, ec.SECP224R1())
    peer = ec.EllipticCurvePublicNumbers(REMOTE_X, REMOTE_Y, ec.SECP224R1()).public_key()
    return pk.exchange(ec.ECDH(), peer)


def ec115_encode_token(pubkey: bytes, timestamp: int, r1: int, r2: int) -> str:
    """Port of ec115/cipher.go EncodeToken (with r1/r2 forced for determinism)."""
    t = timestamp.to_bytes(4, "big")
    tmp = bytearray()
    for i in range(15):
        tmp.append(pubkey[i] ^ r1)
    tmp += bytes([r1, 0x73 ^ r1])
    tmp += bytes([r1, r1, r1])
    for i in range(4):
        tmp.append(r1 ^ t[3 - i])
    for i in range(15, len(pubkey)):
        tmp.append(pubkey[i] ^ r2)
    tmp += bytes([r2, 0x01 ^ r2])
    tmp += bytes([r2, r2, r2])
    crc = zlib.crc32(CRC_SALT + bytes(tmp)) & 0xFFFFFFFF
    crc_b = crc.to_bytes(4, "big")
    for i in range(4):
        tmp.append(crc_b[3 - i])
    return base64.b64encode(bytes(tmp)).decode()


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """ec115 Encrypt == plain AES-128-CBC over PKCS7-padded input."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


# ---------------------------------------------------------------------------
# m115 (download): RSA-1024 with a bare modulus, plus XOR layers.
# ---------------------------------------------------------------------------

M115_N = int(
    "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b86021"
    "36477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad633"
    "8c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f1"
    "0a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683",
    16,
)
M115_E = 0x10001
M115_KEYLEN = M115_N.bit_length() // 8  # 128

M115_XOR_SEED = bytes([
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
])

M115_XOR_CLIENT = bytes([
    0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18,
    0x4c, 0x01, 0x3f, 0x46,
])


def xor_derive_key(seed: bytes, size: int) -> bytes:
    key = bytearray(size)
    for i in range(size):
        key[i] = (seed[i] + M115_XOR_SEED[size * i]) & 0xFF
        key[i] ^= M115_XOR_SEED[size * (size - i - 1)]
    return bytes(key)


def xor_transform(data: bytearray, key: bytes) -> None:
    data_size, key_size = len(data), len(key)
    mod = data_size % 4
    if mod > 0:
        for i in range(mod):
            data[i] ^= key[i % key_size]
    for i in range(mod, data_size):
        data[i] ^= key[(i - mod) % key_size]


def m115_rsa_slice(msg: bytes, ps: bytes) -> bytes:
    """One PKCS#1 v1.5 block with an explicit padding string `ps`."""
    pad_size = M115_KEYLEN - len(msg) - 3
    assert len(ps) == pad_size, (len(ps), pad_size)
    buf = bytearray(M115_KEYLEN)
    buf[0], buf[1] = 0, 2
    for i, b in enumerate(ps):
        buf[2 + i] = b
    buf[pad_size + 2] = 0
    buf[pad_size + 3:] = msg
    m = int.from_bytes(buf, "big")
    return pow(m, M115_E, M115_N).to_bytes(M115_KEYLEN, "big")


def pattern_ps(n: int) -> bytes:
    """The padding the Zig test's PatternRandom produces: ((i)%255)+1."""
    return bytes(((i % 255) + 1) for i in range(n))


def main() -> None:
    print("// ---- P-224 ECDH (private scalar pinned for the test) ----")
    priv = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    pub = ec115_pubkey_encode(priv)
    shared = ec115_shared_secret(priv)
    print(f'const P224_D_HEX = "{priv:048x}";')
    print(f'const P224_PUBKEY_HEX = "{hx(pub)}";  // {len(pub)} bytes')
    print(f'const P224_SHARED_HEX = "{hx(shared)}";  // {len(shared)} bytes')
    print(f"// shared[0:16] = key, shared[12:28] = iv")
    print(f'const P224_KEY_HEX = "{hx(shared[:16])}";')
    print(f'const P224_IV_HEX = "{hx(shared[12:28])}";')
    print()

    print("// ---- ec115 EncodeToken (r1/r2 pinned) ----")
    ts = 1234567890
    for r1, r2, name in ((0xAA, 0xBB, "A"), (0x11, 0x22, "B"), (0x00, 0xFF, "C")):
        tok = ec115_encode_token(pub, ts, r1, r2)
        print(f'// ts={ts} r1=0x{r1:02x} r2=0x{r2:02x} -> len={len(tok)}')
        print(f'const EC115_TOKEN_{name} = "{tok}";')
    print()

    print("// ---- ec115 Encrypt (== AES-128-CBC) ----")
    key = shared[:16]
    iv = shared[12:28]
    for pt, name in ((b"hello ec115", "A"), (b"", "B"), (bytes(range(16)), "C")):
        ct = aes_cbc_encrypt(key, iv, pt)
        print(f'// plaintext {pt!r} -> {len(ct)} bytes')
        print(f'const EC115_ENC_{name}_PT_HEX = "{hx(pt)}";')
        print(f'const EC115_ENC_{name}_CT_HEX = "{hx(ct)}";')
    print()

    print("// ---- m115 RSA-1024 modExp (explicit PKCS#1 padding) ----")
    for msg, name in ((bytes.fromhex("1234567890abcdef"), "M1"),
                      (bytes.fromhex("deadbeefcafebabe1234567890abcdef"), "M2")):
        ps = pattern_ps(M115_KEYLEN - len(msg) - 3)
        ct = m115_rsa_slice(msg, ps)
        print(f'const M115_{name}_M_HEX = "{hx(msg)}";')
        print(f'const M115_{name}_C_HEX = "{hx(ct)}";')
    print()

    print("// ---- m115 xorDeriveKey ----")
    seed = bytes(range(16))
    print(f'const XOR_SEED_HEX = "{hx(seed)}";')
    print(f'const XOR_DERIVE_4_HEX = "{hx(xor_derive_key(seed, 4))}";')
    print(f'const XOR_DERIVE_12_HEX = "{hx(xor_derive_key(seed, 12))}";')
    print()

    print("// ---- m115 Encode (full pipeline, deterministic key) ----")
    k = bytes(range(16))
    inp = b"pickcode:abc123"
    tail = bytearray(inp)
    xor_transform(tail, xor_derive_key(k, 4))
    tail = tail[::-1]
    xor_transform(tail, M115_XOR_CLIENT)
    buf = k + bytes(tail)  # key prefix is part of the RSA payload
    ct = m115_rsa_slice(buf, pattern_ps(M115_KEYLEN - len(buf) - 3))
    print(f'const M115_ENCODE_KEY_HEX = "{hx(k)}";')
    print(f'const M115_ENCODE_IN_HEX = "{hx(inp)}";')
    print(f'const M115_ENCODE_OUT_B64 = "{base64.b64encode(ct).decode()}";')
    print()

    print("// ---- m115 Decode (full pipeline; server-encrypted blob simulated) ----")
    # The server encrypts with a key the client cannot reproduce, so Decode cannot
    # round-trip Encode. We instead pick an arbitrary 128-byte ciphertext block,
    # apply the same `pow(x, E, N)` the Go rsaDecrypt does, then the XOR layers,
    # and pin the whole result.
    dec_key = bytes(range(16))
    for candidate in range(1, 64):
        dec_in = bytes([candidate]) * 128
        ret = pow(int.from_bytes(dec_in, "big"), M115_E, M115_N).to_bytes(M115_KEYLEN, "big")
        idx = next((i for i, b in enumerate(ret) if b == 0 and i != 0), None)
        if idx is None or idx + 1 >= M115_KEYLEN - 16:
            continue
        data = ret[idx + 1:]
        out = bytearray(data[16:])
        xor_transform(out, xor_derive_key(data[:16], 12))
        out = out[::-1]
        xor_transform(out, xor_derive_key(dec_key, 4))
        print(f'const M115_DECODE_IN_B64 = "{base64.b64encode(dec_in).decode()}";')
        print(f'const M115_DECODE_KEY_HEX = "{hx(dec_key)}";')
        print(f'const M115_DECODE_OUT_HEX = "{hx(bytes(out))}";')
        break
    else:
        raise SystemExit("no suitable Decode vector found")


if __name__ == "__main__":
    main()
