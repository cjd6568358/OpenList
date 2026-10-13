"""Generate a real RSA-1024 PKCS#1 v1.5 test vector for src/util/rsa.zig.

Pure stdlib: Miller-Rabin + modular exponentiation. No third-party crypto.
Emits the SPKI DER (both bare-base64 and full PEM, the two shapes the 189 API
and 189pc hand us) plus a deterministic ciphertext so the Zig test can compare
byte-for-byte with a fixed padding string.
"""
import base64
import random

E = 65537
MSG = b"hunter2"

# --------------------------------------------------------------------------
# minimal RSA keygen
# --------------------------------------------------------------------------
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
                 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                 251]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        # e must be coprime with p-1; 65537 is prime so p % 65537 != 1 suffices
        if p % E == 1:
            continue
        if is_probable_prime(p):
            return p


# --------------------------------------------------------------------------
# minimal DER encoder
# --------------------------------------------------------------------------
def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def der_int(n: int) -> bytes:
    body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:          # keep it a positive INTEGER
        body = b"\x00" + body
    return der_tlv(0x02, body)


def der_seq(*parts: bytes) -> bytes:
    return der_tlv(0x30, b"".join(parts))


def der_bitstring(content: bytes) -> bytes:
    return der_tlv(0x03, b"\x00" + content)   # 0 unused bits


def der_null() -> bytes:
    return der_tlv(0x05, b"")


# OID 1.2.840.113549.1.1.1 rsaEncryption
RSA_OID = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])


def main() -> None:
    random.seed(20261010)   # reproducible output

    p = gen_prime(512)
    q = gen_prime(512)
    assert p != q
    n = p * q
    k = (n.bit_length() + 7) // 8
    assert k == 128, k

    spki = der_seq(
        der_seq(RSA_OID, der_null()),
        der_bitstring(der_seq(der_int(n), der_int(E))),
    )
    b64_body = base64.b64encode(spki).decode()

    # Deterministic PS: 1,2,3,...,255,1,2,... — never zero, so the Zig
    # implementation's "redraw on zero" loop never fires and the sequence is
    # exactly reproducible.
    ps_len = k - len(MSG) - 3
    ps = bytes(((i % 255) + 1) for i in range(ps_len))
    assert 0 not in ps

    em = b"\x00\x02" + ps + b"\x00" + MSG
    assert len(em) == k
    c = pow(int.from_bytes(em, "big"), E, n).to_bytes(k, "big")

    # sanity: decrypt with d to prove the vector is a real RSA key
    d = pow(E, -1, (p - 1) * (q - 1))
    assert pow(int.from_bytes(c, "big"), d, n).to_bytes(k, "big") == em

    pem_lines = [b64_body[i:i + 64] for i in range(0, len(b64_body), 64)]
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + "\n".join(pem_lines)
           + "\n-----END PUBLIC KEY-----\n")

    print(f"// modulus bits      : {n.bit_length()}")
    print(f"// modulus bytes     : {k}")
    print(f"// message           : {MSG.decode()!r} ({len(MSG)} bytes)")
    print(f"// PS length         : {ps_len}")
    print()
    print(f"const TEST_MODULUS_HEX =\n    \"{n:0{k*2}x}\";")
    print()
    print(f"const TEST_PEM_BODY =\n    \"{b64_body}\";")
    print()
    print(f"const TEST_PEM_FULL =\n    \"-----BEGIN PUBLIC KEY-----\\n\" ++\n"
          f"    \"{pem_lines[0]}\\n\";")
    print()
    print(f"const TEST_CIPHERTEXT_HEX =\n    \"{c.hex()}\";")
    print()
    print("--- full PEM ---")
    print(pem, end="")
    print("--- ps_len:", ps_len, "---")
    print("--- em hex ---")
    print(em.hex())


if __name__ == "__main__":
    main()
