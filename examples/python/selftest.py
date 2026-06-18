#!/usr/bin/env python3
"""Validate the from-scratch Python crypto against RFC test vectors.
    python3 selftest.py
"""
import sys

import example as bdd

failures = 0


def check(name: str, got: str, want: str) -> None:
    global failures
    if got == want:
        print(f"ok    {name}")
    else:
        print(f"FAIL  {name}\n        got  {got}\n        want {want}")
        failures += 1


# HKDF-SHA256 (RFC 5869 case 3: zero salt, empty info, L=42)
check("hkdf rfc5869#3",
      bdd.hkdf(b"\x0b" * 22, b"", 42).hex(),
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
      "9d201395faa4b61a96c8")

# ChaCha20 encryption (RFC 8439 2.4.2)
key = bytes(range(32))
nonce = bytes.fromhex("000000000000004a00000000")
pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
      b"only one tip for the future, sunscreen would be it.")
check("chacha20 rfc8439 2.4.2 (first 16)",
      bdd.chacha20_xor(key, 1, nonce, pt)[:16].hex(),
      "6e2e359a2568f98041ba0728dd0d6981")

# Poly1305 (RFC 8439 2.5.2)
pkey = bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                     "0103808afb0db2fd4abff6af4149f51b")
check("poly1305 rfc8439 2.5.2",
      bdd.poly1305(b"Cryptographic Forum Research Group", pkey).hex(),
      "a8061dc1305136c6c22b8baf0c0127a9")

# AEAD ciphertext (RFC 8439 2.8.2) — keystream is AAD-independent.
akey = bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                     "909192939495969798999a9b9c9d9e9f")
anonce = bytes.fromhex("070000004041424344454647")
blob = bdd.aead_seal(akey, anonce, pt)
check("aead ciphertext rfc8439 2.8.2",
      blob[28:44].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")

# AEAD round-trip + tamper detection
k = b"\x07" * 32
n = b"\x09" * 12
b = bdd.aead_seal(k, n, b"deadbeef payload")
check("aead roundtrip", bdd.aead_open(k, b).decode(), "deadbeef payload")
tampered = bytearray(b)
tampered[28] ^= 1
threw = False
try:
    bdd.aead_open(k, bytes(tampered))
except Exception:
    threw = True
check("aead tamper detected", "yes" if threw else "no", "yes")

print("\nall vectors pass" if not failures else f"\n{failures} FAILURE(S)")
sys.exit(1 if failures else 0)
