#!/usr/bin/env python3
"""Blind Dead Drop — Python example client, crypto reimplemented from scratch.

Unlike the native PHP example (which imports the bddphp package), this client
reimplements HKDF-SHA256 (RFC 5869) and ChaCha20-Poly1305 (RFC 8439) with only
the Python standard library, to demonstrate that the wire format and derivation
labels are a cross-language contract. It produces the same bytes as the server
and interoperates with the PHP and C++ examples.

WARNING: educational, not constant-time, not audited. Don't protect real
secrets with this — use an audited library (the package does).

Usage:
    python3 example.py --secret HEX [--host H] [--port P]
        [--scheme http|https] [--insecure] CMD CHANNEL [MSG]

Commands: send-request / get-request / send-response / get-response /
wait-response / reply-upper (worker: wait a request, reply UPPERCASED).
The secret may also come from the BDD_SECRET environment variable.
"""
import argparse
import hashlib
import hmac
import http.client
import os
import ssl
import struct
import sys

# ----------------------------------------------------------------- HKDF
def hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 with the RFC default (all-zero) salt, matching the server."""
    salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()  # extract
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ------------------------------------------------------------- ChaCha20
def _rotl(v: int, c: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key))
    s.append(counter & 0xFFFFFFFF)
    s += list(struct.unpack("<3I", nonce))
    w = list(s)
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + s[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    off = 0
    while off < len(data):
        ks = _chacha_block(key, counter, nonce)
        counter += 1
        chunk = data[off:off + 64]
        out += bytes(b ^ ks[i] for i, b in enumerate(chunk))
        off += 64
    return bytes(out)


# ------------------------------------------------------------- Poly1305
def poly1305(msg: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


# ----------------------------------------------- ChaCha20-Poly1305 AEAD
def _mac_data(ciphertext: bytes) -> bytes:
    # AAD is empty in this protocol.
    pad = b"\x00" * ((16 - len(ciphertext) % 16) % 16)
    return ciphertext + pad + struct.pack("<QQ", 0, len(ciphertext))


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    ct = chacha20_xor(key, 1, nonce, plaintext)
    otk = _chacha_block(key, 0, nonce)[:32]
    tag = poly1305(_mac_data(ct), otk)
    return nonce + tag + ct  # nonce(12) || tag(16) || ciphertext


def aead_open(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("blob too short")
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    otk = _chacha_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(poly1305(_mac_data(ct), otk), tag):
        raise ValueError("authentication failed")
    return chacha20_xor(key, 1, nonce, ct)


# ------------------------------------------------------------- protocol
def _info(kind: str, part: str, channel: int) -> bytes:
    return f"bdd-{kind}|{part}|{channel}".encode()


def slot_address(secret: bytes, part: str, channel: int) -> str:
    return hkdf(secret, _info("addr", part, channel), 32).hex()


def message_key(secret: bytes, part: str, channel: int) -> bytes:
    return hkdf(secret, _info("key", part, channel), 32)


def seal(secret: bytes, part: str, channel: int, plaintext: bytes) -> bytes:
    return aead_seal(message_key(secret, part, channel), os.urandom(12), plaintext)


def open_blob(secret: bytes, part: str, channel: int, blob: bytes) -> bytes:
    return aead_open(message_key(secret, part, channel), blob)


# ------------------------------------------------------------- transport
class Client:
    def __init__(self, secret, host, port, scheme="http", insecure=False, cafile=None):
        self.secret, self.host, self.port = secret, host, port
        self.scheme, self.insecure, self.cafile = scheme, insecure, cafile

    def _conn(self, timeout):
        if self.scheme == "https":
            ctx = ssl.create_default_context(cafile=self.cafile)
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.host, self.port, context=ctx,
                                               timeout=timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def send(self, part, channel, plaintext) -> int:
        blob = seal(self.secret, part, channel, plaintext)
        addr = slot_address(self.secret, part, channel)
        conn = self._conn(30)
        try:
            conn.request("PUT", f"/v1/slot/{addr}", body=blob)
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def receive(self, part, channel, wait=0):
        addr = slot_address(self.secret, part, channel)
        path = f"/v1/slot/{addr}"
        timeout = 30
        if wait > 0:
            path += f"?wait={int(wait)}"
            timeout = wait + 10
        conn = self._conn(timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                return None
        finally:
            conn.close()
        return open_blob(self.secret, part, channel, body)


# ------------------------------------------------------------------- CLI
def _status(code: int) -> int:
    if code == 201:
        print("ok: stored", file=sys.stderr)
        return 0
    if code == 409:
        print("error: slot already used", file=sys.stderr)
        return 2
    print(f"error: server returned {code}", file=sys.stderr)
    return 1


def _show(plaintext) -> int:
    if plaintext is None:
        print("error: no message", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(plaintext + b"\n")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--scheme", default="http", choices=["http", "https"])
    p.add_argument("--secret", default=os.environ.get("BDD_SECRET", ""))
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--cafile")
    p.add_argument("command", choices=["send-request", "get-request",
                                       "send-response", "get-response",
                                       "wait-response", "reply-upper"])
    p.add_argument("channel", type=int)
    p.add_argument("message", nargs="?", default="")
    args = p.parse_args()

    if len(args.secret) != 64:
        sys.exit("secret must be 64 hex chars (set --secret or BDD_SECRET)")
    client = Client(bytes.fromhex(args.secret), args.host, args.port,
                    args.scheme, args.insecure, args.cafile)

    if args.command == "send-request":
        return _status(client.send("request", args.channel, args.message.encode()))
    if args.command == "send-response":
        return _status(client.send("response", args.channel, args.message.encode()))
    if args.command == "get-request":
        return _show(client.receive("request", args.channel))
    if args.command == "get-response":
        return _show(client.receive("response", args.channel))
    if args.command == "wait-response":
        return _show(client.receive("response", args.channel, wait=30))
    if args.command == "reply-upper":
        # Worker role: wait for a request, process it (uppercase), respond.
        req = client.receive("request", args.channel, wait=30)
        if req is None:
            print("error: no request arrived", file=sys.stderr)
            return 2
        client.send("response", args.channel, req.upper())
        print(f"replied to {req!r}", file=sys.stderr)
        return 0
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
