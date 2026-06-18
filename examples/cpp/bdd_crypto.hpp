// From-scratch crypto for the Blind Dead Drop, mirroring the server's wire
// format: SHA-256, HMAC-SHA256, HKDF (RFC 5869), ChaCha20 + Poly1305 AEAD
// (RFC 8439).
//
// WARNING: educational, not constant-time, not audited. Matches the server
// byte-for-byte so the examples interoperate; do not use for real secrets.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace bdd {

using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------- SHA-256
class Sha256 {
public:
    Sha256() { reset(); }
    void reset() {
        static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                       0xa54ff53a, 0x510e527f, 0x9b05688c,
                                       0x1f83d9ab, 0x5be0cd19};
        std::memcpy(h_, iv, sizeof(iv));
        len_ = 0;
        buflen_ = 0;
    }
    void update(const uint8_t* p, size_t n) {
        len_ += n;
        while (n) {
            size_t take = 64 - buflen_;
            if (take > n) take = n;
            std::memcpy(buf_ + buflen_, p, take);
            buflen_ += take;
            p += take;
            n -= take;
            if (buflen_ == 64) {
                block(buf_);
                buflen_ = 0;
            }
        }
    }
    void final(uint8_t out[32]) {
        uint64_t bits = len_ * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen_ != 56) update(&zero, 1);
        uint8_t lenbuf[8];
        for (int i = 0; i < 8; i++) lenbuf[i] = (bits >> (56 - 8 * i)) & 0xff;
        update(lenbuf, 8);
        for (int i = 0; i < 8; i++) {
            out[4 * i + 0] = (h_[i] >> 24) & 0xff;
            out[4 * i + 1] = (h_[i] >> 16) & 0xff;
            out[4 * i + 2] = (h_[i] >> 8) & 0xff;
            out[4 * i + 3] = h_[i] & 0xff;
        }
    }

private:
    static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (p[4 * i] << 24) | (p[4 * i + 1] << 16) |
                   (p[4 * i + 2] << 8) | p[4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
    }
    uint32_t h_[8];
    uint64_t len_;
    uint8_t buf_[64];
    size_t buflen_;
};

inline std::array<uint8_t, 32> sha256(const uint8_t* p, size_t n) {
    Sha256 s;
    s.update(p, n);
    std::array<uint8_t, 32> out;
    s.final(out.data());
    return out;
}

// ------------------------------------------------------------- HMAC-SHA256
inline std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t keylen,
                                           const uint8_t* msg, size_t msglen) {
    uint8_t k[64] = {0};
    if (keylen > 64) {
        auto d = sha256(key, keylen);
        std::memcpy(k, d.data(), 32);
    } else {
        std::memcpy(k, key, keylen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    Sha256 inner;
    inner.update(ipad, 64);
    inner.update(msg, msglen);
    uint8_t ih[32];
    inner.final(ih);
    Sha256 outer;
    outer.update(opad, 64);
    outer.update(ih, 32);
    std::array<uint8_t, 32> out;
    outer.final(out.data());
    return out;
}

// -------------------------------------------------------------------- HKDF
inline Bytes hkdf(const uint8_t* ikm, size_t ikmlen, const std::string& info,
                  size_t length) {
    uint8_t salt[32] = {0};
    auto prk = hmac_sha256(salt, 32, ikm, ikmlen);
    Bytes okm;
    Bytes t;
    uint8_t counter = 1;
    while (okm.size() < length) {
        Bytes input(t);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        auto block = hmac_sha256(prk.data(), 32, input.data(), input.size());
        t.assign(block.begin(), block.end());
        okm.insert(okm.end(), t.begin(), t.end());
    }
    okm.resize(length);
    return okm;
}

// ---------------------------------------------------------------- ChaCha20
namespace detail {
inline uint32_t rotl(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }
inline void qr(uint32_t* s, int a, int b, int c, int d) {
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}
inline void chacha_block(const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        s[4 + i] = key[4 * i] | (key[4 * i + 1] << 8) |
                   (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24);
    s[12] = counter;
    for (int i = 0; i < 3; i++)
        s[13 + i] = nonce[4 * i] | (nonce[4 * i + 1] << 8) |
                    (nonce[4 * i + 2] << 16) | (nonce[4 * i + 3] << 24);
    uint32_t w[16];
    std::memcpy(w, s, sizeof(s));
    for (int i = 0; i < 10; i++) {
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13);
        qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12);
        qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = w[i] + s[i];
        out[4 * i + 0] = v & 0xff;
        out[4 * i + 1] = (v >> 8) & 0xff;
        out[4 * i + 2] = (v >> 16) & 0xff;
        out[4 * i + 3] = (v >> 24) & 0xff;
    }
}
}  // namespace detail

inline Bytes chacha20_xor(const uint8_t key[32], uint32_t counter,
                          const uint8_t nonce[12], const uint8_t* data,
                          size_t len) {
    Bytes out(len);
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        detail::chacha_block(key, counter++, nonce, ks);
        size_t n = len - off < 64 ? len - off : 64;
        for (size_t i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
        off += n;
    }
    return out;
}

// ---------------------------------------------------------------- Poly1305
// 32-bit limb implementation (the well-known "donna" layout).
inline std::array<uint8_t, 16> poly1305(const uint8_t* msg, size_t len,
                                        const uint8_t key[32]) {
    auto u32 = [](const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);
    };
    uint32_t t0 = u32(key), t1 = u32(key + 4), t2 = u32(key + 8), t3 = u32(key + 12);
    uint32_t r0 = t0 & 0x3ffffff;
    uint32_t r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    uint32_t r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    uint32_t r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    uint32_t r4 = ((t3 >> 8)) & 0x00fffff;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    uint32_t pad0 = u32(key + 16), pad1 = u32(key + 20),
             pad2 = u32(key + 24), pad3 = u32(key + 28);

    uint8_t block[16];
    size_t off = 0;
    while (off < len) {
        size_t remaining = len - off;
        uint32_t hibit;
        if (remaining >= 16) {
            std::memcpy(block, msg + off, 16);
            hibit = 1u << 24;
            off += 16;
        } else {
            // final partial block: bytes, then a 1 byte, then zeros
            std::memset(block, 0, 16);
            std::memcpy(block, msg + off, remaining);
            block[remaining] = 1;
            hibit = 0;
            off = len;  // exit after this block
        }
        h0 += u32(block) & 0x3ffffff;
        h1 += (u32(block + 3) >> 2) & 0x3ffffff;
        h2 += (u32(block + 6) >> 4) & 0x3ffffff;
        h3 += (u32(block + 9) >> 6) & 0x3ffffff;
        h4 += (u32(block + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
                      (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
                      (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
                      (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
                      (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
                      (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;
    }

    // fully carry h
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    // compute h + -p
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;  // 0 if h<p (keep h), 0xffffffff if h>=p
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    // collapse 26-bit limbs into 32-bit words
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    // mac = (h + pad) mod 2^128
    uint64_t f;
    f = (uint64_t)h0 + pad0; h0 = (uint32_t)f;
    f = (uint64_t)h1 + pad1 + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + pad2 + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + pad3 + (f >> 32); h3 = (uint32_t)f;

    std::array<uint8_t, 16> tag;
    uint32_t words[4] = {h0, h1, h2, h3};
    for (int i = 0; i < 4; i++) {
        tag[4 * i + 0] = words[i] & 0xff;
        tag[4 * i + 1] = (words[i] >> 8) & 0xff;
        tag[4 * i + 2] = (words[i] >> 16) & 0xff;
        tag[4 * i + 3] = (words[i] >> 24) & 0xff;
    }
    return tag;
}

// --------------------------------------------------- ChaCha20-Poly1305 AEAD
namespace detail {
inline void put_le64(Bytes& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((x >> (8 * i)) & 0xff);
}
inline Bytes mac_data(const Bytes& aad, const Bytes& ct) {
    Bytes m = aad;
    while (m.size() % 16) m.push_back(0);
    m.insert(m.end(), ct.begin(), ct.end());
    while (m.size() % 16) m.push_back(0);
    put_le64(m, aad.size());
    put_le64(m, ct.size());
    return m;
}
inline std::array<uint8_t, 32> poly_key(const uint8_t key[32],
                                        const uint8_t nonce[12]) {
    uint8_t ks[64];
    detail::chacha_block(key, 0, nonce, ks);
    std::array<uint8_t, 32> k;
    std::memcpy(k.data(), ks, 32);
    return k;
}
}  // namespace detail

// Returns nonce(12) || tag(16) || ciphertext, matching Protocol::seal.
inline Bytes aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                       const Bytes& plaintext) {
    Bytes ct = chacha20_xor(key, 1, nonce, plaintext.data(), plaintext.size());
    auto otk = detail::poly_key(key, nonce);
    auto md = detail::mac_data(Bytes(), ct);
    auto tag = poly1305(md.data(), md.size(), otk.data());
    Bytes blob(nonce, nonce + 12);
    blob.insert(blob.end(), tag.begin(), tag.end());
    blob.insert(blob.end(), ct.begin(), ct.end());
    return blob;
}

// Parses nonce||tag||ct, verifies, returns plaintext. Throws on tamper.
inline Bytes aead_open(const uint8_t key[32], const Bytes& blob) {
    if (blob.size() < 28) throw std::runtime_error("blob too short");
    const uint8_t* nonce = blob.data();
    const uint8_t* tag = blob.data() + 12;
    Bytes ct(blob.begin() + 28, blob.end());
    auto otk = detail::poly_key(key, nonce);
    auto md = detail::mac_data(Bytes(), ct);
    auto expected = poly1305(md.data(), md.size(), otk.data());
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
    if (diff) throw std::runtime_error("authentication failed");
    return chacha20_xor(key, 1, nonce, ct.data(), ct.size());
}

}  // namespace bdd
