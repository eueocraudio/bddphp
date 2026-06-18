// Validates the from-scratch crypto against published RFC test vectors.
//   g++ -std=c++17 -O2 selftest.cpp -o selftest && ./selftest
#include <cstdio>
#include <string>

#include "bdd_crypto.hpp"

using bdd::Bytes;

static std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += d[p[i] >> 4];
        s += d[p[i] & 0xf];
    }
    return s;
}
template <size_t N>
static std::string hex(const std::array<uint8_t, N>& a) {
    return hex(a.data(), N);
}
static std::string hex(const Bytes& v) { return hex(v.data(), v.size()); }

static Bytes unhex(const std::string& s) {
    Bytes v;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        v.push_back((uint8_t)std::stoul(s.substr(i, 2), nullptr, 16));
    return v;
}

static int failures = 0;
static void check(const std::string& name, const std::string& got,
                  const std::string& want) {
    if (got == want) {
        std::printf("ok    %s\n", name.c_str());
    } else {
        std::printf("FAIL  %s\n        got  %s\n        want %s\n",
                    name.c_str(), got.c_str(), want.c_str());
        failures++;
    }
}

int main() {
    // SHA-256("abc")
    {
        std::string m = "abc";
        check("sha256(abc)", hex(bdd::sha256((const uint8_t*)m.data(), m.size())),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    // HMAC-SHA256 (RFC 4231 case 1)
    {
        Bytes key(20, 0x0b);
        std::string msg = "Hi There";
        auto t = bdd::hmac_sha256(key.data(), key.size(),
                                  (const uint8_t*)msg.data(), msg.size());
        check("hmac-sha256 rfc4231#1", hex(t),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    // HKDF-SHA256 (RFC 5869 case 3: zero salt, empty info, L=42)
    {
        Bytes ikm(22, 0x0b);
        auto okm = bdd::hkdf(ikm.data(), ikm.size(), "", 42);
        check("hkdf rfc5869#3", hex(okm),
              "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
              "9d201395faa4b61a96c8");
    }
    // ChaCha20 encryption (RFC 8439 2.4.2)
    {
        Bytes key;
        for (int i = 0; i < 32; i++) key.push_back(i);
        Bytes nonce = unhex("000000000000004a00000000");
        std::string pt =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        auto ct = bdd::chacha20_xor(key.data(), 1, nonce.data(),
                                    (const uint8_t*)pt.data(), pt.size());
        check("chacha20 rfc8439 2.4.2 (first 16)",
              hex(ct.data(), 16), "6e2e359a2568f98041ba0728dd0d6981");
    }
    // Poly1305 (RFC 8439 2.5.2)
    {
        Bytes key = unhex("85d6be7857556d337f4452fe42d506a8"
                          "0103808afb0db2fd4abff6af4149f51b");
        std::string m = "Cryptographic Forum Research Group";
        auto tag = bdd::poly1305((const uint8_t*)m.data(), m.size(), key.data());
        check("poly1305 rfc8439 2.5.2", hex(tag),
              "a8061dc1305136c6c22b8baf0c0127a9");
    }
    // ChaCha20-Poly1305 AEAD ciphertext (RFC 8439 2.8.2)
    {
        Bytes key = unhex("808182838485868788898a8b8c8d8e8f"
                          "909192939495969798999a9b9c9d9e9f");
        Bytes nonce = unhex("070000004041424344454647");
        std::string pt =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        Bytes ptb((const uint8_t*)pt.data(),
                  (const uint8_t*)pt.data() + pt.size());
        auto ct = bdd::chacha20_xor(key.data(), 1, nonce.data(), ptb.data(),
                                    ptb.size());
        check("aead ct rfc8439 2.8.2", hex(ct),
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116");
    }
    // AEAD round-trip + tamper (empty AAD, as the protocol uses)
    {
        Bytes key(32, 7);
        Bytes nonce(12, 9);
        Bytes pt = unhex("deadbeefcafe");
        auto blob = bdd::aead_seal(key.data(), nonce.data(), pt);
        auto back = bdd::aead_open(key.data(), blob);
        check("aead roundtrip", hex(back), hex(pt));
        blob[28] ^= 1;
        bool threw = false;
        try { bdd::aead_open(key.data(), blob); } catch (...) { threw = true; }
        check("aead tamper detected", threw ? "yes" : "no", "yes");
    }

    std::printf(failures ? "\n%d FAILURE(S)\n" : "\nall vectors pass\n",
                failures);
    return failures ? 1 : 0;
}
