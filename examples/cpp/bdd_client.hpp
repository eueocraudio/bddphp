// Blind Dead Drop client: protocol (address/key/seal/open) + HTTP transport.
//
// Transport shells out to the `curl` CLI because this example carries no
// libcurl/OpenSSL link. A production client would link libcurl directly; the
// crypto and protocol below are unaffected. The scheme defaults to http (the
// bddphp dev server is plain HTTP behind a proxy/Tor); pass https for a TLS
// front.
#pragma once
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

#include "bdd_crypto.hpp"

namespace bdd {

inline std::string to_hex(const Bytes& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) {
        s += d[b >> 4];
        s += d[b & 0xf];
    }
    return s;
}

// ---- protocol (mirrors src/Protocol.php) -------------------------------
inline std::string slot_address(const Bytes& secret, const std::string& part,
                                int channel) {
    std::string info = "bdd-addr|" + part + "|" + std::to_string(channel);
    return to_hex(hkdf(secret.data(), secret.size(), info, 32));
}
inline Bytes message_key(const Bytes& secret, const std::string& part,
                         int channel) {
    std::string info = "bdd-key|" + part + "|" + std::to_string(channel);
    return hkdf(secret.data(), secret.size(), info, 32);
}
inline Bytes random_bytes(size_t n) {
    Bytes v(n);
    std::ifstream f("/dev/urandom", std::ios::binary);
    f.read(reinterpret_cast<char*>(v.data()), n);
    if (!f) throw std::runtime_error("cannot read /dev/urandom");
    return v;
}
inline Bytes seal(const Bytes& secret, const std::string& part, int channel,
                  const Bytes& plaintext) {
    Bytes key = message_key(secret, part, channel);
    Bytes nonce = random_bytes(12);
    return aead_seal(key.data(), nonce.data(), plaintext);
}
inline Bytes open_blob(const Bytes& secret, const std::string& part, int channel,
                       const Bytes& blob) {
    Bytes key = message_key(secret, part, channel);
    return aead_open(key.data(), blob);
}

// ---- transport via the curl CLI ----------------------------------------
struct HttpResult {
    long status;
    Bytes body;
};

class TempFile {
public:
    TempFile() {
        char tmpl[] = "/tmp/bdd_XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd < 0) throw std::runtime_error("mkstemp failed");
        ::close(fd);
        path_ = tmpl;
    }
    ~TempFile() { std::remove(path_.c_str()); }
    const std::string& path() const { return path_; }

private:
    std::string path_;
};

class Client {
public:
    Client(std::string host, int port, std::string scheme = "http",
           bool insecure = false, std::string cafile = "")
        : host_(std::move(host)),
          port_(port),
          scheme_(std::move(scheme)),
          insecure_(insecure),
          cafile_(std::move(cafile)) {}

    // Returns 201 created / 409 already used.
    long send(const Bytes& secret, const std::string& part, int channel,
              const Bytes& plaintext) {
        Bytes blob = seal(secret, part, channel, plaintext);
        std::string addr = slot_address(secret, part, channel);
        auto r = request("PUT", "/v1/slot/" + addr, &blob, 30);
        return r.status;
    }

    // wait > 0 enables the server long poll (?wait=N).
    std::optional<Bytes> receive(const Bytes& secret, const std::string& part,
                                 int channel, double wait = 0) {
        std::string addr = slot_address(secret, part, channel);
        std::string path = "/v1/slot/" + addr;
        double maxtime = 30;
        if (wait > 0) {
            path += "?wait=" + std::to_string((int)wait);
            maxtime = wait + 10;
        }
        auto r = request("GET", path, nullptr, maxtime);
        if (r.status != 200) return std::nullopt;
        return open_blob(secret, part, channel, r.body);
    }

private:
    HttpResult request(const std::string& method, const std::string& path,
                       const Bytes* body, double maxtime) {
        TempFile out;
        std::ostringstream cmd;
        cmd << "curl -s -X " << method;
        if (scheme_ == "https") {
            if (insecure_)
                cmd << " -k";
            else if (!cafile_.empty())
                cmd << " --cacert " << cafile_;
        }
        cmd << " --max-time " << (int)maxtime;
        TempFile bodyfile;
        if (body) {
            std::ofstream bf(bodyfile.path(), std::ios::binary);
            bf.write(reinterpret_cast<const char*>(body->data()), body->size());
            bf.close();
            cmd << " --data-binary @" << bodyfile.path()
                << " -H 'Content-Type: application/octet-stream'";
        }
        cmd << " -o " << out.path() << " -w '%{http_code}'"
            << " '" << scheme_ << "://" << host_ << ":" << port_ << path << "'";

        std::string code = run(cmd.str());
        HttpResult r;
        r.status = code.empty() ? 0 : std::stol(code);
        std::ifstream in(out.path(), std::ios::binary);
        r.body.assign(std::istreambuf_iterator<char>(in),
                      std::istreambuf_iterator<char>());
        return r;
    }

    static std::string run(const std::string& cmd) {
        std::string out;
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) throw std::runtime_error("popen failed");
        char buf[256];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
        pclose(p);
        return out;
    }

    std::string host_;
    int port_;
    std::string scheme_;
    bool insecure_;
    std::string cafile_;
};

}  // namespace bdd
