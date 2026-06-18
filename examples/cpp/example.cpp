// Blind Dead Drop — C++ example client (crypto reimplemented from scratch).
//
// Build:  make           (or: g++ -std=c++17 -O2 example.cpp -o example)
// Usage:
//   ./example --secret HEX [--host H] [--port P] [--scheme http|https]
//             [--insecure] CMD CHANNEL [MSG]
//
// CMD is one of:
//   send-request   CHANNEL MSG     store a request
//   get-request    CHANNEL         read a request (one shot)
//   send-response  CHANNEL MSG     store a response
//   get-response   CHANNEL         read a response (one shot)
//   wait-response  CHANNEL         long-poll until a response appears
//   reply-upper    CHANNEL         worker: wait a request, reply UPPERCASED
//
// The secret may also come from the BDD_SECRET environment variable.
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>

#include "bdd_client.hpp"

using bdd::Bytes;

static Bytes unhex(const std::string& s) {
    if (s.size() != 64) throw std::runtime_error("secret must be 64 hex chars");
    Bytes v;
    for (size_t i = 0; i < s.size(); i += 2)
        v.push_back((uint8_t)std::stoul(s.substr(i, 2), nullptr, 16));
    return v;
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1", scheme = "http", secret_hex, cmd;
    int port = 8080;
    bool insecure = false;
    std::vector<std::string> pos;
    if (const char* env = std::getenv("BDD_SECRET")) secret_hex = env;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--host" && i + 1 < argc) host = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
        else if (a == "--scheme" && i + 1 < argc) scheme = argv[++i];
        else if (a == "--secret" && i + 1 < argc) secret_hex = argv[++i];
        else if (a == "--insecure") insecure = true;
        else pos.push_back(a);
    }
    if (pos.empty() || secret_hex.empty()) {
        std::cerr << "usage: example --secret HEX [--host H --port P "
                     "--scheme http|https --insecure] CMD CHANNEL [MSG]\n";
        return 64;
    }

    Bytes secret = unhex(secret_hex);
    cmd = pos[0];
    int channel = pos.size() > 1 ? std::stoi(pos[1]) : 0;
    std::string msg = pos.size() > 2 ? pos[2] : "";
    Bytes payload(msg.begin(), msg.end());

    bdd::Client client(host, port, scheme, insecure);

    auto do_send = [&](const std::string& part) {
        long s = client.send(secret, part, channel, payload);
        if (s == 201) { std::cerr << "ok: stored\n"; return 0; }
        if (s == 409) { std::cerr << "error: slot already used\n"; return 2; }
        std::cerr << "error: server returned " << s << "\n";
        return 1;
    };
    auto do_recv = [&](const std::string& part, double wait) {
        auto pt = client.receive(secret, part, channel, wait);
        if (!pt) { std::cerr << "error: no message\n"; return 2; }
        std::cout.write(reinterpret_cast<const char*>(pt->data()), pt->size());
        std::cout << "\n";
        return 0;
    };

    if (cmd == "send-request") return do_send("request");
    if (cmd == "send-response") return do_send("response");
    if (cmd == "get-request") return do_recv("request", 0);
    if (cmd == "get-response") return do_recv("response", 0);
    if (cmd == "wait-response") return do_recv("response", 30);
    if (cmd == "reply-upper") {
        // Worker role: wait for a request, process it (uppercase), respond.
        auto req = client.receive(secret, "request", channel, 30);
        if (!req) { std::cerr << "error: no request arrived\n"; return 2; }
        Bytes up = *req;
        for (auto& b : up) b = (uint8_t)std::toupper(b);
        client.send(secret, "response", channel, up);
        std::cerr << "replied to "
                  << std::string(req->begin(), req->end()) << "\n";
        return 0;
    }

    std::cerr << "unknown command: " << cmd << "\n";
    return 64;
}
