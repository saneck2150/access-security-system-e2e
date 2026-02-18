#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <sodium.h>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace admin {

using json = nlohmann::json;

inline uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

inline void sodiumInitOrThrow() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

inline void setJson(httplib::Response& res, const json& j, int status = 200) {
    res.status = status;
    res.set_content(j.dump(2), "application/json");
}

inline bool checkAuth(const httplib::Request& req, const std::string& token) {
    if (token.empty()) return true;
    return req.get_header_value("X-Admin-Token") == token;
}

inline std::vector<uint8_t> hexToBytes(std::string_view hex) {
    auto hexNibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return uint8_t(c - '0');
        if (c >= 'a' && c <= 'f') return uint8_t(10 + (c - 'a'));
        if (c >= 'A' && c <= 'F') return uint8_t(10 + (c - 'A'));
        throw std::runtime_error("invalid hex char");
    };

    std::string s;
    s.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) s.push_back(c);
    }
    if (s.size() % 2 != 0) throw std::runtime_error("hex odd length");

    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back(uint8_t((hexNibble(s[i]) << 4) | hexNibble(s[i + 1])));
    }
    return out;
}

inline bool sqliteIntegrityOk(const std::string& path, std::string& err) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        err = "sqlite_open failed";
        if (db) sqlite3_close(db);
        return false;
    }

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check;", -1, &st, nullptr) != SQLITE_OK) {
        err = "prepare integrity_check failed";
        sqlite3_close(db);
        return false;
    }

    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(st, 0);
        std::string v = txt ? reinterpret_cast<const char*>(txt) : "";
        ok = (v == "ok");
        if (!ok) err = "integrity_check: " + v;
    } else {
        err = "integrity_check: no row";
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

} // namespace admin
