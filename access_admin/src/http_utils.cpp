#include "access_admin/http_utils.hpp"

#include <cctype>
#include <stdexcept>

namespace admin {

uint64_t nowUnixMs() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void sodiumInitOrThrow() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

void setJson(httplib::Response& res, const json& j, int status) {
    res.status = status;
    res.set_content(j.dump(2), "application/json");
}

bool checkAuth(const httplib::Request& req, const std::string& token) {
    if (token.empty()) {
        return true;
    }
    return req.get_header_value("X-Admin-Token") == token;
}

std::vector<uint8_t> hexToBytes(std::string_view hex) {
    std::string s;
    s.reserve(hex.size());
    for (char c : hex) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            s.push_back(c);
        }
    }
    if (s.size() % 2 != 0) {
        throw std::runtime_error("hex odd length");
    }

    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hexNibble(s[i]) << 4) | hexNibble(s[i + 1])));
    }
    return out;
}

uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + (c - 'a'));
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + (c - 'A'));
    }
    throw std::runtime_error("invalid hex char");
}

std::string bytesToHex(const std::vector<uint8_t>& v) {
    std::string out;
    out.resize(v.size() * 2);
    for (size_t i = 0; i < v.size(); ++i) {
        out[i * 2 + 0] = kHexChars[(v[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexChars[(v[i] >> 0) & 0x0F];
    }
    return out;
}

bool sqliteIntegrityOk(const std::string& path, std::string& err) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        err = "sqlite_open failed";
        if (db) {
            sqlite3_close(db);
        }
        return false;
    }

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, kIntegrityCheckSql, -1, &st, nullptr) != SQLITE_OK) {
        err = "prepare integrity_check failed";
        sqlite3_close(db);
        return false;
    }

    bool ok = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(st, 0);
        std::string v = txt ? reinterpret_cast<const char*>(txt) : "";
        ok = (v == "ok");
        if (!ok) {
            err = "integrity_check: " + v;
        }
    } else {
        err = "integrity_check: no row";
    }

    sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

}  // namespace admin
