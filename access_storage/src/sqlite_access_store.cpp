#include "access_storage/sqlite_access_store.hpp"

#include <sqlite3.h>
#include <stdexcept>

namespace access_storage {

static void execOrThrow(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "sqlite error";
        sqlite3_free(err);
        throw std::runtime_error(msg);
    }
}

SqliteAccessStore::SqliteAccessStore(const std::string& path) {
    if (sqlite3_open(path.c_str(), &_db) != SQLITE_OK) {
        throw std::runtime_error("sqlite3_open failed");
    }
    execOrThrow(_db, "PRAGMA foreign_keys=ON;");
}

SqliteAccessStore::~SqliteAccessStore() {
    if (_db) {
        sqlite3_close(_db);
    }
}

void SqliteAccessStore::initSchema() {
    execOrThrow(_db,
                "CREATE TABLE IF NOT EXISTS cards ("
                "  card_hmac TEXT PRIMARY KEY,"
                "  role TEXT NOT NULL"
                ");");
    execOrThrow(_db,
                "CREATE TABLE IF NOT EXISTS door_roles ("
                "  door_id INTEGER NOT NULL,"
                "  role TEXT NOT NULL,"
                "  PRIMARY KEY(door_id, role)"
                ");");
}

void SqliteAccessStore::upsertCardHmac(std::string cardHmacHex, std::string role) {
    const char* sql =
        "INSERT INTO cards(card_hmac, role) VALUES(?,?) "
        "ON CONFLICT(card_hmac) DO UPDATE SET role=excluded.role;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_text(stmt, 1, cardHmacHex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, role.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("upsertCardHmac failed");
    }
    sqlite3_finalize(stmt);
}

void SqliteAccessStore::allowRole(uint32_t doorId, std::string role) {
    const char* sql = "INSERT OR IGNORE INTO door_roles(door_id, role) VALUES(?,?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(doorId));
    sqlite3_bind_text(stmt, 2, role.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("allowRole failed");
    }
    sqlite3_finalize(stmt);
}

std::optional<std::string> SqliteAccessStore::roleForCardHmac(std::string_view cardHmacHex) const {
    const char* sql = "SELECT role FROM cards WHERE card_hmac = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_text(stmt, 1, cardHmacHex.data(), static_cast<int>(cardHmacHex.size()),
                      SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(stmt, 0);
        std::string role = txt ? reinterpret_cast<const char*>(txt) : "";
        sqlite3_finalize(stmt);
        return role;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool SqliteAccessStore::isAllowed(uint32_t doorId, std::string_view role) const {
    const char* sql = "SELECT 1 FROM door_roles WHERE door_id = ? AND role = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(doorId));
    sqlite3_bind_text(stmt, 2, role.data(), static_cast<int>(role.size()), SQLITE_TRANSIENT);

    const int rc = sqlite3_step(stmt);
    const bool allowed = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return allowed;
}

} // namespace access_storage
