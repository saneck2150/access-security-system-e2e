#include "access_storage/sqlite_access_store.hpp"

#include <sqlite3.h>
#include <stdexcept>

namespace access_storage {

static void exec_or_throw(sqlite3* db, const char* sql) {
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
    exec_or_throw(_db, "PRAGMA foreign_keys=ON;");
}

SqliteAccessStore::~SqliteAccessStore() {
    if (_db)
        sqlite3_close(_db);
}

void SqliteAccessStore::init_schema() {
    exec_or_throw(_db,
                  "CREATE TABLE IF NOT EXISTS cards ("
                  "  card_hmac TEXT PRIMARY KEY,"
                  "  role TEXT NOT NULL"
                  ");");
    exec_or_throw(_db,
                  "CREATE TABLE IF NOT EXISTS door_roles ("
                  "  door_id INTEGER NOT NULL,"
                  "  role TEXT NOT NULL,"
                  "  PRIMARY KEY(door_id, role)"
                  ");");
}

void SqliteAccessStore::upsert_card_hmac(std::string card_hmac_hex, std::string role) {
    const char* sql =
        "INSERT INTO cards(card_hmac, role) VALUES(?,?) "
        "ON CONFLICT(card_hmac) DO UPDATE SET role=excluded.role;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK)
        throw std::runtime_error("prepare failed");
    sqlite3_bind_text(st, 1, card_hmac_hex.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, role.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        throw std::runtime_error("upsert_card_hmac failed");
    }
    sqlite3_finalize(st);
}

void SqliteAccessStore::allow_role(uint32_t door_id, std::string role) {
    const char* sql = "INSERT OR IGNORE INTO door_roles(door_id, role) VALUES(?,?);";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK)
        throw std::runtime_error("prepare failed");
    sqlite3_bind_int(st, 1, static_cast<int>(door_id));
    sqlite3_bind_text(st, 2, role.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        throw std::runtime_error("allow_role failed");
    }
    sqlite3_finalize(st);
}

std::optional<std::string> SqliteAccessStore::role_for_card_hmac(
    std::string_view card_hmac_hex) const {
    const char* sql = "SELECT role FROM cards WHERE card_hmac = ? LIMIT 1;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK)
        throw std::runtime_error("prepare failed");
    sqlite3_bind_text(st, 1, card_hmac_hex.data(), static_cast<int>(card_hmac_hex.size()),
                      SQLITE_TRANSIENT);

    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const unsigned char* txt = sqlite3_column_text(st, 0);
        std::string role = txt ? reinterpret_cast<const char*>(txt) : "";
        sqlite3_finalize(st);
        return role;
    }
    sqlite3_finalize(st);
    return std::nullopt;
}

bool SqliteAccessStore::is_allowed(uint32_t door_id, std::string_view role) const {
    const char* sql = "SELECT 1 FROM door_roles WHERE door_id = ? AND role = ? LIMIT 1;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK)
        throw std::runtime_error("prepare failed");
    sqlite3_bind_int(st, 1, static_cast<int>(door_id));
    sqlite3_bind_text(st, 2, role.data(), static_cast<int>(role.size()), SQLITE_TRANSIENT);

    const int rc = sqlite3_step(st);
    const bool ok = (rc == SQLITE_ROW);
    sqlite3_finalize(st);
    return ok;
}

}  // namespace access_storage
