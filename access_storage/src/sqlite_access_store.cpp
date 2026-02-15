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
    execOrThrow(_db,
                "CREATE TABLE IF NOT EXISTS readers ("
                "  reader_id INTEGER PRIMARY KEY,"
                "  current_key_version INTEGER NOT NULL"
                ");");
    execOrThrow(_db,
            "CREATE TABLE IF NOT EXISTS reader_doors ("
            "  reader_id INTEGER NOT NULL,"
            "  door_id   INTEGER NOT NULL,"
            "  PRIMARY KEY(reader_id, door_id),"
            "  FOREIGN KEY(reader_id) REFERENCES readers(reader_id) ON DELETE CASCADE"
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

void SqliteAccessStore::upsertReader(uint32_t reader_id, uint32_t current_key_version) {
    const char* sql =
        "INSERT INTO readers(reader_id, current_key_version) VALUES(?,?) "
        "ON CONFLICT(reader_id) DO UPDATE SET current_key_version=excluded.current_key_version;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK) throw std::runtime_error("prepare failed");
    sqlite3_bind_int(st, 1, static_cast<int>(reader_id));
    sqlite3_bind_int(st, 2, static_cast<int>(current_key_version));

    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        throw std::runtime_error("upsert_reader failed");
    }
    sqlite3_finalize(st);
}

uint32_t SqliteAccessStore::currentKeyVersionForReader(uint32_t reader_id) const {
    const char* sql = "SELECT current_key_version FROM readers WHERE reader_id = ? LIMIT 1;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK) throw std::runtime_error("prepare failed");
    sqlite3_bind_int(st, 1, static_cast<int>(reader_id));

    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const int v = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        if (v <= 0) return 0;
        return static_cast<uint32_t>(v);
    }
    sqlite3_finalize(st);
    return 0;
}

void SqliteAccessStore::allowDoorForReader(uint32_t reader_id, uint32_t door_id) {
    const char* sql = "INSERT OR IGNORE INTO reader_doors(reader_id, door_id) VALUES(?,?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(reader_id));
    sqlite3_bind_int(stmt, 2, static_cast<int>(door_id));

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("allowDoorForReader failed");
    }
    sqlite3_finalize(stmt);
}

bool SqliteAccessStore::isReaderAllowedDoor(uint32_t reader_id, uint32_t door_id) const {
    const char* sql =
        "SELECT 1 FROM reader_doors WHERE reader_id = ? AND door_id = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("prepare failed");
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(reader_id));
    sqlite3_bind_int(stmt, 2, static_cast<int>(door_id));

    const int rc = sqlite3_step(stmt);
    const bool allowed = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return allowed;
}

} // namespace access_storage
