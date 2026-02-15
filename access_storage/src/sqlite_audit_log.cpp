#include <access_storage/sqlite_audit_log.hpp>

#include <crypto_lib/crypto_utils.hpp>

#include <sqlite3.h>
#include <sodium.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace access_storage {

static void execOrThrow(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "sqlite error";
        sqlite3_free(err);
        throw std::runtime_error(msg);
    }
}

SqliteAuditLog::SqliteAuditLog(sqlite3* db, Hash32 hmacKey)
    : _db(db), _key(hmacKey) {
    if (!_db) {
        throw std::invalid_argument("SqliteAuditLog: db is null");
    }
    initSchema();
}

void SqliteAuditLog::initSchema() {
    execOrThrow(_db,
        "CREATE TABLE IF NOT EXISTS audit_log ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  ts_unix_ms INTEGER NOT NULL,"
        "  reader_id INTEGER NOT NULL,"
        "  door_id INTEGER NOT NULL,"
        "  seq INTEGER NOT NULL,"
        "  allow INTEGER NOT NULL,"
        "  reason TEXT NOT NULL,"
        "  card_hmac TEXT,"
        "  action TEXT,"
        "  prev_hash BLOB NOT NULL,"
        "  entry_hash BLOB NOT NULL"
        ");");

    execOrThrow(_db, "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts_unix_ms);");
    execOrThrow(_db, "CREATE INDEX IF NOT EXISTS idx_audit_reader ON audit_log(reader_id);");
}

void SqliteAuditLog::putLe32(uint32_t v, std::vector<uint8_t>& out) {
    out.push_back(static_cast<uint8_t>( v        & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8 ) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

void SqliteAuditLog::putLe64(uint64_t v, std::vector<uint8_t>& out) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    }
}

void SqliteAuditLog::putBytesWithLen(std::string_view s, std::vector<uint8_t>& out) {
    putLe32(static_cast<uint32_t>(s.size()), out);
    out.insert(out.end(), s.begin(), s.end());
}

SqliteAuditLog::Hash32 SqliteAuditLog::getLastEntryHash() const {
    const char* sql = "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;";
    sqlite3_stmt* st = nullptr;

    if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK) {
        throw std::runtime_error("SqliteAuditLog: prepare failed");
    }

    Hash32 last{};
    const int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(st, 0);
        const int n = sqlite3_column_bytes(st, 0);
        if (!blob || n != 32) {
            sqlite3_finalize(st);
            throw std::runtime_error("SqliteAuditLog: bad entry_hash blob");
        }
        std::memcpy(last.data(), blob, 32);
    } else {
        // no rows -> zeros
        last.fill(0);
    }

    sqlite3_finalize(st);
    return last;
}

SqliteAuditLog::Hash32 SqliteAuditLog::computeEntryHash(const Hash32& prevHash,
                                                        const access_decision::AuditEvent& e) const {
    std::vector<uint8_t> fields;
    fields.reserve(64 + e.reason.size() + e.card_id.size() + e.action.size());

    // Canonical event bytes (keep order stable!)
    putLe64(e.ts_unix_ms, fields);
    putLe32(e.reader_id, fields);
    putLe32(e.door_id, fields);
    putLe64(e.seq, fields);
    fields.push_back(static_cast<uint8_t>(e.allow ? 1 : 0));
    putBytesWithLen(e.reason, fields);
    putBytesWithLen(e.card_id, fields); // you store card_hmac here already
    putBytesWithLen(e.action, fields);

    // data = prevHash || fields
    std::vector<uint8_t> data;
    data.reserve(32 + fields.size());
    data.insert(data.end(), prevHash.begin(), prevHash.end());
    data.insert(data.end(), fields.begin(), fields.end());

    unsigned char out[32]{};
    crypto_lib::utils::hmac_sha256(
        std::span<const uint8_t>(_key.data(), _key.size()),
        std::span<const uint8_t>(data.data(), data.size()),
        out);

    Hash32 h{};
    std::memcpy(h.data(), out, 32);
    return h;
}

///@todo split
void SqliteAuditLog::append(access_decision::AuditEvent e) {
    // Make it atomic (avoid races if later you add concurrency)
    execOrThrow(_db, "BEGIN IMMEDIATE;");

    try {
        const Hash32 prev = getLastEntryHash();
        const Hash32 entry = computeEntryHash(prev, e);

        const char* sql =
            "INSERT INTO audit_log("
            " ts_unix_ms, reader_id, door_id, seq, allow, reason, card_hmac, action, prev_hash, entry_hash"
            ") VALUES(?,?,?,?,?,?,?,?,?,?);";

        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(_db, sql, -1, &st, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SqliteAuditLog: prepare insert failed");
        }

        sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(e.ts_unix_ms));
        sqlite3_bind_int(st,   2, static_cast<int>(e.reader_id));
        sqlite3_bind_int(st,   3, static_cast<int>(e.door_id));
        sqlite3_bind_int64(st, 4, static_cast<sqlite3_int64>(e.seq));
        sqlite3_bind_int(st,   5, e.allow ? 1 : 0);
        sqlite3_bind_text(st,  6, e.reason.c_str(), -1, SQLITE_TRANSIENT);

        if (e.card_id.empty()) sqlite3_bind_null(st, 7);
        else sqlite3_bind_text(st, 7, e.card_id.c_str(), -1, SQLITE_TRANSIENT);

        if (e.action.empty()) sqlite3_bind_null(st, 8);
        else sqlite3_bind_text(st, 8, e.action.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_bind_blob(st, 9, prev.data(), 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st,10, entry.data(), 32, SQLITE_TRANSIENT);

        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            throw std::runtime_error("SqliteAuditLog: insert failed");
        }

        sqlite3_finalize(st);
        execOrThrow(_db, "COMMIT;");
    } catch (...) {
        execOrThrow(_db, "ROLLBACK;");
        throw;
    }
}

} // namespace access_storage
