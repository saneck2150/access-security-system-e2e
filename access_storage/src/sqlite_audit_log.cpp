#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <access_storage/serialization.hpp>
#include <access_storage/sqlite_audit_log.hpp>
#include <access_storage/sqlite_helpers.hpp>
#include <crypto_lib/crypto_utils.hpp>
#include <sodium.h>
#include <sqlite3.h>

namespace access_storage {

using detail::execOrThrow;
using detail::prepareOrThrow;
using detail::putBytesWithLen;
using detail::putLe32;
using detail::putLe64;
using detail::StmtGuard;

SqliteAuditLog::SqliteAuditLog(sqlite3* db, Hash32 hmacKey, bool chainEnabled)
    : _db(db), _key(hmacKey), _chainEnabled(chainEnabled) {
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
    execOrThrow(_db,
        "CREATE TABLE IF NOT EXISTS audit_anchor ("
        "  id INTEGER PRIMARY KEY CHECK (id = 1),"
        "  last_hash BLOB NOT NULL,"
        "  updated_ts INTEGER NOT NULL"
        ");");

    execOrThrow(_db,
        "INSERT OR IGNORE INTO audit_anchor(id, last_hash, updated_ts) "
        "VALUES(1, zeroblob(32), 0);");
}

SqliteAuditLog::Hash32 SqliteAuditLog::getLastEntryHash() const {
    const char* sql = "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;";
    StmtGuard guard(prepareOrThrow(_db, sql));

    Hash32 last{};
    const int rc = sqlite3_step(guard.get());
    if (rc == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(guard.get(), 0);
        const int n = sqlite3_column_bytes(guard.get(), 0);
        if (!blob || n != static_cast<int>(kHashSize)) {
            throw std::runtime_error("SqliteAuditLog: bad entry_hash blob");
        }
        std::memcpy(last.data(), blob, kHashSize);
    } else {
        last.fill(0);
    }
    return last;
}

SqliteAuditLog::Hash32 SqliteAuditLog::computeEntryHash(
    const Hash32& prevHash, const access_decision::AuditEvent& e) const {
    std::vector<uint8_t> fields;
    fields.reserve(64 + e.reason.size() + e.card_id.size() + e.action.size());

    // Canonical event bytes (order must remain stable!)
    putLe64(e.ts_unix_ms, fields);
    putLe32(e.reader_id, fields);
    putLe32(e.door_id, fields);
    putLe64(e.seq, fields);
    fields.push_back(static_cast<uint8_t>(e.allow ? 1 : 0));
    putBytesWithLen(e.reason, fields);
    putBytesWithLen(e.card_id, fields);
    putBytesWithLen(e.action, fields);

    // data = prevHash || fields
    std::vector<uint8_t> data;
    data.reserve(kHashSize + fields.size());
    data.insert(data.end(), prevHash.begin(), prevHash.end());
    data.insert(data.end(), fields.begin(), fields.end());

    unsigned char out[kHashSize]{};
    crypto_lib::utils::hmac_sha256(std::span<const uint8_t>(_key.data(), _key.size()),
        std::span<const uint8_t>(data.data(), data.size()),
        out);

    Hash32 h{};
    std::memcpy(h.data(), out, kHashSize);
    return h;
}

void SqliteAuditLog::insertAuditEntry(
    const access_decision::AuditEvent& e, const Hash32& prevHash, const Hash32& entryHash) {
    const char* sql =
        "INSERT INTO audit_log("
        " ts_unix_ms, reader_id, door_id, seq, allow, reason, card_hmac, action, prev_hash, "
        "entry_hash"
        ") VALUES(?,?,?,?,?,?,?,?,?,?);";

    StmtGuard guard(prepareOrThrow(_db, sql));
    auto* st = guard.get();

    sqlite3_bind_int64(st, 1, static_cast<sqlite3_int64>(e.ts_unix_ms));
    sqlite3_bind_int(st, 2, static_cast<int>(e.reader_id));
    sqlite3_bind_int(st, 3, static_cast<int>(e.door_id));
    sqlite3_bind_int64(st, 4, static_cast<sqlite3_int64>(e.seq));
    sqlite3_bind_int(st, 5, e.allow ? 1 : 0);
    sqlite3_bind_text(st, 6, e.reason.c_str(), -1, SQLITE_TRANSIENT);

    if (e.card_id.empty()) {
        sqlite3_bind_null(st, 7);
    } else {
        sqlite3_bind_text(st, 7, e.card_id.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (e.action.empty()) {
        sqlite3_bind_null(st, 8);
    } else {
        sqlite3_bind_text(st, 8, e.action.c_str(), -1, SQLITE_TRANSIENT);
    }

    sqlite3_bind_blob(st, 9, prevHash.data(), static_cast<int>(kHashSize), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 10, entryHash.data(), static_cast<int>(kHashSize), SQLITE_TRANSIENT);

    if (sqlite3_step(st) != SQLITE_DONE) {
        throw std::runtime_error("SqliteAuditLog: insert failed");
    }
}

void SqliteAuditLog::updateAnchor(const Hash32& entryHash, uint64_t ts) {
    const char* sql = "UPDATE audit_anchor SET last_hash = ?, updated_ts = ? WHERE id = 1;";
    StmtGuard guard(prepareOrThrow(_db, sql));
    auto* st = guard.get();

    sqlite3_bind_blob(st, 1, entryHash.data(), static_cast<int>(kHashSize), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, static_cast<sqlite3_int64>(ts));

    if (sqlite3_step(st) != SQLITE_DONE) {
        throw std::runtime_error("SqliteAuditLog: anchor update failed");
    }
}

void SqliteAuditLog::append(access_decision::AuditEvent e) {
    execOrThrow(_db, "BEGIN IMMEDIATE;");

    try {
        if (!_chainEnabled) {
            // Chain disabled: store event without HMAC chaining.
            const Hash32 zeros{};
            insertAuditEntry(e, zeros, zeros);
            execOrThrow(_db, "COMMIT;");
            return;
        }

        const Hash32 prev = getLastEntryHash();
        const Hash32 entry = computeEntryHash(prev, e);

        insertAuditEntry(e, prev, entry);
        updateAnchor(entry, e.ts_unix_ms);

        execOrThrow(_db, "COMMIT;");
    } catch (...) {
        execOrThrow(_db, "ROLLBACK;");
        throw;
    }
}

}  // namespace access_storage
