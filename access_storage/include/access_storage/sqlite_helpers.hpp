#pragma once

#include <stdexcept>
#include <string>

#include <sqlite3.h>

//! Internal SQLite helper utilities.
namespace access_storage::detail {

//! Executes a SQL statement, throwing on error.
//! @param [in] db  SQLite database handle.
//! @param [in] sql SQL statement to execute.
//! @throws std::runtime_error If execution fails.
inline void execOrThrow(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "sqlite error";
        sqlite3_free(err);
        throw std::runtime_error(msg);
    }
}

//! Prepares a SQL statement, throwing on error.
//! @param [in] db  SQLite database handle.
//! @param [in] sql SQL statement to prepare.
//! @return Prepared statement (caller must finalize).
//! @throws std::runtime_error If preparation fails.
inline sqlite3_stmt* prepareOrThrow(sqlite3* db, const char* sql) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        throw std::runtime_error("sqlite prepare failed");
    }
    return st;
}

//! RAII wrapper for sqlite3_stmt that auto-finalizes.
class StmtGuard {
  public:
    //! Takes ownership of a prepared statement.
    //! @param [in] stmt Statement to manage (may be null).
    explicit StmtGuard(sqlite3_stmt* stmt) : _stmt(stmt) {}

    ~StmtGuard() {
        if (_stmt) {
            sqlite3_finalize(_stmt);
        }
    }

    StmtGuard(const StmtGuard&) = delete;
    StmtGuard& operator=(const StmtGuard&) = delete;

    //! Returns the managed statement.
    sqlite3_stmt* get() const { return _stmt; }

    //! Releases ownership without finalizing.
    //! @return The raw statement pointer.
    sqlite3_stmt* release() {
        auto* tmp = _stmt;
        _stmt = nullptr;
        return tmp;
    }

  private:
    sqlite3_stmt* _stmt;
};

}  // namespace access_storage::detail
