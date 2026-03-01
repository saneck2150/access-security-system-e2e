#pragma once

#include <array>
#include <cstdint>
#include <string>

struct sqlite3;

//! Audit log verification.
namespace access_storage {

//! Size of HMAC-SHA256 hash in bytes.
inline constexpr size_t kVerifyHashSize = 32;

//! Result of audit chain verification.
struct AuditVerifyResult {
    //! True if entire chain is valid.
    bool ok = false;
    //! Row ID where verification failed (-1 if N/A, -2 if anchor mismatch).
    int64_t bad_id = -1;
    //! Human-readable error message.
    std::string error;
};

//! Verifies the cryptographic integrity of the audit log chain.
//! Checks that each entry's prev_hash matches the previous entry_hash,
//! recomputes all entry hashes, and validates against the anchor.
//! @param [in] db      SQLite database handle.
//! @param [in] hmacKey 32-byte HMAC key used for hashing.
//! @return Verification result with ok=true if chain is intact.
AuditVerifyResult verifyAuditChain(sqlite3* db,
                                   const std::array<uint8_t, kVerifyHashSize>& hmacKey);

}  // namespace access_storage
