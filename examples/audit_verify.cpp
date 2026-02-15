#include <access_storage/audit_verify.hpp>
#include <key_manager/key_manager.hpp>

#include <sqlite3.h>
#include <sodium.h>

#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: audit_verify <db_path> <master_key_hex_path>\n";
        return 2;
    }

    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 2;
    }

    const std::string dbPath = argv[1];
    const std::string masterPath = argv[2];

    try {
        const auto mk = key_manager::KeyManager::loadMasterKeyHexFile(masterPath);
        key_manager::KeyManager km(mk);
        const auto auditKey = km.deriveAuditHmacKey();

        sqlite3* db = nullptr;
        if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
            std::cerr << "sqlite3_open failed\n";
            return 2;
        }

        const auto r = access_storage::verifyAuditChain(db, auditKey);
        sqlite3_close(db);

        if (!r.ok) {
            std::cerr << "AUDIT VERIFY FAILED at id=" << r.bad_id << " error=" << r.error << "\n";
            return 1;
        }

        std::cout << "AUDIT VERIFY OK\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
