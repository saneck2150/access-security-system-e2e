# key_manager

Cryptographic key derivation and management. Derives all keys from a single 256-bit master secret using HKDF-SHA256 (RFC 5869) with strict domain separation.

## Key Derivation Hierarchy

```
master_key.hex (64 hex chars = 32 bytes)
        │
        ▼
  loadMasterKeyHexFile()
        │
        ├─ deriveAeadKey(reader_id, key_version)
        │       salt = reader_id (LE32) || key_version (LE32)
        │       info = "access-aead-v1"
        │       └──► K_aead  ──► ChaCha20/XChaCha20-Poly1305 frame encryption
        │
        ├─ deriveNonceKey(reader_id, key_version)
        │       salt = reader_id (LE32) || key_version (LE32)
        │       info = "nonce-derivation-v1"
        │       └──► K_nonce  ──► HmacNonceGenerator (R1/R2 profiles)
        │
        ├─ deriveCardPepper(key_version)
        │       salt = key_version (LE32)
        │       info = "card-pepper-v1"
        │       └──► pepper  ──► HMAC(uid) before DB storage
        │
        └─ deriveAuditHmacKey()
                salt = "audit-chain-salt-v1"
                info = "audit-hmac-v1"
                └──► K_audit  ──► hash chain integrity in audit log
```

## Domain Separation

Each derived key uses distinct HKDF parameters to ensure cryptographic isolation:

| Key | Salt | Info string | Used by |
|-----|------|-------------|---------|
| `K_aead` | `reader_id \|\| key_ver` | `"access-aead-v1"` | `FrameDecryptor` (frame encryption) |
| `K_nonce` | `reader_id \|\| key_ver` | `"nonce-derivation-v1"` | `HmacNonceGenerator` (R1/R2 nonce) |
| `pepper` | `key_ver` | `"card-pepper-v1"` | `CardIdHasher` (UID → HMAC) |
| `K_audit` | `"audit-chain-salt-v1"` | `"audit-hmac-v1"` | `SqliteAuditLog` (hash chain) |

`K_aead` and `K_nonce` share the same salt but different info strings — comprimising one does not expose the other.

## Per-Reader Key Isolation

Because `reader_id` is part of the salt for AEAD and nonce keys, each reader derives a unique key pair from the same master secret. Compromising one reader's HMAC shared secret does not expose the AEAD keys of any other reader.

## Components

| File | Purpose |
|------|---------|
| `key_manager.hpp/cpp` | `KeyManager` class: derive, version-check, configuration |
| `hex_utils.hpp/cpp` | Hex string parsing (`parseHex<N>`, `hexNibble`) |

## Usage

```cpp
#include <key_manager/key_manager.hpp>

// Load master key from file
auto masterKey = key_manager::loadMasterKeyHexFile("secrets/master_key.hex");

// Configure
key_manager::KeyManagerConfig cfg;
cfg.currentKeyVersion    = 2;
cfg.allowPreviousKeyVersion = true;   // accept v1 during rotation

key_manager::KeyManager km(masterKey, cfg);

// Derive AEAD key for reader 42, key version 2
auto aeadKey  = km.deriveAeadKey(42, 2);

// Derive nonce key for deterministic nonce generation (R1/R2)
auto nonceKey = km.deriveNonceKey(42, 2);

// Derive card pepper for version 2
auto pepper   = km.deriveCardPepper(2);

// Check whether a frame's key_version is acceptable
if (!km.isAcceptedKeyVersion(frame.header.key_version)) {
    // reject: expired or future version
}
```

## Key Version Flow

```
Frame arrives with key_version = N
          │
          ▼
  isAcceptedKeyVersion(N)
          │
     ┌────┴────┐
     │         │
  N == current? │  allowPrevious && N == current-1?
     │         │
   Accept    Accept (rotation window)
                         │
                    else Reject
```

## File Format

`secrets/master_key.hex` — 64 hexadecimal characters (32 bytes), whitespace ignored:
```
a1b2c3d4e5f60718...  (64 chars)
```

Restrict permissions: `chmod 600 secrets/master_key.hex`. The file is excluded from version control via `.gitignore`.

## Security Notes

- **No key caching**: keys are derived on demand; consider a simple cache if per-frame derivation is a bottleneck.
- **Key rotation**: enable `allowPreviousKeyVersion` while rolling out a new version, disable once all readers are updated.
- **Master key storage**: for production use an HSM or secrets manager (e.g., HashiCorp Vault) instead of a plain file.
