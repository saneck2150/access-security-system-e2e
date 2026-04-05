# crypto_lib

Core cryptographic primitives used throughout the access-security system. All operations delegate to **libsodium 1.0.20** — an audited, constant-time cryptographic library.

## Components

| Header | Namespace | Purpose |
|--------|-----------|---------|
| `crypto_utils.hpp` | `crypto_lib::utils` | Low-level helpers: HMAC-SHA256, little-endian encoding |
| `hkdf.hpp` | `crypto_lib::hkdf` | HKDF key derivation (RFC 5869) |
| `secure_aead.hpp` | `crypto_lib::aead` | AEAD encryption (ChaCha20-Poly1305 and XChaCha20-Poly1305) |
| `nonce_generator.hpp` | `crypto_lib::nonce` | Nonce generation strategies (random and deterministic HMAC) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           crypto_lib                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌───────────┐  │
│  │ crypto_utils │  │     hkdf     │  │ secure_aead│  │  nonce_   │  │
│  ├──────────────┤  ├──────────────┤  ├────────────┤  │ generator │  │
│  │ hmac_sha256  │◄─│    Hkdf      │  │ SecureAead │  ├───────────┤  │
│  │ le32/le64    │  │  - extract   │  │ - seal     │  │ Random-   │  │
│  └──────────────┘  │  - expand    │  │ - open     │  │ Nonce-    │  │
│                    └──────────────┘  └────────────┘  │ Generator │  │
│                                                       │ HmacNonce-│  │
│                                                       │ Generator │  │
│                                                       └───────────┘  │
├──────────────────────────────────────────────────────────────────────┤
│                            libsodium                                 │
│  crypto_auth_hmacsha256_*  │  crypto_aead_chacha20poly1305_ietf_*    │
│  crypto_kdf_hkdf_sha256_*  │  crypto_aead_xchacha20poly1305_ietf_*  │
└──────────────────────────────────────────────────────────────────────┘
```

## AEAD Algorithms

The module supports two AEAD algorithms from the ChaCha20-Poly1305 family. Both use a 256-bit key and a 128-bit Poly1305 authentication tag; they differ in nonce size:

| Profile | Algorithm | Nonce size | Libsodium function |
|---------|-----------|------------|-------------------|
| A1 | ChaCha20-Poly1305 (IETF, RFC 8439) | 12 bytes | `crypto_aead_chacha20poly1305_ietf_*` |
| A2 | XChaCha20-Poly1305 | 24 bytes | `crypto_aead_xchacha20poly1305_ietf_*` |

`SecureAead` is constructed with a `CipherMode` enum selecting the algorithm:

```cpp
crypto_lib::aead::SecureAead aead(key, crypto_lib::aead::CipherMode::XChaCha20Poly1305);
auto ct = aead.seal(plaintext, aad, nonce);
auto pt = aead.open(ciphertext, aad, nonce);
```

**Wire format (frame ciphertext field):**
```
┌────────────────┬──────────────────────┐
│  Ciphertext    │   Poly1305 Tag       │
│  (N bytes)     │   (16 bytes)         │
└────────────────┴──────────────────────┘
```
The nonce is stored separately in the frame header, not appended to the ciphertext.

## Nonce Generation

The interface `INonceGenerator` abstracts nonce generation strategy. Two concrete implementations exist, corresponding to profiles R0, R1, and R2:

### RandomNonceGenerator (R0)

Generates a cryptographically random nonce via `randombytes_buf()`:

```
nonce_R0 = randombytes_buf(n)   where n ∈ {12, 24}
```

Nonce uniqueness depends on RNG quality. Safe collision probability:
- A2 (24-byte nonce): negligible up to ~2⁹⁶ messages
- A1 (12-byte nonce): safe up to ~2⁴⁸ messages

### HmacNonceGenerator (R1 and R2)

Derives the nonce deterministically from the frame header context using HMAC-SHA256:

```
nonce_R1/R2 = HMAC-SHA256(K_nonce, header_context)[:n]
```

where `header_context` is the serialized 52-byte header with the nonce field zeroed, and `K_nonce` is a per-reader key derived via HKDF with `info = "nonce-derivation-v1"`.

**Properties:**
- Eliminates dependence on RNG quality
- Nonce repeats only if the entire context (reader, door, seq, ts, key_version) repeats — prevented by the anti-replay mechanism
- R1 uses this generator without server-side verification; R2 adds verification in `ProtocolAnomalyDetector`

## HKDF Key Derivation

Implements RFC 5869 HKDF using HMAC-SHA256 (extract + expand):

```
IKM (master key) ──► Extract(salt) ──► PRK ──► Expand(info, length) ──► OKM
```

Used by `key_manager` to derive purpose-specific keys. The `info` string provides domain separation between key types.

## Security Properties

| Property | Implementation |
|----------|----------------|
| Key size | 256-bit (32 bytes) |
| Auth tag | 128-bit Poly1305 (16 bytes) |
| Nonce uniqueness | Random (R0) or deterministic HMAC (R1/R2) |
| Constant-time comparison | `sodium_memcmp()` for tag verification |
| Side channels | libsodium constant-time primitives throughout |
| Auth failure | Returns error; no partial plaintext is ever exposed |

## Dependencies

- **libsodium 1.0.20**: all cryptographic operations (compiled from source in `third_party/sodium/`)

## Tests

```bash
cd build && ctest -R "aead_roundtrip|hkdf" -V
```

| Test | Description |
|------|-------------|
| `aead_roundtrip_test` | Encrypt/decrypt cycle for both algorithms, AAD tampering detection |
| `hkdf_test` | RFC 5869 test vectors, determinism check |