# Access Security System

A secure, cryptographically-verified physical access control system for doors and card readers. Hardware layer: ESP32 + MFRC522 over Wi-Fi. Server: C++20, HTTP REST API, SQLite, libsodium.

## Features

- **Dual-algorithm AEAD** — ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305, selectable per deployment profile
- **Three nonce strategies** — random (R0), deterministic HMAC (R1), deterministic + server-side verification (R2)
- **Protocol anomaly detection** — per-reader stateful detector with quarantine (seq reuse, rollback, nonce mismatch, tag-fail streak)
- **Replay attack protection** — sliding window sequence number validation per reader
- **Hash-chained audit log** — tamper-evident audit trail with HMAC chain and anchor for truncation detection
- **Per-reader key isolation** — HKDF derives unique AEAD and nonce keys per reader from a single master secret
- **Key rotation support** — versioned keys, graceful migration without re-enrolling cards
- **Role-based access control** — cards mapped to roles, roles granted per-door access
- **Admin web UI** — real-time event log, card enrollment, reader/door management, audit verification

## Architecture

```
┌──────────────┐  HMAC-signed HTTP   ┌───────────────────────────────────────┐
│  ESP32       │ ──────────────────▶ │              Server                   │
│  + MFRC522   │  uid, reader_id,    │                                       │
│              │  door_id, hw_seq    │  hw_service → build encrypted frame   │
│  hw_seq++    │                     │       │                               │
│  HMAC sign   │                     │       ▼                               │
└──────────────┘                     │  DecisionEngine (access_decision)     │
                                     │    │                                  │
                                     │    ├─ FrameHandler (access_core)      │
                                     │    │    ├─ reader/door binding check  │
                                     │    │    ├─ replay window              │
                                     │    │    └─ AEAD decrypt (A1 or A2)    │
                                     │    │                                  │
                                     │    ├─ ProtocolAnomalyDetector (R2)    │
                                     │    │    ├─ quarantine check           │
                                     │    │    ├─ seq_rollback check         │
                                     │    │    └─ nonce_mismatch check       │
                                     │    │                                  │
                                     │    ├─ HMAC(uid, pepper) lookup        │
                                     │    ├─ RBAC role check                 │
                                     │    └─ tamper-evident audit append     │
                                     │                                       │
                                     │  SQLite  │  Web UI  │  EventBus       │
                                     └───────────────────────────────────────┘
```

## Experimental Profile Matrix

The system supports six security profiles used in the experimental analysis:

|         | **R0** random nonce | **R1** det. nonce | **R2** det. nonce + detector |
|---------|---------------------|-------------------|------------------------------|
| **A1** ChaCha20-Poly1305 | A1-R0 | A1-R1 | A1-R2 |
| **A2** XChaCha20-Poly1305 | A2-R0 | A2-R1 | A2-R2 |

All profiles share the same AAD binding, HKDF key derivation, anti-replay window, pepper, and RBAC. Profiles differ only in cipher algorithm, nonce strategy, and whether the anomaly detector is active.

## Modules

| Module | Description |
|--------|-------------|
| `crypto_lib` | AEAD encryption (A1/A2), HKDF, HMAC-SHA256, nonce generators (R0/R1/R2) |
| `protocol_lib` | Frame serialization, wire format, replay window |
| `key_manager` | Master key loading, HKDF-based key derivation (AEAD, nonce, pepper, audit) |
| `access_core` | Frame validation, decryption, ProtocolAnomalyDetector |
| `access_decision` | DecisionEngine: RBAC policy, card HMAC lookup, audit event logging |
| `access_storage` | SQLite store for readers/cards/roles; hash-chained audit log |
| `config_loader` | YAML configuration parsing |
| `runtime_events` | Thread-safe circular event buffer for real-time UI streaming |
| `access_admin` | HTTP server, REST API, web UI, hardware endpoint |
| `hw_layer` | ESP32/Arduino firmware: card scan, HMAC signing, hw_seq persistence |

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install -y cmake g++ libsqlite3-dev
```

### Build

```bash
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)
```

### Run Tests

```bash
cd build
ctest --output-on-failure
```

### Start Server

```bash
./build/access_admin/access_admin config/access_security.yaml
```

Web UI: `http://localhost:8080/static/index.html`

## Configuration

See [`config/README.md`](config/README.md) and [`config_loader/README.md`](config_loader/README.md). Key parameters:

```yaml
frame_handler:
  anti_replay_enabled: true
  replay_window_size: 256

experiment:
  cipher_mode: "xchacha20"           # A2: XChaCha20-Poly1305 | "chacha20": A1
  nonce_mode: "deterministic"        # R1/R2: HMAC nonce | "random": R0
  aad_mode: "full"                   # bind full header as AAD
  misuse_detection_enabled: true     # R2: ProtocolAnomalyDetector + quarantine
  key_derivation_mode: "hkdf"        # per-reader HKDF keys
  pepper_mode: "versioned"           # per-version card pepper
```

## Security Model

1. **Hardware authentication** — every ESP32 request signed with HMAC-SHA256; `hw_seq` provides per-request freshness
2. **AEAD frame protection** — payload encrypted; full header (including `door_id`) authenticated as AAD
3. **Per-reader key isolation** — HKDF derives unique keys per `reader_id`; one compromised reader does not expose others
4. **Nonce integrity (R2)** — server independently recomputes expected nonce and quarantines reader on mismatch
5. **Replay protection** — sliding window rejects duplicate or rolled-back sequence numbers
6. **Card privacy** — only `HMAC(uid, pepper)` stored; raw UID never persisted
7. **Tamper-evident audit** — HMAC hash chain + anchor; any modification or truncation is detectable

## Development

### Code Formatting

```bash
python3 .dev-tools/clang_run.py
```

### Build with Sanitizers

```bash
cmake -B build-san -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-san -j$(nproc)
cd build-san && ASAN_OPTIONS=detect_leaks=1 ctest --output-on-failure
```

### Docker

```bash
docker build -t access-security .
docker run -d --rm \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/secrets:/app/secrets:ro \
  access-security
```
