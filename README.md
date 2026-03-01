# Access Security System

A secure, cryptographically-verified physical access control system for doors and readers. Designed for embedded hardware (ESP32/Arduino) with a centralized admin server.

## Features

- **End-to-end encryption** – AES-256-GCM authenticated encryption for reader-to-server frames
- **Replay attack protection** – Sliding window sequence number validation
- **Hash-chained audit log** – Tamper-evident audit trail with HMAC verification
- **Key rotation support** – Graceful migration between key versions
- **Role-based access control** – Cards mapped to roles, roles granted per-door access
- **Admin web UI** – Real-time event log, card enrollment, reader management

## Architecture

```
┌──────────────┐      encrypted frame      ┌──────────────────────────────┐
│   Reader     │ ─────────────────────────▶│        Server                │
│  (ESP32)     │                           │                              │
│              │                           │  ┌─────────┐  ┌───────────┐  │
│  Card Scan   │                           │  │ Frame   │  │ Decision  │  │
│      ↓       │                           │  │ Handler │─▶│ Engine    │  │
│  Build Frame │                           │  └─────────┘  └───────────┘  │
│  AES-GCM     │                           │       │             │        │
└──────────────┘                           │       ▼             ▼        │
                                           │  ┌─────────┐  ┌───────────┐  │
                                           │  │ Replay  │  │  Access   │  │
                                           │  │ Window  │  │  Store    │  │
                                           │  └─────────┘  └───────────┘  │
                                           │                     │        │
                                           │                     ▼        │
                                           │              ┌───────────┐   │
                                           │              │ Audit Log │   │
                                           │              │ (chained) │   │
                                           │              └───────────┘   │
                                           └──────────────────────────────┘
```

## Modules

| Module | Description |
|--------|-------------|
| `protocol_lib` | Frame serialization, packet headers, replay window |
| `crypto_lib` | AES-GCM AEAD encryption, key derivation |
| `key_manager` | Master key storage, per-reader key derivation |
| `access_core` | Frame decryption and validation |
| `access_decision` | Policy engine, card HMAC lookup, access decisions |
| `access_storage` | SQLite store for readers, cards, roles, audit log |
| `access_admin` | HTTP admin server with REST API and web UI |
| `config_loader` | YAML configuration parsing |
| `runtime_events` | Real-time event bus for UI streaming |
| `hw_layer` | Arduino/ESP32 firmware for card readers |

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install -y cmake g++ libsqlite3-dev python3

# Optional: SQLite browser for inspecting the database
sudo apt-get install -y sqlitebrowser
```

### Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Run Tests

```bash
cd build
ctest --output-on-failure
```

### Start Admin Server

```bash
cd build
./access_admin/access_admin ../config/access_security.yaml
```

Open http://localhost:8080 in your browser.

## Configuration

See [config/README.md](config/README.md) for YAML configuration options.

## Security Model

1. **Card IDs are never stored** – Only HMAC(card_id, pepper) is stored
2. **Per-reader keys** – Each reader has unique AEAD keys derived from master
3. **Sequence numbers** – Prevent replay of captured frames
4. **Audit chain** – Each log entry includes HMAC of previous entry
5. **Key versioning** – Rotate keys without invalidating all cards

## Development

### Code Formatting

```bash
python3 .dev-tools/clang_run.py
```

### Docker

```bash
# Build container with all dependencies
docker build -t access-security .
```

## License

Proprietary – All rights reserved.