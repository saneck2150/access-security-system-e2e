# access_core

Frame validation, decryption, and protocol anomaly detection. This module sits between `protocol_lib` (parsing) and `access_decision` (policy) and is responsible for all cryptographic and structural checks before a frame reaches the decision engine.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          FrameHandler                                │
├──────────────────────────────────────────────────────────────────────┤
│  handle(frameBytes)                                                  │
│       │                                                              │
│       ├─ parseFrame()               → Parse binary frame            │
│       ├─ isReaderAllowedDoor()      → Check reader-door binding      │
│       ├─ currentKeyVersionForReader()→ Validate key version          │
│       ├─ isReplay()                 → Sliding window check           │
│       └─ FrameDecryptor                                              │
│              ├─ AEAD decrypt with full header as AAD                 │
│              └─ Timestamp validation (optional, maxSkewMs)           │
│                                                                      │
│       ▼                                                              │
│  HandleResult { allow, reason, plaintext, header }                   │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                    ProtocolAnomalyDetector                           │
│    (standalone R2 component — used by DecisionEngine, not here)      │
├──────────────────────────────────────────────────────────────────────┤
│  isQuarantined() / reportReplay() / reportSeq()                      │
│  reportNonceMismatch() / reportTagFailure() / reportSuccess()        │
│  → quarantines reader on anomaly detection                           │
└──────────────────────────────────────────────────────────────────────┘
```

`FrameHandler` performs cryptographic validation only. `ProtocolAnomalyDetector` is a separate stateful class instantiated by `DecisionEngine` — the engine calls it before and after `FrameHandler.handle()` to implement R2 profile behaviour.

## Components

### FrameHandler (`handle_frame.hpp`)

Main entry point. Orchestrates all validation steps in order: parse → reader check → key version → replay → decrypt.

```cpp
FrameHandler handler(keyManager, replayWindows, &store, config);
auto result = handler.handle(frameBytes);
if (result.allow) {
    // result.plaintext contains decrypted JSON payload
}
```

**Configuration options (`FrameHandlerConfig`):**

| Option | Default | Description |
|--------|---------|-------------|
| `antiReplayEnabled` | `true` | Enable replay attack detection |
| `replayWindowSize` | `256` | Sliding window capacity |
| `maxCtLen` | `4096` | Maximum ciphertext length (DoS protection) |
| `maxSkewMs` | `0` | Max timestamp skew in ms (0 = disabled) |
| `allowPreviousKeyVersion` | `true` | Accept previous key version during rotation |
| `enforceReaderDoorBinding` | `true` | Verify reader is authorized for this door |
| `keyDerivationMode` | `"hkdf"` | `"hkdf"` = per-reader HKDF; `"direct"` = master key as AEAD key |
| `aadMode` | `"full"` | `"full"` = serialize header as AAD; `"none"` = empty AAD |
| `pepperMode` | `"versioned"` | `"versioned"` = HKDF per key version; `"static"` = fixed v1 |
| `cipherMode` | `"xchacha20"` | `"xchacha20"` = XChaCha20-Poly1305; `"chacha20"` = ChaCha20-Poly1305 |
| `nonceMode` | `"deterministic"` | `"deterministic"` = HMAC-based (R1/R2); `"random"` = randombytes (R0) |

### FrameDecryptor (`frame_decryptor.hpp`)

Low-level AEAD decryption. The entire serialized header (reader_id, door_id, ts, seq, key_version, nonce) is passed as AAD — any modification to any header field causes tag verification to fail.

```cpp
FrameDecryptor decryptor(aead, DecryptorConfig{.maxSkewMs = 60000, .aadMode = "full"});
auto result = decryptor.decrypt(frame);
```

### ProtocolAnomalyDetector (`protocol_anomaly_detector.hpp`)

Stateful per-reader behaviour monitor. Active only in R2 profiles (`enabled = true`). Tracks four anomaly types and quarantines the reader on detection:

| Anomaly | Detection condition | Response |
|---------|--------------------|---------:|
| `seq_reuse` | replay detected by `ReplayWindow` | Immediate quarantine |
| `seq_rollback` | `seq + rollbackThreshold < maxSeenSeq` | Immediate quarantine |
| `nonce_mismatch` | received nonce ≠ `HMAC(K_nonce, header_ctx)[:n]` | Immediate quarantine |
| `tag_fail_streak` | N consecutive AEAD tag failures (default N=5) | Quarantine on N-th failure |

Once quarantined, `DecisionEngine` rejects all subsequent frames from that reader with reason `"quarantined"` without any cryptographic processing. `ProtocolAnomalyDetector` is not injected into `FrameHandler` — it is owned and driven by `DecisionEngine`.

**Key detail:** `nonce_mismatch` is only evaluated when `nonceMode == "deterministic"` AND the detector is active. In R1 profiles the nonce is generated deterministically on the sender side but the server does not verify it — verification is architecturally tied to the detector.

## Result Codes

These are reason strings returned by `FrameHandler.handle()` in `HandleResult.reason`:

| Code | Meaning |
|------|---------|
| `ok` | Frame valid, plaintext available |
| `frame_too_small` | Frame smaller than minimum (77 bytes) |
| `bad_magic` | Invalid magic bytes (expected "AS01") |
| `bad_protocol_version` | Unsupported version byte |
| `ciphertext_too_large` | Exceeds `maxCtLen` |
| `frame_truncated` | Frame ends before declared length |
| `frame_trailing_bytes` | Unexpected bytes after frame end |
| `parse_error` | Generic parse failure |
| `no_store` | Access store not configured |
| `unknown_reader` | reader_id not registered |
| `reader_door_forbidden` | Reader not bound to this door_id |
| `bad_key_version` | key_version not current or previous |
| `replay` | seq already seen in replay window (includes out-of-window sequences) |
| `key_derivation_failed` | Failed to derive AEAD key from KeyManager |
| `decrypt_failed` | AEAD tag verification failed |
| `mac_verification_failed` | Alias for decrypt_failed |
| `too_old` | Timestamp is stale (behind server clock beyond maxSkewMs) |
| `too_future` | Timestamp ahead of server clock beyond maxSkewMs |

`DecisionEngine` may additionally return `"quarantined"` when the anomaly detector quarantines a reader (R2 profiles only).

## Replay Attack Protection

`FrameHandler` maintains a `ReplayWindow` per reader (map keyed by `reader_id`):

1. Frame arrives with `seq = N`
2. If `N` is below the window lower bound → reject as `replay`
3. If `N` is in the seen set → reject as `replay`
4. Otherwise → accept, add `N` to seen set, update `maxSeen`

The sliding window tolerates out-of-order delivery (common on Wi-Fi) while still rejecting duplicates. Sequences too far below `maxSeen` are treated as replays, not as a separate error code.

## Key Rotation Support

When `allowPreviousKeyVersion = true`:
- Frames with `key_version == current` → accepted normally
- Frames with `key_version == current - 1` → also accepted (rotation window)
- Any other version → `bad_key_version`

## Dependencies

- `key_manager` — AEAD and nonce key derivation
- `crypto_lib` — AEAD encryption, nonce generators
- `protocol_lib` — Frame parsing, ReplayWindow
- `access_decision` — `IAccessStore` interface

## Tests

```bash
cd build && ctest -R "handle_frame|anomaly_detector" -V
```

| Test file | Coverage |
|-----------|----------|
| `handle_frame_test.cpp` | FrameHandler orchestration, replay window poisoning |
| `anomaly_detector_test.cpp` | All four anomaly types, quarantine lifecycle, R2 profile behaviour |
