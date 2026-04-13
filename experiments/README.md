# experiments

Reproducible C++ experimental harness for security profile analysis. Measures detection latency, throughput, and attack resistance across the six A×R profile combinations (A1-R0 through A2-R2).

## Overview

The harness supports two execution modes:

- **In-process** (default): frames passed directly to `DecisionEngine` — no HTTP, no network overhead. Produces pure crypto/decision metrics.
- **E2E** (`--e2e=URL`): frames POSTed to `/api/decision/frame` HTTP endpoint — validates that security properties hold across the network boundary.

In both modes, a fresh `ExperimentContext` (SQLite + DecisionEngine + ProtocolAnomalyDetector) is created per profile per iteration. Results are bit-identical given the same seed (in-process mode).

## Components

| File | Purpose |
|------|---------|
| `experiment_context.hpp/cpp` | `ExperimentContext`: full pipeline; supports in-process and E2E (HTTP) modes |
| `frame_factory.hpp/cpp` | `FrameFactory`: builds encrypted frames; static byte-level tampering helpers |
| `seeded_nonce_generator.hpp/cpp` | `SeededNonceGenerator`: deterministic R0 nonce from seed |
| `metrics_collector.hpp/cpp` | `MetricsCollector`: per-frame CSV output (seed = actual `base_seed + run_idx`) |
| `scenario_common.hpp/cpp` | Shared constants + `makeMasterKey()`, `allProfiles()`, `makeNonceGen()` |
| `scenario_runner.hpp/cpp` | `RunConfig`, `IScenario`, `runScenario()`, `parseCliOverrides()` |
| `run_e2e.sh` | Bash script: starts server per profile, runs all scenarios in E2E mode |

### FrameFactory tampering helpers

| Method | What it modifies |
|--------|-----------------|
| `tamperDoorId(frame, newId)` | bytes [9..12] (door_id field) |
| `tamperReaderId(frame, newId)` | bytes [5..8] (reader_id field) |
| `tamperNonce(frame)` | bytes [33..56] (nonce XOR 0xFF) |
| `tamperCiphertext(frame)` | ciphertext bytes XOR'd with 0xFF |
| `tamperSeq(frame, newSeq)` | bytes [21..28] (seq field) |

## Scenarios

| Binary | Attack | Detection expected |
|--------|--------|--------------------|
| `s1_replay` | Replay captured baseline frame | All: `replay`; R2: `quarantined` (seq_reuse) |
| `s2_tamper` | Modify `door_id` in header | All: `decrypt_failed` (AAD); R2: `quarantined` (nonce_mismatch) |
| `s3_rng_fault` | Fixed nonce for every frame (S3a) | R0/R1: pass (100%); R2: `quarantined` (nonce_mismatch) |
| `s3_cross_reader` | Frame encrypted with wrong reader's HKDF key (S3b) | All: `decrypt_failed`; R2: `quarantined` (nonce_mismatch) |
| `s4_seq_reset` | Sequence number rollback | R0/R1: partial pass (11%); R2: `quarantined` (seq_rollback) |
| `s5_tag_probe` | Corrupt ciphertext bytes | All: `decrypt_failed`; R2: `quarantined` (tag_fail_streak) |
| `s6_throughput` | Valid frames (performance) | All: `ok` |
| `s7_nonce_tamper` | Valid frame, nonce XOR-flipped (MITM) | All: `decrypt_failed`; R2: `quarantined` (nonce_mismatch) |

## Running

### In-process (default)

```bash
cd build/experiments
./s1_replay
./s7_nonce_tamper
# etc.
```

### E2E (through HTTP)

```bash
# From project root — runs all profiles × all scenarios
./experiments/run_e2e.sh

# Or single scenario/profile:
./build/experiments/s7_nonce_tamper --e2e=http://localhost:8080 --profile=A2-R2
```

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--seed=N` | 42 | Base seed (actual = seed + run_idx) |
| `--warmup=N` | 200 | Warmup frames (not recorded) |
| `--baseline=N` | 200 | Baseline frames |
| `--runs=N` | 5 | Repetitions per step |
| `--e2e=URL` | (empty) | E2E mode: POST frames to this URL |
| `--profile=LABEL` | (empty) | Run only this profile (e.g. A1-R2) |

## Dependencies

- `access_decision`, `access_core`, `access_storage`, `crypto_lib`, `protocol_lib`, `key_manager`, `runtime_events`
- `cpp_httplib` (for E2E HTTP client)
- `nlohmann_json`