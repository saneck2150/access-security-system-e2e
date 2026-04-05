# experiments

Reproducible C++ experimental harness for security profile analysis. Measures detection latency, throughput, and attack resistance across the six A×R profile combinations (A1-R0 through A2-R2).

## Overview

The harness is a controlled mini-system: no HTTP transport, no YAML config files. Everything is wired programmatically — a fresh `ExperimentContext` (SQLite + DecisionEngine + ProtocolAnomalyDetector) is created per profile per iteration, run through a fixed sequence of frames, and torn down. This eliminates external variables and makes results bit-identical given the same seed.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Scenario Loop                                │
│                                                                     │
│  for profile in A1-R0 .. A2-R2:                                     │
│    for stepN in cfg.steps:                                          │
│      for run in 0..runs-1:                                          │
│        ExperimentContext (fresh SQLite + engine per iteration)       │
│        FrameFactory (builds frames for this profile)                │
│        scenario.setup()                                             │
│                                                                     │
│        Warmup   (cfg.warmup frames, not recorded)                   │
│        Baseline (cfg.baseline frames → MetricsCollector, phase=baseline) │
│        Trial    (stepN frames → MetricsCollector, phase=attack/measure)  │
│                                                                     │
│        remove(dbPath)                                               │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

| File | Purpose |
|------|---------|
| `experiment_context.hpp/cpp` | `ExperimentContext`: full pipeline (SQLite store, DecisionEngine, anomaly detector) |
| `frame_factory.hpp/cpp` | `FrameFactory`: builds encrypted frames; static byte-level tampering helpers |
| `seeded_nonce_generator.hpp/cpp` | `SeededNonceGenerator`: deterministic R0 nonce from seed (PRNG, not truly random) |
| `metrics_collector.hpp/cpp` | `MetricsCollector`: per-frame CSV output |
| `scenario_common.hpp/cpp` | Shared constants + `makeMasterKey()`, `allProfiles()`, `makeNonceGen()` |
| `scenario_runner.hpp/cpp` | `RunConfig`, `TrialContext`, `IScenario`, `runScenario()`, `parseCliOverrides()` |

### ProfileConfig

Defines one of the six experiment profiles:

| Profile | `cipherMode` | `nonceMode` | `detectorEnabled` |
|---------|-------------|-------------|------------------|
| A1-R0 | `chacha20` | `random` | false |
| A1-R1 | `chacha20` | `deterministic` | false |
| A1-R2 | `chacha20` | `deterministic` | **true** |
| A2-R0 | `xchacha20` | `random` | false |
| A2-R1 | `xchacha20` | `deterministic` | false |
| A2-R2 | `xchacha20` | `deterministic` | **true** |

### ExperimentContext

Self-contained pipeline. Registers one reader, one door, and one card (role "employee"). Provides `processFrame()` and `isQuarantined()`.

Key differences from production:
- **No HTTP** — frames are passed directly to `DecisionEngine`
- **maxSkewMs = 0** — timestamp check disabled (all frames use synthetic timestamps)
- **InMemoryAuditLog** — no filesystem I/O for audit
- **Profiles programmatic** — no YAML; `ProfileConfig` fields map directly to `FrameHandlerConfig`

### FrameFactory

Builds valid encrypted frames. Also provides static tampering helpers:

| Method | What it modifies |
|--------|-----------------|
| `tamperDoorId(frame, newId)` | bytes [9..12] (door_id field) |
| `tamperReaderId(frame, newId)` | bytes [5..8] (reader_id field) |
| `tamperCiphertext(frame)` | ciphertext bytes XOR'd with 0xFF |
| `tamperSeq(frame, newSeq)` | bytes [21..28] (seq field) |

### IScenario / RunConfig / runScenario

Each scenario implements only its unique logic:

```cpp
class IScenario {
    virtual std::string name() const = 0;
    virtual RunConfig config() const = 0;
    virtual void setup(ExperimentContext&, FrameFactory&, ...);   // optional
    virtual void onBaselineFrame(idx, total, frame);              // optional
    virtual std::vector<uint8_t> buildTrialFrame(...) = 0;
    virtual std::string trialPhaseName() const;  // default "attack"
};
```

`runScenario()` handles warmup, baseline timing, trial timing, and CSV output.

**CLI overrides** (all scenarios):
```bash
./s1_replay --seed=99 --warmup=100 --baseline=100 --runs=3
```

### MetricsCollector

Writes one CSV row per frame. CSV columns:

`profile, cipher_mode, nonce_mode, detector_enabled, scenario, phase, attack_n, frame_idx, allowed, reason, quarantined, anomaly_type, latency_ns, run_idx`

Output goes to `results/` directory (created automatically).

## Scenarios

| Binary | File | Attack | Detection expected |
|--------|------|--------|--------------------|
| `s1_replay` | `s1_replay.cpp` | Replay captured baseline frame | All profiles: `replay` deny; R2: `quarantined` on seq_reuse |
| `s2_tamper` | `s2_tamper.cpp` | Modify `door_id` in frame bytes | All profiles: `decrypt_failed` (AAD mismatch) |
| `s3_rng_fault` | `s3_rng_fault.cpp` | Fixed nonce (S3a) / wrong-key nonce (S3b) | R2 only: `quarantined` on nonce_mismatch |
| `s4_seq_reset` | `s4_seq_reset.cpp` | Sequence number rollback | All: `replay`; R2: `quarantined` on seq_rollback |
| `s5_tag_probe` | `s5_tag_probe.cpp` | Tamper ciphertext (XOR 0xFF) | All profiles: `decrypt_failed`; R2: `quarantined` on tag_fail_streak |
| `s6_throughput` | `s6_throughput.cpp` | Valid frames (throughput measurement) | N/A — all `ok` |

## Building and Running

```bash
# Build
cd build && cmake --build . --target s1_replay s2_tamper s3_rng_fault s4_seq_reset s5_tag_probe s6_throughput

# Run all scenarios (from build dir)
./experiments/s1_replay/s1_replay
./experiments/s2_tamper/s2_tamper
./experiments/s3_rng_fault/s3_rng_fault
./experiments/s4_seq_reset/s4_seq_reset
./experiments/s5_tag_probe/s5_tag_probe
./experiments/s6_throughput/s6_throughput

# Results written to results/*.csv in the working directory
```

## Dependencies

- `access_decision` — `DecisionEngine`, policy interfaces
- `access_core` — `FrameHandler`, `ProtocolAnomalyDetector`, `FrameHandlerConfig`
- `access_storage` — `SqliteAccessStore`
- `crypto_lib` — AEAD, nonce generators, HKDF
- `key_manager` — Key derivation
- `protocol_lib` — Frame serialization
- `runtime_events` — `EventBus` (for engine construction; events discarded)
