# Access Security System

A secure, cryptographically-verified physical access control system for doors and card readers. Hardware layer: ESP32 + MFRC522 over Wi-Fi. Server: C++20, HTTP REST API, SQLite, libsodium.

## Repository layout

The project ships as a single source tree containing the production system plus an additive experimental/analytical layer for the thesis security evaluation. The additions are strictly additive — they do not modify any production server or firmware code, and removing them leaves a fully functional production build.

### Additive modules (not required for production)

| Directory | Description |
|-----------|-------------|
| `experiments/` | C++ harness — eight scenario binaries (S1–S7, S3 split into S3a/S3b) that run the DecisionEngine pipeline (in-process or E2E via HTTP) and record per-frame metrics to CSV |
| `analysis/analyze.py` | Python script that loads all CSVs and produces publication-quality plots + LaTeX tables |
| `tukedip_output/` | Thesis document source (Slovak, LaTeX) |

For a minimal production distribution, remove `experiments/`, `analysis/`, and `tukedip_output/` — the root `CMakeLists.txt` and the server build succeed without them.

### Experimental claims tested

| Scenario | Attack | What is validated |
|----------|--------|-------------------|
| **S1** Replay | Replay a captured valid frame | Anti-replay window rejects on all profiles; R2 quarantines on `seq_reuse` |
| **S2** Tamper | Modify `door_id` in frame bytes | AAD binding causes `decrypt_failed` on all profiles |
| **S3a** Fixed nonce | Reuse the same nonce for every frame | R2 detects `nonce_mismatch` and quarantines; R0/R1 do not detect |
| **S3b** Cross-reader | Frame encrypted with different reader's HKDF key | All profiles reject (key isolation); R2 quarantines via `nonce_mismatch` |
| **S4** Seq reset | Roll back sequence number | ReplayWindow rejects on all; R2 additionally quarantines on `seq_rollback` |
| **S5** Tag probe | Corrupt ciphertext bytes | `decrypt_failed` on all profiles; R2 quarantines after 5 consecutive failures |
| **S6** Throughput | Valid frames at varying load | Measures frames/sec per profile; XChaCha20 vs ChaCha20 overhead |
| **S7** Nonce tamper | Valid frame with nonce XOR-flipped post-construction (simulated MITM) | `decrypt_failed` on all profiles; R2 quarantines via `nonce_mismatch` before AEAD |

**Key result (Thesis T1):** R2 enforces nonce policy as the only profile differentiating nonce strategies (S3a). HKDF per-reader key derivation provides cryptographic isolation across all profiles (S3b). Nonce tamper in transit is caught by AEAD on all profiles; R2 detects it proactively (S7).

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
                                     ┌───────────────────────────────┐
┌──────────────┐  HMAC-signed HTTP   │     Port 8080 (frontend)      │
│  ESP32       │ ──────────────────▶ │  /api/hw/uid                  │
│  + MFRC522   │  uid, reader_id,    │    hw_service:                │
│              │  door_id, hw_seq    │      verify HMAC              │
│  hw_seq++    │                     │      build AEAD frame         │
│  HMAC sign   │                     │          │                    │
└──────────────┘                     │          │ POST frame bytes   │
                                     │          ▼                    │
                                     │  Admin API, Web UI, EventBus │
                                     └──────────┬────────────────────┘
                                                │ HTTP (localhost)
                                     ┌──────────▼────────────────────┐
                                     │     Port 8081 (decision)      │
                                     │  /api/decision/frame          │
                                     │    DecisionEngine             │
                                     │      ├─ replay window         │
                                     │      ├─ AEAD decrypt (A1/A2)  │
                                     │      ├─ AnomalyDetector (R2)  │
                                     │      ├─ HMAC(uid) lookup      │
                                     │      ├─ RBAC role check       │
                                     │      └─ audit append          │
                                     │                               │
                                     │  SQLite (WAL mode)            │
                                     └───────────────────────────────┘
```

One process, two ports. `hw_service` on port 8080 builds the AEAD frame and POSTs it to the DecisionService on port 8081. The decision endpoint is also used by E2E experiments (`--e2e` flag). SQLite uses WAL mode + busy_timeout for concurrent access safety.

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
| `experiments` | Reproducible C++ experimental harness for security profile analysis |

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

### First-Time Setup (generate master key)

Before first run of the server or the E2E experiments, create the 32-byte
master key used by the HKDF derivation chain. The file is git-ignored and
is **not** shipped in the source archive.

```bash
mkdir -p secrets
head -c 32 /dev/urandom | xxd -p -c 64 > secrets/master_key.hex
```

Details and format: see [`secrets/README.md`](secrets/README.md). The
in-process experiment harness uses a deterministic demo key and does **not**
require this step.

### Start Server

```bash
./build/access_admin/access_admin config/access_security.yaml
```

Web UI: `http://localhost:8080/static/index.html`

### Run Experiments (full reproduction)

#### 1. Build experiment binaries

```bash
mkdir -p build && cd build
cmake ..
cmake --build . -j$(nproc)
```

#### 2. Run all scenarios (in-process)

Run from the project root. Each binary writes one CSV to `results/`.

```bash
cd build/experiments
for s in s1_replay s2_tamper s3_rng_fault s3_cross_reader s4_seq_reset s5_tag_probe s7_nonce_tamper; do
    ./$s
done
./s6_throughput   # slowest (~10–20 min)
```

#### 3. Run E2E experiments (through HTTP endpoint)

Start server, then run scenarios with `--e2e` flag. The `run_e2e.sh` script automates this for all 6 profiles:

```bash
# From project root
./experiments/run_e2e.sh
```

Results are written to `build/experiments/results_e2e/`.

#### CLI overrides

Each binary accepts `--seed=N`, `--warmup=N`, `--baseline=N`, `--runs=N`, `--e2e=URL`, `--profile=A1-R0`:

```bash
./build/experiments/s1_replay --seed=123 --runs=10
./build/experiments/s7_nonce_tamper --e2e=http://localhost:8081 --profile=A2-R2
```

#### 3. Run Python analysis

```bash
# From repo root — create venv once
python3 -m venv .venv
source .venv/bin/activate
pip install pandas matplotlib seaborn numpy

# Run analysis (reads from build/experiments/results/, writes to analysis/plots/)
python3 analysis/analyze.py --results-dir build/experiments/results --output-dir analysis/plots
```

#### 4. Outputs

**Plots** (saved to `analysis/plots/` as 300 dpi PNG):

| File | Content |
|------|---------|
| `attack_success_heatmap.png` | Attack success rate per scenario × profile |
| `attack_success_by_n.png` | Success rate vs. attack step count |
| `quarantine_speed.png` | Frames to quarantine per scenario (R2 profiles) |
| `latency_boxplot.png` | Per-frame latency distribution |
| `throughput.png` | S6 throughput (frames/sec) per profile |
| `detector_overhead.png` | R2 vs R0/R1 latency overhead |
| `scenario_summary_table.png` | Summary table figure |

**LaTeX tables** (also in `analysis/plots/`):

| File | Content |
|------|---------|
| `scenario_summary.tex` | Main results summary |
| `throughput_table.tex` | S6 throughput stats |
| `baseline_correctness.tex` | Baseline false-reject rates |

**Console summary** — printed after plots, shows key metrics:
```
=== Key Metrics ===
  Max false reject rate (baseline): 0.0000%

  S1: Replay Attack:
    ✓ A1-R0: 0% success
    ✓ A1-R1: 0% success
    ...
  S6: Throughput at N=50,000:
    A1-R0: 42,300 ± 800 fps
    ...
```

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
