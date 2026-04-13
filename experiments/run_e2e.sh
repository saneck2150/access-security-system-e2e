#!/usr/bin/env bash
# E2E experiment runner: starts server per profile, runs all scenarios, collects results.
# Usage: ./experiments/run_e2e.sh [--scenarios=s1_replay,s2_tamper,...] [--runs=1] [--warmup=10] [--baseline=10]
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER="$PROJ_ROOT/build/access_admin/access_admin"
SCENARIOS="${SCENARIOS:-s1_replay s2_tamper s3_rng_fault s3_cross_reader s4_seq_reset s5_tag_probe s7_nonce_tamper}"
PORT=8090
URL="http://localhost:$PORT"
OUTDIR="$PROJ_ROOT/build/experiments/results_e2e"
EXTRA_ARGS="${*}"

# Profile → server config mapping
declare -A CIPHER_MODE=( [A1-R0]=chacha20 [A1-R1]=chacha20 [A1-R2]=chacha20
                         [A2-R0]=xchacha20 [A2-R1]=xchacha20 [A2-R2]=xchacha20 )
declare -A NONCE_MODE=(  [A1-R0]=random [A1-R1]=deterministic [A1-R2]=deterministic
                         [A2-R0]=random [A2-R1]=deterministic [A2-R2]=deterministic )
declare -A DETECTOR=(    [A1-R0]=false [A1-R1]=false [A1-R2]=true
                         [A2-R0]=false [A2-R1]=false [A2-R2]=true )

mkdir -p "$OUTDIR"

generate_config() {
    local profile=$1
    cat > /tmp/e2e_${profile}.yaml << YAML
frame_handler:
  anti_replay_enabled: true
  replay_window_size: 256
  max_ct_len: 4096
  max_skew_ms: 0
  allow_previous_key_version: true
  enforce_reader_door_binding: true
  key_derivation_mode: hkdf
  aad_mode: full
  cipher_mode: ${CIPHER_MODE[$profile]}
  nonce_mode: ${NONCE_MODE[$profile]}
  pepper_mode: versioned

key_management:
  current_key_version: 1
  allow_previous_key_version: true
  master_key_path: "$PROJ_ROOT/secrets/master_key.hex"

storage:
  sqlite_path: "/tmp/e2e_${profile}.db"

admin:
  bind_host: "127.0.0.1"
  port: $PORT
  admin_token: "admin"
  hw_shared_secret_hex: ""
  max_upload_bytes: 20000000
  max_events: 1024

experiment:
  cipher_mode: ${CIPHER_MODE[$profile]}
  nonce_mode: ${NONCE_MODE[$profile]}
  key_derivation_mode: hkdf
  aad_mode: full
  pepper_mode: versioned
  audit_chain_enabled: true
  misuse_detection_enabled: ${DETECTOR[$profile]}
  rollback_threshold: 100
  tag_fail_streak_limit: 5
YAML
}

setup_server_data() {
    # Register reader 1, door 7, card CARD1 via admin API
    sleep 1
    curl -sf -X POST "$URL/api/readers" \
        -H "X-Admin-Token: admin" -H "Content-Type: application/json" \
        -d '{"reader_id": 1, "current_key_version": 1}' > /dev/null

    curl -sf -X POST "$URL/api/readers/1/doors" \
        -H "X-Admin-Token: admin" -H "Content-Type: application/json" \
        -d '{"door_id": 7}' > /dev/null

    curl -sf -X POST "$URL/api/door_roles" \
        -H "X-Admin-Token: admin" -H "Content-Type: application/json" \
        -d '{"door_id": 7, "role": "employee"}' > /dev/null

    curl -sf -X POST "$URL/api/cards" \
        -H "X-Admin-Token: admin" -H "Content-Type: application/json" \
        -d '{"card_id": "CARD1", "role": "employee"}' > /dev/null
}

for PROFILE in A1-R0 A1-R1 A1-R2 A2-R0 A2-R1 A2-R2; do
    echo "=== Profile: $PROFILE ==="

    # Clean up
    rm -f "/tmp/e2e_${PROFILE}.db"
    generate_config "$PROFILE"

    # Start server
    "$SERVER" "/tmp/e2e_${PROFILE}.yaml" &
    SERVER_PID=$!
    setup_server_data

    # Verify server is alive
    if ! curl -sf "$URL/api/decision/frame" -X POST -d "test" > /dev/null 2>&1; then
        echo "ERROR: Server not responding for $PROFILE"
        kill $SERVER_PID 2>/dev/null || true
        continue
    fi

    # Run scenarios for this profile
    for SCENARIO in $SCENARIOS; do
        echo "  Running $SCENARIO ($PROFILE)..."
        cd "$PROJ_ROOT"
        ./build/experiments/$SCENARIO \
            --e2e="$URL" \
            --profile="$PROFILE" \
            ${RUNS:---runs=5} ${WARMUP:---warmup=200} ${BASELINE:---baseline=200} \
            2>&1 | tail -1

        # Append results to combined CSV
        SRCCSV="results/${SCENARIO}.csv"
        if [ -f "$SRCCSV" ]; then
            if [ ! -f "$OUTDIR/${SCENARIO}.csv" ]; then
                head -1 "$SRCCSV" > "$OUTDIR/${SCENARIO}.csv"
            fi
            tail -n +2 "$SRCCSV" >> "$OUTDIR/${SCENARIO}.csv"
        fi
    done

    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    echo "  Server stopped."
done

echo ""
echo "=== E2E experiments complete ==="
echo "Results in: $OUTDIR/"
ls -la "$OUTDIR/"*.csv 2>/dev/null
