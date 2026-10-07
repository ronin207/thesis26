#!/bin/bash
# Poseidon2-KoalaBear matched-field control (harness #2, ℓ=1 point).
# Execute-mode (machine-independent cycle counts, terminates in seconds).
# Builds the host+guest if needed, then runs the slope measurement.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
export VC_PQC_SKIP_LIBIOP=1
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"     # iCloud rlib workaround
OUTDIR="$REPO/docs/measurements/poseidon2_kb_20260707"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/poseidon2_kb.log"

# N_LO/N_HI slope endpoints (override via env if desired).
export POSEIDON2_KB_N_LO="${POSEIDON2_KB_N_LO:-10000}"
export POSEIDON2_KB_N_HI="${POSEIDON2_KB_N_HI:-20000}"

echo "=== run start $(date -u +%Y-%m-%dT%H:%M:%SZ) N_LO=$POSEIDON2_KB_N_LO N_HI=$POSEIDON2_KB_N_HI ===" > "$LOG"
cargo run --release --manifest-path "$REPO/platforms/zkvms/sp1/script/Cargo.toml" \
  --bin poseidon2_kb_host >> "$LOG" 2>&1
rc=$?
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$LOG"
