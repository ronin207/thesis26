#!/bin/bash
# SP1 BDEC execute-mode FULL-REPORT re-run (harness #4).
# Dumps per-op (opcode + syscall) breakdown for CreGen and ShowCre k=1/k=2,
# both arms, on the SP1 cost model — the per-op detail §6 needs and that
# sp1_bdec_execute_20260602 (totals + 2 syscalls only) lacks. The headline
# SP1 TOTALS already exist there; this run adds the histogram + a fresh HEAD
# reproduction. Execute-mode: machine-independent, terminates in seconds.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
export VC_PQC_SKIP_LIBIOP=1
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"     # iCloud rlib workaround
OUTDIR="$REPO/docs/measurements/sp1_bdec_execute_20260707"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/full_report.log"
export BDEC_HOST_SECURITY="${BDEC_HOST_SECURITY:-80}"
export BDEC_REPORT_ARMS="${BDEC_REPORT_ARMS:-both}"

echo "=== run start $(date -u +%Y-%m-%dT%H:%M:%SZ) arms=$BDEC_REPORT_ARMS lambda=$BDEC_HOST_SECURITY ===" > "$LOG"
cargo run --release --manifest-path "$REPO/platforms/zkvms/sp1/script/Cargo.toml" \
  --bin bdec_execute_report >> "$LOG" 2>&1
rc=$?
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$LOG"
