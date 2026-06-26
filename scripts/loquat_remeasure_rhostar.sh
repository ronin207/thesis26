#!/usr/bin/env bash
# =============================================================================
# Loquat zkVM remeasure after the rho*=1/16 fix (branch fix/loquat-rho-star-rate).
# Re-runs the SP1 Loquat-verify PROVE at lambda=80 with the corrected |U|=4096
# workload. NO kill-tripwire: the prove runs to natural completion or a real OS
# OOM. Peak tree-RSS is sampled PASSIVELY (recorded, never used to kill) because
# peak RSS is a reported metric for the substrate comparison. Launch when AFK
# (the 16x-heavier prove hogs ~all of 24 GB).
#
# Usage:
#   scripts/loquat_remeasure_rhostar.sh --check   # cheap: force guest rebuild + execute-mode sanity (~minutes)
#   scripts/loquat_remeasure_rhostar.sh           # full: --check, then the PROVE (hours), passive RSS sampling
#
# Why --check matters: the host embeds the guest ELF via include_bytes!(env!(...)).
# If sp1_build does not rebuild the guest from the FIXED src/signatures/loquat/setup.rs,
# the prove silently re-runs the OLD |U|=256 workload and the remeasure is worthless.
# --check forces a fresh guest build and runs execute mode to confirm it compiled+ran.
# =============================================================================
set -euo pipefail

# rustup succinct toolchain must shadow Homebrew rustc (SP1 guest cross-compile).
export PATH="$HOME/.cargo/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$REPO_ROOT/platforms/zkvms/sp1/script"
GUEST_ELF_OUT="$REPO_ROOT/platforms/zkvms/sp1/program_loquat/elf-out"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$REPO_ROOT/docs/measurements"
LOG="$LOG_DIR/loquat_remeasure_rhostar_${TS}.log"
mkdir -p "$LOG_DIR"

log() { echo "$@" | tee -a "$LOG"; }

# Sum RSS (KB) over a process and all descendants — cargo's prover child is where the RAM lives.
sum_tree_rss() {
  local pid="$1" total kid
  total="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; total="${total:-0}"
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    total=$(( total + $(sum_tree_rss "$kid") ))
  done
  echo "$total"
}

log "=== Loquat rho*-fixed remeasure  ($TS) ==="
log "repo:   $REPO_ROOT"
log "commit: $(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null) on $(cd "$REPO_ROOT" && git rev-parse --abbrev-ref HEAD 2>/dev/null)"
log "expect: |U|=4096, rho*=1/16, r=4 (was |U|=256, rho*=1). NO kill-tripwire; peak RSS sampled passively."

# --- Phase 1: force fresh guest build + execute-mode sanity (cheap) ---
log ""
log "--- phase 1: force guest rebuild + execute sanity ---"
rm -rf "$GUEST_ELF_OUT" 2>/dev/null || true   # drop stale ELF so build.rs/sp1_build must regenerate from fixed src
cd "$SCRIPT_DIR"
if ! LOQUAT_MODE=execute cargo run --release --bin loquat_host >>"$LOG" 2>&1; then
  log "[FAIL] phase-1 execute did not complete — fix the build before proving. See $LOG."
  exit 1
fi
log "[ok] guest rebuilt + execute mode ran. (Confirm the cycle count differs from the |U|=256 run if you recorded it.)"

if [ "${1:-}" = "--check" ]; then
  log "--check only: stopping before the prove. Re-run without --check to prove."
  exit 0
fi

# --- Phase 2: the PROVE (no kill; passive peak-RSS sampling) ---
log ""
log "--- phase 2: PROVE (succinct STARK, NOT zk), lambda=80; runs to completion or real OOM ---"
LOQUAT_MODE=prove cargo run --release --bin loquat_host >>"$LOG" 2>&1 &
PROVE_PID=$!

# Passive sampler: record the max tree-RSS to a sidecar file. Never kills.
PEAK_FILE="$LOG.peakrss"; echo 0 > "$PEAK_FILE"
( while kill -0 "$PROVE_PID" 2>/dev/null; do
    TOTAL_KB="$(sum_tree_rss "$PROVE_PID")"
    PREV="$(cat "$PEAK_FILE" 2>/dev/null || echo 0)"
    if [ "${TOTAL_KB:-0}" -gt "${PREV:-0}" ]; then echo "$TOTAL_KB" > "$PEAK_FILE"; fi
    sleep 15
  done ) &
MON_PID=$!

PROVE_RC=0; wait "$PROVE_PID" || PROVE_RC=$?
kill "$MON_PID" 2>/dev/null || true

PEAK_KB="$(cat "$PEAK_FILE" 2>/dev/null || echo 0)"; rm -f "$PEAK_FILE"
log "peak tree RSS observed: $((PEAK_KB/1024)) MB ($(awk "BEGIN{printf \"%.1f\", $PEAK_KB/1048576}") GB)"
if [ "$PROVE_RC" -eq 0 ]; then
  log "[done] prove COMPLETED. Grep '$LOG' for 'prove_ms=' — that is the rho*-fixed Loquat-verify lambda=80 number."
else
  log "[done] prove ENDED rc=$PROVE_RC (real OS OOM or error — no artificial kill). The peak RSS above is the resource finding for P0/the substrate caveat."
fi
log "log: $LOG"
