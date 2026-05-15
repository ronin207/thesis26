#!/usr/bin/env bash
# Anchor run: ONE full-mode RISC0 prove of BDEC.ShowVer at the smallest
# config (λ=80, k=1, s=1, m=16). Produces the cycle→wallclock calibration
# point needed to extrapolate the 36-cell dev-mode sweep to real prove times.
#
# Designed to survive terminal close + display sleep:
#   - Run inside tmux (detach with C-b d, reattach with `tmux attach -t anchor`)
#   - Wrap with `caffeinate -i` so idle sleep is suppressed
#   - Memory cap via ulimit -v keeps it from dragging the whole machine into swap
#   - Segment_po2=20 (1M cycles/segment) so per-segment RAM fits comfortably
#
# Launch:
#   caffeinate -i tmux new -s anchor -d \
#     'bash "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/scripts/anchor_run.sh"'
#
# Watch live:           tmux attach -t anchor
# Watch log only:       tail -f <RESULTS_DIR>/anchor.log
# Quick status:         bash scripts/anchor_status.sh <RESULTS_DIR>
#
# RESULTS_DIR is printed at the top of the log (and in tmux header).

set -uo pipefail

PROJECT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
ZKVM_DIR="$PROJECT/zkvm"
RUN_ID="anchor_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="$PROJECT/results/$RUN_ID"

mkdir -p "$RESULTS_DIR"

LOG="$RESULTS_DIR/anchor.log"
PID_FILE="$RESULTS_DIR/anchor.pid"
STATUS_FILE="$RESULTS_DIR/anchor.status"
RESULT_FILE="$RESULTS_DIR/anchor.json"
META_FILE="$RESULTS_DIR/anchor.meta"

# Memory cap: 16 GB virtual memory ceiling. Total system RAM is 24 GB.
# If RISC0 tries to balloon past this, we get a clean allocation failure
# instead of swap death dragging the whole machine.
ulimit -v 16000000 2>/dev/null || true

# Segment size: 2^20 = 1,048,576 cycles per segment.
# Default is 21 (2M cycles). Lower = smaller per-segment RAM, more segments.
# 2.91B trace / 1M ≈ 2773 segments at po2=20.
export RISC0_SEGMENT_PO2=20

NICE_LEVEL=5

cd "$ZKVM_DIR" || { echo "cannot cd $ZKVM_DIR" >&2; exit 1; }

echo "$$" > "$PID_FILE"
echo "starting" > "$STATUS_FILE"

# Capture run metadata up front
{
  echo "results_dir=$RESULTS_DIR"
  echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "uname=$(uname -a)"
  echo "ulimit_v_kb=$(ulimit -v)"
  echo "RISC0_SEGMENT_PO2=$RISC0_SEGMENT_PO2"
  echo "config=lambda80_k1_s1_m16"
  echo "nice=$NICE_LEVEL"
} > "$META_FILE"

# Set the tmux window title so it's obvious which session this is
printf '\033]0;anchor | %s\007' "$RUN_ID"

# Trap interrupts so the status file always reflects reality
on_exit() {
  local code=$?
  local end_epoch=$(date +%s)
  local elapsed=$(( end_epoch - START_EPOCH ))
  if [ "$code" -eq 0 ]; then
    echo "done:0:${elapsed}" > "$STATUS_FILE"
  elif [ "$code" -eq 130 ]; then
    echo "interrupted:${code}:${elapsed}" > "$STATUS_FILE"
  else
    echo "failed:${code}:${elapsed}" > "$STATUS_FILE"
  fi
  echo "ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$META_FILE"
  echo "elapsed_s=${elapsed}" >> "$META_FILE"
  echo "exit_code=${code}" >> "$META_FILE"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

START_EPOCH=$(date +%s)

# Launch the host. Capture stdout (JSON line) to RESULT_FILE,
# tee everything (incl. RISC0 progress) into LOG.
{
  echo "==="
  echo "anchor run: BDEC.ShowVer full-mode prove"
  echo "started:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "config:     lambda=80 k=1 s=1 m=16 rev_depth=20"
  echo "segment_po2: $RISC0_SEGMENT_PO2"
  echo "ulimit -v:  $(ulimit -v) KB"
  echo "results:    $RESULTS_DIR"
  echo "==="
  echo ""

  # NB: --dev-mode is intentionally OMITTED so this generates a real STARK proof.
  # --continue-on-error is also OMITTED so a failure surfaces immediately.
  nice -n "$NICE_LEVEL" \
    cargo run --release -- \
      --security-level 80 --k 1 --s 1 --m 16 \
      --json
} 2>&1 | tee "$LOG" | tee -a "$RESULT_FILE" >/dev/null

# We tee'd stdout into both LOG and RESULT_FILE — but RESULT_FILE will contain
# all stdout including cargo's own messages. Extract just the JSON lines.
if [ -f "$RESULT_FILE" ]; then
  grep -E '^\{"status"' "$RESULT_FILE" > "$RESULT_FILE.tmp" 2>/dev/null && \
    mv "$RESULT_FILE.tmp" "$RESULT_FILE" || true
fi
