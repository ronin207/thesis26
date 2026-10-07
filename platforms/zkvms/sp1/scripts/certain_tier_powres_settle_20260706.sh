#!/usr/bin/env bash
# =============================================================================
# CERTAIN-TIER DRIVER (2026-07-06) — standard-Griffin re-baseline.
# Item (c): the TWO POW_RES single-arm PROVES that settle the open
#           full-machine (base RISCV + precompile) trace-area trade the
#           M4 keystone left inconclusive (RESULT.md 2026-07-06).
#
# This driver STAGES the multi-minute proves ONLY. Items (a) [Cell-1
# execute] and (b) [recursion-shape fixpoint] are execute/short and were
# run separately by the launching session (results in this OUT dir).
# Item (d) [RISC0 re-baseline] is a SEPARATE ~6h19m run — see footer; it
# is NOT launched here (its runtime exceeds the 3h cap).
#
# Two guests (built + execute-smoke-validated, uncommitted, in the fork):
#   fp192-powres-b2-test : N=28 symbols, ONE FP192_POW_RES syscall each.
#   fp192-powres-sm-test : N=28 symbols, 261 FP192_MUL syscalls each
#                          (L+popcount = 191+70), square-and-multiply.
# Identical workload; the two proves' TOTAL trace cells are the like-for-
# like full-machine comparison. Per-op keystone already gave precompile-
# chip area (B2 1.22-1.49x LARGER); execute smoke gave the RISCV-cycle
# side (B2 141x FEWER cycles/symbol). These proves combine both.
#
# Config (disclosed): PLUM-80 / lambda=80 / M5 Pro 24GB / SP1_PROVER=cpu /
#   standard-Griffin (fork branch prf-precompiles) / N_SYMBOLS=28.
#   Cap: 3h wall + a 24GB RSS watchdog per item (safety net; each prove
#   is single-shard and expected to finish in minutes).
#
# Machine gotcha: rustup succinct toolchain must precede Homebrew rustc.
# =============================================================================
set -u   # NOT -e: one prove failure must never abort the tier.

export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis"
FORK="$REPO/.claude/worktrees/thesis-restructure-criterion/sp1-fork"
OUT="$REPO/docs/measurements/certain_tier_20260706"
mkdir -p "$OUT"
DRIVERLOG="$OUT/driver_certain_tier.log"
MASTER="$OUT/CERTAIN_SUMMARY.tsv"

# CPU prover, single heavy prove at a time (no GPU / no contention).
export SP1_PROVER=cpu
export RAYON_NUM_THREADS=8
# debug on the shard prover emits ChipStatistics + "Total number of cells".
export RUST_LOG="warn,sp1_hypercube::prover=debug"

WALL_CAP=10800          # 3h per prove (safety net)
RSS_CAP_KB=$((24*1024*1024))   # 24 GB watchdog

log() { echo "[$(date -Iseconds)] $*" | tee -a "$DRIVERLOG"; }

# ---- recursive RSS over a process tree (KB) ---------------------------------
sum_tree_rss() {
  local pid="$1" total kid
  total="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; total="${total:-0}"
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    total=$(( total + $(sum_tree_rss "$kid") ))
  done
  echo "$total"
}

# ---- run a command with RSS sampler + wall-cap + 24GB watchdog --------------
run_capped() {   # $1=dir  $2..=command
  local dir="$1"; shift
  printf 'epoch\ttree_rss_kb\n' > "$dir/rss.tsv"
  ( "$@" ) > "$dir/stdout.log" 2>"$dir/stderr.log" &
  local pid=$!
  ( while kill -0 "$pid" 2>/dev/null; do
      printf '%s\t%s\n' "$(date +%s)" "$(sum_tree_rss "$pid")" >> "$dir/rss.tsv"
      sleep 5
    done ) & local samp=$!
  ( local w=0
    while kill -0 "$pid" 2>/dev/null; do
      sleep 10; w=$((w+10))
      # wall cap
      if [ "$w" -ge "$WALL_CAP" ]; then
        echo "WATCHDOG_KILL wall_cap=${WALL_CAP}s at $(date -Iseconds)" >> "$dir/stderr.log"
        pkill -KILL -P "$pid" 2>/dev/null || true; kill -KILL "$pid" 2>/dev/null || true; break
      fi
      # 24GB RSS cap
      local rss; rss="$(sum_tree_rss "$pid")"
      if [ "${rss:-0}" -ge "$RSS_CAP_KB" ]; then
        echo "WATCHDOG_KILL rss_cap=24GB (tree_rss_kb=$rss) at $(date -Iseconds)" >> "$dir/stderr.log"
        pkill -KILL -P "$pid" 2>/dev/null || true; kill -KILL "$pid" 2>/dev/null || true; break
      fi
    done ) & local wd=$!
  wait "$pid"; R_RC=$?
  kill "$samp" "$wd" 2>/dev/null || true
  wait "$samp" 2>/dev/null || true; wait "$wd" 2>/dev/null || true
}

peak_gb_of() {
  local dir="$1" peak_kb
  peak_kb="$(awk -F'\t' 'NR>1 && $2>m{m=$2} END{print m+0}' "$dir/rss.tsv" 2>/dev/null)"
  awk "BEGIN{printf \"%.2f\", ${peak_kb:-0}/1048576}"
}

# ---- one settle prove -------------------------------------------------------
run_prove() {   # $1=id  $2=testname  $3=label  $4=per_symbol_syscall_note
  local id="$1" test="$2" label="$3" note="$4"
  local dir="$OUT/${id}"
  mkdir -p "$dir"
  {
    echo "=== $id ($label) ==="
    echo "start:        $(date -Iseconds)"
    echo "config:       PLUM-80 lambda=80 | M5 Pro 24GB | SP1_PROVER=cpu | standard-Griffin"
    echo "workload:     N_SYMBOLS=28, fixed canonical operand a0<p; $note"
    echo "cap:          wall=${WALL_CAP}s (3h) + RSS 24GB watchdog"
    echo "fork HEAD:    $(git -C "$FORK" rev-parse HEAD 2>/dev/null) branch=$(git -C "$FORK" branch --show-current 2>/dev/null) (dirty = powres guests + settle tests, uncommitted)"
    echo "RUST_LOG:     $RUST_LOG   SP1_PROVER=$SP1_PROVER RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
    echo "test:         cargo test --release -p sp1-core-machine $test -- --nocapture"
  } > "$dir/meta.txt"

  log "[$id] PROVE START (cap ${WALL_CAP}s / 24GB)"
  local t0 t1; t0=$(date +%s)
  # Substring filter (no --exact): '..._prove' is unique vs '..._execute'.
  run_capped "$dir" bash -c "cd '$FORK' && exec cargo test --release -p sp1-core-machine $test -- --nocapture"
  t1=$(date +%s)
  local wall=$((t1-t0))
  log "[$id] PROVE END rc=$R_RC wall_s=$wall"

  # -------- parse --------
  local passed peak_gb total_cells nvars
  if grep -qE "test .*$test .* ok|test result: ok\. 1 passed" "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null; then passed=true; else passed=false; fi
  peak_gb="$(peak_gb_of "$dir")"
  # total trace cells (unpadded) from the shard prover debug log
  grep -hE "Total number of cells" "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_total_cells.txt"
  total_cells="$(grep -hoE "Total number of cells: [0-9_]+" "$dir/trace_total_cells.txt" 2>/dev/null | head -1 | grep -oE "[0-9_]+")"; total_cells="${total_cells:-NA}"
  nvars="$(grep -hoE "number of variables: [0-9]+" "$dir/trace_total_cells.txt" 2>/dev/null | head -1 | grep -oE "[0-9]+$")"; nvars="${nvars:-NA}"
  # per-chip geometry (Griffin/Fp192PowRes/Fp192Mul/Uint256/base) for the area breakdown
  grep -hiE "chip|cols|rows|cells|Fp192|PowRes|Uint256|Griffin|MemoryLocal|Alu|Cpu|Byte" "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null \
    | grep -iE "cells|cols|rows|events" | sort -u > "$dir/trace_geometry_chips.txt"

  local verdict
  if [ "$passed" = true ]; then verdict=OK
  elif grep -qiE "WATCHDOG_KILL|out of bounds|cannot allocate|out of memory|Killed|SIGKILL" "$dir/stderr.log" 2>/dev/null; then verdict="FINDING(bound)"
  else verdict=BUG-NEEDS-FIX; fi

  # -------- RESULT.md --------
  {
    echo "# $id — $label (POW_RES single-arm settle prove)"
    echo
    echo "- date: $(date -Iseconds)"
    echo "- config: PLUM-80 / lambda=80 / M5 Pro 24GB / SP1_PROVER=cpu / standard-Griffin"
    echo "- workload: N_SYMBOLS=28, $note"
    echo "- fork HEAD: $(git -C "$FORK" rev-parse HEAD 2>/dev/null) (dirty = powres guests + settle tests, uncommitted)"
    echo "- test: \`cargo test --release -p sp1-core-machine $test -- --nocapture\`"
    echo
    echo "## Result (OBSERVED, verbatim)"
    echo "- passed(prove+verify): $passed"
    echo "- wall_s: $wall"
    echo "- peak_rss_gb: $peak_gb"
    echo "- total_trace_cells (unpadded, summed over shards): $total_cells"
    echo "- log2(next_pow2(cells)) num_variables: $nvars"
    echo "- verdict: $verdict"
    echo
    echo "## Trace total-cells lines (verbatim)"
    echo '```'
    cat "$dir/trace_total_cells.txt" 2>/dev/null
    echo '```'
    echo
    echo "## Notes"
    echo "- The SETTLE compares b2 vs sm total_trace_cells on the identical 28-symbol"
    echo "  workload. If cells(b2) < cells(sm): B2 precompile PAYS at the full-machine"
    echo "  level (RISCV-cycle saving outweighs the wider precompile chip). If >: it does"
    echo "  not. Per-op keystone: B2 chip 1.22-1.49x LARGER; execute smoke: B2 141x FEWER"
    echo "  RISCV cycles/symbol. This prove is the tie-breaker."
    echo "- total_trace_cells is UNPADDED (pre power-of-2 shard padding). For the padded"
    echo "  proving-area comparison, next_pow2 per chip dominates; both guests are single-"
    echo "  shard at N=28, so the unpadded comparison is the honest per-workload signal."
  } > "$dir/RESULT.md"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" "$wall" "$peak_gb" "$total_cells" "$passed" "$verdict" >> "$MASTER"
  { echo "end:      $(date -Iseconds) wall_s=$wall rc=${R_RC:-NA}"
    echo "passed=$passed peak_gb=$peak_gb total_cells=$total_cells verdict=$verdict"; } >> "$dir/meta.txt"
  log "[$id] verdict=$verdict passed=$passed cells=$total_cells peak=${peak_gb}GB wall=${wall}s"
}

# =============================================================================
: > "$DRIVERLOG"
log "=== CERTAIN-TIER (c) POW_RES settle proves — START ==="
log "fork: $FORK"
log "fork HEAD: $(git -C "$FORK" rev-parse HEAD 2>/dev/null) branch=$(git -C "$FORK" branch --show-current 2>/dev/null)"
printf 'id\tlabel\twall_s\tpeak_gb\ttotal_trace_cells\tpassed\tverdict\n' > "$MASTER"

# Pre-build the test binary OUTSIDE the timed/capped section (no compile-at-
# prove-time). The two prove tests live in the same sp1-core-machine test bin.
log "pre-building sp1-core-machine test binary (no-run) ..."
( cd "$FORK" && cargo test --release -p sp1-core-machine --no-run ) >> "$DRIVERLOG" 2>&1 || \
  log "!! pre-build returned nonzero — proves may compile at run time"

# --- c1: B2-only prove ---
run_prove "c1_powres_b2_prove" "test_fp192_powres_b2_only_prove" \
  "B2-only (1 FP192_POW_RES/symbol)" "28 FP192_POW_RES syscalls, 0 FP192_MUL"

# --- c2: S&M-only prove ---
run_prove "c2_powres_sm_prove" "test_fp192_powres_sm_only_prove" \
  "S&M-only (261 FP192_MUL/symbol)" "7308 FP192_MUL syscalls (28*261), 0 FP192_POW_RES"

# =============================================================================
{
  echo
  echo "=== CERTAIN-TIER (c) SETTLE SUMMARY ==="
  cat "$MASTER"
  echo
  echo "SETTLE read: compare total_trace_cells(c1_b2) vs total_trace_cells(c2_sm)."
  echo "date_end: $(date -Iseconds)"
} | tee -a "$DRIVERLOG"
log "=== CERTAIN-TIER (c) done ==="
echo "CERTAIN_TIER_C_DONE"

# =============================================================================
# (d) RISC0 RE-BASELINE — STAGE ONLY (NOT launched here; ~6h19m > 3h cap).
# -----------------------------------------------------------------------------
# PLUM-verify prove on native Griffin (RISC Zero has no Griffin precompile):
#   cd "$REPO/platforms/zkvms/risc0" && export PATH="$HOME/.cargo/bin:$PATH"
#   PLUM_HOST_MODE=prove PLUM_HOST_HASHER=griffin PLUM_SECURITY=80 \
#     cargo run --release --bin plum_host
# CreGen prove (RISC0):
#   PLUM_HOST_MODE=prove ... cargo run --release --bin bdec_credgen_plum_host
# PREREQUISITE to verify before trusting (d): the RISC0/vc_pqc Griffin must be
#   the SAME standard-MDS Griffin as the SP1 chip (branch griffin-standard-mds-
#   fix). If vc_pqc still carries the non-MDS variant, (d) is NOT a matched
#   re-baseline. CAP NOTE: PLUM-verify ~6h19m EXCEEDS the 3h cap — run it with
#   its own long cap, not the 3h WALL_CAP used above.
# =============================================================================
