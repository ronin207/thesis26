#!/usr/bin/env bash
# =============================================================================
# Controlled re-run to settle the PLUM-verify Cell 2 prove-time spread
# (historical 14.89 min vs 32.5 min, same precompile build, only the 32.5
# run had a recorded memory-tuned config).
#
# Runs Cell 2 (Griffin GRIFFIN_FP192_PERMUTE precompile) and Cell 3 (SHA3-256
# control) BACK-TO-BACK at MATCHED config, for BOTH a tuned and a default
# config. Four proves, in this order:
#     1. tuned   Cell 2   (syscall)
#     2. tuned   Cell 3   (sha3)
#     3. default Cell 2   (syscall)
#     4. default Cell 3   (sha3)
#
# Same plum_host binary / invocation as docs/sp1_plum_cell2_measurement.md and
# docs/sp1_plum_cell3_measurement.md (PLUM_PROVE_ARM=syscall -> Cell 2,
# PLUM_PROVE_ARM=sha3 -> Cell 3). Succinct STARK ("core"), NOT zk-wrapped,
# matching the 32.5 / 13.28 min anchors.
#
# Each prove runs to natural completion or a real OS OOM. Peak tree-RSS is
# sampled PASSIVELY (recorded, never used to kill). The script NEVER aborts on
# a failed prove: default-config Cell 2 is EXPECTED to OOM on 24 GB (per
# docs/sp1_plum_cell2_measurement.md: "Default SP1 settings OOM-kill on M5 Pro
# 24GB at ~3 minutes silently via macOS Jetsam"); the run after it must still
# proceed.
#
# Usage:
#   platforms/zkvms/sp1/scripts/controlled_rerun_cell2cell3_20260629.sh --check
#       cheap: build the host binary + execute-mode sanity for both arms, then stop.
#   platforms/zkvms/sp1/scripts/controlled_rerun_cell2cell3_20260629.sh
#       full: --check, then the FOUR proves (hours). Launch AFK.
# =============================================================================
set -u   # undefined-var guard; deliberately NOT -e (run 4 must follow a failed run 3)

# --- rustup succinct toolchain must shadow Homebrew rustc (SP1 guest x-compile)
export PATH="$HOME/.cargo/bin:$PATH"

# --- absolute paths (cwd is not assumed)
REPO_ROOT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
SP1_DIR="$REPO_ROOT/platforms/zkvms/sp1"
SP1_SUBMODULE="$REPO_ROOT/submodules/sp1"
# iCloud-excluded build cache (fixed 2026-06-24); keeps target off iCloud sync.
export CARGO_TARGET_DIR="$REPO_ROOT/.build-cache.nosync"

OUT_ROOT="$REPO_ROOT/docs/measurements/controlled_rerun_20260629"
SUMMARY="$OUT_ROOT/SUMMARY.md"
mkdir -p "$OUT_ROOT"

# SP1 compiled DEFAULTS (verbatim from submodules/sp1/crates/core/executor/src/opts.rs):
#   SHARD_SIZE        = MAX_SHARD_SIZE      = 1<<24            = 16777216    (opts.rs:9,75)
#   ELEMENT_THRESHOLD = (1<<28)+(1<<27)                        = 402653184   (opts.rs:12,78)
#   HEIGHT_THRESHOLD  = 1<<22                                  = 4194304     (opts.rs:14,81)
#   TRACE_CHUNK_SLOTS = DEFAULT_TRACE_CHUNK_SLOTS              = 5           (opts.rs:22,65)
#   RAYON_NUM_THREADS = (read by rayon itself) -> all logical cores = 18 on M5 Pro
NCORES="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 18)"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Sum RSS (KB) over a process and all descendants (cargo's prover child holds the RAM).
sum_tree_rss() {
  local pid="$1" total kid
  total="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; total="${total:-0}"
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    total=$(( total + $(sum_tree_rss "$kid") ))
  done
  echo "$total"
}

# Snapshot of machine state -> stdout. Non-allocating (no bare `memory_pressure`,
# which runs an allocation test by default).
machine_state() {
  echo "timestamp:    $(date -Iseconds)"
  echo "uptime/load:  $(uptime)"
  echo "swapusage:    $(sysctl -n vm.swapusage 2>/dev/null)"
  echo "vm_stat (first 6 lines):"
  vm_stat 2>/dev/null | head -6 | sed 's/^/  /'
}

# Apply the TUNED env block (exactly the documented 32.5/13.28 config).
apply_tuned() {
  export SHARD_SIZE=4194304          # 2^22
  export ELEMENT_THRESHOLD=67108864  # 2^26
  export HEIGHT_THRESHOLD=1048576    # 2^20
  export TRACE_CHUNK_SLOTS=2
  export RAYON_NUM_THREADS=8
}

# Apply the DEFAULT env block: unset the four knobs so SP1's compiled defaults
# apply; pin RAYON to all logical cores (default rayon behaviour, made explicit).
apply_default() {
  unset SHARD_SIZE ELEMENT_THRESHOLD HEIGHT_THRESHOLD TRACE_CHUNK_SLOTS \
        MINIMAL_TRACE_CHUNK_THRESHOLD MEMORY_LIMIT
  export RAYON_NUM_THREADS="$NCORES"
}

# Print the env block actually in effect (unset knobs show "<default>").
dump_env_block() {
  for v in SHARD_SIZE ELEMENT_THRESHOLD HEIGHT_THRESHOLD TRACE_CHUNK_SLOTS \
           MINIMAL_TRACE_CHUNK_THRESHOLD MEMORY_LIMIT RAYON_NUM_THREADS \
           PLUM_HOST_MODE PLUM_PROVE_ARM PLUM_SECURITY PLUM_ZK_WRAP RUST_LOG; do
    eval "val=\${$v:-<default/unset>}"
    echo "  $v=$val"
  done
}

# Capture the executor cycle count for an arm (execute mode, ~seconds). Cycle
# count is invariant to the shard config; captured per-run for completeness.
capture_cycles() {
  local arm="$1" outfile="$2"
  PLUM_HOST_MODE=execute PLUM_PROVE_ARM="$arm" PLUM_SECURITY=80 RUST_LOG=warn \
    cargo run --release --bin plum_host --manifest-path "$SP1_DIR/script/Cargo.toml" \
    >"$outfile" 2>&1 || true
  grep -E 'accepted=.*cycles=' "$outfile" | tail -1
}

# ---------------------------------------------------------------------------
# one full measurement: $1=config (tuned|default)  $2=cell (cell2|cell3)
# ---------------------------------------------------------------------------
run_one() {
  local config="$1" cell="$2" arm
  case "$cell" in
    cell2) arm="syscall" ;;   # Griffin via GRIFFIN_FP192_PERMUTE precompile
    cell3) arm="sha3"    ;;   # SHA3-256 control, Griffin syscall dormant
    *) echo "bad cell $cell"; return 1 ;;
  esac

  case "$config" in
    tuned)   apply_tuned   ;;
    default) apply_default ;;
    *) echo "bad config $config"; return 1 ;;
  esac
  export PLUM_HOST_MODE=prove
  export PLUM_PROVE_ARM="$arm"
  export PLUM_SECURITY=80
  export PLUM_ZK_WRAP=core      # succinct STARK, NOT zk — matches 32.5/13.28 anchors
  export RUST_LOG=warn

  local dir="$OUT_ROOT/${config}_${cell}"
  mkdir -p "$dir"
  local result="$dir/RESULT.md"
  local provelog="$dir/prove.log"
  local cyclelog="$dir/execute_cycles.log"
  local ts; ts="$(date -Iseconds)"
  local head; head="$(git -C "$SP1_SUBMODULE" rev-parse HEAD 2>/dev/null)"

  echo "=============================================================="
  echo ">>> RUN: config=$config cell=$cell arm=$arm  start=$ts"
  echo "=============================================================="

  # --- cycle capture (cheap execute) ---
  local cycleline; cycleline="$(capture_cycles "$arm" "$cyclelog")"
  local cycles; cycles="$(echo "$cycleline" | grep -oE 'cycles=[0-9]+' | cut -d= -f2)"
  cycles="${cycles:-UNKNOWN}"

  # --- pre-prove machine state ---
  local pre_state; pre_state="$(machine_state)"

  # --- the prove (passive peak-RSS sampling; never killed) ---
  local peakfile; peakfile="$(mktemp)"; echo 0 > "$peakfile"
  local start_s; start_s="$(date +%s)"
  ( cd "$SP1_DIR" && cargo run --release --bin plum_host \
        --manifest-path "$SP1_DIR/script/Cargo.toml" ) >"$provelog" 2>&1 &
  local prove_pid=$!
  ( while kill -0 "$prove_pid" 2>/dev/null; do
      kb="$(sum_tree_rss "$prove_pid")"
      prev="$(cat "$peakfile" 2>/dev/null || echo 0)"
      if [ "${kb:-0}" -gt "${prev:-0}" ]; then echo "$kb" > "$peakfile"; fi
      sleep 10
    done ) &
  local mon_pid=$!
  local rc=0; wait "$prove_pid" || rc=$?
  kill "$mon_pid" 2>/dev/null || true
  local end_s; end_s="$(date +%s)"
  local wall_s=$(( end_s - start_s ))

  local peak_kb; peak_kb="$(cat "$peakfile" 2>/dev/null || echo 0)"; rm -f "$peakfile"
  local peak_gb; peak_gb="$(awk "BEGIN{printf \"%.2f\", $peak_kb/1048576}")"

  # host-measured prove time (excludes compile/setup); parse `prove_ms=...`
  local prove_ms; prove_ms="$(grep -oE 'prove_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  prove_ms="${prove_ms:-NA}"
  local prove_min="NA"
  if [ "$prove_ms" != "NA" ]; then
    prove_min="$(awk "BEGIN{printf \"%.2f\", $prove_ms/60000}")"
  fi
  local verify_ms; verify_ms="$(grep -oE 'verify_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  verify_ms="${verify_ms:-NA}"
  local setup_ms; setup_ms="$(grep -oE 'setup_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  setup_ms="${setup_ms:-NA}"

  local outcome="COMPLETED"
  if [ "$rc" -ne 0 ] || [ "$prove_ms" = "NA" ]; then
    outcome="DNF/OOM(rc=$rc)"
  fi

  # --- write RESULT.md ---
  {
    echo "# Controlled re-run RESULT — config=$config, $cell (arm=$arm)"
    echo
    echo "- run timestamp (start): $ts"
    echo "- run timestamp (end):   $(date -Iseconds)"
    echo "- outcome: **$outcome**"
    echo "- SP1 submodule HEAD: \`$head\`"
    echo "- repo HEAD: \`$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)\` on \`$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null)\`"
    echo "- hardware: MacBook Pro M5 Pro, ${NCORES}-core CPU, 24 GB RAM"
    echo
    echo "## Env block actually exported"
    echo '```'
    dump_env_block
    echo '```'
    echo
    echo "## Metrics"
    echo "| metric | value |"
    echo "|---|---|"
    echo "| executor cycles | $cycles |"
    echo "| setup_ms | $setup_ms |"
    echo "| prove_ms (host-measured) | $prove_ms ($prove_min min) |"
    echo "| verify_ms | $verify_ms |"
    echo "| script wall (incl. cargo no-op + prove) | ${wall_s}s ($(awk "BEGIN{printf \"%.2f\", $wall_s/60}") min) |"
    echo "| peak tree RSS | ${peak_kb} KB (${peak_gb} GB) |"
    echo "| prove exit code | $rc |"
    echo
    echo "## execute-mode cycle line (verbatim)"
    echo '```'
    echo "$cycleline"
    echo '```'
    echo
    echo "## Pre-prove machine state"
    echo '```'
    echo "$pre_state"
    echo '```'
    echo
    echo "Full prove log: \`$provelog\`"
  } > "$result"

  # --- append one-line summary row ---
  if [ ! -f "$SUMMARY" ]; then
    {
      echo "# Controlled re-run SUMMARY — Cell 2 / Cell 3 spread (2026-06-29)"
      echo
      echo "SP1 submodule HEAD: \`$head\` | hardware: M5 Pro ${NCORES}c / 24 GB"
      echo "zk_wrap=core (succinct STARK, NOT zk). λ=80."
      echo
      echo "| config | cell | arm | cycles | prove_ms | prove_min | peak_GB | rc | outcome |"
      echo "|---|---|---|---|---|---|---|---|---|"
    } > "$SUMMARY"
  fi
  echo "| $config | $cell | $arm | $cycles | $prove_ms | $prove_min | $peak_gb | $rc | $outcome |" >> "$SUMMARY"

  echo ">>> DONE: config=$config cell=$cell  outcome=$outcome  prove_ms=$prove_ms  peak=${peak_gb}GB  (RESULT: $result)"
  echo
}

# ---------------------------------------------------------------------------
# Phase 0: build once (keeps compile time out of prove_ms) + execute sanity
# ---------------------------------------------------------------------------
echo "=== Controlled re-run Cell2/Cell3 ($(date -Iseconds)) ==="
echo "SP1 submodule HEAD: $(git -C "$SP1_SUBMODULE" rev-parse HEAD 2>/dev/null)"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
echo "--- phase 0: build host + guest ELFs (no prove) ---"
if ! ( cd "$SP1_DIR" && cargo build --release --bin plum_host \
        --manifest-path "$SP1_DIR/script/Cargo.toml" ); then
  echo "[FAIL] build failed — fix before proving."; exit 1
fi
echo "--- phase 0: execute-mode sanity (both arms) ---"
SANITY_C2="$(PLUM_HOST_MODE=execute PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 RUST_LOG=warn \
  cargo run --release --bin plum_host --manifest-path "$SP1_DIR/script/Cargo.toml" 2>&1 | grep -E 'accepted=.*cycles=' | tail -1)"
echo "  cell2 (syscall): $SANITY_C2"
SANITY_C3="$(PLUM_HOST_MODE=execute PLUM_PROVE_ARM=sha3 PLUM_SECURITY=80 RUST_LOG=warn \
  cargo run --release --bin plum_host --manifest-path "$SP1_DIR/script/Cargo.toml" 2>&1 | grep -E 'accepted=.*cycles=' | tail -1)"
echo "  cell3 (sha3):    $SANITY_C3"
if ! echo "$SANITY_C2" | grep -q 'accepted=true'; then echo "[FAIL] cell2 execute did not accept"; exit 1; fi
if ! echo "$SANITY_C3" | grep -q 'accepted=true'; then echo "[FAIL] cell3 execute did not accept"; exit 1; fi
echo "[ok] both arms build + execute + accept."

if [ "${1:-}" = "--check" ]; then
  echo "--check only: stopping before the four proves."
  exit 0
fi

# ---------------------------------------------------------------------------
# Phase 1: the four proves, in the specified order
# ---------------------------------------------------------------------------
run_one tuned   cell2
run_one tuned   cell3
run_one default cell2     # EXPECTED to OOM on 24 GB; script continues regardless
run_one default cell3

echo "=== ALL FOUR RUNS DONE ($(date -Iseconds)) ==="
echo "Summary: $SUMMARY"
cat "$SUMMARY"
