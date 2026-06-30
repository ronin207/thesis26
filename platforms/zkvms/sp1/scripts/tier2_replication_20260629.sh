#!/usr/bin/env bash
# =============================================================================
# Tier-2 replication: fixed-config, n=3, TUNED-ONLY re-run of Cell 2 & Cell 3.
#
# Adapted from controlled_rerun_cell2cell3_20260629.sh. Question being settled:
# at the single documented tuned config on a clean machine, does Cell-2 prove
# time CLUSTER (=> the historical 14.89..32.5 min spread was machine-state
# variance) or does it STILL span ~15..32 min (=> spread is intrinsic)?
#
# Six proves, back-to-back, all at the SAME tuned config (the documented one
# that completes within 24 GB), in this order:
#     cell2 run1 (syscall) , cell2 run2 , cell2 run3 ,
#     cell3 run1 (sha3)    , cell3 run2 , cell3 run3
# zk_wrap=core (succinct STARK, NOT zk). lambda=80.
#
# Peak tree-RSS sampled PASSIVELY (recorded, never used to kill). Script never
# aborts on a failed prove.
# =============================================================================
set -u

export PATH="$HOME/.cargo/bin:$PATH"

REPO_ROOT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
SP1_DIR="$REPO_ROOT/platforms/zkvms/sp1"
SP1_SUBMODULE="$REPO_ROOT/submodules/sp1"
export CARGO_TARGET_DIR="$REPO_ROOT/.build-cache.nosync"

OUT_ROOT="$REPO_ROOT/docs/measurements/tier2_replication_20260629"
SUMMARY="$OUT_ROOT/SUMMARY.md"
mkdir -p "$OUT_ROOT"

NCORES="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 18)"

# accumulators (parallel arrays indexed by run)
C2_PROVE=() ; C2_PEAK=()
C3_PROVE=() ; C3_PEAK=()

sum_tree_rss() {
  local pid="$1" total kid
  total="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; total="${total:-0}"
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    total=$(( total + $(sum_tree_rss "$kid") ))
  done
  echo "$total"
}

machine_state() {
  echo "timestamp:    $(date -Iseconds)"
  echo "uptime/load:  $(uptime)"
  echo "swapusage:    $(sysctl -n vm.swapusage 2>/dev/null)"
  echo "vm_stat (first 8 lines):"
  vm_stat 2>/dev/null | head -8 | sed 's/^/  /'
}

apply_tuned() {
  export SHARD_SIZE=4194304          # 2^22
  export ELEMENT_THRESHOLD=67108864  # 2^26
  export HEIGHT_THRESHOLD=1048576    # 2^20
  export TRACE_CHUNK_SLOTS=2
  export RAYON_NUM_THREADS=8
}

dump_env_block() {
  for v in SHARD_SIZE ELEMENT_THRESHOLD HEIGHT_THRESHOLD TRACE_CHUNK_SLOTS \
           RAYON_NUM_THREADS PLUM_HOST_MODE PLUM_PROVE_ARM PLUM_SECURITY \
           PLUM_ZK_WRAP RUST_LOG; do
    eval "val=\${$v:-<default/unset>}"
    echo "  $v=$val"
  done
}

capture_cycles() {
  local arm="$1" outfile="$2"
  PLUM_HOST_MODE=execute PLUM_PROVE_ARM="$arm" PLUM_SECURITY=80 RUST_LOG=warn \
    cargo run --release --bin plum_host --manifest-path "$SP1_DIR/script/Cargo.toml" \
    >"$outfile" 2>&1 || true
  grep -E 'accepted=.*cycles=' "$outfile" | tail -1
}

# run_one $1=cell (cell2|cell3)  $2=run index (1..3)
run_one() {
  local cell="$1" idx="$2" arm
  case "$cell" in
    cell2) arm="syscall" ;;
    cell3) arm="sha3"    ;;
    *) echo "bad cell $cell"; return 1 ;;
  esac

  apply_tuned
  export PLUM_HOST_MODE=prove
  export PLUM_PROVE_ARM="$arm"
  export PLUM_SECURITY=80
  export PLUM_ZK_WRAP=core
  export RUST_LOG=warn

  local dir="$OUT_ROOT/${cell}_run${idx}"
  mkdir -p "$dir"
  local result="$dir/RESULT.md"
  local provelog="$dir/prove.log"
  local cyclelog="$dir/execute_cycles.log"
  local ts; ts="$(date -Iseconds)"
  local head; head="$(git -C "$SP1_SUBMODULE" rev-parse HEAD 2>/dev/null)"

  echo "=============================================================="
  echo ">>> RUN: $cell run$idx (arm=$arm)  start=$ts"
  echo "=============================================================="

  local cycleline; cycleline="$(capture_cycles "$arm" "$cyclelog")"
  local cycles; cycles="$(echo "$cycleline" | grep -oE 'cycles=[0-9]+' | cut -d= -f2)"
  cycles="${cycles:-UNKNOWN}"

  local pre_state; pre_state="$(machine_state)"

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

  local prove_ms; prove_ms="$(grep -oE 'prove_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  prove_ms="${prove_ms:-NA}"
  local prove_min="NA"
  [ "$prove_ms" != "NA" ] && prove_min="$(awk "BEGIN{printf \"%.2f\", $prove_ms/60000}")"
  local verify_ms; verify_ms="$(grep -oE 'verify_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  verify_ms="${verify_ms:-NA}"
  local setup_ms; setup_ms="$(grep -oE 'setup_ms=[0-9]+' "$provelog" | head -1 | cut -d= -f2)"
  setup_ms="${setup_ms:-NA}"

  local outcome="COMPLETED"
  if [ "$rc" -ne 0 ] || [ "$prove_ms" = "NA" ]; then outcome="DNF/OOM(rc=$rc)"; fi

  {
    echo "# Tier-2 replication RESULT — $cell run$idx (arm=$arm, tuned config)"
    echo
    echo "- run timestamp (start): $ts"
    echo "- run timestamp (end):   $(date -Iseconds)"
    echo "- outcome: **$outcome**"
    echo "- SP1 submodule HEAD: \`$head\`"
    echo "- repo HEAD: \`$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)\` on \`$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null)\`"
    echo "- hardware: MacBook Pro M5 Pro, ${NCORES}-logical-core CPU, 24 GB RAM"
    echo
    echo "## Env block actually exported (tuned)"
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

  if [ ! -f "$SUMMARY.rows" ]; then
    echo "| cell | run | arm | cycles | prove_ms | prove_min | peak_KB | peak_GB | rc | outcome |" > "$SUMMARY.rows"
    echo "|---|---|---|---|---|---|---|---|---|---|" >> "$SUMMARY.rows"
  fi
  echo "| $cell | $idx | $arm | $cycles | $prove_ms | $prove_min | $peak_kb | $peak_gb | $rc | $outcome |" >> "$SUMMARY.rows"

  # accumulate for stats
  if [ "$cell" = "cell2" ]; then
    C2_PROVE+=("$prove_ms"); C2_PEAK+=("$peak_kb")
  else
    C3_PROVE+=("$prove_ms"); C3_PEAK+=("$peak_kb")
  fi

  echo ">>> DONE: $cell run$idx  outcome=$outcome  prove_ms=$prove_ms ($prove_min min)  peak=${peak_gb}GB"
  echo
}

# stats over a parallel-array pair; echoes "mean_ms min_ms max_ms  mean_peakgb min_peakgb max_peakgb"
emit_stats() {
  local label="$1"; shift
  local n="$1"; shift
  local proves=() peaks=()
  local i
  for ((i=0;i<n;i++)); do proves+=("$1"); shift; done
  for ((i=0;i<n;i++)); do peaks+=("$1"); shift; done
  awk -v label="$label" -v n="$n" '
    BEGIN{
      split("'"${proves[*]}"'", P, " ");
      split("'"${peaks[*]}"'", K, " ");
      pmin=1e18; pmax=-1; psum=0; pcnt=0;
      kmin=1e18; kmax=-1; ksum=0; kcnt=0;
      for(i=1;i<=n;i++){ v=P[i]; if(v=="NA"||v==""){continue} psum+=v; pcnt++; if(v<pmin)pmin=v; if(v>pmax)pmax=v }
      for(i=1;i<=n;i++){ v=K[i]; if(v==""){continue} ksum+=v; kcnt++; if(v<kmin)kmin=v; if(v>kmax)kmax=v }
      pmean=(pcnt? psum/pcnt : 0);
      kmean=(kcnt? ksum/kcnt : 0);
      printf "### %s\n\n", label;
      printf "- prove_ms: mean=%.0f (%.2f min), range=[%.0f .. %.0f] ms = [%.2f .. %.2f min]  (n=%d completed)\n",
             pmean, pmean/60000, pmin, pmax, pmin/60000, pmax/60000, pcnt;
      printf "- peak RSS: mean=%.2f GB, range=[%.2f .. %.2f] GB\n",
             kmean/1048576, kmin/1048576, kmax/1048576;
      printf "- spread: prove max/min = %.2fx\n\n", (pmin>0? pmax/pmin : 0);
    }'
}

# ---------------------------------------------------------------------------
echo "=== Tier-2 replication Cell2/Cell3 n=3 tuned-only ($(date -Iseconds)) ==="
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

if [ "${1:-}" = "--check" ]; then echo "--check only: stopping before the six proves."; exit 0; fi

# ---------------------------------------------------------------------------
run_one cell2 1
run_one cell2 2
run_one cell2 3
run_one cell3 1
run_one cell3 2
run_one cell3 3

# --- assemble SUMMARY.md ---
{
  echo "# Tier-2 replication SUMMARY — Cell 2 / Cell 3, n=3, tuned-only (2026-06-29/30)"
  echo
  echo "SP1 submodule HEAD: \`$(git -C "$SP1_SUBMODULE" rev-parse HEAD 2>/dev/null)\` | hardware: M5 Pro ${NCORES} logical cores / 24 GB"
  echo "zk_wrap=core (succinct STARK, NOT zk). lambda=80. Tuned config:"
  echo "SHARD_SIZE=2^22, ELEMENT_THRESHOLD=2^26, HEIGHT_THRESHOLD=2^20, TRACE_CHUNK_SLOTS=2, RAYON_NUM_THREADS=8."
  echo
  echo "## Per-run rows"
  echo
  cat "$SUMMARY.rows"
  echo
  echo "## Per-cell statistics"
  echo
  emit_stats "Cell 2 (syscall / GRIFFIN_FP192_PERMUTE precompile)" "${#C2_PROVE[@]}" "${C2_PROVE[@]}" "${C2_PEAK[@]}"
  emit_stats "Cell 3 (sha3 control)" "${#C3_PROVE[@]}" "${C3_PROVE[@]}" "${C3_PEAK[@]}"
} > "$SUMMARY"
rm -f "$SUMMARY.rows"

echo "=== ALL SIX RUNS DONE ($(date -Iseconds)) ==="
cat "$SUMMARY"
