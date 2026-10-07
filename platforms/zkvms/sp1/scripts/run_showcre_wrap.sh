#!/bin/bash
# BDEC ShowCre zk-wrap end-to-end guarded probe (harness #1).
# Usage:  run_showcre_wrap.sh <K>       (K = 1 or 2)
# Mirrors the PASSED run_cregen_wrap.sh: reduced-vk_map sound chain
# Core->Compress->Shrink->Wrap(BN254)->gnark-PLONK->verify, HEIGHT=2^16
# overflow-avoidance, 23.5 GB tree-RSS soft guard, NO wall cap (ShowCre is
# projected ~5.9h at k=1 / ~7.7h at k=2 — the recursion wall, not RAM, is
# the cost). Self-contained: dumps the witness and builds the sp1_prover
# test binary if missing. Do NOT commit.
set -u
K="${1:?usage: run_showcre_wrap.sh <K>   (1 or 2)}"
export PATH="$HOME/.cargo/bin:$PATH"
export VC_PQC_SKIP_LIBIOP=1
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis"
SP1="$REPO/submodules/sp1"
OUTDIR="$REPO/docs/measurements/showcre_k${K}_wrap_20260707"
SCRIPTDIR="$REPO/platforms/zkvms/sp1/script"
mkdir -p "$OUTDIR"

# --- sound-path invariants (verify, not assume) ---
unset SP1_CIRCUIT_MODE                 # stock ~/.sp1/circuits/plonk/v6.1.0
export SP1_PROVER=cpu
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
# NO without_vk_verification, NO mprotect feature (binary built without it)
# --- Core config (ShowCre has MORE deferred-Griffin shards than CreGen;
#     the 2^16 height cap is REQUIRED to avoid the jagged-PCS 2^30 overflow) ---
export SHARD_SIZE=1048576              # 2^20
export ELEMENT_THRESHOLD=67108864     # 2^26
export HEIGHT_THRESHOLD=65536         # 2^16
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8

# --- probe inputs ---
export SHOWCRE_WRAP_ELF_PATH="$REPO/platforms/zkvms/sp1/program_bdec_showcre/elf-syscall/bdec_showcre"
export SHOWCRE_WRAP_WITNESS_PATH="$OUTDIR/showcre_k${K}_witness.bin"
export SHOWCRE_WRAP_PROGRESS_LOG="$OUTDIR/progress.log"
export RUST_LOG="info,sp1_hypercube::prover=debug"

RUNLOG="$OUTDIR/run_showcre_wrap.log"
RSSTSV="$OUTDIR/rss.tsv"
: > "$RSSTSV"
echo "=== run start k=$K $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" > "$RUNLOG"

# --- Step 0a: dump + validate the witness if missing (fails loud if the ELF
#     drifted from the measured ShowCre k=$K workload) ---
if [ ! -f "$SHOWCRE_WRAP_WITNESS_PATH" ]; then
  echo "$(date +%s)  STAGE=witness_dump k=$K START" >> "$OUTDIR/progress.log"
  BDEC_SHOWCRE_K=$K CARGO_TARGET_DIR="$REPO/.build-cache.nosync" \
    cargo run --release --manifest-path "$SCRIPTDIR/Cargo.toml" \
    --bin showcre_witness_dump -- "$SHOWCRE_WRAP_WITNESS_PATH" >> "$RUNLOG" 2>&1
  if [ ! -f "$SHOWCRE_WRAP_WITNESS_PATH" ]; then
    echo "WITNESS_DUMP_FAILED — see $RUNLOG" >> "$RUNLOG"; exit 3
  fi
fi

# --- Step 0b: build the sp1_prover test binary carrying the new probe if none ---
BIN=$(ls -t "$SP1/target/release/deps/" 2>/dev/null | grep -E '^sp1_prover-[0-9a-f]+$' | head -1)
if [ -z "$BIN" ]; then
  echo "$(date +%s)  STAGE=build_test_bin START" >> "$OUTDIR/progress.log"
  ( cd "$SP1" && cargo test --release -p sp1-prover --features experimental,native-gnark \
      --no-run >> "$RUNLOG" 2>&1 )
  BIN=$(ls -t "$SP1/target/release/deps/" 2>/dev/null | grep -E '^sp1_prover-[0-9a-f]+$' | head -1)
fi
BIN="$SP1/target/release/deps/$BIN"
BINBASE=$(basename "$BIN")
echo "BIN=$BIN" >> "$RUNLOG"
env | grep -E "SHARD_SIZE|ELEMENT_THRESHOLD|HEIGHT_THRESHOLD|TRACE_CHUNK_SLOTS|RAYON_NUM_THREADS|SP1_PROVER|SP1_WORKER|SP1_CIRCUIT_MODE|SHOWCRE_WRAP" >> "$RUNLOG"
echo "$(date +%s)  STAGE=launch  k=$K BIN=$BINBASE HEIGHT_THRESHOLD=65536 softkill=23.5GB nowallcap" >> "$OUTDIR/progress.log"

/usr/bin/time -l "$BIN" shapes::tests::probe_showcre_plonk_reduced_vkmap --exact --ignored --nocapture --test-threads=1 >> "$RUNLOG" 2>&1 &
tpid=$!

# tree-RSS sampler (KB) every 5s
( while kill -0 "$tpid" 2>/dev/null; do
    ts=$(date +%s)
    kb=$(ps -axo rss=,command= | grep "$BINBASE" | grep -v grep | awk '{s+=$1} END{print s+0}')
    printf '%s\t%s\n' "$ts" "${kb:-0}" >> "$RSSTSV"
    command sleep 5
  done ) &
sampler=$!

# 23.5 GB tree-RSS soft guard (protect the 24 GB machine); OOM here is a valid FINDING
( while kill -0 "$tpid" 2>/dev/null; do
    peak=$(awk -F'\t' 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' "$RSSTSV" 2>/dev/null)
    if [ "${peak:-0}" -gt 24641536 ]; then    # 23.5 GB in KB
      echo "RSS_SOFT_GUARD_HIT peak_kb=$peak killing $(date -u +%H:%M:%SZ)" >> "$RUNLOG"
      echo "$(date +%s)  STAGE=OOM  tree-RSS soft-guard hit peak_kb=$peak (>23.5GB) — killed" >> "$OUTDIR/progress.log"
      kill -TERM "$tpid" 2>/dev/null; break
    fi
    command sleep 10
  done ) &
rssguard=$!

wait "$tpid"; rc=$?
kill "$sampler" "$rssguard" 2>/dev/null
peak=$(awk -F'\t' 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' "$RSSTSV" 2>/dev/null)
echo "=== run end k=$K rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) sampler_peak_kb=$peak ===" >> "$RUNLOG"
echo "$(date +%s)  STAGE=run_end  k=$K rc=$rc sampler_peak_kb=$peak" >> "$OUTDIR/progress.log"
