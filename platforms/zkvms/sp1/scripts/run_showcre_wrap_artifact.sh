#!/bin/bash
# ARTIFACT RUN (demo prerequisite) — NOT a timing run; wall-clock not citable.
# Same chain as run_showcre_jbind_wrap.sh (the measured 2026-07-11 run), but the
# test variant additionally PERSISTS the final PLONK proof + wrap vk to
# SHOWCRE_ARTIFACT_DIR so the defense demo can verify the ~KB zero-knowledge
# proof of the k=2 statement-bound showing live. Machine may suspend/resume.
#     nohup bash run_showcre_wrap_artifact.sh >detached.out 2>&1 & disown
set -u
export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
SP1="$REPO/submodules/sp1"
OUTDIR="$REPO/docs/measurements/bdec_demo_wrap_20260718"
SRC_WITNESS="$REPO/docs/measurements/showcre_k2_wrap_20260707/showcre_k2_witness.bin"
mkdir -p "$OUTDIR"

# Reuse the exact measured k=2 witness (same GuestInput the jbind ELF reads), so
# this run differs from a plain k=2 wrap ONLY in the ELF (plain -> jbind).
if [ ! -f "$OUTDIR/showcre_k2_witness.bin" ]; then
  cp "$SRC_WITNESS" "$OUTDIR/showcre_k2_witness.bin" || { echo "WITNESS_COPY_FAILED"; exit 3; }
fi

# --- sound-path invariants (verify, not assume) — IDENTICAL to the passed CreGen run ---
unset SP1_CIRCUIT_MODE                 # stock ~/.sp1/circuits/plonk/v6.1.0
export SP1_PROVER=cpu
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
export SHARD_SIZE=1048576              # 2^20
export ELEMENT_THRESHOLD=67108864     # 2^26
export HEIGHT_THRESHOLD=65536         # 2^16  <-- REQUIRED: caps deferred-Griffin shard, avoids 2^30 overflow
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8
# --- probe inputs: the JBIND ELF (this is the whole point) ---
export SHOWCRE_WRAP_ELF_PATH="$REPO/platforms/zkvms/sp1/program_bdec_showcre/elf-jbind/bdec_showcre"
export SHOWCRE_WRAP_WITNESS_PATH="$OUTDIR/showcre_k2_witness.bin"
export SHOWCRE_WRAP_PROGRESS_LOG="$OUTDIR/progress.log"
export SHOWCRE_ARTIFACT_DIR="$REPO/docs/measurements/bdec_demo_artifacts_20260718"
export RUST_LOG="info,sp1_hypercube::prover=debug"

RUNLOG="$OUTDIR/run_showcre_wrap_artifact.log"
RSSTSV="$OUTDIR/rss.tsv"
: > "$RSSTSV"

BIN=$(ls -t "$SP1/target/release/deps/" 2>/dev/null | grep -E '^sp1_prover-[0-9a-f]+$' | head -1)
if [ -z "$BIN" ]; then echo "NO sp1_prover test bin — build: (cd $SP1 && cargo test --release -p sp1-prover --features experimental,native-gnark --no-run)" >> "$RUNLOG"; exit 4; fi
BIN="$SP1/target/release/deps/$BIN"
BINBASE=$(basename "$BIN")

if [ ! -f "$SHOWCRE_WRAP_ELF_PATH" ]; then echo "JBIND_ELF_MISSING $SHOWCRE_WRAP_ELF_PATH" >> "$RUNLOG"; exit 5; fi

echo "=== run start (SHOWCRE k=2 JBIND WRAP ARTIFACT) $(date -u +%Y-%m-%dT%H:%M:%SZ) ELF=elf-jbind/bdec_showcre ===" > "$RUNLOG"
echo "BIN=$BIN" >> "$RUNLOG"
env | grep -E "SHARD_SIZE|ELEMENT_THRESHOLD|HEIGHT_THRESHOLD|TRACE_CHUNK_SLOTS|RAYON_NUM_THREADS|SP1_PROVER|SP1_WORKER|SP1_CIRCUIT_MODE|SHOWCRE_WRAP" >> "$RUNLOG"
echo "$(date +%s)  STAGE=launch  k=2 BIN=$BINBASE JBIND_ELF HEIGHT_THRESHOLD=65536 softkill=23.5GB wallcap=24h" >> "$OUTDIR/progress.log"

caffeinate -dims /usr/bin/time -l "$BIN" shapes::tests::artifact_showcre_plonk_save --exact --ignored --nocapture --test-threads=1 >> "$RUNLOG" 2>&1 &
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
    if [ "${peak:-0}" -gt 24641536 ]; then
      echo "RSS_SOFT_GUARD_HIT peak_kb=$peak killing $(date -u +%H:%M:%SZ)" >> "$RUNLOG"
      echo "$(date +%s)  STAGE=OOM  tree-RSS soft-guard hit peak_kb=$peak (>23.5GB) — killed" >> "$OUTDIR/progress.log"
      kill -TERM "$tpid" 2>/dev/null; break
    fi
    command sleep 10
  done ) &
rssguard=$!

# 24h wall cap (k=2 compress tail is the slow part; k=1 was 11.76h)
( command sleep 86400; if kill -0 "$tpid" 2>/dev/null; then echo "WALLCAP_24H_HIT killing $(date -u +%H:%M:%SZ)" >> "$RUNLOG"; echo "$(date +%s)  STAGE=WALLCAP  24h cap hit — killed" >> "$OUTDIR/progress.log"; kill -TERM "$tpid" 2>/dev/null; fi ) &
wallguard=$!

wait "$tpid"; rc=$?
kill "$sampler" "$rssguard" "$wallguard" 2>/dev/null
peak=$(awk -F'\t' 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' "$RSSTSV" 2>/dev/null)
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) sampler_peak_kb=$peak ===" >> "$RUNLOG"
echo "$(date +%s)  STAGE=run_end  rc=$rc sampler_peak_kb=$peak" >> "$OUTDIR/progress.log"
