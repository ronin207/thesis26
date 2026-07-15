#!/bin/bash
# BDEC CreGen zk-wrap end-to-end guarded probe (FIRST BDEC wrap).
# Mirrors the PASSED run_plum_wrap.sh, with CreGen config (HEIGHT=2^16
# overflow-avoidance) + 5.5h wall cap. Do NOT commit.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
SP1="$REPO/submodules/sp1"
OUTDIR="$REPO/docs/measurements/cregen_wrap_20260707"

# Resolve newest sp1_prover test binary (hash changes each rebuild).
BIN=$(ls -t "$SP1/target/release/deps/" 2>/dev/null | grep -E '^sp1_prover-[0-9a-f]+$' | head -1)
BIN="$SP1/target/release/deps/$BIN"
BINBASE=$(basename "$BIN")

# --- sound-path invariants (verify, not assume) ---
unset SP1_CIRCUIT_MODE                 # stock ~/.sp1/circuits/plonk/v6.1.0
export SP1_PROVER=cpu
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
# NO without_vk_verification, NO mprotect feature (binary built without it)
# --- CreGen Core config (matches measured R2: 289,221,111 cyc / 13206 griffin) ---
export SHARD_SIZE=1048576              # 2^20
export ELEMENT_THRESHOLD=67108864     # 2^26
export HEIGHT_THRESHOLD=65536         # 2^16  <-- REQUIRED: caps deferred-Griffin shard < 2^29, avoids 2^30 round-area overflow
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8
# --- probe inputs ---
export CREGEN_WRAP_ELF_PATH="$REPO/platforms/zkvms/sp1/program_bdec_cregen/elf-syscall/bdec_cregen"
export CREGEN_WRAP_WITNESS_PATH="$OUTDIR/cregen_witness.bin"
export CREGEN_WRAP_PROGRESS_LOG="$OUTDIR/progress.log"
export RUST_LOG="info,sp1_hypercube::prover=debug"

RUNLOG="$OUTDIR/run_cregen_wrap.log"
RSSTSV="$OUTDIR/rss.tsv"
: > "$RSSTSV"
echo "=== run start $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" > "$RUNLOG"
echo "BIN=$BIN" >> "$RUNLOG"
env | grep -E "SHARD_SIZE|ELEMENT_THRESHOLD|HEIGHT_THRESHOLD|TRACE_CHUNK_SLOTS|RAYON_NUM_THREADS|SP1_PROVER|SP1_WORKER|SP1_CIRCUIT_MODE|CREGEN_WRAP" >> "$RUNLOG"
echo "$(date +%s)  STAGE=launch  BIN=$BINBASE HEIGHT_THRESHOLD=65536 wallcap=5.5h softkill=23.5GB" >> "$OUTDIR/progress.log"

/usr/bin/time -l "$BIN" shapes::tests::probe_cregen_plonk_reduced_vkmap --exact --ignored --nocapture --test-threads=1 >> "$RUNLOG" 2>&1 &
tpid=$!

# tree-RSS sampler (KB) every 5s — cross-check on maxRSS, live trajectory + compress peak
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

# 5.5h wall cap
( command sleep 19800; if kill -0 "$tpid" 2>/dev/null; then echo "WALLCAP_5.5H_HIT killing $(date -u +%H:%M:%SZ)" >> "$RUNLOG"; echo "$(date +%s)  STAGE=WALLCAP  5.5h cap hit — killed" >> "$OUTDIR/progress.log"; kill -TERM "$tpid" 2>/dev/null; fi ) &
wallguard=$!

wait "$tpid"; rc=$?
kill "$sampler" "$rssguard" "$wallguard" 2>/dev/null
peak=$(awk -F'\t' 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' "$RSSTSV" 2>/dev/null)
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) sampler_peak_kb=$peak ===" >> "$RUNLOG"
echo "$(date +%s)  STAGE=run_end  rc=$rc sampler_peak_kb=$peak" >> "$OUTDIR/progress.log"
