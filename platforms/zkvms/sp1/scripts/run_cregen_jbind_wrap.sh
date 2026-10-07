#!/bin/bash
# BDEC CreGen STATEMENT-BOUND zk-wrap ("binding-and-wrap-in-one-proof").
# Identical sound path to the PASSED run_cregen_wrap.sh (4.20h plain wrap),
# with ONE change: CREGEN_WRAP_ELF_PATH -> the *jbind* ELF (elf-jbind), which
# commits x_cre=(c,h,ppk) to the journal. The wrap preserves the journal in the
# proof's public values, so the wrapped proof is BOTH statement-bound AND ZK.
# Same measured witness as the plain wrap, so the delta isolates the binding
# cost (expected ~0: a few field elements). Blocks on wait; launch DETACHED:
#     nohup bash run_cregen_jbind_wrap.sh >detached.out 2>&1 & disown
set -u
export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis"
SP1="$REPO/submodules/sp1"
OUTDIR="$REPO/docs/measurements/cregen_jbind_wrap_20260711"
SRC_WITNESS="$REPO/docs/measurements/cregen_wrap_20260707/cregen_witness.bin"
mkdir -p "$OUTDIR"

# Reuse the exact measured CreGen witness (same GuestInput the jbind ELF reads),
# so this run differs from the 4.20h plain wrap ONLY in the ELF (plain -> jbind).
if [ ! -f "$OUTDIR/cregen_witness.bin" ]; then
  cp "$SRC_WITNESS" "$OUTDIR/cregen_witness.bin" || { echo "WITNESS_COPY_FAILED"; exit 3; }
fi

# --- sound-path invariants (verify, not assume) — IDENTICAL to the passed run ---
unset SP1_CIRCUIT_MODE                 # stock ~/.sp1/circuits/plonk/v6.1.0
export SP1_PROVER=cpu
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
export SHARD_SIZE=1048576              # 2^20
export ELEMENT_THRESHOLD=67108864     # 2^26
export HEIGHT_THRESHOLD=65536         # 2^16  <-- REQUIRED: caps deferred-Griffin shard, avoids 2^30 overflow
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8
# --- probe inputs: the JBIND ELF (this is the whole point) ---
export CREGEN_WRAP_ELF_PATH="$REPO/platforms/zkvms/sp1/program_bdec_cregen/elf-jbind/bdec_cregen"
export CREGEN_WRAP_WITNESS_PATH="$OUTDIR/cregen_witness.bin"
export CREGEN_WRAP_PROGRESS_LOG="$OUTDIR/progress.log"
export RUST_LOG="info,sp1_hypercube::prover=debug"

RUNLOG="$OUTDIR/run_cregen_jbind_wrap.log"
RSSTSV="$OUTDIR/rss.tsv"
: > "$RSSTSV"

# Resolve newest sp1_prover test binary (must exist; it does per pre-check).
BIN=$(ls -t "$SP1/target/release/deps/" 2>/dev/null | grep -E '^sp1_prover-[0-9a-f]+$' | head -1)
if [ -z "$BIN" ]; then echo "NO sp1_prover test bin — build with: (cd $SP1 && cargo test --release -p sp1-prover --features experimental,native-gnark --no-run)" >> "$RUNLOG"; exit 4; fi
BIN="$SP1/target/release/deps/$BIN"
BINBASE=$(basename "$BIN")

if [ ! -f "$CREGEN_WRAP_ELF_PATH" ]; then echo "JBIND_ELF_MISSING $CREGEN_WRAP_ELF_PATH" >> "$RUNLOG"; exit 5; fi

echo "=== run start (JBIND + WRAP) $(date -u +%Y-%m-%dT%H:%M:%SZ) ELF=elf-jbind/bdec_cregen ===" > "$RUNLOG"
echo "BIN=$BIN" >> "$RUNLOG"
env | grep -E "SHARD_SIZE|ELEMENT_THRESHOLD|HEIGHT_THRESHOLD|TRACE_CHUNK_SLOTS|RAYON_NUM_THREADS|SP1_PROVER|SP1_WORKER|SP1_CIRCUIT_MODE|CREGEN_WRAP" >> "$RUNLOG"
echo "$(date +%s)  STAGE=launch  BIN=$BINBASE JBIND_ELF HEIGHT_THRESHOLD=65536 wallcap=6h softkill=23.5GB" >> "$OUTDIR/progress.log"

caffeinate -dims /usr/bin/time -l "$BIN" shapes::tests::probe_cregen_plonk_reduced_vkmap --exact --ignored --nocapture --test-threads=1 >> "$RUNLOG" 2>&1 &
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

# 6h wall cap (plain wrap was 4.20h; jbind adds negligible)
( command sleep 21600; if kill -0 "$tpid" 2>/dev/null; then echo "WALLCAP_6H_HIT killing $(date -u +%H:%M:%SZ)" >> "$RUNLOG"; echo "$(date +%s)  STAGE=WALLCAP  6h cap hit — killed" >> "$OUTDIR/progress.log"; kill -TERM "$tpid" 2>/dev/null; fi ) &
wallguard=$!

wait "$tpid"; rc=$?
kill "$sampler" "$rssguard" "$wallguard" 2>/dev/null
peak=$(awk -F'\t' 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' "$RSSTSV" 2>/dev/null)
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) sampler_peak_kb=$peak ===" >> "$RUNLOG"
echo "$(date +%s)  STAGE=run_end  rc=$rc sampler_peak_kb=$peak" >> "$OUTDIR/progress.log"
