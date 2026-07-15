#!/usr/bin/env bash
# CreGen jbind prove — a single statement-bound receipt (synthetic witness).
# Valid for the measurement: prove-time + statement_bound=true are identical to
# a real-attribute run (the relation never inspects the message content).
#
# Run in YOUR OWN Terminal so it survives detached (Claude's background tooling
# kills long jobs a few minutes in):
#     bash "platforms/zkvms/sp1/scripts/run_cregen_jbind.sh"
#
# ~2-3 h. nohup + caffeinate + memory guard, all detached. Keep the LID OPEN +
# on AC (caffeinate can't stop clamshell sleep). Follow with:
#     tail -f docs/measurements/bdec_cregen_jbind_20260710/cregen_jbind_run.log
set -u

export PATH="$HOME/.cargo/bin:$PATH"
export VC_PQC_SKIP_LIBIOP=1
unset SP1_CIRCUIT_MODE 2>/dev/null || true
export SP1_PROVER=cpu
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2
export SHARD_SIZE=1048576
export ELEMENT_THRESHOLD=67108864
export HEIGHT_THRESHOLD=65536
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8
export BDEC_HOST_SECURITY=80
export BDEC_HOST_MODE=prove-jbind

REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"
MANIFEST="$REPO/platforms/zkvms/sp1/script/Cargo.toml"
OUTDIR="$REPO/docs/measurements/bdec_cregen_jbind_20260710"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/cregen_jbind_run.log"

nohup bash -c '
  : > "'"$LOG"'"
  echo "=== CreGen jbind prove (detached, caffeinated, mem-guarded) START $(date -u +%FT%TZ) ===" >> "'"$LOG"'"
  caffeinate -dims cargo run --release --manifest-path "'"$MANIFEST"'" --bin bdec_cregen_host >> "'"$LOG"'" 2>&1 &
  RUN_PID=$!
  low=0
  while kill -0 "$RUN_PID" 2>/dev/null; do
    AVAIL=$(vm_stat | awk "/page size/{ps=\$8}/Pages free/{f=\$3}/Pages inactive/{i=\$3}/Pages purgeable/{p=\$3} END{gsub(/\\./,\"\",f);gsub(/\\./,\"\",i);gsub(/\\./,\"\",p); print int((f+i+p)*ps/1048576)}")
    if [ "${AVAIL:-9999}" -lt 500 ]; then low=$((low+1)); else low=0; fi
    if [ "$low" -ge 2 ]; then
      echo "MEM_GUARD_HIT avail=${AVAIL}MB — killing clean $(date -u +%FT%TZ)" >> "'"$LOG"'"
      pkill -TERM -P "$RUN_PID" 2>/dev/null; kill -TERM "$RUN_PID" 2>/dev/null; sleep 5
      pkill -KILL -P "$RUN_PID" 2>/dev/null; kill -KILL "$RUN_PID" 2>/dev/null; break
    fi
    sleep 8
  done
  wait "$RUN_PID"; RC=$?
  echo "RUN_RC=$RC END $(date -u +%FT%TZ)" >> "'"$LOG"'"
' > /dev/null 2>&1 &
disown

echo "Launched detached (PID $!). CreGen jbind prove, ~2-3 h -> $LOG"
echo "Follow with:  tail -f \"$LOG\""
echo "Keep the lid OPEN + on AC power."
