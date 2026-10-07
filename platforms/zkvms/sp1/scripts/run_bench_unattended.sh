#!/usr/bin/env bash
# Unattended BDEC benchmark runner.
# - pre-build; run the COMPILED binary from .build-cache.nosync (non-iCloud) so
#   cargo never re-reads the iCloud Cargo.toml at run time (dodges fileproviderd EPERM).
# - DYLD: binary needs @rpath/liblibiop_c_api.dylib but has no LC_RPATH. Export
#   DYLD_LIBRARY_PATH and exec the binary DIRECTLY (NOT via /usr/bin/env or
#   /usr/bin/time -- SIP binaries strip DYLD_* from the child).
# - WATCHDOG: SP1 retries the 2^30 round-area-overflow shard forever, so a failing
#   config never exits. Kill the prove after 2 overflow errors -> fail-fast.
# usage: run_bench.sh <name> <ENV=val ...prove env...>
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"
MANIFEST="$REPO/platforms/zkvms/sp1/script/Cargo.toml"
BIN="$CARGO_TARGET_DIR/release/bdec_cregen_host"
NAME="$1"; shift
OUT="/tmp/bdec_runs/$NAME"; mkdir -p "$OUT"
cd /tmp
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$OUT/meta.txt"; }
log "START name=$NAME sp1_fork=$(git -C "$REPO/submodules/sp1" rev-parse --short HEAD 2>/dev/null)"
log "prove_cfg: $*"

# 1. build
built=0
for a in 1 2 3; do
  if cargo build --release --bin bdec_cregen_host --manifest-path "$MANIFEST" >"$OUT/build.log" 2>&1; then
    log "build OK (attempt $a)"; built=1; break
  fi
  log "build FAIL attempt $a: $(tail -n1 "$OUT/build.log" 2>/dev/null)"; sleep 30
done
[ "$built" = 1 ] || { log "ABORT: build failed 3x"; echo "${NAME}_DONE rc=buildfail"; exit 1; }

# 2. DYLD + env
LIBIOP=$(find "$CARGO_TARGET_DIR/release/build" -name 'liblibiop_c_api.dylib' -exec dirname {} \; 2>/dev/null | sort -u | paste -sd: -)
export DYLD_LIBRARY_PATH="$LIBIOP"
export RUST_LOG=warn
log "DYLD_LIBRARY_PATH set"
for kv in "$@"; do export "$kv"; done

# 3. prove: RSS sampler + direct exec + fail-fast overflow watchdog
( while true; do p=$(pgrep -n -f "release/bdec_cregen_host" 2>/dev/null); [ -n "$p" ] && ps -o rss= -p "$p" 2>/dev/null | awk -v t="$(date +%s)" '{print t"\t"$1}'; sleep 5; done ) >"$OUT/rss.tsv" &
S=$!
T0=$(date +%s)
"$BIN" >"$OUT/stdout.log" 2>"$OUT/stderr.log" &
BINPID=$!
( while kill -0 "$BINPID" 2>/dev/null; do
    if [ "$(grep -c 'round area out of bounds' "$OUT/stdout.log" 2>/dev/null)" -ge 2 ]; then
      echo "[$(date '+%F %T')] WATCHDOG: deterministic 2^30 round-area overflow -> killing prove" | tee -a "$OUT/meta.txt"
      kill "$BINPID" 2>/dev/null; sleep 2; kill -9 "$BINPID" 2>/dev/null; break
    fi
    if [ $(( $(date +%s) - T0 )) -gt "${MAX_WALL:-14400}" ]; then
      echo "[$(date '+%F %T')] WATCHDOG: wall cap ${MAX_WALL:-14400}s exceeded -> killing prove" | tee -a "$OUT/meta.txt"
      kill "$BINPID" 2>/dev/null; sleep 2; kill -9 "$BINPID" 2>/dev/null; break
    fi
    sleep 10
  done ) &
WD=$!
wait "$BINPID"; RC=$?
kill "$WD" "$S" 2>/dev/null
T1=$(date +%s)
PEAK=$(awk 'BEGIN{m=0}{if($2>m)m=$2}END{printf "%.2f",(m+0)/1048576}' "$OUT/rss.tsv" 2>/dev/null)
OVF=$(grep -c 'round area out of bounds' "$OUT/stdout.log" 2>/dev/null || echo 0)
ACC=$(grep -c 'accepted=true' "$OUT/stdout.log" 2>/dev/null || echo 0)
PMS=$(grep -oE 'prove_ms=[0-9]+' "$OUT/stdout.log" 2>/dev/null | head -1)
log "prove END rc=$RC wall_s=$((T1-T0)) peak_rss=${PEAK}GiB overflow_errs=$OVF accepted=$ACC ${PMS:-prove_ms=none}"
grep -Ei "prove_ms=|accepted=|round area|not permitted|not loaded|panic" "$OUT/stdout.log" "$OUT/stderr.log" 2>/dev/null | tail -n 15 >>"$OUT/meta.txt"
echo "${NAME}_DONE rc=$RC wall_s=$((T1-T0)) peak=${PEAK}GiB overflow=$OVF accepted=$ACC ${PMS:-prove_ms=none}"
