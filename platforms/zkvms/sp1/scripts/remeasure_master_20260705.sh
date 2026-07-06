#!/usr/bin/env bash
# =============================================================================
# MASTER RE-MEASUREMENT DRIVER  (2026-07-05)  — standard-Griffin chip fix
# -----------------------------------------------------------------------------
# Runs the full thesis re-measurement batch on the corrected Griffin-Fp192 chip
# (standard Griffin: MDS M_4 + quadratic lane-3). Survivable, unattended, with
# per-run triage. NEVER halts on a single failure; stops only after R7.
#
# Sequence:
#   0. WAIT for the already-running Cell-2 recheck (PID 26067 /
#      cell2_recheck_20260705/summary_rows.tsv >= 3 rows). Do NOT relaunch it.
#   R1 Cell-3 PLUM-verify SHA-3 control prove   (COST, n=3, TUNED)
#   R2 CreGen precompile prove (syscall)        (COST, n=1, H16)
#   R3 ShowCre precompile prove k=1 (syscall)   (COST, n=1, H16)
#   R4 ShowCre precompile prove k=2 (syscall)   (COST, n=1, H16)
#   R5 Cell-1 emulated PLUM-verify prove        (FINDING, TUNED, cap 20m)
#   R6 CreGen emulated prove                    (FINDING, H16,   cap 30m)
#   R7 ShowCre k=1 emulated prove               (FINDING, H16,   cap 30m)
#
# Triage per run -> MASTER_SUMMARY.tsv:
#   accepted=true                              -> OK              (COST datum)
#   verify/internal-verifier rejection, or a
#     supposed-success run w/ no receipt        -> BUG-NEEDS-FIX  (log loud, CONTINUE)
#   OOM / round-area-out-of-bounds / SIGKILL /
#     wall-cap-hit                              -> FINDING(bound) (CONTINUE)
#
# Machine gotchas (from project memory):
#   - PATH: rustup succinct toolchain shadows Homebrew rustc.
#   - iCloud EPERM: DIRECT-exec pre-built binary from .build-cache.nosync;
#     NO cargo at run time.
#   - dylib: vc_pqc links liblibiop_c_api.dylib with no LC_RPATH -> export
#     DYLD_LIBRARY_PATH + DIRECT-exec (routing via env/time strips DYLD_*).
#   - detached: launched by python3 Popen(start_new_session=True).
# NOTE: this driver does NOT build. Binaries are pre-built by the launching
#       session. If a binary is missing it is logged and its runs are skipped.
# =============================================================================
set -u   # NOT -e: a single run failure must never exit the batch.

export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"
BINDIR="$CARGO_TARGET_DIR/release"
PLUM_BIN="$BINDIR/plum_host"
CREGEN_BIN="$BINDIR/bdec_cregen_host"
SHOWCRE_BIN="$BINDIR/bdec_showcre_host"

OUT="$REPO/docs/measurements/remeasure_master_20260705"
mkdir -p "$OUT"
DRIVERLOG="$OUT/driver_master.log"
MASTER="$OUT/MASTER_SUMMARY.tsv"

# dylib dir for direct-exec
LIBIOP="$(find "$CARGO_TARGET_DIR/release/build" -name 'liblibiop_c_api.dylib' -exec dirname {} \; 2>/dev/null | sort -u | paste -sd: -)"
export DYLD_LIBRARY_PATH="${LIBIOP:-}"

# scoped trace geometry (metric T2): warn everywhere + debug on the prover
# module that emits per-chip ChipStatistics lines. Coarse per-shard only.
export RUST_LOG="warn,sp1_hypercube::prover=debug"

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

# ---- run a binary with RSS sampler + wall-cap watchdog ----------------------
# uses current exported env; sets global R_RC. dir must exist.
run_capped() {   # $1=bin  $2=dir  $3=cap_s
  local bin="$1" dir="$2" cap="$3"
  printf 'epoch\ttree_rss_kb\n' > "$dir/rss.tsv"
  "$bin" > "$dir/stdout.log" 2>"$dir/stderr.log" &
  local binpid=$!
  ( while kill -0 "$binpid" 2>/dev/null; do
      printf '%s\t%s\n' "$(date +%s)" "$(sum_tree_rss "$binpid")" >> "$dir/rss.tsv"
      sleep 5
    done ) & local samp=$!
  ( local w=0
    while kill -0 "$binpid" 2>/dev/null; do
      sleep 10; w=$((w+10))
      if [ "$w" -ge "$cap" ]; then
        echo "WATCHDOG_KILL cap=${cap}s reached at $(date -Iseconds)" >> "$dir/stderr.log"
        pkill -KILL -P "$binpid" 2>/dev/null || true
        kill -KILL "$binpid" 2>/dev/null || true
        break
      fi
    done ) & local wd=$!
  wait "$binpid"; R_RC=$?
  kill "$samp" "$wd" 2>/dev/null || true
  wait "$samp" 2>/dev/null || true
  wait "$wd"   2>/dev/null || true
}

# ---- bounded execute-mode sanity (cycles + acceptance) ----------------------
# sets globals SANITY_CYCLES, SANITY_ACC. plum=single-arm execute; bdec=compare
# (captures arm A = syscall cycles, the relevant COST-arm count).
do_execute_sanity() {   # $1=dir  $2=bin  $3=hostkind(plum|bdec)  $4=cap_s
  local dir="$1" bin="$2" hk="$3" cap="$4"
  local slog="$dir/execute_sanity.log"
  if [ "$hk" = plum ]; then
    ( PLUM_HOST_MODE=execute RUST_LOG=warn "$bin" ) > "$slog" 2>&1 &
  else
    ( BDEC_HOST_MODE=compare RUST_LOG=warn "$bin" ) > "$slog" 2>&1 &
  fi
  local p=$!
  ( local w=0
    while kill -0 "$p" 2>/dev/null; do
      sleep 5; w=$((w+5))
      if [ "$w" -ge "$cap" ]; then
        echo "SANITY_WATCHDOG_KILL cap=${cap}s" >> "$slog"
        pkill -KILL -P "$p" 2>/dev/null || true
        kill -KILL "$p" 2>/dev/null || true
        break
      fi
    done ) & local wd=$!
  wait "$p" 2>/dev/null || true
  kill "$wd" 2>/dev/null || true; wait "$wd" 2>/dev/null || true
  SANITY_CYCLES="$(grep -oE 'cycles=[0-9]+' "$slog" | head -1 | cut -d= -f2)"
  SANITY_CYCLES="${SANITY_CYCLES:-NA}"
  if grep -q 'accepted=true' "$slog"; then SANITY_ACC=true; else SANITY_ACC=false; fi
}

# ---- config profiles --------------------------------------------------------
set_cfg() {   # $1 = TUNED | H16
  export ELEMENT_THRESHOLD=67108864   # 2^26
  export TRACE_CHUNK_SLOTS=2
  export RAYON_NUM_THREADS=8
  if [ "$1" = TUNED ]; then
    export SHARD_SIZE=4194304          # 2^22
    export HEIGHT_THRESHOLD=1048576    # 2^20
  else
    export SHARD_SIZE=1048576          # 2^20
    export HEIGHT_THRESHOLD=65536      # 2^16
  fi
}

clear_hostenv() {
  unset PLUM_HOST_MODE PLUM_PROVE_ARM PLUM_HASHER PLUM_SECURITY PLUM_ZK_WRAP 2>/dev/null || true
  unset BDEC_HOST_MODE BDEC_PROVE_ARM BDEC_HOST_SECURITY BDEC_SHOWCRE_K 2>/dev/null || true
}

# ---- the workhorse ----------------------------------------------------------
# caller exports host env + calls set_cfg before invoking this.
execute_and_prove() {
  # $1 id  $2 bin  $3 hostkind  $4 expect(COST|FINDING)  $5 cap_s  $6 label
  # $7 dir  $8 sanity(yes|no)  $9 profile-string(for meta)
  local id="$1" bin="$2" hk="$3" expect="$4" cap="$5" label="$6" dir="$7" sanity="$8" prof="$9"
  mkdir -p "$dir"

  if [ ! -x "$bin" ]; then
    log "[$id] SKIP — binary not found: $bin"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$id" "$label" NA NA NA NA NA NA "SKIP-no-binary" >> "$MASTER"
    return
  fi

  {
    echo "=== $id ($label) ==="
    echo "start:        $(date -Iseconds)"
    echo "bin:          $bin"
    echo "bin mtime:    $(stat -f '%Sm' "$bin")"
    echo "hostkind:     $hk    expect: $expect    cap_s: $cap"
    echo "profile:      $prof"
    echo "host env:";    env | grep -E '^(PLUM_|BDEC_)' | sort | sed 's/^/  /'
    echo "config:       SHARD_SIZE=$SHARD_SIZE ELEMENT_THRESHOLD=$ELEMENT_THRESHOLD HEIGHT_THRESHOLD=$HEIGHT_THRESHOLD TRACE_CHUNK_SLOTS=$TRACE_CHUNK_SLOTS RAYON_NUM_THREADS=$RAYON_NUM_THREADS"
    echo "RUST_LOG:     $RUST_LOG"
    echo "DYLD:         $DYLD_LIBRARY_PATH"
    echo "repo HEAD:    $(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
    echo "sp1 sub HEAD: $(git -C "$REPO/submodules/sp1" rev-parse HEAD 2>/dev/null) (working-tree dirty = standard-Griffin chip fix)"
  } > "$dir/meta.txt"

  local CYCLES=NA
  if [ "$sanity" = yes ]; then
    log "[$id] execute-mode sanity (cycles + acceptance)..."
    do_execute_sanity "$dir" "$bin" "$hk" 300
    CYCLES="$SANITY_CYCLES"
    echo "execute_sanity: accepted=$SANITY_ACC cycles=$SANITY_CYCLES" >> "$dir/meta.txt"
    log "[$id] sanity: accepted=$SANITY_ACC cycles=$SANITY_CYCLES"
    if [ "$SANITY_ACC" != true ]; then
      log "[$id] !! WARNING: execute sanity did NOT accept on the fixed chip — a proof-side BUG is likely."
    fi
  fi

  log "[$id] PROVE START (cap ${cap}s)"
  local t0 t1; t0=$(date +%s)
  run_capped "$bin" "$dir" "$cap"
  t1=$(date +%s)
  log "[$id] PROVE END rc=$R_RC wall_s=$((t1-t0))"

  # --- parse ---
  local peak_kb peak_gb pms pmin pbytes accepted
  peak_kb="$(awk -F'\t' 'NR>1 && $2>m{m=$2} END{print m+0}' "$dir/rss.tsv")"
  peak_gb="$(awk "BEGIN{printf \"%.2f\", ${peak_kb:-0}/1048576}")"
  pms="$(grep -oE 'prove_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pms="${pms:-NA}"
  pmin="NA"; [ "$pms" != NA ] && pmin="$(awk "BEGIN{printf \"%.2f\", $pms/60000}")"
  pbytes="$(grep -oE 'proof_bytes=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pbytes="${pbytes:-NA}"
  if [ "$hk" = bdec ]; then
    if grep -q 'accepted=true' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
  else
    if [ "${R_RC:-1}" -eq 0 ] && grep -q 'verify_ms=' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
  fi

  # --- trace geometry (T2) ---
  grep -hE 'Prep Cols =' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_geometry.txt"
  grep -hiE 'griffin' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | grep -E 'Prep Cols =|Rows =|Cells =' | sort -u > "$dir/trace_geometry_griffin.txt"
  grep -hE 'Total number of cells' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_total_cells.txt"

  # --- failure/death signature (bound signals + cycle-at-death) ---
  local boundsig=false verifierrej=false
  if grep -qiE 'round area out of bounds|out of bounds|memory allocation of|cannot allocate|out of memory|Killed: 9|SIGKILL|WATCHDOG_KILL|abort trap' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null; then boundsig=true; fi
  if [ "${R_RC:-1}" -ge 137 ]; then boundsig=true; fi
  if grep -qiE 'internal-verifier|verify failed|guest rejected|verification failed|InvalidProof' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null; then verifierrej=true; fi

  if [ "$accepted" != true ]; then
    grep -hiE 'round area out of bounds|out of bounds|memory allocation|cannot allocate|out of memory|Killed|SIGKILL|WATCHDOG_KILL|panicked|internal-verifier|verify failed|prove.*failed' \
      "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | tail -25 > "$dir/death_signature.txt"
    tail -40 "$dir/stderr.log" > "$dir/death_tail.txt" 2>/dev/null || true
    grep -hoiE '(clk|cycles?|shard)[ =:]+[0-9]+' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | tail -6 > "$dir/death_cycle.txt"
    local dcyc; dcyc="$(grep -hoE '[0-9]+' "$dir/death_cycle.txt" 2>/dev/null | tail -1)"
    [ "$CYCLES" = NA ] && CYCLES="${dcyc:-NA}"
  fi

  # --- triage ---
  local verdict
  if [ "$accepted" = true ]; then
    verdict=OK
  elif [ "$verifierrej" = true ]; then
    verdict=BUG-NEEDS-FIX
  elif [ "$boundsig" = true ]; then
    verdict="FINDING(bound)"
  elif [ "$expect" = FINDING ]; then
    verdict="FINDING(bound)"
  else
    verdict=BUG-NEEDS-FIX
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$label" "$pms" "$pmin" "$pbytes" "$peak_gb" "$accepted" "$CYCLES" "$verdict" >> "$MASTER"

  {
    echo "end:      $(date -Iseconds)"
    echo "rc:       $R_RC   wall_s: $((t1-t0))"
    echo "prove_ms: $pms ($pmin min)   proof_bytes: $pbytes   peak_gb: $peak_gb"
    echo "accepted: $accepted   cycles: $CYCLES"
    echo "verdict:  $verdict"
  } >> "$dir/meta.txt"

  if [ "$verdict" = BUG-NEEDS-FIX ]; then
    log "[$id] *** VERDICT=BUG-NEEDS-FIX  (accepted=$accepted rc=$R_RC) — logged, CONTINUING batch ***"
  else
    log "[$id] verdict=$verdict prove_ms=$pms peak=${peak_gb}GB accepted=$accepted cycles=$CYCLES"
  fi
}

# =============================================================================
# START
# =============================================================================
: > "$DRIVERLOG"
log "=== MASTER RE-MEASUREMENT DRIVER start (standard-Griffin chip) ==="
log "out dir: $OUT"
log "pid=$$  session-leader-sid=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ')"
log "bins: plum=$([ -x "$PLUM_BIN" ] && stat -f '%Sm' "$PLUM_BIN" || echo MISSING) cregen=$([ -x "$CREGEN_BIN" ] && stat -f '%Sm' "$CREGEN_BIN" || echo MISSING) showcre=$([ -x "$SHOWCRE_BIN" ] && stat -f '%Sm' "$SHOWCRE_BIN" || echo MISSING)"

# --- MASTER_SUMMARY header + Cell-2 reference rows ---
printf 'run\tmode\tprove_ms\tprove_min\tproof_bytes\tpeak_gb\taccepted\tcycles\tverdict\n' > "$MASTER"

# --- STEP 0: WAIT for the already-running Cell-2 recheck ---
CELL2_SUM="$REPO/docs/measurements/cell2_recheck_20260705/summary_rows.tsv"
CELL2_PID=26067
log "STEP 0: WAITING on Cell-2 recheck (PID $CELL2_PID / >=3 data rows in $CELL2_SUM). NOT relaunching Cell-2."
while :; do
  rows=0
  [ -f "$CELL2_SUM" ] && rows="$(tail -n +2 "$CELL2_SUM" 2>/dev/null | grep -c '[0-9]' || echo 0)"
  if [ "${rows:-0}" -ge 3 ]; then
    log "STEP 0: Cell-2 has $rows data rows — proceeding."
    break
  fi
  if ! kill -0 "$CELL2_PID" 2>/dev/null; then
    rows=0; [ -f "$CELL2_SUM" ] && rows="$(tail -n +2 "$CELL2_SUM" 2>/dev/null | grep -c '[0-9]' || echo 0)"
    if [ "${rows:-0}" -ge 3 ]; then log "STEP 0: Cell-2 PID gone, $rows rows — proceeding."; break; fi
    log "STEP 0: Cell-2 PID $CELL2_PID gone with only ${rows:-0} rows — proceeding anyway (no relaunch)."
    break
  fi
  sleep 30
done

# fold Cell-2 rows into MASTER_SUMMARY as reference (mode=cell2-syscall-prove)
if [ -f "$CELL2_SUM" ]; then
  awk -F'\t' 'NR>1 && $1 ~ /[0-9]/ {
    pm = ($2!="NA" && $2!="") ? sprintf("%.2f",$2/60000) : "NA";
    printf "cell2.run%s\tcell2-syscall-prove(ref)\t%s\t%s\tNA\t%s\ttrue\tNA\tOK\n", $1, $2, pm, $6
  }' "$CELL2_SUM" >> "$MASTER"
  log "STEP 0: folded Cell-2 reference rows into MASTER_SUMMARY."
fi

# =============================================================================
# COST runs (expect accepted=true)
# =============================================================================

# --- R1: Cell-3 PLUM-verify SHA-3 control, prove, lambda=80, n=3, TUNED ---
for rep in 1 2 3; do
  clear_hostenv; set_cfg TUNED
  export PLUM_HOST_MODE=prove PLUM_PROVE_ARM=sha3 PLUM_HASHER=sha3 PLUM_SECURITY=80 PLUM_ZK_WRAP=core
  san=no; [ "$rep" = 1 ] && san=yes   # sanity once (arm is identical across reps)
  execute_and_prove "R1.run$rep" "$PLUM_BIN" plum COST 2700 "cell3-sha3-prove" \
    "$OUT/R1_cell3_sha3/run$rep" "$san" \
    "TUNED SHARD=2^22 HEIGHT=2^20 ELEMENT=2^26 | PLUM_HOST_MODE=prove PLUM_PROVE_ARM=sha3 lambda=80 zk_wrap=core"
done

# --- R2: CreGen precompile prove, syscall, HEIGHT=2^16, n=1 ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_HOST_SECURITY=80
execute_and_prove "R2" "$CREGEN_BIN" bdec COST 10800 "cregen-syscall-prove" \
  "$OUT/R2_cregen_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall lambda=80"

# --- R3: ShowCre precompile prove k=1, HEIGHT=2^16, n=1 ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_SHOWCRE_K=1 BDEC_HOST_SECURITY=80
execute_and_prove "R3" "$SHOWCRE_BIN" bdec COST 14400 "showcre-k1-syscall-prove" \
  "$OUT/R3_showcre_k1_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall k=1 lambda=80"

# --- R4: ShowCre precompile prove k=2, HEIGHT=2^16, n=1 ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_SHOWCRE_K=2 BDEC_HOST_SECURITY=80
execute_and_prove "R4" "$SHOWCRE_BIN" bdec COST 18000 "showcre-k2-syscall-prove" \
  "$OUT/R4_showcre_k2_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall k=2 lambda=80"

# =============================================================================
# FINDING runs (failure EXPECTED — the failure is the datum)
# =============================================================================

# --- R5: Cell-1 emulated PLUM-verify prove, TUNED, cap 20 min ---
clear_hostenv; set_cfg TUNED
export PLUM_HOST_MODE=prove PLUM_PROVE_ARM=emulated PLUM_SECURITY=80 PLUM_ZK_WRAP=core
execute_and_prove "R5" "$PLUM_BIN" plum FINDING 1200 "cell1-emulated-prove" \
  "$OUT/R5_cell1_emulated" no \
  "TUNED SHARD=2^22 HEIGHT=2^20 ELEMENT=2^26 | PLUM_HOST_MODE=prove PLUM_PROVE_ARM=emulated lambda=80 zk_wrap=core (expect OOM/DNF ~1m45s)"

# --- R6: CreGen emulated prove, HEIGHT=2^16, cap 30 min ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated BDEC_HOST_SECURITY=80
execute_and_prove "R6" "$CREGEN_BIN" bdec FINDING 1800 "cregen-emulated-prove" \
  "$OUT/R6_cregen_emulated" no \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated lambda=80 (expect OOM/DNF)"

# --- R7: ShowCre k=1 emulated prove, HEIGHT=2^16, cap 30 min ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated BDEC_SHOWCRE_K=1 BDEC_HOST_SECURITY=80
execute_and_prove "R7" "$SHOWCRE_BIN" bdec FINDING 1800 "showcre-k1-emulated-prove" \
  "$OUT/R7_showcre_k1_emulated" no \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated k=1 lambda=80 (expect OOM/DNF)"

# =============================================================================
# FINAL SUMMARY
# =============================================================================
{
  echo
  echo "=== MASTER_SUMMARY (all runs) ==="
  cat "$MASTER"
  echo
  echo "=== verdict tally ==="
  awk -F'\t' 'NR>1{v[$9]++} END{for(k in v) printf "  %-16s %d\n", k, v[k]}' "$MASTER"
  echo "date_end: $(date -Iseconds)"
} | tee -a "$DRIVERLOG"

log "=== MASTER RE-MEASUREMENT DRIVER done (R7 reached; batch exhausted) ==="
echo "REMEASURE_MASTER_DONE"
