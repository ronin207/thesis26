#!/usr/bin/env bash
# =============================================================================
# MASTER MEASUREMENT DRIVER  (2026-07-06)  — finalized thesis batch,
#                                            standard-Griffin chip.
# -----------------------------------------------------------------------------
# Survivable, unattended, per-item triage. NEVER halts on one failure; stops
# only after the last item. Fast items (execute + run-to-failure) run FIRST so
# early data lands; long proves run one-at-a-time to avoid OOM contamination.
#
# Sequence:
#   FAST:
#     M5   PLUM-verify EXECUTE, syscall arm, lambda=80         (3rd curve point)
#     A2e  Leakage EXECUTE, N=20 witnesses (data-independence) (anonymity micro)
#     C1e  Cell-1 emulated PLUM-verify prove   (FINDING, TUNED, cap 20m)
#     R7e  CreGen emulated prove               (FINDING, H16,  cap 30m)
#     R8e  ShowCre k=1 emulated prove          (FINDING, H16,  cap 30m)
#     KFMT Keystone matched-field control EXECUTE (fmt tax; chip-arm FLAGGED)
#   LONG PROVES (one heavy prove at a time):
#     C2   Cell-2 PLUM-verify precompile prove  (COST, n=5, TUNED)
#     C3   Cell-3 PLUM-verify SHA-3 control     (COST, n=5, TUNED)
#     CG   CreGen precompile prove (syscall)    (COST, n=1, H16)
#     S1   ShowCre k=1 precompile prove         (COST, n=1, H16)
#     S2   ShowCre k=2 precompile prove         (COST, n=1, H16)
#     A2p  Leakage PROVE, N=3 (proof-size variance)
#   TABULATION:
#     M2   per-chip trace-area table + execute anchors (no run)
#
# Triage per run -> MASTER_SUMMARY.tsv:
#   accepted=true                              -> OK              (datum)
#   verify/internal-verifier rejection, or a
#     supposed-success run w/ no receipt        -> BUG-NEEDS-FIX  (log loud, CONTINUE)
#   OOM / round-area-out-of-bounds / SIGKILL /
#     wall-cap-hit                              -> FINDING(bound) (CONTINUE)
#   A2e nonzero trace spread                    -> FINDING(leak-located)
#
# Machine gotchas (project memory):
#   - PATH: rustup succinct toolchain shadows Homebrew rustc.
#   - iCloud EPERM: DIRECT-exec pre-built binary from .build-cache.nosync; NO
#     cargo at run time.
#   - dylib: vc_pqc links liblibiop_c_api.dylib with no LC_RPATH -> export
#     DYLD_LIBRARY_PATH + DIRECT-exec (routing via env/time strips DYLD_*).
#   - detached: launched by setsid/Popen(start_new_session=True).
# NOTE: this driver does NOT build. Binaries are pre-built by the launching
#       session. Missing binaries are logged and their runs skipped.
# =============================================================================
set -u   # NOT -e: a single run failure must never exit the batch.

export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"
BINDIR="$CARGO_TARGET_DIR/release"
PLUM_BIN="$BINDIR/plum_host"
LEAK_BIN="$BINDIR/plum_leakage_host"
FMT_BIN="$BINDIR/fmt_keystone_host"
CREGEN_BIN="$BINDIR/bdec_cregen_host"
SHOWCRE_BIN="$BINDIR/bdec_showcre_host"

OUT="$REPO/docs/measurements/master_batch_20260706"
mkdir -p "$OUT"
DRIVERLOG="$OUT/driver_master.log"
MASTER="$OUT/MASTER_SUMMARY.tsv"

# dylib dir for direct-exec
LIBIOP="$(find "$CARGO_TARGET_DIR/release/build" -name 'liblibiop_c_api.dylib' -exec dirname {} \; 2>/dev/null | sort -u | paste -sd: -)"
export DYLD_LIBRARY_PATH="${LIBIOP:-}"

# scoped trace geometry (metric T2 / item M2): warn everywhere + debug on the
# prover module that emits per-chip ChipStatistics lines.
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
  unset PLUM_LEAK_MODE PLUM_LEAK_N 2>/dev/null || true
  unset BDEC_HOST_MODE BDEC_PROVE_ARM BDEC_HOST_SECURITY BDEC_SHOWCRE_K 2>/dev/null || true
}

# ---- common: capture trace geometry + peak RSS + death signature ------------
post_capture() {   # $1=dir
  local dir="$1"
  grep -hE 'Prep Cols =' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_geometry.txt"
  grep -hiE 'griffin|fp192|uint256|poseidon2' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | grep -E 'Prep Cols =|Rows =|Cells =|Cols =' | sort -u > "$dir/trace_geometry_chips.txt"
  grep -hE 'Total number of cells|total cells' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_total_cells.txt"
}
peak_gb_of() {   # $1=dir -> echoes GB
  local dir="$1" peak_kb
  peak_kb="$(awk -F'\t' 'NR>1 && $2>m{m=$2} END{print m+0}' "$dir/rss.tsv" 2>/dev/null)"
  awk "BEGIN{printf \"%.2f\", ${peak_kb:-0}/1048576}"
}
death_capture() {   # $1=dir
  local dir="$1"
  grep -hiE 'round area out of bounds|out of bounds|memory allocation|cannot allocate|out of memory|Killed|SIGKILL|WATCHDOG_KILL|panicked|internal-verifier|verify failed|prove.*failed' \
    "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | tail -25 > "$dir/death_signature.txt"
  tail -40 "$dir/stderr.log" > "$dir/death_tail.txt" 2>/dev/null || true
}
is_boundsig() {   # $1=dir  $2=rc  -> return 0 if bound signal
  local dir="$1" rc="$2"
  if grep -qiE 'round area out of bounds|out of bounds|memory allocation of|cannot allocate|out of memory|Killed: 9|SIGKILL|WATCHDOG_KILL|abort trap' \
     "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null; then return 0; fi
  [ "${rc:-1}" -ge 137 ] && return 0
  return 1
}

# =============================================================================
# EXECUTE-ITEM runner (M5, KFMT): run bin in execute mode, parse cycles/accept.
# =============================================================================
run_execute_item() {  # $1 id  $2 bin  $3 dir  $4 cap  $5 label  $6 prof  $7 parsekind(plum|fmt)
  local id="$1" bin="$2" dir="$3" cap="$4" label="$5" prof="$6" pk="$7"
  mkdir -p "$dir"
  if [ ! -x "$bin" ]; then
    log "[$id] SKIP — binary not found: $bin"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" NA NA NA NA NA NA "SKIP-no-binary" >> "$MASTER"
    return
  fi
  {
    echo "=== $id ($label) ==="
    echo "start:     $(date -Iseconds)"
    echo "bin:       $bin  (mtime $(stat -f '%Sm' "$bin"))"
    echo "profile:   $prof"
    echo "host env:"; env | grep -E '^(PLUM_|BDEC_)' | sort | sed 's/^/  /'
    echo "config:    SHARD_SIZE=${SHARD_SIZE:-NA} ELEMENT_THRESHOLD=${ELEMENT_THRESHOLD:-NA} HEIGHT_THRESHOLD=${HEIGHT_THRESHOLD:-NA} RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-NA}"
    echo "repo HEAD: $(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
    echo "sp1 HEAD:  $(git -C "$REPO/submodules/sp1" rev-parse HEAD 2>/dev/null) (dirty = standard-Griffin chip fix)"
  } > "$dir/meta.txt"

  log "[$id] EXECUTE START (cap ${cap}s)"
  local t0 t1; t0=$(date +%s)
  run_capped "$bin" "$dir" "$cap"
  t1=$(date +%s)
  post_capture "$dir"
  local peak_gb; peak_gb="$(peak_gb_of "$dir")"

  local cycles accepted verdict
  if [ "$pk" = plum ]; then
    cycles="$(grep -oE 'cycles=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; cycles="${cycles:-NA}"
    if grep -q 'accepted=true' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
    { echo "griffin_fp192: $(grep -oE 'griffin_fp192=[0-9]+' "$dir/stdout.log" | head -1)"
      echo "uint256_mul:   $(grep -oE 'uint256_mul=[0-9]+' "$dir/stdout.log" | head -1)"; } >> "$dir/meta.txt"
  else
    # fmt keystone: no accepted line; success = it printed the ratio.
    cycles="$(grep -oE 'per-mult: *[0-9.]+ cycles/mul' "$dir/stdout.log" | head -1 | grep -oE '[0-9.]+' | head -1)"; cycles="${cycles:-NA}"
    if grep -qE 'ratio = c_Fp192' "$dir/stdout.log" && [ "${R_RC:-1}" -eq 0 ]; then accepted=true; else accepted=false; fi
    grep -hE 'per-mult|ratio =|cycle counts|cycles$' "$dir/stdout.log" 2>/dev/null >> "$dir/meta.txt"
  fi

  if [ "$accepted" = true ]; then
    verdict=OK
  elif is_boundsig "$dir" "${R_RC:-1}"; then
    verdict="FINDING(bound)"; death_capture "$dir"
  else
    verdict=BUG-NEEDS-FIX; death_capture "$dir"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" NA NA NA "$peak_gb" "$accepted" "$cycles" "$verdict" >> "$MASTER"
  { echo "end:     $(date -Iseconds)  wall_s=$((t1-t0)) rc=${R_RC:-NA}"
    echo "accepted:$accepted cycles=$cycles peak_gb=$peak_gb verdict=$verdict"; } >> "$dir/meta.txt"
  log "[$id] verdict=$verdict accepted=$accepted cycles=$cycles peak=${peak_gb}GB wall=$((t1-t0))s"
}

# =============================================================================
# A2 LEAKAGE runner (execute variance / prove proof-size variance).
# =============================================================================
run_leakage() {  # $1 id  $2 dir  $3 cap  $4 leakmode(execute|prove)  $5 N  $6 label  $7 prof
  local id="$1" dir="$2" cap="$3" lm="$4" n="$5" label="$6" prof="$7"
  mkdir -p "$dir"
  if [ ! -x "$LEAK_BIN" ]; then
    log "[$id] SKIP — leakage binary not built: $LEAK_BIN  (A2 FLAGGED needs-engineering)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" NA NA NA NA NA NA "FLAGGED-no-binary" >> "$MASTER"
    return
  fi
  export PLUM_LEAK_MODE="$lm" PLUM_LEAK_N="$n" PLUM_SECURITY=80
  {
    echo "=== $id ($label) ==="
    echo "start:   $(date -Iseconds)"
    echo "bin:     $LEAK_BIN  (mtime $(stat -f '%Sm' "$LEAK_BIN"))"
    echo "profile: $prof"
    echo "leak env: PLUM_LEAK_MODE=$lm PLUM_LEAK_N=$n PLUM_SECURITY=80"
    echo "config:  SHARD_SIZE=${SHARD_SIZE:-NA} HEIGHT_THRESHOLD=${HEIGHT_THRESHOLD:-NA}"
    echo "repo HEAD:$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
  } > "$dir/meta.txt"

  log "[$id] LEAKAGE ($lm N=$n) START (cap ${cap}s)"
  local t0 t1; t0=$(date +%s)
  run_capped "$LEAK_BIN" "$dir" "$cap"
  t1=$(date +%s)
  post_capture "$dir"
  local peak_gb; peak_gb="$(peak_gb_of "$dir")"

  local verdict accepted pms pmin pbytes cyc
  pms=NA; pmin=NA; pbytes=NA; cyc=NA
  if [ "$lm" = execute ]; then
    local di allacc
    di="$(grep -oE 'data_independent=(true|false)' "$dir/stdout.log" | head -1 | cut -d= -f2)"
    allacc="$(grep -oE 'all_accepted=(true|false)' "$dir/stdout.log" | head -1 | cut -d= -f2)"
    accepted="${allacc:-false}"
    cyc="$(grep -E '^cycles: +distinct=' "$dir/stdout.log" | grep -oE 'min=[0-9]+' | head -1 | cut -d= -f2)"; cyc="${cyc:-NA}"
    { grep -E 'A2 LEAKAGE VARIANCE|^cycles:|^griffin_fp192:|^uint256_mul:|^sig_bytes:|A2_VERDICT' "$dir/stdout.log" 2>/dev/null; } >> "$dir/meta.txt"
    if [ "$accepted" != true ]; then
      verdict=BUG-NEEDS-FIX; death_capture "$dir"
    elif [ "$di" = true ]; then
      verdict=OK
    else
      verdict="FINDING(leak-located)"
    fi
  else
    if grep -q 'accepted=true' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
    pms="$(grep -oE 'prove_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pms="${pms:-NA}"
    [ "$pms" != NA ] && pmin="$(awk "BEGIN{printf \"%.2f\", $pms/60000}")"
    pbytes="$(grep -oE 'proof_bytes=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pbytes="${pbytes:-NA}"
    { grep -E 'A2 PROOF-SIZE VARIANCE|^proof_bytes:|A2_PROVE_VERDICT|^witness=' "$dir/stdout.log" 2>/dev/null; } >> "$dir/meta.txt"
    if [ "$accepted" = true ]; then verdict=OK
    elif is_boundsig "$dir" "${R_RC:-1}"; then verdict="FINDING(bound)"; death_capture "$dir"
    else verdict=BUG-NEEDS-FIX; death_capture "$dir"; fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" "$pms" "$pmin" "$pbytes" "$peak_gb" "$accepted" "$cyc" "$verdict" >> "$MASTER"
  { echo "end:     $(date -Iseconds)  wall_s=$((t1-t0)) rc=${R_RC:-NA}"; echo "verdict: $verdict"; } >> "$dir/meta.txt"
  log "[$id] verdict=$verdict accepted=$accepted peak=${peak_gb}GB wall=$((t1-t0))s"
}

# =============================================================================
# PROVE runner (cells, creds, emulated findings) — from vetted template.
# =============================================================================
execute_and_prove() {
  # $1 id  $2 bin  $3 hostkind  $4 expect(COST|FINDING)  $5 cap_s  $6 label
  # $7 dir  $8 sanity(yes|no)  $9 profile-string(for meta)
  local id="$1" bin="$2" hk="$3" expect="$4" cap="$5" label="$6" dir="$7" sanity="$8" prof="$9"
  mkdir -p "$dir"
  if [ ! -x "$bin" ]; then
    log "[$id] SKIP — binary not found: $bin"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" NA NA NA NA NA NA "SKIP-no-binary" >> "$MASTER"
    return
  fi
  {
    echo "=== $id ($label) ==="
    echo "start:        $(date -Iseconds)"
    echo "bin:          $bin  (mtime $(stat -f '%Sm' "$bin"))"
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

  local peak_gb pms pmin pbytes accepted
  peak_gb="$(peak_gb_of "$dir")"
  pms="$(grep -oE 'prove_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pms="${pms:-NA}"
  pmin="NA"; [ "$pms" != NA ] && pmin="$(awk "BEGIN{printf \"%.2f\", $pms/60000}")"
  pbytes="$(grep -oE 'proof_bytes=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pbytes="${pbytes:-NA}"
  if [ "$hk" = bdec ]; then
    if grep -q 'accepted=true' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
  else
    if [ "${R_RC:-1}" -eq 0 ] && grep -q 'verify_ms=' "$dir/stdout.log"; then accepted=true; else accepted=false; fi
  fi
  post_capture "$dir"

  local verifierrej=false
  if grep -qiE 'internal-verifier|verify failed|guest rejected|verification failed|InvalidProof' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null; then verifierrej=true; fi

  if [ "$accepted" != true ]; then
    death_capture "$dir"
    grep -hoiE '(clk|cycles?|shard)[ =:]+[0-9]+' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | tail -6 > "$dir/death_cycle.txt"
    local dcyc; dcyc="$(grep -hoE '[0-9]+' "$dir/death_cycle.txt" 2>/dev/null | tail -1)"
    [ "$CYCLES" = NA ] && CYCLES="${dcyc:-NA}"
  fi

  local verdict
  if [ "$accepted" = true ]; then
    verdict=OK
  elif [ "$verifierrej" = true ]; then
    verdict=BUG-NEEDS-FIX
  elif is_boundsig "$dir" "${R_RC:-1}"; then
    verdict="FINDING(bound)"
  elif [ "$expect" = FINDING ]; then
    verdict="FINDING(bound)"
  else
    verdict=BUG-NEEDS-FIX
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" "$pms" "$pmin" "$pbytes" "$peak_gb" "$accepted" "$CYCLES" "$verdict" >> "$MASTER"
  { echo "end:      $(date -Iseconds)"
    echo "rc:       $R_RC   wall_s: $((t1-t0))"
    echo "prove_ms: $pms ($pmin min)   proof_bytes: $pbytes   peak_gb: $peak_gb"
    echo "accepted: $accepted   cycles: $CYCLES   verdict: $verdict"; } >> "$dir/meta.txt"

  if [ "$verdict" = BUG-NEEDS-FIX ]; then
    log "[$id] *** VERDICT=BUG-NEEDS-FIX (accepted=$accepted rc=$R_RC) — logged, CONTINUING batch ***"
  else
    log "[$id] verdict=$verdict prove_ms=$pms peak=${peak_gb}GB accepted=$accepted cycles=$CYCLES"
  fi
}

# =============================================================================
# START
# =============================================================================
: > "$DRIVERLOG"
log "=== MASTER MEASUREMENT DRIVER start (finalized batch, standard-Griffin chip) ==="
log "out dir: $OUT"
log "pid=$$  session-leader-sid=$(ps -o sid= -p $$ 2>/dev/null | tr -d ' ')"
log "bins: plum=$([ -x "$PLUM_BIN" ] && stat -f '%Sm' "$PLUM_BIN" || echo MISSING) leak=$([ -x "$LEAK_BIN" ] && stat -f '%Sm' "$LEAK_BIN" || echo MISSING) fmt=$([ -x "$FMT_BIN" ] && stat -f '%Sm' "$FMT_BIN" || echo MISSING) cregen=$([ -x "$CREGEN_BIN" ] && stat -f '%Sm' "$CREGEN_BIN" || echo MISSING) showcre=$([ -x "$SHOWCRE_BIN" ] && stat -f '%Sm' "$SHOWCRE_BIN" || echo MISSING)"

printf 'run\tmode\tprove_ms\tprove_min\tproof_bytes\tpeak_gb\taccepted\tcycles\tverdict\n' > "$MASTER"

# =============================================================================
# FAST FIRST
# =============================================================================

# --- M5: PLUM-verify EXECUTE, syscall arm, lambda=80 (3rd curve point) ---
clear_hostenv; set_cfg TUNED
export PLUM_HOST_MODE=execute PLUM_PROVE_ARM=syscall PLUM_SECURITY=80
run_execute_item "M5" "$PLUM_BIN" "$OUT/M5_plum_execute_l80" 600 "plum-execute-syscall-l80" \
  "lambda=80 | PLUM_HOST_MODE=execute PLUM_PROVE_ARM=syscall" plum

# --- A2e: leakage EXECUTE, N=20 (data-independence / anonymity micro) ---
clear_hostenv; set_cfg TUNED
run_leakage "A2e" "$OUT/A2e_leakage_execute" 1800 execute 20 "leakage-execute-N20" \
  "lambda=80 | 20 witnesses, fixed pk+M, fresh signing randomness, Cell-2 ELF"

# --- C1e: Cell-1 emulated PLUM-verify prove, TUNED, cap 20 min (FINDING) ---
clear_hostenv; set_cfg TUNED
export PLUM_HOST_MODE=prove PLUM_PROVE_ARM=emulated PLUM_SECURITY=80 PLUM_ZK_WRAP=core
execute_and_prove "C1e" "$PLUM_BIN" plum FINDING 1200 "cell1-emulated-prove" \
  "$OUT/C1e_cell1_emulated" no \
  "TUNED SHARD=2^22 HEIGHT=2^20 ELEMENT=2^26 | prove emulated lambda=80 zk_wrap=core (expect OOM/DNF ~1m45s)"

# --- R7e: CreGen emulated prove, H16, cap 30 min (FINDING) ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated BDEC_HOST_SECURITY=80
execute_and_prove "R7e" "$CREGEN_BIN" bdec FINDING 1800 "cregen-emulated-prove" \
  "$OUT/R7e_cregen_emulated" no \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | prove emulated lambda=80 (expect OOM/DNF)"

# --- R8e: ShowCre k=1 emulated prove, H16, cap 30 min (FINDING) ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=emulated BDEC_SHOWCRE_K=1 BDEC_HOST_SECURITY=80
execute_and_prove "R8e" "$SHOWCRE_BIN" bdec FINDING 1800 "showcre-k1-emulated-prove" \
  "$OUT/R8e_showcre_k1_emulated" no \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | prove emulated k=1 lambda=80 (expect OOM/DNF)"

# --- KFMT: Keystone matched-field control EXECUTE (field-mismatch mul tax) ---
# NB: the DEDICATED FP192_POW_RES / FP192_MUL prove-chips live in the SEPARATE
# fork .claude/worktrees/thesis-restructure-criterion/sp1-fork/ (async smoke
# tests test_fp192_powres_prove / fp192_mul tokio::test). Their chip-prove +
# host-served baseline arms are FLAGGED needs-engineering (see driver footer).
# This run captures the READY execute-mode Fp192-vs-KoalaBear per-mult tax.
clear_hostenv; set_cfg TUNED
run_execute_item "KFMT" "$FMT_BIN" "$OUT/KFMT_keystone_fmt_execute" 1800 "keystone-fmt-matched-field-execute" \
  "execute | Fp192(l=7) vs KoalaBear(l=1) per-mult cycle tax; M=10000/20000 slope" fmt

# =============================================================================
# LONG PROVES (one heavy prove at a time)
# =============================================================================

# --- C2: Cell-2 PLUM-verify precompile prove, lambda=80, n=5, TUNED (COST) ---
for rep in 1 2 3 4 5; do
  clear_hostenv; set_cfg TUNED
  export PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 PLUM_ZK_WRAP=core
  san=no; [ "$rep" = 1 ] && san=yes
  execute_and_prove "C2.run$rep" "$PLUM_BIN" plum COST 2700 "cell2-syscall-prove" \
    "$OUT/C2_cell2_syscall/run$rep" "$san" \
    "TUNED SHARD=2^22 HEIGHT=2^20 ELEMENT=2^26 | prove syscall lambda=80 zk_wrap=core"
done

# --- C3: Cell-3 PLUM-verify SHA-3 control prove, lambda=80, n=5, TUNED (COST) ---
for rep in 1 2 3 4 5; do
  clear_hostenv; set_cfg TUNED
  export PLUM_HOST_MODE=prove PLUM_PROVE_ARM=sha3 PLUM_HASHER=sha3 PLUM_SECURITY=80 PLUM_ZK_WRAP=core
  san=no; [ "$rep" = 1 ] && san=yes
  execute_and_prove "C3.run$rep" "$PLUM_BIN" plum COST 2700 "cell3-sha3-prove" \
    "$OUT/C3_cell3_sha3/run$rep" "$san" \
    "TUNED SHARD=2^22 HEIGHT=2^20 ELEMENT=2^26 | prove sha3 lambda=80 zk_wrap=core"
done

# --- CG: CreGen precompile prove (syscall), H16, n=1 (COST) ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_HOST_SECURITY=80
execute_and_prove "CG" "$CREGEN_BIN" bdec COST 7200 "cregen-syscall-prove" \
  "$OUT/CG_cregen_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | prove syscall lambda=80"

# --- S1: ShowCre precompile prove k=1, H16, n=1 (COST) ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_SHOWCRE_K=1 BDEC_HOST_SECURITY=80
execute_and_prove "S1" "$SHOWCRE_BIN" bdec COST 9000 "showcre-k1-syscall-prove" \
  "$OUT/S1_showcre_k1_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | prove syscall k=1 lambda=80"

# --- S2: ShowCre precompile prove k=2, H16, n=1 (COST) ---
clear_hostenv; set_cfg H16
export BDEC_HOST_MODE=prove BDEC_PROVE_ARM=syscall BDEC_SHOWCRE_K=2 BDEC_HOST_SECURITY=80
execute_and_prove "S2" "$SHOWCRE_BIN" bdec COST 12000 "showcre-k2-syscall-prove" \
  "$OUT/S2_showcre_k2_syscall" yes \
  "H16 SHARD=2^20 HEIGHT=2^16 ELEMENT=2^26 | prove syscall k=2 lambda=80"

# --- A2p: leakage PROVE, N=3 (proof-size variance), TUNED ---
clear_hostenv; set_cfg TUNED
run_leakage "A2p" "$OUT/A2p_leakage_prove" 5400 prove 3 "leakage-prove-N3" \
  "TUNED SHARD=2^22 HEIGHT=2^20 | 3 witnesses core-prove; proof-size variance"

# =============================================================================
# M2 TABULATION (no run): per-chip trace-area table + execute anchors
# =============================================================================
M2="$OUT/M2_trace_area_and_anchors.txt"
{
  echo "=== M2: per-chip trace geometry, harvested from run trace_geometry files ==="
  for d in "$OUT"/*/ "$OUT"/*/run*/; do
    [ -d "$d" ] || continue
    for f in trace_geometry.txt trace_geometry_chips.txt trace_total_cells.txt; do
      if [ -s "$d$f" ]; then
        echo "--- ${d#$OUT/}$f ---"; cat "$d$f"
      fi
    done
  done
  echo
  echo "=== M2: existing EXECUTE anchors (verbatim from docs/four_scheme_benchmark.md) ==="
  awk '/^## Execute-mode cycle anchors/{p=1} p&&/^\| /{print} /^## Prove-mode/{p=0}' \
    "$REPO/docs/four_scheme_benchmark.md" 2>/dev/null
} > "$M2"
log "M2 tabulation written: $M2"

# =============================================================================
# FINAL SUMMARY
# =============================================================================
{
  echo
  echo "=== MASTER_SUMMARY (all runs) ==="
  cat "$MASTER"
  echo
  echo "=== verdict tally ==="
  awk -F'\t' 'NR>1{v[$9]++} END{for(k in v) printf "  %-20s %d\n", k, v[k]}' "$MASTER"
  echo "date_end: $(date -Iseconds)"
} | tee -a "$DRIVERLOG"

log "=== MASTER MEASUREMENT DRIVER done (last item reached; batch exhausted) ==="
echo "MASTER_BATCH_DONE"
