#!/usr/bin/env bash
# =============================================================================
# Cell-2 RE-CHECK after Griffin-Fp192 chip fix (standard Griffin: MDS M_4 +
# quadratic lane-3). n=3 back-to-back Cell-2 proves (PLUM_PROVE_ARM=syscall =
# GRIFFIN_FP192_PERMUTE precompile), lambda=80, zk_wrap=core, TUNED config.
#
# Goal: confirm prove time unchanged vs the tier2 baseline Cell-2 n=3 mean
#       (prove_ms mean=854990 = 14.25 min) AND capture per-chip trace geometry
#       (metric T2) via the sp1_hypercube::prover=debug ChipStatistics lines.
#
# Machine gotchas handled:
#  - PATH: rustup succinct toolchain must shadow Homebrew rustc.
#  - iCloud EPERM: DIRECT-exec the pre-built binary from .build-cache.nosync
#    (NO cargo at run time -> fileproviderd never re-reads iCloud Cargo.toml).
#  - dylib: plum_host links @rpath/liblibiop_c_api.dylib with no LC_RPATH ->
#    export DYLD_LIBRARY_PATH and DIRECT-exec (never via env/time; SIP strips DYLD_*).
#  - detached: this script is launched by python3 Popen(start_new_session=True).
# =============================================================================
set -u
export PATH="$HOME/.cargo/bin:$PATH"

REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
export CARGO_TARGET_DIR="$REPO/.build-cache.nosync"
BIN="$CARGO_TARGET_DIR/release/plum_host"
OUT="$REPO/docs/measurements/cell2_recheck_20260705"
mkdir -p "$OUT"

if [ ! -x "$BIN" ]; then
  echo "[FATAL] pre-built binary not found: $BIN" | tee -a "$OUT/meta.txt"
  echo "CELL2_RECHECK_DONE rc=nobinary"
  exit 1
fi

# --- DYLD for direct-exec (dylib has no LC_RPATH) ---
LIBIOP="$(find "$CARGO_TARGET_DIR/release/build" -name 'liblibiop_c_api.dylib' -exec dirname {} \; 2>/dev/null | sort -u | paste -sd: -)"
export DYLD_LIBRARY_PATH="$LIBIOP"

# --- TUNED shard config (verbatim from tier2_replication_20260629 baseline) ---
export SHARD_SIZE=4194304          # 2^22
export ELEMENT_THRESHOLD=67108864  # 2^26
export HEIGHT_THRESHOLD=1048576    # 2^20
export TRACE_CHUNK_SLOTS=2
export RAYON_NUM_THREADS=8

export PLUM_SECURITY=80
export PLUM_ZK_WRAP=core            # succinct STARK, NOT zk — matches baseline
# scoped debug: warn everywhere + debug ONLY for the prover module that emits
# the per-chip ChipStatistics line (T2). Coarse per-shard spans only; no per-row logs.
export RUST_LOG="warn,sp1_hypercube::prover=debug"

# sum RSS (KB) over a process tree
sum_tree_rss() {
  local pid="$1" total kid
  total="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; total="${total:-0}"
  for kid in $(pgrep -P "$pid" 2>/dev/null || true); do
    total=$(( total + $(sum_tree_rss "$kid") ))
  done
  echo "$total"
}

NCORES="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 18)"

# --- meta.txt: exact config + commit ---
{
  echo "=== cell2_recheck after Griffin-Fp192 fix (standard Griffin: MDS M_4 + quadratic lane-3) ==="
  echo "date_start:        $(date -Iseconds)"
  echo "repo HEAD:         $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
  echo "sp1 submodule HEAD:$(git -C "$REPO/submodules/sp1" rev-parse HEAD)"
  echo "sp1 submodule dirty (the Griffin fix, working-tree):"
  git -C "$REPO/submodules/sp1" status --porcelain=v1 | sed 's/^/    /'
  echo "binary:            $BIN"
  echo "binary mtime:      $(stat -f '%Sm' "$BIN")"
  echo "config:            PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 PLUM_ZK_WRAP=core"
  echo "tuned config:      SHARD_SIZE=2^22 ELEMENT_THRESHOLD=2^26 HEIGHT_THRESHOLD=2^20 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8"
  echo "RUST_LOG:          $RUST_LOG"
  echo "DYLD_LIBRARY_PATH: $DYLD_LIBRARY_PATH"
  echo "hardware:          M5 Pro, ${NCORES} logical cores, 24 GB"
  echo "baseline (tier2 n=3 Cell2): prove_ms mean=854990 (14.25 min), range [843267..876591], peak ~14.21 GB"
  echo
} > "$OUT/meta.txt"

# --- execute-mode sanity (cheap; also the 'launched + no crash' + cycles/syscall signal) ---
echo "[$(date -Iseconds)] execute-mode sanity (Cell-2 syscall arm)..." >> "$OUT/meta.txt"
PLUM_HOST_MODE=execute PLUM_PROVE_ARM=syscall RUST_LOG=warn "$BIN" > "$OUT/execute_sanity.log" 2>&1
SANITY="$(grep -E 'accepted=.*cycles=' "$OUT/execute_sanity.log" | tail -1)"
echo "  sanity: ${SANITY:-<none>}" >> "$OUT/meta.txt"
if ! echo "$SANITY" | grep -q 'accepted=true'; then
  echo "[FATAL] execute-mode sanity did NOT accept — aborting before proves." >> "$OUT/meta.txt"
  echo "CELL2_RECHECK_DONE rc=sanityfail"
  exit 1
fi
echo >> "$OUT/meta.txt"

# --- three proves ---
SUMROWS="$OUT/summary_rows.tsv"
printf 'run\tprove_ms\tprove_min\tverify_ms\tsetup_ms\tpeak_gb\trc\n' > "$SUMROWS"
for idx in 1 2 3; do
  dir="$OUT/run$idx"; mkdir -p "$dir"
  export PLUM_HOST_MODE=prove
  export PLUM_PROVE_ARM=syscall
  echo "[$(date -Iseconds)] === run$idx START (prove, syscall) ===" >> "$OUT/meta.txt"

  printf 'epoch\ttree_rss_kb\n' > "$dir/rss.tsv"
  t0="$(date +%s)"
  "$BIN" > "$dir/stdout.log" 2>"$dir/stderr.log" &
  binpid=$!
  ( while kill -0 "$binpid" 2>/dev/null; do
      kb="$(sum_tree_rss "$binpid")"
      printf '%s\t%s\n' "$(date +%s)" "${kb:-0}" >> "$dir/rss.tsv"
      sleep 5
    done ) &
  samp=$!
  wait "$binpid"; rc=$?
  kill "$samp" 2>/dev/null
  t1="$(date +%s)"

  peak_kb="$(awk -F'\t' 'NR>1 && $2>m{m=$2} END{print m+0}' "$dir/rss.tsv")"
  peak_gb="$(awk "BEGIN{printf \"%.2f\", ${peak_kb:-0}/1048576}")"
  pms="$(grep -oE 'prove_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; pms="${pms:-NA}"
  pmin="NA"; [ "$pms" != "NA" ] && pmin="$(awk "BEGIN{printf \"%.2f\", $pms/60000}")"
  vms="$(grep -oE 'verify_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; vms="${vms:-NA}"
  sms="$(grep -oE 'setup_ms=[0-9]+' "$dir/stdout.log" | head -1 | cut -d= -f2)"; sms="${sms:-NA}"

  # T2: per-chip trace geometry (ChipStatistics Display). Search BOTH streams.
  grep -hE 'Prep Cols =' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_geometry_allchips.txt"
  grep -hiE 'griffin' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | grep -E 'Prep Cols =|Rows =|Cells =' | sort -u > "$dir/trace_geometry_griffin.txt"
  grep -hE 'Total number of cells' "$dir/stdout.log" "$dir/stderr.log" 2>/dev/null | sort -u > "$dir/trace_total_cells.txt"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$idx" "$pms" "$pmin" "$vms" "$sms" "$peak_gb" "$rc" >> "$SUMROWS"
  echo "[$(date -Iseconds)] === run$idx END rc=$rc wall_s=$((t1-t0)) prove_ms=$pms ($pmin min) verify_ms=$vms peak=${peak_gb}GB ===" >> "$OUT/meta.txt"
  echo "  griffin trace geom lines: $(wc -l < "$dir/trace_geometry_griffin.txt" 2>/dev/null | tr -d ' ')" >> "$OUT/meta.txt"
  echo >> "$OUT/meta.txt"
done

# --- summary ---
{
  echo
  echo "=== SUMMARY (n=3 Cell-2 syscall, tuned, zk_wrap=core, lambda=80) ==="
  cat "$SUMROWS"
  awk -F'\t' 'NR>1 && $2!="NA"{s+=$2; c++; if(min==""||$2<min)min=$2; if($2>max)max=$2}
    END{ if(c>0) printf "prove_ms mean=%.0f (%.2f min), range=[%d..%d] ms, n=%d\n", s/c, (s/c)/60000, min, max, c;
         else print "prove_ms: no completed runs" }' "$SUMROWS"
  echo "baseline mean=854990 ms (14.25 min); delta = (this mean) - baseline"
  echo "date_end: $(date -Iseconds)"
} >> "$OUT/meta.txt"

echo "CELL2_RECHECK_DONE"
