#!/usr/bin/env bash
# run_benchmarks.sh — unified thesis benchmark driver
#
# Dispatches to two benchmark families:
#   * --snark   Rust-side Aurora/Fractal/Noir suites (B1–B5, B7) via bench_runner,
#               PLUS the libiop Fp127² Aurora cells (B8).
#   * --zkvm    RISC Zero zkVM suite (B6) via bench_runner.
#   * --all     both, in order (SNARK first; zkVM second, since B6 is the
#               long-pole and a silent SNARK failure shouldn't waste zkvm hours).
#
# Each benchmark is a bash function prefixed `cell_`. The CELLS array maps
# family|label|funcname. This sidesteps the multi-line shell-quoting trap
# where a heredoc'd cmd gets truncated at the first newline by `read -r`.
#
# Design goals:
#   - Flat, readable: one function per benchmark.
#   - Crash-resilient: each cell → its own log file; exit-code asserted;
#     failures recorded but don't halt the sweep.
#   - Sleep-proof: whole dispatch under `caffeinate -di -s`.
#   - Idempotent: --dry-run prints the list without running anything.
#
# Usage:
#   scripts/run_benchmarks.sh --snark
#   scripts/run_benchmarks.sh --zkvm
#   scripts/run_benchmarks.sh --all
#   scripts/run_benchmarks.sh --dry-run --all
#   scripts/run_benchmarks.sh --tiny --all

set -u

THESIS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$THESIS_ROOT"

TS="$(date +%Y%m%d_%H%M%S)"
MODE=""
DRY=0
TINY=0
RUNS_OVERRIDE=""
ONLY=""   # optional regex; if set, only cells whose label matches are run

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snark) MODE="snark"; shift ;;
    --zkvm)  MODE="zkvm"; shift ;;
    --all)   MODE="all"; shift ;;
    --dry-run) DRY=1; shift ;;
    --tiny) TINY=1; shift ;;
    --runs)  RUNS_OVERRIDE="$2"; shift 2 ;;
    --only)  ONLY="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown flag: $1" >&2; usage 64 ;;
  esac
done
[[ -z "$MODE" ]] && { echo "error: --snark | --zkvm | --all required" >&2; usage 64; }

OUT_DIR="results/bench_run_${TS}"
mkdir -p "$OUT_DIR"
MANIFEST="$OUT_DIR/manifest.txt"
LIBIOP_JSONL="$OUT_DIR/libiop_aurora.jsonl"
export THESIS_ROOT TS OUT_DIR LIBIOP_JSONL  # visible to cell_ functions

echo "# run_benchmarks.sh — mode=$MODE tiny=$TINY runs_override=${RUNS_OVERRIDE:-<config>} ts=$TS" > "$MANIFEST"
echo "# cwd: $THESIS_ROOT" >> "$MANIFEST"
echo "# out: $OUT_DIR" >> "$MANIFEST"
echo "" >> "$MANIFEST"

TINY_FLAG=""; [[ "$TINY" -eq 1 ]] && TINY_FLAG="--tiny"
RUNS_FLAG=""; [[ -n "$RUNS_OVERRIDE" ]] && RUNS_FLAG="--runs $RUNS_OVERRIDE"

# ─────────────────────────────────────────────────────────────────────────────
# Cell functions — one per benchmark. EDIT HERE to add/remove cells.
# Each function's exit code is treated as the cell's pass/fail.
# ─────────────────────────────────────────────────────────────────────────────

br_suite() {
  local label="$1" suite="$2"
  cargo run --release --bin bench_runner -- \
    --suite "$suite" \
    --output "$OUT_DIR/bench_runner_${label}.jsonl" \
    $TINY_FLAG $RUNS_FLAG
}

# Rust-side suites (B1–B5, B7) — via bench_runner.
cell_B1_noir()          { br_suite B1_noir          noir; }
cell_B2_r1cs_compare()  { br_suite B2_r1cs_compare  r1cs-compare; }
cell_B3_circuit_scale() { br_suite B3_circuit_scale circuit-scale; }
cell_B4_backend()       { br_suite B4_backend       backend; }
cell_B5_griffin()       { br_suite B5_griffin       griffin; }
cell_B7_aurora_rerun()  { br_suite B7_aurora_rerun  aurora-rerun; }
cell_B9_pp3_policy()    { br_suite B9_pp3_policy    pp3-policy; }

# libiop Fp127² Aurora cells (B8) — emit wire + run C++ runner + append JSONL.
# Returns the runner's exit code (0=ACCEPT, 1=REJECT, 2=sanity, 137/killed=OOM).
_libiop_run() {
  # $1 label, $2 wire, $3..$N env vars for runner (e.g. ZK=1)
  local label="$1" wire="$2"; shift 2
  local tmpjson; tmpjson=$(mktemp)
  # NB: use ${*:+...} (not ${env_kv[@]}) — safe with set -u on bash 3.2 (macOS).
  echo "[B8] $label: running $wire${*:+ with env=$*}"
  env "$@" SKIP_BUILD=1 bash scripts/fp127_aurora_runner.sh "$wire" \
    | tee /dev/stderr \
    | tail -1 > "$tmpjson"
  local runner_rc=${PIPESTATUS[0]}
  if [[ -s "$tmpjson" ]]; then
    jq -c --arg label "$label" --arg ts "$TS" --arg rc "$runner_rc" \
      '. + {suite:"B8", label:$label, ts:$ts, runner_rc:($rc|tonumber)}' "$tmpjson" \
      >> "$LIBIOP_JSONL" || echo "[B8] $label: jq parse failed on runner output"
  else
    echo "[B8] $label: runner produced no JSON tail (rc=$runner_rc, likely killed)"
  fi
  rm -f "$tmpjson"
  return "$runner_rc"
}

cell_B8_libiop_l80_nozk() {
  set -e
  cargo run --release --bin emit_aurora_r1cs -- --mode bdec --security 80 \
    --out target/aurora_bdec_s80.bdec-r1cs
  _libiop_run B8_libiop_l80_nozk target/aurora_bdec_s80.bdec-r1cs
}

cell_B8_libiop_l128_nozk() {
  set -e
  cargo run --release --bin emit_aurora_r1cs -- --mode bdec --security 128 \
    --out target/aurora_bdec_s128.bdec-r1cs
  _libiop_run B8_libiop_l128_nozk target/aurora_bdec_s128.bdec-r1cs
}

cell_B8_libiop_l128_zk() {
  set -e
  # Reuse the λ=128 wire from the previous cell if it exists; else emit fresh.
  [[ -f target/aurora_bdec_s128.bdec-r1cs ]] || \
    cargo run --release --bin emit_aurora_r1cs -- --mode bdec --security 128 \
      --out target/aurora_bdec_s128.bdec-r1cs
  _libiop_run B8_libiop_l128_zk target/aurora_bdec_s128.bdec-r1cs ZK=1
}

# Soundness negative test — corrupt bytes, skip sanity, expect verifier REJECT.
# Exit code from runner: 0=ACCEPT, 1=REJECT, 2=sanity-caught (shouldn't happen
# because we set SKIP_SATISFIED_CHECK=1). We want rc != 0.
cell_B8_libiop_l128_corrupt() {
  set -e
  local src="target/aurora_bdec_s128.bdec-r1cs"
  local dst="target/aurora_bdec_s128.corrupt.bdec-r1cs"
  [[ -f "$src" ]] || cargo run --release --bin emit_aurora_r1cs -- --mode bdec --security 128 --out "$src"
  cp "$src" "$dst"
  # Corrupt LIVE witness bytes. We can't flip the tail because the BDEC R1CS is
  # padded with zero witness slots up to the next power of two, and those slots
  # aren't referenced by any live constraint — so tail corruption leaves the
  # R1CS satisfied. We parse the header + constraints section to find the
  # witness start offset, then flip a byte inside the first witness element
  # (var_idx=1, guaranteed referenced by constraint 0 in libiop's construction).
  python3 - "$dst" <<'PY'
import struct, sys
p = sys.argv[1]
with open(p, "r+b") as f:
    buf = f.read()
assert buf[:4] == b"BR1S", "bad magic"
version, field_id, elem_bytes = struct.unpack_from("<III", buf, 4)
num_variables, num_inputs, num_constraints = struct.unpack_from("<QQQ", buf, 16)
assert elem_bytes == 16
# Walk the constraint section to find witness start.
off = 40
for _ in range(num_constraints):
    for _row in range(3):
        (nnz,) = struct.unpack_from("<I", buf, off); off += 4
        off += nnz * (4 + 16)  # (var_idx u32, coeff 16B) each
witness_off = off
# Sanity: (len - witness_off) must equal (num_variables - 1) * 16.
assert len(buf) - witness_off == (num_variables - 1) * 16, \
    f"witness size mismatch: {len(buf) - witness_off} vs {(num_variables - 1) * 16}"
# Flip byte at witness_off + 0 (first byte of witness[0] = var_idx 1, live).
# Also flip witness_off + 16 (first byte of witness[1] = var_idx 2, live).
with open(p, "r+b") as f:
    for off in (witness_off, witness_off + 16):
        f.seek(off); b = f.read(1)[0]
        f.seek(off); f.write(bytes([b ^ 0xff]))
print(f"[corrupt] flipped bytes at offsets {witness_off} and {witness_off+16} "
      f"(witness slot 0/1, guaranteed live)")
PY
  # The runner will print WARNING then run; we expect verifier REJECT (rc=1).
  # _libiop_run returns the runner's exit code via `return`, so $? is correct.
  set +e
  _libiop_run B8_libiop_l128_corrupt "$dst" SKIP_SATISFIED_CHECK=1
  local rc=$?
  set -e
  # Runner exit: 0=ACCEPT (bad), 1=REJECT (good), 2=sanity-hit (bad).
  if [[ "$rc" -eq 1 ]]; then
    echo "[B8] corrupt: PASS (verifier rejected as expected)"
    return 0
  else
    echo "[B8] corrupt: FAIL rc=$rc (expected rc=1 = REJECT)"
    return 1
  fi
}

# zkVM full sweep (B6).
cell_B6_zkvm_sweep()    { br_suite B6_zkvm_sweep    zkvm; }

# ─────────────────────────────────────────────────────────────────────────────
# Cell registry. Edit to add/remove.
# Format: "family|label|funcname" — funcname must match a cell_* above.
# ─────────────────────────────────────────────────────────────────────────────
declare -a CELLS=()
if [[ "$MODE" == "snark" || "$MODE" == "all" ]]; then
  CELLS+=(
    "snark|B1_noir|cell_B1_noir"
    "snark|B2_r1cs_compare|cell_B2_r1cs_compare"
    "snark|B3_circuit_scale|cell_B3_circuit_scale"
    "snark|B4_backend|cell_B4_backend"
    "snark|B5_griffin|cell_B5_griffin"
    "snark|B7_aurora_rerun|cell_B7_aurora_rerun"
    "snark|B9_pp3_policy|cell_B9_pp3_policy"
    "snark|B8_libiop_l80_nozk|cell_B8_libiop_l80_nozk"
    "snark|B8_libiop_l128_nozk|cell_B8_libiop_l128_nozk"
    "snark|B8_libiop_l128_zk|cell_B8_libiop_l128_zk"
    "snark|B8_libiop_l128_corrupt|cell_B8_libiop_l128_corrupt"
  )
fi
if [[ "$MODE" == "zkvm" || "$MODE" == "all" ]]; then
  CELLS+=("zkvm|B6_zkvm_sweep|cell_B6_zkvm_sweep")
fi

# ─────────────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────────────

# Apply --only regex filter if set.
if [[ -n "$ONLY" ]]; then
  FILTERED=()
  for cell in "${CELLS[@]}"; do
    IFS='|' read -r fam lab fn <<<"$cell"
    [[ "$lab" =~ $ONLY ]] && FILTERED+=("$cell")
  done
  CELLS=("${FILTERED[@]}")
fi

print_cells() {
  echo "=== benchmark cells (mode=$MODE${ONLY:+ only=/$ONLY/}) ==="
  local i=1
  for cell in "${CELLS[@]}"; do
    IFS='|' read -r fam lab fn <<<"$cell"
    printf "  [%2d] %-6s %-32s -> %s\n" "$i" "$fam" "$lab" "$fn"
    i=$((i+1))
  done
  echo "=== total: ${#CELLS[@]} cells ==="
}

print_cells | tee -a "$MANIFEST"
if [[ "$DRY" -eq 1 ]]; then
  echo "[dry-run] not executing" | tee -a "$MANIFEST"
  exit 0
fi

echo "" >> "$MANIFEST"
echo "=== execution log ===" >> "$MANIFEST"

PASS=0; FAIL=0
for cell in "${CELLS[@]}"; do
  IFS='|' read -r fam lab fn <<<"$cell"
  LOG="$OUT_DIR/bench_${lab}.log"
  START="$(date +%s)"
  echo "[$(date '+%H:%M:%S')] >>> $lab ($fam) — log: $LOG" | tee -a "$MANIFEST"
  # Export cell functions + helpers into the caffeinate'd subshell.
  caffeinate -di -s bash -c "
    set -u
    cd \"$THESIS_ROOT\"
    export THESIS_ROOT=\"$THESIS_ROOT\" TS=\"$TS\" OUT_DIR=\"$OUT_DIR\" LIBIOP_JSONL=\"$LIBIOP_JSONL\"
    export TINY_FLAG=\"$TINY_FLAG\" RUNS_FLAG=\"$RUNS_FLAG\"
    $(declare -f br_suite _libiop_run \
        cell_B1_noir cell_B2_r1cs_compare cell_B3_circuit_scale cell_B4_backend \
        cell_B5_griffin cell_B7_aurora_rerun cell_B9_pp3_policy \
        cell_B8_libiop_l80_nozk cell_B8_libiop_l128_nozk cell_B8_libiop_l128_zk \
        cell_B8_libiop_l128_corrupt cell_B6_zkvm_sweep)
    $fn
  " > "$LOG" 2>&1
  RC=$?
  END="$(date +%s)"
  DUR=$((END - START))
  if [[ $RC -eq 0 ]]; then
    echo "[$(date '+%H:%M:%S')] PASS (${DUR}s)" | tee -a "$MANIFEST"
    PASS=$((PASS+1))
  else
    echo "[$(date '+%H:%M:%S')] FAIL (rc=$RC, ${DUR}s) — see $LOG" | tee -a "$MANIFEST"
    FAIL=$((FAIL+1))
  fi
done

echo "" >> "$MANIFEST"
echo "=== summary: $PASS passed, $FAIL failed, $OUT_DIR ===" | tee -a "$MANIFEST"
exit $(( FAIL > 0 ? 1 : 0 ))
