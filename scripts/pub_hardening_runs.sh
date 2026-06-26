#!/usr/bin/env bash
# Publication-hardening measurement batch (2026-06-10).
#
# Closes the four measurement gaps the adversarial pass identified:
#   S1  Aurora Loquat-verify lambda=80 with ZK ENABLED (the run the
#       security-deployability tension assumes but never had).
#   S2  Aurora Loquat-verify lambda=80, zk=false, n=3 solo runs
#       (variance + clean replacement for the contended 2026-06-10 run).
#   S3  SP1 Loquat-verify prove, tuned settings, n=3 (provenance for
#       tab:loquat-substrate + variance).
#   S4  Cell 2 shard-size sensitivity: SHARD_SIZE in {2^21, 2^22, 2^23}
#       (turns "OOM at defaults" into a memory/time trade-off curve;
#       2^23 may OOM -- that is data, not failure).
#   S5  Cell 2 and Cell 3 repeats at the documented tuning (-> n=3 each
#       including the archived 2026-05 runs).
#   S6  PLONK-wrap memory-floor probe with RSS sampling (expected OOM;
#       captures the demand curve, not a success).
#
# Run stages sequentially, never in parallel (the 2026-06-10 contended
# Aurora run moved 225 s -> 376 s; contention invalidates wall-clocks).
#
# S7 (MANUAL, not automated because it mutates the sp1 fork): the fork's
# shard-budgeting table submodules/sp1/.../artifacts/rv64im_costs.json
# prices GriffinFp192 at 348 columns vs the compiled width 3,819 (and
# GriffinFp192Control at 682 vs 265), so Griffin-bearing shards carry ~10x
# more real area than the ELEMENT_THRESHOLD budget intends. Correct the two
# entries, rebuild, re-run the S5 Cell 2 command, and diff peak RSS +
# wall-clock against the uncorrected runs. Revert the submodule after.
# Usage:
#   scripts/pub_hardening_runs.sh S1 S2          # selected stages
#   scripts/pub_hardening_runs.sh all            # everything (~7 h)
# Recommend: caffeinate -is scripts/pub_hardening_runs.sh all

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP=$(date +%Y%m%d)
OUT="$ROOT/docs/measurements/pub_hardening_${STAMP}"
mkdir -p "$OUT"
export PATH="$HOME/.cargo/bin:$PATH"

TUNE="SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8"

note() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUT/RUNBOOK.log"; }

rss_sampler() { # rss_sampler <pid> <outfile>
  while kill -0 "$1" 2>/dev/null; do
    ps -o rss= -p "$1" 2>/dev/null | awk -v t="$(date +%s)" '{print t"\t"$1}'
    sleep 5
  done > "$2"
}

ensure_wire() {
  WIRE="$ROOT/target/aurora_loquat-verify_s80.loquat-verify-r1cs"
  if [[ ! -f "$WIRE" ]]; then
    note "emitting Loquat-verify wire (security 80)"
    (cd "$ROOT" && cargo run --release --bin emit_aurora_r1cs -- --mode loquat-verify --security 80) \
      > "$OUT/aurora_emit_s80.log" 2>&1
  fi
}

s1() {
  note "S1: Aurora Loquat-verify lambda=80, ZK ENABLED"
  ensure_wire
  (cd "$ROOT" && ZK=1 SKIP_BUILD=1 /usr/bin/time -l scripts/fp127_aurora_runner.sh "$WIRE") \
    > "$OUT/s1_aurora_zk_true.log" 2>&1
  echo "EXIT: $?" >> "$OUT/s1_aurora_zk_true.log"
}

s2() {
  ensure_wire
  for i in 1 2 3; do
    note "S2: Aurora Loquat-verify lambda=80, zk=false, run $i/3"
    (cd "$ROOT" && SKIP_BUILD=1 /usr/bin/time -l scripts/fp127_aurora_runner.sh "$WIRE") \
      > "$OUT/s2_aurora_zk_false_run${i}.log" 2>&1
    echo "EXIT: $?" >> "$OUT/s2_aurora_zk_false_run${i}.log"
  done
}

s3() {
  for i in 1 2 3; do
    note "S3: SP1 Loquat-verify prove (tuned), run $i/3 (~56 min each)"
    (cd "$ROOT/platforms/zkvms/sp1/script" && \
      env $TUNE LOQUAT_MODE=prove RUST_LOG=warn \
      /usr/bin/time -l cargo run --release --bin loquat_host) \
      > "$OUT/s3_sp1_loquat_prove_tuned_run${i}.log" 2>&1
    echo "EXIT: $?" >> "$OUT/s3_sp1_loquat_prove_tuned_run${i}.log"
  done
}

s4() {
  for SS in 2097152 4194304 8388608; do
    note "S4: Cell 2 prove, SHARD_SIZE=$SS (2^21/2^22/2^23 sweep)"
    (cd "$ROOT/platforms/zkvms/sp1" && \
      env SHARD_SIZE=$SS ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 \
      TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8 \
      PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 RUST_LOG=warn \
      /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
      > "$OUT/s4_cell2_shard${SS}.log" 2>&1
    echo "EXIT: $?" >> "$OUT/s4_cell2_shard${SS}.log"
  done
  # Thread-headroom probe: Loquat S3 runs peaked at 59-64% of 24 GB at 8
  # threads, so 12 threads at the documented shard size may fit. OOM here is
  # data (locates the thread ceiling), not failure.
  note "S4: Cell 2 prove, SHARD_SIZE=4194304, RAYON_NUM_THREADS=12 (headroom probe)"
  (cd "$ROOT/platforms/zkvms/sp1" && \
    env SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 \
    TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=12 \
    PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 RUST_LOG=warn \
    /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
    > "$OUT/s4_cell2_shard4194304_t12.log" 2>&1
  echo "EXIT: $?" >> "$OUT/s4_cell2_shard4194304_t12.log"
}

s5() {
  for i in 1 2; do
    note "S5: Cell 2 repeat $i/2 (documented tuning)"
    (cd "$ROOT/platforms/zkvms/sp1" && \
      env $TUNE PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 RUST_LOG=warn \
      /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
      > "$OUT/s5_cell2_repeat${i}.log" 2>&1
    echo "EXIT: $?" >> "$OUT/s5_cell2_repeat${i}.log"
    note "S5: Cell 3 repeat $i/2 (documented tuning)"
    (cd "$ROOT/platforms/zkvms/sp1" && \
      env $TUNE PLUM_HOST_MODE=prove PLUM_PROVE_ARM=sha3 PLUM_SECURITY=80 RUST_LOG=warn \
      /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
      > "$OUT/s5_cell3_repeat${i}.log" 2>&1
    echo "EXIT: $?" >> "$OUT/s5_cell3_repeat${i}.log"
  done
}

s6() {
  note "S6: PLONK wrap memory-floor probe (expected OOM; capturing RSS curve)"
  (cd "$ROOT/platforms/zkvms/sp1" && \
    env SHARD_SIZE=1048576 ELEMENT_THRESHOLD=33554432 HEIGHT_THRESHOLD=524288 \
    TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=4 \
    PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall PLUM_SECURITY=80 PLUM_ZK_WRAP=plonk RUST_LOG=warn \
    /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
    > "$OUT/s6_plonk_wrap_probe.log" 2>&1 &
  PROVE_PID=$!
  sleep 20
  GUEST_PID=$(pgrep -n -f "target/release/plum_host" || echo "$PROVE_PID")
  rss_sampler "$GUEST_PID" "$OUT/s6_plonk_wrap_probe.rss.tsv" &
  wait "$PROVE_PID"
  echo "EXIT: $?" >> "$OUT/s6_plonk_wrap_probe.log"
}

s9() {
  # SP1 BDEC prove at the DOCUMENTED Cell-2 configuration (comparability with
  # Cell 2 overrides any faster setting S4 may find). Succinct STARK, NOT ZK.
  note "S9: SP1 BDEC CreGen prove (lambda=80, documented tuning, ~1h expected)"
  (cd "$ROOT/platforms/zkvms/sp1/script" && \
    env $TUNE BDEC_HOST_MODE=prove RUST_LOG=warn \
    /usr/bin/time -l cargo run --release --bin bdec_cregen_host) \
    > "$OUT/s9_cregen_prove.log" 2>&1
  echo "EXIT: $?" >> "$OUT/s9_cregen_prove.log"
  note "S9: SP1 BDEC ShowCre k=1 prove (lambda=80, documented tuning, ~1.6h expected)"
  (cd "$ROOT/platforms/zkvms/sp1/script" && \
    env $TUNE BDEC_HOST_MODE=prove BDEC_SHOWCRE_K=1 RUST_LOG=warn \
    /usr/bin/time -l cargo run --release --bin bdec_showcre_host) \
    > "$OUT/s9_showcre_k1_prove.log" 2>&1
  echo "EXIT: $?" >> "$OUT/s9_showcre_k1_prove.log"
}

if [[ $# -eq 0 ]]; then echo "usage: $0 S1 [S2 ...] | all" >&2; exit 64; fi
STAGES=("$@"); [[ "$1" == "all" ]] && STAGES=(S1 S2 S3 S4 S5 S6)
note "stages: ${STAGES[*]} -> $OUT"
for st in "${STAGES[@]}"; do
  case "$st" in
    S1) s1 ;; S2) s2 ;; S3) s3 ;; S4) s4 ;; S5) s5 ;; S6) s6 ;; S9) s9 ;;
    *) note "unknown stage $st, skipping" ;;
  esac
done
note "done"

# S9 (run AFTER S2-S6; ~1h + ~1.6h expected): SP1 BDEC prove at lambda=80.
# CreGen = 243M cycles (~1.9x Cell 2), ShowCre k=1 = 363M (~2.9x). First
# credential-level prove attempts on SP1 (the anomaly was RISC Zero's
# pipeline). Build first (contends with nothing once S2-S6 done):
#   cd platforms/zkvms/sp1/script && PATH="$HOME/.cargo/bin:$PATH" cargo build --release --bin bdec_cregen_host --bin bdec_showcre_host
# Then, with the documented Cell-2 tuning:
#   env SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 \
#     TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8 BDEC_HOST_MODE=prove RUST_LOG=warn \
#     /usr/bin/time -l cargo run --release --bin bdec_cregen_host
#   (same for bdec_showcre_host with BDEC_SHOWCRE_K=1)
