#!/usr/bin/env bash
# Audit-5 measurement campaign (2026-06-12, rev 2: tmux+caffeinate, Cell 1
# UNCAPPED and moved last, BDEC stage folded in).
#
# Closes the measurement gaps of docs/sako_audits/log.md Audit 5:
#   S5   Cell 2/3 repeats (n=3 with May archives) — defends the 2.45x inversion
#   S4   shard sweep 2^21/2^22/2^23 + 12-thread probe — settings justification
#   B    BDEC repeats (CreGen, ShowCre k=1 -> n=2) + ShowCre k=2 prove (NEW
#        third point: prove-mode linearity of the additive cost model)
#   C1U  Cell 1, documented tuning, UNCAPPED — logs a CHECKPOINT_3H marker in
#        passing (the abstract's three-hour datum) and then runs to its true
#        outcome (completion or OOM), RSS sampled throughout.
#
# Strictly serial; 10-min cooldowns between stages. Launch:
#   tmux new-session -d -s audit5 'caffeinate -is bash scripts/audit5_campaign_20260612.sh'

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/measurements/audit5_campaign_20260612"
mkdir -p "$OUT"
export PATH="$HOME/.cargo/bin:$PATH"
TUNE_ENV=(SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8)
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$OUT/CAMPAIGN.log"; }

log "campaign rev2 start; commit $(cd "$ROOT" && git rev-parse --short HEAD); tmux=$([ -n "${TMUX:-}" ] && echo yes || echo no)"

# ---- stage 0: pre-build (compile time never contaminates run 1) ----
log "STAGE 0: pre-building plum_host + bdec hosts"
(cd "$ROOT/platforms/zkvms/sp1" && cargo build --release --bin plum_host --manifest-path script/Cargo.toml) \
  > "$OUT/stage0_build.log" 2>&1
log "STAGE 0a plum_host exit $?"
(cd "$ROOT/platforms/zkvms/sp1/script" && cargo build --release --bin bdec_cregen_host --bin bdec_showcre_host) \
  >> "$OUT/stage0_build.log" 2>&1
log "STAGE 0b bdec hosts exit $?"

# ---- stage 1: S5 — Cell 2/3 repeats (finding 5) ----
log "STAGE 1: S5 Cell2/Cell3 repeats"
bash "$ROOT/scripts/pub_hardening_runs.sh" S5 >> "$OUT/CAMPAIGN.log" 2>&1
log "STAGE 1 done; cooldown 600s"; sleep 600

# ---- stage 2: S4 — shard sweep + thread probe (settings justification) ----
log "STAGE 2: S4 shard sweep + 12-thread probe"
bash "$ROOT/scripts/pub_hardening_runs.sh" S4 >> "$OUT/CAMPAIGN.log" 2>&1
log "STAGE 2 done; cooldown 600s"; sleep 600

# ---- stage 3: B — BDEC repeats + k=2 point ----
run_bdec() { # run_bdec <label> <bin> [extra env...]
  local label="$1" bin="$2"; shift 2
  log "STAGE 3: $label"
  (cd "$ROOT/platforms/zkvms/sp1/script" && \
    env "${TUNE_ENV[@]}" "$@" BDEC_HOST_MODE=prove RUST_LOG=warn \
    /usr/bin/time -l cargo run --release --bin "$bin") \
    > "$OUT/${label}.log" 2>&1
  echo "EXIT: $?" >> "$OUT/${label}.log"
  log "STAGE 3: $label done; cooldown 600s"; sleep 600
}
run_bdec b1_cregen_prove_repeat2    bdec_cregen_host
run_bdec b2_showcre_k1_prove_repeat2 bdec_showcre_host BDEC_SHOWCRE_K=1
run_bdec b3_showcre_k2_prove         bdec_showcre_host BDEC_SHOWCRE_K=2
log "STAGE 3 done"
touch "$OUT/DONE_BOUNDED"   # everything time-bounded is finished

# ---- stage 4: C1U — Cell 1 uncapped, last (finding 2, then the true outcome) ----
log "STAGE 4: Cell 1 (emulated arm), documented tuning, UNCAPPED"
(cd "$ROOT/platforms/zkvms/sp1" && \
  env "${TUNE_ENV[@]}" PLUM_HOST_MODE=prove PLUM_PROVE_ARM=emulated PLUM_SECURITY=80 RUST_LOG=warn \
  /usr/bin/time -l cargo run --release --bin plum_host --manifest-path script/Cargo.toml) \
  > "$OUT/c1u_cell1_tuned_uncapped.log" 2>&1 &
C1_PID=$!
sleep 30
GUEST_PID=$(pgrep -n -f "target/release/plum_host" || echo "$C1_PID")
( while kill -0 "$GUEST_PID" 2>/dev/null; do
    ps -o rss= -p "$GUEST_PID" 2>/dev/null | awk -v t="$(date +%s)" '{print t"\t"$1}'
    sleep 30
  done ) > "$OUT/c1u_cell1_rss.tsv" &
( sleep 10800
  if kill -0 "$C1_PID" 2>/dev/null; then
    log "CHECKPOINT_3H: Cell 1 still running at the 3-hour mark (the abstract's datum); continuing uncapped"
    echo "CHECKPOINT_3H reached $(date '+%Y-%m-%d %H:%M:%S'), run continues" >> "$OUT/c1u_cell1_tuned_uncapped.log"
  fi ) &
wait "$C1_PID"; C1_EXIT=$?
echo "EXIT: $C1_EXIT" >> "$OUT/c1u_cell1_tuned_uncapped.log"
log "STAGE 4 done (Cell 1 exit $C1_EXIT)"

log "CAMPAIGN_DONE"
touch "$OUT/DONE"
