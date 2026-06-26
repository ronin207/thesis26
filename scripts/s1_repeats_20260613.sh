#!/usr/bin/env bash
# S1 repeats 2-3: Aurora Loquat-verify lambda=80 ZK ENABLED (n=1 -> n=3).
# Same build state and wire as the 2026-06-12 S1 run. 600 s cooldown between.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/measurements/audit5_campaign_20260612"
WIRE="$ROOT/target/aurora_loquat-verify_s80.loquat-verify-r1cs"
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$OUT/CAMPAIGN.log"; }
for i in 2 3; do
  log "S1 ZK=1 repeat $i/3 start"
  (cd "$ROOT" && ZK=1 SKIP_BUILD=1 /usr/bin/time -l scripts/fp127_aurora_runner.sh "$WIRE") \
    > "$OUT/s1_aurora_zk_true_repeat${i}.log" 2>&1
  echo "EXIT: $?" >> "$OUT/s1_aurora_zk_true_repeat${i}.log"
  log "S1 ZK=1 repeat $i/3 done; cooldown 600s"
  sleep 600
done
log "S1_REPEATS_DONE"; touch "$OUT/DONE_S1_REPEATS"
