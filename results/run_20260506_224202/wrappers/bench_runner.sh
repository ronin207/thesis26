#!/usr/bin/env bash
set -uo pipefail

# Auto-generated wrapper for suite: bench_runner
SUITE_ID='bench_runner'
LOG_FILE='/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/results/run_20260506_224202/logs/bench_runner.log'
STATUS_FILE='/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/results/run_20260506_224202/status/bench_runner'
WORK_DIR='/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis'
FULL_CMD='cargo run --release --bin bench_runner'
LABEL='Full benchmark suite B1-B7 via bench_runner'

# Tee all output to the log file.
exec > >(tee -a "$LOG_FILE") 2>&1

# Set the Terminal window / tab title.
printf '\033]0;vc-pqc | %s\007' "$SUITE_ID"

divider() { printf "%0.s-" $(seq 1 68); echo; }

echo ""
divider
printf "  vc-pqc thesis -- suite: %s\n" "$SUITE_ID"
printf "  %s\n" "$LABEL"
printf "  Started : %s\n" "$(date +'%Y-%m-%d %H:%M:%S')"
printf "  Log     : %s\n" "$LOG_FILE"
divider
echo ""

echo "running" > "$STATUS_FILE"

cd "$WORK_DIR"

EXIT_CODE=0
eval "$FULL_CMD" || EXIT_CODE=$?

echo ""
divider
if [ "$EXIT_CODE" -eq 0 ]; then
    printf "  RESULT : PASSED\n"
    echo "done:0" > "$STATUS_FILE"
else
    printf "  RESULT : FAILED (exit %d)\n" "$EXIT_CODE"
    echo "failed:$EXIT_CODE" > "$STATUS_FILE"
fi
printf "  Finished: %s\n" "$(date +'%Y-%m-%d %H:%M:%S')"
printf "  Log     : %s\n" "$LOG_FILE"
divider
echo ""

echo "Press Enter to close this window..."
read -r || true
