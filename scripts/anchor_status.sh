#!/usr/bin/env bash
# Quick status check for an anchor run.
#
# Usage:
#   bash scripts/anchor_status.sh                # auto-find latest anchor_* dir
#   bash scripts/anchor_status.sh <RESULTS_DIR>

set -uo pipefail

PROJECT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"

if [ "$#" -ge 1 ]; then
  DIR="$1"
else
  DIR=$(ls -td "$PROJECT/results/anchor_"*/ 2>/dev/null | head -1)
  DIR="${DIR%/}"
fi

if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
  echo "no anchor run dir found"
  exit 1
fi

echo "dir:    $DIR"
echo "status: $(cat "$DIR/anchor.status" 2>/dev/null || echo 'unknown')"
echo

if [ -f "$DIR/anchor.pid" ]; then
  PID=$(cat "$DIR/anchor.pid")
  if ps -p "$PID" > /dev/null 2>&1; then
    RSS_KB=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
    RSS_MB=$(( RSS_KB / 1024 ))
    ETIME=$(ps -o etime= -p "$PID" 2>/dev/null | tr -d ' ')
    echo "process pid=$PID alive  rss=${RSS_MB}MB  elapsed=${ETIME}"
  else
    echo "process pid=$PID NOT running"
  fi
fi
echo

if [ -f "$DIR/anchor.json" ] && [ -s "$DIR/anchor.json" ]; then
  echo "result:"
  cat "$DIR/anchor.json"
  echo
fi

if [ -f "$DIR/anchor.log" ]; then
  echo "log tail (last 15 lines):"
  tail -15 "$DIR/anchor.log"
fi
