#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ITERS="${ITERS:-5}"
MSG_LEN="${MSG_LEN:-32}"

echo "Loquat Table-3-style rows (Rust, Griffin hash)"
echo "Columns: Security & kappa & |sigma| (KiB) & tP (s) & tV (s) & Hash \\\\"
echo

echo "Building loquat_snark_stats (release)..."
cargo build --release --bin loquat_snark_stats
BIN="$ROOT_DIR/target/release/loquat_snark_stats"
echo

for LEVEL in 80 100 128; do
  "$BIN" "$LEVEL" "$MSG_LEN" --paper-table3 --iters "$ITERS" --skip-aurora
done


