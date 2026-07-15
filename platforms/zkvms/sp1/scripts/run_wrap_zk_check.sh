#!/bin/bash
# ZK-verification of the completed gnark PLONK wrap (harness #3, EMPIRICAL).
# Proves the STOCK v6.1.0 PLONK circuit twice on the shipped plonk_witness.json
# (gnark-only, ~20 min total — NO SP1 core/compress/wrap chain) and diffs the
# two raw proofs. Randomized blinding (zk) => proofs DIFFER; deterministic
# (not zk) => byte-identical. This confirms the wrap's PLONK is zero-knowledge
# without re-running the 47-min / 4.2-h chain.
#
# STATIC pre-confirmation (already established, decisive): the gnark fork
# p4u/gnark@cd7874155e26 backend/plonk/bn254/prove.go sets blinding orders
# L/R/O=1, Z=2 (active) and fills them via getRandomPolynomial/SetRandom, so
# PLONK.Prove on this path is zero-knowledge by construction. This run is the
# empirical belt-and-suspenders.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
REPO="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis"
SP1="$REPO/submodules/sp1"
OUTDIR="$REPO/docs/measurements/wrap_zk_check_20260707"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/wrap_zk_check.log"

# Stock plonk artifacts (circuit/pk/vk + witness) — no chain re-run.
export SP1_PLONK_BUILD_DIR="${SP1_PLONK_BUILD_DIR:-$HOME/.sp1/circuits/plonk/v6.1.0}"
export SP1_PLONK_WITNESS="${SP1_PLONK_WITNESS:-$SP1_PLONK_BUILD_DIR/plonk_witness.json}"

echo "=== run start $(date -u +%Y-%m-%dT%H:%M:%SZ) build_dir=$SP1_PLONK_BUILD_DIR ===" > "$LOG"
( cd "$SP1" && cargo test --release -p sp1-recursion-gnark-ffi --features native \
    plonk_zk_determinism_stock_circuit -- --ignored --nocapture --test-threads=1 ) >> "$LOG" 2>&1
rc=$?
echo "=== run end rc=$rc $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" >> "$LOG"
grep -E "PLONK_ZK_CHECK|VERDICT" "$LOG" | tail -8
