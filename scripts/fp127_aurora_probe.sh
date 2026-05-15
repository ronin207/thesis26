#!/usr/bin/env bash
# Build + run the Aurora-over-Fp2_M127 template-instantiation probe.
#
# This is a pure compilation canary: it tries to instantiate
#   aurora_snark_prover<libff::fp127_Fq2, binary_hash_digest>
# from a small standalone .cpp, links against the cargo-built libiop.a + libff.a,
# and runs a ~64-constraint R1CS example to confirm the verifier accepts.
#
# Usage:
#   scripts/fp127_aurora_probe.sh            # log_n = 6  (64 constraints)
#   scripts/fp127_aurora_probe.sh 8 31       # log_n = 8, num_inputs = 31

set -euo pipefail

THESIS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$THESIS_ROOT"

LIBIOP_A=$(ls -t target/*/build/vc-pqc-*/out/build/libiop/libiop.a 2>/dev/null | head -1 || true)
LIBFF_A=$(ls -t target/*/build/vc-pqc-*/out/build/depends/libff/libff/libff.a 2>/dev/null | head -1 || true)

if [[ -z "${LIBIOP_A:-}" || -z "${LIBFF_A:-}" ]]; then
  echo "error: missing libiop.a or libff.a; run \`cargo build\` first" >&2
  exit 1
fi

# Both archives must live in the SAME cargo build out/ dir so the static archive
# contents are mutually consistent. Derive libff path from libiop path.
LIBIOP_BUILD_ROOT=$(dirname "$(dirname "$LIBIOP_A")")  # .../out/build
LIBFF_A="${LIBIOP_BUILD_ROOT}/depends/libff/libff/libff.a"

echo "[probe] using libiop.a = $LIBIOP_A" >&2
echo "[probe] using libff.a  = $LIBFF_A"  >&2

LIBIOP_SRC="libiop"
LIBFF_SRC="libiop/depends/libff"
LIBFQFFT_SRC="libiop/depends/libfqfft"

OUT_BIN="target/fp127_aurora_probe"
mkdir -p target

CXX=${CXX:-/usr/bin/c++}

# Intentionally OMIT -DBINARY_OUTPUT / -DMONTGOMERY_OUTPUT so bigint<<ostream and
# Fp<<ostream print decimal canonical form in our probe. libiop internals don't
# depend on these macros except via operator<< (headers are token-identical).
DEFS=(-DCURVE_EDWARDS -DNO_PROCPS -DUSE_ASM=0)
INCS=(
  -I"$LIBIOP_SRC"
  -I"$LIBFF_SRC"
  -I"$LIBFQFFT_SRC"
  -I"$LIBFF_SRC/depends/gtest/googletest/include"
  -isystem /opt/homebrew/include
)

"$CXX" -std=gnu++14 -O2 -g \
  "${DEFS[@]}" "${INCS[@]}" \
  scripts/fp127_aurora_probe.cpp \
  "$LIBIOP_A" "$LIBFF_A" \
  -L/opt/homebrew/lib -lgmpxx -lgmp -lsodium -lpthread \
  -o "$OUT_BIN"

echo "[probe] built $OUT_BIN" >&2
echo "[probe] running ..." >&2
"./$OUT_BIN" "${1:-6}" "${2:-15}"
