#!/usr/bin/env bash
# Build + run the Aurora-over-Fp2_M127 runner for the BDEC-R1CS wire format.
#
# Links against the cargo-built libiop.a + libff.a (so the surgery changes to
# blake2b.tcc / field_utils.tcc / subgroup.tcc are picked up automatically).
#
# Usage:
#   scripts/fp127_aurora_runner.sh <wire-file>                   # build + run
#   SKIP_BUILD=1 scripts/fp127_aurora_runner.sh <wire-file>      # reuse prior build

set -euo pipefail

THESIS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$THESIS_ROOT"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 path/to/file.bdec-r1cs" >&2
  exit 64
fi
WIRE="$1"
if [[ ! -f "$WIRE" ]]; then
  echo "error: wire file not found: $WIRE" >&2
  exit 66
fi

LIBIOP_A=$(ls -t target/*/build/vc-pqc-*/out/build/libiop/libiop.a 2>/dev/null | head -1 || true)
if [[ -z "${LIBIOP_A:-}" ]]; then
  echo "error: missing libiop.a; run \`cargo build\` first" >&2
  exit 1
fi
LIBIOP_BUILD_ROOT=$(dirname "$(dirname "$LIBIOP_A")")
LIBFF_A="${LIBIOP_BUILD_ROOT}/depends/libff/libff/libff.a"

echo "[runner] libiop.a = $LIBIOP_A" >&2
echo "[runner] libff.a  = $LIBFF_A"  >&2

LIBIOP_SRC="libiop"
LIBFF_SRC="libiop/depends/libff"
LIBFQFFT_SRC="libiop/depends/libfqfft"

OUT_BIN="target/fp127_aurora_runner"
mkdir -p target

CXX=${CXX:-/usr/bin/c++}
# Match the probe's flags verbatim so the Fp2 / bigint / operator<< token-equivalence
# across TUs is preserved (CURVE_EDWARDS / NO_PROCPS / USE_ASM=0 must stay in sync
# with libiop's CMake config).
DEFS=(-DCURVE_EDWARDS -DNO_PROCPS -DUSE_ASM=0)
INCS=(
  -I"$LIBIOP_SRC"
  -I"$LIBFF_SRC"
  -I"$LIBFQFFT_SRC"
  -I"$LIBFF_SRC/depends/gtest/googletest/include"
  -isystem /opt/homebrew/include
)

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "[runner] compiling $OUT_BIN ..." >&2
  "$CXX" -std=gnu++14 -O2 -g \
    "${DEFS[@]}" "${INCS[@]}" \
    scripts/fp127_aurora_runner.cpp \
    "$LIBIOP_A" "$LIBFF_A" \
    -L/opt/homebrew/lib -lgmpxx -lgmp -lsodium -lpthread \
    -o "$OUT_BIN"
  echo "[runner] built $OUT_BIN" >&2
fi

echo "[runner] running on $WIRE ..." >&2
"./$OUT_BIN" "$WIRE"
