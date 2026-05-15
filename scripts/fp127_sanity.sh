#!/usr/bin/env bash
# Build + run the Fp127 / Fp2_M127 runtime sanity check against a
# cargo-built libff.a. Finds the freshest libff.a under target/{debug,release}.
#
# Usage:
#   scripts/fp127_sanity.sh          # compile + run, print diff against reference
#   scripts/fp127_sanity.sh --emit   # just print the libff dump

set -euo pipefail

THESIS_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$THESIS_ROOT"

LIBFF_A=$(ls -t target/*/build/vc-pqc-*/out/build/depends/libff/libff/libff.a 2>/dev/null | head -1 || true)
if [[ -z "${LIBFF_A:-}" ]]; then
  echo "error: no cargo-built libff.a found; run \`cargo build\` or \`cargo build --release\` first" >&2
  exit 1
fi

LIBFF_BUILD_DIR=$(dirname "$LIBFF_A")
LIBFF_SRC="libiop/depends/libff"
LIBIOP_SRC="libiop"

OUT_BIN="target/fp127_sanity"
mkdir -p target

CXX=${CXX:-/usr/bin/c++}

# Match CMakeFiles/ff.dir/flags.make (CXX_DEFINES + CXX_INCLUDES),
# but *omit* BINARY_OUTPUT / MONTGOMERY_OUTPUT so our operator<< template
# instantiations print decimal canonical-form — we inspect values by eye.
DEFS=(-DCURVE_EDWARDS -DNO_PROCPS)
INCS=(
  -I"$LIBIOP_SRC"
  -I"$LIBFF_SRC"
  -isystem /opt/homebrew/include
)

echo "[fp127_sanity] using libff.a = $LIBFF_A" >&2

"$CXX" -std=gnu++14 -O2 -g \
  "${DEFS[@]}" "${INCS[@]}" \
  scripts/fp127_sanity.cpp \
  "$LIBFF_A" \
  -L/opt/homebrew/lib -lgmpxx -lgmp -lsodium \
  -o "$OUT_BIN"

echo "[fp127_sanity] built $OUT_BIN" >&2

DUMP=$(mktemp -t fp127_libff_dump.XXXXXX)
REF=$(mktemp -t fp127_python_dump.XXXXXX)

"./$OUT_BIN" | tee "$DUMP"

echo >&2
echo "[fp127_sanity] Python reference:" >&2
python3 scripts/compute_fp127_constants.py > "$REF"
cat "$REF" >&2

# Targeted cross-checks. Each line: "label=<libff_key>=<python_regex>".
p_minus_1="170141183460469231731687303715884105726"
checks=(
  "modulus|modulus|170141183460469231731687303715884105727"
  "s|s|1"
  "Rsquared|Rsquared|4"
  "Rcubed|Rcubed|8"
  "nqr|nqr|3"
  "nqr_to_t|nqr_to_t|${p_minus_1}"
  "Fp2::s|Fp2::s|128"
  "Fp2::t|Fp2::t|85070591730234615865843651857942052863"
  "Fp2::Frob[1]|Fp2::Frob\\[1\\]|${p_minus_1}"
  "Fp2::nqr.c0|Fp2::nqr.c0|1"
  "Fp2::nqr.c1|Fp2::nqr.c1|1"
  "Fp2::nqr_to_t.c0|Fp2::nqr_to_t.c0|113698847273379981554412195351293103809"
  "Fp2::nqr_to_t.c1|Fp2::nqr_to_t.c1|75527839882519493969654137360158369215"
  "3*3|3\\*3|9"
  "2^127_mod_p|2\\^127_mod_p|1"
  "5^(p-1)|5\\^\\(p-1\\)_via_square_of_euler|1"
  "legendre(3,p)|legendre\\(3,p\\)|${p_minus_1}"
  "7*7^-1|7\\*7\\^-1|1"
  "U*U.c0|U\\*U.c0|3"
  "U*U.c1|U\\*U.c1|0"
  "(1+U)(1-U).c0|\\(1\\+U\\)\\*\\(1-U\\).c0|170141183460469231731687303715884105725"
  "(1+U)(1-U).c1|\\(1\\+U\\)\\*\\(1-U\\).c1|0"
  "nqr_to_t^2^s.c0|nqr_to_t\\^\\(2\\^s\\).c0|1"
  "nqr_to_t^2^s.c1|nqr_to_t\\^\\(2\\^s\\).c1|0"
  "(11+13U)*inv.c0|\\(11\\+13U\\)\\*inv.c0|1"
  "(11+13U)*inv.c1|\\(11\\+13U\\)\\*inv.c1|0"
  "Fp2::mult_gen.c0|Fp2::mult_gen.c0|2"
  "Fp2::mult_gen.c1|Fp2::mult_gen.c1|3"
  "Fp2::rou.c0|Fp2::root_of_unity.c0|89166704926539866563981873303895936595"
  "Fp2::rou.c1|Fp2::root_of_unity.c1|93612632323303961918017786187501417908"
  "rou^2^s.c0|rou\\^\\(2\\^s\\).c0|1"
  "rou^2^s.c1|rou\\^\\(2\\^s\\).c1|0"
  "rou^2^(s-1).c1|rou\\^\\(2\\^\\(s-1\\)\\).c1|0"
  "rou^2^(s-1).c0|rou\\^\\(2\\^\\(s-1\\)\\).c0|${p_minus_1}"
)

echo >&2
echo "[fp127_sanity] cross-checks:" >&2
fail=0
for entry in "${checks[@]}"; do
  IFS='|' read -r label pat expected <<<"$entry"
  actual=$(grep -E "^${pat}=" "$DUMP" | head -1 | sed -E "s/^${pat}=([^ ]*).*/\\1/" || true)
  if [[ "$actual" == "$expected" ]]; then
    printf "  OK   %-30s = %s\n" "$label" "$actual" >&2
  else
    printf "  FAIL %-30s got=%s  expected=%s\n" "$label" "$actual" "$expected" >&2
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "[fp127_sanity] ALL CHECKS PASSED" >&2
  exit 0
else
  echo "[fp127_sanity] FAILURES" >&2
  exit 1
fi
