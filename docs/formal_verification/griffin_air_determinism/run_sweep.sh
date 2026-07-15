#!/bin/bash
# Determinism-harness scale sweep. Logs to sweep_results.log.
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
CVC5="$DIR/bin/cvc5"
LOG="$DIR/sweep_results.log"
: > "$LOG"
gen() { python3 gen_determinism_smt.py "$@"; }
one() { # tag  timeout_s  solver  gen-args...
  local tag="$1" tmo="$2" solver="$3"; shift 3
  gen "$@" --out smt/_sw.smt2 2>/dev/null
  local vars=$(grep -o 'VARS=[0-9]*' smt/_sw.smt2 | head -1)
  local as=$(grep -o 'ASSERTS=[0-9]*' smt/_sw.smt2 | head -1)
  local t0=$(python3 -c 'import time;print(time.time())')
  local res
  if [ "$solver" = z3 ]; then
    res=$(z3 -T:$tmo smt/_sw.smt2 2>&1 | grep -iE '^(sat|unsat|unknown|timeout)' | head -1)
  else
    res=$("$CVC5" --tlimit=$((tmo*1000)) smt/_sw.smt2 2>&1 | grep -iE '^(sat|unsat|unknown)' | head -1)
    [ -z "$res" ] && res="timeout/unknown"
  fi
  local t1=$(python3 -c 'import time;print(time.time())')
  local dt=$(python3 -c "print(f'{$t1-$t0:.1f}')")
  printf '%-40s %-11s %-13s %-6s %ss\n' "$tag" "$vars" "$as" "$res" "$dt" | tee -a "$LOG"
}
echo "== SAT direction (detection), PLUM-like LOOSE modulus (mod_bytes=n-1) ==" | tee -a "$LOG"
one "n=2  det  z3"  60 z3 --n 2  --op mul --mod-bytes 1
one "n=4  det  z3"  60 z3 --n 4  --op mul --mod-bytes 3
one "n=8  det  z3"  60 z3 --n 8  --op mul --mod-bytes 6
one "n=16 det  z3"  90 z3 --n 16 --op mul --mod-bytes 13
one "n=32 det  z3"  120 z3 --n 32 --op mul --mod-bytes 25
echo "== UNSAT direction (determinism proof), result-canonical, loose modulus ==" | tee -a "$LOG"
one "n=2  proof z3"   90 z3   --n 2 --op mul --mod-bytes 1 --result-canonical
one "n=2  proof cvc5" 120 cvc5 --n 2 --op mul --mod-bytes 1 --result-canonical
one "n=3  proof z3"   120 z3   --n 3 --op mul --mod-bytes 2 --result-canonical
echo "DONE" | tee -a "$LOG"
