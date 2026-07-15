#!/bin/bash
# Reproducible entry point for the FieldOpCols determinism prototype.
# Regenerates the headline SMT queries and runs them. No zkVM prove is invoked.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
CVC5="$DIR/bin/cvc5"     # cvc5 1.3.4 static-gpl (has FF + BV); see bin/.gitignore
GEN="python3 gen_determinism_smt.py"
have() { command -v "$1" >/dev/null 2>&1; }
Z3=z3; have z3 || Z3="echo (z3 not found) "

echo "### 1. ENCODING FIDELITY (oracle): honest populate() witness must be SAT"
$GEN --n 2 --op mul --mode oracle --oracle 12345 23456 --out smt/oracle_mul_n2.smt2
$Z3 smt/oracle_mul_n2.smt2      # expect: sat

echo "### 2. FIDELITY negative control: one perturbed result byte must be UNSAT"
$GEN --n 2 --op mul --mode oracle --oracle 12345 23456 --out smt/negctl_mul_n2.smt2
python3 - <<'PY'
import re
p="smt/negctl_mul_n2.smt2"; s=open(p).read()
m=re.search(r'\(assert \(= c1_res0 \(_ bv(\d+) 8\)\)\)', s)
new=(int(m.group(1))+1)%256
open(p,"w").write(s.replace(m.group(0), f'(assert (= c1_res0 (_ bv{new} 8)))'))
PY
$Z3 smt/negctl_mul_n2.smt2      # expect: unsat

echo "### 3. DETERMINISM, FieldOpCols ALONE (n=2, loose modulus): expect SAT (under-constrained)"
$GEN --n 2 --op mul --mod-bytes 1 --out smt/det_mul_n2.smt2
$Z3 smt/det_mul_n2.smt2         # expect: sat  (result determined only mod M)

echo "### 4. DETERMINISM, + result<M canonicity (n=2): expect UNSAT (deterministic)"
$GEN --n 2 --op mul --mod-bytes 1 --result-canonical --out smt/det_mul_n2_rescanon.smt2
"$CVC5" --tlimit=180000 smt/det_mul_n2_rescanon.smt2   # expect: unsat (cvc5 ~90s)

echo "### 5. Scale sweep (detection + proof): see run_sweep.sh -> sweep_results.log"
