#!/usr/bin/env python3
"""
Generate an SMT-LIB2 determinism (under-constraint) query for one SP1
`FieldOpCols<T,P>` limb-gadget instance (the thesis's lem:limb-gadget).

GROUND TRUTH (verbatim structure from
  submodules/sp1/crates/core/machine/src/operations/field/field_op.rs
  submodules/sp1/crates/core/machine/src/operations/field/util_air.rs):

MUL gadget, operands a,b (byte-limb vectors, base 256):
  p_op(X)        = a(X) * b(X)                         (convolution)
  p_vanishing(X) = p_op(X) - result(X) - carry(X)*modulus(X)
  CONSTRAINT     : p_vanishing(X) == (witness(X) - offset) * (X - 256)   [coeff-wise over F_q]
  RANGE          : result_i,carry_i in [0,256); witness_j in [0,2^16)
  q = 2^31-2^24+1 (KoalaBear), offset = WITNESS_OFFSET = 2^14,
  NB_WITNESS_LIMBS = 2*NB_LIMBS-1, #coeff-constraints = NB_WITNESS_LIMBS+1.

DETERMINISM QUERY: two witness copies, SAME operand inputs a,b, both satisfying
all gadget constraints, outputs asserted to DIFFER.
  UNSAT => output uniquely determined (deterministic; good).
  SAT   => under-constraint (finding; model exhibits two valid outputs).

BACKENDS
  bv (default): bit-vectors (QF_BV). Ranges are native (byte=8-bit,u16=16-bit);
                multiplication native; backed by bit-blast SAT (z3 or cvc5).
  ff          : finite field F_q (QF_FF, cvc5 only), ranges via bit-decomposition.

BV-vs-FF SOUNDNESS NOTE. Each constraint's integer value Sigma = p_vanishing_k -
product_k. With every limb range-checked (result/carry<256, witness<2^16, a,b<256),
|Sigma| <= ~2.1M (op) + ~2.1M (carry*mod) + ~16.8M (256*witness) + 255 < ~21M,
which is < q/2 ~ 1.06e9. Hence "Sigma == 0 (mod q)" <=> "Sigma == 0 over Z" for
every range-checked assignment: NO wraparound witness is reachable. The BV/integer
model is therefore FAITHFUL to the F_q AIR over the range-checked domain. This is
the same limb-magnitude side-condition lem:limb-gadget itself relies on.
"""
import argparse, sys

Q = 2130706433          # KoalaBear 2^31 - 2^24 + 1
BASE = 256
DEFAULT_OFFSET = 1 << 14

def is_prime(m):
    if m < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if m % p == 0: return m == p
    d, r = m-1, 0
    while d % 2 == 0: d //= 2; r += 1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        x = pow(a, d, m)
        if x in (1, m-1): continue
        for _ in range(r-1):
            x = x*x % m
            if x == m-1: break
        else:
            return False
    return True

def pick_modulus(mod_bytes):
    m = 256**mod_bytes - 1
    lo = 256**(mod_bytes-1)
    while m > lo:
        if is_prime(m): return m
        m -= 2
    raise RuntimeError("no prime found")

def to_bytes_le(x, n): return [(x >> (8*i)) & 0xff for i in range(n)]

# ---- monomial core (backend-independent) ----------------------------------
# A constraint is a list of (coeff:int, vars:tuple[str,...]) monomials that must sum to 0.
# vars=() means a constant term. Built once, emitted per backend.

def vanishing_monomials(k, a, b, result, carry, witness, n, mod_bytes, M_bytes, op, offset):
    """Monomials of  op_k - result_k - (carry*mod)_k - product_k   (must == 0)."""
    W = 2*n - 1
    mons = []
    # + op_k
    if op == "mul":
        for i in range(n):
            j = k - i
            if 0 <= j < n:
                mons.append((1, (a[i], b[j])))
    else:  # add
        if 0 <= k < n:
            mons.append((1, (a[k],))); mons.append((1, (b[k],)))
    # - result_k
    if 0 <= k < n:
        mons.append((-1, (result[k],)))
    # - (carry*modulus)_k
    for i in range(n):
        j = k - i
        if 0 <= j < mod_bytes and M_bytes[j] != 0:
            mons.append((-M_bytes[j], (carry[i],)))
    # - product_k, product = (witness - offset)*(X-256); product_k = ws_{k-1} - 256*ws_k
    #   ws_j = witness_j - offset (j in [0,W), else 0)
    def add_ws(sign, j):
        # contributes sign*ws_j = sign*witness_j - sign*offset  (if 0<=j<W)
        if 0 <= j < W:
            mons.append((sign, (witness[j],)))
            mons.append((-sign*offset, ()))
    # -product_k = -ws_{k-1} + 256*ws_k
    add_ws(-1, k-1)
    add_ws(256, k)
    return mons

def constant_of(mons):
    return sum(c for c,v in mons if len(v) == 0)

def populate_mirror(a_int, b_int, M, n, mod_bytes, op, offset):
    """Byte-exact Python mirror of FieldOpCols::populate_carry_and_witness
       (field_op.rs). Returns (p_result, p_carry, witness_stored) as int lists.
       Used to build the ORACLE fidelity check: the honest witness MUST satisfy
       the SMT constraints. If the oracle query is UNSAT, the encoding is wrong."""
    p_a = to_bytes_le(a_int, n); p_b = to_bytes_le(b_int, n)
    if op == "mul":
        val = a_int * b_int
    else:
        val = a_int + b_int
    result = val % M
    carry = (val - result) // M
    p_mod = to_bytes_le(M, mod_bytes)
    p_result = to_bytes_le(result, n)
    p_carry = to_bytes_le(carry, n)
    W = 2*n - 1
    van = [0]*(W+1)
    if op == "mul":
        for i in range(n):
            for j in range(n):
                van[i+j] += p_a[i]*p_b[j]
    else:
        for i in range(n):
            van[i] += p_a[i] + p_b[i]
    for i in range(n):
        van[i] -= p_result[i]
    for i in range(n):
        for j in range(mod_bytes):
            van[i+j] -= p_carry[i]*p_mod[j]
    length = W+1
    pol_carry = van[length-1]
    for i in range(length-2, -1, -1):
        ai = van[i]; van[i] = pol_carry; pol_carry = ai + pol_carry*256
    assert pol_carry == 0, "synthetic division remainder != 0 (mirror bug)"
    witness = [van[i] + offset for i in range(W)]
    for wv in witness:
        assert 0 <= wv < (1<<16), f"witness {wv} out of u16 range (bound violated)"
    return p_result, p_carry, witness

# ---- BV backend ------------------------------------------------------------
class BV:
    def __init__(self, wbits):
        self.wbits = wbits
        self.lines = []
        self.nvars = 0; self.nasserts = 0
    def emit(self, s): self.lines.append(s)
    def declare(self, name, width):
        self.emit(f"(declare-fun {name} () (_ BitVec {width}))"); self.nvars += 1
    def const(self, val):
        return f"(_ bv{val % (1<<self.wbits)} {self.wbits})"
    def zext(self, name, from_w):
        if from_w == self.wbits: return name
        return f"((_ zero_extend {self.wbits-from_w}) {name})"
    def assert_(self, s):
        self.emit(f"(assert {s})"); self.nasserts += 1

def emit_bv(smt_lines_holder, args, n, mod_bytes, M, M_bytes, a_w, b_w):
    bv = BV(args.wbits)
    W = 2*n - 1
    var_width = {}  # name -> declared width
    def decl_vec(prefix, count, width):
        names = []
        for i in range(count):
            nm = f"{prefix}{i}"; bv.declare(nm, width); var_width[nm] = width; names.append(nm)
        return names
    a = decl_vec("a", n, 8); b = decl_vec("b", n, 8)
    def col(copy, kind, count, width): return decl_vec(f"c{copy}_{kind}", count, width)
    r1 = col(1,"res",n,8); c1 = col(1,"car",n,8); w1 = col(1,"wit",W,16)
    two_copy = (args.mode == "determinism")
    if two_copy:
        r2 = col(2,"res",n,8); c2 = col(2,"car",n,8); w2 = col(2,"wit",W,16)

    def term_expr(coeff, vs):
        # returns (side, expr) where side in {'pos','neg'}, expr is |coeff|*prod(vs) at wbits
        sign = 1 if coeff >= 0 else -1
        mag = abs(coeff)
        if len(vs) == 0:
            e = bv.const(mag)
        else:
            factors = [bv.zext(v, var_width[v]) for v in vs]
            prod = factors[0] if len(factors)==1 else "(bvmul " + " ".join(factors) + ")"
            e = prod if mag == 1 else f"(bvmul {bv.const(mag)} {prod})"
        return ('pos' if sign>0 else 'neg', e)

    def emit_constraint(mons):
        pos, neg = [], []
        for coeff, vs in mons:
            if coeff == 0: continue
            side, e = term_expr(coeff, vs)
            (pos if side=='pos' else neg).append(e)
        def side_sum(lst):
            if not lst: return bv.const(0)
            return lst[0] if len(lst)==1 else "(bvadd " + " ".join(lst) + ")"
        bv.assert_(f"(= {side_sum(pos)} {side_sum(neg)})")

    copies = [(r1,c1,w1)] + ([(r2,c2,w2)] if two_copy else [])
    for (result,carry,witness) in copies:
        for k in range(W+1):
            emit_constraint(vanishing_monomials(k, a,b, result,carry,witness,
                                                n, mod_bytes, M_bytes, args.op, args.offset))
    # canonical range: assemble little-endian bytes into a big BV and bvult M
    def assemble(names):
        wbig = 8*len(names)
        parts = list(reversed(names))  # concat is big-endian, so hi..lo
        expr = parts[0] if len(parts)==1 else "(concat " + " ".join(parts) + ")"
        return expr, wbig
    def lt_M(names, tag):
        expr, wbig = assemble(names)
        Mc = f"(_ bv{M} {wbig})"
        bv.assert_(f"(bvult {expr} {Mc})")
    if args.operand_canonical:
        lt_M(a,"a"); lt_M(b,"b")
    if args.result_canonical:
        lt_M(r1,"r1")
        if two_copy: lt_M(r2,"r2")

    if args.mode == "determinism":
        # outputs DIFFER
        cols = args.diff.split(",")
        diffs = []
        if "res" in cols: diffs += [f"(not (= {x} {y}))" for x,y in zip(r1,r2)]
        if "car" in cols: diffs += [f"(not (= {x} {y}))" for x,y in zip(c1,c2)]
        if "wit" in cols: diffs += [f"(not (= {x} {y}))" for x,y in zip(w1,w2)]
        bv.assert_("(or " + " ".join(diffs) + ")")
    elif args.mode == "oracle":
        # ground a,b to concrete ints and copy1 to the reference-populate witness.
        A_int, B_int = args.oracle
        p_res, p_car, wit = populate_mirror(A_int, B_int, M, n, mod_bytes, args.op, args.offset)
        pa = to_bytes_le(A_int, n); pb = to_bytes_le(B_int, n)
        def fix(names, vals, w):
            for nm, v in zip(names, vals):
                bv.assert_(f"(= {nm} (_ bv{v} {w}))")
        fix(a, pa, 8); fix(b, pb, 8)
        fix(r1, p_res, 8); fix(c1, p_car, 8); fix(w1, wit, 16)
    # mode == "single": copy1 constraints only, free vars, expect SAT

    hdr = [
        f"; FieldOpCols {args.mode} query  backend=bv  op={args.op}  n={n}  mod_bytes={mod_bytes}",
        f"; q={Q} (KoalaBear)  offset={args.offset}  wbits={args.wbits}",
        f"; modulus M={M} prime={is_prime(M)} bytes_le={M_bytes}",
        f"; result_canonical={args.result_canonical} operand_canonical={args.operand_canonical} diff={args.diff}",
        "(set-logic QF_BV)",
    ]
    tail = [f"; VARS={bv.nvars} ASSERTS={bv.nasserts}", "(check-sat)"]
    return "\n".join(hdr + bv.lines + tail) + "\n", bv.nvars, bv.nasserts

# ---- FF backend (tiny cross-check only) ------------------------------------
def emit_ff(args, n, mod_bytes, M, M_bytes):
    lines = []; nv=[0]; na=[0]
    def E(s): lines.append(s)
    def V(nm): E(f"(declare-fun {nm} () F)"); nv[0]+=1; return nm
    def A(s): E(f"(assert {s})"); na[0]+=1
    def lit(c): return f"(as ff{c % Q} F)"
    def add(ts):
        ts=[t for t in ts if t is not None]
        return lit(0) if not ts else (ts[0] if len(ts)==1 else "(ff.add "+" ".join(ts)+")")
    def mul(ts): return ts[0] if len(ts)==1 else "(ff.mul "+" ".join(ts)+")"
    def bits(nm, nb, tag):
        bs=[]
        for k in range(nb):
            bb=V(f"{tag}_b{k}"); A(f"(= (ff.mul {bb} {bb}) {bb})"); bs.append(bb)
        A(f"(= {nm} {add([mul([lit(1<<k), bs[k]]) for k in range(nb)])})")
    def vec(pfx,cnt,nb):
        out=[]
        for i in range(cnt):
            nm=V(f"{pfx}{i}"); bits(nm,nb,f"{pfx}{i}"); out.append(nm)
        return out
    W=2*n-1
    a=vec("a",n,8); b=vec("b",n,8)
    def copy(cp):
        r=vec(f"c{cp}_res",n,8); c=vec(f"c{cp}_car",n,8); w=vec(f"c{cp}_wit",W,16)
        for k in range(W+1):
            mons=vanishing_monomials(k,a,b,r,c,w,n,mod_bytes,M_bytes,args.op,args.offset)
            terms=[]
            for coeff,vs in mons:
                if coeff==0: continue
                if len(vs)==0: terms.append(lit(coeff))
                else: terms.append(mul([lit(coeff)]+list(vs)))
            A(f"(= {add(terms)} (as ff0 F))")
        return r,c,w
    r1,c1,w1=copy(1); r2,c2,w2=copy(2)
    cols=args.diff.split(",")
    d=[]
    if "res" in cols: d+=[f"(not (= {x} {y}))" for x,y in zip(r1,r2)]
    if "car" in cols: d+=[f"(not (= {x} {y}))" for x,y in zip(c1,c2)]
    if "wit" in cols: d+=[f"(not (= {x} {y}))" for x,y in zip(w1,w2)]
    A("(or "+" ".join(d)+")")
    hdr=[f"; FieldOpCols determinism  backend=ff op={args.op} n={n}",
         "(set-logic QF_FF)", f"(define-sort F () (_ FiniteField {Q}))"]
    tail=[f"; VARS={nv[0]} ASSERTS={na[0]}","(check-sat)"]
    return "\n".join(hdr+lines+tail)+"\n", nv[0], na[0]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2)
    ap.add_argument("--mod-bytes", type=int, default=None)
    ap.add_argument("--op", choices=["mul","add"], default="mul")
    ap.add_argument("--offset", type=int, default=DEFAULT_OFFSET)
    ap.add_argument("--backend", choices=["bv","ff"], default="bv")
    ap.add_argument("--mode", choices=["determinism","oracle","single"], default="determinism")
    ap.add_argument("--oracle", type=int, nargs=2, default=[0,0], metavar=("A","B"),
                    help="concrete operands for --mode oracle")
    ap.add_argument("--wbits", type=int, default=40)
    ap.add_argument("--result-canonical", action="store_true")
    ap.add_argument("--operand-canonical", action="store_true")
    ap.add_argument("--diff", default="res,car,wit")
    ap.add_argument("--out", default="-")
    args = ap.parse_args()
    n = args.n
    mod_bytes = args.mod_bytes if args.mod_bytes else n
    assert mod_bytes <= n
    M = pick_modulus(mod_bytes); M_bytes = to_bytes_le(M, mod_bytes)
    if args.backend == "bv":
        out, nv, na = emit_bv(None, args, n, mod_bytes, M, M_bytes, 8, 8)
    else:
        out, nv, na = emit_ff(args, n, mod_bytes, M, M_bytes)
    if args.out == "-": sys.stdout.write(out)
    else:
        open(args.out,"w").write(out)
        sys.stderr.write(f"wrote {args.out} backend={args.backend} n={n} VARS={nv} ASSERTS={na}\n")

if __name__ == "__main__":
    main()
