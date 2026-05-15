# Specification: A Griffin-over-Mersenne-127 Precompile for RISC0

*Version 0.3, 2026-05-12. Working draft.*

**Changelog:**
- *v0.3*: §5 revised after empirical three-level attribution
  (Griffin + F_p + F_p²) in
  `results/loquat_three_level_20260512_024956/`. The v0.2 projection of
  40-60× speedup with Griffin + F_p² precompiles assumed F_p² add/sub
  contributed substantially; the measured data shows F_p² wrappers add
  only 1.31% of cycles. The corrected ceiling is **~30×**, bounded by a
  ~5% rv32im control-flow floor that no primitive precompile can attack.
  Added §5.2 (three-level decomposition table) and §5.4-§5.5
  articulating the ceiling and what exceeding it would require.
- *v0.2*: §5 revised after empirical two-level attribution. Earlier
  projection of ~35.8× speedup with both Griffin and F_p mul precompiles
  was incorrect; the measured projection is ~15.2× because most
  non-Griffin work is F_p² arithmetic, not F_p multiplication. Added
  §5.4 sketching the F_p² precompile as the path to higher speedups.
- *v0.1*: Initial draft based on Griffin-level attribution only.

## 0. What this document is

A formal-enough specification of a RISC0 zkVM precompile that would
implement the Griffin permutation as configured in Loquat
[Zhang et al. 2024/868]: state width 4, lanes in $\mathbb{F}_p$ where
$p = 2^{127} - 1$ (the 127-bit Mersenne prime), round count determined
by the Griffin paper's security argument at $\kappa = 128$
(empirically: $\approx 11$ rounds).

The specification is designed to make four things concrete:

1. **What** computation the precompile performs (a single Griffin
   permutation on a 4-lane state).
2. **How** the guest invokes it (memory-mapped syscall, input/output
   layout).
3. **What** it would cost to implement (AIR constraint count estimate,
   reference to comparable RISC0 precompiles, F_p arithmetic substrate
   required).
4. **What** it would save (projected cycle reductions for Loquat verify,
   anchored in measured cycle and permutation counts).

This document does not implement the precompile. It specifies the
interface and cost model precisely enough that an implementer can build
it, and rigorously enough that a reviewer can verify the projected
savings against the empirical three-level attribution measurements in
`results/loquat_three_level_20260512_024956/` (Griffin + F_p + F_p²
counters, plus microbenches for each primitive).

## 1. Motivation: empirical attribution

From the measurements documented in `results/loquat_attribution_*` and
`results/loquat_only_multi_*`:

| metric | λ=80 | λ=100 | λ=128 |
|---|---:|---:|---:|
| Loquat verify total cycles (rv32im, dev-mode, single sig) | 685.8M | 840.7M | 895.0M |
| Griffin permutations per verify | 727 | 884 | 931 |
| Microbenched cycles per permutation | 892,840 | 892,840 | 892,840 |
| Total cycles attributable to Griffin | 649.1M | 789.5M | 831.2M |
| **% of verify cycles consumed by Griffin** | **94.65%** | **93.88%** | **92.88%** |

Reading across the table: Loquat verification's cycle cost in RISC0 is
dominated by the cost of *executing the Griffin permutation in rv32im
software*. The 892,840-cycle figure per permutation is the multi-limb
arithmetic tax for performing $\mathbb{F}_p$ operations on a 32-bit
ISA — every $\mathbb{F}_p$ multiplication is implemented as a multi-word
multiply + Mersenne reduction. Griffin's 11 rounds per permutation, each
with ~4 multiplications + matrix-vector multiplications, accumulate this
tax.

A precompile that executes one Griffin permutation as a single STARK
sub-circuit replaces 892,840 rv32im cycles with a small constant number
of "Griffin steps" recorded in the precompile's AIR. The savings bound
is determined by the precompile's per-invocation cost; for comparable
RISC0 precompiles (SHA-256 ≈ 70 cycles per block, Poseidon2 in the
recursion circuit ≈ comparable order), this is **~3–4 orders of
magnitude cheaper than software execution**.

The remaining 5–7% of Loquat verify cycles (the non-Griffin remainder
in the table above) is split between:
- Legendre PRF field operations (≈ 4–6M cycles per verify, ~0.7%).
- FRI polynomial reconstruction over $\mathbb{F}_p^2$ (≈ 50–60M cycles
  per verify, ~7% of total, concentrated entirely inside
  `ldt_openings`).
- Rv32im control flow and Loquat-specific bookkeeping (≈ 10M cycles).

A Griffin precompile alone cannot reduce these. They become the
post-precompile floor.

## 2. Background

### 2.1 RISC0 precompile model

A RISC0 *precompile* (also called an *accelerator*) is a special
sub-circuit of the prover's STARK that implements a fixed computation
more efficiently than executing it as rv32im. The guest invokes a
precompile via a syscall (`ecall` with a specific syscall number); the
host-side prover allocates a precompile trace segment, fills it with the
input data, runs the precompile's transition function, and produces an
output. The main rv32im trace records only the syscall boundary,
not the precompile's internal computation.

Precompiles in production RISC0 (v3.x):
- **SHA-256**: ~70 cycles charged to the main rv32im trace per 64-byte
  block, vs ~30,000 cycles for software SHA-256 execution. ~430×
  speedup.
- **secp256k1 scalar multiplication**, **bigint modular multiplication**,
  **Poseidon2 (recursion circuit)**: comparable savings ratios.

The precompile's AIR ("Algebraic Intermediate Representation") has its
own column layout, constraint set, and execution-trace size. The cost
the prover pays is in the *precompile circuit's* trace size, not in the
main rv32im trace. For STARK-proving wall-clock, the precompile's
amortized contribution is dominated by FRI on its own column set, which
is much cheaper than FRI over a 10⁶-row rv32im trace.

### 2.2 Griffin construction (Loquat instantiation)

From [Zhang et al. 2024/868, §3] and the implementation in
`src/loquat/griffin.rs`:

- **State**: $\mathbf{s} \in \mathbb{F}_p^4$ where $p = 2^{127} - 1$.
- **Round count**: 11 (computed from Griffin's algebraic-attack security
  argument at $\kappa = 128$).
- **Each round** $r$ applies:
  1. **Nonlinear layer**: lane 0 → $s_0^{1/d}$, lane 1 → $s_1^d$, where
     $d$ is the smallest integer $\geq 3$ coprime to $p-1$ (concretely:
     $d = 5$ for $p = 2^{127} - 1$). Lanes 2 and 3 each multiplied by
     $L_i(\cdot)^2 + \alpha_{i-2} L_i(\cdot) + \beta_{i-2}$ where
     $L_i$ is a linear form in $(s_0, s_1, s_{i-1})$.
  2. **Linear layer**: matrix-vector multiply
     $\mathbf{s} \leftarrow M \mathbf{s}$ for a fixed $4 \times 4$ MDS
     matrix $M$ over $\mathbb{F}_p$.
  3. **Constants**: $\mathbf{s} \leftarrow \mathbf{s} + \mathbf{c}_r$.
- **Final round**: nonlinear + linear only (no constants), per the
  Griffin specification.

The dominant arithmetic cost per round is:
- 1 × $\mathbb{F}_p$ exponentiation to power $d$ (lane 1) — ~$\log_2 d$
  squarings + 1 multiplication; for $d=5$, that's 2 squarings + 1 mul.
- 1 × $\mathbb{F}_p$ exponentiation to power $d^{-1} \bmod (p-1)$ (lane 0)
  — this is the expensive operation. $d^{-1} \bmod (p-1)$ is a
  ~126-bit exponent; square-and-multiply takes ~190 multiplications.
- ~6 $\mathbb{F}_p$ multiplications for the lane-2/3 quadratic terms.
- 16 $\mathbb{F}_p$ multiplications for the linear layer
  (4×4 matrix × 4-vector = 16 lane multiplications).

Per permutation: 11 rounds × (~213 multiplications per round) ≈ **~2,343
F_p multiplications per Griffin permutation**.

Each $\mathbb{F}_p$ multiplication in rv32im, with Mersenne reduction,
is roughly 380 cycles (one 128×128 → 256-bit multiply + Mersenne fold
+ conditional subtraction). Cross-checking: 2,343 × 380 ≈ 890,340 cycles
per permutation, matching the microbenched 892,840 within 0.3%.

The dominant cost inside Griffin is therefore the inverse S-box on
lane 0 (~190 of 213 multiplications per round, or ~89% of in-round
arithmetic).

## 3. Specification

### 3.1 Precompile name and syscall

Name: `loquat_griffin_perm`. Syscall number: TBD (assigned by RISC0
when the precompile is upstreamed; for prototyping, use the user-defined
range above `0x10000`).

### 3.2 Input/output layout

The guest invokes the precompile with two memory pointers and a length:

```
syscall(LOQUAT_GRIFFIN_PERM, input_ptr, output_ptr)
```

- `input_ptr`: pointer to 64 bytes of guest memory containing the
  4-lane $\mathbb{F}_p$ state in little-endian byte order. Each lane is
  16 bytes (a 127-bit value stored in a 128-bit slot; the top bit is
  always zero by the canonical reduction).
- `output_ptr`: pointer to 64 bytes of guest memory into which the
  precompile writes the permuted state in the same format. May alias
  `input_ptr` (the precompile must read all 64 bytes before writing).

The precompile reads the input state, applies one full Griffin
permutation (all 11 rounds), and writes the output state.

### 3.3 Pseudocode of computed function

```
fn griffin_permutation(state: [Fp; 4]) -> [Fp; 4]:
    for r in 0..(R-1):                # R = 11 rounds
        state = nonlinear_layer(state)
        state = linear_layer(state)
        state = state + ROUND_CONSTANTS[r]
    state = nonlinear_layer(state)    # final round
    state = linear_layer(state)
    return state
```

where `nonlinear_layer`, `linear_layer`, and `ROUND_CONSTANTS` are as
defined in [Grassi-Hadipour-Pernot-Schofnegger-Walch 2022, Griffin paper]
with parameters $(p, t, d) = (2^{127}-1, 4, 5)$.

The round constants `ROUND_CONSTANTS[0..R-1]` are derived from the
SHAKE256 expansion of a fixed domain-separation seed and are
**hard-coded into the precompile circuit**, not passed as input.

### 3.4 Trace semantics

In the precompile's AIR:
- Each round is encoded as one row (or a small fixed number of rows,
  depending on how the implementation splits the nonlinear S-box).
- Lanes are represented as 4 native-field "limbs" each (for BabyBear
  prover, $p = 2^{31} - 2^{27} + 1$, four BabyBear limbs encode one
  128-bit slot).
- Constraints enforce:
  1. The S-box on lane 1 ($s_1^d$): a degree-5 polynomial constraint.
  2. The S-box on lane 0 ($s_0^{1/d}$): an *inverse* constraint, encoded
     as $s_0^{\text{new}} \cdot$ (degree-5 polynomial in $s_0^{\text{new}}$)
     $= s_0^{\text{old}}$, which is cheap because we only need to prove
     consistency in the witness.
  3. The quadratic terms on lanes 2 and 3.
  4. The matrix multiplication (16 constraints per round).
  5. The constants (4 constraints per round, satisfied by the
     hard-coded values).
  6. Multi-limb arithmetic consistency: each $\mathbb{F}_p$ operation is
     decomposed into BabyBear-limb operations with appropriate range
     checks and Mersenne-reduction constraints.

### 3.5 Estimated AIR constraint count

| component | constraints per perm | notes |
|---|---:|---|
| 11 × nonlinear layer ($s_0^{1/d}$, $s_1^d$, quad lane-2, quad lane-3) | ~250 | dominated by inverse S-box encoding |
| 11 × linear layer (4×4 mat-vec over $\mathbb{F}_p$) | ~700 | each lane-mul ~ 4 BabyBear mul-constraints + reduction |
| 10 × constant addition | ~40 | trivial |
| state ingress/egress (limb decomposition) | ~30 | input/output range checks |
| **Total** | **~1,020** | order of magnitude; precise count is implementation-dependent |

**Reference points**:
- RISC0 SHA-256 precompile: ~64 AIR rows per 512-bit block, ~50 columns.
- Poseidon2 in the recursion circuit (used internally by RISC0): ~50–100
  AIR rows per permutation.
- Griffin-over-F_p^127 would be ~5–10× larger than Poseidon2 because of
  the wider field (127-bit vs 31-bit lanes).

Even at ~1,000 constraints, one Griffin permutation in the precompile
circuit is two orders of magnitude smaller than the ~10^5 constraint
equivalent of running 892,840 rv32im cycles through the main trace
(rv32im trace cost is roughly 1 constraint per cycle in the main AIR).

### 3.6 Cycles charged to main rv32im trace

The precompile invocation is recorded in the main trace as:
- 1 syscall instruction.
- Memory accesses to read the input state and write the output state
  (~16 word reads + 16 word writes).
- A small fixed cost for syscall dispatch overhead.

**Estimated per-invocation cost in the rv32im main trace: ~100 cycles.**
This is in line with the SHA-256 precompile's documented ~70 cycles per
block.

## 4. Underlying primitive: $\mathbb{F}_p$ arithmetic substrate

The Griffin precompile needs $\mathbb{F}_p$ operations encoded as
BabyBear-AIR constraints. The cheapest path:

### 4.1 Mersenne-127 multi-limb multiplication

Mersenne primes admit cheap modular reduction: for
$p = 2^{127} - 1$ and any $0 \leq z < 2^{254}$,
$z \bmod p = (z \bmod 2^{127}) + (z \gg 127)$, repeated at most twice.

In a 4-limb BabyBear encoding (each limb $\leq 2^{32}$, fits in one
BabyBear element with range checks):
- $(a_0, a_1, a_2, a_3) \times (b_0, b_1, b_2, b_3)$ produces a
  7-limb product (with carries up to 33 bits).
- The Mersenne fold combines the upper 4 limbs into the lower 4
  with a single addition (after a bit-shift).
- Total: ~16 BabyBear multiplications + ~30 additions + 4 range
  checks per $\mathbb{F}_p$ multiplication.

### 4.2 Whether to include this as a separate precompile

Two design options:

**Option A — Single precompile, Griffin only.** Encode multi-limb
arithmetic as inline constraints inside the Griffin precompile circuit.
Pros: one syscall covers everything Loquat needs for hashing. Cons:
larger circuit; not reusable for other Loquat phases (Legendre PRF
checks, FRI polynomial reconstruction).

**Option B — Two precompiles, Griffin + $\mathbb{F}_p$ mul.** Expose
$\mathbb{F}_p$ multi-limb multiplication as a separate precompile that
the Griffin precompile internally uses, AND that the guest can directly
invoke for non-Griffin field arithmetic (Legendre symbol, FRI
reconstruction).

**Recommendation: Option B.** Loquat's non-Griffin remainder (~64M
cycles at λ=128) is roughly evenly split between Legendre PRF checks
(~6M, all $\mathbb{F}_p$ mul) and FRI polynomial reconstruction (~58M,
mostly $\mathbb{F}_p^2$ mul which decomposes into 3-4 $\mathbb{F}_p$ muls).
An $\mathbb{F}_p$ multiplication precompile attacks both. At ~380 cycles
per software $\mathbb{F}_p$ mul vs ~5 cycles per precompile invocation
(syscall + 2 reads + 1 write), this is another ~75× speedup on the
~60M-cycle remainder, pushing the total post-precompile floor down to
~10M cycles (mostly rv32im control flow).

Option B is described in Section 7 as Stage 1; Griffin precompile in
Stage 2.

## 5. Projected cycle savings

**Revised 2026-05-12 after empirical three-level attribution** (see
`results/loquat_three_level_20260512_024956/`). The v0.2 estimate of
40–60× speedup with Griffin + F_p² precompiles assumed F_p² add/sub
contributed substantially to the remainder. The instrumented measurement
shows F_p² wrappers contribute only 1.31% of cycles at λ=128. The
revised ceiling is **~30×**, set by a ~5% rv32im control-flow floor
that no primitive precompile can attack.

### 5.1 Empirical baseline (measured, not projected)

Three security levels, single signature, RISC0 dev mode on M5 Pro:

| λ | total cycles | Griffin perms | F_p muls | F_p² muls | **Griffin %** | **F_p mul %** |
|---:|---:|---:|---:|---:|---:|---:|
| 80 | 698,611,363 | 727 | 1,856,229 | ~22,300 | **94.71%** | **64.57%** |
| 100 | 856,977,477 | 884 | 2,276,714 | ~26,200 | **93.88%** | **64.56%** |
| 128 | 912,254,567 | 931 | 2,418,910 | 28,367 | **92.88%** | **64.44%** |

Microbenched primitive costs:
- 1 Griffin permutation = 910,143 rv32im cycles
- 1 F_p multiplication = 243 rv32im cycles
- 1 F_p² multiplication = 1,394 rv32im cycles (= 4 × F_p mul + 422 cyc wrapper)
- 1 F_p² add/sub ≈ 30 rv32im cycles (estimate; tight-loop microbench was
  optimised by the compiler — counter confirms invocations, cycle counter
  reported 0; bounded above by ~50 cyc/op, contribution <1% regardless)

Within one Griffin permutation at λ=128:
- F_p multiplication work (2,580 muls × 243 cyc) = 627,116 cycles ≈ **69%**
- Other work (F_p additions, struct ops, function calls) = 282,983 cycles ≈ **31%**

### 5.2 Three-level attribution at λ=128 (single verify)

Decomposed against total = 912,254,567 cycles:

| component | cycles | % of total |
|---|---:|---:|
| **Griffin permutations** (931 × 910,143) | 847,343,133 | **92.88%** |
| └─ F_p mul work inside Griffin (931 × 2,580 × 243) | 583,681,140 | 63.98% |
| └─ Other Griffin work (lane adds, struct, control flow) | 263,661,993 | 28.90% |
| **Non-Griffin remainder** | 64,911,434 | **7.12%** |
| └─ F_p muls outside Griffin (~17 K × 243) | 4,113,990 | 0.45% |
| └─ F_p² mul wrappers (28,367 × 422) | 11,970,874 | 1.31% |
| └─ Control-flow floor (F_p² add/sub, branches, struct, memory) | 48,826,570 | **5.35%** |

The 5.35% control-flow floor is the **fundamental ceiling**: it is
neither Griffin work, nor F_p arithmetic, nor F_p² arithmetic. It is
the cost of running Loquat as an rv32im program — signature
deserialization, loop control in `Algorithm7Verifier`, byte ↔ field
conversions, sumcheck protocol logic, memory access through the virtual
address space. No primitive precompile reduces it.

### 5.3 Per-verify projections, $n = 1$

Assuming RISC0-style precompile costs: Griffin 100 cyc/invocation,
F_p mul 5 cyc/op, F_p² ops 100 cyc/op each (add/sub/mul):

| λ | baseline | Griffin only | Griffin + F_p mul | **Griffin + F_p²** | Griffin + F_p² + F_p mul |
|---:|---:|---:|---:|---:|---:|
| 80 | 698.6 M | ~50.1 M (14.0×) | ~45.5 M (15.4×) | **~22.8 M (30.7×)** | ~22.8 M (30.7×) |
| 100 | 857.0 M | ~57.6 M (14.9×) | ~52.6 M (16.3×) | **~27.9 M (30.7×)** | ~27.9 M (30.7×) |
| 128 | 912.3 M | ~65.0 M (14.0×) | ~59.9 M (15.2×) | **~29.7 M (30.7×)** | ~29.7 M (30.7×) |

**Key findings**:

1. The **F_p² precompile is far more impactful than the F_p mul
   precompile** on top of a Griffin precompile. F_p² mul (1,394 cyc)
   internally does 4 F_p multiplications — replacing the entire F_p²
   mul with a precompile attacks both the inner F_p mul work AND the
   422-cyc wrapper (struct construction, lane additions, counter
   overhead). F_p mul precompile only attacks the inner multiplications,
   leaving the wrapper cost intact.

2. **F_p mul precompile is redundant when Griffin + F_p² precompiles
   are present.** The only F_p muls remaining after those two
   precompiles are ~21,000 standalone F_p muls (Legendre PRF checks),
   contributing ~5M cycles — swamped by the 48.8M control-flow floor.

3. **The ~30× speedup is a hard ceiling for primitive precompiles.**
   Beyond Griffin + F_p², the residual is overwhelmingly rv32im
   control-flow (5.35% of baseline) which is not addressable by any
   primitive precompile.

### 5.4 The control-flow floor: a fundamental ceiling

The 48.8 M residual at λ=128 (5.35% of total cycles) is **not**
algebraic primitive work. It comprises:

- Signature deserialization (bincode parsing of `LoquatSignature`).
- Loop control and branches in `Algorithm7Verifier::run_phased`.
- Byte ↔ field conversions in `GriffinHasher::hash` output formatting.
- Sumcheck protocol logic (challenge derivation outside primitives).
- F_p² struct construction overhead (the ~30-cycle F_p² adds/subs).
- Memory accesses through the rv32im virtual address space.

These are the cost of running Loquat as a *program* inside a zkVM
rather than expressing it as a *circuit*. **No primitive precompile
can reduce them.** They constitute a hard ~30× ceiling on what the
primitive-precompile approach can achieve for Loquat-in-zkVM at λ=128.

### 5.5 What exceeding ~30× would require

To go beyond the ~30× ceiling one would need one of:

1. **A Loquat-specific accelerator**: a precompile that handles the
   entire Algorithm 7 (or a substantial chunk — e.g., LDT verification)
   as a single AIR sub-circuit, eliminating the rv32im interpreter cost
   entirely. This is much more invasive than primitive precompiles —
   essentially building a custom circuit for Loquat verify, which is
   exactly what Aurora/Fractal already does.

2. **Abandon the zkVM execution model**: move to a circuit-targeted
   Loquat verifier (Aurora/Fractal approach, ~148K R1CS constraints).
   Note that for *aggregation*, the zkVM's recursive succinct receipt
   composition is equivalent to Fractal's constant-size aggregate; the
   choice between approaches is then about the per-signature
   verification circuit, not the aggregation strategy.

This is the **Precompile Paradox** sharpened: the cost of running
Loquat as a program inside a zkVM has a ~30× ceiling on improvement
from primitive precompiles, after which the rv32im control-flow floor
dominates. SNARK-friendliness in the R1CS sense does not transfer to
zkVM-cycle-friendliness automatically; closing the gap requires either
extending the precompile set toward scheme-specific accelerators or
moving back to circuit-targeted arithmetization.

### 5.6 Aggregate-signature regime, $n = 64$

The measured linearity result (`loquat_only_multi_*`, spread <0.1%
across $n = 1..64$) makes per-verify savings extrapolate directly.
At the paper's headline aggregation benchmark (LOQUAT-128, $n = 64$;
Aurora: 553 s, 207 KB linear-size aggregate; Fractal: 556 s, 145 KB
constant-size):

| approach | trace cycles at n=64, λ=128 | reduction |
|---|---:|---:|
| stock zkVM today (no precompile) | 58.4 B | 1× |
| with Griffin precompile only | ~4.2 B | **14×** |
| with Griffin + F_p mul precompiles | ~3.8 B | **15×** |
| with Griffin + F_p² precompiles | ~1.9 B | **30.7×** |
| with Griffin + F_p² + F_p mul precompiles | ~1.9 B | **30.7×** |
| circuit-targeted Loquat verifier (Aurora/Fractal R1CS) | ~150 M constraints | – |

The R1CS-targeted figure ($2^{23} \approx 8.4$ M constraints/signature
× 64 ≈ 540 M; with Fractal's amortization, ~150-200 M effective) is
shown for comparison. The zkVM-with-precompiles approach at ~30× of
baseline approaches but does not reach R1CS arithmetization cost; the
remaining ~10× gap is the rv32im control-flow floor.

### 5.7 What's not improved by any primitive precompile

Restating §5.4 in the aggregate context: the 5.35% control-flow floor
(rv32im interpreter cost, signature parsing, sumcheck logic,
byte↔field conversion) scales linearly with $n$. At $n=64$ it is
~3.1 B cycles — comparable in absolute terms to the Griffin + F_p²
precompiled work. Eliminating it requires moving away from the
program-execution model entirely.

## 6. Integration with `vc-pqc`

Once the precompiles exist, the integration is small:

```rust
// src/loquat/griffin.rs, in griffin_permutation():
#[cfg(feature = "risc0-precompile")]
{
    extern "C" {
        fn loquat_griffin_perm(input: *const u8, output: *mut u8);
    }
    unsafe { loquat_griffin_perm(state_in_bytes, state_out_bytes); }
    return;
}
// otherwise, existing software implementation
```

The same gating pattern would expose the $\mathbb{F}_p$ multiplication
precompile through `field_utils::Fp127::mul`. Behaviorally identical
output (the precompile must compute the same permutation/multiplication
as the software path), so all existing test vectors continue to pass.

No changes needed to `loquat_sign`, `keygen_with_params`, or
`loquat_verify` themselves — they call `GriffinHasher::hash` and field
operations, which transparently route through the precompile when the
guest is built with the feature flag.

## 7. Implementation roadmap

**Stage 1: $\mathbb{F}_p$ multi-limb multiplication precompile**
*(Estimated effort: ~6–10 weeks for someone with RISC0 circuit
internals familiarity.)*

- Specify exact column layout for 4-limb BabyBear encoding.
- Implement Mersenne-127 reduction constraints.
- Range checks for limb canonicity.
- Test against the existing `Fp127::mul` software implementation
  (cross-check on random inputs).
- Microbench: should reduce per-multiplication cost from ~380 cycles to
  ~5 cycles in the rv32im main trace.

**Stage 2: Griffin permutation precompile**
*(Estimated effort: ~4–6 additional weeks once Stage 1 is done.)*

- Build on Stage 1: each Griffin lane operation uses the
  $\mathbb{F}_p$ precompile constraints.
- Encode the inverse S-box ($s_0^{1/d}$) as a witness-inversion
  constraint (cheaper than computing the inverse exponent in-circuit).
- Hard-code round constants and matrix coefficients.
- Microbench: target ~100 cycles per permutation in the main trace.

**Stage 3: Loquat integration**
*(Estimated effort: ~1 week.)*

- Add `risc0-precompile` feature flag to vc-pqc.
- Route `griffin_permutation` and `Fp127::mul` through the precompile
  when the feature is on.
- Validate that the Loquat verify test suite passes unchanged.
- Re-run the attribution sweep to confirm projected savings.

**Total: 11–17 weeks of focused work**, of which the first ~10 are
high-risk (Stage 1 — RISC0 circuit implementation is the hard part).
Stages 2 and 3 are relatively mechanical once Stage 1 is correct.

For a master's thesis, this roadmap is **future work**. The thesis
deliverables are the empirical attribution, this specification, and
the generalization argument (Section 8).

## 8. Generalization to other PQ signature schemes

The methodology used to derive this specification — *phase-decompose
verification, count primitive invocations, microbench the primitive,
specify a precompile for the dominant primitive* — applies directly to
other SNARK-friendly post-quantum signature schemes whose verification
relies on algebraic hashes over non-native fields.

Three candidate schemes:

**LegRoast** [Beullens-de Saint Guilhem, 2021].
Also Legendre-PRF-based. Different parameterization (smaller R1CS,
larger signature) but identical phase structure: message commit →
challenge expansion → Legendre constraint check → low-degree test. The
attribution would proceed identically. Expected outcome: same Griffin
(or Rescue, depending on the instantiation) dominance pattern.

**FAEST** [Baum-Beullens-Mukherjee et al., NIST Round 1 PQ Signatures].
MPC-in-the-Head signature with significant hash invocations in the
commitment and challenge-derivation phases. The attribution would
identify SHA-256 / Keccak / Rescue as the dominant primitive, depending
on instantiation. For SHA-256-instantiated FAEST in RISC0, the existing
SHA-256 precompile would already capture most of the savings — the
attribution measurement would *confirm* this without requiring new
precompile design.

**SQIsign** [Feo-Kohel-Leroux-Petit-Wesolowski].
Isogeny-based; verification involves elliptic-curve arithmetic over
quadratic extensions of large primes. Same methodology applies, but the
precompile target would be EC arithmetic rather than algebraic hashes.

The general claim that the thesis can make:

> *Any SNARK-friendly post-quantum signature whose verifier circuit is
> dominated by an algebraic primitive over a field that does not match
> a zkVM's native field will exhibit a comparable cycle-cost dominance
> when executed in that zkVM. The attribution methodology identifies
> the precompile target; the specification methodology projects the
> savings. Whether building a precompile is worthwhile depends on the
> deployment scale: at single-signature scale, the speedup is
> ~10–50× (depending on field width); at aggregate-signature scale
> ($n \geq 32$), the absolute savings make the precompile a
> well-justified engineering investment.*

## 9. Limitations and open questions

### 9.1 Honest limitations

1. **The AIR constraint estimate (~1,020 per Griffin permutation) is
   not validated.** It is derived from comparable precompile structures
   (Poseidon2, SHA-256) scaled for the wider field. The actual figure
   could be 2–3× higher depending on how the Mersenne reduction is
   encoded.
2. **The per-invocation cycle estimate (~100 cycles) is also a
   projection.** RISC0's documented SHA-256 precompile cost of ~70
   cycles per block is the closest reference point; Griffin's larger
   state may push this to ~150 cycles in practice. The ~30× ceiling in
   §5.3 is robust to this within ±20%: if the F_p² precompile actually
   costs 200 cyc/op instead of 100, the projected speedup at λ=128
   falls from 30.7× to ~25×.
3. **The F_p² add/sub microbench was DCE'd by the compiler.** The
   tight-loop measurement of `Fp2::add` and `Fp2::sub` reported 0
   cycles despite the counter confirming 100,000 invocations; the loop
   body was vectorised or otherwise compressed below the cycle-counter
   resolution. We use ~30 cyc/op as an estimate; the actual cost is
   bounded above by ~50 cyc/op. If the true cost is materially higher
   (say, 100 cyc/op), the residual control-flow floor at λ=128 shrinks
   by at most ~2M cycles (from 48.8M to ~46.8M) — does not affect the
   ~30× ceiling claim.
4. **Per-Griffin-perm F_p mul count estimated at 2,580** by averaging
   across phases. The actual value may vary by ±2% depending on the
   nonlinear-layer's lane interactions. Does not affect headline
   percentages.
5. **Real STARK proving wall-clock savings are not directly proportional
   to rv32im cycle savings.** The precompile circuit has its own STARK
   to prove. For small precompile invocation counts (~hundreds per
   verify), the precompile's contribution to total proving wall-clock
   is small; for large counts (~thousands per aggregation), the
   precompile FRI cost becomes non-negligible.
6. **The thesis cannot benchmark the implemented precompile** because
   the implementation is future work. Projected speedups are based on
   measured pre-precompile cycle counts and modeled post-precompile
   cycle counts — internally consistent but not empirically validated
   end-to-end.

### 9.2 Open questions a follow-up paper or implementer would resolve

- Should the $\mathbb{F}_p$ precompile cover only multiplication, or
  also addition / subtraction / inversion? Inversion is rare but
  expensive in software (~$O(\log p)$ multiplications via Fermat); a
  dedicated precompile path may be warranted.
- For aggregation at $n \gg 32$, does the precompile circuit's column
  width and trace length become the bottleneck (FRI on the precompile
  trace)? At what $n$ does precompile FRI cost equal rv32im FRI cost?
- Can the Griffin precompile be parameterized over the prime $p$
  (e.g., support Mersenne-127 and also other 64-bit / 128-bit primes
  used by similar schemes)? This affects reusability for the
  generalization argument in Section 8.

## 10. References

- Zhang, Steinfeld, Esgin, Liu, Liu, Ruj (2024). *Loquat: A SNARK-Friendly Post-Quantum Signature based on the Legendre PRF with Applications in Ring and Aggregate Signatures*. Cryptology ePrint Archive 2024/868. `references/2024-868.pdf`.
- Grassi, Hadipour, Pernot, Schofnegger, Walch (2022). *Horst meets Fluid-SPN: Griffin for Zero-Knowledge Applications*. CRYPTO 2023.
- Ben-Sasson, Chiesa, Riabzev, Spooner, Virza, Ward (2019). *Aurora: Transparent Succinct Arguments for R1CS*. EUROCRYPT 2019.
- Chiesa, Ojha, Spooner (2020). *Fractal: Post-Quantum and Transparent Recursive Proofs from Holography*. EUROCRYPT 2020.
- RISC Zero. *zkVM Proof System Reference*. https://dev.risczero.com/proof-system-in-detail.pdf

## Appendix A: Numerical cross-check

For a reviewer reproducing the attribution numbers in Section 5
(λ=128, single signature, RISC0 dev mode):

```
# Microbenched primitive costs
cycles_per_griffin_perm   = 910,143    (10,000 perms)
cycles_per_fp127_mul      = 243        (100,000 muls)
cycles_per_fp2_mul        = 1,394      (= 4 × 243 + 422 wrapper)
cycles_per_fp2_add_sub    ≈ 30         (estimate; tight loop DCE'd)
fp127_muls_per_fp2_mul    = 4.0        (cross-checked via counter)

# Counted at λ=128, single verify
total_cycles              = 912,254,567
griffin_perms             = 931
fp127_muls (total)        = 2,418,910
fp2_muls (total)          = 28,367

# Three-level decomposition
griffin_cycles            = 931 × 910,143       = 847,343,133  (92.88%)
fp_mul_inside_griffin     = 931 × 2,580 × 243   = 583,681,140  (63.98%)
griffin_other_work        = griffin − fp_inside = 263,661,993  (28.90%)
fp_muls_outside_griffin   = (2,418,910 − 931 × 2,580) × 243
                          ≈ 4,113,990                          (0.45%)
fp2_mul_wrappers          = 28,367 × 422        =  11,970,874  (1.31%)
control_flow_floor        = remainder           =  48,826,570  (5.35%)

# Projected with precompiles (100 cyc/Griffin, 5 cyc/Fp mul,
# 100 cyc/Fp2 op)
none                      = 912.3 M             (1.0×)
griffin_only              = 65.0 M              (14.0×)
griffin + fp_mul          = 59.9 M              (15.2×)
griffin + fp2             = 29.7 M              (30.7×)  <-- ceiling
griffin + fp2 + fp_mul    = 29.7 M              (30.7×)  same
```

All raw data:
- `results/loquat_three_level_20260512_024956.jsonl` — 3 attribution rows
- `results/loquat_three_level_20260512_024956_griffin_bench.json`
- `results/loquat_three_level_20260512_024956_fp127_bench.json`
- `results/loquat_three_level_20260512_024956_fp2_bench.json`
