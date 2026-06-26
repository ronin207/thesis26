# Thesis

## Research Goal

Reduce the proof-generation time for PLUM signature verification inside a
general-purpose zero-knowledge virtual machine (RISC Zero and SP1) to a
practically acceptable time on a personal PC (target hardware: MacBook Pro
M5 Pro, 18-core CPU, 20-core GPU, 24 GB RAM, 1 TB SSD), by constructing a
custom precompile suite that eliminates the field-mismatch overhead.

(*"Practically acceptable" is currently undefined and is an open question
to be settled operationally before final evaluation.*)

## Problem Statement

**Two field-mismatches in the stack — distinct, and only one is this
thesis's target.**

*(A) Protocol-level, Loquat → PLUM (already solved by PLUM §1.1).*
Loquat operates over `F_{p²}` with a 127-bit Mersenne prime, requiring
internal extension-field arithmetic. PLUM eliminates this by choosing a
single 192-bit prime `p = 2⁶⁴ · p₀ + 1` that simultaneously satisfies
Power-Residue-PRF and STIR requirements.

*(B) Substrate-level, PLUM → zkVM (this thesis's target).*
General-purpose zkVMs use small-characteristic prime fields — BabyBear
(`p = 2³¹ − 2²⁷ + 1`) in RISC Zero and SP1 (whose prover is built on
Plonky3, which also supports Mersenne-31, KoalaBear, and Goldilocks as
alternatives). When the PLUM signature-verification predicate
`Verify(pk, M, σ) → {0,1}` executes inside a zkVM guest, every 192-bit
field operation is emulated by multi-limb arithmetic over BabyBear
(~7 BabyBear limbs per 192-bit operand), and algebraic-hash primitives
like Griffin amplify the cost because each permutation invokes many such
operations.

Concretely, for PLUM-128 verification (analytical decomposition per
PLUM §4.2 p.125; the thesis's current measurements are on PLUM-80, with
proportionally different counts — see four_scheme_benchmark.md for measured
values):

- **977 Griffin permutations** per PLUM-128 verify: 30 hash-chain
  compressions + 69 challenge-expansion expansions + 878 Merkle-commitment
  compressions. **PLUM-80 measured value: 1052 Griffin permutations**
  (`GRIFFIN_FP192_PERMUTE` syscall count, Cell 2) — decomposition to be
  re-derived for PLUM-80 parameters.
- **10,333 algebraic R1CS constraints total** per PLUM-128 verify
  (PLUM §4.2 p.125), decomposed across multiple buckets: 746 virtual-oracle
  response multi-limb 192-bit modular multiplications, 911 Lagrange
  interpolation multiplications, 2,184 point evaluations, 168 FFT/IFFT
  polynomial interpolation, plus the 5,628 from PRF symbol checks (next
  bullet) and ~700 other. The 746 figure is one sub-bucket, not the total.
- **28 t-th power-residue PRF symbol checks** per verify, each a modular
  exponentiation `a^((p-1)/t) mod p` with `t = 256` fixed (≈ 5,628 R1CS
  constraints total per PLUM §4.2).

PLUM §4.2's R1CS decomposition reports that 105,952 of the 116,285
constraints in PLUM-128 verification (91.1%) are hash permutations.
Without precompile support, the cost of these primitives is dominated by
the multi-limb field-emulation tax (mismatch B above) over BabyBear,
putting end-to-end proof generation beyond a practical bound on the target
hardware.

## Approach

**Goal (per Sako's A→B template):** make PLUM Verify (A) generate proofs in
practically acceptable time inside a zkVM (B) on a personal PC.
**Means:** construct a custom precompile suite that bypasses field
emulation for the primitives that dominate the cost.

### Construction

Three precompile AIR modules, in expected cycle-share order:

1. **Griffin permutation over PLUM's 192-bit prime field** — the
   load-bearing target (91% share). Instantiated as in Loquat: state
   size 4 for compression / 3 for expansion, capacity parameter 2;
   constraint cost 110 R1CS per compression and 88 R1CS per expansion.
2. **Multi-limb 192-bit modular arithmetic** (multiplication, addition,
   reduction) over `p = 2⁶⁴ · p₀ + 1`. Partially covered on RISC Zero by
   the existing 256-bit modular-multiplication precompile (10 cycles/op);
   the thesis ships a 192-bit-specific bigint program.
3. **t-th Power Residue PRF symbol check** (`t = 256` fixed): a constant-
   exponent bigint program implementing `a^((p-1)/t) mod p`.

Construction vehicle: RISC Zero v1.2 application-defined precompiles via
the Zirgen bigint MLIR dialect, OR SP1's custom-precompile framework. Both
are verified as feasible paths for a 192-bit-field Griffin AIR.

Each precompile ships with a written soundness argument tying the AIR
constraints to the reference specification, so that the precompile layer
preserves PLUM's EU-CMA security under the assumption that the zkVM's
cross-table lookup argument is sound.

**Zero-knowledge property — conditional, currently open.** The current
SP1 measurements (Cell 1/2/3) use `client.prove(&pk, stdin).run()`
(verified in `platforms/zkvms/sp1/script/src/bin/plum_host.rs:339`,
`bench_pqc.rs:313`, `griffin_smoke_host.rs:108`). Per Succinct's own
documentation (`docs.succinct.xyz/docs/sp1/security/security-model`),
individual STARK proofs in SP1 produced by the default `prove()` path do
NOT satisfy the zero-knowledge property. ZK is obtained only by chaining
`.compressed().groth16()` or `.compressed().plonk()`. The thesis adopts
a baseline-then-ZK measurement arc as an explicit object of study:

  - Baseline (Cell 1/2/3 as currently measured): succinct STARK proofs,
    not zero-knowledge.
  - ZK-wrapped (to be measured): `.compressed().groth16()` on the same
    workload; the prove-time delta captures the ZK-wrapping cost.

Any anonymity claim depending on the underlying zkSNARK being ZK
(notably BDEC Theorems 2 and 3 in Li, Zhang et al., ProvSec 2024) holds
only for the ZK-wrapped variant. Cell 4's OUTER circuit-SNARK (Aurora) is ZK at
the IOP level per Aurora Theorems 1.1 + 1.2 when zk is enabled — this is the
anon-cred prover, DISTINCT from PLUM's own INNER STIR signature IOP. (The measured
Aurora proxy ran zk=false; verified 2026-06-05.)

### Parameter rationale (knobs the thesis does not vary, with reasons)

These parameter choices are inherited from PLUM and pinned for the
thesis; any reviewer asking "why this value?" should be answered by the
points below.

- **λ = 80 (Cell 1/2/3 measurements).** PLUM-128 is the paper's headline
  parameter; the thesis measures PLUM-80 because Cell 1 already does not
  terminate within the 24 GB / 3-hour bound at λ=80 on the target
  hardware. λ=128 would worsen the memory/time ceiling. Re-measurement
  at λ=128 is feasible only after Cell 1's terminate-vs-DNF threshold is
  understood.
- **t = 256 (Power Residue PRF parameter).** Pinned by PLUM §3.3 p.123:
  t = 256 with β = 0.961, L = 2¹², yields B = 28 for 128-bit security.
  Note: per PLUM §2.1 p.115 verbatim, *"when t = 2, the power residue
  PRF is equivalent to the Legendre PRF"* — i.e., **PLUM with t = 2
  collapses to Loquat**. The thesis's PLUM-vs-Loquat measurement
  conflates the t change with the FRI→STIR change and the hash-family
  change; future work could isolate the t-axis by varying it alone.
- **η = 4 (STIR folding parameter).** Pinned by PLUM §3.3 p.123 verbatim:
  *"slightly smaller than the recommended folding parameter in STIR …
  this choice is due to the relatively small polynomial degree in our
  protocol (d* = 128 for PLUM and d* = 256 for PLUM*), which prevents
  us from using the recommended η = 16."* The thesis measures within
  this off-recommendation regime; STIR-canonical η = 16 would require
  switching to PLUM* with proportionally larger signatures.
- **PLUM prime substitution.** The paper's printed `p₀` (PLUM §3.3 p.123)
  is composite (smallest prime factor 97; verified by
  `tests/plum_field_primality.rs::paper_p0_is_composite`). The Rust
  implementation substitutes a near-by 199-bit `p₀` that preserves
  bit-width, 2-adicity ≥ 64, and `t = 256 | p − 1`. The substitution
  is acceptable for cycle-count and timing measurement (which depend
  on bit-width and 2-adicity, both preserved) but not for any claim
  conditioned on the specific decimal value of `p`. **Action item:**
  contact PLUM authors for the canonical `p₀`.

### Four-cell evaluation

| Cell | Setting | Role |
|---|---|---|
| 1 | PLUM-Griffin in zkVM **without** custom precompile | baseline (current field-mismatch state) |
| 2 | PLUM-Griffin in zkVM **with** custom precompile | predicted ~10× speedup, Amdahl-capped at 91% hash share |
| 3 | PLUM-SHA in zkVM (existing SHA-256 precompile) | control: what precompile availability alone buys |
| 4 | PLUM Verify in the OUTER circuit-SNARK (R1CS). NB: STIR is PLUM's OWN inner signature IOP, NOT the outer prover — do not label the outer system "Aurora/STIR". Measured proxy = Loquat-BDEC in Aurora/Fp127 (PLUM-in-Aurora-Fp192 not runnable: fp127-only harness; see docs/r_static_finding_20260605.md) | in-SNARK reference baseline |

Loquat is retained only as historical reference; the central comparison
is PLUM-Griffin with-vs-without the shipped precompile.

### Feasibility evidence

- **Plonky3's Poseidon2 AIR** — existence proof that algebraic-hash AIRs
  are an engineering-solved pattern (one permutation per row, fixed
  constraint structure).
- **Zirgen's bigint MLIR dialect**, used to build `ec_add` / `ec_double`
  precompiles over 256-bit prime fields — structurally analogous to
  192-bit Griffin S-box arithmetic.
- **SP1's custom-precompile framework** documents the engineering path
  explicitly.
- **Comparable speedups in the literature**: Automata RSA 39M → 217K
  cycles; BN254 / BLS12-381 in R0VM 2.0 cutting Ethereum block proving
  35min → 44s.

## Requirements

**Deliverable set:**

- 3 precompile AIR modules (Griffin permutation, 192-bit modular
  arithmetic, t-th Power Residue PRF symbol check)
- Written soundness arguments, one per AIR module
- A PLUM Verify Rust crate invoking the precompiles via the appropriate
  RISC-V syscalls
- Four-cell measurement data + analysis

**Metrics to report (per Wu AQ8 — explain where the speedup comes from):**

- Total proof generation time (the goal-aligned metric)
- Cycle count
- Trace size
- Memory usage

**Open question requiring an operational answer before final evaluation
(per Wu AQ7):**

- What proving time counts as "practically acceptable" on the target
  hardware?

# Project Directory (it will be alphabetically ordered of course)
THESIS
|- .venv
|- submodules
|-- libiop
|- references
|-- all existing pdfs...
|- platforms
|-- compilers
|---- noir
|-- zkvms
|---- risc0
|---- jolt
|---- sp1
|- src
|-- primitives
|---- all existing primitives...
|-- anoncreds
|---- bdec
|-- signatures
|---- loquat
|---- plum
|-- snarks
|---- aurora
|---- fractal
|...
|- 修論2025_Takumi
|- CLAUDE.md

# Sako's Approach
> 目的と手段について。この機会にみなさんも考えてください。「AをBするためにAのCをDにおきかえてみる」という場合、「AをBする」のが目的、「CをDにおきかえる」は手段です。興味本位で「CをDにおきかえてみたらどうなるか」といってもいいですが、その場合、そもそもCとDは同等のものなのか、おきかえてみたときの評価軸はどういうものがあるのか、というのが明確ではありません。自分にとっては「CとDは同等のものであるとわかりきっている」「評価軸は明確である」としてもそれが他人に伝わっていない、あるいは、他人はそれに同意していないかもしれません。これは誰もがおちいる落とし穴だと思うので、ご自身もふりかえってみてください。

# Github
