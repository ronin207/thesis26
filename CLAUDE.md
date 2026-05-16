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

**Field-mismatch overhead.** General-purpose zkVMs (RISC Zero, SP1) adopt
small-characteristic prime fields — BabyBear in RISC Zero and SP1,
Mersenne-31 in Plonky3 — because their proving systems generate proofs
faster over such fields. Post-quantum signature schemes in the Loquat /
PLUM family operate over large prime fields: Loquat over `F_{p²}` with the
127-bit Mersenne prime, PLUM over a 192-bit prime `p = 2⁶⁴ · p₀ + 1`. When
the signature-verification predicate `Verify(pk, M, σ) → {0,1}` is executed
inside the zkVM guest, every large-field operation is emulated by
multi-limb arithmetic over the zkVM's native field, and algebraic-hash
primitives like Griffin amplify the cost because each permutation invokes
many such operations.

Concretely, for PLUM-128 verification:

- 977 Griffin permutations per verification: 30 hash-chain compressions
  + 69 challenge-expansion expansions + 878 Merkle-commitment compressions
- ≈ 746 multi-limb 192-bit modular multiplications (FFT/IFFT polynomial
  interpolation over the smooth subgroup, point evaluations, virtual-
  oracle response computation)
- 28 t-th power-residue PRF symbol checks (each a modular exponentiation
  `a^((p-1)/t) mod p` with `t = 256`)

PLUM §4.2's R1CS decomposition reports that 105,952 of the 116,285
constraints in PLUM-128 verification (91.1%) are hash permutations.
Without precompile support, the cost of these primitives is dominated by
the multi-limb field-emulation tax over BabyBear, putting end-to-end proof
generation beyond a practical bound on the target hardware.

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
preserves PLUM's EU-CMA security and zero-knowledge property under the
assumption that the zkVM's cross-table lookup argument is sound.

### Four-cell evaluation

| Cell | Setting | Role |
|---|---|---|
| 1 | PLUM-Griffin in zkVM **without** custom precompile | baseline (current field-mismatch state) |
| 2 | PLUM-Griffin in zkVM **with** custom precompile | predicted ~10× speedup, Amdahl-capped at 91% hash share |
| 3 | PLUM-SHA in zkVM (existing SHA-256 precompile) | control: what precompile availability alone buys |
| 4 | PLUM-Griffin in Aurora/STIR (in-SNARK) | reference baseline from the original paper |

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
