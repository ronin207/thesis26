# On-spec power-residue settle — dedicated chip vs stock UINT256_MUL baseline

Date: 2026-07-11
Machine: Apple M5 Pro, 24 GB. Config: PLUM-80, λ=80, SP1_PROVER=cpu,
RAYON_NUM_THREADS=8, standard-Griffin.
Fork: `.claude/worktrees/thesis-restructure-criterion/sp1-fork`
(sp1 v6.2.1), branch `prf-precompiles`, HEAD **25d4241c6**
(Step-0 protect commit `9e7812bee`; u256 guest commit `25d4241c6`).
Non-synced `target/` cache; nothing in the main thesis repo built here.

## Purpose

Close the cost criterion's **open positive case** (the power-residue PRF
symbol chip, §5:115 / §6:283). The earlier `certain_tier_20260706` settle
had two named defects: (1) **n=1**, and (2) **off-baseline** — its
square-and-multiply arm used the custom `FP192_MUL`, whereas the criterion
names the **stock `UINT256_MUL`** the measured PLUM verification path
actually uses. This run fixes both.

## Method

Two single-arm guests, identical 28-symbol workload of a fixed canonical
operand `a0 < p` (PLUM's 199-bit prime), committing the identical 32-byte
symbol (correctness asserted vs an independent BigUint reference in each
guest's execute test):

- **Chip arm** (`fp192-powres-b2`): 1 `FP192_POW_RES` syscall / symbol.
- **On-spec baseline** (`fp192-powres-sm-u256`, NEW): MSB-first
  square-and-multiply over the stock `sys_bigint` (`UINT256_MUL`) with `p`
  passed as the runtime modulus — `L + popcount(e) = 191 + 70 = 261`
  `UINT256_MUL` syscalls / symbol.

Metric (per §6:283): **total committed machine trace area** = Σ over
shards of the prover's per-shard `Total number of cells` (field-op **plus**
control, base RISC-V **plus** precompile), end-to-end. Summed over **all**
shards (correcting the `certain_tier` summary TSV, which reported only the
first shard's cells and so mis-showed 15.6×).

Tests: `test_fp192_powres_{b2,sm_u256}_only_prove`
(`crates/core/machine/src/syscall/precompiles/fp192_powres/mod.rs`).
Command: `RUST_LOG=warn,sp1_hypercube::prover=debug cargo test --release
-p sp1-core-machine test_fp192_powres_<arm>_only_prove -- --nocapture`.

## Results (n=3)

Both arms prove **3 shards**, prove+verify OK every run. Trace area is
deterministic, so all three runs are identical (reproducibility, not
statistical spread):

| Arm | committed cells (Σ 3 shards) | per-shard | wall (n=3) |
|---|---|---|---|
| Chip `FP192_POW_RES` (B2) | **11,369,616** | 1,937,552 + 4,830,240 + 4,601,824 | 8.7–9.4 s |
| On-spec `UINT256_MUL` S&M | **117,460,272** | 62,710,864 + 50,026,560 + 4,722,848 | 15.7–17.4 s |
| **PAY (baseline / chip)** | **10.33×** | | |

For context, `certain_tier_20260706`'s off-baseline (`FP192_MUL`) arm gave
6.14×; switching to the heavier stock `UINT256_MUL` baseline the criterion
actually names strengthens the pay to **10.33×**, as expected.

Execute-mode cross-check (`test_fp192_powres_*_only_execute`,
committed_symbol_ok=true both): chip 365 cyc/symbol; `UINT256_MUL` loop
14,421 cyc/symbol — a 39.5× RISC-V-side cycle reduction for the chip.

## Mechanism

The pay is the **261:1 syscall-count collapse**, not per-op arithmetic.
The baseline issues 28 × 261 = 7,308 `UINT256_MUL` syscalls; the chip
issues 28. Each syscall drives the cross-shard memory bus (`Global` chip),
whose cells dominate the baseline's shards 1–2 (62.7M + 50.0M). This is the
irreducibly-large-prime component the criterion predicted would pay.

## Honest caveats

- **Trace area is deterministic**; n=3 confirms reproducibility, not a
  statistical distribution. Wall time varies (overhead-dominated at N=28)
  and is a secondary, not the priced, metric.
- **N=28 isolated batch.** In-situ, the 28 PRF-symbol checks sit inside the
  full PLUM verification whose shard structure differs; the isolated ratio
  is the like-for-like settle the criterion specifies, not a claim about
  the in-situ marginal cost.
- **Chip is the naive B2**, not a fused addition-chain chip. On the
  per-operation arithmetic axis B2 is 1.22–1.49× *larger*
  (`keystone_chipprove_20260706`); that objection is orthogonal to this
  total-machine result and a fused chip would only widen the 10.33×. The
  fused chip remains future work; it is not needed to establish the pay.
- Peak RSS not sampled in these runs (small workload; the
  `certain_tier_20260706` B2 arm peaked 2.79 GB, far within 24 GB).

## Bottom line

The power-residue PRF-symbol chip **pays 10.33×** on total committed trace
area against the on-spec stock-`UINT256_MUL` baseline, n=3, deterministic.
The criterion's open positive case is closed in the chip's favour.
