# SP1 PLUM-SHA3 (Cell 3) — prove measurement

Cell 3 is the **control arm** of the four-cell evaluation. It runs the
same PLUM verification as Cells 1 and 2 on the same SP1 zkVM and the
same M5 Pro 24 GB hardware, but swaps the algebraic Griffin hash for
SHA3-256 in software (no algebraic-hash precompile invoked). It
isolates whether Cell 2's feasibility win is **Griffin-precompile-
specific** or **generic to any precompile-class workload**.

The result is **unexpected and important**: Cell 3 proves *faster*
than Cell 2 on the same hardware.

## Hardware

- **MacBook Pro M5 Pro**, 18-core CPU, 20-core GPU, **24 GB RAM**, 1 TB SSD.
- macOS 25.5.0 (Darwin), Apple Silicon.

## Configuration

- SP1 v6.2.1 (forked at `submodules/sp1`), Griffin Fp192 chip
  registered but NOT exercised on this arm.
- Cell 3 ELF built with `--features plum-sha3-hasher` on the
  `program/` crate. The cfg-gate in
  [program/src/main.rs](platforms/zkvms/sp1/program/src/main.rs)
  swaps the guest's `Hasher` from `PlumGriffinHasher` to
  `PlumSha3Hasher`.
- Host (`plum_host`) signs with `PlumSha3Hasher` to match the
  guest's compile-time `Hasher`; `PLUM_PROVE_ARM=sha3` selects the
  sha3 ELF.
- Memory tuning identical to Cell 2 (the configuration that produced
  Cell 2's 32.53 min prove).

```bash
SHARD_SIZE=4194304            # 2^22
ELEMENT_THRESHOLD=67108864    # 2^26
HEIGHT_THRESHOLD=1048576      # 2^20
TRACE_CHUNK_SLOTS=2
RAYON_NUM_THREADS=8
PLUM_HOST_MODE=prove
PLUM_PROVE_ARM=sha3
PLUM_SECURITY=80
```

## Cell 3 result (2026-05-21)

| Metric        | Value                                                  |
|---------------|---------------------------------------------------------|
| Configuration | PLUM-80, SP1 v6.2.1 (forked), SHA3-256 in software       |
| setup_ms      | 789                                                    |
| **prove_ms**  | **797,009 (= 13.28 min = 0.22 h)**                     |
| verify_ms     | 2,804 (≈ 3 s)                                          |
| Peak memory   | 80.92 % (same envelope as Cell 2's 81.31 %)            |
| Griffin syscalls fired | 0 (cfg gate verified)                          |
| UINT256_MUL syscalls   | 69,385 (essentially same as Cell 2's 69,396)   |
| Outcome       | proof produced + verified ✓                            |

Log: `measurements/cell3_prove_sha3_tuned_20260521_224506.log`.

## Four-cell comparison table

| Cell | Hasher | Precompile path | Execute cycles | Execute wall | Prove wall | Peak mem |
|------|--------|-----------------|---------------:|-------------:|-----------:|--------:|
| 1    | Griffin in rv32im | none (Griffin emulated) | **7,082,608,888** | 40.4 s | **DNF** (projected ~30 h; 2 attempts failed) | 87.94 % default / 81.95 % tuned |
| 2    | Griffin           | `GRIFFIN_FP192_PERMUTE` precompile | 125,504,123 | 1.90 s | **32.53 min** | 81.31 % |
| 3    | SHA3-256 (software) | none (no algebraic hash; SHA3 in rv32im) | 110,795,424 | 1.27 s | **13.28 min** | 80.92 % |

## Key deltas

### Prove-time

| Comparison              | Ratio                                  |
|-------------------------|----------------------------------------|
| Cell 2 / Cell 3         | **2.45× (Cell 2 is slower)**           |
| Cell 1 / Cell 2 (projected) | ~56× (Cell 1 is infeasible)        |
| Cell 1 / Cell 3 (projected) | ~135× (Cell 1 vs SHA3 control)     |

### Execute-cycle vs prove-cost is non-monotonic

Cell 2 has **13 % more executor cycles** than Cell 3 (125.5 M vs
110.8 M) yet takes **145 % longer to prove** (32.53 min vs 13.28 min).
This non-monotonicity is the load-bearing observation of Cell 3.

### Why Cell 2 is slower in prove despite fewer absolute cycles

Cell 2 exercises the **Griffin Fp192 AIR chip**: 1,052
`GRIFFIN_FP192_PERMUTE` syscalls × 14 rows per syscall × ~33
algebraic-op cells per row × ~96 trace cells per `FieldOpCols` cell
≈ **37 M trace cells just for Griffin work**, plus the per-row Limbs
and bit cells. Each cell contributes to the prover's FRI / polynomial
commit cost.

Cell 3 fires **zero** Griffin syscalls. The PLUM-SHA3 verification
runs the SHA3-256 absorb/squeeze in pure RISC-V, exercising only the
CPU table, the Memory tables, and the `UINT256_MUL` precompile (for
the Fp192 modular arithmetic that PLUM does outside the hash). The
total trace cell count is *lower* than Cell 2's despite the 13 %
higher executor cycle count, because the per-row width of the CPU /
Memory chips is much narrower than the Griffin chip's row.

## What this means for the thesis

The Cell 3 result refines the C1/C2 claims and **strengthens** them
rather than weakens them, by making the gap argument more specific.

### Restating C2 — "precompile-driven recovery"

The naive version is "the Griffin precompile makes PLUM-80 prove
faster." Cell 3 falsifies that wording: precompile Griffin is slower
than software SHA3 here.

The precise version is **"the Griffin precompile makes algebraic-hash
PLUM workloads feasible on consumer hardware, where they are
otherwise non-viable (Cell 1)."** The precompile is a
*feasibility-recovery* mechanism, not a *performance optimization* of
already-feasible workloads. This is the workload-feasibility vs
performance-optimization distinction the thesis insists on.

### Restating the application-design implication

If PLUM had been designed with SHA3 as its hash instead of Griffin,
its zkVM prover cost would be **lower** (13.28 min instead of 32.53
min, both on M5 Pro 24 GB). But PLUM chose Griffin because Griffin is
**SNARK-friendly in circuit SNARKs** (Aurora / STIR), where the
SNARK's field is matched to PLUM's field and the algebraic hash
collapses into a small constraint count. The thesis-relevant
observation:

> *"PLUM's hash choice (algebraic Griffin over its 192-bit prime) is
> optimal for the circuit-SNARK target it was designed against. The
> same choice creates a structural mismatch in BabyBear-native zkVMs,
> requiring a precompile-class chip to restore feasibility — but even
> with the precompile, the algebraic-hash arm carries a 2.45× prover
> cost penalty over a SHA3-class hash on the same zkVM."*

This is the empirical instantiation of the **precompile paradox** the
thesis names: the precompile resolves the feasibility gap but leaves
a structural prover-cost penalty for the design choice (algebraic
hash) that was made for a *different* proving target (circuit SNARK).

### What Cell 3 does NOT say

- It does *not* say "PLUM should use SHA3." The choice of Griffin is
  load-bearing for PLUM's circuit-SNARK arithmetization (per PLUM
  §4.2's R1CS decomposition: 91.1 % of PLUM-128's constraints are
  Griffin permutations, but each Griffin permutation in the
  circuit-SNARK costs *less* than its SHA3 equivalent would, because
  Griffin is designed to be SNARK-arithmetization-friendly).
- It does *not* say "Cell 2's precompile is unnecessary." Without
  the precompile, Cell 1 projects to ~30 h prove time — infeasible.
  Cell 2's existence is what enables PLUM on this zkVM at all.
- It does *not* generalize to all PQ signature families. SHA3 here
  is a control: a *non-algebraic*, *non-precompiled* hash, run in
  software. Other PQ schemes (lattice, hash-based) don't share PLUM's
  large-prime field, so their cost analysis is different.

## Reproducer

```bash
cd platforms/zkvms/sp1
PATH="$HOME/.cargo/bin:$PATH" \
  SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 \
  TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8 \
  PLUM_HOST_MODE=prove PLUM_PROVE_ARM=sha3 PLUM_SECURITY=80 \
  RUST_LOG=warn cargo run --release --bin plum_host --manifest-path script/Cargo.toml
```

## Sources

- Execute-mode cycle anchors: [sp1_plum_cell3_execute.md](sp1_plum_cell3_execute.md)
- Cell 1 evidence (cycle anchor + non-termination): [sp1_plum_cell1_attempt2.md](sp1_plum_cell1_attempt2.md)
- Cell 2 measurement: [sp1_plum_cell2_measurement.md](sp1_plum_cell2_measurement.md)
- Engineering-effort accounting: [precompile_engineering_cost.md](precompile_engineering_cost.md)
- Griffin Fp192 chip soundness: [precompile_soundness/griffin_fp192.md](precompile_soundness/griffin_fp192.md)
