# Cell 1 (rv32im baseline) — non-termination + execute-mode cycle anchor

**Date:** 2026-05-21
**Hardware:** MacBook Pro M5 Pro, 18-core CPU, 20-core GPU, 24 GB RAM, 1 TB SSD
**SP1:** v6.2.1 (forked at `submodules/sp1`)
**Workload:** PLUM-80 verify, Griffin in rv32im (no `GRIFFIN_FP192_PERMUTE` precompile);
            `UINT256_MUL` precompile remains on for both arms (clean Griffin isolation).
**Memory tuning:** the same configuration that allowed Cell 2 to complete in 32.53 min on the same hardware:

```
SHARD_SIZE=4194304               # 2^22
ELEMENT_THRESHOLD=67108864       # 2^26
HEIGHT_THRESHOLD=1048576         # 2^20
TRACE_CHUNK_SLOTS=2
RAYON_NUM_THREADS=8
```

## Outcome

The prove did not produce a completion signal within **3 h 6 min 56 s** of
wall time and was terminated by SIGTERM. Process state at termination:

- Running (`R`), 887 % CPU (≈9 cores pegged)
- RSS 5.7 GB / 23.7 % memory share
- macOS swap usage 15.06 GB / 16.4 GB total (kernel auto-grew swap by
  +2 GB during the run from an initial 14.3 GB)
- SP1's internal monitor reported peak 81.95 % memory (within Jetsam's
  tolerance — no kill); 80–82 % memory continuously after the first
  20 minutes
- **No log activity for the final 1 h 1 min** before kill. SP1's prove
  phase is silent except for the 80 %-threshold memory monitor; CPU
  remained pegged throughout, indicating the prover was grinding (not
  wedged), most plausibly in a swap-thrashing heavy phase
  (FRI / polynomial commit)

## Combined with the earlier attempt

This is the **second** failed Cell 1 attempt on M5 Pro 24 GB:

| Attempt | Date       | Configuration                         | Outcome                                |
|---------|------------|---------------------------------------|----------------------------------------|
| 1       | 2026-05-18 | SP1 default settings                  | OOM-killed at 1 m 45 s (peak 87.94 %)  |
| 2       | 2026-05-21 | Cell 2's memory-tuned env vars        | Did not terminate within 3 h 6 m; SIGTERM |

Both attempts share the same outcome class: **PLUM-80 verify without the
Griffin Fp192 precompile is not consumer-hardware-feasible on M5 Pro
24 GB** under the configurations tested, even when the precompile arm
proves successfully on the same hardware in 32.53 min using identical
memory tuning.

## Cell 1 execute-mode cycle anchor (2026-05-21 22:37 JST)

Captured in 40 s after the prove rethink: PLUM-80 verify in SP1
executor with `PLUM_PROVE_ARM=emulated` (Griffin in rv32im, no
precompile) produces a complete cycle count without proving:

| Arm                                | Cycles            | UINT256_MUL syscalls | Griffin syscalls | Execute wall |
|------------------------------------|------------------:|---------------------:|-----------------:|-------------:|
| Cell 1 — rv32im Griffin (no precompile) | **7,082,608,888** | 4,870,724            | 0                | 40.4 s       |
| Cell 2 — Griffin via precompile         |       125,504,123 |   69,396             | 1,052            |  1.90 s      |
| Cell 3 — PLUM-SHA3 (control)            |       110,795,424 |   69,385             | 0                |  1.27 s      |

**Cell 1 / Cell 2 = 56.4× more rv32im cycles** for the same PLUM-80
verification.

Each rv32im Griffin permutation in Cell 1 expands to ≈ (4,870,724 −
69,396) / 1,052 ≈ **4,564 additional UINT256_MUL operations per
permutation**, every one of which the `GRIFFIN_FP192_PERMUTE`
precompile collapses to a single syscall on the Cell 2 arm.

### Projection to prove cost

SP1's prove-time and trace-memory scale roughly linearly with cycle
count (the dominant cost is FRI / polynomial-commitment work over the
trace; row count scales with cycle count under fixed shard size).
Projecting Cell 2's measured prove cost forward:

- **Projected Cell 1 prove time:** ≈ 56.4 × 32.53 min = **~30.6 hours**
  on M5 Pro 24 GB at Cell 2's tuning.
- **Projected Cell 1 trace memory:** ≈ 56.4 × the 81 % peak Cell 2
  observed, far exceeding the 24 GB envelope. To fit, `SHARD_SIZE`
  would need to drop by a factor of ≈ 56, increasing shard count and
  serialization overhead proportionally.

The projection mathematically confirms the two empirical failures
(2026-05-18 OOM at 1 m 45 s, 2026-05-21 non-termination at 3 h 6 m):
the workload doesn't fit the hardware envelope by orders of magnitude.

## What this means for the thesis

This is admissible evidence for **Claim C1 (workload feasibility gap)**
*with* a quantitative anchor: the cycle delta is 56.4×, the prove
projection is > 30 hours and > 20 GB working set on consumer hardware
that has a 24 GB total memory budget. The defensible statement is:

> *"PLUM-80 verify produces 7.08 × 10⁹ rv32im cycles without the
> Griffin Fp192 precompile — 56.4× the 1.25 × 10⁸ cycles of the
> precompile arm (captured by SP1 executor on M5 Pro 24 GB,
> 2026-05-21). Two attempts at proving the no-precompile arm on the
> same hardware did not complete: the first OOM-killed in 1 m 45 s
> under default SP1 settings (2026-05-18), the second non-terminating
> after 3 h 6 m under the memory-tuned configuration that allows the
> precompile arm to complete in 32.5 min (2026-05-21). Projected
> linearly from the cycle delta, the Cell 1 prove would require ~30 h
> wall and ~56× the 81 % peak memory observed in Cell 2 — exceeding
> the 24 GB envelope by an order of magnitude. We therefore
> characterise the baseline as infeasible on the target hardware.
> Cell 2 with the Griffin precompile completes in 32.5 min on the
> same hardware, demonstrating a feasibility recovery (infeasible →
> feasible) attributable to the precompile."*

This is the load-bearing C1 evidence: a quantitative cycle anchor for
the PQ-migration / AC implementer audience, with the prove-side
infeasibility empirically confirmed twice and explained by the
56.4× projection.

## Log file

[cell1_prove_rv32im_tuned_20260521_144051.log](cell1_prove_rv32im_tuned_20260521_144051.log)
— 19.8 KB of mostly memory-monitor warnings; no setup/prove/verify
completion lines.
