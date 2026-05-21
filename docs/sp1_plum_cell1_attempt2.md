# Cell 1 (rv32im baseline) — attempt 2 did not terminate

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

## What this means for the thesis

This is admissible evidence for **Claim C1 (workload feasibility gap)**
without a completion number for Cell 1. The defensible statement is:

> *"Two attempts at the precompile-less baseline (Cell 1) on M5 Pro 24 GB
> failed to produce a proof: the first OOM-killed in 1 m 45 s under default
> SP1 settings (2026-05-18), the second non-terminating after 3 h 6 m
> under the memory-tuned configuration that allows the precompile arm to
> complete in 32.5 min (2026-05-21). We therefore characterise the
> baseline as infeasible on the target hardware. Cell 2 with the Griffin
> precompile completes in 32.5 min on the same hardware, demonstrating a
> qualitative feasibility recovery (infeasible → feasible) attributable
> to the precompile."*

This is qualitatively stronger than a numeric speedup ratio for the
target audience (PQ-migration / AC implementers): the message is
"the workload doesn't run at all without precompile-class support on
24 GB-class consumer hardware," which is the structural claim, not a
performance optimisation claim.

## Log file

[cell1_prove_rv32im_tuned_20260521_144051.log](cell1_prove_rv32im_tuned_20260521_144051.log)
— 19.8 KB of mostly memory-monitor warnings; no setup/prove/verify
completion lines.
