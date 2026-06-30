# Tier-2 replication SUMMARY — Cell 2 / Cell 3, n=3, tuned-only (2026-06-29/30)

SP1 submodule HEAD: `8bf0248bc5b6b7ba7c820253c3918ea277008641` | hardware: M5 Pro 18 logical cores / 24 GB
zk_wrap=core (succinct STARK, NOT zk). lambda=80. Tuned config:
SHARD_SIZE=2^22, ELEMENT_THRESHOLD=2^26, HEIGHT_THRESHOLD=2^20, TRACE_CHUNK_SLOTS=2, RAYON_NUM_THREADS=8.

## Per-run rows

| cell | run | arm | cycles | prove_ms | prove_min | peak_KB | peak_GB | rc | outcome |
|---|---|---|---|---|---|---|---|---|---|
| cell2 | 1 | syscall | 125506731 | 843267 | 14.05 | 16099280 | 15.35 | 0 | COMPLETED |
| cell2 | 2 | syscall | 125506731 | 876591 | 14.61 | 14611632 | 13.93 | 0 | COMPLETED |
| cell2 | 3 | syscall | 125506731 | 845111 | 14.09 | 13992144 | 13.34 | 0 | COMPLETED |
| cell3 | 1 | sha3 | 110798116 | 789328 | 13.16 | 15117808 | 14.42 | 0 | COMPLETED |
| cell3 | 2 | sha3 | 110798116 | 775772 | 12.93 | 14575184 | 13.90 | 0 | COMPLETED |
| cell3 | 3 | sha3 | 110798116 | 783299 | 13.05 | 15451568 | 14.74 | 0 | COMPLETED |

## Per-cell statistics

### Cell 2 (syscall / GRIFFIN_FP192_PERMUTE precompile)

- prove_ms: mean=854990 (14.25 min), range=[843267 .. 876591] ms = [14.05 .. 14.61 min]  (n=3 completed)
- peak RSS: mean=14.21 GB, range=[13.34 .. 15.35] GB
- spread: prove max/min = 1.04x

### Cell 3 (sha3 control)

- prove_ms: mean=782800 (13.05 min), range=[775772 .. 789328] ms = [12.93 .. 13.16 min]  (n=3 completed)
- peak RSS: mean=14.35 GB, range=[13.90 .. 14.74] GB
- spread: prove max/min = 1.02x

