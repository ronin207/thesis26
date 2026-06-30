# Tier-2 replication RESULT — cell2 run1 (arm=syscall, tuned config)

- run timestamp (start): 2026-06-30T00:39:42+09:00
- run timestamp (end):   2026-06-30T01:00:12+09:00
- outcome: **COMPLETED**
- SP1 submodule HEAD: `8bf0248bc5b6b7ba7c820253c3918ea277008641`
- repo HEAD: `e0628b449cf51c4e4af01914d311b43eb26de700` on `main`
- hardware: MacBook Pro M5 Pro, 18-logical-core CPU, 24 GB RAM

## Env block actually exported (tuned)
```
  SHARD_SIZE=4194304
  ELEMENT_THRESHOLD=67108864
  HEIGHT_THRESHOLD=1048576
  TRACE_CHUNK_SLOTS=2
  RAYON_NUM_THREADS=8
  PLUM_HOST_MODE=prove
  PLUM_PROVE_ARM=syscall
  PLUM_SECURITY=80
  PLUM_ZK_WRAP=core
  RUST_LOG=warn
```

## Metrics
| metric | value |
|---|---|
| executor cycles | 125506731 |
| setup_ms | 788 |
| prove_ms (host-measured) | 843267 (14.05 min) |
| verify_ms | 2953 |
| script wall (incl. cargo no-op + prove) | 1038s ( min) | | script wall (incl. cargo no-op + prove) | 1038s ( min) |
| peak tree RSS | 16099280 KB (15.35 GB) |
| prove exit code | 0 |

## execute-mode cycle line (verbatim)
```
accepted=true cycles=125506731 elapsed_ms=1759 syscalls=70448 uint256_mul=69396 griffin_fp192=1052
```

## Pre-prove machine state
```
timestamp:    2026-06-30T00:42:54+09:00
uptime/load:   0:42  up 3 days,  2:21, 4 users, load averages: 4.55 4.20 4.06
swapusage:    total = 2048.00M  used = 734.06M  free = 1313.94M  (encrypted)
vm_stat (first 8 lines):
  Mach Virtual Memory Statistics: (page size of 16384 bytes)
  Pages free:                                   531977.
  Pages active:                                 316345.
  Pages inactive:                               325715.
  Pages speculative:                             10188.
  Pages throttled:                                   0.
  Pages wired down:                             208171.
  Pages purgeable:                                2878.
```

Full prove log: `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/tier2_replication_20260629/cell2_run1/prove.log`
