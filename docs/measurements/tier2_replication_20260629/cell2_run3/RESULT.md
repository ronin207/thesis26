# Tier-2 replication RESULT — cell2 run3 (arm=syscall, tuned config)

- run timestamp (start): 2026-06-30T01:21:20+09:00
- run timestamp (end):   2026-06-30T01:41:53+09:00
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
| setup_ms | 786 |
| prove_ms (host-measured) | 845111 (14.09 min) |
| verify_ms | 2947 |
| script wall (incl. cargo no-op + prove) | 1039s ( min) | | script wall (incl. cargo no-op + prove) | 1039s ( min) |
| peak tree RSS | 13992144 KB (13.34 GB) |
| prove exit code | 0 |

## execute-mode cycle line (verbatim)
```
accepted=true cycles=125506731 elapsed_ms=1761 syscalls=70448 uint256_mul=69396 griffin_fp192=1052
```

## Pre-prove machine state
```
timestamp:    2026-06-30T01:24:34+09:00
uptime/load:   1:24  up 3 days,  3:02, 4 users, load averages: 2.56 6.91 8.55
swapusage:    total = 3072.00M  used = 1486.25M  free = 1585.75M  (encrypted)
vm_stat (first 8 lines):
  Mach Virtual Memory Statistics: (page size of 16384 bytes)
  Pages free:                                   816064.
  Pages active:                                 192059.
  Pages inactive:                               197975.
  Pages speculative:                             61959.
  Pages throttled:                                   0.
  Pages wired down:                             202120.
  Pages purgeable:                                3465.
```

Full prove log: `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/tier2_replication_20260629/cell2_run3/prove.log`
