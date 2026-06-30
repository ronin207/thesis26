# Tier-2 replication RESULT — cell3 run2 (arm=sha3, tuned config)

- run timestamp (start): 2026-06-30T02:00:54+09:00
- run timestamp (end):   2026-06-30T02:19:37+09:00
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
  PLUM_PROVE_ARM=sha3
  PLUM_SECURITY=80
  PLUM_ZK_WRAP=core
  RUST_LOG=warn
```

## Metrics
| metric | value |
|---|---|
| executor cycles | 110798116 |
| setup_ms | 780 |
| prove_ms (host-measured) | 775772 (12.93 min) |
| verify_ms | 2695 |
| script wall (incl. cargo no-op + prove) | 948s ( min) | | script wall (incl. cargo no-op + prove) | 948s ( min) |
| peak tree RSS | 14575184 KB (13.90 GB) |
| prove exit code | 0 |

## execute-mode cycle line (verbatim)
```
accepted=true cycles=110798116 elapsed_ms=1239 syscalls=69385 uint256_mul=69385 griffin_fp192=0
```

## Pre-prove machine state
```
timestamp:    2026-06-30T02:03:49+09:00
uptime/load:   2:03  up 3 days,  3:42, 4 users, load averages: 7.04 8.07 8.36
swapusage:    total = 3072.00M  used = 1802.44M  free = 1269.56M  (encrypted)
vm_stat (first 8 lines):
  Mach Virtual Memory Statistics: (page size of 16384 bytes)
  Pages free:                                   824450.
  Pages active:                                 145686.
  Pages inactive:                               229663.
  Pages speculative:                             71752.
  Pages throttled:                                   0.
  Pages wired down:                             200620.
  Pages purgeable:                                2672.
```

Full prove log: `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/tier2_replication_20260629/cell3_run2/prove.log`
