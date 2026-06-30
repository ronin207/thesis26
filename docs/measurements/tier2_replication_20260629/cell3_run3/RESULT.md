# Tier-2 replication RESULT — cell3 run3 (arm=sha3, tuned config)

- run timestamp (start): 2026-06-30T02:19:37+09:00
- run timestamp (end):   2026-06-30T02:38:25+09:00
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
| setup_ms | 773 |
| prove_ms (host-measured) | 783299 (13.05 min) |
| verify_ms | 2683 |
| script wall (incl. cargo no-op + prove) | 956s ( min) | | script wall (incl. cargo no-op + prove) | 956s ( min) |
| peak tree RSS | 15451568 KB (14.74 GB) |
| prove exit code | 0 |

## execute-mode cycle line (verbatim)
```
accepted=true cycles=110798116 elapsed_ms=1229 syscalls=69385 uint256_mul=69385 griffin_fp192=0
```

## Pre-prove machine state
```
timestamp:    2026-06-30T02:22:29+09:00
uptime/load:   2:22  up 3 days, 4 hrs, 4 users, load averages: 4.18 6.86 7.92
swapusage:    total = 3072.00M  used = 2026.38M  free = 1045.62M  (encrypted)
vm_stat (first 8 lines):
  Mach Virtual Memory Statistics: (page size of 16384 bytes)
  Pages free:                                   880826.
  Pages active:                                 145908.
  Pages inactive:                               177028.
  Pages speculative:                             52547.
  Pages throttled:                                   0.
  Pages wired down:                             206032.
  Pages purgeable:                                1222.
```

Full prove log: `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/tier2_replication_20260629/cell3_run3/prove.log`
