# c2_powres_sm_prove — S&M-only (261 FP192_MUL/symbol) (POW_RES single-arm settle prove)

- date: 2026-07-07T01:19:43+09:00
- config: PLUM-80 / lambda=80 / M5 Pro 24GB / SP1_PROVER=cpu / standard-Griffin
- workload: N_SYMBOLS=28, 7308 FP192_MUL syscalls (28*261), 0 FP192_POW_RES
- fork HEAD: 5c82940bda6c0045fa7e3a9f04f3bb62febf2958 (dirty = powres guests + settle tests, uncommitted)
- test: `cargo test --release -p sp1-core-machine test_fp192_powres_sm_only_prove -- --nocapture`

## Result (OBSERVED, verbatim)
- passed(prove+verify): true
- wall_s: 40
- peak_rss_gb: 2.91
- total_trace_cells (unpadded, summed over shards): 30_256_496
- log2(next_pow2(cells)) num_variables: 25
- verdict: OK

## Trace total-cells lines (verbatim)
```
[2m2026-07-06T16:19:30.763205Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 30_256_496, number of variables: 25
[2m2026-07-06T16:19:36.776403Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 34_860_256, number of variables: 26
[2m2026-07-06T16:19:41.043655Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 4_713_632, number of variables: 23
```

## Notes
- The SETTLE compares b2 vs sm total_trace_cells on the identical 28-symbol
  workload. If cells(b2) < cells(sm): B2 precompile PAYS at the full-machine
  level (RISCV-cycle saving outweighs the wider precompile chip). If >: it does
  not. Per-op keystone: B2 chip 1.22-1.49x LARGER; execute smoke: B2 141x FEWER
  RISCV cycles/symbol. This prove is the tie-breaker.
- total_trace_cells is UNPADDED (pre power-of-2 shard padding). For the padded
  proving-area comparison, next_pow2 per chip dominates; both guests are single-
  shard at N=28, so the unpadded comparison is the honest per-workload signal.
