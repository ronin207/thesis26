# c1_powres_b2_prove — B2-only (1 FP192_POW_RES/symbol) (POW_RES single-arm settle prove)

- date: 2026-07-07T01:19:03+09:00
- config: PLUM-80 / lambda=80 / M5 Pro 24GB / SP1_PROVER=cpu / standard-Griffin
- workload: N_SYMBOLS=28, 28 FP192_POW_RES syscalls, 0 FP192_MUL
- fork HEAD: 5c82940bda6c0045fa7e3a9f04f3bb62febf2958 (dirty = powres guests + settle tests, uncommitted)
- test: `cargo test --release -p sp1-core-machine test_fp192_powres_b2_only_prove -- --nocapture`

## Result (OBSERVED, verbatim)
- passed(prove+verify): true
- wall_s: 34
- peak_rss_gb: 2.79
- total_trace_cells (unpadded, summed over shards): 1_937_552
- log2(next_pow2(cells)) num_variables: 21
- verdict: OK

## Trace total-cells lines (verbatim)
```
[2m2026-07-06T16:18:55.373753Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 1_937_552, number of variables: 21
[2m2026-07-06T16:18:59.110615Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 4_830_240, number of variables: 23
[2m2026-07-06T16:19:01.402343Z[0m [34mDEBUG[0m [1mprove shard with data[0m: Total number of cells: 4_601_824, number of variables: 23
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
