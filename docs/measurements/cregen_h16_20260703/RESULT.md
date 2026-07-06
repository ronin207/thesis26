# CreGen prove — COMPLETED on the current fork (2026-07-03), the 2^30 overflow SOLVED

**VERDICT: ACCEPTED.** The first machine-verified completing BDEC CreGen succinct
prove on the current (dirty) sp1 fork. The `2^30` jagged round-area overflow that
blocked every prior attempt is resolved by a **single config knob** — no cost-model
edit, no fork edit, no rebuild. This SUPERSEDES the earlier same-day
"config-exhausted / fork-pinned / no config solution" conclusion
(`cregen_config_exhausted_20260703.md`), which was wrong: a tractable lever exists.

## The number (measured)

| metric | value |
|---|---|
| `accepted` | **true** |
| `prove_ms` | **4,254,093 ms = 70.90 min** |
| wall | 4,346 s = 72.4 min |
| `verify_ms` | 27,579 ms (27.6 s) |
| `proof_bytes` | 1,470,771,798 (**1.47 GB**) |
| peak RSS | **13.98 GiB** (well within 24 GB) |
| `overflow_errs` | 0 |

## Config (the fix)

`BDEC_HOST_MODE=prove BDEC_HOST_SECURITY=80 BDEC_PROVE_ARM=syscall` (with-precompile),
λ=80, sp1 fork HEAD **8bf0248bc (dirty)**, run 2026-07-03 08:31→09:44.

```
SHARD_SIZE=1048576        (2^20)
HEIGHT_THRESHOLD=65536    (2^16)   <- the fix (was 2^17=131072, which overflowed)
ELEMENT_THRESHOLD=67108864 (2^26)
TRACE_CHUNK_SLOTS=2
RAYON_NUM_THREADS=8
```

## Root cause (the mechanism)

The overflowing round is the **deferred-Griffin shard** (proved last). Its full chip
breakdown (from the E2 shape-dump):

```
GriffinFp192 (base) | Main Cols = 3,819 | Rows = 130,816 | Cells = 499,586,304   <- dominant
Global              | Main Cols = 241   | Rows = 308,352 | Cells =  74,312,832
MemoryLocal / GriffinFp192Control / Byte / Range / ...                            (small)
Total number of cells = 581,604,864 ;  number of variables = 30
```

The jagged PCS commits each shard by stacking its total cells into a polynomial padded
to the **next power of two** (`total.next_power_of_two()`, `hypercube shard.rs:668-672`).
`581M > 2^29 (536.9M)` ⇒ pads to **2^30** ⇒ the check `round_area >= 1<<30`
(`slop/jagged/verifier.rs:238`) fires. So the checked quantity is the *stacked* size,
not the raw cell sum — which is why every raw count I measured looked under the bound.

The base `GriffinFp192` chip is 3,819 columns wide; at the `2^17` HEIGHT cap the Griffin
shard held **9,344 perms** (`= 9,344 × 14 rows × 3,819 cols = 499.6M`), pushing the shard
total just over `2^29`. `HEIGHT_THRESHOLD=2^16` caps Griffin at 4,681 perms → shard
≈332M < `2^29` → pads to `2^29` → under the bound. (Only a ~8% reduction below 581M is
strictly required; `2^16` gives comfortable margin.)

Note: this also corrects the earlier "CreGen ≈ 2,104 Griffin perms" estimate (Cell-2 × 2).
The measured Griffin count is **~9,344 in one shard** — CreGen's Merkle/BCS commitments
emit far more Griffin permutations than the base power-residue symbol checks.

## Honest caveats

- This is a **workaround config**, NOT the shipped `2^22` tuning. It is heavily de-tuned
  (small shards) specifically to keep the deferred-Griffin shard under `2^29`.
- **70.90 min is ~2.6× slower** than the buried 6/11 datum of 26.98 min (which was at a
  different, never-machine-logged config — see `metric_drift_prove_vs_wall_20260702.md`).
- **`proof_bytes` = 1.47 GB is ~5× the 6/11 CreGen proof (296 MB)** — the many small
  shards inflate the aggregate proof. This is a real cost of the workaround.
- A larger `SHARD_SIZE` with the same `HEIGHT_THRESHOLD=2^16` should complete faster with a
  smaller proof (the HEIGHT cap on Griffin is independent of `SHARD_SIZE`); tested next.

## What this settles
- CreGen **is** completable on the current fork (config lever = `HEIGHT_THRESHOLD`, keep the
  deferred-Griffin shard < `2^29`). Not fork-pinned; the cost-model fix is NOT needed.
- The `2^22`/`2^17` overflow is fully explained (deferred-Griffin shard next-pow2 padding).
- Open: a faster/leaner completing config (E4), and reconciling with the 6/11 26.98-min
  provenance (its config was never logged; this run documents one that works).
