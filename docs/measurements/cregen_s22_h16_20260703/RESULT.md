# CreGen prove — E4 speed-check: SHARD_SIZE=2^22 + HEIGHT=2^16 (2026-07-03)

**VERDICT: ACCEPTED.** Second completing CreGen prove on the current fork, testing whether a
larger `SHARD_SIZE` is faster than E3's `2^20`. Answer: **no** — essentially identical.

| metric | E4 (SHARD 2^22) | E3 (SHARD 2^20) |
|---|---|---|
| `prove_ms` | 4,257,727 = **70.96 min** | 4,254,093 = 70.90 min |
| wall | 4,347 s = 72.45 min | 4,346 s = 72.4 min |
| `verify_ms` | 27,546 | 27,579 |
| `proof_bytes` | 1,470,771,798 (**byte-identical**) | 1,470,771,798 |
| peak RSS | 13.22 GiB | 13.98 GiB |
| overflow | 0 | 0 |

Config: `SHARD_SIZE=4194304 (2^22)`, `HEIGHT_THRESHOLD=65536 (2^16)`,
`ELEMENT_THRESHOLD=67108864`, `TRACE_CHUNK_SLOTS=2`, `RAYON_NUM_THREADS=8`; λ=80,
syscall arm, sp1 fork 8bf0248bc-dirty; run 2026-07-03 09:55→11:08.

## Conclusion
`SHARD_SIZE` has **no material effect** on the CreGen prove time or proof size (2^20 vs 2^22
→ same ~71 min, byte-identical 1.47 GB proof): the cost is set by the total trace work and
the HEIGHT-capped deferred-Griffin shards, not the main-shard granularity. So ~71 min is
inherent to CreGen at this fork/λ with the `HEIGHT=2^16` overflow fix. Root cause + the fix:
see `../cregen_h16_20260703/RESULT.md`. There is no faster completing config via `SHARD_SIZE`;
a faster path would require either the (unlogged) 6/11 config or a different HEIGHT that stays
just under `2^29` (marginal at best) — not pursued, diminishing returns.
