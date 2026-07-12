# ShowCre k=2 statement-bound + ZK-wrapped ("binding-and-wrap-in-one-proof") — RESULT

**Run:** the JBIND ShowCre ELF (`program_bdec_showcre/elf-jbind/bdec_showcre`, commits
`x_show=((ppk_TA)_j, ppk_UV, h_UV)` to the journal) put through the full sound wrap chain
(Core → Compress → Shrink → Wrap(BN254) → gnark PLONK → verify), reduced-vk_map path.
**Probe:** `sp1_prover … shapes::tests::probe_showcre_plonk_reduced_vkmap` with
`SHOWCRE_WRAP_ELF_PATH=…/elf-jbind/bdec_showcre`, reusing the measured k=2 witness
(`showcre_k2_wrap_20260707/showcre_k2_witness.bin`), so this differs from a plain k=2 wrap
ONLY in the ELF (plain → jbind).
**Date:** 2026-07-11 (START 13:48:56Z → END 2026-07-12 00:01:47Z). **Exit:** `rc=0`, `VERIFY_OK`.
**Machine:** target hardware (24 GB), `SP1_PROVER=cpu`, sound path (stock gnark v6.1.0,
verifying-key verification ON, `HEIGHT_THRESHOLD=2^16`). elf_bytes=379832, witness_bytes=360304.

## Result — a single proof that is BOTH statement-bound AND zero-knowledge (k=2 showing)

| Stage | wall |
|---|---|
| setup_core (one-time core-shape pass) | 8224.70 s = **137.08 min = 2.28 h** |
| build_vks (reduced vk_map, 28 setups) | 42.63 s |
| plonk_chain / per-proof wrap (Core+Compress+Shrink+Wrap+PLONK) | 28484.95 s = **7.91 h** |
| verify (gnark PLONK/BN254) | 0.25 s → **VERIFY_OK** |
| observed_total (launch→end) | 36752.53 s = **10.21 h** |

- **Peak tree-RSS (sampler): 15.66 GiB** (`sampler_peak_kb=16419360`), ~8.3 GiB headroom under 24 GB.
- **core_shards=2011**, distinct_shard_shapes=16, union_indices=28, total_enumerated=191670.
- gnark PLONK/BN254 wrap circuit: nbConstraints=27,576,375; verifier accepted.
- **Continuous wall (no sleep gap):** internal monotonic timer (36752.53 s) matches the UTC
  delta (13:48:56Z→00:01:47Z = 36771 s) to ~19 s; rss sampler shows no interval >30 s across
  7293 samples over 10.2 h. The total-wall figure is sound.

Statement-binding is by construction: the jbind ELF commits `x_show` to the journal
(the k=2 showing whose core prove recovered+matched `x_show` at 127.94 min,
`bdec_e2e_20260710/`), and the wrap preserves the journal in the proof's public values,
so the wrapped proof is statement-bound. ZK is by gnark PLONK with blinding enabled
(`wrap_zk_check_20260707/`, VERDICT=ZK).

## Comparison to k=1 — AND a wall-clock anomaly to read honestly

| | verifies | core_shards | setup_core | per-proof | end-to-end | peak RSS | run date |
|---|---|---|---|---|---|---|---|
| ShowCre k=1 (`showcre_k1_wrap_20260707`) | 3 | 1516 | 2.96 h | 8.79 h | 11.76 h | 14.93 GiB | 2026-07-07 |
| **ShowCre k=2 (this run, jbind)** | 4 | **2011** | 2.28 h | **7.91 h** | 10.21 h | **15.66 GiB** | 2026-07-11 |

- **Monotone in k (config-stable quantities):** core-shard count (1516 → 2011) and peak RSS
  (14.93 → 15.66 GiB) both grow with the verification count, as the compress-dominated model
  predicts, and both stay within the 24 GB envelope.
- **NON-monotone in wall-clock:** k=2 (more work) came in *faster* per-proof (7.91 h) than
  k=1 (8.79 h). Same harness (both `probe_showcre_plonk_reduced_vkmap`, reduced vk_map),
  so this is NOT a config difference. Most likely cause: these are **single runs on different
  days**, and the k=1 run (2026-07-07) was flagged thermally throttled near its ~11 h tail.
- **Reading:** do NOT read a monotone wall-clock k-law off these two thermally-uncontrolled
  single runs. The defensible k-scaling statement rests on shard count and peak memory (both
  monotone, both bounded). Wall-clock is reported as a single-run figure; a controlled
  wall-clock k-series would need same-session repeated runs, which we did not do.

## What this closes / does NOT

- CLOSES the last open measurement: the combined statement-bound-AND-wrapped run at the
  **k=2 showing** scope (§5/§6/§8/§055 flagged it as the one remaining gap). Both credential
  relations now have a measured, verified, statement-bound zk-wrap.
- Does NOT change the post-quantum obstruction: the wrap is pairing-based (BN254), so the
  anonymity it supplies is classical only (Horn 2 stands).
- Does NOT establish a wall-clock k-scaling law (see anomaly above).

## Thesis touchpoints (update in careful mode, no scale/skip language)
- `05-system.tex:130` "with k=2 not yet run" → measured: 10.21 h end-to-end / 7.91 h per-proof,
  15.66 GiB peak, statement-bound, VERIFY_OK.
- `06-evaluation.tex:190`, `06-evaluation.tex:249` "k=2 wrap projected/not yet run" → measured,
  with the wall-clock anomaly handled by anchoring k-growth to shard count + peak memory.
- `06-evaluation.tex:359` "What remains is the same combined run at the k=2 showing scope" →
  now measured (both relations combined-bound-and-wrapped).
- `08-conclusion.tex:9,15,18`, `055-security.tex:305` "k=2 ... projected / not yet measured" → measured.
