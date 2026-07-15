# CreGen statement-bound + ZK-wrapped ("binding-and-wrap-in-one-proof") — RESULT

**Run:** the JBIND CreGen ELF (`program_bdec_cregen/elf-jbind/bdec_cregen`, commits
`x_cre=(c,h,ppk)` to the journal) put through the full sound wrap chain
(Core → Compress → Shrink → Wrap(BN254) → gnark PLONK → verify), reduced-vk_map path.
**Probe:** `sp1_prover … shapes::tests::probe_cregen_plonk_reduced_vkmap` with
`CREGEN_WRAP_ELF_PATH=…/elf-jbind/bdec_cregen`.
**Date:** 2026-07-11 (START 01:32:37Z → END 06:55:54Z). **Exit:** `rc=0`, `VERIFY_OK`.
**Machine:** target hardware (24 GB), `SP1_PROVER=cpu`, sound path (stock gnark v6.1.0,
verifying-key verification ON, `HEIGHT_THRESHOLD=2^16`).

## Result — a single proof that is BOTH statement-bound AND zero-knowledge

| Stage | wall |
|---|---|
| setup_core (one-time core-shape pass) | 4287.00 s = **71.45 min** |
| build_vks (reduced vk_map, 27 setups) | 40.13 s |
| plonk_chain / per-proof wrap (Core+Compress+Shrink+Wrap+PLONK) | 15040.67 s = **4.18 h** |
| verify (gnark PLONK) | 0.25 s → **VERIFY_OK** |
| observed_total (launch→end, **includes relocation sleep**) | 19368.05 s = 5.38 h |

- **Peak tree-RSS (sampler): 15.2 GB** (`sampler_peak_kb=15948336`), ~8.3 GiB headroom under 24 GB.

Statement-binding is by construction: the jbind ELF commits `x_cre` to the journal
(the same guest whose core prove recovered+matched `x_cre` at 66.05 min,
`bdec_cregen_jbind_20260710/`), and the wrap preserves the journal in the proof's
public values, so the wrapped proof is statement-bound. ZK is by gnark PLONK with
blinding enabled (`wrap_zk_check_20260707/`, VERDICT=ZK).

## Comparison — binding cost is negligible (now MEASURED)

| | per-proof wall | peak RSS |
|---|---|---|
| plain CreGen wrap (boolean-only ELF) `cregen_wrap_20260707` | 4.20 h | 15.63 GiB |
| **bound CreGen wrap (jbind ELF)** this run | **4.18 h** | **15.2 GB** |

Same witness, same sound path; only the ELF differs (plain → jbind). Peak memory is
sleep-independent and matches; the per-proof wall matches within run-to-run noise (and
the 4.18 h is an over-estimate here because the wall spans the machine's relocation
sleep). **Statement-binding adds negligible cost to the wrap — the additivity claim,
previously argued, is now measured.**

## What this closes / does NOT

- CLOSES the "combined statement-bound-AND-wrapped run" open measurement for **credential
  generation** (§6/§8 flagged it as the one remaining timing gap).
- Does NOT cover the **k=2 showing** combined run (ShowCre k=2 wrap still projected,
  ~16–22 h; `showcre_k2_wrap_20260707` never completed).
- Does NOT change the post-quantum obstruction: the wrap is pairing-based (BN254), so the
  anonymity it supplies is classical only (Horn 2 stands).
