# Precompile-paradox attribution: does the Griffin Fp192 chip enlarge the arity-4 COMPOSE recursion shape?

Date: 2026-06-28. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB. SP1 submodule HEAD `8bf0248bc`
(detached fork of v6.2.1). Closes STILL-MISSING item #2 of
`docs/measurements/zkwrap_failure_map_20260628/RESULT.md`.

## VERDICT: PARADOX CONFIRMED — Griffin is the SOLE enlarger of the compose shape.

The fork's non-Griffin recursion-circuit edits (recursion/circuit core.rs, compress.rs)
move the compose shape by **exactly zero**. Removing only the Griffin chip — keeping every
other fork edit intact — reproduces the pre-Griffin (upstream `ca6159a05`) compose shape
**byte-for-byte** (md5-identical). Adding Griffin back reproduces the live fork shape
byte-for-byte. The entire 795,264 -> 1,072,032 ExtAlu jump is Griffin's.

## Three points (OBSERVED), all under IDENTICAL flags

`cargo test --release -p sp1-prover --features experimental -- test_find_recursion_shape --include-ignored`
(writes `crates/prover/compress_shape.json`; the ~52 s regen, NOT the ~51 h vk_map). SP1_PROVER n/a (shape-find only).

| Build | ExtAlu (provisioned) | PrefixSumChecks | shape md5 | source |
|---|---|---|---|---|
| stale / pre-Griffin (upstream ca6159a05) | 795,264 | 224,608 | f97a8b2f | committed `.bak` (given) |
| **no-Griffin + fork recursion edits (THE NEW NUMBER)** | **795,264** | **224,608** | **f97a8b2f** | OBSERVED, regen_noGriffin2 |
| with-Griffin (current fork, control) | 1,072,032 | 263,424 | 585b8571 | OBSERVED, regen_withGriffin = live |

- no-Griffin regen md5 `f97a8b2f` == the stale `.bak` md5, byte-for-byte (all 8 heights identical, not just ExtAlu).
- with-Griffin control regen md5 `585b8571` == the live committed-working `compress_shape.json`, byte-for-byte.
- Both committed shapes are thus REPRODUCED from source under one toolchain; the only variable was Griffin.

## Griffin's marginal contribution to the wrap shape (INFERRED from the three points)
- Compose ExtAlu (provisioned, next-mult-32): 1,072,032 - 795,264 = **276,768** (+34.8% over the pre-Griffin budget).
- Compose ExtAlu (REQUIRED height, failure-map #4 observed 1,064,022): 1,064,022 - 795,264 = **268,758** marginal — this is the exact overflow that trips `hypercube/src/util.rs:50` against the stale committed 795,264.
- PrefixSumChecks: 263,424 - 224,608 = **38,816** marginal (the second overflow dimension of failure-map #4, 263,400 > 224,608 — also entirely Griffin).
- Non-Griffin recursion-circuit edits' marginal share: **0** (byte-identical to pre-Griffin).

## Mechanism (source-confirmed, shapes.rs)
`compute_compress_shape` (shapes.rs:198-300) takes the MAX recursion event count over
`machine.shape().chip_clusters` (loop L233-240), then grows the arity-4 (DEFAULT_ARITY) compose
shape until it can verify 4 such proofs. Griffin adds (a) 4 chips to `RiscvAir::machine()`
(riscv/mod.rs:478-481) and (b) a new cluster `[GriffinFp192, GriffinFp192Control]` (riscv/mod.rs:615).
Both channels were removed together, so the 276,768 is Griffin's NET marginal effect; this
experiment does NOT split the cluster-max channel from the full-machine-verifier channel.

## What this means for the thesis (one line)
CONFIRMED, sharp, citable: **the very precompile that makes Cell-2 CORE proving feasible
(removes the no-precompile RAM/time walls #1/#2/#3) is exactly what overflows the arity-4
recursion-shape budget for the ZK-wrap** — the precompile pays for itself at the core layer
and bills the recursion layer. The structural wrap wall is Griffin-caused, not fork-incidental.

## Method / surgery (minimal, non-destructive, fully restored)
1. Backed up live `compress_shape.json` (585b8571) to scratchpad (the existing `.bak` is the STALE
   795,264, NOT the regenerated shape — committed HEAD copy is also 795,264; `git checkout` would
   have given the WRONG file). Backed up `riscv/mod.rs` (md5 9ccc7a28).
2. Commented (marker `// GRIFFINTEST`) the 4 chip registrations (riscv/mod.rs:478-481), the
   supervisor cluster (615) and user cluster (644). First regen FAILED on a chip-count sanity
   assertion `assert_eq!(chips_map.len(), RiscvAirDiscriminants::iter().len())` (riscv/mod.rs:564,
   122 != 126: the 4 Griffin enum variants still exist). Neutralized ONLY that line (line 565
   independently asserts `chips_map.len()==chips.len()`; `chips_map[&id]` at L822 is only hit for
   ids present in clusters, and the Griffin cluster was removed — so no missing-key panic). This is
   a consistency check, not soundness logic. Removing the enum variants instead would have touched
   many match arms (1741-1744 etc.) — reported, not done.
3. no-Griffin regen -> 795,264 / f97a8b2f.
4. Restored `riscv/mod.rs` from pristine backup (md5 back to 9ccc7a28, 0 GRIFFINTEST, assertion
   intact). with-Griffin control regen -> 1,072,032 / 585b8571 (== live). This control rules out
   any flag/toolchain confound: same `--features experimental`, only Griffin differs.

## Restore / state (committed NOTHING)
- `compress_shape.json` = 585b8571 (with-Griffin control regen reproduced it exactly; left in place).
- `compress_shape.json.bak` = f97a8b2f (stale, untouched).
- `riscv/mod.rs` = 9ccc7a28 (pristine, Griffin compiled in, assertion intact, NOT git-modified).
- Final `git -C submodules/sp1 status --short`: identical to pre-experiment —
  ` M griffin_fp192/mod.rs`, ` M compress_shape.json`, ` M gnark-ffi/build.rs`,
  `?? griffin_fp192/fault_injection.rs`, `?? compress_shape.json.bak`. riscv/mod.rs NOT listed.

## Wall-time (this session)
- regen_noGriffin (1st, assertion fail): 48.14 s real, maxRSS 4.05 GiB.
- regen_noGriffin2 (success): 52.85 s real, maxRSS 4.04 GiB.
- regen_withGriffin (control): 53.57 s real, maxRSS 4.04 GiB.
- Heavy compute total ~2.6 min (3 incremental builds + 3 shape-finds). RAM never a factor (~4 GiB).

## Five-attack
- **Source.** Both regen outputs are md5-identical to the two independently-committed shapes
  (.bak and live). Reproduced from source, strongest cross-check. The `.bak`=pre-Griffin-ca6159a05
  provenance is given by the task, not re-verified by me — but the no-Griffin regen reproducing it
  byte-for-byte corroborates it.
- **Assumption.** FIRED productively: did I isolate Griffin? Recursion-circuit edits were KEPT;
  only Griffin removed; result == pre-Griffin -> edits contribute 0, Griffin contributes all.
  `--features experimental` held constant across both runs (controlled). The control (assertion
  intact) reproduced 585b8571 exactly -> neutralizing assertion 564 in the no-Griffin run did not
  distort the shape.
- **Failure-mode.** FIRED: could 795,264 be a coincidental convergence floor? No — the WHOLE file
  is md5-identical (all 8 heights, incl. PrefixSumChecks 224,608, MemoryVar 661,984), not just
  ExtAlu. Coincidence across 8 heights to byte-identity is not plausible.
- **Structure.** FIRED: ExtAlu is not the only overflow dimension — PrefixSumChecks also overflowed
  in failure-map #4 (263,400 > 224,608) and it too is entirely Griffin (224,608 -> 263,424). The
  attribution holds for both binding dimensions.
- **Frontier.** FIRED: this gives Griffin's NET marginal contribution, NOT the channel split
  (cluster-max vs full-machine-verifier). And it is the COMPOSE-shape attribution only; it does not
  re-derive the downstream vk_map (~51 h) or gnark wrap RAM (#6) walls — those couple to Griffin
  only transitively via shape -> vk-digest.
