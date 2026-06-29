# Regenerated recursion shape → ZK-wrap re-attempt (SP1 PLUM-verify)

Date: 2026-06-28. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB (`hw.memsize=25769803776`).
Continues `docs/measurements/zkwrap_default_shard_20260627/RESULT.md` and the mechanism
diagnostic `docs/measurements/precompile_paradox_mechanism_20260627/RESULT.md`.
SP1 submodule HEAD `8bf0248` (detached from v6.2.1).

## Question
The prior wrap failed at the arity-4 COMPRESS/REDUCE stage because the committed static
`submodules/sp1/crates/prover/compress_shape.json` provisions ExtAlu=795,264 but PLUM-verify's
compose program needs 1,064,022. Hypothesis: a STALE static shape (regenerate it → unblock the
pipeline → reach gnark wrap → measure the long-sought wrap-stage peak RAM). Documented fix:
`crates/prover/src/shapes.rs:943` → `test_find_recursion_shape`.

## Step 3 GATE — PASSED: regeneration DID lift the compose ceiling
Ran `cargo test --release -p sp1-prover --features experimental -- test_find_recursion_shape --include-ignored`
(`compute_compress_shape`, shapes.rs:198 — a fixpoint iteration that grows chip heights until the
arity-4 compose program fits; reads NOT the stale file but a fresh search from `max_cluster_count`).

| chip | committed (stale) | regenerated (true fixpoint) | required (prior run) | gate |
|---|---|---|---|---|
| ExtAlu | 795,264 | **1,072,032** | 1,064,022 | PASS (margin 8,010 / 0.75%) |
| PrefixSumChecks | 224,608 | **263,424** | 263,400 | PASS (margin 24) |

The razor-thin margins corroborate that the prior run's "required" heights were the genuine
compose real-heights. **Staleness of compress_shape.json is CONFIRMED as a real capacity wall.**
This REFUTES the prior frontier-attack worry that the fallback (850,000 < 1,064,022) implied a
"deeper machine/shape mismatch" — the true fixpoint is only marginally above the requirement; the
file was simply never regenerated after the 22 Griffin + recursion-verifier fork commits.

## Step 4/5 — re-attempt the wrap: a SECOND, DEEPER static-artifact wall appeared
Rebuilt `plum_host` (forced sp1-prover recompile so the new shape is `include_bytes!`'d via
`[patch.crates-io] sp1-prover = submodules/sp1/crates/prover`). Re-ran the EXACT prior config:
PLUM-80, λ=80, arm=syscall (Griffin precompile ON), `PLUM_ZK_WRAP=plonk`, default `SHARD_SIZE`(1<<24),
`SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`, `SP1_WORKER_NUM_CORE_WORKERS=2`, SP1_PROVER=cpu.
Wrapper `run.py` (this dir). Raw: `regen_w2.log/.meta/.rss.tsv`.

**Result: rc=101 (panic), wall 2.38 min, maxRSS 13.14 GiB, sampler peak 10.16 GiB.**
Did NOT reach COMPRESS. Failed EARLIER, at recursion-vk validation:
```
ERROR task failed with fatal error: vk not allowed
panicked at script/src/bin/plum_host.rs:359: prove (plonk) failed: ... artifact not found
```
Root cause traced to source:
- `crates/prover/src/recursion.rs:151` — `RecursionVks::open()` hashes each recursion program's vk
  (`hash_koalabear()`) and looks it up in an allowed-vk map; a miss is Fatal **"vk not allowed"**.
- The allowed-vk map is a SECOND committed static artifact:
  `crates/prover/src/recursion.rs:57` → `include_bytes!("vk_map.bin")` (7.43 MB, unmodified May 17).
- Regenerating compress_shape.json changed the recursion programs' SHAPES → new program vks → new
  `hash_koalabear()` digests → **absent from the stale vk_map.bin** → "vk not allowed". The
  downstream "artifact not found" (`prover-types/src/artifacts.rs:379`) is a consequence: the failed
  core/recursion task produced no artifact for the next stage to fetch.

**The compose-capacity shape and the recursion-vk allowlist are COUPLED static artifacts.**
Regenerating one without the other does not remove the wall — it relocates it EARLIER (from COMPRESS
at ~30 min to vk-validation at 2.38 min).

## Primary question answered (with a precise caveat)
- **Did the regenerated shape clear the compose panic?** STATICALLY YES (gate: ExtAlu 1,072,032 >
  1,064,022). **RUNTIME UNCONFIRMED** — the run never reached COMPRESS because the vk-allowlist wall
  fires first. To runtime-confirm requires also regenerating vk_map.bin (see below).
- **Furthest stage reached:** CORE proving (in progress, ~108 s) → aborted at recursion-vk
  validation. EARLIER than the prior run, by design of the new failure.
- **Wrap-stage peak RAM (the 24 GB decision-unknown):** STILL UNREACHED / UNMEASURED — now blocked by
  a second structural wall, not RAM. Through the partial run, RAM was a non-issue (maxRSS 13.1 GiB).

## The full unblock chain is THREE coupled artifacts, not one stale file
1. `compress_shape.json` — recursion trace CAPACITY. **DONE** (regenerated; gate passed).
2. `vk_map.bin` — recursion-vk ALLOWLIST (Merkle set). **NOT DONE.** Regen entrypoint
   `test_build_vk_map` (shapes.rs:1037) / `build_vk_map` (shapes.rs:471): requires a full recursion
   setup (core proof + create ALL circuit shapes per cluster + shrink vks) — heavy, multi-stage.
3. gnark PLONK/Groth16 BN254 wrap circuit — keyed to the vk-map root. **NOT PRESENT** locally
   (`~/.sp1/circuits` absent); the final wrap would hit `crates/prover/src/build.rs:749`
   "Plonk artifact not found; generate them locally". A THIRD regeneration.

So the documented `shapes.rs:943` fix addresses only artifact #1 of #3. The path to the gnark wrap
RAM number is a 3-artifact coupled regeneration, well beyond a single-file fix. The sound bypass
(`WITHOUT_VK_VERIFICATION=1`, builder.rs:366) was NOT used — it disables the vk soundness check
and was correctly blocked as a security-weakening action; it is the Operator's call.

## Verdict
- **Staleness as the COMPOSE-capacity cause: CONFIRMED.** Shape regen lifts ExtAlu 795,264 →
  1,072,032 ≥ the required 1,064,022 (and PrefixSumChecks 224,608 → 263,424 ≥ 263,400).
- **Staleness is NOT the whole story: REFUTED that shape-regen alone unblocks the wrap.** The shape
  is one of a coupled static-artifact set {compress_shape.json, vk_map.bin, gnark circuit}. Regen of
  the shape alone moves the wall from COMPRESS (capacity) to recursion-vk-validation (allowlist).
- **Binding blocker now:** the recursion-vk ALLOWLIST (`vk_map.bin`), a SECOND build-time static
  artifact, stale w.r.t. the regenerated shape — a CONSISTENCY/CAPACITY wall, NOT a RAM wall.
- **24 GB for PLUM-verify ZK-wrap:** STILL MOOT as the fork ships — two structural walls stacked in
  front of (a missing) gnark circuit; none is a memory wall (peak ≤ 16.5 GiB across all attempts).

## Cost (machine wall-time, separated)
- Shape regeneration: **110.48 s (1.84 min)**, rc=0 (build cache warm; fixpoint search 4.57 s).
- Rebuild plum_host: **275.95 s (4.60 min)**, rc=0 (sp1-prover + sdk + script recompiled).
- Wrap re-attempt: **142.6 s (2.38 min)**, rc=101 (vk not allowed).
- Total heavy compute ≈ **8.8 min**. n=1 each. Source tracing ~20 min.

## State / recoverability (submodules/sp1)
- `crates/prover/compress_shape.json` — **REGENERATED, left in place** (md5 585b8571..., git ` M`).
  Intended function (lift capacity) achieved; pipeline still blocked downstream by vk_map.bin.
- Backup of original: `crates/prover/compress_shape.json.bak` (md5 f97a8b2f..., untracked) AND
  scratchpad copy. Committed blob `d59c84df...`.
- **Restore original (one command):** `git -C submodules/sp1 checkout crates/prover/compress_shape.json`
  (or `cp compress_shape.json.bak compress_shape.json`).
- `vk_map.bin` UNMODIFIED. `shapes.rs` touched (mtime only; no content diff — verified).
- Pre-existing (not mine): `griffin_fp192/mod.rs`, `gnark-ffi/build.rs` modified; `fault_injection.rs`
  untracked. Nothing committed. Operator decides whether to keep or revert the regenerated shape.

## Five-attack
- **Source.** Heights read from the regenerated JSON + prior run log; "vk not allowed" / "artifact
  not found" read from `regen_w2.log` and traced to recursion.rs:151/57 + artifacts.rs:379 + the
  7.43 MB vk_map.bin. maxRSS from getrusage(RUSAGE_CHILDREN). FIRED: COMPRESS was not reached, so the
  shape's runtime sufficiency is inferred from the static fixpoint, not observed in this run.
- **Assumption.** FIRED productively: "stale shape is THE blocker" downgraded — it is the FIRST of
  ≥3 coupled static artifacts. The precompile-paradox doc's "config-fixable via shape regen" is shown
  insufficient.
- **Failure-mode.** FIRED. The trap of declaring victory at the gate (ExtAlu ≥ required) is avoided:
  the rebuilt binary fails EARLIER than before. A "fix" that relocates a wall is not a fix.
- **Structure.** FIRED. The valid unblock is a 3-artifact coupled regeneration (shape + vk allowlist
  + gnark circuit), not a single file; the sound path is regen, not WITHOUT_VK_VERIFICATION.
- **Frontier.** FIRED. Whether regenerating vk_map.bin (heavy) then building the gnark circuit
  actually reaches a completed wrap within 24 GB is the remaining open question; the wrap peak RAM
  stays unmeasured.
