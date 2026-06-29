# vk_map allowlist regeneration is a ~185,862-setup, ~25 h SCALE wall (SP1 PLUM-verify ZK-wrap)

> **SUPERSEDED (2026-06-28):** the ~25 h figure here is extrapolated from 6–8-setup slices and is STARTUP-CONTAMINATED. The authoritative cost is **~51 h (48–54 h, ≈1 s/setup × 185,862 entries)** from larger contiguous slices in `../zkwrap_vkmap_slope_20260628/RESULT.md`. Cite that record, not this one, for the regeneration cost. (The 185,862-setup count and the compute-scale-not-memory finding here remain correct.)

Date: 2026-06-28. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB (`hw.memsize=25769803776`).
SP1 submodule HEAD `8bf0248bc` (detached, fork of v6.2.1). Prover features: mprotect OFF.
Continues `docs/measurements/zkwrap_regen_shape_20260628/RESULT.md` (artifact #1 done, #2 wall found).
All numbers n=1, λ=80, PLUM-80, arm=syscall (Griffin precompile ON). Soundness preserved:
`WITHOUT_VK_VERIFICATION=1` NOT used at any point.

## Question
The prior run regenerated artifact #1 `compress_shape.json` (ExtAlu 795,264 -> 1,072,032) and hit a
SECOND wall: "vk not allowed" at recursion-vk validation, because the regenerated shape invalidated
the committed recursion-vk allowlist `crates/prover/src/vk_map.bin`. This run sizes the SOUND
regeneration of #2 and reports the binding constraint.

## Step 0 - starting state CONFIRMED
- `crates/prover/compress_shape.json` = REGENERATED (md5 585b8571..., ExtAlu 1072032, PrefixSumChecks
  263424); `.bak` of original present (288 vs 287 bytes). Not reverted.
- `crates/prover/src/vk_map.bin` = original (md5 931c0bba..., 7,434,488 bytes, May 17). Unmodified.

## Step 1 (#2) - vk_map.bin regeneration: a SCALE wall, NOT a RAM wall
### Entrypoint (sound, production)
NOT `test_build_vk_map` (shapes.rs:1053): that test builds a SUBSET (Fibonacci proof shapes + last
12), writes to a temp dir, and DELETES it - a self-test, not the production map generator.
Production generator = bin `build_recursion_vks` (`crates/prover/scripts/build_recursion_vks.rs`,
registered `[[bin]]` in `crates/prover/Cargo.toml:84`). Run with NO `--start/--end` it calls
`node.build_vks(None, chunk_size)` -> `build_vk_map(..., indices=None, ...)` which sets up EVERY shape
from `create_all_input_shapes` (shapes.rs:702). A `--start/--end` range writes ONLY those indices ->
an INCOMPLETE map that breaks all other vks, so a partial write is not a sound shortcut.

### Job size (exact)
`vk_map.bin` bincode header (first 8 bytes, u64 LE) = **185,862** entries; file size check is exact:
185,862 x 40 bytes/entry (32-byte [SP1Field;8] key + 8-byte usize) + 8-byte header = 7,434,488 =
actual file size. So a full sound regen performs **185,862 recursion-program setups** (compile
recursion program + STARK preprocessing/vk per shape).

### Measured per-setup cost (build_recursion_vks, chunk_size 4)
- Build the bin (warm sp1-prover deps): **279.94 s real (4m 39s)**, peak RSS 6.55 GiB, rc=0.
- Slice idx 0..8 (smallest Normalize shapes): **13.43 s real** (~9 s node startup + ~4 s for 8
  setups), user 134.94 s (~10x core saturation), **peak RSS 9.05 GiB**, rc=0.
- Slice idx 185856..185862 (the Compose arity-1..4 + Deferred + Shrink - the shapes that changed and
  the heaviest): **10.89 s real** (~8 s startup + ~2.8 s for 6 setups), user 115.22 s, **peak RSS
  11.0 GiB**, rc=0.
- Both slices => steady-state ~**0.5 s/setup** at chunk_size 4; CPU already ~10x saturated, so more
  workers won't materially reduce wall. Peak RSS ~9-11 GiB regardless of shape kind => RAM is NOT the
  limit anywhere in vk_map regen.

### Extrapolation (the wall)
Full regen ~= 9 s startup + 185,862 x ~0.49 s ~= **~25 hours** wall on this host (chunk_size 4).
Even with full 18-core saturation, order ~12-25 h. This BLOWS the 90-min Step-1 cap by ~10-17x.
**Classification: CAPACITY/SCALE wall (compute-time), NOT a memory/OOM wall.** Per-setup RAM <= 11 GiB.

### No splice shortcut (mechanism, source-confirmed)
`compress_shape.json` is `include_bytes!`'d at COMPILE time (shapes.rs:306). In `build_vk_map`,
`reduce_shape = retrieve_or_compute_reduce_shape(...)` -> `compress_proof_shape_from_arity(DEFAULT_ARITY)`
reads that embedded (regenerated) shape (shapes.rs:530-533), and the **Normalize** arm assigns
`program.shape = Some(reduce_shape.clone().shape)` (shapes.rs:551) - likewise for Compose. The
recursion-program vk commits to `program.shape`, so the regenerated shape changes the vk digest of
ALL 185,862 programs, not just the ~6 compose/deferred/shrink ones. Therefore there is NO cheap
6-entry splice; the entire allowlist is invalidated and the full ~25 h rebuild is intrinsic, not a
mere tooling gap. (Raw-byte search for the rebuilt idx-0 digest in the old map returned absent, but
that is inconclusive alone - stored keys may be Montgomery-form; the source mechanism is the proof.)

## Step 2 (#3) - gnark PLONK circuit feasibility (read-only; NOT built)
- `~/.sp1/circuits` ABSENT (confirmed). The final wrap would hit `build.rs` "Plonk artifact not
  found; generate them locally".
- Toolchain present: Go 1.26.3 (`/opt/homebrew/bin/go`), Docker 29.4.3. The thesis uses the
  `native-gnark` feature -> gnark-ffi builds via local `go build` (cgo), Docker NOT required. So the
  gnark build is toolchain-feasible on this host.
- NOT built: the gnark circuit is keyed to the wrap vk, which is keyed to the (unrebuildable) vk_map
  root. It is downstream of the Step-1 wall, so its setup-RAM number stays unmeasured. Per the gate
  ("stop at the first wall, don't burn hours blind"), #3 was not attempted.

## Steps 3-5 - not reached
The wrap re-run (Step 4) and the long-sought gnark wrap-stage peak RAM (Step 5) are blocked behind
the Step-1 scale wall. Furthest sound stage reachable as the fork ships: still pre-COMPRESS
(unchanged from the prior run), now with the root cause quantified.

## Verdict
- **vk_map.bin sound regen = ~185,862 recursion-program setups, ~25 h wall on M5 Pro / 24 GB.**
  CONFIRMED scale wall. NOT RAM (peak <= 11 GiB). The prior RESULT.md's "tens of minutes, memory-heavy"
  framing is REFUTED on both axes: it is tens of HOURS, and it is compute-bound, not memory-bound.
- **The coupling is worse than "two artifacts":** regenerating the cheap shape (#1, ~2 min)
  invalidates the ENTIRE allowlist (#2, ~25 h) because every recursion vk commits to the reduce shape.
  Source-confirmed (shapes.rs:530-551). The cheap fix forces a cluster-scale rebuild.
- **24 GB is NOT the binding limit at this stage.** The binding limit for the sound ZK-wrap path on
  this fork is COMPUTE TIME at the vk-allowlist rebuild, ~10-17x over a 90-min budget. Memory never
  exceeded ~13 GiB across any attempt (this run <= 11 GiB; prior wrap attempt maxRSS 13.1 GiB).
- **Honest bottom line:** ZK-wrapped PLUM-verify is NOT achievable end-to-end on this host as the fork
  ships - blocked first by a ~25 h vk-allowlist regeneration (sound path), then by an unbuilt gnark
  circuit whose own setup RAM remains the still-unmeasured downstream unknown. The gnark wrap-stage
  peak RAM (the thesis's decision-determining number) is NOT reached, and the reason is a build-time
  static-artifact regeneration of cluster scale, not a prover memory ceiling.

## Cost (machine wall-time, this run)
- build_recursion_vks bin build: 279.94 s (4.66 min), rc=0.
- vk slice idx 0..8: 13.43 s, rc=0. vk slice idx 185856..185862: 10.89 s, rc=0.
- Source tracing / state checks: ~10 min.
- Heavy compute ~= 5.1 min. No multi-hour run launched (gated at the sized wall). n=1 each.

## State / recoverability (submodules/sp1) - committed NOTHING
- `crates/prover/compress_shape.json` REGENERATED, left in place (md5 585b8571..., git ` M`).
- `crates/prover/src/vk_map.bin` UNMODIFIED (md5 931c0bba...). The full regen was NOT run; the timing
  slices wrote only to a scratchpad temp build-dir (deleted-on-next or left in /private/tmp).
- Backup of original shape: `crates/prover/compress_shape.json.bak` (untracked).
- Restore original shape (one command): `git -C submodules/sp1 checkout crates/prover/compress_shape.json`.
- New build artifact: `platforms/zkvms/sp1/target/release/build_recursion_vks` (untracked, build output).
- Pre-existing (not from this run): `griffin_fp192/mod.rs`, `gnark-ffi/build.rs` modified;
  `griffin_fp192/fault_injection.rs` untracked.

## Five-attack
- **Source.** Entry counts from the vk_map.bin bincode header (185,862, exact file-size match) and the
  build_recursion_vks log digests; per-setup times from `/usr/bin/time -l`; RSS from getrusage maxRSS.
  FIRED: the full 185,862-setup wall is EXTRAPOLATED from two 6-8 setup slices, not observed end to
  end (the ~25 h run was deliberately not launched, per the gate).
- **Assumption.** FIRED productively: "only the compose vks changed -> cheap splice" REFUTED at source
  (shapes.rs:551 assigns reduce_shape to all Normalize programs => all 185,862 vks change).
- **Failure-mode.** FIRED. The cheap-looking config fix (regen one JSON) triggers a cluster-scale
  consequence; declaring the path "config-fixable" would be wrong.
- **Structure.** FIRED. The sound generator is build_recursion_vks(None), not the temp-dir self-test
  test_build_vk_map, and not WITHOUT_VK_VERIFICATION (security-weakening, not used).
- **Frontier.** FIRED. Whether a bespoke incremental vk-splicer (recompute only the genuinely-changed
  digests in place) could collapse the 25 h to minutes is open - but source shows ALL digests change,
  so the splice set = the full set; no incremental win exists for a compress_shape change of this kind.
