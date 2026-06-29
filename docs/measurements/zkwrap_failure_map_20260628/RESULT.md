# PLUM-verify ZK-wrap pipeline: stage-anchored FAILURE-OCCURRENCE MAP (SP1)

> **UPDATE (2026-06-28):** the "STILL MISSING #2" item below (per-arm Griffin attribution of the recursion-shape overflow) was subsequently CLOSED — Griffin is the SOLE cause (+276,768 ExtAlu / +34.8%, byte-for-byte) per `../zkwrap_griffin_shape_attribution_20260628/RESULT.md`. Treat that record as authoritative for the attribution.

Date: 2026-06-28. Machine: Mac17,9 (M5 Pro, 18 cores), 24 GB (`hw.memsize=25769803776`).
SP1 submodule HEAD `8bf0248bc` (detached fork of v6.2.1). Arm = syscall (Griffin Fp192
precompile ON, Cell 2) unless stated; PLUM-80, λ=80; `SP1_PROVER=cpu`, in-process CPU prover.
Soundness preserved: `WITHOUT_VK_VERIFICATION=1` NOT used anywhere.
This run produced TWO fresh observations (RUN 1, RUN 2) and consolidates four prior ones.

State at run time (CONFIRMED): `crates/prover/compress_shape.json` = REGENERATED
(md5 585b8571, ExtAlu 1,072,032 / PrefixSumChecks 263,424); `.bak` of original present;
`crates/prover/src/vk_map.bin` = STALE original (md5 931c0bba, 7,434,488 B, May 17). UNCHANGED.

---

## THE MAP — one row per distinct failure occurrence ever seen

Legend: RESOURCE wall = RAM/time the deployer pays PER PROOF. STRUCTURAL/BUILD wall =
one-time toolchain provisioning, paid once, independent of per-proof resource.

| # | Pipeline stage | Exact location (file:line) | Number tripped → threshold | Mechanism (WHERE + WHY, 1 sentence) | Wall | Peak RSS | OBS/EXTR | Wall type | Log ref |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CORE prove, no Griffin precompile (Cell 1, default cfg) | jetsam/OOM kill (no panic; SP1 monitor `prover` mem-warn path) | 87.94% of 24 GB ≈ 21.1 GB → macOS jetsam pressure threshold | rv32im Griffin emulates each permute as ~4,564 extra UINT256_MUL → 7.08e9 cycles → core trace working set blows 24 GB at default SHARD_SIZE | 1 m 45 s | ≈21.1 GB (SP1 monitor %, no getrusage) | OBSERVED (prior, 2026-05-18) | RESOURCE (RAM) | `docs/sp1_plum_cell1_attempt2.md` L42 |
| 2 | CORE prove, no Griffin precompile, memory-tuned UNCAPPED (Cell 1) | no panic/kill — Operator SIGTERM; swap-thrash throughput collapse | wall 5 h 07 m → Operator patience; no completion receipt, no OOM | same 7.08e9-cycle trace shrunk under tuning fits RAM but pages to swap (15 GB swap, CPU pegged 9 cores) → prove throughput collapses, never terminates | 5 h 07 m (08:17:42–13:24:50) | resident modest (~5.7 GB + 15 GB swap on the comparable 2026-05-21 3h6m run; 6-12 run sampler bound wrong PID) | OBSERVED (prior, 2026-06-12) | RESOURCE (TIME) | `docs/measurements/audit5_campaign_20260612/SUMMARY.txt` L40; `c1u_cell1_tuned_uncapped.log` |
| 3 | CORE+early-recursion, ZK-wrap @ default 8 core / 4 recursion workers (quartered SHARD_SIZE 1<<22) | jetsam kill on SYSTEM mem pressure (not process RSS); `/usr/bin/time -l` | getrusage maxRSS 19,976,421,376 B = 19.98 GB; phys footprint 96,395,253,696 B = 89.8 GiB → jetsam | 8 core workers each materialize a shard trace concurrently → macOS compressor footprint hits 89.8 GiB → jetsam fires though RSS only 18.6 GiB | ~19.9 min | 18.60 GiB RSS / 89.8 GiB compressor footprint | OBSERVED (prior, 2026-05-29) | RESOURCE (RAM, concurrency-driven) | `docs/measurements/zkwrap_worker_concurrency_20260627/RESULT.md` L44-50 |
| 4 | COMPRESS/REDUCE (arity-4 compose), workers=2, STALE shape | `crates/hypercube/src/util.rs:50` (`panic!("fixed height is too small...")`), surfaced via `recursion/machine/src/chips/alu_ext.rs:99` + `prefix_sum_checks.rs:95` | ExtAlu 1,064,022 > 795,264; PrefixSumChecks 263,400 > 224,608 | the arity-4 compose verifier is a FIXED circuit; PLUM-verify's recursion witness needs ExtAlu 1,064,022 rows but committed `compress_shape.json` provisioned 795,264 → trace cannot be formed | 30.33 min | maxRSS 16.509 GiB (sampler 15.95) — no kill | OBSERVED (prior, 2026-06-27) | STRUCTURAL/BUILD (stale static shape; RAM not binding) | `docs/measurements/zkwrap_default_shard_20260627/RESULT.md` L25-57 |
| 5 | recursion-vk VALIDATION (pre-COMPRESS), workers=2, REGENERATED shape | `crates/prover/src/recursion.rs:151` (`RecursionVks::open` → `.ok_or(Fatal("vk not allowed"))`); host panic `script/src/bin/plum_host.rs:359` | regenerated reduce-shape digest ∉ stale `vk_map.bin` 185,862-entry allowlist | regenerating `compress_shape.json` changed `program.shape` → changed every recursion-program vk digest (`hash_koalabear`) → absent from the May-17 `vk_map.bin` Merkle allowlist (`recursion.rs:57 include_bytes!`) | **2.49 min** (vk-reject @ 146.1 s) | **maxRSS 14.56 GiB**, sampler peak 10.74 GiB @ 85.8 s; RSS 6.88 GiB at reject instant | **OBSERVED (RUN 1, FRESH, this run; n=2 with prior)** | STRUCTURAL/BUILD (stale vk allowlist; RAM never binding) | THIS DIR `../zkwrap_vkreject_run1_20260628/vkreject_w2.{log,meta}` |
| 6 | gnark PLONK BN254 wrap | UNREACHED; would hit `crates/prover/src/build.rs` "Plonk artifact not found; generate them locally" | n/a — never executed | downstream of #5: gnark circuit is keyed to the wrap vk → keyed to the vk_map root; `~/.sp1/circuits` ABSENT; needs the (un-rebuilt) vk_map first | — | UNMEASURED (the decision-determining unknown) | n/a | STRUCTURAL/BUILD (missing keyed circuit) | `docs/measurements/zkwrap_vkmap_scale_wall_20260628/RESULT.md` L63-76 |

### Resource-vs-structural reading of the map
- The TWO walls a deployer pays PER PROOF are RESOURCE walls and BOTH are in the
  no-precompile / high-concurrency regime: Cell-1 RAM-OOM (#1), Cell-1 time-DNF (#2),
  and the 8-worker jetsam (#3). The Griffin precompile + low workers REMOVE all three
  (Cell 2 completes core+recursion at maxRSS ≤ 16.5 GiB, no kill).
- The walls that then block the ZK-wrap (#4, #5, #6) are ALL STRUCTURAL/BUILD walls —
  stale or missing build-time static artifacts ({compress_shape.json, vk_map.bin, gnark
  circuit}), paid ONCE at toolchain provisioning, INDEPENDENT of per-proof RAM/time.
  Across every wrap attempt RAM never exceeded ~16.5 GiB; none of #4/#5/#6 is a memory wall.

---

## RUN 1 (FRESH) — the current binding wall, fully instrumented

Config: PLUM-80, λ=80, arm=syscall (Griffin ON), `PLUM_ZK_WRAP=plonk`,
`SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`, `SP1_WORKER_NUM_CORE_WORKERS=2`,
SHARD_SIZE default (1<<24), SP1_PROVER=cpu. Binary `plum_host` built 2026-06-28 01:34
(regenerated-shape build). Instrumentation: timestamped stdout + 3 s ps-rss sampler +
getrusage(RUSAGE_CHILDREN). Raw: `../zkwrap_vkreject_run1_20260628/`.

- **Result: rc=101 (panic), wall 2.49 min (149.2 s), getrusage maxRSS 14.562 GiB,
  sampler peak 10.74 GiB @ 85.8 s.**
- **Exact failure (log, verbatim):**
  `07:28:27 ERROR task failed with fatal error: vk not allowed`
  → `ERROR Controller: task failed: Fatal(Core proof task local_worker_...failed)`
  → `thread 'main' panicked at script/src/bin/plum_host.rs:359:14: prove (plonk) failed:
     ... artifact not found`.
- **Stage timeline (elapsed / RSS at line):** 31.5 s "starting proof generation mode=Plonk"
  (RSS 4.15 GiB) → 90.1 s "Memory usage is high 80.27%" (8.98 GiB) → 110.1 s 80.07% (3.51 GiB,
  RSS dropped = core→recursion transition) → **146.1 s "vk not allowed" (6.88 GiB)**.
  CORE proving executed (115 s of work, RSS climbed to 10.7 GiB peak then fell); the
  rejection fires at the FIRST recursion-vk lookup — EARLIER than the prior compose panic
  (#4, 30 min): the shape regen relocated the wall from COMPRESS (capacity) back to
  vk-validation (allowlist).
- **vk digest:** the rejected digest is NOT printed by the binary — `recursion.rs:151` does
  `.ok_or(...)` with no logging of the missing `hash_koalabear` key. The MISS is what is
  observed; the mechanism (digest changed by shape regen) is source-confirmed, not log-printed.
- **Confirms (n=2):** matches the prior regen-run (`zkwrap_regen_shape_20260628`: rc=101,
  2.38 min, maxRSS 13.14 GiB, same "vk not allowed"). Reproducible.
- **WHY-chain (pinned):** regen `compress_shape.json` → `program.shape` changed (shapes.rs:551
  assigns reduce_shape to ALL Normalize programs) → every recursion-program vk digest changed →
  absent from the stale `vk_map.bin` allowlist. Allowlist size = **185,862 entries** (bincode
  u64 header; 185,862×40 B + 8 B = 7,434,488 B = file size, exact), file
  `submodules/sp1/crates/prover/src/vk_map.bin`.

## RUN 2 (FRESH) — vk_map regeneration slope: CORRECTS the ~25 h figure to ~51 h

Generator = bin `build_recursion_vks` (production, sound; `--start/--end` slices for timing
only, written to a scratch dir — real `vk_map.bin` UNTOUCHED, md5 unchanged). chunk_size=4
(the default the full job uses). getrusage maxRSS per slice. Raw:
`../zkwrap_vkmap_slope_20260628/slope.out`.

| slice (index range) | n | wall | per-setup (startup-subtracted) | maxRSS |
|---|---|---|---|---|
| 0..2 (startup probe) | 2 | 7.63 s | (startup ≈ 7.6 s) | 8.61 GiB |
| 0..400 (small Normalize, range start) | 400 | 382.82 s | **0.938 s** | 11.998 GiB |
| 90000..90400 (mid Normalize) | 400 | 400.00 s | **0.981 s** | 14.411 GiB |
| 185400..185800 (large Normalize, range end) | 400 | 422.45 s | **1.037 s** | 14.316 GiB |

- **Linearity:** rate rises monotonically 0.938 → 0.981 → 1.037 s/setup (+10.6% start→end),
  ~linear in index (larger shapes at higher index). Midpoint sample (0.981 @ idx 90k) matches
  the linear-interpolated 0.988 within 1% → linear model holds. CONFOUND (flagged): the three
  slices ran back-to-back over 20 min, so part of the +10% upward trend may be M5 THERMAL
  accumulation, not purely shape size — either way the steady-state rate is 0.94–1.04 s/setup.
- **Corrected total (OBSERVED-LINEAR-EXTRAPOLATION):** 185,862 setups ×
  {0.938 → 48.4 h | mean 0.985 → **50.9 h** | 1.037 → 53.5 h}, + ~8 s startup.
  **Defensible bound: ~51 h, envelope 48–54 h** (chunk_size 4, single process, CPU already
  ~10× saturated so more workers won't materially help; M5 Pro 24 GB).
- **This REPLACES the prior EXTRAPOLATED ~25 h** (`zkwrap_vkmap_scale_wall_20260628`), which
  used 0.49 s/setup measured from 6–8-setup slices too short to clear startup/warmup. The true
  per-setup rate is ~2× higher; the sound vk_map regen is **~51 h, not ~25 h.**
- **RAM is NOT the limit anywhere in vk_map regen:** per-setup maxRSS 12–14.4 GiB (larger
  shapes ≈ 14.4 GiB), well under 24 GB. The wall is COMPUTE TIME (~51 h), a STRUCTURAL/BUILD wall.

---

## STILL MISSING (measurements not yet taken that would close where/why)

1. **gnark wrap-stage peak RAM** — the thesis's decision-determining number. Blocked behind
   the ~51 h vk_map regen (#6 is downstream of #5). Cost to obtain: ~51 h vk_map rebuild + gnark
   circuit setup (Go 1.26.3 + native-gnark present, toolchain-feasible) + one wrap run. Matters:
   it is the ONLY way to learn whether the FINAL wrap fits 24 GB; everything before it is ≤16.5 GiB.
2. **Per-arm (Griffin vs SHA-3) trace-area split at the COMPOSE stage** — the precompile-paradox
   attribution. Does the Griffin precompile chip ENLARGE the core machine → enlarge the compose
   ExtAlu count to 1,064,022 (#4), or is the stale shape fork-wide? Cost: a feature-gated
   no-Griffin (SHA-3) build + shape regen + take it to the compose stage. This is the ONLY way to
   settle whether the precompile that accelerates Cell-2 CORE is what overflows the wrap shape.
   No non-precompile compose-stage datapoint exists (the 2026-05-29 baseline OOM'd before the
   shape check). Cost ~1 build + ~30 min run.
3. **Whether the regenerated toolchain, once vk_map is rebuilt, completes the wrap within 24 GB** —
   the end-to-end verdict. Requires #1 done; then re-run RUN-1 config to completion. Cost: the
   ~51 h gate + downstream wrap.

---

## Cost (machine wall-time, this session)
- RUN 1 (vk-reject re-run, fresh): 2.49 min, rc=101.
- RUN 2 (4 vk slices: 7.63 + 382.82 + 400.00 + 422.45 s): 18.55 min compute.
- Source tracing / state verification: ~15 min.
- Total heavy compute ≈ 21 min. n=1 per slice; RUN-1 wall is n=2 with the prior regen run.
- No multi-hour run launched (the ~51 h vk_map regen was sized, not executed, per gate).

## State / recoverability (submodules/sp1) — committed NOTHING
- `compress_shape.json` REGENERATED, left in place (md5 585b8571); `.bak` present.
  Restore: `git -C submodules/sp1 checkout crates/prover/compress_shape.json`.
- `crates/prover/src/vk_map.bin` UNMODIFIED (md5 931c0bba, re-verified post-run). RUN-2 slices
  wrote only to `/private/tmp/claude-501/vkmap_slope_build/` (incomplete 16 KB, discardable).
- Pre-existing (not this run): `griffin_fp192/mod.rs`, `gnark-ffi/build.rs` modified;
  `griffin_fp192/fault_injection.rs` untracked.

## Five-attack
- **Source.** RUN-1 failure read from `vkreject_w2.log` (timestamped) and traced to recursion.rs:151
  / plum_host.rs:359 / vk_map.bin 185,862-entry header. RUN-2 rates from getrusage + wall, startup
  isolated by the 0..2 probe. FIRED: the rejected vk DIGEST is not log-printed (code does no
  logging on the miss) — the miss is observed, the digest-change mechanism is source-inferred, not
  printed. FIRED: RUN-2 per-setup is n=400×3 slices, not the full 185,862 — the ~51 h is
  LINEAR-EXTRAPOLATED from a measured, mildly-rising slope, explicitly labelled EXTRAPOLATED.
- **Assumption.** FIRED productively: the prior 0.49 s/setup (→25 h) is REFUTED by a larger
  contiguous measurement (0.94–1.04 s/setup → ~51 h); the short-slice rate was startup-contaminated.
- **Failure-mode.** FIRED. The +10% rate rise across slices is partly attributable to thermal
  accumulation, not solely shape size — flagged; it does not change the dominant 0.5→~1.0 correction.
- **Structure.** FIRED. Walls #4/#5/#6 are distinct STRUCTURAL artifacts (shape capacity, vk
  allowlist, gnark circuit), each relocating the wall earlier/later, none a RAM wall — separated
  cleanly from the RESOURCE walls #1/#2/#3 (no-precompile RAM/time, 8-worker jetsam).
- **Frontier.** FIRED. The gnark wrap peak RAM (#6) stays UNMEASURED behind the ~51 h gate; whether
  the rebuilt toolchain completes the wrap within 24 GB is the open end-to-end question.
