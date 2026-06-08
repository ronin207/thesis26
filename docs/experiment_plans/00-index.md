# Experiment plans — prove-mode runs (read before running)

These are **preparation** documents, not run logs. Each plan fixes, in advance, the OOM tuning
ladder, the watch/abort criteria, and the per-outcome thesis impact, so the run itself is mechanical
and **any failure reads as a measured frontier, not a setup shortfall**. Generated 2026-06 from the
host sources; verify commands against the host before each run.

Hardware target: Apple M5 Pro, 18-core CPU, 24 GB unified memory, macOS 26.5 (Darwin 25.5.0),
CPU-bound provers (no GPU path).

## The "not an all-OOM thesis" framing (read first)

The thesis is **not** dominated by OOM. Completed, verified anchors already exist:
- Cell 2 (PLUM verify + Griffin precompile, SP1): **32.53 min, receipt verified**.
- Cell 3 (PLUM-SHA3 control, SP1): **13.28 min, verified**.
- RISC Zero single PLUM verify (`sys_bigint`): **6 h 19 m, verified**.
- Griffin-Fp192 single-permutation smoke prove: completes (execute+prove+verify).
- Aurora BDEC static baseline: **3.78 min**. `R_static` recompile: **~0.3 s**.
- All execute-mode relations: CreGen 9.4e9, ShowCre 1.41e10 (k=1) / 1.88e10 (k=2) cycles.

The OOMs/anomalies are concentrated at exactly two layers — the **credential-relation prove**
(CreGen/ShowCre) and the **ZK-wrap** — and the purpose of these runs is to convert each *ambiguous*
negative into a *characterised* one (completes / OOM-at-floor frontier / recursion-independent
failure). Each plan ties every outcome to the specific thesis sentence/table it moves.

**Do not re-run the ZK-wrap to "fix" the OOM.** The pairing-based wraps (Groth16/PLONK) are not
post-quantum regardless of whether they fit in memory, so the dual-obstruction conclusion's primitive
prong stands independently of any wrap OOM. The wrap OOM is a *writing* item (enumerate the tuning
sweep already on record in `docs/experiments.csv`: Groth16 default 87.8 %, Groth16 halved 83 %,
PLONK quartered 81.7 %), not a re-run.

## Recommended run order (cheapest-informative first)

1. **`01-risc0-cregen-composite.md`** — runnable as-is; the cheapest test of "does the full credential
   relation prove at all?" Resolves the succinct-anomaly ambiguity from the composite direction.
2. **`04-loquat-in-zkvm-sp1.md`** — runnable as-is; independent; locates the decision-rule crossover
   (same-scheme Loquat point on both substrates). Can run anytime.
3. **`02-sp1-cregen-prove.md`** — **prerequisite: wire prove mode into the SP1 BDEC host** (the SP1
   `bdec_cregen_host.rs` / `bdec_showcre_host.rs` are execute-only; mirror the prove path in
   `plum_host.rs`). Highest conclusion-impact: the cross-substrate discriminator. SP1 completing where
   RISC0's succinct failed is itself a thesis result.
4. **`03-sp1-showcre-k1.md`** — same wiring prerequisite; run after `02` confirms CreGen. The
   anonymity-relevant relation (k+2 = 3 verifications at k=1).

## Shared SP1 OOM tuning ladder (used by `02`, `03`, `04`)

Anchor = the Cell-2 known-good config (`docs/sp1_plum_cell2_measurement.md`):
`SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8`,
`PLUM_SECURITY=80`, `RUST_LOG=warn`.

On OOM (jetsam kill / memory pressure), step **in this order**, re-running after each step:
1. `SHARD_SIZE`: 2^22 → 2^21 → 2^20 (more, smaller shards; less memory spike, more sequential work).
2. `RAYON_NUM_THREADS`: 8 → 4 → 2 (fewer concurrent trace buffers).
3. `ELEMENT_THRESHOLD` / `HEIGHT_THRESHOLD`: one step down each (smaller per-shard traces).
4. `TRACE_CHUNK_SLOTS`: 2 → 1 (saves ~768 MB/slot).

**Floor config** = `SHARD_SIZE=2^20`, `RAYON_NUM_THREADS=2`, thresholds stepped down, `TRACE_CHUNK_SLOTS=1`.
If it still OOMs at the floor, **that is the SP1 frontier for that relation** — record it as such; it is
the "adapted and still bounded" evidence, not an unexplored configuration. Do **not** raise
`PLUM_SECURITY` to 128 (λ=80 is pinned; 128 worsens the ceiling). RISC Zero (`01`) exposes no shard
knobs — its only lever is `BDEC_PROVER_OPTS` (`composite`, already the reliable path), so its floor is
reached immediately.

## Recording each run

- Log under `docs/measurements/<run-id>/` (timestamped, with peak-RSS watch).
- Add one row to `docs/experiments.csv` (existing schema).
- Update the thesis per the "conclusion-impact" table in each plan (which §/table each outcome moves).

## Plans

- `01-risc0-cregen-composite.md` — RISC0 CreGen prove, composite mode (as-is).
- `02-sp1-cregen-prove.md` — SP1 CreGen prove, Griffin precompile (needs prove-mode wiring).
- `03-sp1-showcre-k1.md` — SP1 ShowCre prove at k=1 (needs prove-mode wiring).
- `04-loquat-in-zkvm-sp1.md` — Loquat verify prove inside SP1 (as-is; same-scheme crossover).
