# Experiment 4 — Loquat verification prove inside SP1 (same-scheme crossover anchor)

This is a **preparation document**, read before committing CPU-hours. The
OOM ladder, watch criteria, abort thresholds, and conclusion-impact are
fixed in advance so that — if the run hits the memory wall — it reads as a
**measured frontier with explicit adaptation**, not as a setup shortfall.

We do **not** run anything here. The host
(`platforms/zkvms/sp1/script/src/bin/bench_pqc.rs`) was read to make the
command and knobs exact: `MODE=prove` already wires the full
`setup → prove → verify` path (lines 304–326), `SCHEME=loquat` builds a
λ=128 in-tree (software-Griffin, no precompile) verify workload (lines
215–237), and `ProverClient::from_env()` (line 251) honours the SP1 memory
env knobs. **Runnable as-is — no wiring prerequisite.**

## Objective and conclusion-impact

**Objective.** Obtain a SAME-SCHEME per-proof measurement: Loquat-verify
proved *inside* SP1 (this run, BabyBear substrate) against the existing
Loquat/Aurora *static* point (3.78 min, in-SNARK substrate). One scheme,
two substrates → this **locates the decision-rule crossover** that
§discussion currently only bounds in form (it knows the *sign* of the
churn threshold but not its numeric position).

Why this matters and not the others: the four-scheme execute table and the
PLUM cells compare *across schemes* (PLUM-Griffin vs SHA-3 vs lattice
proxies) or *within one substrate*. None of them holds the scheme fixed
while swapping the substrate. Loquat is the only scheme with both an
in-zkVM path (this host) and an in-SNARK static point (Aurora/Fp127), so it
is the unique lever that turns a qualitative crossover into a number.

| Outcome | What it changes | Thesis section / table |
|---|---|---|
| **Completes** (prove_ms recorded) | §discussion can state the crossover **numerically**: Loquat-in-zkVM (this run) vs Loquat/Aurora 3.78 min → which side of the re-audit/churn threshold a given deployment cadence falls on. Adds the same-scheme per-proof row. | §discussion (decision rule); per-proof comparison table |
| **OOM at floor config** | Records a **measured memory frontier** for a ~518M-cycle software-Griffin workload at λ=128 on 24 GB. The decision rule then reads: "on this hardware the in-zkVM arm is not even per-proof-feasible at λ=128 → the static substrate dominates by infeasibility, not just by churn cost." That is a *stronger* statement of the same crossover direction. | §discussion (decision rule); §evaluation memory-frontier note |
| **Anomaly** (verify fail / wrong cycles / non-OOM crash) | Quarantined; flagged in experiments.csv `discrepancy_flag`; does **not** enter §discussion until reproduced. | none until resolved |

**Bounding claim (state in the doc regardless of outcome):** this run moves
§discussion's decision rule only. It does **NOT** touch the central
dual-obstruction finding (agility tax + slower-than-SHA-3 inversion), and it
is **NOT** a zero-knowledge result — `client.prove()` (line 313) yields a
succinct STARK, not a ZK proof (same caveat as Cells 1/2/3).

## Prerequisite (wiring)

None. `MODE=prove` is already implemented in `bench_pqc.rs`
(`run_prove`, lines 304–326): it runs `client.setup(elf)` then
`client.prove(&pk, stdin).run()` and prints `setup_ms`, `prove_ms`
(also in min and h), and `verify_ms`. The host reads `SCHEME` and `MODE`
from the environment (lines 244–245) and builds the client with
`ProverClient::from_env()` (line 251), so every SP1 env knob below takes
effect with no code change.

## Exact command and starting config

Anchor = the SP1 Cell-2 known-good tuning (standalone PLUM verify completed
in 32.53 min at this config). Loquat is ~518M cycles (vs Cell 2's
125.5M proved cycles, but heavier on software-Griffin in-circuit), so the
anchor is the prudent *starting* point, not a guaranteed-fit point.

```sh
cd "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1/script"

SCHEME=loquat \
MODE=prove \
PLUM_SECURITY=128 \
SHARD_SIZE=4194304 \
ELEMENT_THRESHOLD=67108864 \
HEIGHT_THRESHOLD=1048576 \
TRACE_CHUNK_SLOTS=2 \
RAYON_NUM_THREADS=8 \
RUST_LOG=warn \
cargo run --release --bin bench_pqc \
  2>&1 | tee "../../../../docs/measurements/loquat_zkvm_prove_$(date +%Y%m%d_%H%M%S)/run.log"
```

Notes:
- Create the log dir first: `mkdir -p docs/measurements/loquat_zkvm_prove_<timestamp>/`.
- λ is fixed in-source for Loquat (`loquat_setup(128)`, line 222); `PLUM_SECURITY=128` is set for env-record consistency and has no effect on the Loquat workload — record it so the CSV row is unambiguous.
- `RUST_LOG=warn` keeps shard/segment progress visible without log spam burying the OOM signal.

## OOM tuning ladder

Step **only on OOM** (jetsam silent kill / process vanishes / RSS pinned at
the ceiling). Each step trades prover parallelism/peak-trace-residency for a
lower memory high-water mark, at the cost of wall time. Run one rung,
observe, then descend. The **floor** is the frontier: an OOM there is the
measured result, not a failure to adapt.

| Rung | SHARD_SIZE | ELEMENT_THRESHOLD | HEIGHT_THRESHOLD | TRACE_CHUNK_SLOTS | RAYON_NUM_THREADS | Trades |
|---|---|---|---|---|---|---|
| 0 (anchor) | 4194304 (2^22) | 67108864 | 1048576 (2^20) | 2 | 8 | Cell-2 known-good baseline |
| 1 | 2097152 (2^21) | 33554432 | 524288 (2^19) | 2 | 6 | Halve shard + element thr; fewer threads → lower concurrent trace RAM, ~+20–40% wall |
| 2 | 1048576 (2^20) | 16777216 | 262144 (2^18) | 1 | 4 | Quarter shard; single trace slot (~768 MB→ one resident); ~+50–80% wall |
| 3 (FLOOR) | 524288 (2^19) | 8388608 | 131072 (2^17) | 1 | 2 | Minimum-RAM config: smallest practical shards, single trace slot, near-serial. If this OOMs, that is the frontier. |

Rules:
- Change knobs **together per rung** (the table) — do not hand-mix, so each rung is a reproducible config a reviewer can re-run.
- `TRACE_CHUNK_SLOTS` dominates peak residency (~768 MB/slot); at rungs 2–3 it is pinned at 1.
- Do **not** introduce a ZK wrap (`PLUM_ZK_WRAP`) here. All three Cell-2 wrap attempts OOMed at Cell-2 scale, and pairing wraps are not post-quantum anyway, so a wrap would neither fit nor deliver PQ anonymity. This run measures the core STARK prove only.
- If rung 3 OOMs: **stop**. Record the floor config as the frontier evidence. Descending further is below any deployable config and is not informative.

## Watch and log

- **Peak RSS %.** Live: `while true; do ps -o rss= -p <pid> | awk '{printf "%.1f GB (%.1f%% of 24)\n",$1/1048576,$1/1048576/24*100}'; sleep 30; done`. Record the high-water mark per rung. >85% sustained = OOM risk imminent.
- **Wall time.** From host stdout: `setup_ms`, `prove_ms` (host prints min and h too), `verify_ms`. `prove_ms` is the goal metric.
- **Shard/segment counts.** From `RUST_LOG=warn` lines; record shard count per rung (rises as SHARD_SIZE shrinks) — context for the wall-time trade.
- **Pre-flight RAM.** Note free memory at kick (`memory_pressure` / Activity Monitor). The Cell-2 wrap OOMs showed RSS already at 80% pre-prove from other apps; close them. Record the baseline.
- **Log path.** `docs/measurements/loquat_zkvm_prove_<timestamp>/run.log` (full stdout+stderr via `tee`). Add a short `RESULT.md` in the same dir in house style: Hardware / Configuration / Result / Reproducer / "What this means for the thesis".

## Success / partial / abort criteria

**Hard time budget: 4 h wall, total, across all rungs.** This is a
same-scheme *anchor* point, not the headline result — it cannot eat days.
Cell 2 (125.5M proved cycles) took 32.5 min; Loquat is ~4× the cycles and
software-Griffin-heavy, so a completing rung should land in roughly
2–4 h. If 4 h elapses with no completed rung, stop and record DNF + the
last rung's RSS as the frontier.

- **Success.** A rung completes: host prints `prove_ms` and `verify_ms`, and `verify` does not error (line 322–324, an honest proof must verify). Record prove_ms + the completing rung's config. Done — do not descend further for a "better" number.
- **Partial.** Rungs 0–2 OOM but rung 3 (floor) is still running within budget — let it finish if time remains. Or: a rung completes but only at the floor config (record it, note the tuning needed).
- **Abort / frontier.** Rung 3 (floor) OOMs, OR the 4 h budget expires with no completed rung. Either is a **measured frontier**: record the floor config and its peak RSS, and write the §discussion line as "in-zkVM Loquat-verify at λ=128 is not per-proof-feasible on 24 GB even at minimum tuning."
- **Anomaly halt.** `verify failed` panic, `prove failed` with a non-memory error, or `accepted=false`-equivalent → halt, do not retune, quarantine, set `discrepancy_flag`.

## Recording

**experiments.csv row** (append; column order matches the existing header):

```
loquat_lambda128_zkvm_prove,Loquat λ=128 verify proved in-zkVM (software Griffin),Loquat,Griffin (Fp127² software),128,SP1 (BabyBear),none,none,<final SHARD_SIZE>,<final RAYON_NUM_THREADS>,518258824,n/a,<prove_ms or empty>,<human or DNF/OOM>,<peak RSS %>,<measured|OOM|DNF>,docs/measurements/loquat_zkvm_prove_<timestamp>/run.log,2026-06-08,Same-scheme crossover anchor vs Loquat/Aurora 3.78min static; succinct STARK NOT ZK; rung=<n>,<none|frontier>
```

(Cycles 518,258,824 are the already-measured execute count — fixed for this
workload — so they are filled in regardless of prove outcome.)

**Thesis update per outcome:**
- **Completes** → §discussion: add the numeric crossover (Loquat-in-zkVM `prove_ms` vs Loquat/Aurora 3.78 min); add the same-scheme per-proof comparison row. State which side of the deployment-cadence threshold this places the in-zkVM arm.
- **OOM at floor / DNF** → §discussion + §evaluation memory-frontier note: record the floor config + peak RSS as the measured ceiling; phrase the crossover as substrate-dominance-by-infeasibility.
- **Either way** → re-state the bounding clause: this does not change the central dual-obstruction finding, and is not a ZK result.

