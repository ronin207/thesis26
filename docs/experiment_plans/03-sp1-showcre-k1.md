# Experiment 3 — SP1 BDEC ShowCre prove at k=1

PROVE-MODE plan. Read this before spending wall-clock. The OOM ladder, watch
criteria, abort thresholds, and conclusion-impact are decided in advance so an
OOM at the floor reads as a measured FRONTIER, not a setup shortfall.

- Host: `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1/script/src/bin/bdec_showcre_host.rs`
- Guest: `program_bdec_showcre` (built two arms by `build.rs:169`; syscall + `griffin-emulated`)
- Relation: `k` pseudonym-ownership + 1 verifier-facing pseudonym + 1 shown credential = `k+2` PLUM-Griffin verifications under one hidden `sk_U`.
- At k=1: `k+2 = 3` verifications. This is the SMALLEST presentation and is HEAVIER than CreGen's 2 verifications (Exp 2). Start here; only attempt k=2 (4 verifications) if k=1 completes.
- Hardware: Apple M5 Pro, 18-core CPU, 24 GB unified memory, macOS 26.5 (Darwin 25.5.0). CPU-bound prover; no GPU/CUDA path.

## Objective and conclusion-impact

ShowCre is the relation that actually carries anonymity in a credential
*showing* — it is the one a verifier runs against. A measured prove number here
is the deployability anchor for the presentation side, distinct from CreGen
(issuance side, Exp 2).

| Outcome | What it changes | Thesis section / table |
|---|---|---|
| **k=1 completes (core STARK)** | First measured prove number for the presentation relation at the smallest setting. Strengthens the deployability picture: "the anonymity-carrying showing relation proves in X min on a 24 GB personal PC." Feeds the four-cell prove-time column for the ShowCre row. | §evaluation, four-cell prove table (add ShowCre k=1 row) |
| **k=2 completes** | Establishes the per-verification scaling slope of the presentation relation (3→4 verifications). Lets the thesis extrapolate to realistic k without measuring every k. | §evaluation, scaling paragraph |
| **k=1 OOM at floor config** | The presentation-relation FRONTIER on the target hardware. With the ladder documented, this is a measured ceiling, not a tuning failure. Reported as: "even the smallest showing (3 verifications) exceeds 24 GB once the prover is tuned to its floor." | §evaluation, frontier/limitations subsection |
| **Anomaly (non-OOM crash, wrong cycle count, rejected witness)** | Blocks the measurement; route to the anomaly procedure below. Not a thesis number. | (held; no table update) |

**Dual-obstruction tie-in (carry verbatim into prose).** A completed ShowCre
*core* STARK proof is succinct but NOT zero-knowledge (Succinct security model:
the default `prove()` path does not satisfy ZK). A showing that is not ZK leaks
the witness and is therefore NOT anonymous. PQ anonymity needs a ZK wrap, and
every SP1 ZK wrap is a pairing-based SNARK (Groth16/PLONK) which is NOT
post-quantum. So even a fast, completing ShowCre core proof does not by itself
deliver PQ-anonymous presentation — that is the dual obstruction. State this
next to any "ShowCre completes" claim.

**Cross-experiment prediction.** If Exp 2 (CreGen, 2 verifications) OOMs at its
floor, predict that ShowCre (3 verifications, strictly heavier) OOMs at the same
floor a fortiori — and say so explicitly in the plan and in the writeup. In that
case k=1 here is run only to CONFIRM the predicted frontier, not in expectation
of completion.

## Prerequisite (wiring)

`bdec_showcre_host.rs` is **execute-only** and MUST be extended to add a prove
mode before this experiment can run. Confirmed by reading the host:

- It calls only `client.execute(elf, stdin).run()` (line 57), never `client.setup(...)` or `client.prove(...)`.
- It has no `PLUM_HOST_MODE`, `PLUM_PROVE_ARM`, or `PLUM_ZK_WRAP` env handling.
- It always runs BOTH arms (syscall arm A, emulated arm B) back-to-back for the cycle delta. A prove run must NOT do this — prove ONE arm per invocation or it double-spends the wall budget.

This is the SAME wiring gap as Exp 2 (CreGen). If Exp 2's host was already wired
for prove, mirror that change here identically.

**Source pattern to mirror:** `plum_host.rs::run_prove` (lines 299–376). The
load-bearing sequence:

```rust
// 1. select ONE arm's ELF (syscall = with-precompile, default)
let arm = std::env::var("PLUM_PROVE_ARM").unwrap_or_else(|_| "syscall".into());
let elf = match arm.as_str() {
    "syscall"  => Elf::Static(BDEC_SHOWCRE_SYSCALL_ELF_BYTES),
    "emulated" => Elf::Static(BDEC_SHOWCRE_EMULATED_ELF_BYTES),
    other => panic!("unknown BDEC_SHOWCRE_ARM={other:?}; use syscall or emulated"),
};

// 2. write the SAME serialized GuestInput the execute path builds (bytes)
let mut stdin = SP1Stdin::new();
stdin.write_vec(bytes);

// 3. setup (timed), then prove ONE arm with the ZK-wrap selector
let pk_proof = client.setup(elf).expect("setup elf failed");
let zk_wrap = std::env::var("BDEC_SHOWCRE_ZK_WRAP").unwrap_or_else(|_| "core".into());
let t_prove = Instant::now();
let proof = match zk_wrap.as_str() {
    "groth16" => client.prove(&pk_proof, stdin).groth16().run().expect("prove (groth16) failed"),
    "plonk"   => client.prove(&pk_proof, stdin).plonk().run().expect("prove (plonk) failed"),
    "core" | _ => client.prove(&pk_proof, stdin).run().expect("prove (core) failed"),
};
let prove_ms = t_prove.elapsed().as_millis() as u64;
println!("prove_ms={prove_ms} (= {:.2} min)", prove_ms as f64 / 60_000.0);

// 4. verify the proof round-trip
client.verify(&proof, pk_proof.verifying_key(), None).expect("verify failed");
```

Notes for the port:
- The ELF byte consts already exist in the host: `BDEC_SHOWCRE_SYSCALL_ELF` (line 28) and `BDEC_SHOWCRE_EMULATED_ELF` (line 29), wired by `build.rs:169` via `cargo:rustc-env=BDEC_SHOWCRE_SYSCALL_ELF_PATH` / `..._EMULATED_ELF_PATH`. No build.rs change needed.
- Reuse the EXISTING `GuestInput` build (host lines 108–118) and `bincode::serialize` (line 118) — do NOT change the witness; k is already read from `BDEC_SHOWCRE_K` (line 83, default 2, floored at >=1).
- Gate prove behind a mode env (e.g. `BDEC_SHOWCRE_MODE=prove`) so the default execute A/B path is preserved for the cycle-delta measurement.
- Keep the honest-witness `accepted` assertion (host line 141) — but in prove mode the check happens via the guest commit decoded from the proof, not a second execute.

Until the host is wired, this experiment is BLOCKED. Wiring is a code change, not
a run; do it, `cargo build`, then proceed.

## Exact command and starting config

Starting anchor = SP1 Cell-2 KNOWN-GOOD config (the only SP1 PLUM prove config
on record that COMPLETED: standalone PLUM verify, 32.53 min). ShowCre k=1 is 3
verifications, so heavier than that single verify — expect this anchor to be
tight or to OOM, hence the ladder below.

Arm: `syscall` (with-precompile, Cell-2 analogue). This is the headline arm; the
precompile is the thesis's instrument, so measure it first. `emulated` is a
secondary run only if the syscall arm completes and budget remains.

ZK wrap: `core` only. Every ZK wrap OOMed at Cell-2 scale already (Groth16 87.8%,
Groth16-halved 83%, PLONK-quartered 81.7%), and pairing wraps are not PQ anyway.
Do NOT spend wall on a wrap here.

```sh
cd "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1/script"

SHARD_SIZE=4194304 \
ELEMENT_THRESHOLD=67108864 \
HEIGHT_THRESHOLD=1048576 \
TRACE_CHUNK_SLOTS=2 \
RAYON_NUM_THREADS=8 \
BDEC_SHOWCRE_K=1 \
BDEC_HOST_SECURITY=80 \
BDEC_SHOWCRE_MODE=prove \
BDEC_SHOWCRE_ARM=syscall \
BDEC_SHOWCRE_ZK_WRAP=core \
RUST_LOG=warn \
cargo run --release --bin bdec_showcre_host \
  2>&1 | tee "../../../../docs/measurements/sp1-showcre-k1-step0/run.log"
```

Pin choices (state in the writeup so no reviewer reads "didn't adapt"):
- `BDEC_SHOWCRE_K=1` — smallest presentation (3 verifications). Confirmed: host line 83 reads this env, floored at >=1.
- `BDEC_HOST_SECURITY=80` — λ=80 is the only level that fits 24 GB; λ=128 OOMs even on lighter relations (host comment, plum_host.rs:98–99).
- `RAYON_NUM_THREADS=8` (not 18) — fewer rayon threads = fewer concurrent trace buffers = lower peak RSS. The memory/throughput trade is taken toward memory because 24 GB is the binding constraint, not core count.

## OOM tuning ladder

The prover's peak RSS is dominated by trace buffers: `SHARD_SIZE` (rows per
shard), `TRACE_CHUNK_SLOTS` (~768 MB per slot), and `RAYON_NUM_THREADS`
(concurrent shard generation) are the big levers; `ELEMENT_THRESHOLD` /
`HEIGHT_THRESHOLD` gate when SP1 splits a chip into a new shard. Step DOWN from
the anchor. Each step trades time for memory. **The floor is itself the
result** — an OOM at the floor is the measured frontier of the presentation
relation on 24 GB.

| Step | Change from previous | Trades | Config |
|---|---|---|---|
| 0 (anchor) | Cell-2 known-good | baseline | `SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8` |
| 1 | `RAYON_NUM_THREADS=4` | ~2× fewer concurrent trace buffers; slower shard gen | `...RAYON_NUM_THREADS=4` |
| 2 | `TRACE_CHUNK_SLOTS=1` | drops ~768 MB resident; more chunk passes (slower) | `...TRACE_CHUNK_SLOTS=1 RAYON_NUM_THREADS=4` |
| 3 | `SHARD_SIZE=2097152` (2^21) | half-size shards = smaller per-shard trace, ~2× more shards (more overhead, slower) | `SHARD_SIZE=2097152 ...HEIGHT_THRESHOLD=524288...` |
| 4 | `ELEMENT_THRESHOLD=33554432`, `HEIGHT_THRESHOLD=524288` (2^19) | force earlier shard splits → smaller live chips per shard, lower peak; many more shards | `ELEMENT_THRESHOLD=33554432 HEIGHT_THRESHOLD=524288 SHARD_SIZE=2097152 TRACE_CHUNK_SLOTS=1 RAYON_NUM_THREADS=4` |
| 5 (FLOOR) | `SHARD_SIZE=1048576` (2^20), `RAYON_NUM_THREADS=2`, `TRACE_CHUNK_SLOTS=1` | smallest shard / least parallelism / one chunk slot. Maximally serial, slowest, lowest peak. | `SHARD_SIZE=1048576 ELEMENT_THRESHOLD=33554432 HEIGHT_THRESHOLD=524288 TRACE_CHUNK_SLOTS=1 RAYON_NUM_THREADS=2` |

Procedure: run step 0. If it OOMs (or peak RSS crosses the abort threshold
below), advance one step and rerun, logging each attempt under its own
`docs/measurements/sp1-showcre-k1-step<N>/`. Stop at the first step that
completes (record it as the working config) OR at step 5 (the floor). An OOM at
step 5 = frontier evidence; record it as a result, not a failure.

Keep `BDEC_SHOWCRE_K=1`, `BDEC_HOST_SECURITY=80`, `BDEC_SHOWCRE_ARM=syscall`,
`BDEC_SHOWCRE_ZK_WRAP=core`, `RUST_LOG=warn` fixed across all steps — only the
memory knobs move. (Note: SP1 reads `SHARD_SIZE`/`ELEMENT_THRESHOLD`/
`HEIGHT_THRESHOLD`/`TRACE_CHUNK_SLOTS`/`RAYON_NUM_THREADS` from the environment;
they are not host CLI flags. Verify each is honored by grepping the step-0 log
for the shard count changing as `SHARD_SIZE` changes between steps 0 and 3 — if
the count is identical, the env var is not being read and the ladder is invalid.)

## Watch and log

Log dir per step: `docs/measurements/sp1-showcre-k1-step<N>/` with `run.log`
(full stdout+stderr via `tee`, command above) and `mem.log` (sampler below).

Live memory sampler (run in a second shell alongside the prove run; 24 GB =
24576 MB, so peak % = peak_rss_mb / 24576 * 100):

```sh
OUT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/sp1-showcre-k1-step0/mem.log"
while pgrep -f bdec_showcre_host >/dev/null; do
  rss_kb=$(ps -axo rss,comm | awk '/bdec_showcre_host/ {s+=$1} END {print s}')
  printf '%s  rss_mb=%s  pct=%.1f\n' "$(date +%H:%M:%S)" "$((rss_kb/1024))" \
    "$(echo "scale=4; $rss_kb/1024/24576*100" | bc)" | tee -a "$OUT"
  /bin/sleep 15
done
```

Watch criteria (live):
- **Peak RSS %** — the binding signal. macOS will swap before a hard OOM-kill; once RSS crosses ~90% of 24 GB, throughput collapses to swap I/O. Treat sustained >90% as a soft OOM (abort, step down) rather than waiting for a kill.
- **Wall time** — note when the proof phase starts (`prove_ms` timer begins after `setup`). Watch for the per-step time budget below.
- **Shard count** — `RUST_LOG=warn` SP1 logs shard generation. Record the total shard count per step; it should rise as `SHARD_SIZE` falls (sanity check the env var is honored). ShowCre k=1 (3 verifications) should produce noticeably more shards than the standalone-verify anchor.
- **Griffin syscall count** in the proof's execution summary should be > 0 on the syscall arm and scale with k+2; if 0, the precompile is inactive and the run is an anomaly, not a measurement.

## Success / partial / abort criteria

Hard time budget: **3 hours wall per step**, **8 hours total across the whole
ladder** (matches the project's 3-hour DNF convention for Cell 1; a gamble must
not eat days). If a single step has not produced a proof in 3 h, abort that step
and advance the ladder. If the cumulative ladder exceeds 8 h, stop and record the
best-completing step (or the frontier if none completed).

- **Success** — the syscall arm produces a valid proof and `client.verify(...)` passes, within budget, at any ladder step. Record `prove_ms`, `setup_ms`, cycle count, shard count, peak RSS %, and the working config. This is the ShowCre k=1 number.
- **Partial** — completes only at a deep ladder step (3–5) with peak RSS >85% and/or wall near the 3 h cap. Report it WITH the config; frame as "completes only at the tuned floor," which is itself informative about headroom. Then do NOT attempt k=2 (it will be heavier and almost certainly OOM).
- **Abort (frontier)** — OOM (soft >90% RSS sustained, or hard kill) persists through step 5. This is the measured frontier of the presentation relation. Record the floor config and the RSS trajectory; this is a thesis RESULT.
- **Abort (anomaly)** — non-OOM crash, `verify` failure, rejected honest witness, or Griffin syscall count = 0 on the syscall arm. Stop, capture the panic/log, do NOT record a prove number. Route to debugging; this is not a frontier.
- **k=2 gate** — attempt `BDEC_SHOWCRE_K=2` (4 verifications) ONLY if k=1 reached Success (not Partial) AND budget remains. Reuse the SAME ladder; expect it to need a deeper step than k=1.

Pre-run prediction (write this BEFORE running, so the outcome is falsifiable):
if Exp 2 (CreGen, 2 verifications) OOMed at its floor, predict ShowCre k=1
(3 verifications) OOMs at the floor too. Running k=1 then CONFIRMS the predicted
frontier.

## Recording

House style: writeup at `docs/sp1_showcre_k1_prove_<date>.md` with sections
Hardware / Configuration / Result / Reproducer / "What this means for the thesis";
logs under `docs/measurements/sp1-showcre-k1-step<N>/`; one row per run in
`docs/experiments.csv`.

CSV header (verbatim):
`experiment_id,workload,signature_scheme,hash,security_level,substrate,precompile,zk_wrap,shard_size,rayon_threads,cycles,execute_wall_ms,prove_wall_ms,prove_wall_human,memory_peak_pct,status,source,measurement_date,notes,discrepancy_flag`

Row template — fill the COMPLETING step's values (status = `completed`); on
frontier, log the floor step with status = `oom`:

```
exp3-showcre-k1-syscall,bdec_showcre_k1,plum,griffin,80,sp1,syscall,core,<shard_size>,<rayon>,<cycles>,,<prove_ms>,<MM.MMmin>,<peak_pct>,<completed|oom|anomaly>,docs/measurements/sp1-showcre-k1-step<N>/run.log,2026-06-08,"k=1=3 verifications; ladder step <N>; presentation-relation anchor",<0|1>
```

Thesis update per outcome:
- **Completed** — add the ShowCre k=1 row to the §evaluation four-cell prove table (prove time, cycles, peak RSS, working config). Add the dual-obstruction caveat: core STARK, not ZK, so not anonymous without a PQ ZK wrap (which SP1 does not offer post-quantum).
- **Completed + k=2 completed** — add the scaling slope (3→4 verifications) to the §evaluation scaling paragraph.
- **Frontier (OOM at floor)** — add to the §evaluation frontier/limitations subsection: the smallest showing (3 verifications) exceeds 24 GB at the tuned floor; cite the floor config and RSS trajectory so it reads as a measured ceiling. If CreGen also OOMed, note the a-fortiori prediction was confirmed.
- **Anomaly** — no table update; log only.

