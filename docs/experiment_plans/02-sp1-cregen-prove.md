# SP1 CreGen Prove (Griffin Precompile) — Prove-Mode Experiment Plan

> **Read before running.** This run can consume several hours. The OOM ladder, watch criteria, and abort thresholds below are decided in advance so that an OOM at the floor config reads as a *measured frontier of the M5 Pro 24 GB substrate*, not as a setup shortfall. CreGen = two PLUM-Griffin verifications under one hidden `sk_U`, so it is roughly 2x the work of the standalone Cell-2 verify (32.53 min completed) and is the single most OOM-prone prove target in the suite.

---

## Objective and conclusion-impact

**Objective.** Produce an end-to-end SP1 STARK proof of the BDEC **CreGen** relation (two PLUM-Griffin verifications) with the `GRIFFIN_FP192_PERMUTE` precompile active, on the M5 Pro 24 GB, and measure prove wall-time / cycles / trace / peak RSS. This is the *prove-mode* counterpart of the already-completed `bdec_cregen_host` execute-mode A/B.

**Why this is the HIGHEST conclusion-impact prove run in the suite — it is the cross-substrate discriminator:**

- RISC Zero CreGen under `succinct` (recursive aggregation) **FAILED after 15.6 h** with an internal-verifier rejection (NOT an OOM; peak RSS 11.24 GB) — see `docs/measurements/risc0_cregen_prove_failed_20260529/`. RISC0 `composite` is the surviving R0 path (its own plan).
- If SP1 CreGen prove **completes** where RISC0 `succinct` could not, that asymmetry is *itself a thesis result*: it shows the BDEC-credential prove is reachable on a personal PC on at least one general-purpose zkVM substrate, and it upgrades the central claim from "verify is reachable" to "the credential-issuance relation is reachable."

**Outcome → thesis artifact mapping:**

| Outcome | Moves which claim | Table / section to update |
|---|---|---|
| **Completes (core)** | SP1 CreGen prove is feasible on 24 GB; cross-substrate discriminator resolves in SP1's favor vs RISC0 `succinct` | §evaluation prove-mode table: add SP1 CreGen row (cycles / prove min / peak %). Strengthen the central claim sentence. |
| **Completes at a stepped-down config** | Feasible but only inside an explicit memory envelope; the *config* is the result | Same row + a footnote stating the exact knob settings that fit; frame as "fits within bound X" |
| **OOM at FLOOR config** | SP1 CreGen prove is *beyond* the 24 GB frontier even fully adapted | §evaluation: record the floor config + peak% as the *adapted-and-bounded frontier*. This is a measured negative, parallel to RISC0 `succinct`'s 15.6 h failure — both substrates bounded on CreGen at λ=80/24 GB. NOT a setup shortfall. |
| **core completes, groth16/plonk OOM** | ZK-wrapping CreGen is the harder ceiling; baseline STARK is reachable but PQ-ZK is not via pairing wraps anyway | §evaluation ZK-wrap note: extend the existing "all ZK-wrap attempts OOMed at Cell-2 scale" finding to the CreGen relation. Reiterate: Groth16/PLONK are **not post-quantum**, so a successful wrap would still not deliver PQ anonymity. |
| **Anomaly** (accepts wrong, 0 Griffin syscalls in proof, verify fails) | Wiring or precompile-routing bug, not a substrate result | Do not record as a measurement; fix wiring, re-run. |

---

## Prerequisite (wiring)

`bdec_cregen_host.rs` is **EXECUTE-ONLY** today. It has no `client.setup(...)`, no `client.prove(...)`, no `client.verify(...)`, and imports neither `ProvingKey` nor `ProveRequest`. A prove path must be added before this experiment can run. Mirror the proven pattern from `plum_host.rs::run_prove` (lines 299–376) onto the CreGen syscall ELF.

**Exact edits to `platforms/zkvms/sp1/script/src/bin/bdec_cregen_host.rs`:**

1. **Imports (lines 18–21).** Mirror `plum_host.rs:26–29`. Change the `sp1_sdk` use to pull in the prove-side types:
   ```rust
   use sp1_sdk::{
       Elf, ProvingKey, SP1Stdin,
       blocking::{ProveRequest, Prover, ProverClient},
   };
   ```
   (`ProvingKey` / `ProveRequest` are needed for the `setup` return value and the `.groth16()/.plonk()` builder calls.)

2. **Add a `run_prove` function** modeled on `plum_host.rs:299–376`. It must use **`Elf::Static(SYSCALL_ELF)`** (the `BDEC_CREGEN_SYSCALL_ELF_PATH` ELF already wired by `build.rs:167–199`; this is the arm where `GRIFFIN_FP192_PERMUTE` fires). The `GuestInput` struct already exists at `bdec_cregen_host.rs:33–41` — reuse it verbatim; do **not** redefine. Skeleton:
   ```rust
   fn run_prove(client: &impl Prover, input: &GuestInput) {
       let bytes = bincode::serialize(input).expect("serialize input");
       println!("input bytes: {}", bytes.len());
       let mut stdin = SP1Stdin::new();
       stdin.write_vec(bytes);

       // setup — mirror plum_host.rs:334-336
       let t_setup = Instant::now();
       let pk_proof = client.setup(Elf::Static(SYSCALL_ELF)).expect("setup elf failed");
       println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

       // ZK-wrap selector — mirror plum_host.rs:345-364 verbatim.
       // PLUM_ZK_WRAP=core (default, succinct STARK, NOT ZK) | groth16 | plonk
       let zk_wrap = std::env::var("PLUM_ZK_WRAP").unwrap_or_else(|_| "core".into());
       println!("zk_wrap={zk_wrap}");

       let t_prove = Instant::now();
       let proof = match zk_wrap.as_str() {
           "groth16" => client.prove(&pk_proof, stdin).groth16().run().expect("prove (groth16) failed"),
           "plonk"   => client.prove(&pk_proof, stdin).plonk().run().expect("prove (plonk) failed"),
           "core" | _ => client.prove(&pk_proof, stdin).run().expect("prove (core) failed"),
       };
       let prove_ms = t_prove.elapsed().as_millis() as u64;
       println!("prove_ms={prove_ms} (= {:.2} min = {:.2} h)",
           prove_ms as f64 / 60_000.0, prove_ms as f64 / 3_600_000.0);

       // verify — mirror plum_host.rs:371-375
       let t_verify = Instant::now();
       client.verify(&proof, pk_proof.verifying_key(), None).expect("verify failed");
       println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);
   }
   ```
   Lines mirrored: setup `plum_host.rs:334–336`; zk_wrap selector `345–364`; verify `371–375`. The CreGen host has no `PLUM_PROVE_ARM` selector and does not need one — CreGen prove is the precompile (syscall) arm by construction; the rv32im `EMULATED_ELF` is for execute-mode A/B only and is far too heavy to prove.

3. **Add a mode gate in `main()`** so the existing execute A/B is preserved and prove is opt-in. After the witness/`input` is built (`bdec_cregen_host.rs:95`, where `let input = GuestInput {...}`), and `client` is created (mirror `plum_host.rs:100` / its own line 100), branch on a host-mode env var. To stay consistent with `plum_host.rs:124`, use **`PLUM_HOST_MODE`** (default keeps current execute A/B behavior):
   ```rust
   let mode = std::env::var("PLUM_HOST_MODE").unwrap_or_else(|_| "compare".into());
   if mode == "prove" {
       run_prove(&client, &input);
       return;
   }
   // ... existing execute A/B (arm A / arm B / delta) unchanged ...
   ```
   Note: the existing code serializes `input` to `bytes` at line 96 and consumes it in `execute_once`. Keep `input` borrowable for `run_prove` by branching *before* the `bincode::serialize(&input)` move at line 96, or pass `&input` and let `run_prove` do its own serialize (the skeleton above does the latter — preferred, no change to existing execute lines).

4. **Build check (no proving) before the real run** so a compile error does not surface 30 min into a prove:
   ```
   cargo build --release --bin bdec_cregen_host
   ```

No `Cargo.toml` change is required — `bdec_cregen_host` is already a declared bin (`script/Cargo.toml:18–20`) and `sp1-sdk` already carries the `blocking` + `native-gnark` features needed for `.groth16()/.plonk()`.

---

## Exact command and starting config

Run from `platforms/zkvms/sp1/script`. Use the **SP1 Cell-2 known-good anchor** (the config under which the standalone PLUM verify prove completed in 32.53 min). CreGen is ~2x heavier, so the anchor is the *starting* rung, not a guaranteed fit.

```bash
cd "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1/script"

# anchor = SP1 Cell-2 known-good
PLUM_HOST_MODE=prove \
PLUM_ZK_WRAP=core \
BDEC_HOST_SECURITY=80 \
SHARD_SIZE=4194304 \
ELEMENT_THRESHOLD=67108864 \
HEIGHT_THRESHOLD=1048576 \
TRACE_CHUNK_SLOTS=2 \
RAYON_NUM_THREADS=8 \
RUST_LOG=warn \
  cargo run --release --bin bdec_cregen_host \
  2>&1 | tee "../../../../docs/measurements/sp1_cregen_prove_$(date +%Y%m%d_%H%M)/run.log"
```

Anchor values (decimal): `SHARD_SIZE=4194304` = 2^22, `ELEMENT_THRESHOLD=67108864` = 2^26, `HEIGHT_THRESHOLD=1048576` = 2^20, `TRACE_CHUNK_SLOTS=2`, `RAYON_NUM_THREADS=8`. `BDEC_HOST_SECURITY=80` is the CreGen host's own λ knob (`bdec_cregen_host.rs:72`); λ=128 is out of scope (OOMs per the project's standing finding).

Create the log dir first: `mkdir -p ../../../../docs/measurements/sp1_cregen_prove_<stamp>`.

---

## OOM tuning ladder

Start at the anchor. On OOM (process killed / `mmap`/alloc failure / kernel `jetsam` kill), step DOWN **one rung at a time**, lowest-cost knob first, re-running the build only if a code change was made (none here — knobs are env vars). Each rung trades prove-time/parallelism for peak RSS. The floor is the maximally-adapted config; an OOM at the floor is the frontier evidence.

| Rung | Change from previous | Trades | Config (only the changed knob shown) |
|---|---|---|---|
| 0 (anchor) | — | baseline Cell-2 known-good | `SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8` |
| 1 | `SHARD_SIZE` 2^22 → **2^21** | smaller shards ⇒ lower per-shard trace RAM, more shards (slower) | `SHARD_SIZE=2097152` |
| 2 | `SHARD_SIZE` 2^21 → **2^20** | further; this is the shard-size floor | `SHARD_SIZE=1048576` |
| 3 | `RAYON_NUM_THREADS` 8 → **4** | fewer concurrent shard traces in flight ⇒ lower peak RSS, ~2x slower | `RAYON_NUM_THREADS=4` |
| 4 | `RAYON_NUM_THREADS` 4 → **2** | minimal parallelism, deepest RAM cut | `RAYON_NUM_THREADS=2` |
| 5 | `ELEMENT_THRESHOLD` and `HEIGHT_THRESHOLD` each down one step | tighter trace-chunk thresholds ⇒ smaller in-memory trace windows | `ELEMENT_THRESHOLD=33554432` (2^25) `HEIGHT_THRESHOLD=524288` (2^19) |
| 6 | `TRACE_CHUNK_SLOTS` 2 → **1** | ~768 MB/slot reclaimed; single in-flight trace chunk | `TRACE_CHUNK_SLOTS=1` |

**FLOOR config (rung 6, all cuts applied):**
```
SHARD_SIZE=1048576
ELEMENT_THRESHOLD=33554432
HEIGHT_THRESHOLD=524288
TRACE_CHUNK_SLOTS=1
RAYON_NUM_THREADS=2
```
If the FLOOR config still OOMs, **that is the SP1 CreGen frontier at λ=80 on M5 Pro 24 GB** — record it as adapted-and-bounded evidence (see Recording). Do not interpret it as "the student didn't tune."

**Note on the env knobs.** These names (`SHARD_SIZE`, `ELEMENT_THRESHOLD`, `HEIGHT_THRESHOLD`, `TRACE_CHUNK_SLOTS`, `RAYON_NUM_THREADS`) are the documented SP1 prover memory knobs and are consumed by the SP1 prover at runtime, not by the host source — so no code edit is needed to step them; only the env vars on the command line change. Confirm each rung's value is actually read by `RUST_LOG=info` on the first rung if uncertain (the SP1 prover logs shard config at startup); revert to `RUST_LOG=warn` for the timed runs to avoid log overhead.

**ZK-wrap is a separate axis, attempted ONLY after `core` completes.** Do not gamble wrap rungs before a clean `core` proof exists. If `core` completes, re-run with `PLUM_ZK_WRAP=groth16` then `=plonk` at whatever rung produced the `core` success. Standing evidence: all SP1 ZK-wrap attempts OOMed even at the *lighter* Cell-2 scale (Groth16 default 87.8%, halved 83%, PLONK quartered 81.7%); CreGen is heavier, so a wrap OOM is the expected outcome — record it, do not ladder-chase it. Reiterate in the writeup: Groth16/PLONK are **not post-quantum**, so even a successful wrap does not deliver PQ anonymity.

---

## Watch and log

Run the prove in the foreground with `tee` (above) so the full SP1 log is captured. In a second terminal, sample peak RSS and wall time live:

```bash
# live RSS sampler (MB + % of 24 GB), 10 s cadence, appended to the run dir
LOGDIR="docs/measurements/sp1_cregen_prove_<stamp>"
while pgrep -f bdec_cregen_host >/dev/null; do
  RSS_KB=$(ps -A -o rss,comm | awk '/bdec_cregen_host/ {s+=$1} END {print s}')
  printf '%s rss_mb=%s pct_of_24gb=%.1f\n' "$(date +%H:%M:%S)" \
    "$((RSS_KB/1024))" "$(echo "$RSS_KB/1024/24576*100" | bc -l)" \
    | tee -a "$LOGDIR/rss_samples.log"
  sleep 10
done
```

(For a non-blocking equivalent that survives turn boundaries, the `Monitor` tool with an until-`pgrep`-empty loop is preferable to a foreground `sleep` loop.)

**Capture from the SP1 stdout/`run.log`:** `setup_ms`, `prove_ms` (printed as min and h), `verify_ms`, the per-shard count and shard config the prover logs at startup, `input bytes`. **Capture from `rss_samples.log`:** peak `rss_mb` and `pct_of_24gb`. CreGen does not re-print cycle counts in prove mode (cycles come from the already-recorded execute A/B); cite the execute-mode cycle figure alongside this prove row.

Also check `Activity Monitor` "Memory Pressure" — sustained yellow/red before a kill is the tell that the next OOM rung is imminent.

Log path convention (house style): `docs/measurements/sp1_cregen_prove_<YYYYMMDD_HHMM>/` containing `run.log`, `rss_samples.log`, and a short `README.md` in Hardware / Configuration / Result / Reproducer / "What this means for the thesis" sections.

---

## Success / partial / abort criteria

**Hard time budget: 4 h per rung; 12 h total across all rungs for this experiment.** A gamble cannot eat days. The RISC0 `succinct` failure burned 15.6 h on a single attempt — do not repeat that pattern. If a rung exceeds 4 h without completing or OOMing, abort it (Ctrl-C) and record it as a *time-budget abort at that config* (distinct from an OOM), then step down one rung.

| Verdict | Criteria |
|---|---|
| **Success (core)** | `client.verify(...)` returns Ok (prints `verify_ms`), `prove_ms` recorded, peak RSS < 100% (no kill). The verify passing is the proof-validity gate — a proof that doesn't verify is not a success. |
| **Partial** | core completes at a stepped-down rung (record the rung), OR core completes but groth16/plonk OOM (record the wrap OOM; expected). |
| **Frontier (negative result, still a result)** | OOM at the FLOOR config (rung 6). Record floor config + peak% at kill. This is the adapted-and-bounded SP1 CreGen frontier. |
| **Abort (time)** | any rung > 4 h, or cumulative > 12 h. Record as time-budget abort, not OOM. |
| **Abort (anomaly — do NOT record as measurement)** | guest commits `accepted=false` path surfaces, OR `setup`/`prove` panics on a non-OOM error (e.g., ELF mismatch, serialize failure). Fix wiring, re-run. The execute-mode asserts (`acc_a`, `grf_a > 0`) already guard correctness in A/B mode; in prove mode the `verify` call is the analogous gate. |

A clean OOM (kernel kill / alloc failure) at any rung 0–5 is **not** a stop — it is a signal to step down. Only rung-6 OOM, time-budget exhaustion, or an anomaly stops the experiment.

---

## Recording

**One row to add to `docs/experiments.csv`** (header: `experiment_id,workload,signature_scheme,hash,security_level,substrate,precompile,zk_wrap,shard_size,rayon_threads,cycles,execute_wall_ms,prove_wall_ms,prove_wall_human,memory_peak_pct,status,source,measurement_date,notes,discrepancy_flag`):

- **On core success** (example shape; fill measured values):
  ```
  bdec_cregen_prove_sp1_core,BDEC CreGen (2× PLUM-Griffin verify),PLUM,Griffin (Fp192),80,SP1 (BabyBear),GRIFFIN_FP192_PERMUTE,core,<shard_size_used>,<threads_used>,<cycles_from_execute_AB>,<execute_ms>,<prove_ms>,<X.XX min>,<peak_pct>,measured,docs/measurements/sp1_cregen_prove_<stamp>/,2026-06-08,"Cross-substrate discriminator: SP1 CreGen prove completes where RISC0 succinct failed (15.6h internal-verifier reject); core STARK = NOT ZK",none
  ```
- **On floor OOM:** same columns, `prove_wall_ms` empty, `prove_wall_human=OOM`, `memory_peak_pct=<peak at kill>`, `status=oom-frontier`, `notes="FLOOR config (SHARD_SIZE=2^20, RAYON=2, TRACE_CHUNK_SLOTS=1); adapted-and-bounded SP1 CreGen frontier at λ=80/24GB"`, `discrepancy_flag=none`.
- **On groth16/plonk OOM after core success:** add a second row with `zk_wrap=groth16` (or `plonk`), `status=oom`, `notes="ZK-wrap OOM at CreGen scale, parallels Cell-2 wrap OOMs; pairing wrap is NOT post-quantum regardless"`.

**Thesis artifacts to update per outcome** (see Objective table for the claim each moves):
- **§evaluation prove-mode table** — add the SP1 CreGen row (cycles / prove min / peak %), or the frontier row if floor-OOM.
- **Central-claim sentence in §evaluation / §conclusion** — on core success, upgrade from "verify reachable" to "CreGen credential-issuance relation reachable on SP1," and state the RISC0-succinct-vs-SP1 asymmetry explicitly as a cross-substrate finding.
- **ZK-wrap note** — extend the existing "all SP1 ZK-wrap attempts OOMed at Cell-2 scale" finding to CreGen; keep the standing caveat that pairing wraps are not PQ.

**House-style writeup** in `docs/measurements/sp1_cregen_prove_<stamp>/README.md` with the five sections: Hardware (M5 Pro, 18-core CPU, 24 GB unified, macOS 26.5 / Darwin 25.5.0, CPU-bound — no CUDA), Configuration (final rung's env vars verbatim), Result (setup/prove/verify ms + peak%), Reproducer (the exact command block above), "What this means for the thesis" (the claim-impact mapping).

