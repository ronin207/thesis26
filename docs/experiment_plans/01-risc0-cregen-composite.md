# RISC Zero CreGen prove (composite) — full credential-generation relation prove attempt

This is a **preparation** document. Read it before the run. The knob ladder, watch
criteria, abort thresholds, and per-outcome thesis impact are all decided here so that
the run itself is mechanical and an unsuccessful outcome reads as a **measured
frontier**, not a setup shortfall.

The host driver
(`platforms/zkvms/risc0/host/src/bin/bdec_credgen_plum_host.rs`) drives the
`BDEC_CREDGEN_PLUM_GRIFFIN_ELF` guest, which runs **two** `plum_verify` calls under a
shared witness-only `pk_U` — the formal CreGen relation
`Verify(pk_U, h_{U,TA}, c_{U,TA}) ∧ Verify(pk_U, ppk_{U,TA}, psk_{U,TA})`. This is the
*full credential-generation relation*, twice the standalone-verify workload.

---

## Objective and conclusion-impact

**Question this run answers:** does the full CreGen relation produce a *valid receipt
at all* on RISC Zero on the target hardware, using the recursion-free `composite`
path that avoids the failure mode that killed the `succinct` attempt?

Background, verified in source:
- The `succinct` (recursive-aggregation) path **failed after 15.6 h** with RISC Zero's
  own recursive verifier rejecting an intermediate segment proof — *not* an OOM (peak
  RSS 11.24 GB on 24 GB) — at 9.4×10⁹ guest cycles, λ=80
  (`docs/risc0_prove_failure_finding_20260530.md`).
- Execute mode for the same guest/input is reproducible: **9.4×10⁹ cycles, 65 s**, both
  signatures `Accept`. That number stands regardless of this run's outcome.
- `composite` (`ProverOpts::default()`, confirmed at host line 266) performs **no
  recursive aggregation** — larger receipt, more reliable on long workloads — so it
  structurally sidesteps the segment-composition rejection. This is the cheapest
  informative test of "does CreGen prove at all on RISC0".

Per-outcome impact, by thesis section/table:

| Outcome | What it changes |
|---|---|
| **Completes** (valid receipt, `receipt.verify` passes) | UPGRADES the central claim from *"only standalone PLUM verify is feasible to prove on RISC0"* to *"the full CreGen relation proves on RISC0 (composite) in X h on M5 Pro 24 GB"*. **Retires the §evaluation CreGen prove anomaly** (the 15.6 h succinct rejection becomes "a recursion-path-specific failure, routed around by composite"). Add the CreGen-prove row to **Table `tab:bdec`** with measured wall time + cycles. |
| **OOM** (kernel memory pressure / killed) | NEW frontier datum distinct from the succinct rejection: composite's larger non-recursive proof exceeds 24 GB. This is a *memory* frontier (composite trades recursion for receipt/working-set size), recorded as such in §evaluation. RISC0 exposes no shard knobs, so this OOM is itself the as-is RISC0 ceiling — no further tuning lever exists (see ladder). |
| **Repeat internal-verifier rejection** (`verify segment / verification indicates proof is invalid`, no OOM) | The failure is **recursion-independent** — it is not the segment-composition bug. Escalates the §evaluation finding from "succinct recursion bug" to "a guest/precompile-level prove obstruction on RISC0", and triggers debug rerun #3 (`RUST_LOG=risc0_zkvm=debug` to localise). Strengthens the Sako framing (consumer-hardware zkVM stack does not produce a valid receipt for this workload). |
| **Wall-clock blowup** (no completion within hard budget) | Confirms the **RISC0 credential-prove time frontier** at λ=80: composite is 2–3× slower than succinct per phase, and succinct already burned 15.6 h. Recorded as a time-frontier datum in §evaluation; the full-lifecycle estimate stays qualitative. |

Either way this run is a thesis-movable datum: success retires an anomaly and fills
`tab:bdec`; any failure is a *characterised* frontier (memory / recursion-independent
soundness / time), explicitly distinct from the already-recorded succinct rejection.

---

## Prerequisite (wiring)

**None — runnable as-is.** Confirmed by reading the host:

- `BDEC_HOST_MODE=prove` is a recognised mode (host lines 100–106; `prove` →
  `HostMode::Prove`, the prove branch at lines 254–316).
- `BDEC_HOST_SECURITY` parses to `usize`, **defaults to 80** (lines 109–114). Leave at 80.
- `BDEC_PROVER_OPTS` selector (lines 263–273): `composite` → `ProverOpts::default()`,
  `succinct` → `ProverOpts::succinct()`, `groth16` → `ProverOpts::groth16()`; any other
  value **panics**. Default when unset is `composite` (line 264).
- The prove branch already calls `prove_with_opts`, decodes the journal, **and verifies
  the receipt** against `BDEC_CREDGEN_PLUM_GRIFFIN_ID` (lines 301–304) — so a "completes"
  outcome includes a built-in soundness check; no extra verify step is needed.

Note: the inline comment at host line 287 still prints `"ProverOpts::succinct, NOT
zero-knowledge"` regardless of the selected opts — a stale string, not a behavioural bug
(the actual opts come from `BDEC_PROVER_OPTS`). Do not be misled by that log line.

---

## Exact command and starting config

Run from the RISC0 host crate directory. Set `BDEC_PROVER_OPTS=composite` explicitly
(do not rely on the default), pin security to 80, and quiet logging. `caffeinate -i`
prevents idle sleep over a multi-hour run (a sleep gap polluted the prior succinct run).
`/usr/bin/time -l` captures peak RSS on macOS.

```
cd "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/risc0/host"

mkdir -p "../../../../docs/measurements/risc0_cregen_composite_$(date +%Y%m%d_%H%M)"

RUN_DIR="../../../../docs/measurements/risc0_cregen_composite_$(date +%Y%m%d_%H%M)"

caffeinate -i /usr/bin/time -l \
  env BDEC_HOST_MODE=prove \
      BDEC_HOST_SECURITY=80 \
      BDEC_PROVER_OPTS=composite \
      RUST_LOG=warn \
      RUST_BACKTRACE=1 \
  cargo run --release --bin bdec_credgen_plum_host \
  2>&1 | tee "$RUN_DIR/bdec_credgen_composite.log"
```

`RUST_BACKTRACE=1` costs nothing on success and gives a stack on a panic (the
`.expect("prove failed")` at host line 278 will panic on a verifier rejection).

---

## OOM tuning ladder

**RISC Zero exposes no shard/segment env knobs.** The SP1 ladder (SHARD_SIZE,
ELEMENT_THRESHOLD, HEIGHT_THRESHOLD, TRACE_CHUNK_SLOTS, RAYON_NUM_THREADS) **does not
exist here**. The only levers the host exposes are `BDEC_PROVER_OPTS` and
`BDEC_HOST_SECURITY`. So the "ladder" is short and the floor is reached quickly — which
is exactly what makes a failure at the floor a clean as-is frontier rather than an
unexplored configuration.

| Step | Config | What it trades | Verdict if it fails |
|---|---|---|---|
| **Anchor** | `BDEC_PROVER_OPTS=composite`, `BDEC_HOST_SECURITY=80` | No recursion (avoids the succinct segment-composition rejection); larger receipt + working set in exchange. The most reliable path at this cycle scale. | Step down to the floor. |
| **Floor** | same: `composite`, security 80 | This *is* the floor. There is no smaller in-protocol prove config: security cannot go below 80 (it is the lowest measured parameter, and the thesis pins λ=80 for Cell 1/2/3), and there is no shard knob to shrink. | **An OOM or timeout here is the as-is RISC0 CreGen-prove frontier.** Record it as such. |

Explicitly **off the ladder** (do not step to these to "rescue" a run):
- **Do not raise to `BDEC_HOST_SECURITY=128.`** The CLAUDE.md parameter rationale pins
  λ=80 because Cell 1 already does not terminate at λ=80; 128 worsens the time/memory
  ceiling. Raising it would invalidate the cross-cell comparison.
- **Do not switch to `succinct`** — that is the path that already failed at 15.6 h; this
  whole run exists to route around it.
- **`groth16`** is a *different question* (a pairing wrap that is not post-quantum
  anyway, so it cannot deliver PQ anonymity even on success); it is not a memory-relief
  step for the composite prove and belongs to a separate experiment plan, not this ladder.

Consequence for framing: because the floor is the anchor, there is no "the student
didn't tune" gap to attack. The adaptation that *exists* (recursion-free composite vs.
the failed succinct) is the lever, and it is pulled. A floor failure is therefore a
property of the RISC0 stack at this workload on 24 GB, recorded as a frontier.

---

## Watch and log

Composite is a long run (estimate: succinct burned 15.6 h *without finishing*; composite
is 2–3× slower per phase, so plan for a multi-hour-to-overnight window and gate it with
the hard budget below, not with optimism).

Live monitor in a second terminal, sampling at 60 s (matches the cadence of the prior
run's watcher trace so the two are comparable):

```
RUN_DIR="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/risc0_cregen_composite_<stamp>"
PID=$(pgrep -f bdec_credgen_plum_host | head -1)
while kill -0 "$PID" 2>/dev/null; do
  ts=$(date +%s)
  rss_kb=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
  cpu=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ')
  free_pct=$(vm_stat | awk '/Pages free/{f=$3} /Pages active/{a=$3} END{gsub(/\./,"",f); gsub(/\./,"",a); printf "%.0f", 100*f/(f+a)}')
  printf '%s rss_mb=%s cpu_pct=%s kfree_pct=%s\n' "$ts" "$((rss_kb/1024))" "$cpu" "$free_pct" \
    | tee -a "$RUN_DIR/prove_watch.log"
  sleep 60
done
```

Metrics to capture:
- **Peak RSS (MB and % of 24 GB)** — from the live `ps` trace and from `/usr/bin/time -l`
  ("maximum resident set size") at exit. The succinct run peaked at 11.24 GB (≈47%);
  composite's larger non-recursive proof is expected higher — the watch number tells us
  *how much* higher and whether it approaches the ~85–90% danger zone where macOS starts
  killing.
- **Wall time** — `prove_ms` in the host's final `println!` (line 306) on success;
  otherwise the elapsed wall from the watch trace at the panic/kill.
- **Kernel free %** — early-warning for OOM. Sustained drop below ~10% means an imminent
  kill; that is the abort trigger (below), recorded as the memory-frontier datum.
- **`total_cycles`** — host prints it (line 311); should match the 9.4×10⁹ execute-mode
  figure. RISC0 has no shard/segment knobs and the host does not surface a segment count,
  so segment count is **not** a watch metric here (unlike SP1).

Log paths (house style — one directory per run under `docs/measurements/`):
- Driver log: `docs/measurements/risc0_cregen_composite_<stamp>/bdec_credgen_composite.log`
- Watcher trace: `docs/measurements/risc0_cregen_composite_<stamp>/prove_watch.log`

(There is already a `risc0_cregen_composite_20260531_1553` directory under
`docs/measurements/` — use a fresh timestamp so this attempt does not clobber it.)

---

## Success / partial / abort criteria

**Hard time budget: 12 h wall clock.** Rationale: the succinct path ran 15.6 h and
failed; a composite run that has not produced a receipt by 12 h is on the same
no-completion trajectory and a second multi-hour gamble is not warranted without a
structural reason to expect completion. The budget is set *before* the run so a gamble
cannot quietly eat days. If 12 h elapses with no receipt and no panic, **kill it** and
record a timeout (time-frontier datum).

| Verdict | Criterion | Action |
|---|---|---|
| **Success** | Host prints `mode=prove ... both_ok=true` and `receipt.verify` passes (the host already calls it at line 303 before printing). Process exits 0. | Record `prove_ms` → X h, `total_cycles`, peak RSS%. UPGRADE the central claim; fill `tab:bdec`; retire the anomaly. |
| **Partial** | Process is still alive and *making forward progress* (CPU pegged near ~1700%+, RSS stable, kernel free % steady) at 12 h. | Honest partial datum: *"composite prove had not completed at 12 h on M5 Pro 24 GB."* Kill at the 12 h mark; report the lower bound. Do **not** extend without a structural reason. |
| **Abort — OOM** | Kernel free % drops below ~10% sustained, or the process is killed by the OS, or `/usr/bin/time -l` shows RSS at machine ceiling. | Record peak RSS% and elapsed at kill → memory-frontier datum. No tuning lever remains (no shard knobs); this is the as-is RISC0 memory frontier for CreGen prove. |
| **Abort — verifier rejection** | Panic with `verify segment / verification indicates proof is invalid` (or any `prove failed` panic) **without** memory pressure. | Capture the backtrace (`RUST_BACKTRACE=1`). Because composite does no recursion, this is a **recursion-independent** rejection — escalate to debug rerun #3 with `RUST_LOG=risc0_zkvm=debug`. Record as distinct from the succinct segment-composition bug. |
| **Abort — time** | 12 h elapsed, no receipt, no panic, no forward progress. | Kill; record timeout as the time-frontier datum. |

In all four abort cases the outcome is a *characterised* frontier tied to a specific
cause (memory / recursion-independent soundness / time), not an undifferentiated "it
didn't work".

---

## Recording

**`docs/experiments.csv`** — append one row (20 columns, matching the existing header
`experiment_id,workload,signature_scheme,hash,security_level,substrate,precompile,zk_wrap,shard_size,rayon_threads,cycles,execute_wall_ms,prove_wall_ms,prove_wall_human,memory_peak_pct,status,source,measurement_date,notes,discrepancy_flag`). Fill per outcome:

- **On success:**
  ```
  bdec_cregen_plum_risc0_composite_prove,BDEC CreGen (2× plum_verify under shared pk_U),PLUM,Griffin (Fp192 precompile),80,RISC Zero (BabyBear),Griffin-Fp192,none,n/a,n/a,9400000000,65000,<prove_ms>,<X h>,<peak%>,measured,01-risc0-cregen-composite.md,2026-06-08,Composite path (no recursion) routes around the 15.6h succinct segment-composition rejection; receipt.verify passed,none
  ```
- **On OOM / rejection / timeout:** same row with `prove_wall_ms` blank,
  `prove_wall_human=not completed`, `memory_peak_pct=<peak%>`,
  `status=oom` / `status=prove-failed` / `status=timeout`, and `notes` naming the
  specific frontier (e.g. `composite OOM at <peak%> after <elapsed>; RISC0 has no shard knob, as-is memory frontier`, or `recursion-independent verifier rejection — distinct from succinct segment-composition bug`). Set `discrepancy_flag` if the cycle count diverges from 9.4×10⁹.

**Thesis prose, per outcome:**
- **Success** → update **Table `tab:bdec`** with the CreGen-prove wall time + cycles +
  peak RSS, and rewrite the **§evaluation CreGen prove anomaly subsection** to: "succinct
  recursion fails at this scale; the composite path completes in X h." Central claim moves
  from *standalone-verify-only* to *full-CreGen-proves-on-RISC0*.
- **OOM** → §evaluation: add a memory-frontier line (composite trades recursion for
  working-set size; exceeds 24 GB; no shard lever to relieve it).
- **Recursion-independent rejection** → §evaluation: split the anomaly into two findings
  (succinct segment-composition bug *and* a deeper prove obstruction visible under
  composite); queue debug rerun #3.
- **Timeout** → §evaluation: time-frontier line (composite ≥ 12 h without completing,
  consistent with the 15.6 h succinct lower bound); keep the full-lifecycle estimate
  qualitative.

Cross-reference `docs/risc0_prove_failure_finding_20260530.md` (the succinct failure)
from whichever subsection this run updates, so the two RISC0 prove attempts read as one
coherent frontier-mapping arc.

