# Thesis working memory — July 2025 → June 2026

**As of 2026-06-05.** A single chronological spine for the thesis, built from the
Slack origin, the `docs/` evidence ledger, the 2026-05-25 advisor meeting
transcript, and the 2026-06-05 multi-agent audits. Every load-bearing number is
sourced. This is the "where did this come from and where is it now" map; the
scattered per-experiment docs remain authoritative for details.

---

## 0. One-paragraph state

The thesis asks whether a **general-purpose zkVM** can carry a **post-quantum
anonymous credential (BDEC, instantiated with PLUM)** without the rigidity of a
static SNARK circuit — and at what cost. The verified answer so far: a custom
**Griffin-Fp192 precompile** is what makes a single PLUM verification provable at
all (DNF → 32.5 min), but on a 24 GB personal machine **no configuration is
simultaneously flexible, post-quantum-anonymous, and feasible**: the
zero-knowledge wrap both OOMs *and*, being pairing-based, forfeits PQ anonymity;
the full credential relation does not prove (CreGen prove rejected at 15.6 h).
The contribution is the **quantified trade-off + the PQ-anonymity dual
obstruction**, framed as Sako endorsed (problem → asset → measure the cost), not
a speedup. The honest open risk is whether the precompile AIR is *sound*.

---

## 1. Origin — July/Aug 2025 (Slack, sako-lab `#discuss-mthesis-2025`)

- **2025-07-25 / 07-28:** research-plan draft to Sako. Plan = (1) implement
  Loquat/BDEC verification as a general-purpose program; (2) run inside an
  existing zkVM (Jolt / RISC Zero); (3) **analyze performance to understand the
  trade-offs.** Tsutsumi's steer: custom precompiles are faster, but start with
  an existing zkVM.
- **2025-08-02 (Sako, verbatim):** *"Besides zkVMs (as they are not really
  zero-knowledge) can you … find … viable compilers that output a SNARK circuit,
  and add it into your plan? … real zero-knowledge zkVMs may exist, but it may be
  too slow."* → The plan became a **two-environment comparison**: zkVM **vs**
  SNARK-circuit compiler, on **ZK-property AND performance**. Plan stamped Aug 3.
- Significance: the trade-off framing and the zkVM-not-ZK problem were in the
  plan from day one. Detail in memory `[[thesis-origin-july2025-slack]]`.

## 2. Build-out — autumn 2025 → spring 2026

- Implemented Loquat, then PLUM (similar structure; PLUM cheaper to verify,
  smaller constraints; same Legendre/power-residue PRF family).
- Pulled RISC Zero + SP1 official repos; added custom precompiles (Griffin
  Fp192, 192-bit modmul, power-residue PRF). Aurora (libiop) retained as the
  static-circuit / in-SNARK reference.
- **2026-04-21:** M2 progress report introduces the **"Agility Tax"** framing
  (zkVM flexibility paid for in emulation overhead).

## 3. The measurement burst — 2026-05-20 → 05-22 (SP1, M5 Pro 24 GB)

Four-scheme structural picture (`docs/four_scheme_benchmark.md`, `experiments.csv`):

| Workload | Execute cycles | Prove wall |
|---|---|---|
| ECDSA-secp256k1 (classical anchor) | 113,871 | 13.6 s |
| PLUM-80 Cell 1 (Griffin, NO precompile) | 7.08e9 | **DNF** (~30 h proj.) |
| PLUM-80 Cell 2 (Griffin + precompile) | 125.5e6 | **32.5 min** |
| PLUM-80 Cell 3 (SHA-3 control) | 110.8e6 | **13.3 min** |
| Loquat λ=128 (software Griffin) | 518e6 | n/m |

- Precompile recovers feasibility: Cell 1 DNF → Cell 2 32.5 min (**56.4×** cycle
  cut). **But Cell 2 is 1.13× SLOWER in cycles than the software SHA-3 control
  (Cell 3)** — a top-tier reviewer's "why build the chip?" question.

## 4. Advisor reframe — 2026-05-25 (the meeting; `meetings/2026-05-25-sako/`)

> NOTE: the `Downloads/2026-research-meeting-zoom-recording.mp4` file is
> **byte-identical** (MD5 `f2a014…94c5`) to this meeting's recording — it is the
> May 25 meeting, not a later one. No advisor meeting after 2026-05-25 is on
> record as of 2026-06-05.

Sako's verified asks (transcript-cited; `[[sako-2026-05-25-meeting-verified-content]]`):
- Drop "ZK-SNARK-friendly" as a term [34:36]. Frame as **BDEC rigidity problem →
  is zkVM an asset → fix PLUM, measure the cost** [34:47–35:40].
- The OOM is **"a finding, not a failure"** — write it [36:39].
- **Measure** the static recompile cost per φ and **compare** to the zkVM [10:39,
  17:17]; write the φ predicates formally [16:00, 23:15].
- Confirm RISC0/SP1 are actually zero-knowledge [32:06].
- Curation skepticism [42:27, verbatim]: *"Was it a very special setting … to
  make your result faster? Or is it plausible?"*
- Limit to 1–2 zkVMs; no new-zkVM experiments; concentrate on findings [37:48,
  41:54]. Closing: **"Sounds good"** [44:41].

## 5. Toward end-to-end — 2026-05-26 → 06-04 (BDEC integration + frontier)

- **05-26:** ZK-wrap attempts — Groth16 ×2, PLONK ×1, all **OOM ~20 GB** on 24 GB
  (`experiments.csv`). ZK (=anonymity) is not 24-GB-tractable; and the wrap is
  pairing-based ⇒ forfeits PQ anonymity even with infinite RAM (dual obstruction).
- **05-29:** PLUM-in-BDEC **CreGen** (2 Sig.Verify under hidden pk_U; paper-faithful)
  runs in **execute** mode: 9.4e9 cyc, 65 s (`plum_in_bdec_blocker…`).
- **05-30:** CreGen **prove** = internal-verifier **REJECTION** at **15.6 h**
  (NOT OOM; peak RSS 11.2 GB), root cause undetermined. Candidate cause (iii) =
  precompile trace malformed across a segment boundary ⇒ **would imply the Griffin
  AIR is unsound** (`risc0_prove_failure_finding_20260530.md`).
- **05-31:** composite re-run reached 2,452/9,936 segments → measured **43.5
  s/segment** → CreGen composite prove ≈ **5 days** extrapolated
  (`pc_prove_extrapolation.md`). Also: security chapter (assumptions ledger
  A1–A8, conditional preservation theorem), 12 TikZ figures, genre reframe
  (measurement crypto, not scheme-design).
- **06-02:** **ShowCre** (the φ-bearing relation) implemented + execute-measured:
  k=1 = 1.41e10 cyc, k=2 = 1.88e10 cyc, validates additive (k+2)·C_ver model to
  <2% (`docs/measurements/showcre_execute_20260602/`). **Never proven.**
- **~06-04:** Boundless (outsourced) export built + executor-validated for
  plum-verify and cregen; **not yet submitted** (`boundless_setup.md`).

## 6. Current verified state (2026-06-05) — corrections to earlier claims

From the 2026-06-05 adversarial panel (verified against disk):
- **ShowCre IS implemented and execute-measured** (earlier "unbuilt" was wrong);
  it is just never *proven*.
- **φ is checked outside the proof** (cleartext selective disclosure by the
  relying party), not as an in-circuit ZK predicate over hidden attributes. The
  real anon-cred weakness: this is selective *disclosure*, not predicate ZK
  (unlike Coconut/BBS+).
- **CreGen prove is n=2**, not a bare n=1 "didn't terminate."
- The **precompile-loses-to-SHA-3** result (1.13×) is the real top-venue threat,
  not the trilemma slogan.
- **Sharpest risk:** the CreGen rejection's cause (iii) would make the Griffin
  AIR unsound — and the run used to dismiss it (single PLUM-verify proves on
  RISC0, 6h19m) uses `sys_bigint`/**software** Griffin, NOT the precompile, so it
  cannot discriminate. Cheap fix: prove single PLUM-verify *with* the precompile,
  and/or run CreGen on SP1.

## 7. The honest two-sided thesis (converged from 3 independent sources)

The July-2025 plan, Sako's May-2025 reframe, and the 2026-06-05 audit all
converge: **zkVM (programmable / flexible, but ZK-feasible only off-PC and not
PQ-anonymous under the cheap wrap) vs SNARK-circuit / Aurora (zero-knowledge at
the IOP level, but rigid / recompile-per-φ).** Defensible headline:

> *Moving a PLUM-instantiated BDEC credential from a relation-specific zkSNARK
> into a general-purpose zkVM eliminates recompilation churn on a signature/λ/
> structure change, and a custom Griffin-Fp192 precompile makes a single
> verification provable at all (DNF → 32.5 min); but on a 24 GB personal machine
> the construction cannot be simultaneously flexible, post-quantum-anonymous, and
> feasible — the ZK wrap both exceeds memory and, being pairing-based, forfeits PQ
> anonymity. The contribution is locating and quantifying that trade-off, not a
> speedup.*

## 8. Open threads / decisions (2026-06-05)

- **DECIDED:** Boundless testnet (smallest-first) to obtain one real Groth16 ZK
  receipt as existence-proof, keeping the PC-infeasibility as the headline.
- **Defense bar:** likely-pass under Sako's framing, *conditional on root-causing
  the CreGen rejection* (the soundness discriminator above).
- **Top-tier bar:** reject-but-salvageable; 2 months buys reject→borderline.
  Highest-value missing measurement = **R_static** (per-φ recompile wall-clock),
  the unmeasured denominator of the crossover.
- **Literature gaps under audit (workflow 2026-06-05):** real-ZK of zkVMs;
  S-two/Circle-STARK "precompiles may be obsolete" (28–39× claim); folding/NIVC
  as a precompile alternative; Arguzz soundness-bug taxonomy; small-field
  soundness (Fenzi–Sanso); compiler blindness.

## Sources
`docs/`: four_scheme_benchmark.md, experiments.csv, discrepancies.csv,
sako_reframe_recovery_20260529.md, plum_in_bdec_blocker_20260529.md,
plum_in_bdec_integration_plan_20260529.md, risc0_prove_failure_finding_20260530.md,
pc_prove_extrapolation.md, bdec_plum_risc0_cost_calculation_20260529.md,
boundless_setup.md, measurements/showcre_execute_20260602/.
`meetings/2026-05-25-sako/transcript_timed.txt`. Memory:
`[[thesis-origin-july2025-slack]]`, `[[sako-2026-05-25-meeting-verified-content]]`,
`[[plum-paper-and-prime-substitution]]`. NotebookLM: "Flexibility of PQ Anonymous
Credentials" (212 sources). 2026-06-05 panels: survival audit + zkVM-literature
gap audit.
