# Defense pivot plan (2026-06-05)

Output of the strict defense-jury workflow (`wo1680720`: crypto-expert, smart-work,
Sako-philosophy, senior-angle research, math-leverage → chair integration). It verified
every in-thesis line-number against source.

**Provenance caveat carried forward:** every EXTERNAL citation here (CAPSS 2025/061,
Policharla 2023/414, Pegasus 2025/1841, Arguzz 2509.10819, SoK:zkVM 2026/525, Zirgen
bigint dialect, Kota, Argo 2024/131, CertiPlonk, FreeLunch 2024/347) is **UNVERIFIED**
(eprint 403'd the fetch tool). Confirm against the primary PDF before any enters the thesis.

## Key reorientation
The honest reframe is **already in the prose** (Tier-1 edits landed): T2 is an explicit
"unverified premise" (055 L116-119); the theorem is "conditional" (055 L112); the
execute-mode lemma is hedged to "program level" (055 L97-99); FMT shares units (04 L26);
the churn table says N_circ≥1 for the shipped AIR (04 L83); the conclusion concedes "No
BDEC relation has been successfully proven" (08 L27). **What is missing is the MATH and ONE
measurement.** That gap is what the non-crypto professors smell as "not working smart."

## What sinks the defense today (ranked)
1. **The decision axis is never measured.** The crossover rule (06 eq:crossover, L427-445)
   fixes every sign, but R_static (per-change recompile cost) "is not yet isolated" (06 L429).
   The one experiment that answers the thesis question, specified months ago, has no number.
2. **No BDEC relation was ever proven** (CreGen rejected ≥15.6h; ShowCre execute-only); the
   title-level question is unanswered in prove mode.
3. **The one theorem hangs on T2, and the CreGen rejection leans against it** (same relation,
   silent-acceptance direction untested, 055 L203-208).
4. **The flagship loses to the trivial baseline** (precompile 2.45× slower in prove-wall than
   software SHA-3) — and Cell 3's λ=80 is still unconfirmed (06 L113 dagger); if λ differs the
   inversion is void.
5. **The "not smart" signature**: CLAUDE.md still promises 10×; the contribution list
   apologizes for the abandoned goal; losses are measured, the one win (flexibility) is asserted.

## The non-diluting pivot (one move)
Reframe from "we built a precompile and measured its cost" to: **"we built a formal cost
model of the field-mismatch tax, derived from it the falsifiable prediction that a custom
algebraic-hash chip should beat standard-hash emulation, designed the SHA-3 control to
falsify it, and it falsified — then closed the one premise (AIR soundness) the security
claim hangs on."** Same artifacts, same data; the negative result becomes the **target the
work aimed at**, not wreckage. Routes through the MATH strength: (a) the AIR
soundness/rejection proof, (b) the cost model + crossover as a derived prediction. Drops the
broad claims (speedup, methodology generalization, novel conjunction).

## Senior's generalize-the-precompile angle: TRAP as a spine; PARTIAL as one section
Of the six PQ-primitive classes, exactly **one** (large-prime AO-hash over a ~199-bit
application prime) is both unoccupied and cost-justified, and the thesis owns it at n=1. The
others are pre-empted: bigint/mod-exp by **Zirgen's bigint MLIR dialect [UNVERIFIED]**;
lattice-NTT by **Kota's SP1 gadget [UNVERIFIED]**; the "generic AO-permutation → PQ-sig →
anon-cred methodology" move is the exact claim of **CAPSS 2025/061 [UNVERIFIED]** (same
Griffin/Anemoi family, same application). Generalizing from one unverified chip with no
second chip in 2 months is the broad-shallow trap + a goal-jumping relapse. **Your "do not
force" instinct was correct.** Strongest defensible PARTIAL form: a bounded **"precompile-gap
map"** (a verified-negative map of which PQ-credential primitives already have zkVM coverage
vs not, justifying why this thesis attacked exactly the large-prime AO-hash slot) + one
future-work sentence. Days of work, leverages the cost decomposition, reads as insight.

## Cleaned goal (Sako A→B form)
- **Purpose (A→B):** decide whether a general-purpose zkVM is a viable substrate for a PQ
  anonymous credential whose signature uses a large-prime algebraic hash, and quantify the
  cost of that choice on consumer hardware.
- **Means (C→D):** replace the relation-specific transparent zkSNARK (C) with a zkVM whose
  universal relation late-binds the signature, predicate, and parameters as runtime guest
  data (D), using the Griffin-Fp192 precompile as the *instrument* that makes the dominant
  cost finite enough to measure — explicitly testing whether C and D compute the same
  predicate (the AIR-soundness premise) and on which axis (deployment-lifetime cost under
  predicate churn) D can win.

## Cleaned contribution list (ranked; tag; required citation to survive)
1. **[MATH] Griffin-Fp192 AIR soundness — the rejection/malicious-prover direction, T2 resolved.**
   Deepest thing you own; the security chapter's load-bearing premise. Cite ethSTARK,
   cairoverify (in appendix); Arguzz 2509.10819 [UNVERIFIED] (silent-acceptance is where real
   zkVM soundness bugs live); CertiPlonk [UNVERIFIED] (SP1 *is* Plonky3 → constraint-level
   verification is reachable). Theorem if T2 closed; measured finding if the fault-injection
   campaign is thorough.
2. **[MEASUREMENT] The amortization (update-churn) crossover, quantified.** The only axis the
   zkVM wins, unpublished across all six families. Cite SoK:zkVM 2026/525 [UNVERIFIED] (owns
   the mechanism; you own the quantification); Policharla 2023/414 [UNVERIFIED] (the
   hand-rolled-per-relation rival your crossover rebuts).
3. **[MEASUREMENT] The SHA-3-beats-precompile inversion, as a falsified prediction.** Void
   unless Cell 3 λ=80 confirmed (06 L113).
4. **[MEASUREMENT] The dual ZK/PQ obstruction, as a measured toolchain-instantiation.** Drop
   "novel conjunction"; keep "first *measured* for the deployed RISC0/SP1 pipeline."
5. **[ARTIFACT] The audited Griffin-Fp192 AIR as a negative-space existence result** (first
   AO-hash AIR over a ~199-bit application prime in any zkVM). Downgraded from "proved-sound."

**CUT:** precompile-as-speedup; the methodology generalization as a contribution; "novel
conjunction"; "first prove-mode costs for BDEC"; FMT as a central conceptual contribution.

## Evaluation metrics that follow
**Must-have for defense:**
- **R_static** — wall-clock per localized recompile (swap φ; λ 80→128; k 1→2) on the in-repo
  Noir/Aurora BDEC circuit → supports C2. **UNRUN, load-bearing, do first.**
- **Crossover n\*** (shows-per-φ-change), closed-form in measured constants → follows from R_static.
- **AIR rejection rate on malformed Griffin traces** (does the AIR REJECT?) → supports C1 (T2).
  **UNRUN, math-track, highest value.**
- **Cell 3 λ confirmation** → C3 inversion is void without it.
- **Per-phase decomposition of the 32.5 min** → explains the loss to SHA-3.
- (Done: cycles, prove-wall, peak-RSS, proof size; the 24 GB wrap-OOM frontier.)

**Reach (only if cheap):** Cell 4 (Aurora over Fp192, the native-prover endpoint) — do NOT
let it displace R_static or T2; CertiPlonk/Arguzz machine-check (upgrades C1 to theorem); one
ZK-wrapped proof on ≥64 GB/Boundless.

**CUT as forced:** the 37M trace-cell (off ~76×: 33×14×1052 = 486,024 — recompute); FMT as a
headline metric; the 91% as a zkVM-cycle/Amdahl claim (it's an R1CS ratio; you have the
syscall count 1052 — measure the real share); the Fp127/107.5-bit static datum bundled with
the 31-bit small-field floor (different objects; the floor hits ε_KS, not anonymity).

## Smart-work narrative (defense voice)
> "I started by asking the wrong question, can a custom chip make this fast, and the right
> move turned out to be building the cost model first. The model predicts a bespoke
> algebraic-hash precompile over the signature's 199-bit prime should beat emulating a
> standard hash; I built the SHA-3 control as the experiment to falsify that prediction, and
> it falsified it, the bespoke chip is 2.45× slower in prove wall-clock. That is the first
> finding, and it inverts the folk assumption. The second is sharper than any timing number:
> on the deployed RISC0/SP1 pipeline the proof that is feasible on 24 GB is not anonymous, and
> the proof that would be anonymous either exhausts memory or is pairing-based and forfeits the
> post-quantum guarantee, and I measured that frontier rather than asserting it. The third is
> where my work is hardest to dispute: the security of the whole construction rests on one
> premise, that my AIR rejects a malformed Griffin trace, and my own CreGen prove rejection
> sits on that exact fault line, so I treated it not as a bug to hide but as the question to
> answer. The one axis a zkVM actually wins is crypto-agility under predicate churn, so that is
> the one crossover I measured. I am not claiming a zkVM makes this cheap; I am showing, with
> measurements and a soundness argument rather than a speedup, exactly where the cost lives and
> where, on a personal machine, anonymity and the memory budget collide."

## 2-month to-do (ranked; track-tagged; ★ = load-bearing)
**Week 1 — WRITING (huge payoff, low effort):**
1. ★ Finish framing: theorem fully Conjecture-modulo-T2; CreGen rejection stated as evidence
   *against T2* (silent-acceptance direction), not a separate anomaly (finish in 08 + abstract).
2. ★ Fix C2 first-ness overclaim (08 L25); add the negative-survey paragraph; resolve the
   01 L38 / 08 TODOs.
3. Promote the SHA-3 inversion into 01/08; demote FMT to a cost-accounting frame.
4. Kill cheap credibility-killers: recompute the 37M trace-cell; standardize 199-bit naming;
   Aurora "polylogarithmic"→**linear verifier** (03-prelim L323); λ-label every figure; update
   CLAUDE.md to drop the dead 10× promise.

**Weeks 2-5 — the decisive runs (parallel):**
5. ★ **Measure R_static** (in-repo Noir/Aurora circuit, N recompiles) — single highest-payoff run.
6. ★ **Confirm Cell 3 λ=80** (06 L113 dagger) — cheap; the inversion dies without it.
7. ★ **Fault-injection on the Griffin-Fp192 AIR** (feed malformed traces, confirm it REJECTS) —
   the T2 gap; math-strength falsifiability, not benchmarking.
8. Per-phase decomposition of the 32.5 min.

**Weeks 6-8 — math depth:**
9. ★ Tighten the AIR soundness argument (appendices skeleton + gcd(3,p-1)=1) into the rejection
   direction; machine-check via CertiPlonk [UNVERIFIED] if time → upgrades C1 to a theorem.
10. Resolve the CreGen rejection cause (single PLUM-verify prove *with* the precompile is the
    missing discriminator) — closes the rejection box and the T2 box together.
11. Resolve the QROM hedge with Pegasus 2025/1841 [UNVERIFIED]; state Griffin RO-replaceability
    at d=3/t=4/14-round as the live open question.
12. The one-paragraph precompile-gap map (the senior angle's only non-diluting form); Cell 4 only if cheap.

**Do NOT:** build a second chip; pursue the methodology generalization as a contribution; chase
the BDEC prove to completion as a feasibility claim; attempt Cell 4 + ZK-wrap + CreGen +
fault-injection all at once (that IS the goal-jumping failure mode).

## Companions
`docs/thesis_landscape_realignment_20260605.md`, `docs/thesis_revision_audit_20260605.md`,
`docs/thesis_journey_2025-07_to_2026-06.md`. Memory `[[thesis-precompile-framing-forced]]`.
