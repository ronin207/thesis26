# Thesis Completion Workflow — everything remaining
*Honest, exhaustive inventory + sequenced plan. ~7 weeks to the end-July deadline. Genre-B (measurement) crypto.*

## Was the earlier "Worth doing" list complete? No.
It covered only the **closing measurements** (≈ one-third of the work). The larger remaining effort is **writing/reframing** (folding in the R_static finding, fixing the contribution headline, the security hypothesis) and the **honest disposition of open claims**. The deck is last.

## Hard truth: "met" vs "scoped"
Not every unconfirmed claim can be *met* in 7 weeks. Two are separate research efforts (constraint-level Griffin-AIR equivalence; Griffin QROM-replaceability). The honest move for those is to **state them as explicit conditional assumptions** — which the thesis already does — **not to chase them**. Measurement crypto permits *stated* open assumptions; it forbids *silent* ones. Chasing the unprovable is the goal-jump trap.

---

## DONE — do not redo
- Recompile cost **measured**: R_static ≈ 0.3 s (Aurora param-setup = 4 µs) → the wall-clock rigidity/flexibility advantage is **refuted**.
- ShowCre **implemented** (RISC0 + SP1) + execute-measured (k = 1, 2); additive model validated.
- SP1 BDEC CreGen/ShowCre **with vs without** Griffin precompile (~58×, same-platform clean isolation).
- Coherence fractures fixed: F1 (P1–P5 scorecard), F2 (ShowCre "not built"), F8 (dangling A-labels). Thesis compiles clean.
- φ predicates formal (§3); A7 prime caveat written; CreGen relation made paper-exact; Aurora baseline measured; §055 security + appendix structure; story-coherence audit (`story-coherence-audit.md`).

---

## PHASE 1 — REFRAME (writing only, NO new data) ← do first; this is the coherent spine
| # | Task | Addresses | Effort | Dep |
|---|---|---|---|---|
| 1.0 | **Finalize headline + title** (drop "flexibility"; e.g. (b) cost-architecture study or (d) "cost of generality") | F6 | decision | you |
| 1.1 | Propagate the chosen headline to §1 contributions, §4.1 (stop calling churn "the central conceptual contribution"), §7.2, §8 | F6 | 0.5 d | 1.0 |
| 1.2 | Fold R_static: **delete the wall-clock crossover** (§6.5.3); reframe §7.1 decision rule to **operational/audit-surface**, not speed | the finding | 0.5 d | — |
| 1.3 | Write the **SP1 BDEC ~58%** (same-platform with/without precompile) into §6 | new data | 0.5 d | — |
| 1.4 | Add the **signature-simulatability hypothesis** to the §055 anonymity bound (rests on Loquat HVZK) | F7 (security) | 0.5 d | — |
| 1.5 | State the **cross-scheme seam** (Loquat-Aurora vs PLUM-zkVM) explicitly in §6 | F4 | 0.25 d | — |
| 1.6 | Align **abstract + intro** to the honest contribution (cost-architecture + corrected assumptions + the tension) | coherence | 0.5 d | 1.0–1.5 |

## PHASE 2 — CLOSING MEASUREMENTS (targeted; days, not a sweep)
| # | Task | Why | Effort |
|---|---|---|---|
| 2.1 | **Per-component cycle attribution** (Griffin vs FFT/sumcheck vs PRF vs rest), one λ, execute-mode | THIS is the "architecture study" — where the cost lives | ~1 d |
| 2.2 | **λ-consistency**: redo attribution at λ=80 so prove + attribution stop straddling 80/128 | close the seam | 0.5 d |
| 2.3 | **Variance**: ≥3 runs of Aurora-prove + SP1 single-verify-prove (error bars) | kill single-run weakness | 0.5 d wall |
| 2.4 | **Nail the headline number**: exact + labeled (precompile-on-PLUM, single-verify, *execute-cycle ratio*, NOT BDEC, NOT wall-clock) | Sako number-hygiene | 0.25 d |
| 2.5 | **Proof size**: state ~260 B Groth16 / ~868 B PLONK as the documented constant (the wrap OOMs, so not produced here) | honesty | 0.25 d |

## PHASE 3 — CONFIRM-OR-SCOPE (honest disposition)
| # | Claim | Disposition | Effort |
|---|---|---|---|
| 3.1 | RISC0/SP1 zero-knowledge (Sako [32:06]) | **Confirm + cite**: base STARK ≠ ZK (SP1 docs); ZK only via wrap; Haböck–Al Kindi 2024/1037 + RISC0 advisory | 0.25 d |
| 3.2 | CreGen-prove anomaly (15.6 h internal-verifier rejection) | **Check** the launched diagnostic; classify transient vs reproducible; else keep quarantined ("no claim rests on it") | check now |
| 3.3 | A4 — Griffin chip ≡ constraint system (constraint level) | **SCOPE as open** (separate project); keep 256-vector empirical support + explicit premise | scope |
| 3.4 | A6 — Griffin QROM-replaceability (this d=3 / w=4 / 199-bit / 14-round instance) | **SCOPE as open** (literature-dependent upstream assumption) | scope |
| 3.5 | Commit `x_cre` to the CreGen receipt (binds proof to the instance) | **Small fix** if time; else note as refinement | 0.5 d / scope |
| 3.6 | PLUM-in-Aurora same-scheme static point | **Out of scope** — state the seam (done in 1.5) | — |

## PHASE 4 — POLISH
- Scrub remaining "**SNARK-friendly**" usages in §3/§4 (Sako [34:31] rejected the term).
- **Bib** completion: Jeudy 2022/509, BCS transform, CL/Coconut/BBS, RISC0-v2 (35 min→44 s), Automata RSA.
- Wire the **12 TikZ figures** into the body (`\includegraphics`; currently 0).
- **Threats-to-validity + settings-justification**: every number labeled (λ, mode, status) — Sako [42:27]. (Mostly done; verify.)
- Repro-artifact citation (`[NEEDS DATA]` markers in §6).
- *(If time)* the explicit unforgeability **reduction 𝓑** (extractor→forger) in §055.

## PHASE 5 — DECK
- Realign `draft.pptx` onto the honest spine: PLUM (not Loquat), Griffin precompile, measured numbers, "one ZK proof of the k+2 conjunction under hidden pk_U," operational-not-wall-clock rigidity, the anonymity-feasibility tension. **Depends on Phase 1.**

---

## The one discipline (the [21:49] "goal jumps around" antidote)
- **Phase 1 is writing, and it's the priority** — it makes the thesis cohere and is most of what Sako reads.
- **Phases 2–3 are days, not weeks** — targeted closures, not an open benchmark sweep.
- **Do not chase A4 / A6** — scope them. They are separate research projects; a stated open assumption is honest and sufficient here.
- Order: **Phase 1 → Phase 2 → dispose Phase 3 → Phase 4 → Phase 5.** Do not let "I need more benchmarks" defer Phase 1.
- Rough budget: ~2–3 focused weeks of work inside the 7, leaving buffer for Sako feedback and revisions.
