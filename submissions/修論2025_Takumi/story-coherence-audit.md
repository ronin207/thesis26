# Thesis Story-Coherence Audit
*A cryptographic-researcher read of the draft, section by section — does the story connect?*
*Audited: 01-intro → 02-related → 03-preliminaries → 04-theoretical → 05-system → 055-security → 06-evaluation → 07-discussion → 08-conclusion → appendices (main.tex order).*

---

## TL;DR verdict

**The spine exists and is sound.** There is a real, single through-line:

> Rigidity is the hidden cost of static-circuit PQ anon-creds (§1.3) → a zkVM escapes it but pays a *field-mismatch tax* (§1.4, §4.2) → a precompile absorbs the tax so the cost becomes *measurable* (§4, §5) → we measure it (§6) and find (a) feasible-but-bounded cost dominated by the algebraic hash, (b) an anonymity-vs-feasibility collision (§055-security, §6) → the two sides combine into a *substrate-selection rule* keyed on churn rate (§6.5.3, §7).

**Why it nonetheless reads as disconnected.** The spine is fractured at **three concrete joints**, and the *contribution* is declared in **three incompatible ways**. A reader cannot see the connection because the connective claims are, variously, *dangling* (a scorecard that grades deleted predictions), *contradictory* (the construction section says a thing is unbuilt that the evaluation section measures), and *numerically empty at the climax* (the decision rule's crossover is never located, and its two sides are different signature schemes). None of these is fatal; all are fixable. Ranked fixes are at the end.

---

## The intended through-line (state it once, explicitly — the thesis never does)

| Step | Section | The claim it must hand forward |
|---|---|---|
| **A. Problem** | §1.3 | Static circuits are *rigid*: any relation change forces recompile ("update churn"). |
| **B. Candidate** | §1.4 | A zkVM removes rigidity (relation = fixed ISA) but pays a *field-mismatch tax*. |
| **C. Question** | §4.1 | Is a zkVM a *viable substrate* for PQ-anon-creds on consumer HW, and at what cost? |
| **D. Instrument** | §4.2, §5 | A Griffin-Fp192 precompile absorbs the tax so the residual cost is *measurable*. |
| **E. Answer (cost)** | §6 | Feasible-but-bounded; cost ≈ the algebraic hash; ZK-wrap exceeds 24 GB. |
| **F. Answer (security)** | §055 | Substitution preserves BDEC's guarantees; anonymity collides with the resource frontier. |
| **G. Decision** | §6.5.3, §7 | Choose substrate by churn rate `(U/P)*` — the crossover. |

Everything in the thesis is *on* this spine. The failures are at the **baton-passes between steps**, audited next.

---

## Section-by-section: does the baton land?

### §1 Introduction — **strong; the best-connected section.**
- **In:** —. **Out:** the rigidity problem (A), the zkVM candidate (B), the 5 contributions.
- **Lands?** Mostly yes. §1.3 (rigidity) → §1.4 (zkVM + tax) → contributions is a clean arc.
- **Crack:** Contribution 1 states ShowCre "realise[d] … as a k+2-verification guest and measure[d] it in execute mode (1.41×10¹⁰ at k=1 …)." **This commits the intro to a claim that §5 later denies** (see §5 below). The intro is *ahead* of the construction section.
- **Crack:** The five contributions silently span **three different headlines** — (1)/(2)/(4) = *quantification*, (3) = *update churn as the conceptual contribution*, and the closing ¶ = *the anonymity-feasibility finding*. The intro never says which is **the** thesis. (See Fracture F6.)

### §2 Related Work — **coherent; sets up the "gap" cleanly.**
- **Out:** the five strands → the unmeasured dimension (update churn) + the unmeasured frontier. §2.6 names the gap the thesis fills.
- **Lands?** Yes. The one thing to verify: §2 promises *two* omissions (predicate-change cost **and** the consumer-HW frontier); make sure §6 pays back *both* explicitly (it does, but the frontier payback is buried in §6.5.2).

### §3 Preliminaries — **complete and careful, but it is two prelims welded together.**
- It defines Loquat **and** PLUM, Aurora **and** zkVM, the full BDEC construction (CreGen/ShowCre relations — excellent, this is the asset the deck should reuse), and update churn.
- **Crack (the Loquat/PLUM seam starts here):** Loquat is defined in full (§3.2.3) *and* PLUM (§3.2.4), and the thesis keeps both alive. Per your own framing ("Loquat is retained only as historical reference"), Loquat's presence here sets up an expectation of a Loquat result that never comes in the zkVM — yet Loquat *does* reappear as the **static baseline** (§6.3). So the reader meets two schemes and cannot tell which is the protagonist. This is the root of F4.
- **Good:** §3.5's "receipt structure and ZK property" paragraph already plants the ZK-only-from-wrap point that §055 and §6 pay off. Clean setup→payoff.

### §4 Theoretical Foundations — **the cost framework is good; but this section is the origin of the worst fracture.**
- **Out:** four cost dimensions, the field-mismatch-tax definition, update-churn definition, the CreGen/ShowCre cost decomposition.
- **FRACTURE F1 (dangling predictions).** §4 **no longer contains a numbered "Predictions P1–P5" list** (it was removed). But **§6.6 is titled "Evaluation Against the Predictions … P1–P5" and scores P1, P2, P3, P4, P5 one by one**, and §6.5.2/§6.5.3 reference "prediction P5." *A reader who reaches §6.6 and flips back to §4 to find P1 finds nothing.* This is the single most jarring broken connection in the thesis: an entire scorecard grading a list that does not exist. (The **deck still has the P1/P2 framing** in its notes — so the predictions live on in two downstream places while their definition was deleted upstream.)
- **Crack:** §4.2 leans on "PLUM §4.2 reports 91% of R1CS constraints are hash" — and §6.4 then *correctly cautions not to transfer that 91% to the cycle model*. Good that §6 corrects it, but §4 introduces the 91% as if load-bearing and §6 walks it back; state the caution **once, in §4**, so the two sections agree on first contact.

### §5 Construction — **STALE; it contradicts §1 and §6.**
- **FRACTURE F2 (construction vs evaluation contradiction).** §5.1 lists, under *"Deliberately not built … treated as future work"*: **"the full BDEC presentation relation (ShowCre) as a zkVM guest."** §5.5 closes with *"integration of the full presentation relation (ShowCre) is left as future work."* But **§1 contribution 1 and §6.5.2 both state ShowCre IS implemented and measured (k=1: 1.41×10¹⁰, k=2: 1.88×10¹⁰).** This is a direct internal contradiction — §5 was written before the ShowCre guest existed and never updated. A careful reader (or examiner) who reads in order is told ShowCre is unbuilt, then sees it measured 40 pages later. **This alone would produce the "things don't connect" feeling.**
- **Consequence for the security/precompile story:** §5.1 also says the bespoke Griffin AIR is **SP1-only** (RISC0 uses `sys_bigint`). That is true and well-stated — but it means "the precompile" is two different things on the two substrates, which §6 then has to disclaim repeatedly. The construction section should foreground this *once* as a deliberate design split (SP1 = the Griffin-precompile instrument; RISC0 = the application substrate), so §6 doesn't read as a string of apologies.
- **Missing:** the **new SP1 BDEC CreGen/ShowCre measurements** (the clean same-platform syscall-vs-emulated ~58× on the actual BDEC relations) are not here at all. §5 stops at "CreGen on RISC0 + PLUM-verify on SP1."

### §055 Security — **structurally strong (threat model + preservation theorem + AIR soundness + honest open premises). Two cracks.**
- **In:** §3 BDEC games + §5 precompile soundness. **Out:** the conditional preservation theorem + the ZK-barrier-as-finding (F in the spine).
- **Lands?** Yes — this is the cryptographic keystone and it connects backward (to §3/§5 hypotheses) and forward (to §6's frontier) well. The ZK-only-from-wrap + non-PQ-pairing tension is genuinely sharp and is the thesis's best single finding.
- **Crack (cryptographic, from the adversarial model):** the **anonymity** bound (`Adv^anon ≤ Adv^anon_BDEC + ε_ZK`) silently assumes the **signature is simulatable**. BDEC's own anonymity proof invokes a *signature simulator* `S_σ` — a non-standard requirement (a plain EU-CMA signature is not ZK); it rests on PLUM inheriting **Loquat's HVZK**. §055 treats only the SNARK's ε_ZK and never states the signature-simulatability hypothesis. This is a genuine missing link in the security spine, not just narrative.
- **Crack (numbering):** the prose references "assumption A7" / "A6" / "A4" (e.g. Remark prime-substitution = "A7", §5 Thm = "A6", AIR = "A4"), but §055 itself folds assumptions into theorem hypotheses rather than an enumerated A1–A10 ledger (per the de-AI rewrite). So **the "A4/A6/A7" labels are now dangling cross-references** to a ledger that was removed — the same failure mode as F1, in miniature. Either restore a small named-assumption table or replace "A7" etc. with prose pointers.

### §6 Evaluation — **rich and honest, but it is where every upstream seam comes due at once.**
- **FRACTURE F1 surfaces here** (scores P1–P5 that §4 no longer defines).
- **FRACTURE F3 / F4 (the comparison never closes same-scheme).** §6.3's Aurora baseline is **Loquat over Fp² (127-bit)**; the zkVM numbers are **PLUM over Fp (199-bit)**. §6.3 itself says "not a same-scheme comparison," §6.5.3 says the crossover can't be numerically located because of it, §6.6/P3 says convergence "not supported … not same-scheme." The thesis is *honest* about this five times — but five disclaimers of the central comparison is precisely what makes a reader feel the two halves never actually meet. **The spine's step E↔G join is hedged into non-existence.**
- **FRACTURE F5 (the climax is numerically empty).** §6.5.3's crossover `(U/P)*` is the thesis's actual thesis — the rule that *fuses* the rigidity motivation (A) with the cost answer (E). But it is "form known, every sign known, number unknown": the per-φ recompile delta is unmeasured (no φ-parameterised emitter) and the two sides are different schemes. So the climax the whole spine builds toward resolves to *"we know the shape of the answer."* That is defensible research, but narratively it means **the two story-halves are joined by a quantity the thesis does not have.**
- **Loose thread:** §6.5.1 CreGen prove **anomaly** (internal-verifier rejection at 15.6 h). Beautifully quarantined ("no claim rests on it") — but it is an unresolved dangling item the reader keeps waiting to see resolved.
- **Missing data:** the new SP1 BDEC CreGen/ShowCre syscall-vs-emulated numbers (~58×, same-platform, the *clean* with/without-precompile contrast on the actual BDEC relations) are not integrated. §6's with/without story currently rests on the **single-verification** 56.4× (§6.4) + the infeasible-to-feasible prove transition — strictly weaker than the BDEC-relation result now available.

### §7 Discussion — **clean; correctly refuses to over-claim.** 
- It restates the decision rule and the security-deployability tension. It inherits F5 (the rule is "directional, not a numeric threshold"). Consistent with §6 — good. It also crowns the anonymity-feasibility tension as "the sharpest finding," which competes with §4.1's "update churn is the central conceptual contribution" → feeds F6.

### §8 Conclusion — **consistent with §6/§7; honest.** Reasserts "quantification, not speedup." Lists future work = exactly the open joints (recompile wall-clock, A4, A6, ShowCre extension). Note: it says ShowCre is "now implemented and measured in execute mode" — **agreeing with §6 and contradicting §5** (confirms §5 is the stale one).

### Appendix (AIR soundness) — **the most rigorous part of the document.** B-1…B-10 family lemmas, completeness, the argument-layer separation, the explicit open premise (chip-vs-constraint). Connects cleanly to §055. Only crack: shares the "A4" dangling-label issue.

---

## Cross-cutting fractures, ranked by damage to the story

| # | Fracture | Where | Severity | Why it breaks the connection |
|---|---|---|---|---|
| **F1** | §6.6 scores predictions **P1–P5** that §4 no longer defines | §4 ↔ §6.6 | **High** | Reader flips back for P1, finds nothing. A scorecard with no rubric. |
| **F2** | §5 says ShowCre **unbuilt/future work**; §1 & §6 say **measured** | §5 ↔ §1,§6,§8 | **High** | Flat internal contradiction; reads as two authors. |
| **F6** | "The contribution" stated 3 ways: *churn* (§4.1) vs *quantification* (§1,§8) vs *anonymity-tension* (§7.2) | global | **High** | Reader can't identify the spine, so every section seems to serve a different thesis. |
| **F4** | Central comparison is **cross-scheme** (static=Loquat, zkVM=PLUM), disclaimed ~5× | §3,§6.3,§6.5.3,§6.6 | **Medium-High** | The two halves are hedged apart; the comparison never resolves. |
| **F5** | The **crossover `(U/P)*`** — the rule that fuses motivation+cost — has no number | §6.5.3,§7.1 | **Medium-High** | The climax is empty; the join between rigidity-story and cost-story is a missing quantity. |
| **F7** | Security: **signature-simulatability** hypothesis missing from anonymity bound | §055 | **Medium** (cryptographic) | The anonymity reduction's chain has an unstated link (rests on Loquat HVZK). |
| **F8** | Dangling **A4/A6/A7** assumption labels after the ledger was removed | §055, §3, §5, app | **Medium** | Same dangling-reference failure as F1, smaller blast radius. |
| **F9** | CreGen prove **anomaly** unresolved | §6.5.1 | **Low** | Well-quarantined, but a thread the reader watches dangle. |
| **F10** | **Deck tells the old story** (Loquat/Aurora/Poseidon/"SHA-wins paradox"/P1–P2) | draft.pptx 8–13 | **High (deck only)** | The slides argue a different, older thesis than the document. |

---

## The cryptographic-argument spine (does the *security* story connect?)

Walked as a reduction, the chain is: **BDEC unforgeability** (§3) ← **zkVM knowledge-soundness extractor** pulls the witness (§3 zkVM def, §055) ← extracted signature is a **PLUM EU-CMA forgery** (§3 EUF-CMA) ← **Loquat→PLUM analysis** (§3.2.4) ← **β-approx power-residue PRF**. **Anonymity/unlinkability** ← **SNARK ZK** (wrap only, §3.5/§055) **+ signature simulatability** (← Loquat HVZK). Precompile correctness ← **AIR soundness (App)** + **lookup binding** (cited).

This chain is *almost* fully connected and is the strongest part of the thesis. The two missing links: **(i) the signature-simulatability hypothesis (F7)** is used implicitly but never stated; **(ii) the explicit reduction `B` is not written** — §055 argues an advantage-shift bound rather than exhibiting the extractor-to-forger reduction, so the connection from "zkVM knowledge-soundness" to "PLUM EU-CMA" is asserted in prose, not constructed. Both are closable with a few paragraphs (the exact BDEC + Loquat games are available).

---

## Minimal fix list to make the story flow (ordered by leverage)

1. **Pick one headline and make every section point at it (F6).** Recommended spine: *"We quantify the zkVM path for PQ-anon-creds. The cost is feasible-but-bounded and concentrates in the algebraic hash; anonymity collides with the consumer-HW frontier; and update churn is the deployment axis on which the zkVM repays its per-proof cost."* Then: §4.1 stops calling churn "the central contribution" (it's the *motivation/decision axis*); §7.2's tension and §1's quantification become *findings under* the one headline.
2. **Fix F2: rewrite §5 to say ShowCre is built + measured** (it is). Remove it from "deliberately not built." Add the new SP1 BDEC CreGen/ShowCre data and frame the SP1=instrument / RISC0=application split as deliberate (kills the §6 string of disclaimers).
3. **Fix F1: reconcile §4 and §6.6.** Either (a) reinstate a *lean* numbered prediction list in §4 (P1–P5, one line each) so the scorecard has a rubric, or (b) rewrite §6.6 to drop the "P1–P5" labels and score against the §4 cost-framework claims by name. (b) is more in keeping with the de-AI rewrite.
4. **Fix F4/F5 — close the comparison, or stop implying it closes.** Best: measure **PLUM-in-Aurora** (a same-scheme static point) *and* the **per-φ recompile delta** (the φ-parameterised emitter, already named as #1 future work) → then the crossover gets a number and the two halves visibly meet. If that's out of scope before submission: explicitly reframe the contribution as *"structural separation (proven) + indicative timing (cross-scheme, bounded)"* and remove language that promises a numeric verdict, so the reader stops waiting for a join that isn't coming.
5. **Fix F7/F8 (security): add the signature-simulatability hypothesis to the anonymity bound; write the explicit unforgeability reduction `B`; replace dangling A4/A6/A7 labels** with either a small named-assumption table or prose pointers.
6. **Fix F10 (deck): realign the slides onto the thesis spine** — PLUM (not Loquat) as protagonist, the Griffin-Fp192 precompile (not a Poseidon/SHA precompile), the measured 58%/58× numbers (not the cited Aurora-blowup table), and "one ZK proof of the k+2 conjunction under hidden pk_U." (Separate deliverable; this audit is its blueprint.)

**Bottom line:** the connection you can't see is real and locatable — it's broken at the predictions-scorecard (F1), the construction-vs-evaluation contradiction (F2), the three-way contribution statement (F6), and a climax (the crossover) whose number was never measured across two different schemes (F4/F5). Close those four and the spine becomes visible end-to-end.
