# 10-Minute Defence Revision Pack

Takumi Otsuka · 5124FG15 · Sako Laboratory
Built against the current 27-page deck (`p5124fg15d4.pdf`), script draft 2, and Prof. Sako's page-by-page review of 2026-07-26.

---

## 0a. Discrepancies between the deck and the thesis — read this first

Checked against `07-discussion.tex`, `08-conclusion.tex`, `06-evaluation.tex`, `055-security.tex`. The deck **understates the thesis** in four places and **overstates** it in one. All five are fixable without new measurement.

**① The zero-knowledge wrap campaign is missing entirely.** `tab:proof-mode` records seven measured proof modes. None of the wrap rows are in the deck:

| Substrate | Configuration | ZK | PQ | Time | Peak |
|---|---|---|---|---|---|
| SP1 | PLUM verify (core) | no | yes | 14.24 min | — |
| | PLUM verify, SHA-3 (core) | no | yes | 13.24 min | — |
| | PLUM verify, **BN254 wrap** | **yes** | no | **46.83 min** | 15.3 GiB |
| | CreGen (core) | no | yes | 68.96 min | — |
| | CreGen, **BN254 wrap** | **yes** | no | **252 min** | 15.6 GiB |
| | ShowCre k=1,2 (core) | no | yes | 103–137 min | — |
| | ShowCre k=1, **BN254 wrap** | **yes** | no | **706 min** | 14.93 GiB |
| Aurora | Loquat verify | no | yes | 3.76 min | — |
| | Loquat verify, **ZK** | **yes** | **yes** | **≈22 min** (n=3) | — |

The 706 min includes a one-time 2.96 h core-shape pass (footnote ¶), so the steady-state figure comparable to CreGen's 252 min is ≈528 min. Plus a statement-bound k=2 wrap at 10.21 h / 15.66 GiB — *faster* than k=1 because they are different configurations, not a matched k-series — shard count 1516 → 2011, and an ML-DSA-proxy baseline jetsam-killed at 249 s with an 82.7 GB virtual footprint. The thesis opens the dual obstruction with *"Feasibility is not the issue"* — because these runs establish it isn't. **S10 currently shows the wrap as a ✗ in a 2×2 and never says it completes.**

**② The Aurora ZK+PQ row is what makes the obstruction a finding.** It is the one configuration that is both zero-knowledge and post-quantum. It is the existence proof licensing *"a limitation of the wrappers SP1 ships, not an impossibility result for zkVMs."* Without it that line is an assertion.

**③ Everlasting anonymity is a proved theorem, typeset as a caveat.** `Theorem thm:no-everlasting` — for the hash-committed showing class, everlasting anonymity cannot be established in the standard model; `Proposition prop:everlasting` gives the conditional route out (a non-interactive statistically-hiding trace commitment). Currently a sub-bullet starting "this route cannot give…".

**④ Five open assumptions plus one conjecture, not six assumptions.** The multi-shard receipt's knowledge soundness rests on `Conjecture conj:extract-recursion`, which the thesis deliberately keeps separate from the five assumptions. The Future Works slide merges them.

**⑤ Overstated: the flexibility motivation.** §8 lists it as one of **two falsified predictions** — *"against the transparent, non-preprocessing Aurora baseline the zkVM's update-churn advantage never shows up in wall-clock. The static-side recompile is sub-second (R_static ≈ 0.3 s)."* S2/S3 imply a rebuild cost you measured at 0.3 seconds. The defensible claim is the **re-audit and governance footprint** (zero regenerations vs ≥1 per change), not proving time. A wall-clock advantage would appear only against a *preprocessing* baseline, which is not what BDEC uses.

**Also corrected below:** 69/103/137 min are *measured single runs* (68.96, 103.34, 136.82), not estimates — your summary was right and the deck's "estimated" understates. And λ=80 applies to prove-mode wall-clock only: the field-multiplication ablation is at λ=128, and the 58.5× ratio and credential cycle counts are execute-mode at λ=80.

---

## 0b. The three rules this pack applies

1. **One name per concept.** Her closing line was *"the terms you are using in 17 pages slide are not consistent or defined carefully."* Every renaming below is non-negotiable, including inside figures.
2. **Every number carries a unit and a provenance.** Measured, estimated, or predicted — marked on the slide, not just in the script.
3. **Nothing spoken that is not written.** If a term is in the script and not on the slide, it does not exist.

---

## 1. Slide map: 19 content slides → 10

| New | Source | Action |
|---|---|---|
| S1 Title | p1 | Restore the summary's question-form title |
| S2 Anonymous credentials, and what changes | p2 + p3 | Merge. Keep the holder→verifier figure, drop one bullet layer |
| S3 zkVM, and what a proof costs | p4 + p5 | Merge. This is where **committed area** gets defined, once |
| S4 Goal and three questions | p6 | Keep, tighten |
| S5 The field-mismatch tax | p7 | Keep. Strongest slide in the deck |
| S6 The cost criterion | p8 + p9 | Merge Test A and Test B onto one slide |
| S7 Three precompiles, three outcomes | p10 | Keep, relabel (see §2) |
| S8 Feasibility recovered | p12 | Keep + fix the λ scope + mark provenance (all measured) |
| S9 Did the criterion hold? | p16 | Cut to three measured rows, add status column, move the prediction out |
| S10 The dual obstruction | p17 | **Rebuild** — the 2×2 omits the whole wrapper campaign and the Aurora ZK+PQ row |
| S11 Conclusion and future work | p18 + p19 | Merge. Future work reordered to the thesis's own priority |

**Moved to appendix, not deleted:** p11 (machine specs), p13 (Griffin vs SHA-3), p14 (Multiply), p15 (Power-Residue Check).

Those four are simultaneously your lowest value-per-second slides **and** the ones carrying every repeat offence Sako flagged — "loses/pays", `chip 304`, `host 371`, unlabelled bars. Moving them fixes the clock and removes the attack surface in one edit. S9's table already carries their conclusions; the detail stays one keypress away.

---

## 2. Terminology sweep — apply everywhere, including inside figures

| Replace | With | Why |
|---|---|---|
| chip, custom chip, Chip Table | **precompile**, **precompile table** | She listed shortcut/precompile/accelerator/chip as the main obstacle to understanding |
| shortcut | **precompile** | *"I don't recommend using the term shortcuts, as it is unclear why shortcut exists"* |
| custom accelerator | **precompile** | same |
| building a hardware / custom hardware | **adding a precompile** | *"this is misleading as you are only using custom hardware"* |
| total trace area / area / total-committed area | **committed area** | Four names for one quantity across p4, p8, p15, p16 |
| size mismatch (script) | **field mismatch** | Script and slide disagree; she flagged this exact pair |
| number check | **power-residue check** | *"Number check never explained"* |
| loses / pays / wins | **is at a disadvantage / is worth building** | *"we rather use 'advantage/disadvantage' … but not win/lose"* |
| privacy wrap | **zero-knowledge wrapper** | never defined |
| base proof | **SP1's default receipt** | never defined |
| ℓ | **pieces** (spoken), ℓ = pieces (on slide) | *"what does ℓ=1 mean?"* |
| host 371 / chip 304 | **software multiply: 371 cells/op · precompile: 304 cells/op** | asked verbatim, still unchanged |

Keep "Build / Do not build" in S9 — that is the rule's output, not a value judgement.

---

## 3. Final on-slide content

### S1 — Title
> **When Does a Precompile Pay?**
> A Cost Criterion for Post-Quantum Signature Verification in a Zero-Knowledge Virtual Machine

Master's Thesis Defence · Takumi Otsuka, 5124FG15 · Sako Kazue Laboratory

*The summary you submitted uses the question form. The deck dropped it. The question is what the deck answers — put it back, and the jury knows what to listen for from second one.*

### S2 — Anonymous credentials, and what changes over a lifetime
Keep the existing holder→verifier figure.

> An issuer signs a set of attributes. The holder later discloses part of the set with a zero-knowledge proof that a valid signature covers the whole set.
>
> Three properties, and they must hold for decades:
> **unforgeable** · **anonymous** (the verifier learns the fact, not the holder) · **quantum-safe**
>
> BDEC [5] shows all three are achievable, instantiated with Loquat [14].
>
> **What is not settled is deployment.** Over a credential's lifetime what must be proved keeps changing — which attributes, the security level, even the signature scheme. With a fixed circuit, every such change means a **regeneration and a re-audit** of the constraint system.

⚠️ **Do not imply this is a wall-clock cost.** Your §8 measures the static-side recompile at R_static ≈ 0.3 s and lists the absent flexibility advantage as one of two falsified predictions. Say **re-audit footprint**, not rebuild time — zero regenerations on the zkVM side against ≥1 per change on the static side, an engineering-and-assurance cost paid by humans. If you imply a runtime advantage, anyone who has read the thesis opens with your own falsification.

### S3 — zkVM, and what a proof costs
Keep the program→trace→proof figure and the emulated-vs-precompile cell diagram.

> In a zkVM the program is an **input**, so a change is an edit, not a rebuild and re-audit.
>
> The prover records the run as tables of field elements and commits to them.
> **Committed area** = every trace cell the prover commits, across all tables. *(one square = one cell)*
>
> A **precompile** is a fixed sub-circuit the zkVM proves natively instead of emulating step by step. It removes CPU rows and adds one precompile table.
>
> **Cycle count is the first estimate. It sees only the rows removed, not the table added. Committed area sees both.**

### S4 — Goal and three questions
Unchanged from p6 except:
- Question 1: "When is a **precompile** worth building?" (was "custom accelerator")
- Add one line under the questions: *Q1 is answered by a rule, Q2 by a measurement. Q2 only exists once Q1's answer lets the run finish at all.*

### S5 — The field-mismatch tax
Keep exactly as-is. Two edits:
- Move the grey footnote up to slide body: **"19 → 3,121 guest cycles, execute mode: a 164× penalty (measured)."**
- Add: *ℓ = number of 31-bit pieces one 199-bit number is split into.*

### S6 — The cost criterion
One slide, both tests. Keep the removed-vs-added cell figure.

> Build a precompile only when it removes more proving work than it adds. Work is measured in **committed area**, A.
>
> **Test A — against the program's own emulation**
> (A_emulated − A_call) · n > A_table
>
> **Test B — against a precompile that already exists**
> A_total(new) < A_total(alternative)
>
> **Declared inputs:** n = invocations per proof; the baseline. Once both are declared the rule is deterministic — no judgement left in it.
>
> **The contribution is not the arithmetic. It is which quantity is priced: committed area, not cycles.**
>
> What the rule does not price: engineering effort, and the soundness assumptions each precompile adds.

That last line is worth 10 seconds. It shows you know the boundary of your own claim, which is the single thing Sako rewards most.

### S7 — Three precompiles, three outcomes
Keep the construction map. Relabel the three nodes:

- **Griffin hash** — ~91% of verification work · *built; measured, at a disadvantage vs SHA-3*
- **192-bit field multiplication** — *built; kept off the measured path (SP1 already ships a multiplier)*
- **Power-residue check** `a^((p−1)/t) mod p`, t = 256 — *built; predicted worth building, then confirmed*

### S8 — Feasibility recovered
Keep the bars. Corrected labelling:

> **Prove-mode wall-clock at λ = 80** — the largest level observable within the 24 GB budget, not a deployment security level.

Mark every bar with its provenance:
- `> 5 h` → **stopped, did not terminate**
- `14.24 min` → **measured, mean of n = 5 (14.16–14.44)**
- `68.96 min` CreGen · `103.34 / 136.82 min` ShowCre k=1/k=2 → **measured, single run**

> The precompile turns a proof that never terminated into one that finishes. Feasible in one specific sense — completion inside the 24 GB envelope in bounded wall-clock. Sub-second interactive latency stays out of reach.

**Say what each bar proves.** Sako asked this on 26 July — *"What is full credential? what is the difference from one PLUM signature verification? which selective disclosure happening?"* — and the slide still does not answer it. One line under each bar:

> **Issue (CreGen)** — proves two signature verifications: the credential, and the pseudonym link.
> **Show (ShowCre)** — proves a fresh pseudonym and the disclosed attributes, for *k* credentials shown.

Label the pale extension on the Show bar as the k=1 → k=2 growth.

**Ready for the obvious follow-ups:**
- *Why does showing cost more than issuing?* Showing carries the credential, a new pseudonym, and the disclosure predicate, and it scales with k. Issuing does not scale.
- *How much does one more credential cost?* The k=1→k=2 increment is 4.6×10¹⁰ cycles; CreGen proves two verifications in 9.12×10¹⁰, so one verification ≈4.56×10¹⁰. Each extra shown credential costs about one signature verification — this is what "consistent with the additive cost model" means, said plainly.
- *Are single runs trustworthy?* Prove throughput is constant to within 1% across all three: 1.32, 1.32, 1.33 ×10⁹ cycles/min.
- *If one verification is 14.24 min, why is CreGen with two 68.96 min and not ~28?* The remainder is the credential relation's own machinery around the signatures — attribute hashing, Merkle path, pseudonym derivation, statement binding.

**Corrections to what the deck currently says:**
- Your deck's conclusion calls issuance *"estimated at 69 min."* The thesis has it as **68.96 min, measured, single run** (`tab:proof-mode`). Your gaiyousho is the correct one. Change the deck, not the summary.
- Do **not** write "all figures at λ = 80." λ = 80 is prove-mode wall-clock only. The field-multiplication ablation is reported at **λ = 128**, and the 58.5× Griffin ratio and the credential cycle counts are **execute-mode** figures at λ = 80. State the scope precisely or you create a second inconsistency for someone to find.

### S9 — Did the criterion hold?

**The problem with the table as it stands.** S3 and S6 both claim that cycles are the wrong quantity and committed area is the right one — that is the contribution. The "Deciding Measurement" column then shows which quantity actually made each call, and two of the four rows are decided on cycles:

- Row 1, *58.5× fewer cycles* — cycles.
- Row 4, *164× tax vanishes at ℓ=1* — this is the 19 → 3,121 guest-cycle figure from S5, so also cycles.

If cycles sufficed for those two rows, they are not evidence for the criterion; they are evidence that the cheap metric you argue against would have done the job. Half the validation table undercuts the claim it exists to support. The question is one line long: *"only one row needed your metric — what does the criterion buy?"*

**The fix.** Cut the table to three measured rows, make each declare what kind of evidence it is, and move the prediction out of it.

| Case | Test | Rule's call | Deciding quantity | Status |
|---|---|---|---|---|
| Griffin vs. its own emulation | A | Build | guest cycles — committed area unmeasurable, the baseline never completed | retrospective |
| Griffin vs. SHA-3 control | B | Expect a disadvantage | +5.6 × 10⁷ committed cells | control, confirmed |
| Power-residue check | A | Build | **10.33 × less committed area** | **prospective — priced before building** |

Below the table, on its own line:

> **Not yet measured:** field multiplication at ℓ = 1. The rule says do not build, because the 164× field-mismatch tax vanishes once the field matches. Stated as a prediction.

Three edits inside the table: drop the redundant *+11% cycles* from row 2 so it reads as pure area; give row 1's cycles figure its reason in the same cell; keep the header **"Deciding quantity"** rather than softening it to "Evidence" — the precise header is what makes the fix legible, and blurring it is the move she would catch.

**Then the punchline line, which is what turns this around:**

> Only the power-residue row needed committed area to decide it — and that is the design. It is the one case where the cheaper quantities disagree: field-operation columns say disadvantage (382 vs 261), execute cycles say an 18× advantage (365 vs 6,549), committed area says 10.33×. Where they disagree, only committed area matches what the prover actually commits.

That reframes "only one row uses my metric" from a weakness into the reason the experiment is informative. Keep the falsifiability line under it:

> The rule is falsifiable. It would have failed if the power-residue precompile had come in larger on committed area, or if the matched-field operation had shown a large removable cost. Neither happened.

This section and the §2 sweep are the two things worth doing properly. The status column also answers her *"It is hard to see which worked and which not"* directly.

### S10 — The dual obstruction
**Rebuild this slide.** The current 2×2 is the weakest slide in the deck relative to what the thesis actually establishes: it presents the zero-knowledge wrapper as a ✗ and never says you built it, ran it, and measured it. Replace the 2×2 with a compressed `tab:proof-mode`:

| Substrate | Configuration | ZK | PQ | Time |
|---|---|---|---|---|
| SP1 | PLUM verify (core) | ✗ | ✓ | 14.24 min |
| SP1 | PLUM verify + wrapper | ✓ | ✗ | 46.83 min |
| SP1 | Credential issue + wrapper | ✓ | ✗ | 4.2 h |
| SP1 | Credential show + wrapper | ✓ | ✗ | 11.8 h * |
| **Aurora** | **Loquat verify, ZK** | **✓** | **✓** | **≈22 min** |

> \* includes a one-time 2.96 h core-shape pass. Each run peaks near 15 GiB, inside the 24 GB budget.

**Why show costs more than issue** — you will be asked, so put the footnote on the slide:
- Showing is ~1.5× the work: 1.36×10¹¹ cycles vs 9.12×10¹⁰, which is also the core ratio (103.34 vs 68.96 min).
- The 11.8 h carries a one-time 2.96 h core-shape pass the 4.2 h does not. Like-for-like is ≈8.8 h vs 4.2 h.
- The residual (2.1× against a 1.5× core) is the wrap's shard count and peak memory growing with the relation.

**Quote 11.8 h with the footnote, not the derived 8.8 h.** 8.8 is sound arithmetic but it is not a number in your thesis, and two days out you do not want to defend a figure the committee cannot find in the document.

**Keep k=2 off this slide.** Your k=2 wrap is 10.21 h — *faster* than k=1 at 11.76 h — because they are different configurations (k=1 plain and carrying the one-time pass, k=2 statement-bound), which your conclusion states explicitly: "the two are different configurations, not a matched k-series." Side by side and unexplained, that reads as showing two credentials being cheaper than showing one. Keep it as a backup answer.

> **Feasibility is not what blocks anonymity.** The full wrapper chain completes on the target machine, each run peaking near 15 GiB inside the 24 GB budget, with the public statement bound to the receipt. The deployable object is a statement-bound zero-knowledge credential.
>
> **What blocks it is the primitive.** The only wrapper the toolchain ships is pairing-based, so its anonymity is classical. On SP1, no proof is at once zero-knowledge and post-quantum.
>
> **The obstruction is substrate-specific, not a fact about zkVMs** — the static circuit delivers both in ~22 minutes.
>
> **Theorem.** For the hash-committed showing class this construction uses, *everlasting* anonymity cannot be established in the standard model. The conditional route out is a statistically-hiding trace commitment.
>
> Positive results hold under **five open assumptions and one extractor conjecture** (appendix A5).

Four reasons this version is stronger:

1. **It reports the work you did.** Seven measured proof modes, one of them an 11.8-hour run, currently invisible.
2. **The Aurora row is what turns a failure into a finding.** It is the existence proof behind "a limitation of the wrappers SP1 ships, not an impossibility result for zkVMs." Without it, that sentence is an assertion; with it, it is demonstrated.
3. **The theorem is stated as a theorem.** An impossibility result is the strongest object in your deck. Right now it is a sub-bullet beginning "this route cannot give…".
4. **Assumption and conjecture are kept apart**, as the thesis keeps them.

Terminology: "Zero-knowledge Wrap (Pairing-based)" → **zero-knowledge wrapper (pairing-based)**; keep "SP1's default receipt, built from hashing alone."

### S11 — Conclusion and future work
Keep p18's structure, with two corrections: issuance and showing figures are **measured**, not estimated (see S8), and the security line should read *five open assumptions and one extractor conjecture*.

**Rewrite the future-work list.** It is directionally right but misordered, merges an assumption with a conjecture, and drops two of the thesis's five items. Use your §8.4 order:

> **Next:** ① a 199-bit 𝔽ₚ Aurora harness to run PLUM on both substrates at matched security — the current harness is 127-bit, and this fixes the sign of the per-proof crossover · ② wire VEIL into the multi-shard prover for post-quantum zero knowledge · ③ re-specify PLUM over a bit-oriented hash and re-derive its soundness · ④ close Assumptions AIR and sZK, and the multi-shard extractor conjecture · ⑤ a generator emitting sound precompiles from a primitive's specification.

- **Item ① leads.** Your conclusion calls it *"the most informative next measurement."* The deck lists it third. *(Ignore my earlier advice to cut it from the spoken talk — that was wrong. It is the best-grounded of the five, with the blocker named: the harness is 127-bit only.)*
- **Item ② keeps the specifics.** VEIL exists as code and ships in your SP1 fork, unwired. The blocker is its one-mask-per-commitment discipline colliding with multi-shard proving, plus one open HVZK lemma for STIR/WHIR at η=4 over the 199-bit field. That is a research plan; "add zero knowledge using a post-quantum-sound method" is not. Add the qualifier: this route gives **computational** post-quantum anonymity in the QROM, **not** everlasting.
- **Item ④ separates the two objects.** "The remaining assumptions … multi-shard proof composition" implies an assumption covers shard composition. None does — it is `Conjecture conj:extract-recursion`.
- **Item ⑤ is missing from the deck entirely**, and is the most forward-looking thing on the slide: a soundness meta-theorem letting the criterion drive an automated build-or-skip decision. Cheap to add, and it is what makes the criterion look like the start of something rather than a one-off.

---

## 4. Speaker script — 10 slides, ≈ 9:40 at a calm pace

**S1 · 20s**
Good morning. I'm Takumi Otsuka from Sako Laboratory. This thesis answers one design question: when is it worth adding a precompile — a custom sub-circuit — to a zero-knowledge virtual machine? I give a cost criterion for that decision, and test it on post-quantum signature verification inside an anonymous credential, on a twenty-four gigabyte laptop.

**S2 · 55s**
An anonymous credential works like this. An issuer signs a set of attributes. Later the holder discloses only part of that set — a qualification, say — together with a zero-knowledge proof that a valid signature covers the whole credential. These are meant to last decades, so they need three properties: they must be unforgeable, they must be anonymous, meaning the verifier learns the fact proved and not which holder proved it, and they must be quantum-safe. BDEC, an earlier protocol by other researchers, shows all three can hold together, so existence is settled. What is not settled is deployment. The holder generates the proof on an ordinary laptop, and over a credential's lifetime what must be proved keeps changing — which attributes are shown, the security level, even the signature scheme. With a fixed circuit, every such change regenerates the constraint system and has to be re-audited. I want to be precise about that cost: I measured the static-side recompile at about three tenths of a second, so this is not a runtime penalty. It is a regeneration-and-re-audit footprint — zero on the zkVM side, at least one per change on the static side — and it is paid by engineers, not by the prover.

**S3 · 70s**
That is what motivates a zero-knowledge virtual machine. In a zkVM the program is an input, so a change in what must be proved is an edit rather than a rebuild and a re-audit. The prover records the run as tables of field elements and commits to them, and I will call the total number of committed cells the committed area. That is the quantity this thesis prices. A precompile is a fixed sub-circuit the machine recognises as one instruction and proves natively, instead of emulating it step by step. It removes rows from the CPU table and adds one precompile table of its own. Cycle count is the natural first estimate, and it is not enough, because it sees the rows removed and not the table added. Committed area sees both. I use the SP1 zkVM throughout.

**S4 · 35s**
The goal is to decide, before building, what it costs to prove a post-quantum anonymous credential inside a zkVM on consumer hardware, and what that costs in security. Three questions follow. When is a precompile worth building? Can a zkVM verify a post-quantum signature in practical time on consumer hardware? And does the proof the zkVM emits stay both post-quantum and zero-knowledge? The first is answered by a rule, the second by a measurement — and the measurement only exists once the rule's answer lets the run finish at all.

**S5 · 55s**
I hit a wall immediately. A single PLUM verification ran over five hours and never produced a proof. The cause is a field mismatch. PLUM computes on one hundred ninety-nine bit numbers; SP1 computes natively on thirty-one bit numbers. So each PLUM number is split into seven pieces, and one multiplication becomes forty-nine partial products. In execute mode a multiply costs nineteen cycles at one piece and three thousand one hundred twenty-one at seven — a one hundred sixty-four times penalty, measured. That establishes the mismatch is large. What it costs to *prove* is the next slide.

**S6 · 85s**
So when should a precompile be built? The rule is: build one only when it removes more proving work than it adds, with work measured in committed area. There are two comparisons. Test A is against the program's own emulation. The area removed per invocation, times the number of invocations in one proof, must exceed the area of the table the precompile adds. Test B is against a precompile that already exists for the same operation — there the new one is only worth building if the total committed area comes out lower. Two things are declared up front: n, the number of invocations per proof, and which baseline is being compared against. Once those are declared the rule is deterministic; there is no judgement left in it. And I want to be clear about what the contribution is. It is not the arithmetic — the arithmetic is a break-even. It is which quantity is priced: committed area, not cycles. What the rule does not price is engineering effort, or the soundness assumptions each precompile adds, and that is where a person still has to decide whether to accept its answer.

**S7 · 50s**
I built three precompiles over PLUM's numbers, and they land on three different outcomes. The Griffin hash matters most — it is about ninety-one percent of the verification work, and it is the only one on the end-to-end measurements. The field multiplication precompile works and proves correctly, but I keep it off the measured path, because SP1 already ships a multiplier for this arithmetic, so the rule says it should not pay and that row stays a prediction. Third is the power-residue check at PLUM's core, the modular exponentiation the verifier recomputes. I measured that one on its own, and it gives the cleanest test of the rule.

**S8 · 65s**
Prove-mode wall-clock here is PLUM at eighty-bit security — the largest level observable inside twenty-four gigabytes, and not a deployment security level. Without the precompile the run was stopped after five hours having produced nothing. With the Griffin precompile a proof finished for the first time in this study, in fourteen point two four minutes, the mean of five fixed-configuration runs. Both halves of the credential also run and prove: issuing measured at sixty-nine minutes, and showing at one hundred three minutes for one credential and one hundred thirty-seven for two. Those are single runs. So the computation is feasible in one specific sense — completion inside the memory envelope in bounded wall-clock, against a baseline that never terminated. Sub-second interactive latency is not what I am claiming, and it stays out of reach.

**S9 · 80s**
So did the rule hold? Three measured cases. Griffin against its own emulation: the rule said build, and it turned a proof that never finished into fourteen minutes — that one is decided on cycles, because the emulated baseline never completed, so there is no committed area to measure for it. Griffin against a plain software SHA-3 control: the rule said expect a disadvantage, because the precompile's own table still has to be proved, and it came in larger by five point six times ten to the seventh committed cells. Then the power-residue check: the rule said build, and this is the one that was priced *before* I built it, coming in at ten point three three times less committed area. That row is the load-bearing one, and deliberately so — it is the case where the cheaper quantities disagree with each other. Field-operation columns say the precompile is at a disadvantage. Execute cycles say it wins by eighteen times. Only committed area gives ten point three three, and only committed area is what the prover actually commits. Separately, field multiplication at matched field is a prediction I have not measured: the rule says do not build. And the rule is falsifiable — it would have failed if the power-residue precompile had come in larger on area, or if the matched-field operation had shown a large removable cost. Neither happened.

**S10 · 60s**
What remains is security, and I want to be clear that feasibility is not what blocks it. I built and measured the zero-knowledge wrapper chain: PLUM verification wraps in forty-seven minutes, credential issuance in four point two hours, and a showing in eleven point eight hours — each completing on the same laptop, peaking near fifteen gigabytes inside the twenty-four gigabyte budget, with the public statement bound to the receipt. So the deployable object is a statement-bound zero-knowledge credential, not two separate demonstrations. What blocks post-quantum anonymity is the primitive. The only wrapper the toolchain ships is pairing-based, so the anonymity it delivers is classical, and on SP1 no proof is at once zero-knowledge and post-quantum. That this is a limitation of the wrappers rather than of zkVMs is something I can show rather than assert: the static circuit produces a proof that is both, in about twenty-two minutes. And there is a sharper limit I prove: for the hash-committed showings this construction uses, everlasting anonymity — safety against an attacker who stores a proof today and breaks it later — cannot be established in the standard model at all. Reaching it needs a statistically-hiding trace commitment. All the positive results hold under five open assumptions and one extractor conjecture.

**S11 · 50s**
So can a holder do this today? Not yet, and now for a precise reason. First contribution: a cost criterion that decides, before building, whether a precompile is worth it, confirmed in advance on the power-residue precompile — eleven point three seven against one hundred seventeen point four six million cells. On the second question, PLUM verification completes at eighty-bit security inside twenty-four gigabytes, and so does the whole credential, wrapper included. On the third, no proof SP1 currently produces is both post-quantum and zero-knowledge, and the reason is the wrapper's primitive rather than any resource limit. Second contribution: to my knowledge this is the first empirical characterisation of post-quantum credential relations inside a zkVM on consumer hardware. The most informative next measurement is running PLUM on both substrates at matched security, which needs a one-hundred-ninety-nine-bit static harness; after that, wiring a post-quantum-sound wrapper into the multi-shard prover. Thank you.

*Word count ≈ 1,290. At 135 wpm that is 9:34, leaving buffer for the title slide and pauses.*

---

## 5. Appendix order

Put the four moved slides **first** — those are what get asked about.

| A# | Slide | Was |
|---|---|---|
| A1 | Griffin vs SHA-3 | p13 |
| A2 | Field multiplication | p14 |
| A3 | Power-residue check — three measures | p15 |
| A4 | Machine specifications | p11 |
| A5 | **The five open assumptions** | *new — write this* |
| A6 | **λ = 80 vs λ = 128** | *new — write this* |
| A7–A11 | Loquat, PLUM, BDEC | p23–p27 |

### A5 — write this slide (content pulled from your `055-security.tex`)

> **Five open assumptions — and one conjecture**
> 1. **Griffin-AIR constraint soundness** — the AIR admits only the reference permutation. Argued at specification level; not established at constraint level for the lookup-borne families, not machine-checked.
> 2. **Cross-table lookup binding** (LogUp) — inherited from SP1, not re-established at the deployed parameters. *Weakest link: every precompile depends on it.*
> 3. **PLUM signature-transcript simulatability** — PLUM establishes EUF-CMA, not simulatability. Needed by the anonymity bounds.
> 4. **Credential-signature key-privacy** — open for PLUM; needed by BDEC's Theorem 2 reduction.
> 5. **Griffin (Q)ROM instantiation** — published analyses cover the original instantiations, not d=3, width-4, 199-bit, 14-round.
>
> **Separately — not an assumption:** the multi-shard extractor conjecture (`conj:extract-recursion`), on which the composite receipt's knowledge soundness rests.
>
> Plus three standard assumptions inherited unchanged from PLUM, Griffin and SP1 (Griffin collision resistance, Q1 power-residue-PRF hardness, black-box transfer of PLUM's reduction).

Keep the conjecture visually separate from the five. Your thesis is careful about this distinction and the Future Works slide currently is not — if someone asks "which assumption covers shard composition?", the answer is *none, it is a conjecture*, and you want the slide to have said so first.

Having this slide ready is worth more than any polish elsewhere. Right now S10 asserts "five" and never names them, which is exactly the shape of claim Sako opens with.

### A6 — write this slide

> **Why λ = 80**
> λ = 80 is the highest level that completes within 24 GB on this machine. λ = 128 is untested and expected to exceed memory.
> Power-residue key recovery at the deployed data (L = 2¹², p ≈ 2¹⁹⁹) costs ≈ 2¹⁷⁵, clearing both 80 and 128.
> The binding ceiling at 128 is elsewhere: the Merkle path truncates the Griffin digest to one field element, birthday-capping collision resistance at ≈ 2⁹⁹·⁵ — above 80, below 128.

That last line is the real answer, and it is a good one: **the 80-bit choice is a memory limit for the measurement, and separately there is a structural ceiling at 2⁹⁹·⁵ you have identified.** Do not let this stay buried in §055.

---

## 6. Q&A pack

**"80-bit is not a deployable security level. What have you actually shown is feasible?"**
Two separate things. Eighty is a measurement limit — it is the highest level that completes inside twenty-four gigabytes on this machine, and one hundred twenty-eight is expected to exceed memory. Separately, the thesis identifies a structural ceiling: the deployed Merkle path truncates the Griffin digest to one field element, birthday-capping collision resistance at two to the ninety-nine point five, which clears eighty and not one hundred twenty-eight. So what is shown feasible is the *cost structure* — the field-mismatch tax and the criterion do not depend on λ. The absolute timings do. → **A6**

**"Which numbers are end-to-end measurements?"**
Fourteen point two four minutes is measured, mean of five runs. The five-hour figure is a run I stopped, not a completion. The credential issue and show figures are [measured / estimated — **decide this before the defence**]. The multiply row is a prediction from the rule, and I label it as such. → **A3**

**"You say cycles are the wrong quantity, then decide the first row on cycles."**
For that row, yes, and for a specific reason: the emulated baseline never completed, so there is no committed area to measure for it — cycles are the only quantity that exists. The two other measured rows are decided on committed area. The prediction for field multiplication is a cycles-derived argument, which is one reason I keep it out of the evidence table and label it a prediction rather than a result. → **S9**

**"Only one of your rows actually needed committed area to decide it."**
That is correct, and it is the design rather than a gap. A metric only earns its keep where the cheaper metrics disagree, and the power-residue check is the case where they do: field-operation columns say disadvantage, execute cycles say an eighteen-times advantage, committed area says ten point three three. The other rows agree across metrics, so they are consistency checks, not discriminating tests. If every row had needed committed area, that would mean cycles never work, which is not my claim — my claim is that cycles cannot be *relied* on, because you cannot tell in advance which case you are in. → **A3**

**"One prospective confirmation is not much to call this a criterion."**
Agreed, and I would not claim more. One row was priced before building and confirmed; one is a retrospective check; one is a control that behaved as predicted; one is an unmeasured prediction. What makes it more than bookkeeping is that the cheaper quantities *disagree* — field-operation columns say the power-residue precompile is at a disadvantage, execute cycles say it wins by eighteen times, and only committed area gives ten point three three. The criterion is testable precisely because those disagree. → **A3**

**"Is one hundred thirty-seven minutes practical?"**
No, not for an interactive showing. The thesis does not claim it is. What it claims is a move from *does not complete* to *completes*, which is what makes the next question — how fast — askable at all. Defining an operational threshold for "practically acceptable" is open work and I flag it as such.

**"Why build the multiply precompile if you never measured it?"**
To have the rule make a falsifiable call against something real. It works and proves correctly; the rule says the per-operation saving of eighteen percent cannot cover a whole second table for arithmetic SP1 already provides, so I left it off the measured path and labelled the row a prediction rather than quietly dropping it. → **A2**

**"PLUM's printed p₀ is composite and you substituted a different prime."**
Yes — the paper's printed p₀ has smallest prime factor 97, which I verify in the test suite. I substituted a nearby 199-bit p₀ preserving bit-width, 2-adicity at least sixty-four, and t = 256 dividing p − 1. Since cost depends on bit-width and 2-adicity, both preserved, the substitution is sound for the timing and area claims. It is not sound for any claim conditioned on the specific decimal value of p, and I make no such claim.

**"You motivate the zkVM by flexibility, but your thesis measures the static recompile at 0.3 seconds. What is the flexibility worth?"**
Nothing in wall-clock, and I report that as a falsified prediction. Against a transparent non-preprocessing argument like the Aurora that BDEC uses, there is no runtime flexibility advantage — the recompile is sub-second and sits outside the multi-minute prover. What separates the regimes is the regeneration-and-re-audit footprint: zero on the zkVM side against at least one per change on the static side, a cost in engineering and assurance. A wall-clock advantage would appear only against a preprocessing baseline, and that is not what BDEC uses. The substrate-selection rule in the thesis is stated on that basis.

**"You claim the wrapper is infeasible, or you claim it is not?"**
Neither — it is feasible and I measured it. PLUM verification wraps in 46.83 minutes, issuance in 4.2 hours, a showing in 11.8 hours, each peaking near 15 GiB inside 24 GB, statement-bound. Feasibility is not what blocks post-quantum anonymity; the wrapper's pairing is. That distinction is the finding. → **S10**

**"If no proof is both zero-knowledge and post-quantum, how do you know that is not just how zkVMs are?"**
Because the static circuit does both — Loquat verification, zero-knowledge enabled, post-quantum, in about 22 minutes on the same machine. That is why I state it as a limitation of the wrappers SP1 ships rather than an impossibility result. → **S10**

**"Where is RISC Zero? Where is Cell 4?"**
Out of the talk for time; both are in the thesis. The Aurora/Loquat cell is a cross-scheme reference over a different field, so it bounds nothing about SP1 — it is the only measured system that hides its inputs, which is why it is there at all.

**"Is Griffin vs SHA-3 a fair comparison if PLUM's security isn't defined over SHA-3?"**
It is a cost control, not a deployable alternative, and I say so on the slide. PLUM's security analysis does not cover SHA-3, so making thirteen point two four minutes mean anything would require re-specifying PLUM with a standard hash and re-deriving its security. That is future work. → **A1**

---

## 7. Verification against Sako's 26 July review

| Her comment | Status after this pack |
|---|---|
| Illustrate selective disclosure | ✅ already fixed in current deck |
| BDEC: call it a protocol / other researchers' work | ✅ already fixed |
| "What must be proved keeps changing" belongs earlier + say why zkVM helps | ✅ S2 + S3 |
| shortcuts / precompile / accelerator / chip inconsistent | ⬜ **§2 sweep — largest remaining item** |
| "committed area" not on slide, undefined | ✅ S3 defines it once, one name |
| Never said PLUM is xx bits and SP1 is xx bits | ✅ already fixed on p7 |
| script says "size mismatch", slide says "field mismatch" | ⬜ **§2 sweep** |
| Want to see the algorithm behind the criterion | ✅ S6 |
| "host 371 / chip 304" meaningless | ⬜ **§2 — units added, moved to A2** |
| p13 bars: what is baseline/chip, what is total area | ✅ legend + moved to A3 |
| win/lose language | ⬜ **§2 sweep — she flagged this explicitly; repeating it is the costliest error** |
| "Finding 3" with no Findings 1 and 2 | ✅ already fixed |
| "definitive validation", "rigorous testing" | ✅ already gone from draft 2 |
| what does ℓ = 1 mean | ⬜ S5 adds the definition |
| which are end-to-end measurements | ⬜ **S8 marks — and resolve the summary/deck conflict** |
| base proof / privacy wrap / hash-based proof undefined | ⬜ S3 + S10 |
| power-residue check never explained | ⬜ S7 gives the formula and the words |
| "custom chips", "multi-shard proofs" unclear | ⬜ §2 sweep; multi-shard cut from spoken talk |
| Terms not consistent or defined carefully (overall) | ⬜ §2 is the whole answer to this |
| — | **New:** five open assumptions + the conjecture named (A5); λ scope corrected (S8 + A6); S9 cut to three measured rows with a status column; **S10 rebuilt to carry the wrapper campaign, the Aurora ZK+PQ row, and the everlasting-anonymity theorem**; future work reordered to §8.4 |

Everything marked ⬜ is a mechanical edit. None of it requires new measurement.

---

## 8. If you only have two hours

1. **S10 rebuild** — replace the 2×2 with the compressed `tab:proof-mode`, add the Aurora ZK+PQ row, state the everlasting-anonymity theorem as a theorem. *(30 min)*
2. §2 terminology sweep, including inside every figure. *(45 min — this alone is most of her review)*
3. **S2 motivation** — change "rebuilding" to the re-audit footprint, and say the recompile is sub-second before anyone else does. *(10 min)*
4. Move p11, p13, p14, p15 to appendix; renumber. *(10 min)*
5. S9: cut the table to three measured rows, add the status column, move the field-multiply prediction below it, add the "where the metrics disagree" line. *(20 min)*
6. S8: correct the λ scope; relabel 69/103/137 as measured. *(10 min)*
7. Write A5 (five assumptions + the conjecture) and A6 (why 80). *(30 min)*
8. Reorder future work to the §8.4 priority; add the precompile generator. *(10 min)*
9. Restore "When Does a Precompile Pay?" to the title. *(1 min)*

Steps 1, 2 and 3 are the ones that change the outcome. Step 1 because it is the difference between a deck that reports a partial result and one that reports what you actually did; step 3 because it removes the only place where the deck claims more than the thesis.
