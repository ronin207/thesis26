# Defence Q&A — FINAL, MERGED & VERIFIED (07-29 pre-dawn)
**Defence: 2026-07-29 (Wed) 10:00, first presenter. ~10 min talk + short Q&A.**
Jury: Sako (supervisor, read everything) · Yamana (web/data mining, performance) · Mori (network security, measurement) · Shimizu (secure computation, knows ZK) · Ishikawa (vision/optimization).

**Every number and claim below has been verified against the thesis TeX (`修論2025_Takumi/`) and the gaiyousho (`abst_Takumi2025/`). All previously-flagged ⚠ facts are RESOLVED and folded into the answers. The only action items left are in "Five seams" and the one spoken-line fix (Q28).**

---

## Tier 1 — Near-certain

**Q1. What is the novelty? Anyone could run PLUM in SP1.** (Sako — asks everyone)
> The measurement overturned the standard metric: cycle counts give the wrong build decision in all three cases (Griffin removes 58.5× cycles yet is at a disadvantage vs SHA-3; multiply is 18% narrower per op yet a net loss; power-residue costs 17.9× fewer execute cycles *and* loses on field-op columns, yet pays 10.33× on total area). The criterion, priced in total committed area, gives the right decision and was confirmed prospectively. The thesis contains falsified predictions (the wall-clock flexibility advantage — R_static ≈ 0.3 s), so outcomes were not guessable. And the security result is a localization: the PQ/ZK conflict lives in the pairing-based wrapper, not the zkVM. If "isn't this just the hardware cost criterion?": the form is deliberately classical (Hennessy & Patterson, cited on slide 7); what's new is the mapping — the fixed cost recurs per proof, not once at fabrication, and the unit is committed area, not cycles.

**Q2. At issuance, is zero-knowledge necessary? Is a proof necessary at all?** (Sako — asked verbatim in Slack 07-26) ✅ VERIFIED from R_cre
> Yes to both, and here is exactly why: CreGen's relation is the conjunction of **two signature verifications under the user's long-term key pk_U**; the statement is x = (c, h, ppk) and the **witness is w = (pk_U, psk)** — the long-term public key and the pseudonym secret. The proof is necessary to bind the pseudonym to the master key (prevents forged links). ZK is necessary because revealing the witness would **link every pseudonym of the user**. The attribute digest h is public to the TA — ZK at issuance protects identity and link material, not attributes. And yes, the 14.24-min verify is the non-ZK default proof; that is stated on slide 10.

**Q3. Is ~103–137 minutes practical? Would anyone use this?**
> The claim is feasibility and characterization, not deployability. Before this work the answer at this level on consumer hardware was "does not finish"; now every operation completes inside 24 GB and we know exactly where the cost is. Say "feasible in computation time" — never bare "practical."

**Q4. Why λ=80 and not 128?** ✅ thesis wording verified
> Use the thesis's own sentence: *"λ=80 is the largest level at which prove-mode wall-clock is observable on this hardware — which is why we use it, and not because it is favourable."* The attribution analysis is at λ=128 in execute mode; no number mixes the two levels silently — every table states λ. Sharper follow-up you can volunteer if pushed: the Merkle path truncates the two-lane Griffin digest to one field element, birthday-capping collision resistance at √p ≈ 2^99.5 — unconditional, above 80, below 128, disclosed with the assumption bundle.

**Q4b (follow-up). But BDEC runs at high security inside its static zkSNARK — why not in the zkVM? What is the architectural difference?**
> Two structural taxes, and they multiply. (1) **Generality tax:** a static circuit commits only the verification arithmetic — the statement *is* the circuit. A zkVM proves the execution of a *program*: every step also commits fetch/decode/register/memory-consistency columns — the same control overhead the power-residue experiment measured collapsing at 261:1. (2) **Field-mismatch tax:** a static SNARK picks its field to match the scheme; SP1's is fixed at ~31 bits, so PLUM's multiply splits into 7 limbs / 49 partial products — measured ~164×. Raising λ grows hash parameters and repetitions, and both taxes scale with it → expected to exceed *this machine's* 24 GB, not architecturally impossible. Caveat: the static figure is a different harness (Loquat, 127-bit field) — matched comparison is future-work #1.

**Q5. Which numbers are end-to-end measurements and which are estimates?** (Sako — repeat concern) ✅ VERIFIED
> All headline numbers are measured. Verify 14.24 = **mean of five runs, range 14.16–14.44**; SHA-3 13.24 (13.02–13.38); each arm's spread under 5%, inversion sign-robust in every run. The Aurora reference is a mean of three (±0.8%). Every other prove-mode and wrap figure is a **single run, disclosed as such** — wall-clock is thermally confounded (1.4–1.6×), so the thesis rests conclusions on order-of-magnitude separations, memory walls, and shard-count/peak-memory monotonicity. The multiply row is a labelled prediction, not a measurement. (If variance is pressed: an early 32.53-min outlier was excluded after fixed-config replication — machine-state contamination.)

**Q6. "The obstruction is the wrapper, not the zkVM — what's your evidence?" / "Doesn't a static circuit already give both?"** (MOST EXPOSED — the static row was deliberately cut from slide 12; evidence is verbal-only) ✅ numbers verified
> "The thesis reports a static-circuit reference: Aurora proving Loquat verification **with zero-knowledge enabled — 21.96 minutes, mean of three runs (±0.8%), proof 856 KiB, peak 9.2–11.0 GiB, all accepting** — showing both guarantees are achievable outside SP1's wrapper. I kept it off the slide because it is cross-scheme (Loquat-shaped, 127-bit field), not like-for-like; the matched comparison is future-work #1." If pushed on why zkVM at all: not speed (static recompile ≈0.3 s — a falsified prediction, reported honestly; a wall-clock advantage would exist only vs a *preprocessing* baseline, and Aurora is non-preprocessing) but the re-audit footprint: 0 regenerations on the zkVM side per predicate change vs ≥1 static. **Overclaim guard (thesis Table tab:churn): this holds for presentation changes and security retunes; a signature swap (Loquat→PLUM) regenerates the field-specific Griffin AIR on the zkVM side too. Say "predicate changes," never "any change."**

**Q7. What exactly leaks from the default proof?** (Sako/Shimizu) ✅ now measured, not hypothetical
> SP1's default proof has no zero-knowledge guarantee, and the leak is measured: fixing the relation and varying only the witness, core receipts came out **154.67 / 156.12 / 153.21 MB — distinct across three witnesses (~1.9% spread)**; the Griffin permutation count is witness-invariant (1,052) but multiplication and cycle counts vary (N=20, execute mode). This is on the non-ZK path where no anonymity is claimed; the constant-size wrap (260 B Groth16 / 868 B PLONK) closes it — but is pairing-based, which is the dual obstruction.

**Q8. What are the "five open assumptions" and the "extractor conjecture"?** ✅ exact names verified
> Five open: **Griffin-AIR constraint soundness (asm:air)** · **PLUM signature-transcript simulatability (asm:szk)** · **cross-table lookup-argument binding (asm:lookup)** · **credential-signature key-privacy (asm:keypriv)** · **Griffin (Q)ROM instantiation (asm:qrom)**. One conjecture: **knowledge extraction through the SP1 shard and recursion tree (conj:extract-recursion)**. Inherited (standard, not open problems of this work): Griffin collision resistance at deployed parameters · Q1 power-residue-PRF key-recovery hardness (t=256; the t=2 Legendre case falls to a quantum Q2 attack, hence the Q1 restriction) · black-box transfer of PLUM's EUF-CMA reduction. Closing the opens is future-work #4.

---

## Tier 1½ — From the final deck (printed but unspoken → invitations)

**Q25. "Slide 11 says the area was 'unmeasurable' — how can an area-based rule decide without area?"** (Mori/Ishikawa)
> The rule's *inputs* are per-call figures from execute-mode counts and the table's design — none require completing a proof. What was unmeasurable was the *baseline's end-to-end total*, because that run never finished. ✅ Detail: the baseline was **stopped by the watchdog at 5 h 07 m, peaking at 13.62 GiB — memory was NOT the constraint**; do not say it "ran out of memory" at λ=80 (that's the *expected* failure mode at 128).

**Q26. "What is A_syscall in the Test A formula?"**
> The cost of invoking the precompile itself — the call's own overhead, subtracted so the per-call saving isn't overstated (the underbrace says "net of the call's own cost"). If notation is cross-checked against the thesis: the slide is a simplification of the trace-area model — thesis writes (cyc_em(op) − cyc_syscall)·ā_core·κ_core vs the chip area; same inequality, presentation units.

**Q27. "What were the memory peaks for the wrapper runs?"** ✅ all verified
> Verify+wrap **15.29 GiB** · CreGen wrap **15.63 GiB** · ShowCre k=1 wrap **14.93 GiB** · k=2 wrap **15.66 GiB** — all inside 24 GB; the obstruction is cryptographic, not resources. If growth-in-k comes up: rest it on **shard count (1,516 → 2,011)** and peak memory (14.93 → 15.66), never wall-clock (single runs, thermally confounded — which is also why k=2's end-to-end 10.21 h being *shorter* than k=1's 11.76 h is not a paradox). 706 min = 11.76 h end-to-end = 8.79 h per-proof chain + 2.96 h one-time core-shape pass.

**Q28. "The 91% Griffin share — how measured?"** 🔴 SEAM — SPOKEN-LINE FIX REQUIRED
> **The 91% is PLUM's own R1CS constraint share (their circuit-SNARK accounting: 10,333 of 116,285 constraints are non-hash), and your thesis EXPLICITLY cautions against transferring that figure to the zkVM cost model.** Spoken line for slide 8: *"in PLUM's own circuit accounting, about ninety-one percent of the constraints are hash work — and in the zkVM's own units the hash dominates as well."* zkVM-native evidence if challenged: the software-Griffin arm fires **4,870,724** multiplication syscalls vs **69,396** with the AIR active (~70×). Qualitative conclusion (hash dominates) agrees; the exact share differs by cost model — say so before they do.

**Q29. "Contribution 2 says 'credential relations' — meaning what?"**
> The proved statements of the credential operations — CreGen and ShowCre. Say "credential operations" aloud.

---

## Tier 2 — Likely, by juror

**Q9. Why PLUM and not a NIST-standard signature (ML-DSA/Falcon)?** (Shimizu/Mori) ✅ now measured
> The signature must verify *inside* a proof, so it must be SNARK-friendly; PLUM is the SNARK-friendly post-quantum design BDEC builds on. And it's measured, not asserted: a baseline STARK of ML-DSA-65's dominant work (17 NTT polynomial multiplications) was **jetsam-killed after 249 s at 12.59 GB RSS / 82.7 GB virtual footprint** — standard lattice verification doesn't even start on this substrate. The SNARK-friendly-vs-standardized trade-off is exactly what the SHA-3 future-work item addresses.

**Q10. Why SP1? Do results generalize?**
> Representative, mature open-source STARK zkVM with a documented precompile interface. The criterion's *form* is general (thesis: the field-mismatch tax and update-churn dimension are substrate-independent); the *magnitudes* are tied to PLUM's 199-bit field, the M5 Pro's 24 GB, and SP1's CPU-bound prover. Transfer is testable — future work.

**Q11. n=1 for the long runs — error bars? Validity?** (Mori) ✅ merged into Q5 — same answer; lead with "disclosed as such" and the thermal 1.4–1.6× caveat, then the sign-robustness of the one comparison that matters.

**Q12. Why a laptop?** (Yamana)
> The holder generates the showing proof; outsourcing it hands the witness (attributes, keys) to the server. Consumer hardware is the deployment-honest setting; 24 GB is the binding constraint that shaped every result.

**Q12b. "20-core GPU listed, prover CPU-bound — why not use the GPU?"** ✅ RESOLVED from thesis setup table
> *"CPU-bound; no CUDA/network prover — Apple Silicon has no NVIDIA GPU path."* SP1's GPU acceleration is CUDA-only; there is no CUDA on Apple Silicon, so the prover is CPU-bound by necessity. The 20-core GPU is irrelevant to SP1.

**Q13. How do you obtain the criterion's inputs before building?**
> Execute-mode counts plus the planned table's geometry — a counting exercise, hours not weeks. Declared before either test: the call count n and the baseline; measurable today: the emulated cost; from the design: the table dimensions.

**Q14. Isn't this just textbook amortization?** (Ishikawa)
> The form is deliberately classical (H&P ch. 7, cited). The contribution is the accounting basis: in a zkVM the fixed cost is recommitted in **every proof** (not paid once at fabrication) and the right unit is committed area — cycles mis-rank all three cases. The corrected mapping plus prospective validation is the contribution.

**Q15. Griffin passed Test A but loses to SHA-3 — didn't the criterion approve a bad build?**
> The criterion is baseline-relative. Test A (vs own emulation): "should we accelerate Griffin-PLUM?" — yes, DNF→14.24. Test B (vs SHA-3): "is Griffin the right hash?" — the rule predicted the disadvantage, and it appeared. A correctly predicted disadvantage is the rule working. SHA-3 is a *deliberately confounded control* (differs in hash AND field, matched only on λ) and PLUM-with-SHA-3 has no security analysis — re-deriving it is future-work #3.

**Q16. Power-residue: MORE columns (382 vs 261) yet 10× less area — why?** ✅ verified detail
> 382 = 2×191: the naive chip evaluates both square and multiply branches at every step; the guest loop does 191 squarings + ~70 multiplies ≈ 261. But columns omit the guest loop's per-call control overhead — syscall dispatch, memory access, cross-table lookup for each of ~261 calls vs once for the chip: the **261:1 collapse**. Total committed area: 11.37M vs 117.46M cells over 28 symbols (n=3, deterministic) = 10.33×. And execute cycles say 17.9× the *other* way (365 vs 6,549) — the thesis's own line: "a criterion read off execute cycles alone would mislead."

**Q17. What is the power-residue check, in one sentence?** ✅ verified
> A modular exponentiation — the chip computes the power-residue symbol a^((p−1)/t) mod p with t=256, realised as a 191-step square-and-multiply, which the verifier recomputes against the public key.

---

## Tier 2½ — Threat model & security definitions (Shimizu/Mori territory) ✅ verified from 055-security

**Q30. What is your threat model / how is security defined?**
> Three game-based experiments (Def. def:zkvm-cred-adv), each printed with its model line — *classical PPT adversary, classical random-oracle model*: **Exp^unf** (adversary with adaptive issuance and showing oracles must produce an accepting showing for a statement outside its honestly issued set); **Exp^anon** (adversary designates two honestly issued credentials of registered honest users whose secret keys stay hidden, and must tell which was shown — advantage |Pr[b′=b]−½|); **Exp^unlink** (same oracle interface, single-transcript linking; where a public linking tag is intentional, linkability is allowed only as the tag determines). The challenger keeps an honest-user registry and an issuance log ℒ.

**Q31. Who is trusted? Who are the parties?**
> The teaching authorities and the issuer hold signing keys; the holder proves; the relying party verifies; the ledger roots (credential, TA, revocation list) are public. The games model honest registered users via the registry; the adversary gets adaptive oracle access to issuance and showing. Revocation is a public list keyed by the master public key.

**Q32. Is the adversary quantum? Where exactly does "post-quantum" enter?**
> Layered, and be precise: the *proofs* are in the classical ROM against classical PPT adversaries. The *post-quantum reading* enters at the assumption layer: (i) **Q1 power-residue-PRF hardness** — a quantum adversary restricted to classical PRF queries; the restriction is essential because the t=2 Legendre case falls to a polynomial-time Q2 attack, and the signature exposes the PRF only on fixed public indices, which is what makes Q1 the right model; (ii) **Griffin's (Q)ROM instantiation** for the hashes. And one adversary stronger than quantum-PPT is handled separately: the C3 harvest-now adversary (records today, unbounded later) — for that one, everlasting anonymity is *provably not establishable* in the standard model (Q18).

**Q33. Do the precompiles weaken security? Why doesn't moving operations into custom circuits break soundness?** (the security chapter's own framing question — likely from Sako or Shimizu)
> The substitution is value-level: each precompile computes the same input–output map the software path computed, so PLUM's EUF-CMA reduction, which treats Griffin and field multiplication as black boxes, transfers unchanged (asm:bbt). What must additionally hold is that each precompile's AIR constrains exactly its operation (asm:air — a written soundness argument per precompile) and that the cross-table lookup argument binds the chip's rows to the CPU table (asm:lookup). Those are two of the five open assumptions, stated as such on slide 12 — the honest answer is "security is preserved *conditional on* the AIR soundness and lookup binding, which is why they are named assumptions and future-work #4 is closing them."

---

## Tier 3 — Tail risk

**Q18. Everlasting anonymity — can anonymity last decades?** (Shimizu) ✅ exact statement verified
> Theorem (thm:no-everlasting): everlasting anonymity — anonymity against a C3 "harvest-now" adversary who records the receipt today and is later unbounded — **cannot be established in the standard model** for the class 𝒞 of showings this construction lives in: the receipt binds the witness through H(w‖r), whose statistical hiding is an artefact of the random oracle; and a standard-model statistically-hiding commitment before H is excluded from 𝒞 and not available black-box for a single-message receipt. Computational anonymity under the stated assumptions is what a PQ wrapper would give.

**Q19. Relation to existing credential-in-SNARK work (zk-creds etc.)?**
> Prior systems are pairing-based (not PQ) or static-circuit. This is, to our knowledge, the first empirical characterisation of a PQ credential inside a zkVM on consumer hardware — the contribution is the data point and cost model, not a new scheme.

**Q20. Could the precompile decision be automated?** (Ishikawa)
> Yes — a precompile generator with a soundness meta-theorem is the natural extension; the criterion is its objective function. (If crossover math is wanted: (U/P)* = (t_zkVM − t_static)/R_static — churn threshold; thesis quantifies both sides, leaves the same-scheme sign as a conjecture.)

**Q21. Who needs this? One concrete application.**
> BDEC's own setting: educational credentials — prove "I hold degree X" without revealing the transcript, valid and private for decades — hence post-quantum.

**Q22. The 58.5× / 164× numbers — measured where?** ✅ verified
> Both execute-mode. 58.5× = precompile-free vs Griffin-AIR cycles at λ=80; exceeds ℓ²=49 because the whole permutation collapses into ONE syscall. 164× = 19 cycles (matched, ℓ=1, KoalaBear single-limb) vs 3,121 (mismatched ℓ=7 bignum); exceeds 49 due to num_bigint library overhead — a conservative endpoint, not a scaling law. Never mix with prove-mode wall-clock.

**Q23. What breaks at 128 bits?** 
> Expected (not measured) to exceed 24 GB: hash parameters and repetition counts grow, and committed trace grows with them; the precompile-free arm already fails at 80. Say "expected," never "measured."

**Q24. Japanese one-minute summary.** Prepare 3 sentences: goal + two contributions + conclusion.

**Q34. Is this only feasible for AIR zkVMs and SNARK-friendly PRF-family signatures? How extensible is it?**
> Three layers — be precise about which extends. (1) **The criterion's form** (amortized removed work vs added fixed work, per proof) extends to any zkVM exposing precompiles; the thesis states the field-mismatch tax and update-churn dimension are *substrate-independent* — any large-field algebraic-hash signature in any small-field zkVM. (2) **The unit** — total committed area — is correct for the AIR/STARK class (SP1, RISC Zero, Cairo, OpenVM), whose provers price work in committed trace cells; a lookup-based (Jolt) or folding-based zkVM keeps the form but needs its own native cost unit and re-measured constants. (3) **The criterion is scheme-agnostic** (its inputs — emulated cost, table size, call count — exist for any scheme, including lattice ones); what is PRF-family-specific is the *feasibility outcome*: the ML-DSA proxy baseline was jetsam-killed (82.7 GB footprint) while PLUM completes. Magnitudes never transfer — which is exactly why matched-substrate comparison is future-work #1.

---

## 🔴 Five seams — know cold (verified against thesis + gaiyousho)

1. **91% (Q28)** — spoken-line fix required; see above.
2. **192 vs 199 + the composite prime.** "F_p^192" is a loose label; the concrete prime is 199-bit. Deeper: **PLUM's published modulus p₀ is composite (smallest factor 97 — a typo in their paper)**; you substituted a nearby 199-bit prime meeting the structural requirements (t=256 | p−1, 2-adicity ≥64), benign for measurements (cost tracks bit-width), carried as an explicit hypothesis in the security chapter. Rehearse once — it turns a gotcha into your best answer.
3. **Gaiyousho vs thesis on the Aurora cell.** Gaiyousho Table 1 footnote says "target 80-bit"; the thesis's ZK-enabled Aurora runs are **target 128, achieved 107.5 bits**. If cross-read: the gaiyousho footnote is the simplification; give the thesis numbers; either way a rough cross-scheme reference.
4. **Gaiyousho says "receipt" and "custom accelerator"** — the jury's document uses the words the deck standardised away. Bridge: "same objects — the deck standardises on 'default proof' and 'precompile'; the summary itself defines a precompile as a custom accelerator for a single operation."
5. **"Stopped at 5 h" ≠ out of memory** — watchdog stop at 5 h 07 m, peak 13.62 GiB (see Q25).

## If you rehearse only six answers:
**Q1 (novelty) · Q2 (issuance ZK — now exact) · Q6 (wrapper evidence, verbal-only) · Q12b (GPU — one sentence) · Q28 (the 91% line fix) · Seam 2 (the prime story).**
