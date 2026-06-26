# Thesis defensibility fix tracker (Sako two-dimensional attack, 2026-06-06)

Source: workflow `wyklx6agz` (10 agents, all high-severity findings re-verified against the .tex).
Sako verdict: **defensible on ONE proposition (the dual ZK/PQ obstruction), but mis-weighted under
five siblings + two self-contradictions.** Biggest gap = re-weighting + honest reframe, not new science.
The full Sako lens is now two-dimensional: MACRO framing (A→B/C→D, what-are-you-proving, curation,
so-what) + MICRO rigor (define-before-use, one canonical name, explicit algorithm I/O, sources) — the
latter extracted from her 28 margin comments on the BDEC draft (`Downloads/bdec_v1-wc.pdf`).

## PHASE 1 — writing-only, defensibility-critical
### 1a Correctness defects — DONE (build-clean, verified)
- [x] A1 `05:41` false "derived in B-2" cross-ref → self-contained derivation; p₀≡1 mod 3 / gcd(3,p−1)=1 VERIFIED by computation on the implemented 199-bit prime (p mod 3 = 2 ⇒ p₀ mod 3 = 1; cube IS a bijection — no soundness bug).
- [x] A2 `05:53` theorem "transfers unchanged" overstated `05:66` caveat → added premise **(T3)** (black-box I/O); "transfers unchanged" now conditioned on (T3).
- [x] A3 premise T2 named 4 ways → unified to **"the chip–constraint equality (premise (T2))"** across 05/06/08/appendices; preserved the chip–executor vs chip–constraint distinction.
- [x] A4 theorem covered non-existent RISC0 Griffin AIR → made platform-explicit (SP1 = Griffin AIR + bigint, (T2) applies; RISC0 = sys_bigint emulation, (T2) replaced by emulated-permutation I/O equality).
### 1b Headline alignment — DONE
- [x] S1 `01:51` 3-item-list headline → dual-obstruction proposition; agrees with `08`.
- [x] S2 reframed precompile/flexibility nulls as the **falsified-prediction arc** in the intro headline.
- [x] S5 led with the unconditional primitive prong (toolchain fact) as the spine.

### 1c Curation consistency — DONE (build-clean; S8 verified vs experiments.csv: headline Cell 2 ran at defaults, tuning only on the OOM'd wraps)
- [ ] S8 `06:70-77` scope the "reduced shards to fit" tuning paragraph to the ZK-wrap attempts; the 32.5-min Cell 2 ran at DEFAULTS per `experiments.csv` (VERIFY before editing — honesty claim).
- [ ] S9 `06:328` split the 82.7 GB ML-DSA datum out of the ZK-wrap frontier (it is a non-ZK baseline, `bench_pqc.rs:313`).
- [ ] S10 `06:149,326,583` disambiguate PLONK "~20 GB" (peak RSS 17.8 GB vs ~20 GB system pressure at kill).
- [ ] S7 `06:256` disambiguate the 56.4× (Griffin/λ80/Griffin-AIR) vs 37.9–70.5% ablation (SHA-3/λ128/bigint) triples.
- [ ] S6 `07:69` add crossover-sign-robustness sentence (PLUM-Fp199 static can only be slower than Loquat-Fp127 ⇒ sign survives the seam).
- [ ] S12 `06:497` add N_src/N_audit columns (or caption why prose-only) to tab:churn.

### 1d Notation/definition sweep — DONE (build-clean: B1 ShowCre input line; B2 pk_U-as-private-witness flagged; B3 AC↔BDEC mapping; B4 epoch t→e rename (no residue); B5 define-before-use in §4; B6 bare R^Sig defined as meta-var; B7 composite-STARK receipt removed; B8 dead R dropped; B9 false "equivalently" fixed; C1/C3 Griffin sponge+I/O specified from griffin_p192.rs; C2 N_circ counting rule; C4 R_vm img=digest clause)

PHASE 1 COMPLETE (1a+1b+1c+1d), all build-clean. Per Sako's verdict the thesis is now defensible; Phases 2–3 are the not-a-so-what + desk-reject-proof hardening.

ORIGINAL 1d checklist (all done above):
- [ ] B1 `03:611` add ShowCre "On input" line.
- [ ] B2 `03:625` add pk_U-as-private-witness clarifying sentence.
- [ ] B3 `03:502` add AC↔BDEC name-mapping block.
- [ ] B4 `03:512` rename epoch t→e (overloaded with PRF t=256).
- [ ] B5 `04:36-49` move let-clauses ahead of Def-4.1 display; type Pre⊆ops(Pred).
- [ ] B6 `04:84`/`055:84` define or eliminate bare R^Sig.
- [ ] B7 `04:13` define or delete "composite STARK receipt".
- [ ] B8 `04:62` drop dead regime variable R.
- [ ] B9 `055:70` fix "equivalently R_cre" (not equivalent; k+2 vs 2 predicates).
- [ ] C1 `05:47` resolve [NEEDS DATA]: WIDTH=4/CAP=2/RATE=2 from `griffin_p192.rs:42-44`; give the 2-to-1 compression def.
- [ ] C3 `03:42-46` Griffin I/O definition box (rate/capacity/width/rounds; cite 2022/403 params).
- [ ] C4 `03:746` add img=digest(P) clause to R_vm.
- [ ] C2 `04:62-80` operational counting rules for the 4 churn N-components.

## PHASE 2 — primary-source verification
### Number-verification pass — DONE (build-clean)
- [x] D1/D3 ALL PLUM numbers VERIFIED correct vs §3.3 p.123 / §4.2 p.125: 105,952 hash + 10,333 algebraic = 116,285 R1CS (1.28× < Loquat 148,825); 977 perms (30+69+878); t=256, β=0.961, L=2^12, B=28, m=4, n=7, η=4; 37KB (1.5× < Loquat 57KB). Citations added at point of use; λ=128 labelled. NOTE: PLUM timing figures are the paper's ESTIMATES "based on the implementation of Loquat" (Table 2 caption); the "4× faster" is "we expect"; Table 2's Griffin row (PLUM-128 t_V=2.75s vs SHA 0.053s) corroborates the inversion. Estimate-provenance note added to §3.
- [x] D2 Loquat 148,825 now cited to `cryptoeprint:2024/868` separately.
- [x] D4 Aurora citation VERIFIED correct: Thm 1.2 IS the zkSNARK result (polylog proof O(log²N), linear verifier O(N)); Thm 1.1 is the IOP (linear proof). TODO removed. (Aurora's own example uses a 192-bit field at 128-bit, 40–130 kB.)
- [x] D5 unsourced "2^24-domain FFTs (~17s)" softened to "the prover's low-degree-encoding FFTs" (not traceable in run logs; was my own edit).
- [x] D6 "two constraints exhibited in §5" repointed to the modular-multiplication reduction of ssec:bigint.

### Novelty pass — DONE (build-clean, all 8 rival cites resolve)
- [x] S3 7 rivals VERIFIED + cited + distinguished in §2 positioning paragraph; first-ness narrowed to "first measured algebraic-hash PQ anon-cred (BDEC+PLUM) in a general-purpose zkVM". pdf-read: Policharla 2023/414 (relation-specific STARK, lattice), BLNS 2023/560 (CRYPTO'23, lattice), Argo 2024/131 (CCS'24, lattice, <80KB/sub-s). web-verified: CAPSS 2025/061 (SNARK-friendly PQ sig framework), SoK:zkVM 2026/525 (AsiaCCS'26), zk-creds 2022/878 (S&P'23, classical pairing). engineering @misc: S2morrow (Cairo), Kota (Dilithium-in-SP1, Groth16-wrapped — corroborates the dual obstruction). 4 TODOs resolved (01:38, 02:52, 02:55-65, 04:23 SoK cite added).
- [x] S4 BDEC genericity VERIFIED from bdec_full.txt (Contribution I: "black-box access to a digital signature scheme and a zkSNARK"; Thm 1=unf, Thm 2=anon, Thm 3=unlink — mapping correct). Cited; "paywalled" TODO removed. NUANCE for A5/A6: BDEC anonymity/unlinkability (Thm 2/3) assume the SIGNATURE itself is ZK, not only the zkSNARK.

### Advantage-definitions pass — DONE (build-clean, proof-checker-verified)
- [x] A5 §3 now defines Adv^unf=Pr[wins], Adv^anon=Adv^unlink=|Pr[b'=b]-1/2|; unlinkability restated from ≈_c into a b'=b game with the oracle interface (mirrors BDEC AdvUNL).
- [x] A6/Q4 ε_AIR reframed to Pr[argument accepts a non-reference Griffin trace] over prover-trace + verifier randomness (type-correct probability); T2 = "ε_AIR negligible".
- [x] Q3 (BLOCKING gap proof-checker caught, now fixed): BDEC anon/unlink (Thm 2/3) simulate credential/pseudonym transcripts with the SIGNATURE's own simulator, but PLUM is only EU-CMA. Added open premise (T4) PLUM-simulatability + ε_sZK term; anon bound +ε_ZK→+ε_ZK+ε_sZK; unlink 2ε_ZK→2(ε_ZK+ε_sZK); two-hop derivation + glossary + open-premises summary (now T2,T4,QROM) all updated. Honest disclosure, not hidden. Draft+verdict: docs/a5a6_draft_20260606.md.

PHASE 2 COMPLETE (D + S3 + S4 + A5/A6). Open premises now disclosed: T2 (AIR soundness), T4 (PLUM simulatability), QROM lifts. Remaining: minor Arguzz cite (055); Phase 3 (gated).

### Advantage-definitions pass — (superseded; see DONE above)
- [ ] D1/D3 verify PLUM numbers (37KB / 116,285 / 91% / 105,952 / factor-4 / t=256 / L=2^12 / B=28) vs §3.3 p.123 & §4.2 p.125; add \cite at each use; λ=128 labels. (`references/978-981-95-2961-2.pdf` IS present.)
- [ ] D2 `03:268` cite Loquat 148,825 separately (`cryptoeprint:2024/868`).
- [ ] D4 `02:24` fix Aurora Thm 1.2→1.1 against the PDF.
- [ ] D5 `06:521` source or correct the 2^24-FFT/17s figure (circuit is 2^19-padded).
- [ ] D6 `055:174` repoint "two constraints" to `ssec:bigint`.
- [ ] S3 add 6 rival ref.bib entries + 1 distinguishing sentence each (Policharla 2023/414, zk-creds S&P2023, CAPSS 2025/061, BLNS/Argo 2024/131, S2morrow, Kota); narrow first-ness to "first PLUM-in-BDEC zkVM measurement".
- [ ] S4 BDEC genericity (`055:162`): quote the genericity hypothesis verbatim from ProvSec 2024, OR weaken in text; resolve Thm-1-3 mapping.
- [ ] A5 `055:36` add advantage-function defs to §3 for unf/anon/unlink; restate unlinkability in advantage form before the 2ε_ZK step.
- [ ] A6 `055:124` model ε_AIR as Pr[chip accepts non-reference trace], or carry T2 as a conditioning event (not an additive term).

## PHASE 3 — NEW MEASUREMENT / CODE — HUMAN REVIEW GATE before coding
- [ ] S11 Fractal re-run at smaller folding parameter for a FINITE large R_static (vs the OOM); else demote to qualitative + move RS caveat up.
- [ ] S13 ShowCre k=3 execute run to validate the additive model on a third point (within k≤4 target).
- [ ] C5 `03:677` the m_show-over-A↓ vs issuance-over-full-A gap may be a REAL construction/soundness defect (selective opening) → route to proof-checker BEFORE any code.
- [ ] S4-fallback if ProvSec 2024 inaccessible → weaken genericity claim in prose.

## Security-analysis structure (2026-06-06, workflow weeocg3bg — top-tier survey)
VERDICT: the thesis's structure is ALREADY top-tier-correct (defs in §3, premises-in-hypothesis preservation theorem in the §055 body, new-component AIR proof self-contained in the appendix, open premises flagged — the BLNS/Aurora/BDEC/zk-creds pattern done right for a thesis). The AIR-audit appendix is "the single best-supported structural choice in the document," NOT a deviation. Costly reorganizations CONTRAINDICATED (R3: don't move proofs; R4: don't add game-hopping — credential-composition exemplars use single-step extractor+simulator). Applied navigational relabels (build-clean): R1 appendix retitled "Evidence for Premise (T2)…"; R2 terse one-glance T1–T4+QROM premise-status list at the threat-model subsection (name+status, NOT a graded (A1) ledger); R5 PLUM Theorem~1 cited by number at ε_EUF + Loquat-carryover; R6 conservative-reading fallback posture for T4 + QROM. PLUM-vs-Loquat: KEEP PLUM headline + Loquat anchor (the "PLUM is an unvetted custom zkSNARK" worry is a misconception — PLUM = established components + Loquat-carried EU-CMA proof; same construction kind as Loquat).

## Security reductions formalized (2026-06-06, proof-checker ac618484 verified)
Rewrote the three §055 reductions to explicit-skeleton form (construct the reduction, tie each ε to a step). proof-checker caught TWO real bugs the compact prose hid + 3 more corrections, all applied (build-clean):
- Q-A: the bounds DOUBLE-COUNTED (BDEC Thm 1 verbatim already loses ε_EUF + knowledge-error). Dropped the abstract Adv^•_BDEC(B) terms; re-instantiation bounds now: unf ≤ ε_EUF+ε_KS+ε_AIR; anon ≤ ε_ZK+ε_sZK; unlink ≤ ε_ZK+ε_sZK.
- Q-B: unlinkability factor mismatch — §3 had a TWO-transcript game (2×) but BDEC Thm 3 is SINGLE-credential (1×). Aligned §3 (03:461+) to BDEC's single-credential game; §055 unlink now 1× with faithful Thm 3 citation.
- Q-C/D: ε_AIR + ε_KS enter unforgeability ONLY (extraction); anon/unlink are simulator-based (ε_ZK+ε_sZK), ε_AIR/ε_KS correctly absent. Anonymity hop RELABELED: BDEC Thm 2 = honest prover + zkSNARK ZK (not S_Π, which was Thm 3's mechanism); bound unchanged.
- Q-E: added "classical 𝒜 in the ROM" scoping; T4/ε_sZK marked open premise; the "ε_ZK not negligible on consumer HW ⇒ anon/unlink inherited-but-not-delivered" caveat kept. (\psk→\mathsf{psk} build fix.)
Drafts/verdict: docs/security_reductions_draft_20260606.md. This is the payoff of formalizing — the compact English hid a double-count and a game/factor mismatch.

## §6 + appendix formalised as a crypto paper (2026-06-06, proof-checker a6b75f2d verified)
Option (A) full formalisation, §6 + appendix ONLY (no §3, per Operator scope):
- Appendix: AIR soundness now Definition→Definition→Theorem→Lemma(round-fn, explicit Q_sq/Q_cube/Q_inv/Q_i/Q^mds/Q^rc)→Lemma(composition)→Lemma(completeness), all in \begin{proof} envs. Structural/lookup families (B-7/B-9/B-10) kept prose, per "prose only if needed."
- §6: Definition[zkVM-BDEC advantage] added (theorem LHS now defined); both proofs → \begin{proof}; threat-model unlinkability aligned to single-credential game (Q-B consistency).
- proof-checker VERDICT: all 5 constraint polynomials FAITHFUL to the actual Griffin round + AIR (worst-case wrong-polynomial did NOT occur). Applied C1-C4 (exhibition/attribution, not false-statement fixes): C1 explicit L_i; C2 symmetric circulant (j+col)%4 not (col-j)%4 (differ rows 1,3); C3 last-round RC=0 zero-padding; C4 B-9 threading is a lookup interaction under T1, not a polynomial.
- OPEN provenance link: the Griffin reference round shape is sourced to the in-repo reference impl griffin_p192.rs, NOT Griffin eprint 2022/403 (IACR blocks WebFetch). Action item: fetch 2022/403 to confirm the Rust reference faithfully implements Griffin-π.

## Body-sketch / appendix-formal split (2026-06-06, proof-checker aee437ad verified)
Per Operator's model: body = prose sketches + key points (readable); appendix = full formal math-paper development (auditable). §6 + appendix ONLY.
- §6: relation-preservation lemma + preservation theorem keep STATEMENTS + bounds; their proofs are now `\begin{proof}[Proof sketch]` (key points + which ε enters + open premises + pointer to appendix). Theorem stated ONCE in §6.
- Appendix A (new, app:preservation): "Formal Development of the Security Preservation" — 4 property-based Definitions (def:ks/eair/szk/zk: "∃ algorithm with error ε", premise asserts negligibility — keeps T4 honestly OPEN), full relation-preservation proof, 3 step-by-step theorem proofs (construct-ℬ unf; hybrids H0/H1/H2 anon; single-credential unlink), Corollary[Preservation under closed premises], Remark[BDEC re-instantiation]. AIR development = Appendix B.
- proof-checker VERDICT (sound to keep): item 1 (definitional care) PASS — def:szk keeps T4 open by routing existence to a premise, "the rare correct treatment"; item 2 (lockstep) PASS — appendix bounds match body eq:adv-unf/anon character-for-character, no drift. Applied required correction: T3 (PLUM EU-CMA black-box-reduction premise) now explicit in BOTH body theorem Suppose-clauses AND appendix unf proof. Polish: anon Leak-equality clause; corollary retitled (dropped "Unconditional").

## Cryptographic rigor pass (2026-06-07, workflow wijtg2uqd: 8 dims, 32 agents + proof-checker a2f8290d)
VERDICT: no dimension below the bar; spine "exemplary" (premise architecture, T2 coverage-vs-soundness, error-term composition, gcd bijection guard, verified params — DO NOT TOUCH). 14 confirmed-real findings (rest false-positive, incl. gcd/d=3/14-round which is machine-verified).
HIGHEST-LEVERAGE done + build-clean:
- (I) Front matter conditionality: intro non-goal now names open premises (T2/T4/QROM); abstract drops unmeasured "Noir" arm + unsourced "three hours" (→ OOM at 1m45s).
- (II) Proof obligations (proof-checker a2f8290d gave exact text, all closable by written argument):
  - D4-3 anonymity terminal step (the one QED that didn't follow): now accounts for EVERY b-dependent statement component — A↓ + TA-pseudonym multiset equalised by Leak (Leak redefined in §3 to include the multiset), ppk_UV freshly sampled (b-independent), witness simulated by S_σ/S_Π.
  - D4-2 ε_sZK: load-bearing in BOTH props (role = produce credential/psk without sk_U); BDEC A.2/A.3 cites pinned; disclosed that thesis moved c_UV from BDEC's statement to its witness (re-derivation, NOT verbatim re-instantiation — flagged in Remark).
  - D3 L_i law: B-3 now reconstructible — L_2=s0^nl+s1^nl explicit, α_{i-2}=(i-1)α, β_{i-2}=(i-1)²β, SHAKE256 seed "PlumGriffin(p,4,2,128)". def:ref-perm tightened.
  - Also fixed: Leak defined, T1 mis-cite downgraded (bensasson2016iop can't source a 2022+ lookup arg), my own RC=0 error (52-entry table, RC on first 13 rounds).
§A polish DONE (build-clean): T3 grading reconciled (summary now "four inputs" incl. T3 argued-not-audited), epoch subscript rt_{*,t}→rt_{*,e} (epoch defined as e at 03:485; 0 stragglers), Griffin §3 inverse+Horst added, LDT layer-qualified (03:333 Aurora's outer / 04:90 PLUM's inner STIR), "14 rounds" presented as derived+code-checked, ε_EUF def:euf added to appendix building-blocks.
GRIFFIN-LAW VERIFIED (researcher-agent a9e2e0fb): code's L_i=(i-1)z0+z1+z_{i-1} + α_{i-2}=(i-1)α, β_{i-2}=(i-1)²β MATCHES two independent reference impls (authors' IAIK Rust + Nashtare SageMath) — verified code-vs-code; paper-text itself IACR-403-blocked (one epistemic notch below, strongly corroborated). Citation UPGRADED: ref.bib cryptoeprint:2022/403 @misc→@inproceedings CRYPTO 2023 (LNCS 14083, pp.573-606), ePrint kept as full-version note. (Venue is CRYPTO 2023 not USENIX — thesis ref.bib was already correct.)
REMAINING: (1) OPEN premises (disclose, don't close): T2, T4, QROM lifts, prime substitution. (2) OPTIONAL code follow-up (strongest Griffin-law close): add a known-answer test against IAIK reference vectors (currently absent). (3) banked: k=3 ShowCre cost-model point (23.5e9 cyc). (4) parked: RISC0 CreGen prove (not load-bearing).

## Build status
All edits build-clean (latexmk, 0 undefined refs). Uncommitted on `master`.
