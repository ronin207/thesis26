# Security-Assumptions Literature Review

Grounding pass for every named assumption in `修論2025_Takumi/055-security.tex`.
Produced from four parallel deep-research streams (external literature, fetched
sources) plus two source-of-truth verifications (Griffin/AO-hash security against
paper+code; proving-system params against the deployed SP1 fork). **Not written
from recall** — every claim below traces to a fetched source or a repo file:line,
and items that could not be verified from primary text are marked UNVERIFIED
rather than filled from memory.

**Access caveat (applies throughout):** IACR eprint serves abstract/metadata HTML
but 403s the `.pdf` path to the fetchers used. So bibliographic data and abstracts
are PRIMARY; several *theorem bodies* (Basefold KS, logUp soundness, Bellare
IK-CPA definition, vDHI single-query theorem) are SECONDARY (abstract + reputable
paraphrase). To quote an exact theorem/bound in the thesis, open that PDF in a
browser first. Repo-grounded facts (SP1 params, the Griffin hasher) are PRIMARY.

---

## 0. The standout finding (not a literature item — code-grounded)

**Griffin-Merkle collision resistance is birthday-capped at √p ≈ 2^99.5 by the
deployed digest width, independent of round count and before any algebraic attack.**

Evidence, `src/primitives/hash/hasher_plum.rs` (verified by direct read):
- `:38` `PLUM_DIGEST_BYTES = 32`; `:37` comment: 64-byte (2-lane) Griffin digest, "we keep the first 32 bytes for compatibility with the SHA3 path."
- `:101-107` leaf `finalize_bytes` keeps the first 32 bytes → one `Fp192` element.
- `:109-146` `compress_pair` (Merkle 2-to-1) loads lanes `[left,right,0,0]`, runs one permutation, outputs `state.lanes()[0]` only (`:141`) → one ~199-bit element (masked at `:123-124`).
- `src/primitives/merkle/plum.rs` builds/verifies the whole tree on these 32-byte digests.

Two floors, over p ≈ 2^199:
- **Capacity floor** (sponge internal, 2 field elements ≈ 398 bits): 2^199 — not binding.
- **Output floor** (deployed 1-element Merkle digest): **√p ≈ 2^99.5 — binding.**

Consequence: clears the measured **λ=80** (2^99.5 ≫ 2^80); sits **below λ=128**
(2^99.5 < 2^128). Mirrors the power-residue-PRF √p ceiling exactly — the thesis
already states 2^99.5 for the PRF (`055-security.tex:111-115`) but has **not** made
the parallel statement for Griffin-Merkle CR. That is the disclosure gap.

Caveats: (i) the 1-lane truncation is annotated as a repo choice ("SHA3-path
compatibility"); whether canonical Loquat/PLUM keeps 1 or 2 lanes per node is
UNVERIFIED (local Loquat PDF has no extractable Griffin text). The *deployed*
(measured) instance keeps 1. (ii) Fixable orthogonally to rounds: keep the 2nd
lane per node → output floor returns to 2^199.

**This does not break asm:griffin-cr at λ=80; it means asm:griffin-cr cannot
honestly be read as 128-bit for the Merkle role.** Recommend a one-line disclosure
in asm:griffin-cr. Operator's call on wording (his lane).

---

## 1. Action summary

| # | Assumption | Verdict | Primary action |
|---|---|---|---|
| air | Griffin-AIR constraint soundness | open, correct — **under-cited** | name the standard notion (circuit uniqueness / under-constrained) + tools QED2, Picus |
| szk | PLUM transcript simulatability | faithful, open honest — **under-cited at assertion** | cite Loquat Thm 1 + §3.5 (BCS ZK-preservation); BCS already in bib |
| keypriv | Credential-signature key-privacy | faithful — **thinnest bib in the thesis** | add Bellare-Boldyreva-Desai-Pointcheval'01 + Bobolz et al.'21; label the decomposition as the thesis's own gap-repair |
| qrom | Griffin (Q)ROM instantiation | standard move + real AO-hash caveat — **no external cite** | add DFMS'19, Grilo et al.'21, Bertoni'08, Alagic et al.'25 |
| griffin-cr | Griffin collision resistance @ 14 rounds | defensible-as-assumed @ λ=80 — **2 items** | add the 2^99.5 output floor (§0); re-source the line-282 instance params |
| q1 | Power-residue PRF Q1 hardness | standard + honestly-scoped — **1 misattribution** | re-attribute p/L² to Beullens et al.'20 (add it; it's also the sole t>2 analysis) |
| lookup | LogUp cross-table binding | faithful in form — **wrong protocol cited** | add LogUp-GKR (Papini-Häböck 2023/1284); deployed arg is GKR not plain logUp |
| bbt | Black-box transfer of EUF-CMA | routine, faithful — **done** | optional: name Bellare-Rogaway ROM / Reingold-Trevisan-Vadhan |
| (εKS) | SP1 knowledge soundness | sturdiest, verified to source-comment level | add BCIKS'20 + Häböck'24 list-decoding; fix "blow-up 2" wording |

---

## 2. Per-assumption entries

### asm:air — Griffin-AIR constraint soundness (D1)
- **Standard notion, named:** "AIR satisfied only by the reference computation" = the circuit **uniqueness property** = absence of an **under-constrained** witness. The thesis presents it as bespoke; it is a named, tooled concept.
- **"not machine-checked = open" is correct:** SMT-based uniqueness checking (QED2/Picus/Ecne) is the accepted discharge method; 256-vector KAT + fault injection is exactly the *incomplete* evidence those tools are built to replace.
- **Canonical sources (PRIMARY bib; verbatim def UNVERIFIED — hosted PDF unparseable):**
  - Pailoor, Wang, Feng, Chen, Wang, Rao, Dillig, "Automated Detection of Under-Constrained Circuits in Zero-Knowledge Proofs," IACR ePrint 2023/512, **PLDI 2023** (PACMPL 7(PLDI); corrected from OOPSLA per DBLP), DOI 10.1145/3591282 (tool **QED2**).
  - **Picus** (Veridise), "uniqueness property for ZKP circuits," github.com/Veridise/Picus.
- **Missing:** the two above; optionally Ecne / Circomspect. Lets you write "we decline to machine-check uniqueness *in the sense of [QED2]*" — scoped, not vague.
- **Could-not-verify:** whether any published tool targets **AIR** uniqueness specifically (confirmed tools target R1CS/Circom).

### asm:szk — PLUM signature-transcript simulatability (B1) [PRIMARY: local PDFs read]
- **Faithful; "open" is honest.** Mechanism = masked-HVZK IOP → simulatable non-interactive proof via BCS (the analog of "FS of an HVZK Σ-protocol yields a simulatable NIZK"). Standard, and the ingredients exist.
- **Verbatim support (read from PDFs):** Loquat Thm 1 ("complete, knowledge sound, and zero-knowledge"); Loquat §3.5 ("BCS transform … preserves the proof-of-knowledge and zero-knowledge properties"); Loquat Rmk 2/3 (masking); PLUM Alg 4 Phase 3 ("Enable ZK of Univariate Sumcheck").
- **Under-cited at the point of assertion** (`:95` cites nothing for the mechanism). Add Loquat Thm 1 + §3.5 + BCS = Ben-Sasson-Chiesa-Spooner TCC 2016 (**already in bib**, `bensasson2016iop`). Optional lineage: Chase et al. CCS'17; Katz-Kolesnikov-Wang CCS'18.
- **The genuine gap (why "open" is right):** no paper states the exact simulator-*with-error-bound* that Def:szk consumes; Loquat argues ZK via masking remarks, not a fully specified simulator. Small, real.

### asm:keypriv — Credential-signature key-privacy (B2) [PRIMARY: local PDFs read]
- **Thinnest bibliography in the thesis:** "key-privacy" named with **zero** citation (grep: no "Bellare"/"Bobolz"/"issuer"/"anonymous signature" in source or ref.bib).
- **Property is standard, with a canonical name:**
  - Bellare, Boldyreva, Desai, Pointcheval, "Key-Privacy in Public-Key Encryption," ASIACRYPT 2001, LNCS 2248:566-582 — origin of "key-privacy" (IK-CPA/IK-CCA). asm:keypriv (indistinguishability of c under pk_0 vs pk_1 on a **common message**) = exactly the Bellare game, transposed to signatures.
  - Bobolz, Eidens, Krenn et al., "Issuer-Hiding Attribute-Based Credentials," CANS 2021, LNCS 13099:158-178 / ePrint 2022/213 — the credential-layer analog.
- **Distinguish (do NOT cite as the definition):** Yang-Wong-Deng-Wang PKC'06 / Fischlin PKC'07 "anonymous signatures" condition on *message entropy* — NOT the common-known-message notion. Adjacent only.
- **The decomposition is the thesis's OWN contribution, not BDEC's:** BDEC App. A.2 simulates the credential under a *random* pk_U* (verbatim: "S selects a random long term public key pk_U* … invokes S_σ with (h*, pk_U*)") and bundles both halves under "owing to zero-knowledgeness." Only simulator-without-sk = simulatability (szk); simulation-under-random-pk = key-privacy. **The thesis split repairs a gap BDEC left informal.** Label it as the thesis's analysis, not "BDEC already separates these."
- **Falsifiability (the concrete test):** PLUM's T_{i,j}=L_0^t(o)−pk commitments are pk-dependent; whether they leak pk across two keys is exactly the open question.
- **Live frontier (optional adds; corroborates "open for PLUM" — none gets issuer-hiding generically from EUF-CMA):** Katz-Sefranek 2025/2080; "Issuer-Hiding for BBS via Randomizable Keys" 2026/369; Bobolz et al. 2026/555.
- **Could-not-verify (bib-level; open PDFs before a precise formal cite):** verbatim IK-CPA/IK-CCA text; verbatim issuer-hiding def (2022/213 403'd); YWDW anonymity body.

### asm:qrom — Griffin (Q)ROM instantiation (A2)
- **The move is standard and proven; the AO-hash instantiation caveat is real and sharper than for SHA-3.** Modeling a hash as a (Q)RO for Fiat-Shamir is textbook; instantiating the RO by a *sponge* is justified via indifferentiability, which **requires the permutation to be ideal** — and the Griffin attack literature (asm:griffin-cr) is direct evidence Griffin's permutation is not. So: standard assumption + non-standard load-bearing caveat. "open … upstream of the AIR" framing is correct. Coupled to asm:griffin-cr (same ideal-permutation premise).
- **Canonical sources (PRIMARY bib; tightness bounds UNVERIFIED):** the thesis currently cites **nothing external** here. Add:
  - Don, Fehr, Majenz, Schaffner, "Security of the Fiat-Shamir Transformation in the QROM," CRYPTO 2019, ePrint 2019/190.
  - Grilo, Hövelmanns, Hülsing, Majenz, "Tight adaptive reprogramming in the QROM," ASIACRYPT 2021, ePrint 2020/1361 — the EUF-CMA-signature lift.
  - Bertoni, Daemen, Peeters, Van Assche, "On the Indifferentiability of the Sponge Construction," EUROCRYPT 2008, LNCS 4965:181-197 — instantiation bridge + ideal-permutation caveat.
  - Alagic, Carolan, Majenz, Tokat, "The Sponge is Quantum Indifferentiable," 2025, arXiv 2504.16887.
- **Could-not-verify:** that PLUM's proof literally models Griffin as a QRO (PLUM not re-fetched for this) → cite the exact PLUM theorem inherited. Canetti-Goldreich-Halevi ROM-uninstantiability NOT fetched — verify before citing.

### asm:griffin-cr — Griffin collision resistance at deployed parameters (A1)
- **Bottom line (SOT-verified):** DEFENSIBLE-AS-ASSUMED at the measured λ=80 instance; NOT defensible as 128-bit CR. The operative threat is the **output-length floor** (§0), not the 2026 algebraic result.
- **The 2026 result (2026/1281, `bak2026resultants`) does not reach the thesis instance:** abstract (verbatim, fetched): "…full-round instances of Anemoi and Griffin in the CICO-2 setting for the first time." But (a) CICO-2 ≠ collision (permutation-structural; voids the ideal-permutation premise but does not exhibit a collision), and (b) the Griffin instance is the small-field t=12/≈55-bit/10-round benchmark, NOT t=4/199-bit/14-round. Instance parameters UNVERIFIED (PDF 403); reasoned from abstract phrasing ("practical," "implementation confirms") + benchmark lineage.
- **Provenance nit to fix:** `055-security.tex:282` states "full-round (10/10) … t≥12, ≈55-bit" as if sourced from `bak2026`; those specifics are NOT in that paper's accessible text — they come from the FreeLunch/Resultant benchmark. Re-source, or soften to "on the small-field benchmark instances of the FreeLunch/resultant line."
- **Round margin (SOT-verified against code + guarded facts):** 14 rounds at t=4/199-bit is OUTSIDE the broken regime (broken instances t=12/55-bit/10-round, same S-box degree d=3, separated by width/field/rounds). Griffin's own Table 2 (2022/403) → R=15 for (d=3,t=4,κ=128) [guarded fact, 2022/403 not re-opened this session]; the repo's scaled heuristic (`griffin_p192.rs:469-502`) yields 14, one below. The thesis already discloses this exactly (`:282` + Table `tab:round-margin`). Correct, matches code.
- **Canonical sources (PRIMARY bib via abstracts/slides; full-round bit-complexity UNVERIFIED — PDFs 403'd):**
  - Grassi, Hao, Rechberger, Schofnegger, Walch, Wang, "Horst Meets Fluid-SPN: Griffin…," CRYPTO 2023, ePrint 2022/403.
  - Bariant et al., "The Algebraic FreeLunch…," CRYPTO 2024, ePrint 2024/347 (CICO 7/10) — **in bib**.
  - Bariant et al., "Improved Resultant Attack…," CRYPTO 2025, ePrint 2025/259 (CICO 8/10) — **in bib**.
  - Bak, Bariant, Hostettler, Neiger, "Resultants Meet Resultant…," ePrint 2026/1281 (full-round CICO-2) — **already cited** (`bak2026`).
  - Candidate lineage adds: CheapLunch (2025/2040), Yang et al. Asiacrypt 2024 (Griffin-specific numbers UNVERIFIED).
- **Dependency to state:** the deployed Griffin was earlier a non-MDS variant, FIXED to standard + KAT-validated; the published analyses transfer **only** because the deployed permutation now matches the standard spec. Worth an explicit line.

### asm:q1 — Power-residue PRF Q1 key-recovery hardness (C)
- **Standard in structure, honestly-scoped.** Q1/Q2 framing, classical √p ceiling, and the vDHI Q2 caveat are all textbook-standard and correctly deployed. The one genuine gap — t=256 Q1 hardness *inherited* from t=2 (no published t>2 Q1 analysis) — is correctly flagged as open.
- **Confirmed misattribution (`:111`):** the operative **p/L²** (quadratic-in-data, 2^175) bound is credited to Khovratovich (who gives the *linear* p/L) and May-Zweydinger (who give *preprocessing* tradeoffs). The quadratic form is **Beullens-Beyne-Udovenko-Vitto**, "Cryptanalysis of the Legendre PRF and Generalizations," ToSC 2020(1):313-330 / ePrint 2019/1357 (abstract verbatim: "reducing the time complexity from O(p log p/M) to O(p log² p/M²) … when M ≤ ⁴√(p log²p)"). **This same paper is the sole dedicated t>2 (power-residue) analysis** — load-bearing on two counts, and MISSING (the `beullens` in bib is `beullens2020legroast` = LegRoast, a different paper).
- **Minor numeric:** `:115` "≈2^183 with a single log p factor" — Beullens' bound carries log²p → ≈2^190. Qualitative point (≫2^99.5) robust; recommend "up to polylog" or explicit log².
- **Cleared (my-prompt artifacts, checked against actual bib):** khovratovich2019legendre title ✓, may2022legendre title ✓, frixons2021quantum = Frixons & Schrottenloher, ePrint 2021/149 ✓ (the right Q1 paper, not the boomerang paper).
- **All numeric claims SUPPORTED by real sources:** 2^99.5 ceiling (Khovratovich 2019/862); 2^175 operative (Beullens 2019/1357); coincidence at L=p^{1/4}≈2^50 (Beullens' M ≤ p^{1/4} boundary); Q2 poly-time t=2 break (van Dam-Hallgren-Ip, SIAM J.Comput 36(3):763-778); Q1 open for t>2 (Frixons-Schrottenloher is t=2 only).
- **Optional adds:** Kaplan et al. CRYPTO 2016 (Q1/Q2 terminology anchor); Seres-Horváth-Burcsi AAECC 2023 (algebraic/MQ view); Pegasus 2025/1841 (already known).
- **Could-not-verify:** vDHI single-superposition-query theorem body; Frixons-Schrottenloher exact Q1 exponents beyond O(√p); whether Pegasus cryptanalyzes t>2 directly (abstract = scheme+proof only).

### asm:lookup — LogUp cross-table binding (D2) [PRIMARY: SP1 source read]
- **Faithful in form:** the property ("the lookup argument binds the multiset+range conditions") is the standard accepted soundness guarantee; the bound ε ≤ (entries·degree)/|K| is the standard Schwartz-Zippel accounting for a rational-identity check. |K| = KoalaBear^4 ≈ 2^124 VERIFIED (`slop/crates/basefold/src/config.rs:41`).
- **Citation defect:** SP1 deploys **LogUp-GKR** (Papini & Häböck, ePrint 2023/1284) — evidence `crates/recursion/circuit/src/logup_gkr.rs`, `crates/hypercube/src/logup_gkr/`, `grinding_bits_lookup = GKR_GRINDING_BITS`. The thesis cites only plain logUp (`haback2022logup` = 2022/1530). The M·d/|K| number survives (GKR soundness is also per-round Schwartz-Zippel over K), but the citation points at the wrong protocol. **Add 2023/1284.**
- **Optional:** Eagen-Häböck 2024/2067 (characteristic-bound side condition — fractional-sum needs char > max multiplicity; holds over KoalaBear char≈2^31, currently unstated); Lasso 2023/1216, plookup 2020/315 as landscape.
- **Could-not-verify:** Häböck's verbatim soundness theorem/numbering (PDF 403); as-instantiated byte/cross-table soundness (thesis leaves this open — not a literature question).

### asm:bbt — Black-box transfer of PLUM's EUF-CMA reduction (B3) [PRIMARY: local PDFs read]
- **Routine and well-grounded — done.** Already cites PLUM §3.2 with a faithful near-verbatim paraphrase ("building blocks … treated as black boxes … carry over from Loquat"). PLUM Thm 1's reduction manipulates F_p values + the RO interface, never an internal representation; `rem:field-boundary` correctly notes it "operates on F_p values, not limb encodings."
- **Optional only:** name the general principle — Bellare-Rogaway "Random Oracles Are Practical" CCS 1993, and/or Reingold-Trevisan-Vadhan "Notions of Reducibility…" TCC 2004. Indifferentiability (Maurer-Renner-Holenstein) NOT needed — the substitution is value-level, not a hash-construction swap.

### (bonus) ε_KS — SP1 knowledge soundness (D3) [PRIMARY: SP1 source read]
- **Sturdiest of all — verified to the source-comment level in the deployed fork:** `CORE_LOG_BLOWUP = RECURSION_LOG_BLOWUP = 2` → rate 1/4 (`fri_params.rs:5-6`); target 100 bits, 16 grinding (`:44-45`); query count via `fn unique_decoding_queries` → ⌈84/0.678⌉ = 124 (reproduced); `udr_only = true` (`gen_soundcalc_toml.rs`). The "94-query/rate-1/2/conjecture" config is `default_fri_config` with verbatim comment "relies on a conjecture … increased the number of queries to 94 … Gruen and Diamond's recent result," used in test/scaffold/`slop-veil` only. Thesis quote + 84→94 attribution EXACTLY correct.
- **Strength to state explicitly:** deployed config is UDR-only → ε_KS does NOT depend on the contested list-decoding proximity-gap conjecture.
- **Add 2 canonical refs:** Ben-Sasson-Carmon-Ishai-Kopparty-Saraf, "Proximity Gaps for Reed-Solomon Codes," FOCS 2020 / ePrint 2020/654 (the UDR proximity-gap bound the 124-query count rests on); Häböck, "Basefold in the List Decoding Regime," ePrint 2024/1571 (the exact cite for "original extractor proven only at UDR; list-decoding needs conjectures").
- **⚠️ Terminology fix (load-bearing):** "blow-up 2" reads as rate-1/2 to a STARK reader — the exact *conjectured* regime the thesis is excluding. You mean log-blowup 2 = factor 4 = rate 1/4. Spell it out wherever it appears.
- **Minor:** "Gruen and Diamond" reversed vs published "Diamond and Gruen" (matches SP1 source comment; bib has correct order).
- **Could-not-verify:** verbatim Basefold KS theorem body + logUp soundness body (PDFs 403). Fetch from a browser if quoting exact bounds.

---

## 3. Master could-not-verify list (open PDFs before quoting these verbatim)
1. Basefold (2023/1705) KS theorem body + error expression + numbering.
2. logUp (2022/1530) soundness theorem body + numbering.
3. 2026/1281 Griffin instance parameters (field, t, rounds) — full-round CICO-2 confirmed at claim level only.
4. FreeLunch (2024/347) / Improved-Resultant (2025/259) full-round Griffin bit-complexity tables.
5. Bellare et al. IK-CPA/IK-CCA verbatim definition; Bobolz issuer-hiding verbatim definition.
6. van Dam-Hallgren-Ip single-superposition-query theorem statement.
7. Griffin design round formula (2022/403 Table 2 → R=15 for d=3,t=4 is a guarded prior fact, not re-read this session).
8. Whether canonical Loquat/PLUM Merkle keeps 1 or 2 lanes per node (the deployed instance keeps 1; §0).
9. QED2 (2023/512) verbatim uniqueness definition + full author list.

---

## 4. Peer-review status + Related-Work impact (workflow-verified vs DBLP, 2026-07-15)

**Method:** verified each source against DBLP/venue, NOT the IACR "Preprint" label — that label is demonstrably unreliable (IOP 2016/116, Lasso 2023/1216, Grilo 2020/1361 all self-report "Preprint" yet are refereed).

**Peer-reviewed:** Bellare-BDP ASIACRYPT'01 · DFMS CRYPTO'19 · Grilo ASIACRYPT'21 · Bertoni EUROCRYPT'08 · Griffin CRYPTO'23 · FreeLunch CRYPTO'24 · Improved-Resultant CRYPTO'25 · Yang-Resultant ASIACRYPT'24 · Beullens ToSC'20 · May-Zweydinger CSF'22 · vDHI SIAM'06 (+SODA'03) · Frixons-Schrottenloher ToMC'22 (FLVC diamond-OA, refereed) · Damgård CRYPTO'88 · Kaplan CRYPTO'16 (DISAMBIGUATE: same authors also have ToSC 2016(1) — match the title) · Seres AAECC'23 · Basefold CRYPTO'24 · BCS/IOP TCC'16 · Diamond-Gruen CiC 1(4) 2025 · QED2 PLDI'23 · Lasso EUROCRYPT'24 · KKW CCS'18 · Bobolz CANS'21 · Yang PKC'06 · Fischlin PKC'07 · Katz-Sefranek PKC 2026 (cite the PKC version, not just eprint).

**Preprint-only (NOT refereed):** Khovratovich 2019/862 · Pegasus 2025/1841 · logUp 2022/1530 · LogUp-GKR 2023/1284 · Basefold-list-decoding 2024/1571 · Eagen-Häböck 2024/2067 · Bak 2026/1281 · CheapLunch 2025/2040 · Alagic sponge-quantum-indiff 2025/731 (arXiv 2504.16887) · Flamini-Friedrichs-Lehmann 2026/369 · 2026/555 (author/title MISLABELED in earlier notes — do NOT cite on label alone).

**Documentation (self-published, not refereed):** ethSTARK 2021/582 — cite strictly as vendor docs.

### Related-Work (§2) impact — adversarially checked against the actual 02-related.tex
- **Genuine §2 gaps (only 2, both narrow):** Lasso EUROCRYPT'24 (§2:30 describes Jolt's lookup approach with no cite for the lookup argument; bib's `Setty` is Jolt not Lasso); KKW CCS'18 (§2 cites Picnic/Banquet/Limbo but not the NIZK technique underneath). Both peer-reviewed + confirmed absent.
- **Conditional (off-topic as §2 stands):** Bobolz CANS'21 + Katz-Sefranek PKC'26 (issuer-hiding) — peer-reviewed + uncited, but §2's AC subsection frames classical ACs (Chaum/CL/PS/Coconut/BBS). Add only if building an issuer-hiding/eIDAS-flexibility thread.
- **Already cited (not gaps):** Griffin (bib+used), Basefold (055:254). At most an inline `\cite` in §2 prose.
- **Belongs in §055 not §2:** the whole PRF-cryptanalysis / QROM / AO-attack / proximity-gap / under-constrained-tooling / key-privacy-definition set. Routing to §2 would misfile.
- **Honesty item (§055, not §2):** SP1 soundness lineage rests partly on non-refereed work — logUp, LogUp-GKR, Basefold-list-decoding (preprints; two not in bib), ethSTARK (docs). ε_KS is UDR-only so it stands on peer-reviewed Basefold+proximity-gaps; the lookup-binding + STARK-framing cites are the preprint-leaning ones. Worth one disclosing sentence.
- **Corrections to §1-2 of this doc:** QED2 = PLDI'23 not OOPSLA; Katz-Sefranek IS peer-reviewed (PKC'26); the 2026/369 + 2026/555 issuer-hiding labels were wrong.
