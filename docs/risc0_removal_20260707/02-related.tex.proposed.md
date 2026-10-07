# PROPOSED edits — strip RISC Zero, retarget `02-related.tex` to SP1-only

**Status: PROPOSAL ONLY. Nothing applied to the manuscript.** This is a framing / contribution chapter; the operator must review before anything lands.

**File:** `修論2025_Takumi/02-related.tex`
**Hard constraints honoured:** "RISC-V" / "RISC~V" left untouched (base ISA SP1 uses); no sentence partly about SP1 deleted (reworded instead); all non-RISC0 sentences, every `\ref`/`\label`/`\cite` (except the RISC0 ones) preserved; no facts invented.

**Coverage:** 6 RISC-Zero-related sites in the file. 4 are direct RISC0/R0VM/Zirgen content edits (§1–§4 below). 1 is a coherence retarget of a plural "zkVMs'" phrase (§5). 1 is a third-party citation I recommend **KEEP** because editing it would invent a fact (§6). No `\ref`/`\label` is orphaned by any edit.

---

## 1. Line 34 — RISC Zero bullet in the zkVM-designs list  ⟶ DELETE whole bullet  [CONTRIBUTION-SCOPE FLAG]

**Current:**
```
  \item \textbf{RISC Zero}~\cite{bruestle2023risczero} is a RISC-V zkVM whose prover is a recursive STARK over the BabyBear field. Application-defined precompiles are supported via the Zirgen big-integer dialect.
```

**Proposed (SP1-only):** delete this `\item` line in its entirety. The `itemize` block then contains two bullets, SP1 (line 35) and Jolt (line 36). The lead-in "Several zkVM designs are mature enough to be considered for credential-system deployment:" (line 31) still reads correctly with two items.

**Rationale:** The bullet is pure RISC Zero content (RISC Zero name + Zirgen big-integer dialect + `\cite{bruestle2023risczero}`); no SP1 text is entangled, so deletion is clean.

**Scope note for operator:** This narrows the set of zkVMs the chapter presents as "considered for credential-system deployment" from {RISC Zero, SP1, Jolt} to {SP1, Jolt}. It is framing, not a "we built X" claim, but it is the chapter's stated substrate landscape — your call. `\cite{bruestle2023risczero}` is still used in 5 other chapters (01-intro, 03-preliminaries, 04-theoretical, 05-system, 055-security), so the bib entry is **not** orphaned by this deletion.

---

## 2. Line 43 (sentence 1) — R0VM 2.0 speedup example  ⟶ DELETE sentence  [EVIDENCE-REMOVAL FLAG]

**Current:**
```
The R0VM~2.0 release adds precompiles for BN254 and BLS12-381 elliptic-curve operations and reports reducing Ethereum block-proving from approximately $35$ minutes to approximately $44$ seconds~\cite{risczero2025r0vm2}.
```

**Proposed (SP1-only):** delete this sentence (and its trailing space) so the paragraph goes straight from "…has been applied to several primitives." to "Each such precompile introduces a primitive-specific arithmetisation…".

**Antecedent check:** the next sentence begins "Each such precompile…"; after deletion "such" refers back to the paragraph's opening "The general technique … a native AIR-based sub-circuit … applied to several primitives." The prose still flows (verified reading: "…applied to several primitives. Each such precompile introduces a primitive-specific arithmetisation…").

**Rationale:** R0VM is RISC Zero's zkVM; the 35 min → 44 s figure is a RISC0 measurement/number/claim and `\cite{risczero2025r0vm2}` is a RISC Zero citation — both fall under "remove all RISC0 numbers/claims entirely."

**Scope note for operator:** (a) This removes a piece of external *feasibility/motivation* evidence (that precompiles yield large speedups). It is third-party evidence, not one of the thesis's own contribution claims, so no thesis claim narrows — but the motivation paragraph loses one data point (the community-RSA "two orders of magnitude" footnote on line 44 remains). (b) `risczero2025r0vm2` is cited **only** here in the whole thesis, so after this deletion it becomes an *unused* bib entry in `ref.bib`/`main.bbl`. That is harmless for compilation (an uncited entry simply does not appear in the bibliography after re-running bibtex; it is not a broken reference), but you may want to delete the entry from `ref.bib` for tidiness. **Alternative if you would rather keep the evidence:** there is no way to keep the 35 min → 44 s number without RISC Zero attribution (it is specifically R0VM 2.0's figure), so keeping it means keeping a RISC Zero mention — your call.

---

## 3. Line 43 (Arguzz sentence) — RISC Zero soundness-bug / \$50k-bounty clause  ⟶ DELETE clause, keep the sentence

**Current (full sentence):**
```
Arguzz~\cite{hochrainer2025arguzz}, a metamorphic-testing fuzzer for soundness and completeness bugs in zkVMs, found eleven such bugs across six zkVMs, including a RISC Zero soundness bug that earned a \$50{,}000 bounty despite prior audits; results of this kind motivate the written soundness arguments that accompany the precompile in this thesis.
```

**Proposed (SP1-only):**
```
Arguzz~\cite{hochrainer2025arguzz}, a metamorphic-testing fuzzer for soundness and completeness bugs in zkVMs, found eleven such bugs across six zkVMs; results of this kind motivate the written soundness arguments that accompany the precompile in this thesis.
```

**Exact change:** delete the clause `, including a RISC Zero soundness bug that earned a \$50{,}000 bounty despite prior audits`.

**Rationale:** The deleted clause is a RISC0-specific claim/number (the \$50,000 bounty on a RISC Zero bug). The general Arguzz finding — eleven bugs across six zkVMs — is not RISC0-specific and is preserved, keeping the motivation for the thesis's written soundness arguments intact. "despite prior audits" is dropped along with the clause because in the source it modifies the RISC Zero bug specifically; asserting it of the general six-zkVM set would be inventing a fact.

---

## 4. Line 45 — default-precompile comparison, RISC Zero half  ⟶ DELETE second clause  [CONTRIBUTION-SCOPE FLAG, minor]

**Current:**
```
SP1's standard library ships SHA-256 and ECDSA precompiles by default~\cite{succinct2024sp1}; RISC Zero ships SHA-256 and BigInt-256 modular-multiplication precompiles by default~\cite{bruestle2023risczero}.
```

**Proposed (SP1-only):**
```
SP1's standard library ships SHA-256 and ECDSA precompiles by default~\cite{succinct2024sp1}.
```

**Exact change:** delete `; RISC Zero ships SHA-256 and BigInt-256 modular-multiplication precompiles by default~\cite{bruestle2023risczero}` (keep the sentence-final period on the SP1 clause).

**Rationale:** The first clause is entirely about SP1 and is kept verbatim; the removed clause is the RISC Zero default-precompile inventory (RISC Zero name + BigInt-256 + `\cite{bruestle2023risczero}`).

**Scope note for operator:** Removes the RISC Zero data point from this default-precompile comparison, leaving an SP1-only statement. `\cite{bruestle2023risczero}` remains used in 5 other chapters, so no orphan.

---

## 5. Line 47 — "the zkVMs' existing 256-bit modmul precompiles"  ⟶ retarget plural to SP1  [COHERENCE, SOFT — operator confirm]

**Current (relevant clause within the sentence):**
```
whose multiplications are carried by the zkVMs' existing $256$-bit modular-multiplication precompiles via zero-padding, so no field-width-specific bigint circuit is required on the measured path
```

**Proposed (SP1-only):**
```
whose multiplications are carried by SP1's existing $256$-bit modular-multiplication precompile via zero-padding, so no field-width-specific bigint circuit is required on the measured path
```

**Exact change:** `the zkVMs' existing $256$-bit modular-multiplication precompiles` → `SP1's existing $256$-bit modular-multiplication precompile` (plural → singular).

**Rationale:** This does not literally say "RISC Zero," but the plural "zkVMs'" was written when both RISC Zero and SP1 were targets; retargeting to SP1-only makes it singular. **Fact-checked, not invented:** SP1 does ship a 256-bit modular-multiplication precompile, `UINT256_MUL` (verified in `05-system.tex:10` and `05-system.tex:27`), and the measured path in this thesis is SP1, so the singular SP1 statement is accurate.

**Note:** This is the one edit here that is coherence-driven rather than a literal RISC0-token removal. If you prefer to leave the generic plural "zkVMs'" (since Jolt is still a zkVM in the chapter and the statement is a general one), that is defensible too — flagged for your decision.

---

## 6. Line 76 — HAPPIER "(XMSS in RISC~Zero via the built-in SHA precompile)"  ⟶ RECOMMEND KEEP  [DECISION REQUIRED — do NOT auto-edit]

**Current (relevant fragment within the related-work sentence):**
```
HAPPIER~\cite{saygan2026happier} (XMSS in RISC~Zero via the built-in SHA precompile)
```

**Recommendation: KEEP UNCHANGED.**

**Rationale:** This is an accurate factual description of a cited third-party system — HAPPIER genuinely runs XMSS inside RISC Zero. This is not the thesis's own substrate targeting; it is a citation about the literature. Two ways to "remove" it both fail a hard constraint:
- Changing "RISC~Zero" → "SP1" would **invent a fact** (HAPPIER did not use SP1) — forbidden by constraint (5).
- Deleting "in RISC~Zero" (→ "XMSS via the built-in SHA precompile") is not false but strips accurate provenance from a related-work comparison whose whole point is "who ran what where," weakening the paragraph's precision for no gain.

The surrounding claim ("None of them authors a custom precompile or compares substrates, so we do not claim the first PQ signature in a zkVM") is unaffected either way. **If you nonetheless want zero RISC-Zero strings in the file**, the least-bad option is deleting only the two words `in RISC~Zero` so it reads "(XMSS via the built-in SHA precompile)". Flagged for your explicit decision; I did not draft it as the default because it degrades an accurate citation.

---

## Summary for the operator

**Scratch file:** `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Archive/Waseda/thesis/docs/risc0_removal_20260707/02-related.tex.proposed.md`

**Mentions covered:** 6 sites (all RISC-Zero-related text in the file).
- 4 direct RISC0/R0VM/Zirgen content edits: §1 (line 34 bullet), §2 (line 43 R0VM sentence), §3 (line 43 Arguzz bounty clause), §4 (line 45 RISC Zero default-precompile clause).
- 1 coherence retarget of a plural phrase: §5 (line 47 "zkVMs'" → "SP1's").
- 1 flagged third-party citation recommended KEEP: §6 (line 76 HAPPIER).

**Contribution-scope / evidence changes the operator must approve:**
1. **§1 (line 34):** drops RISC Zero from the chapter's presented set of deployment-ready zkVMs (now SP1 + Jolt). Framing change.
2. **§2 (line 43):** removes the R0VM 2.0 35 min → 44 s speedup as external precompile-motivation evidence, and leaves `risczero2025r0vm2` an unused bib entry (harmless; consider deleting from `ref.bib`). No way to retain the number without RISC Zero attribution.
3. **§4 (line 45):** the default-precompile comparison becomes SP1-only.
4. **§5 (line 47):** soft coherence edit — confirm whether to singularise "zkVMs'" to "SP1's" or keep the generic plural.
5. **§6 (line 76):** decision required — recommend KEEP (accurate third-party fact; the only edit that avoids inventing a fact merely deletes provenance).

**Reference / citation integrity:**
- No `\ref` or `\label` is orphaned by any proposed edit (the removed RISC0 text contains none; the `\ref{asm:air}`/`\ref{sec:security}` on line 43 sit in the kept "Each such precompile…" sentence).
- `\cite{bruestle2023risczero}` remains cited in 01-intro.tex, 03-preliminaries.tex, 04-theoretical.tex, 05-system.tex, 055-security.tex — **not** orphaned; bib entry stays.
- `\cite{risczero2025r0vm2}` is used **only** on line 43 of this file — after §2 it is uncited (unused bib entry, not a broken reference).
- No "we express CreGen as a RISC Zero guest" / "both RISC Zero and SP1" contribution claim exists **in this file**; the chapter's own contribution wording ("the custom large-prime-field precompile inside a general-purpose zkVM," line 12; "first execution-and-proving study … inside a general-purpose zkVM," line 76) is already substrate-generic and stays valid SP1-only.

**Out-of-scope reminder (not edited here):** the substrate-choice framing that names RISC Zero lives in other chapters too — `01-intro.tex:17` ("Both RISC~Zero and SP1 permit application-defined precompiles"), `03-preliminaries.tex:696`, `05-system.tex:10,27` (`sys_bigint`, dual-target wiring), `055-security.tex:319,355` (RISC Zero Groth16 x86-only). A coherent SP1-only thesis would need those retargeted as well; they are outside this file's task.
