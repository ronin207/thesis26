# PROPOSED edits — strip RISC Zero from `08-conclusion.tex` (SP1-only)

**Status: PROPOSAL ONLY. Nothing has been applied to `08-conclusion.tex`.**
This is a framing / contribution chapter; every block below is the operator's call.

- **File:** `修論2025_Takumi/08-conclusion.tex`
- **Literal `RISC~Zero` occurrences:** 6 (lines 3, 7, 11×2, 19, 24)
- **RISC-Zero mentions carried in RISC0-derived vocabulary without the literal string:** line 22 (`receipt journal`, `segment-level diagnostics`, the credential-generation anomaly)
- **Total edit blocks below:** 6 (covering every RISC0 mention in the file)
- **`\cite{bruestle2023risczero}`:** NOT present in this file (nothing to remove here).
- **`sys_bigint` / `Zirgen`:** NOT present in this file.
- **`RISC-V` / `RISC~V`:** not present in this file either, so the keep-constraint is trivially satisfied; nothing was touched on that account.

### Cross-file safety checks (no orphaned `\ref`/`\cite` created by these edits)
- **`\ref{ssec:cregen-anomaly}` (dropped in Block 3):** the `\label` is defined in `06-evaluation.tex:480` and is *also* referenced from `055-security.tex:290` and `06-evaluation.tex` lines 455, 462, 708, 1065, 1104, 1143. Removing the reference from the conclusion orphans nothing. (Note: that subsection is itself RISC-Zero-specific and will presumably be handled in the `06-evaluation.tex` / `055-security.tex` pass; that is out of scope here.)
- **`\cite{cryptoeprint:2024/1037}` (masked FRI, dropped in Block 6):** the same key is *also* cited in `055-security.tex:386` and `055-security.tex:419`, so the bib entry stays used; no dangling/unused-entry issue.

---

## Block 1 — Line 3 (opening paragraph) — CONTRIBUTION SCOPE CHANGE ⚠️

**BEFORE:**
> We realised the construction on RISC~Zero and SP1, measured it against an Aurora static-circuit baseline, and analysed what the substitution preserves and what it costs.

**AFTER (SP1-only):**
> We realised the construction on SP1, measured it against an Aurora static-circuit baseline, and analysed what the substitution preserves and what it costs.

**Rationale:** Narrows the headline realisation claim from two substrates to SP1 alone. This is the top-line "what we built" sentence of the conclusion, so it is a genuine contribution-scope narrowing the operator must ratify. (Cross-reference for the operator: the abstract / cover — a *different* file — almost certainly carries a parallel "RISC Zero and SP1" targets claim that will need the same narrowing; out of scope for this file.)

---

## Block 2 — Line 7 (Main Findings, second prong of the obstruction) — CONTRIBUTION SCOPE CHANGE ⚠️

**BEFORE (the second-prong sentence only; the first-prong sentence before it is pure SP1 and is left untouched):**
> The second is a fact about the deployed toolchains, and it takes a different form on each substrate: the only succinct zero-knowledge wraps exposed by the SP1 pipeline we measure (v6.2.1, forked) are Groth16 and PLONK, both pairing-based, so on SP1 even a completed wrap could be at best classically secure; on RISC~Zero the blinded succinct receipt carries no formally established zero-knowledge guarantee, so BDEC's anonymity premise cannot be formally discharged on it, and its pairing-based wrap is x86-only and does not run on the Apple-silicon target at all (Section~\ref{sec:security}).

**AFTER (SP1-only):**
> The second is a fact about the deployed toolchain: the only succinct zero-knowledge wraps exposed by the SP1 pipeline we measure (v6.2.1, forked) are Groth16 and PLONK, both pairing-based, so on SP1 even a completed wrap could be at best classically secure (Section~\ref{sec:security}).

**Rationale:** Removes the RISC~Zero clause (no formal ZK guarantee; x86-only pairing wrap unavailable on Apple silicon) and the two-substrate framing ("takes a different form on each substrate", "toolchains" → "toolchain"). The second prong of the obstruction is now stated as an SP1-only fact. **Scope note for the operator:** the *substance* of the second prong is unchanged (the affordable wrap is not post-quantum), but its evidentiary base narrows from "both deployed toolchains" to SP1's pairing-based wraps alone. Keeps `\ref{sec:security}`.

---

## Block 3 — Line 11 (Main Findings, credential-relation ZK) — FLAG: verify SP1 blocker attribution

**BEFORE:**
> No zero-knowledge \emph{proof} of either relation was produced on consumer hardware: on RISC~Zero the credential-generation succinct prove terminated in an internal-verifier rejection (RISC~Zero~$3.0.5$; an anomaly under diagnosis, categorically distinct from a resource limit and on which no claim of this thesis rests, Section~\ref{ssec:cregen-anomaly}), and the presentation wrap is blocked by the same recursion-shape provisioning wall.

**AFTER (SP1-only):**
> No zero-knowledge \emph{proof} of either relation was produced on consumer hardware: the succinct proves are not zero-knowledge, and the succinct-to-zero-knowledge wrap is blocked by the same recursion-shape provisioning wall.

**Rationale:** The RISC~Zero credential-generation internal-verifier rejection (RISC~Zero 3.0.5) is a RISC-Zero-only event — on SP1 the credential-generation prove *completes* (previous sentence: 26.98 / 27.45 min). Removing it drops `\ref{ssec:cregen-anomaly}` (safe — see cross-file check above). The SP1-grounded blocker (the recursion-shape provisioning wall, established for SP1 in Block-2/Block-line-7 and in `sec:evaluation`) is retained for the presentation wrap.

**⚠️ FLAG — do not let this fabricate an SP1 failure mode.** The original attributes the recursion-shape wall only to the *presentation* wrap. My rewrite generalises it to the succinct-to-ZK wrap of *both* relations. That is the honest reading (the same wall blocks the standalone PLUM-verification wrap in line 7, and the credential relations are larger), but if there is no machine-logged SP1 run showing the credential-generation ZK wrap actually hitting this wall, soften to a conditional, e.g.:
> "... the succinct proves are not zero-knowledge, and no zero-knowledge wrap of either relation was produced; the presentation wrap is blocked by the same recursion-shape provisioning wall."

This keeps the only substrate-observed SP1 claim (presentation wrap → recursion-shape wall) and avoids asserting an unobserved cregen-ZK-wrap failure.

---

## Block 4 — Line 19 (Limitations, statement-binding) — terminology retarget, limitation preserved

**BEFORE:**
> Finally, the RISC~Zero prototype does not yet bind the receipt journal to the public statement, so the artifact is at present a functional benchmark rather than a statement-bound credential verifier.

**AFTER (SP1-only):**
> Finally, the SP1 prototype does not yet bind the guest's committed public values to the public statement, so the artifact is at present a functional benchmark rather than a statement-bound credential verifier.

**Rationale:** The statement-binding limitation is real for the SP1 guests too (they commit only an aggregate boolean, not the statement — verified). "receipt journal" is RISC-Zero's public-output object; SP1's equivalent is the guest's *committed public values* (`io::commit`). The limitation is preserved; only the RISC-Zero object name is retargeted. No invented fact.

---

## Block 5 — Line 22 (Future Work, immediate engineering step) — RISC0 vocabulary + anomaly

**BEFORE:**
> The immediate engineering step is to commit the public statement to the receipt journal, after which the credential-generation prove anomaly should be re-run with segment-level diagnostics.

**AFTER (SP1-only):**
> The immediate engineering step is to commit the public statement to the guest's committed public values.

**Rationale:** Three RISC-Zero-specific items here, none containing the literal string "risc":
- "receipt journal" → SP1's "committed public values" (same retarget as Block 4).
- "the credential-generation prove anomaly should be re-run" — the anomaly is the RISC-Zero 3.0.5 internal-verifier rejection removed in Block 3; on SP1 the cregen prove completes, so there is no anomaly to re-run.
- "segment-level diagnostics" — "segment" is RISC Zero's execution-splitting unit (SP1 uses "shards"), and the phrase only makes sense for the removed RISC-Zero anomaly.

The genuinely SP1-relevant future step (bind the public statement) is preserved; the RISC-Zero-only re-run clause is dropped. If the operator wants to keep a diagnostics-style follow-up for SP1, that would be a new claim needing its own grounding, not a rewrite of this sentence — flagged rather than invented.

---

## Block 6 — Line 24 (Future Work, masked low-degree test path) — CONTRIBUTION/OUTLOOK SCOPE CHANGE ⚠️, drops one cite

**BEFORE:**
> The zero-knowledge the produced receipt lacks can be supplied without a pairing-based wrap, by masking the prover's own low-degree test rather than wrapping its output: for the {FRI}/{STARK}-based prover of RISC~Zero by masked {FRI}~\cite{cryptoeprint:2024/1037}, and for the multilinear Basefold-style commitment of the SP1 prover by the VEIL compiler~\cite{cryptoeprint:2026/683}, both plausibly post-quantum and neither reintroducing a quantum-vulnerable assumption.

**AFTER (SP1-only):**
> The zero-knowledge the produced proof lacks can be supplied without a pairing-based wrap, by masking the prover's own low-degree test rather than wrapping its output: for the multilinear Basefold-style commitment of the SP1 prover, by the VEIL compiler~\cite{cryptoeprint:2026/683}, plausibly post-quantum and not reintroducing a quantum-vulnerable assumption.

**Rationale:** Removes the RISC-Zero masked-FRI path (FRI/STARK prover + `\cite{cryptoeprint:2024/1037}`) and collapses the two-item list to the single SP1 (VEIL) path — hence "both/neither" → singular, and "receipt" → "proof" (SP1's term). The masked-FRI citation is still used in `055-security.tex` (lines 386, 419), so dropping it here leaves no unused bib entry. **Scope note:** this narrows the stated forward path to post-quantum ZK from "one route per substrate" to the single SP1/VEIL route — an outlook narrowing the operator should confirm. (Alternative if the operator wants to keep masked FRI as a *general* technique rather than a RISC-Zero-specific one: "... by masking the prover's own low-degree test rather than wrapping its output — for the SP1 prover's multilinear Basefold-style commitment, by the VEIL compiler~\cite{cryptoeprint:2026/683}." This retains the "mask, don't wrap" principle without naming RISC Zero.)

---

## Optional terminology consistency (NOT RISC0 mentions; operator's call, left unchanged in the blocks above unless noted)

The word **"receipt"** is RISC Zero's name for its proof object (SP1 produces "proofs"). It appears in SP1-context sentences that are otherwise fine and were **not** on the strip list, so I did not force-change them — flagging for coherence in an SP1-only manuscript:
- **Line 7 (first prong, kept):** "the standalone PLUM-verification receipt" and "the PLONK wrap of the standalone PLUM verification receipt". Both describe SP1 objects; consider "proof" for consistency. (Block 6 already changes the line-24 "receipt" → "proof".)

These are stylistic, not RISC0 content, so they do not affect compilability or claims; batching them into an SP1-terminology sweep would tidy the chapter but is discretionary.

---

## Compilability note
All six blocks preserve every non-RISC0 sentence, all `\ref`/`\label`/math, and keep the document compilable. The only removed cross-reference (`\ref{ssec:cregen-anomaly}`, Block 3) and the only removed citation (`\cite{cryptoeprint:2024/1037}`, Block 6) are both still defined/used elsewhere in the thesis, so neither is orphaned by these edits.
