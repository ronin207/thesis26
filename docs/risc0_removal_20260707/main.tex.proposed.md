# PROPOSED edits — strip RISC Zero from `修論2025_Takumi/main.tex` (SP1-only retarget)

**Status:** PROPOSAL ONLY. `main.tex` is NOT edited. Operator review required before anything lands.
**File audited:** `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/修論2025_Takumi/main.tex` (195 lines)
**Date:** 2026-07-07

## Scan result

- RISC0 / RISC Zero mentions found: **1** (line 148, `\begin{coverabstract}`).
- `sys_bigint`, `Zirgen`, `RISC0`, `risczero`, `\cite{bruestle2023risczero}`: **0** occurrences in this file.
- `RISC-V` / `RISC~V` (base ISA — must be KEPT): **0** occurrences in this file (nothing to preserve here; hard constraint (1) not triggered).
- Orphaned `\ref` / `\label` from the removal: **none** (the mention is inline prose in the abstract, carries no label and is not the referent of any `\ref`).
- Math, `\cite`, other `\ref`/`\label`: untouched by this proposal.

All RISC0 measurement numbers / rows / claims: **none are RISC0-specific in this file.** The abstract's quantitative claims ($14.24$ min Griffin, $13.24$ min SHA-3 control, $n{=}5$, out-of-memory at ${\approx}1$m$45$s) are the SP1 Cell 1/2/3 measurement arc per `CLAUDE.md` ("The current SP1 measurements (Cell 1/2/3)..."). They are SP1 results, not RISC Zero results, so they stay. The only RISC0-attributing text is the platform list "RISC~Zero and SP1"; removing "RISC~Zero and" leaves those numbers correctly attributed to SP1 alone. **No numbers are added, removed, or changed.**

---

## Edit 1 — line 148, cover abstract, platform list

**CURRENT (exact text, the containing clause):**

> and answer with a trace-area cost model validated by benchmarking the BDEC CreGen and ShowCre relations (as non-statement-bound cost workloads) instantiated with PLUM on RISC~Zero and SP1 (Apple M5~Pro, $24$~GB).

**PROPOSED SP1-only rewrite:**

> and answer with a trace-area cost model validated by benchmarking the BDEC CreGen and ShowCre relations (as non-statement-bound cost workloads) instantiated with PLUM on SP1 (Apple M5~Pro, $24$~GB).

**Precise change:** `on RISC~Zero and SP1` → `on SP1`. (Delete the two words `RISC~Zero and`; nothing else in the sentence changes.)

**Rationale:** Only textual RISC0 reference in the file; retargets the abstract's stated evaluation platform to SP1 alone while preserving the sentence structure, the CreGen/ShowCre workloads, the hardware `(Apple M5~Pro, $24$~GB)`, and all downstream numbers. Prose still flows and the document still compiles.

---

## CONTRIBUTION-SCOPE change requiring operator approval

**This edit narrows the abstract's stated evaluation targets from "RISC Zero and SP1" to "SP1 only."** The abstract is the thesis's top-level contribution statement, so this is a scope change, not a cosmetic one:

- **Before:** the cost model is claimed to be "validated by benchmarking ... on RISC~Zero and SP1" — i.e. validated on **two** general-purpose zkVM substrates.
- **After:** validated on **SP1 alone.**

Consequences the operator should weigh before approving:
1. The two-substrate framing was arguably a cross-substrate generality claim for the trace-area cost model (the model holds "on RISC Zero and SP1", two independently-built provers). Dropping RISC Zero removes that second data point from the headline claim. If the operator wants to retain a generality signal, that must come from prose the operator writes (framing is the operator's lane), not from an invented RISC0 result.
2. No other sentence in the abstract, and no other sentence in `main.tex`, depends on the two-substrate claim — the mechanism prose ("$31$-bit field", "field-mismatch tax", "application-defined precompile", the three-precompile family, the dual obstruction) is substrate-agnostic and reads identically under SP1-only.
3. This is the ONLY place in `main.tex` where the thesis names its evaluation platforms. Retargeting here is sufficient for `main.tex`; the included chapters (`01-intro` … `08-conclusion`, `appendices`) are separate files and are out of scope for this proposal.

---

## Report summary

- **Scratch file:** `/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/risc0_removal_20260707/main.tex.proposed.md`
- **RISC0 mentions covered:** 1 of 1 (100%).
- **Contribution-scope change (operator's call):** the abstract's stated evaluation targets narrow from "RISC Zero and SP1" to "SP1 only." No numbers move; the affected numbers were already SP1 measurements.
- **Orphaned refs/labels:** none.
- **RISC-V preserved:** N/A (no RISC-V mention in this file).
