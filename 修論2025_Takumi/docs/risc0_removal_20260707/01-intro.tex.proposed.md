# PROPOSED edits — strip RISC Zero, retarget `01-intro.tex` to SP1-only

**Status: PROPOSAL ONLY. Nothing applied to `01-intro.tex`.** This chapter is a framing / contribution chapter; the operator reviews before anything lands.

**Scope of this file:** `修論2025_Takumi/01-intro.tex` only.

**Coverage:** 8 RISC-Zero mention *sites* (6 rendered + 2 commented-out), 10 total textual occurrences of `RISC~Zero` / `\cite{bruestle2023risczero}`. Every one is covered below.

**Preserved by construction:** every `RISC-V` / `RISC~V` occurrence (none appear in this file, but the constraint stands), all `\ref`/`\label`/`\cite` except `bruestle2023risczero`, all math, all non-RISC0 sentences.

**No orphaned references.** No `\label`/`\ref` in this file is RISC0-tied (labels present: `sec:intro`, `ssec:deploy-question`, `ssec:question`, `fig:two-provers`). `bruestle2023risczero` is still cited in five other chapters (`02-related.tex`, `03-preliminaries.tex`, `04-theoretical.tex`, `05-system.tex`, `055-security.tex`), so its `ref.bib` entry stays live and removing the intro cite creates no undefined-citation. Document remains compilable.

---

## Rendered mentions (these affect the compiled PDF)

### 1. Line 11 — RISC Zero citation in the generic zkVM-substrate reference list

**Current:**
```
~\cite{cryptoeprint:2023/1032,bruestle2023risczero,yang2026sokzkvm}
```

**SP1-only rewrite:**
```
~\cite{cryptoeprint:2023/1032,yang2026sokzkvm}
```

**Rationale:** Drop only the RISC Zero cite from the three-item zkVM-substrate reference; the two remaining cites keep the general claim supported. Sentence prose unchanged (it is about zkVMs generically, not RISC Zero).

---

### 2. Line 13 — BabyBear / RISC Zero field example (RISC0 field number)

**Current (fragment):**
```
while modern zkVM provers operate over $31$-bit native fields (BabyBear, $2^{31}-2^{27}+1$, in RISC~Zero; KoalaBear, $2^{31}-2^{24}+1$, in the SP1 fork evaluated here).
```

**SP1-only rewrite:**
```
while modern zkVM provers operate over $31$-bit native fields (KoalaBear, $2^{31}-2^{24}+1$, in the SP1 fork evaluated here).
```

**Rationale:** Removes the RISC0 field number (`BabyBear, $2^{31}-2^{27}+1$`) entirely per the "remove RISC0 numbers" constraint. Keeps the KoalaBear number — that is SP1's own native field, not a RISC Zero fact. The field-mismatch point (31-bit prover vs large-prime signature) is fully carried by the SP1 instance alone. "fields" (plural) kept because the lead-in still generalises over the zkVM class.

---

### 3. Line 17 — "application-defined precompiles" support sentence

**Current (fragment):**
```
Both RISC~Zero~\cite{bruestle2023risczero} and SP1~\cite{succinct2024sp1} permit \emph{application-defined precompiles}:
```

**SP1-only rewrite:**
```
SP1~\cite{succinct2024sp1} permits \emph{application-defined precompiles}:
```

**Rationale:** Reword the "Both X and Y permit" construction to "SP1 permits" (subject/verb agreement fixed), removing RISC Zero and its cite. The remainder of the paragraph (precompile-as-instrument argument) is untouched and still flows.

---

### 4. Line 23 — criterion calibration/measurement target  *(SCOPE — see summary)*

**Current (fragment):**
```
is the concrete workload through which the criterion is calibrated and measured on RISC~Zero and SP1.
```

**SP1-only rewrite:**
```
is the concrete workload through which the criterion is calibrated and measured on SP1.
```

**Rationale:** Narrows the stated measurement substrates of the whole criterion from two to one. This is a scope statement, not just a citation — flagged in the summary.

---

### 5. Line 39 — Figure 1 (`fig:two-provers`) zkVM-column label

**Current:**
```
  \node[lbl, below=1pt of vmicon] (vmlab) {\textbf{zkVM} (RISC~Zero / SP1)};
```

**SP1-only rewrite:**
```
  \node[lbl, below=1pt of vmicon] (vmlab) {\textbf{zkVM} (SP1)};
```

**Rationale:** Figure 1 labels the zkVM column with only the evaluated substrate. Visible in the compiled figure; consistent with the SP1-only retarget.

---

### 6. Line 57 — CONTRIBUTION 3: "PLUM-in-a-zkVM" empirical characterisation  *(SCOPE — operator's call)*

**Current (fragment):**
```
We express the credential-generation (CreGen) relation as a RISC~Zero guest with PLUM in place of Loquat,
```

**SP1-only rewrite:**
```
We express the credential-generation (CreGen) relation as an SP1 guest with PLUM in place of Loquat,
```

**Rationale:** Retargets the CreGen-guest contribution claim to SP1. This narrows Contribution 3 ("The first empirical characterisation of PLUM-in-a-zkVM") from a two-substrate framing (CreGen expressed on RISC Zero, standalone verify + credential relations proved on SP1) to an SP1-only characterisation.

**Factual note (not a fabrication):** an SP1 CreGen guest demonstrably exists in the repo — the SP1 host binary `platforms/zkvms/sp1/script/src/bin/bdec_cregen_host.rs` is present, and Cells 1/2/3 are all measured on SP1. So the SP1-only wording is *supported by repo evidence*. The flag is editorial, not factual: whether to re-attribute the CreGen guest to SP1 (vs. rewording to drop the guest-substrate attribution altogether) is a contribution-scope decision that is the operator's to make. If preferred, an attribution-neutral variant avoids re-asserting the substrate: `We express the credential-generation (CreGen) relation with PLUM in place of Loquat,` — but this loses the "expressed as a guest" concreteness.

---

## Commented-out mentions (currently `%`-prefixed; no render / no compile effect)

Lines 64–68 are a commented-out `Scope and Non-Goals` subsection. Editing them changes nothing in the compiled PDF today; it matters only if the operator later uncomments the subsection. Included for completeness and to keep the block consistent if revived.

### 7. Line 66 — (commented) scope statement, two RISC~Zero occurrences

**Current:**
```
% We instantiate the anonymous-credential construction with BDEC~\cite{10.1007/978-981-96-0957-4_3} and the zkVM with RISC~Zero and SP1. BDEC is the leading symmetric-primitive PQ anonymous-credential system, its two-signature-checks-under-a-hidden-key structure is representative of the design class, and its Aurora baseline is well-defined; RISC~Zero and SP1 both expose application-defined precompiles and target consumer hardware.
```

**SP1-only rewrite:**
```
% We instantiate the anonymous-credential construction with BDEC~\cite{10.1007/978-981-96-0957-4_3} and the zkVM with SP1. BDEC is the leading symmetric-primitive PQ anonymous-credential system, its two-signature-checks-under-a-hidden-key structure is representative of the design class, and its Aurora baseline is well-defined; SP1 exposes application-defined precompiles and targets consumer hardware.
```

**Rationale:** Removes both RISC~Zero occurrences; "both expose ... and target" → "exposes ... and targets". Commented-out, so cosmetic today.

---

### 8. Line 68 — (commented) security trusted-base list  *(SCOPE — commented)*

**Current (fragment):**
```
PLUM is taken as given, and the system's security reduces to those of Loquat, PLUM, BDEC, RISC~Zero, and SP1 plus the three open premises named above.
```

**SP1-only rewrite:**
```
PLUM is taken as given, and the system's security reduces to those of Loquat, PLUM, BDEC, and SP1 plus the three open premises named above.
```

**Rationale:** Drops RISC Zero from the trusted-base / security-reduction list. Consistent with SP1-only retarget. Commented-out, so no render effect today.

---

## Contribution-scope changes the operator must approve

These narrow the thesis from a two-substrate (RISC Zero + SP1) framing to SP1-only. They are the operator's call, not mine:

1. **Contribution 3 — line 57 (RENDERED).** "CreGen expressed as a RISC Zero guest" → "as an SP1 guest". Narrows "the first empirical characterisation of PLUM-in-a-zkVM" from spanning two substrates to SP1 alone. Repo-supported (SP1 CreGen host binary exists), but the scope decision is editorial.
2. **Criterion measurement target — line 23 (RENDERED).** "calibrated and measured on RISC~Zero and SP1" → "on SP1". States the whole criterion is now measured on one substrate, not two.
3. **Figure 1 column label — line 39 (RENDERED).** "(RISC~Zero / SP1)" → "(SP1)". Same narrowing, visible in the figure.
4. **Scope subsection + trusted-base list — lines 66, 68 (COMMENTED).** Only bite if the subsection is uncommented; flagged so they don't get missed later.

## OUT-OF-SCOPE flag (NOT in this file — needs a separate pass)

The **abstract** is not in `01-intro.tex`. It lives in `修論2025_Takumi/main.tex:148` inside `\begin{coverabstract}` and states the same two-substrate target verbatim:

> "...benchmarking the BDEC CreGen and ShowCre relations (as non-statement-bound cost workloads) instantiated with PLUM **on RISC~Zero and SP1** (Apple M5~Pro, $24$~GB)."

This is the abstract's stated target and carries the identical scope narrowing (RISC~Zero and SP1 → SP1). It requires its own edit pass; it is deliberately left untouched here because it is outside the target file.

## Counts

- RISC-Zero mention **sites covered: 8** (6 rendered + 2 commented-out).
- Total textual occurrences addressed: **10** (`RISC~Zero` ×7 + `\cite{bruestle2023risczero}` ×3).
- `RISC-V` / `RISC~V` occurrences in file: **0** (none to preserve, constraint moot but honoured).
- Orphaned `\ref`/`\label`: **0**.
- Undefined-citation risk from removing the intro `bruestle2023risczero` cites: **0** (still cited in 5 other chapters).
