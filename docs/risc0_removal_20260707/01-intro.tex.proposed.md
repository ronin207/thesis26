# PROPOSED edits — `修論2025_Takumi/01-intro.tex` (RISC Zero strip → SP1-only)

**STATUS: PROPOSAL ONLY. Do NOT apply to the .tex without operator approval.**
Scope: remove `RISC~Zero` / `RISC0` / `\cite{bruestle2023risczero}`. KEEP Aurora, Loquat, and `RISC-V` (the ISA SP1 uses — not present in this file). No `Zirgen` / `sys_bigint` occur in this file.

Mentions covered: **8 locations** (6 rendered: lines 11, 13, 17, 23, 39, 57; 2 commented-out: lines 66, 68).
Scope-narrowing edits requiring operator approval are flagged **⚑ SCOPE**.

---

## 1. Line 11 — general zkVM-substrate citation list (no scope change)

**BEFORE**
```
in which a single universal relation proves the correct execution of an ordinary program~\cite{cryptoeprint:2023/1032,bruestle2023risczero,yang2026sokzkvm}, so a change to the predicate becomes a program edit rather than a new circuit
```

**AFTER**
```
in which a single universal relation proves the correct execution of an ordinary program~\cite{cryptoeprint:2023/1032,yang2026sokzkvm}, so a change to the predicate becomes a program edit rather than a new circuit
```

**Rationale:** Drop only the `bruestle2023risczero` cite from a general statement about what a zkVM *is*; the two remaining cites still support the generic claim. No target scope changes.

---

## 2. Line 13 — native-field example (BabyBear/RISC Zero dropped)

**BEFORE**
```
while modern zkVM provers operate over $31$-bit native fields (BabyBear, $2^{31}-2^{27}+1$, in RISC~Zero; KoalaBear, $2^{31}-2^{24}+1$, in the SP1 fork evaluated here).
```

**AFTER**
```
while modern zkVM provers operate over $31$-bit native fields (KoalaBear, $2^{31}-2^{24}+1$, in the SP1 fork evaluated here).
```

**Rationale:** The general "modern zkVM provers use 31-bit fields" claim survives with the single instance actually used. Removing the BabyBear/RISC Zero half-example does not weaken the field-mismatch setup.

---

## 3. Line 17 — precompile-capability claim ⚑ SCOPE

**BEFORE**
```
Both RISC~Zero~\cite{bruestle2023risczero} and SP1~\cite{succinct2024sp1} permit \emph{application-defined precompiles}: dedicated AIR sub-circuits for designated primitives, exposed to the guest as syscalls.
```

**AFTER**
```
SP1~\cite{succinct2024sp1} permits \emph{application-defined precompiles}: dedicated AIR sub-circuits for designated primitives, exposed to the guest as syscalls.
```

**Rationale + ⚑FLAG:** Narrows "both RISC Zero and SP1 permit application-defined precompiles" to SP1 alone. The thesis previously asserted the precompile mechanism exists across **two independent zkVMs** (a generality/portability signal). Post-edit it asserts it only for SP1. **Operator must approve dropping the cross-substrate generality claim.**

---

## 4. Line 23 — measurement-platform claim ⚑ SCOPE

**BEFORE**
```
The credential construction (BDEC~\cite{10.1007/978-981-96-0957-4_3}) instantiated with PLUM is the concrete workload through which the criterion is calibrated and measured on RISC~Zero and SP1.
```

**AFTER**
```
The credential construction (BDEC~\cite{10.1007/978-981-96-0957-4_3}) instantiated with PLUM is the concrete workload through which the criterion is calibrated and measured on SP1.
```

**Rationale + ⚑FLAG:** Narrows the stated measurement platform from two zkVMs to SP1 only. **Operator must confirm no RISC Zero measurements are reported anywhere in the thesis** (if any four-cell datum is RISC Zero, this narrowing is wrong and RISC Zero cannot be fully stripped).

---

## 5. Line 39 — Figure 1 (`fig:two-provers`) zkVM label ⚑ SCOPE (figure)

**BEFORE**
```
  \node[lbl, below=1pt of vmicon] (vmlab) {\textbf{zkVM} (RISC~Zero / SP1)};
```

**AFTER**
```
  \node[lbl, below=1pt of vmicon] (vmlab) {\textbf{zkVM} (SP1)};
```

**Rationale + ⚑FLAG:** Figure label narrowed to SP1. The static-circuit-vs-zkVM contrast (the figure's point) is untouched; only the zkVM node stops naming two vendors. Cosmetic-but-visible scope narrowing.

---

## 6. Line 57 — Contribution 3, "CreGen relation as a RISC Zero guest" ⚑ SCOPE (LOAD-BEARING contribution claim)

**BEFORE**
```
  \item \textbf{The first empirical characterisation of PLUM-in-a-zkVM.} We express the credential-generation (CreGen) relation as a RISC~Zero guest with PLUM in place of Loquat, benchmark the ShowCre relation, the $k{+}2$-verification generalisation, as a non-statement-bound cost workload, and run standalone PLUM verification on SP1.
```

**AFTER**
```
  \item \textbf{The first empirical characterisation of PLUM-in-a-zkVM.} We express the credential-generation (CreGen) relation as an SP1 guest with PLUM in place of Loquat, benchmark the ShowCre relation, the $k{+}2$-verification generalisation, as a non-statement-bound cost workload, and run standalone PLUM verification on SP1.
```

**Rationale + ⚑FLAG (HIGHEST PRIORITY):** This is a **contribution statement**. It previously placed the CreGen guest on RISC Zero and only standalone verification on SP1 — i.e. the empirical contribution implicitly spanned two zkVMs. Retargeting CreGen to SP1 makes the entire empirical contribution single-substrate (SP1). **Operator must confirm the CreGen (and ShowCre) guests were actually built/measured on SP1**, which project memory indicates they were (SP1 CreGen/ShowCre guests). Secondary: the rewrite now says "SP1" twice in one sentence ("as an SP1 guest ... verification on SP1"); operator may prefer to smooth to e.g. "...run standalone PLUM verification, all on SP1." — flagged as a wording, not a scope, choice.

---

## 7. Line 66 — COMMENTED-OUT Scope-and-Non-Goals block (2 mentions; does NOT render)

**BEFORE**
```
% We instantiate the anonymous-credential construction with BDEC~\cite{10.1007/978-981-96-0957-4_3} and the zkVM with RISC~Zero and SP1. BDEC is the leading symmetric-primitive PQ anonymous-credential system, its two-signature-checks-under-a-hidden-key structure is representative of the design class, and its Aurora baseline is well-defined; RISC~Zero and SP1 both expose application-defined precompiles and target consumer hardware.
```

**AFTER**
```
% We instantiate the anonymous-credential construction with BDEC~\cite{10.1007/978-981-96-0957-4_3} and the zkVM with SP1. BDEC is the leading symmetric-primitive PQ anonymous-credential system, its two-signature-checks-under-a-hidden-key structure is representative of the design class, and its Aurora baseline is well-defined; SP1 exposes application-defined precompiles and targets consumer hardware.
```

**Rationale:** Line is commented out (`%`) and does not render — LOW priority. Retarget only for consistency in case the block is ever re-enabled. Two RISC Zero mentions removed here.

---

## 8. Line 68 — COMMENTED-OUT security-reduction dependency list (does NOT render)

**BEFORE**
```
% We do \emph{not} propose a new signature scheme or new assumptions: PLUM is taken as given, and the system's security reduces to those of Loquat, PLUM, BDEC, RISC~Zero, and SP1 plus the three open premises named above.
```

**AFTER**
```
% We do \emph{not} propose a new signature scheme or new assumptions: PLUM is taken as given, and the system's security reduces to those of Loquat, PLUM, BDEC, and SP1 plus the three open premises named above.
```

**Rationale:** Commented out — LOW priority. Drop RISC Zero from the security-reduction list if the block is re-enabled.

---

## Summary of scope changes requiring operator approval

- **⚑ #3 (line 17):** precompile capability narrowed from "both RISC Zero and SP1" → SP1 only (drops cross-substrate generality).
- **⚑ #4 (line 23):** measurement platform narrowed to SP1 only — confirm no RISC Zero data is reported anywhere.
- **⚑ #5 (line 39):** Figure 1 zkVM label → SP1 only.
- **⚑ #6 (line 57):** CONTRIBUTION statement — CreGen guest retargeted RISC Zero → SP1; makes the whole empirical contribution single-substrate. Confirm CreGen/ShowCre were measured on SP1.

Net effect: the thesis's stated targets narrow from "two zkVMs (RISC Zero + SP1)" to **SP1 only**. This is a genuine contribution-scope reduction, not a cosmetic change.
