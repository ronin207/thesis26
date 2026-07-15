# PROPOSED edits — `修論2025_Takumi/04-theoretical.tex` (RISC Zero strip → SP1-only)

**STATUS: PROPOSAL ONLY. Do NOT apply to the .tex without operator approval.**
Scope: remove `RISC~Zero` / `\cite{bruestle2023risczero}`. **KEEP `RISC-V`** (the ISA SP1 uses — appears twice on line 21 as "RISC-V instruction set" / "native RISC-V instructions"; both retained). KEEP Aurora, Loquat. No `Zirgen` / `sys_bigint` occur in this file.

Mentions covered: **3 locations** (lines 17, 21, 55).
Scope-narrowing edits requiring operator approval flagged **⚑ SCOPE**.

---

## 1. Line 17 — "standard in the literature" citation list (no scope change)

**BEFORE**
```
The first three dimensions are standard in the zkSNARK and zkVM literature~\cite{cryptoeprint:2024/868,10.1007/978-981-95-2961-2_6,bruestle2023risczero,succinct2024sp1,cryptoeprint:2023/1217}.
```

**AFTER**
```
The first three dimensions are standard in the zkSNARK and zkVM literature~\cite{cryptoeprint:2024/868,10.1007/978-981-95-2961-2_6,succinct2024sp1,cryptoeprint:2023/1217}.
```

**Rationale:** Drop only the `bruestle2023risczero` cite from a "these metrics are standard" reference list; four remaining cites still support the claim. No target scope changes.

---

## 2. Line 21 — native-field example inside the field-mismatch-tax setup (BabyBear/RISC Zero dropped; RISC-V kept)

**BEFORE**
```
When it is proved by a zkVM whose prover field $\mathbb{F}_{p_{\mathsf{vm}}}$ is small (BabyBear, $p_{\mathsf{vm}} = 2^{31} - 2^{27} + 1$, in RISC~Zero; KoalaBear, $p_{\mathsf{vm}} = 2^{31} - 2^{24} + 1$, in the evaluated SP1 fork), each $\mathbb{F}_p$ operation must be emulated by software running on the zkVM's RISC-V instruction set, which in turn is encoded in $\mathbb{F}_{p_{\mathsf{vm}}}$.
```

**AFTER**
```
When it is proved by a zkVM whose prover field $\mathbb{F}_{p_{\mathsf{vm}}}$ is small (KoalaBear, $p_{\mathsf{vm}} = 2^{31} - 2^{24} + 1$, in the evaluated SP1 fork), each $\mathbb{F}_p$ operation must be emulated by software running on the zkVM's RISC-V instruction set, which in turn is encoded in $\mathbb{F}_{p_{\mathsf{vm}}}$.
```

**Rationale:** Drop the BabyBear/RISC Zero half of the parenthetical example; keep the SP1/KoalaBear instance actually evaluated. **`RISC-V instruction set` is KEPT** — it is the ISA the SP1 guest compiles to, not RISC Zero. The field-mismatch argument is generic, so shrinking the example list does not narrow the argument's scope.

---

## 3. Line 55 — Remark `rem:fmt-instantiation`, ℓ=7 instantiation ⚑ SCOPE (minor; example only)

**BEFORE**
```
For PLUM ($\log_2 p\approx 199$) on a $31$-bit host field ($\lfloor\log_2 p_{\mathsf{vm}}\rfloor = 30$, for both RISC~Zero's BabyBear and the SP1 fork's KoalaBear), $\ell = 7$, so Proposition~\ref{prop:fmt-lb} places the per-multiplication tax between $7$ and $49$.
```

**AFTER**
```
For PLUM ($\log_2 p\approx 199$) on a $31$-bit host field ($\lfloor\log_2 p_{\mathsf{vm}}\rfloor = 30$, the SP1 fork's KoalaBear), $\ell = 7$, so Proposition~\ref{prop:fmt-lb} places the per-multiplication tax between $7$ and $49$.
```

**Rationale + ⚑FLAG (minor):** The parenthetical previously named **both** BabyBear and KoalaBear to make the point that both 31-bit fields have `⌊log₂ p_vm⌋ = 30` and therefore both give `ℓ = 7` — i.e. the width result is robust across the two zkVMs. Narrowing to KoalaBear alone keeps the arithmetic exactly correct (KoalaBear `p = 2^31 − 2^24 + 1`, so `⌊log₂ p_vm⌋ = 30`, `⌈199/30⌉ = 7`). The only loss is the "same ℓ for both zkVMs" robustness aside; the `ℓ = 7` conclusion is unaffected. Low impact — this is an illustrative instantiation, not a target claim.

---

## Summary of scope changes requiring operator approval

- **⚑ #3 (line 55):** the ℓ=7 instantiation stops citing "both RISC Zero's BabyBear and SP1's KoalaBear" and cites KoalaBear alone. Arithmetic unchanged; only the cross-zkVM robustness aside is lost. Minor.
- #1 (line 17) and #2 (line 21) are non-scope: a dropped citation and a dropped half-example, respectively; the field-mismatch-tax formalism is field-generic and unaffected.

Net effect in this chapter: no argument narrows. The only visible change is that the two 31-bit-field examples (BabyBear + KoalaBear) collapse to the single evaluated field (KoalaBear). `RISC-V` (the ISA) is preserved throughout.
