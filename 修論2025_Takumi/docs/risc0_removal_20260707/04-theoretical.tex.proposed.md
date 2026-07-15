# PROPOSED edits — strip RISC Zero, retarget `04-theoretical.tex` to SP1-only

**Status: PROPOSAL ONLY. Nothing applied to the manuscript.** This is a framing /
contribution chapter; the operator reviews before anything lands.

**Scope of this file:** `修論2025_Takumi/04-theoretical.tex` only.

**Summary of findings**
- RISC0 mentions in this file: **3 sites** (lines 17, 21, 55). All 3 are covered below
  as MANDATORY edits.
  - Line 17: one `\cite{bruestle2023risczero}` inside a 5-key citation list.
  - Line 21: a `BabyBear … in RISC~Zero` native-field example, bundled in the same
    parenthetical as the KoalaBear/SP1-fork example (sentence is partly about SP1 →
    reworded, not deleted).
  - Line 55: a `for both RISC~Zero's BabyBear and the SP1 fork's KoalaBear`
    parenthetical (reworded to KoalaBear/SP1 alone).
- No `Zirgen`, no `sys_bigint`, no `R0VM`/`Bonsai` in this file. `num_bigint` (line 170)
  is the Rust `num-bigint` crate on the SP1 measurement path, NOT a RISC0 artefact —
  **left untouched.**
- **No orphaned `\ref`/`\label`.** None of the removed text carries or targets a label.
- **The `bruestle2023risczero` bib entry is NOT orphaned by this edit** — it remains
  cited in 6 other chapters (01-intro, 02-related, 03-preliminaries, 05-system,
  055-security). So dropping it from line 17's cite list breaks nothing. (Removing it
  from those other files is a separate task, out of scope here.)
- **No CONTRIBUTION claim in THIS chapter narrows.** The theoretical results
  (Def. field-mismatch tax, Prop. fmt-lb, Prop. precompile-break-even,
  Prop. field-matching) are stated generically over "a zkVM whose native field is
  $\mathbb{F}_{p_{\mathsf{vm}}}$." RISC Zero appears here only as an illustrative field
  instantiation (BabyBear), never as a claimed contribution target. Stripping it drops
  an example, not a claim. The contribution-scope narrowing ("we target both RISC Zero
  and SP1") lives in OTHER chapters — see the note at the bottom.

---

## MANDATORY edit 1 — line 17: drop the RISC Zero citation from the literature list

**Current (exact):**
```latex
The first three dimensions are standard in the zkSNARK and zkVM literature~\cite{cryptoeprint:2024/868,10.1007/978-981-95-2961-2_6,bruestle2023risczero,succinct2024sp1,cryptoeprint:2023/1217}.
```

**Proposed (SP1-only):**
```latex
The first three dimensions are standard in the zkSNARK and zkVM literature~\cite{cryptoeprint:2024/868,10.1007/978-981-95-2961-2_6,succinct2024sp1,cryptoeprint:2023/1217}.
```

**Rationale:** Remove only `bruestle2023risczero,` from the multi-key list. The
remaining four keys (including `succinct2024sp1`) still support the "standard in the
literature" claim; the sentence is otherwise unchanged.

---

## MANDATORY edit 2 — line 21: rewrite the native-field example to SP1-only

**Current (exact):**
```latex
When it is proved by a zkVM whose prover field $\mathbb{F}_{p_{\mathsf{vm}}}$ is small (BabyBear, $p_{\mathsf{vm}} = 2^{31} - 2^{27} + 1$, in RISC~Zero; KoalaBear, $p_{\mathsf{vm}} = 2^{31} - 2^{24} + 1$, in the evaluated SP1 fork), each $\mathbb{F}_p$ operation must be emulated by software running on the zkVM's RISC-V instruction set, which in turn is encoded in $\mathbb{F}_{p_{\mathsf{vm}}}$.
```

**Proposed (SP1-only):**
```latex
When it is proved by a zkVM whose prover field $\mathbb{F}_{p_{\mathsf{vm}}}$ is small (KoalaBear, $p_{\mathsf{vm}} = 2^{31} - 2^{24} + 1$, in the evaluated SP1 fork), each $\mathbb{F}_p$ operation must be emulated by software running on the zkVM's RISC-V instruction set, which in turn is encoded in $\mathbb{F}_{p_{\mathsf{vm}}}$.
```

**Rationale:** Sentence is partly about SP1, so it is reworded rather than deleted. Drop
the `BabyBear … in RISC~Zero` clause and its semicolon; keep the KoalaBear/SP1-fork
example as the sole small-native-field instance. **`RISC-V` is preserved** (base ISA SP1
itself runs). No numbers changed.

---

## MANDATORY edit 3 — line 55 (Remark `rem:fmt-instantiation`): rewrite the host-field parenthetical to SP1-only

**Current (exact, first sentence of the remark):**
```latex
For PLUM ($\log_2 p\approx 199$) on a $31$-bit host field ($\lfloor\log_2 p_{\mathsf{vm}}\rfloor = 30$, for both RISC~Zero's BabyBear and the SP1 fork's KoalaBear), $\ell = 7$, so Proposition~\ref{prop:fmt-lb} places the per-multiplication tax between $7$ and $49$.
```

**Proposed (SP1-only):**
```latex
For PLUM ($\log_2 p\approx 199$) on a $31$-bit host field ($\lfloor\log_2 p_{\mathsf{vm}}\rfloor = 30$, the SP1 fork's KoalaBear), $\ell = 7$, so Proposition~\ref{prop:fmt-lb} places the per-multiplication tax between $7$ and $49$.
```

**Rationale:** KoalaBear alone is a 31-bit field ($p_{\mathsf{vm}} = 2^{31} - 2^{24} + 1$,
$\lfloor\log_2 p_{\mathsf{vm}}\rfloor = 30$), so $\ell = 7$ and the $7$–$49$ bound are
unchanged by dropping the "for both … BabyBear" comparison. `\ref{prop:fmt-lb}` intact.
No facts invented; no numbers changed. The rest of the remark (the $56.4\times$ figure,
etc.) is untouched.

---

## OPTIONAL coherence edits (operator's call — NOT RISC0 mentions, flagged for consistency)

After the three edits above, this chapter no longer names RISC Zero, but three phrases
still say **"zkVMs" (plural)** / **"target zkVMs"**, which read as "RISC Zero + SP1" and
become technically singular once RISC Zero is gone. These are **not** RISC0 mentions and
are **not** required by the task (they name no vendor); I am flagging, not forcing them.
The theorems remain correct either way — plural can also be read as "the class of
small-field zkVMs the thesis targets."

- **Line 25 (Def. `def:fmt`):** `Because the target zkVMs expose no native
  $\mathbb{F}_p$ instruction` → e.g. `Because the target zkVM exposes no native
  $\mathbb{F}_p$ instruction`.
- **Line 47 (proof of Prop. `prop:fmt-lb`):** `Schoolbook multi-limb multiplication, the
  method the evaluated zkVMs use` → e.g. `… the method the evaluated SP1 fork uses` (or
  `… the evaluated zkVM uses`).
- **Line 104 (Prop. `prop:field-match` lead-in):** `$\Theta(\ell^2)$ under the
  schoolbook routine the evaluated zkVMs use` → e.g. `… the evaluated SP1 fork uses`.

Recommendation: apply all three for singular-consistency if the thesis is now SP1-only,
but this is the operator's editorial call.

---

## NOT touched (verified non-RISC0, SP1 or generic — left as-is)

- Line 66/68: `the deployed SP1 toolchain … vm/gas.rs` — SP1, keep.
- Line 91: `SP1's own cost table prices its Keccak chip at 2,640 columns
  (rv64im_costs.json)` — SP1, keep. `production zkVMs` (line 91, 151) is generic, keep.
- Line 170: `num_bigint` — Rust `num-bigint` crate on the SP1 path, NOT RISC0, keep.
- All other `RISC-V` / `RISC~V` occurrences (base ISA) — keep per hard constraint (1).
- "both regimes" (line 210) = static-circuit vs zkVM; "both directions" (line 214),
  "both quantities" (line 25), "both terms" / "two arms" (line 91) — none refer to
  RISC0+SP1; keep.

---

## Cross-chapter note (informational; OUT OF SCOPE for this task)

The contribution-scope narrowing the operator must eventually decide lives in OTHER
files, not `04-theoretical.tex`:
- `01-intro.tex:17` — "Both RISC~Zero and SP1 permit application-defined precompiles…"
- `05-system.tex:27` — "Both target zkVMs already ship a 256-bit modular-multiplication
  precompile … SP1's UINT256_MUL and RISC~Zero's sys_bigint(OP_MULTIPLY)"
- `02-related.tex:34,45`, `03-preliminaries.tex:696` — RISC Zero + Zirgen + BigInt-256
  descriptions.
- `055-security.tex:319,355` — RISC Zero ZK-advisory / Groth16 x86-only obstruction.

Those carry the actual "we target both zkVMs" scope claim and the RISC0 ZK-obstruction
half of the dual-obstruction argument. Stripping RISC Zero there narrows the thesis to
SP1-only in a way that changes claims (e.g., the security chapter's two-substrate
zero-knowledge argument). Handle in separate, per-file review passes.
