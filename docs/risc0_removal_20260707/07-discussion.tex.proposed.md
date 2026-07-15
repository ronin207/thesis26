# PROPOSED edits — strip RISC Zero from `07-discussion.tex` (SP1-only retarget)

**Status: PROPOSAL ONLY. Nothing applied to the manuscript.** This is a framing /
contribution chapter; the operator reviews before anything lands.

**Target file:** `修論2025_Takumi/07-discussion.tex`

## Scan result

Full scan of `07-discussion.tex` for `RISC Zero`, `RISC0`, `RISC~Zero`,
`sys_bigint`, `Zirgen`, `\cite{bruestle2023risczero}`, and substrate-count
phrasing (`two zkVMs`, `both`):

- `\cite{bruestle2023risczero}` — **not present** in this file. Nothing to remove.
- `sys_bigint` — **not present.**
- `Zirgen` — **not present.**
- RISC0 measurement rows / numbers / RISC0-attributed claims — **none present.**
  (The measured numbers in this chapter — the ~22 min Aurora Loquat run,
  `R_static ≈ 0.3 s`, Fractal `0.86–18.5 s`, and the `3.76 min` vs `44–64 min`
  Loquat substrate comparison where "the zkVM" is singular — are all Aurora /
  static-circuit or the single measured zkVM (SP1). None is attributed to RISC
  Zero, so none is removed.)
- RISC-V / RISC~V — **not present** in this file, so the hard constraint to keep
  the base ISA never fires here.

**Exactly 2 RISC0 mentions found, both in §"What Generalises and What Does Not".
Both are contribution-scope claims.** Details below.

No `\ref`/`\label`/`\cite` is orphaned by either edit: both are pure prose
changes inside sentences that carry no RISC0-specific label or reference.

---

## Block 1 — line 124–125 (generalisation anchor: `RISC~Zero/SP1`)

**CURRENT (exact):**

```latex
substrate-independent: they apply to any large-field algebraic-hash
post-quantum signature of this form verified in any small-field zkVM, not only
to PLUM in RISC~Zero/SP1. The
```

**PROPOSED SP1-only rewrite:**

```latex
substrate-independent: they apply to any large-field algebraic-hash
post-quantum signature of this form verified in any small-field zkVM, not only
to PLUM in SP1. The
```

**Rationale:** Drops the `RISC~Zero` half of the named substrate pair; keeps the
sentence (which is partly about SP1) intact and grammatical. Only the two tokens
`RISC~Zero/` are removed.

**⚠ CONTRIBUTION-SCOPE CHANGE — operator's call.** This sentence names the
concrete instances the substrate-independent mechanism specialises to. Original
asserts the mechanism was instantiated on *both* RISC Zero *and* SP1; the rewrite
narrows the stated anchor to SP1 alone.

---

## Block 2 — line 127–128 (empirical footprint: `provers of the two zkVMs studied`)

**CURRENT (exact):**

```latex
specific magnitudes (Section~\ref{sec:evaluation}) do not generalise: they are
tied to PLUM's $199$-bit field, the M5~Pro's $24$~GB envelope, and the CPU-bound
provers of the two zkVMs studied. We drew the boundary deliberately, so that the
```

**PROPOSED SP1-only rewrite:**

```latex
specific magnitudes (Section~\ref{sec:evaluation}) do not generalise: they are
tied to PLUM's $199$-bit field, the M5~Pro's $24$~GB envelope, and the CPU-bound
prover of the SP1 zkVM studied. We drew the boundary deliberately, so that the
```

Change: `provers of the two zkVMs studied` → `prover of the SP1 zkVM studied`
(plural `provers` → singular `prover`; `the two zkVMs` → `the SP1 zkVM`).

**Alternative wording** (if you prefer not to re-name SP1 mid-paragraph, since
the whole thesis is now SP1): `the CPU-bound prover of the zkVM studied`.

**Rationale:** `two zkVMs studied` asserts a two-substrate evaluation (RISC Zero
+ SP1). Retargeting to SP1-only makes the count singular; the rest of the
sentence (deliberately-drawn boundary, cost shape carrying over) is untouched.

**⚠ CONTRIBUTION-SCOPE CHANGE — operator's call.** This is the sharper of the
two: it reduces the *empirical evaluation footprint* the thesis claims, from two
zkVMs measured to one. Any earlier claim (abstract, intro, evaluation chapter)
that the study covers "two general-purpose zkVMs" or "RISC Zero and SP1" is
inconsistent with this rewrite unless those are retargeted in the same pass. See
"Cross-file note" below.

---

## Cross-file note (not part of this file's edits)

The task flagged "the abstract's stated targets" and "both RISC Zero and SP1"
phrasing as scope-narrowing items. **Those live in other files** (abstract,
intro, evaluation, theoretical chapters), **not in `07-discussion.tex`.** Within
this chapter the only two count/substrate claims are Blocks 1 and 2 above. If the
operator approves the SP1-only narrowing here, the "two zkVMs" / "RISC Zero and
SP1" framing in the abstract and other chapters must be retargeted consistently,
or the discussion chapter will contradict them.

---

## Summary for operator

- **Mentions covered: 2 / 2** (both in §"What Generalises and What Does Not").
- **No** `\cite{bruestle2023risczero}`, `sys_bigint`, `Zirgen`, RISC-V, or
  RISC0-attributed numbers in this file — nothing else to strip.
- **No orphaned `\ref`/`\label`/`\cite`.** Both edits are pure prose; document
  stays compilable.
- **Two contribution-scope changes need your approval:**
  1. Block 1 — generalisation anchor `PLUM in RISC~Zero/SP1` → `PLUM in SP1`
     (narrows named instantiation to SP1).
  2. Block 2 — `provers of the two zkVMs studied` → `prover of the SP1 zkVM
     studied` (narrows the measured-substrate count from two to one; the
     load-bearing one — makes "two zkVMs" claims elsewhere inconsistent unless
     they are retargeted too).
