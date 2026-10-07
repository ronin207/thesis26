# Whole-thesis review — 2026-07-17, six-reviewer panel

> **FIX ADDENDUM (same day).** All non-framing findings below were repaired in a
> two-round pass and re-verified by a blank-perspective panel (fresh
> proof-checker, ripple consistency auditor, top-to-bottom flow reader):
> anonymity/unlinkability/ε_AIR arms verified SOUND; the unforgeability arm
> repaired (prelim-style freshness clause quantifying over issued AND
> showing-time material, ledger-anchoring conjunct, extractor out of the win
> condition, both-relations reduction, conjunct-selection freshness rule,
> Q-bookkeeping fixed); round-2 flow fixes (λ-scope in §4, rv64im, tension
> named in §6, §7.5.3 self-contradiction, Table-1 legend, conjecture in the
> assumption census of §1/§9). Build clean, 125pp, 0 errors/undefined refs.
> STILL OPEN (Operator framing): empty \title{}, RQ flexibility axis (D1),
> "practically acceptable" operational bar (Wu AQ7), WHY-SP1 axis (D12),
> §6 mega-paragraph/E1 caveat dedup (deliberately not machine-rewritten).

Panel: cross-document consistency auditor, cryptography proof-checker, and four
technical-paper reviewers (§1/§2/§4, §3/§5, §6-Security, §7–§9+appendices).
All ten chapter files + main.tex + ref.bib read in full. Findings deduped;
"×2" marks a defect found independently by two reviewers.

Chapter map (main.tex include order): 01-intro=§1, 02-related=§2,
03-preliminaries=§3, 04-theoretical=§4, 05-system=§5, 055-security=§6,
06-evaluation=§7, 07-discussion=§8, 08-conclusion=§9.

---

## Verdict

The manuscript's **number lattice is fully consistent** (every headline figure
cross-checks between table, prose, and chapters; zero dangling refs; zero
missing cite keys), the **scoping honesty is uniform** (computational
anonymity / classical distinguisher / ZK-only-when-wrapped never oversold,
Thm 2/3 never swapped), and **5 of the 7 previously-open pending items are
fixed in the working tree**. What is NOT yet clean: (i) three logic holes in
the security argument's games/reductions, (ii) a cluster of
claim-contradicts-own-data sentences, (iii) results and judgments sitting in
the wrong chapters, and (iv) a large definition-order debt. The empty title
remains submission-fatal.

---

## A. Blocking

**A1. Empty title.** `main.tex:139` `\title{}` (todo comment at :140).
Submission-fatal. Operator-only.

**A2. Unforgeability reduction inequality is false for the game as defined.**
`appendices.tex:69` claims `Adv^euf-cma(B) ≥ (1/N)·Pr[S₂]`, but the win
condition at `055-security.tex:57` has **no honest-key-anchoring conjunct**
(no ledger-membership requirement under `rt_cred,e`): an adversary using a
self-generated key pair produces a surviving run implicating no honest key,
so `E*` never fires yet `S₂` occurs. Fix: add an "implicated key is a
registered honest key" (ledger-membership) conjunct to the win condition, or
condition the probability on it — then re-derive the 1/N step.

**A3. The credential experiment is defined two contradictory ways.**
The gamebox `055:57` embeds the knowledge extractor **inside the win
condition** (with the extractor unbound — def:ks only asserts existence),
while the appendix proof (`appendices.tex:44`) defines G₀ *without*
extraction and introduces it as the G₀→G₁ hop. Same site: `Q` and `m*` are
free variables in the win condition (`Q` is bound only in §3's EUF-CMA game;
`m*` is never constructed from `x*`). Fix: state the game without the
extractor (standard practice), bind `Q` via the challenger's oracle
bookkeeping, define `m* = EncodeSig(x*)` explicitly.

**A4. Unlinkability game underspecified; terminal step unproven as worded.**
(×2 — found independently by the crypto expert and the §3/§5 reviewer.)
(a) Neither `03:432` nor `055:80` states whether the adversary receives
`(ppk⁰, ppk¹)` — with them the game as worded is trivially winnable, without
them it is unwinnable. (b) `appendices.tex:141` claims "the only b-dependent
component is the challenge pseudonym signature, now simulated without
psk^(b)" — but the challenge *statement/message* itself encodes `ppk^(b)`,
and def:szk's simulator runs "on the same message and public key", i.e.
simulation removes secret-key dependence, **not message dependence**. The
terminal needs a different argument (or the game needs the pseudonyms
withheld and that stated).

**A5. Chapter-opening soundness claim contradicted by own disclosure.**
`055:2` "knowledge soundness in full modulo Assumption asm:air" vs `055:279`:
the multi-shard extractor is an **unproved conjecture** (conj:extract-recursion)
that "touches the current core claim and not only a wrapped one. If the
conjecture fails, unforgeability is what is lost." Also: the theorem premise
"the zkVM is a knowledge-sound argument of knowledge" is not itself in the
assumption bundle. Fix: the opening sentence must carry the conjecture.

**A6. §4's tax ceiling is falsified by §4's own quoted measurement.**
`04:44` "Schoolbook multi-limb multiplication, the method the evaluated zkVMs
use, attains Θ(ℓ²), so the realised tax per multiplication lies between ℓ and
ℓ²" (=49) — vs `04:107`'s own 164× and its explanation "a general-bignum
(num_bigint), **non-limb-aligned** per-multiplication ratio that legitimately
exceeds the limb-aligned schoolbook ceiling ℓ²=49". The two sentences cannot
both stand; the :44 claim must be weakened to the limb-aligned case.

**A7. Results/judgments in the wrong chapters (three sites).**
- `05:115,130,132` — pay/no-pay *verdicts* and eval numbers (304-vs-371
  cells, ≈261:1, 10.33×, "the two costing essentially the same", "peaking
  near 15 GiB") delivered inside §5's soundness subsection.
- `03:312` — run statistics inside a Preliminaries definition: "completes in
  about 22 minutes (mean of three runs, 21.4–22.9)".
- `06:8` promises "whether a completed time is *acceptable* is the separate
  judgment of Section~\ref{sec:discussion}" — **§8 never renders it** (the
  word "acceptable" does not occur in 07-discussion.tex); it first surfaces
  in §9 (`08:2`) against a *never-introduced* bar ("sub-second
  interactive-showing latency"). This is also Wu AQ7 (operational definition
  of "practically acceptable") still unanswered.

**A8. Generic anonymity definition uses BDEC-instance symbols before they
exist.** `03:423` binds `Leak(stmt)` to `A↓`, `ppk_{U,TA}^{(j)}`, `ppk_{U,V}`
— first defined only in the BDEC construction at 03:443/480/485. The generic
definition cannot be parsed where it stands. Fix: parameterize Leak
abstractly in the definition; instantiate it in the BDEC subsection.

---

## B. Major — security-argument rigor

- **B1 (×2).** `055:127` attributes the t=256-inherits-Legendre claim to
  Assumption **asm:griffin-cr** (Griffin collision resistance); it belongs to
  **asm:q1** (whose sublabel (ii) says "inherited to t=256"); the retired box
  at 055:118 itself says PRF hardness "is not a property of Griffin".
  One-token fix: `\ref{asm:q1}`.
- **B2 (×3).** Assumption-count bookkeeping drift: `055:326` "three named
  assumptions … the fourth (key-privacy)" vs `055:144` "three of the five …
  a fourth (qrom) … the fifth (keypriv)" vs theorem's four premises
  (szk, lookup, bbt, air); `01:39`/`08:2` "five explicitly named open
  assumptions" counts bbt (not open) and qrom (open but carries no positive
  result) inconsistently. Pick one census and one ordinal scheme.
- **B3.** `055:67` — the anonymity adversary outputs `(cred_b, usk_b, A_b)`
  including **user secret keys**, but `055:37` says "There is no corruption
  oracle" and no game step grants them. State how the adversary obtains usk
  (e.g., adversarially generated users) or drop them from the output.
- **B4.** `055:10` "a strengthening that does not weaken the adversary" is
  false for the added win conjuncts (extractor success, JBind, `m*∉Q` all
  *narrow* the win predicate); and the freshness transfer consumes EncodeSig
  **injectivity** (`appendices:67` "BDEC's own obligation, not re-established
  here") which `03:89`'s definition never requires and no bundle assumption
  carries.
- **B5.** `appendices:14` — ε_AIR is a "probability" over an empty sample
  space ("worst-case over prover-chosen traces … no argument-verifier
  randomness enters"), hence 0-or-1-valued; "negligible ε_AIR" and the union
  bound `Pr[F₂] ≤ N_G·ε_AIR` (`appendices:48`) are degenerate dressing of a
  deterministic statement. Restate as a soundness *property* (∀ traces), not
  a probability.
- **B6.** `03:432` vs `055:81` — the prelim and Security-chapter unlinkability
  games hand the adversary **different challenge objects** (raw credential vs
  showing receipt) while `055:10` claims mere oracle-interface refinement.
- **B7.** `055:352` (prop:wall) — Horn 1 derives "ε_ZK not negligible" from
  simulator *absence* (non-sequitur; the SP1-docs leakage claim is the actual
  support) and calls the bare receipt "post-quantum-sound because hash-based"
  while `055:268/279` record the QROM extractor status as open.
- **B8.** `03:47` — no collision floor for the Griffin Merkle digest is
  stated anywhere (only the PRF √p ceiling at 055:123); asm:inherited(i)
  concedes "no floor being established at these parameters" — the digest-width
  intent claim is uncapped against λ=128.
- **B9.** `055:165` — stale orphan number: "the 9.4×10⁹-cycle execute-mode
  run" matches no run of record (CreGen execute = 9.12×10¹⁰, software-Griffin
  = 7.21×10⁹).
- **B10.** `03:480/493` — `c_{U,V}` enters ShowCre's input and witness with
  **no generating algorithm** anywhere (CreGen outputs only `c_{U,TA}`) and no
  statement of who signs it, though the third conjunct verifies it under
  `pk_U`.
- **B11.** `03:440` — BDEC's algorithm set (CreGen/CreVer/ShowCre/ShowVer)
  does not type-match the generic AC syntax (Setup, UserKeyGen, …, Show,
  Verify) it claims to instantiate; no interface mapping is given.
- **B12.** `055:265` vs `055:268` — adjacent-paragraph contradiction: "nor do
  we state whether it is claimed in the proven or the conjectured … regime"
  immediately followed by "The measured core commitment therefore sits in the
  proven unique-decoding regime." Rewrite the first, don't refute it.

## C. Major — definition order / forward references

- **C1 (×2).** asm:lookup's box (`055:246`) sits ~80 lines *after* its four
  premise-uses (055:144/147/161/168), none signposted "stated below";
  `055:144`'s "(Assumption asm:bbt … below)" points the wrong way (box is
  above at :113).
- **C2 (×2).** def:ks / def:szk / def:zk (also def:euf, def:eair) live only
  in the appendix (`appendices:9,17,21`) yet are consumed by every §6 gamebox
  and the Theorem, with no appendix pointer at first use (`055:10`).
- **C3.** `05:100–109` — Theorem thm:precompile-sound's hypotheses (1)–(3)
  and proof sketch are bare forward references to objects stated only in §6
  (asm:lookup 055:246, asm:air 055:91, asm:bbt 055:113, lem:relation-preserve
  055:160): uncheckable at point of reading. Add one sentence stating each
  hypothesis's content inline.
- **C4.** §3 forward-use list (worst offenders): `03:49` Griffin-syscall
  paragraph uses zkVM/precompile/syscall machinery defined at 03:578 and
  rem:prime-substitution at 03:209; `03:129` "BDEC's showing relation" ~300
  lines before BDEC; `03:222` B ("challenged symbols") never formally
  defined; `03:292` knowledge-soundness deferred to an appendix definition;
  `03:326` pp/usk/ipk free in the AC definition until the correctness
  paragraph.
- **C5.** Terms used before (or without) definition, §1/§2/§4: "chip" (AIR
  sub-circuit sense — never defined), "Cell 1/Cell 2" (04:52, defined 06:50),
  "execute/prove mode" (01:36, defined 06:8), "shard" (04:65, never defined
  in §1–§4), "keystone test/control" (never defined as a term),
  "already-served" (01:32, explained 04:103), "bare receipt" (01:20, taxonomy
  at 03:571–576), "natively" in the RQ (ambiguous, never disambiguated),
  "R1CS" unexpanded in §2, FRI/STIR/Legendre-PRF first uses without §3
  cross-ref, "arithmetisation-oriented hash" (§2) never equated with §3's
  "algebraic hash", "non-preprocessing static baseline" (04:15) never defined.
- **C6.** `055:244` — dangling antecedent: "Three of these hypotheses were
  graded partial or missing" — the grading table (055:190–217) is commented
  out; no grading exists in the document.
- **C7.** `055:383` — "the **earlier** recursion-shape provisioning wall":
  mechanism is described only later in include order (06:175); "earlier" has
  no antecedent.
- **C8.** `03:576` points the anonymity/unlinkability dependency at
  `sec:system`, but 05:127 defers exactly that to `sec:security`.

## D. Major — framing & cross-chapter consistency

- **D1.** `01:17` vs `02:4` — the research question never mentions the
  flexibility/update-churn axis, yet Table 1's uniqueness claim ("the
  flexibility column is where this thesis stands alone") answers exactly that
  axis. Either the RQ gains the axis or the Table-1 claim is re-scoped.
  **Operator framing call** (ties to the known RQ-box decision).
- **D2.** `02:15` vs `04:138` — Table 1 scores the thesis "High" flexibility
  with no stated High/Low criterion, while §4.4's own churn math shows
  precompile-touching changes re-impose static-circuit churn (N_circ, N_param,
  N_audit ≥ 1). State the criterion (e.g., "High = guest-code-only changes
  ship without circuit regeneration") and scope the row.
- **D3.** `02:2` — missing premise in the load-bearing holder-side-churn
  inference: circuit re-audit/regeneration is issuer/developer-side work
  independent of where the prover runs; the artifact-distribution argument
  that closes the gap is never stated.
- **D4 (×2).** Criterion triad mismatch: `01:32`/`08:6` name {Griffin,
  **field-multiplication chip**, power-residue} with intro citing §7, but
  `06:2`'s triad is {Griffin, **matched-field control**, power-residue}; the
  field-mul no-pay verdict is a §5 *prediction* explicitly not measured
  end-to-end (05:115), yet §9 states it as a finding.
- **D5.** `main.tex:157` (abstract) — "Calibrated on the three shipped
  precompiles, the criterion accounts for…" converts the criterion's one
  **out-of-sample test** (already-served power-residue break-even, 04:107,
  06:248 "postdictive on its two calibration points") into a calibration
  point. The abstract oversells; one word-level fix.
- **D6.** `07:29` vs `07:39` — crossover verdict asserted as fact ("the
  wall-clock crossover favours the static circuit in any realistic churn
  regime") then downgraded ten lines later ("the sign of that crossover is a
  conjecture rather than a measurement"), and the assertion rests on the
  cross-scheme reading §7.6 rules "not licensed".
- **D7.** `06:257` — "In sum" quotes Griffin's pay in execute cycles two
  sentences after declaring that metric misleading, and says "the one
  instance … paying" while the same sentence reports a second paying instance
  (power-residue 10.33×).
- **D8.** Eval/Discussion duplication: `06:177` duplicates §8.1's central
  judgment ("What binds is … the dual obstruction"); `06:312/337` duplicate
  §8.2's re-audit / conditional-flexibility judgments. Keep the observation
  in §7, the judgment in §8.
- **D9.** `06:59/64/69` — headline DNF has no stated stopping rule: table
  says "DNF (time budget)" (budget undefined), prose says "ran for 5 h 07 m …
  before we stopped it by hand", §9 inherits "over five hours without
  terminating".
- **D10.** `01:30` vs §9 — Contribution 1's second half ("we prove that
  *everlasting* anonymity cannot be established … and give the conditional
  route out") is answered nowhere in §9's Findings/Answer; it appears only as
  a Future-Work caveat (08:46).
- **D11.** `04:88` (mirrored 01:32) — the counter-intuitive premise that the
  syscall arm runs *more* guest cycles is asserted as if model-derived, with
  no §7 reference and no stated cause; the "for every non-negative choice of
  the κ's" conclusion rests on it.
- **D12 (known open).** `01:13` + `02:29` — WHY-SP1 has no stated selection
  axis in §1/§2 while §2 itself names OpenVM as "custom-chip-native".
  **Operator framing call** (known: host-agnostic finding + ergonomics +
  complete wrap pipeline; concede OpenVM as production target).
- **D13.** `05:90` vs `03:64` — contradiction on what the guest-side 2-to-1
  compression serves: "used by the BDEC Merkle trees" (05) vs ledger trees
  outside the proof, in-proof cost from PLUM's BCS commitments (03).
- **D14.** `05:130` — `R_cre^PLUM` attributed to §3, which defines only
  `R_cre^Σ`; the PLUM-superscripted symbol exists nowhere else.
- **D15.** `04:3` — §4's roadmap sentence announces churn/decomposition
  before the criterion; actual order is 4.1→4.2→4.3 criterion→4.4 churn→4.5
  decomposition, and the decomposition that *identifies Griffin as the
  target* comes after the criterion section that already argues Griffin.

## E. Major — repetition / paragraph structure (§6 esp.)

- **E1.** Pairing-based/classical-only caveat restated ~11×; asm:air-open
  caveat ~9× (055:2,92,144,165,169,188,296,316,321). Explain once,
  cross-reference after (the chapter's own boolean-only caveat at 055:88–89
  already models the right pattern).
- **E2.** Dual obstruction expounded three times in §6.3 (prose 326, formal
  prop 349–355, re-derivation 381–385); novelty claim duplicated near-verbatim
  (326 vs 387); `ssec:zk-gap` cites itself (328, 353).
- **E3.** Mega-paragraph sites, lead sentence not carrying: 055:2 (333 w),
  055:10 (168-w sentence), 055:237 (349 w), 055:296 (341 w), 055:298 (514 w);
  05:67 (~130-w first sentence, five semicolons); 03:43–47; 01:13; 01:20;
  04:18.
- **E4.** `055:448` — chapter ends on an open-problem aside; no tie-back to
  the opening promise; the delivery summary sits at the head of §6.3 (326)
  instead of the close.
- **E5.** `055:298` — `t` overloaded within one chapter (PRF t=256 vs "t=4
  Griffin" width; 03/05 use t_state precisely to avoid this); same paragraph
  uses both d=3 and "α=3" for the S-box degree.
- **E6.** `055:291/298` — Griffin-as-random-oracle question attributed to
  asm:szk when the chapter's own box (055:104) assigns it to asm:qrom.

## F. Minor (selected; full lists in the panel outputs)

- `06:170`+`08:36` "15.2 GB" vs sibling wraps in GiB (15.29/15.63/…).
- `06:344`+tab:platform "Cycle attribution is at λ=128" over-broad (58.5× and
  credential cycles are λ=80; each locally labelled; 08:24 states it right).
- tab:proof-mode `706 min` row silently bundles the one-time 2.96 h
  core-shape pass; k=2 statement-bound wrap (10.21 h) has no table row.
- Table 7.1 "†mean of five runs" marks Cell 2 only; Cell 3's 13.24 is equally
  n=5 (06:76, 341).
- `055:399` d* used in conj:rbr-stir, never defined in the manuscript.
- Two figures never \ref'd: fig:fmt-precompile (05:62), fig:dual-obstruction
  (055:378).
- 8 uncited bib entries: cnsa2, cryptoeprint:2014/349, cryptoeprint:2024/367,
  eidas2024, l2beatzk, risczero2025r0vm2, scmp2021manavbharti, setty2024lasso.
- `05:82` hardcoded "\S5.3" + leftover `% TODO(Takumi)`; `05:10` stray math
  toggles "(execute$, $prove$…".
- `06:74` "markedly cheaper" for a 1.08× gap vs 06:341 "its magnitude we do
  not over-read".
- `06:89` \ref to the subsection the sentence itself sits in.
- `06:2` "we report them honestly" + priority self-assessment in the Eval
  opening (belongs in intro/discussion).
- `06:236` "about 6,603 Griffin permutations" — only count in the subsection
  with no run-record/derivation anchor.
- `08:36` Limitations "Statement binding" paragraph is mostly restated
  positives; the sole limitation ("wrap figures are single runs") buried in
  the last clause.
- `appendices:22,31` — formal layer carries deployment/measurement facts
  (def:zk parenthetical; proof step citing §7 empirics).
- Notation: Legendre `L_K(·)` (03:166) vs `L_t(K,·)` (03:33); H overloaded
  (2-to-1 compression vs arbitrary-tuple digest, 03:437/443 vs 03:53); ℓ
  collision (limb count vs Merkle leaf vector, 05:2 vs 03:53); `psk` =
  secret key (03:432) vs signature (03:443) — also hit by A4's proof
  (appendices:116/135, incl. `ppk ← {0,1}^λ` type error);
  `Griffin_FP192_Permute` (05:64) vs `Griffin_{F_p^192}` (03:49); "one cycle"
  (05:84) vs "one zkVM syscall" (03:49); `φ₂(A⁽¹⁾,A⁽²⁾)` arity-2 vs Φ defined
  over single vectors (03:499 vs 03:320); `(ρ^(j))` vs `ρ_{U,TA}` index form
  (03:496); `x_show` game-form (03:485) vs committed-form (06:170) — this
  pair IS reconciled at 055:34, keep.
- Abrupt openings: §3.4/§3.5 bare formalism; §5.4 opens with a float; §4.4
  opens with a definition environment, no transition.
- `03:17` §3.2 lead asserts "eliminating field-lifting overhead" that 03:252
  denies for Loquat.

## G. Checked clean (adversarial pass — what fired nothing)

- **Numbers**: full lattice verified consistent, incl. 14.24/13.24 (n=5,
  ranges), 46.83 min / 15.29 GiB (7 sites), 68.96, 103.34/136.82, 66.05,
  66.14/65.59, 127.94, 58.5× (=7.21e9/1.23e8), 164× (19 vs 3,121), 10.33×
  (11.37M vs 117.46M), ≈65×, shards 104/1018/1516/2011, 5.6e7 cells arithmetic,
  10,333 = 116,285 − 105,952, tab:ablation deltas recomputed, 2^82/2^87,
  2^175, 2^99.5 (PRF), B=16/28, Aurora 3.76/22 min/107.5 bits, 260/868 B,
  13.0 s smoke, 706 min = 11.76 h, 252 min = 4.20 h.
- **References**: 0 dangling \ref/\eqref, 0 duplicate labels, 0 missing \cite
  keys; impossibilitybox/\asmsublabel counters resolve correctly.
- **Scoping honesty**: computational/classical-distinguisher wording uniform
  at every site; ZK claims tied to the wrapped variant everywhere; bare
  receipt consistently "not zero-knowledge"; Thm1/2/3 roles never swapped.
- **Reduction directions**: all adversary-against-credential ⇒
  adversary-against-leaf; hybrid telescoping and Difference-Lemma mechanics
  correctly assembled (modulo A2–A4).
- **Assumption census**: exactly 6 boxes (air, szk, keypriv, qrom,
  inherited{griffin-cr,q1,bbt}, lookup) — the 8→6 consolidation is real; the
  defect is only the ordinal/open-count bookkeeping (B2).
- **One-name discipline**: recursion-shape provisioning wall + dual
  obstruction naming clean, all dead variants 0 hits; field-mismatch tax,
  cost criterion vs trace-area model roles distinct; statement-bound family
  consistent; precompile/chip/AIR consistent; Cell-1 DNF (time) vs Cell-2
  default-settings OOM kept distinct.
- **§2 roadmap/transitions**: sound; contribution order matches §1 and §7's
  "four findings, one per contribution".
- **Intro↔conclusion contract**: holds except D4 (triad) and D10
  (everlasting-impossibility unanswered in Findings).
- **λ=80/128 seam**: disclosed per table, no silent mixing (except the F
  blanket sentence).

## H. Known pending items — status in working tree

| Item | Status |
|---|---|
| 5a Empty \title{} | **STILL OPEN** (main.tex:139) |
| 5b x_show two-ways | **FIXED** — reconciled at 055:34 (h_UV deterministic in A↓); c_{U,V} private witness everywhere |
| 5c field-mul "not paying" spine | **FIXED** — aligned at 01:32/05:115/08:6; residual: D4 triad wording |
| 5d "deployable" definition | **FIXED** — def:deployable once at 055:153 = {KS, ZK, PQ-sound} in budget; flexibility separate |
| 5e Table 1 shape | **PARTIAL** — churn column named "Flexibility" not "Update churn"; row label "This thesis" (no BDEC+PLUM); lone ⊘ ✓ |
| 5f RISC-Zero-primary stale claims | **FIXED** — none survive; SP1 named as the measured zkVM (03:587) |
| 5g 4× hedge | **FIXED** — all three sites "estimated up to" |

## I. Suggested fix order

1. **Operator-only framing**: title (A1); RQ flexibility axis (D1); Table-1
   High criterion (D2); the "practically acceptable" bar + where §8 renders
   it (A7c); WHY-SP1 axis (D12).
2. **Crypto blockers needing the proof-hand** (A2, A3, A4, B3, B4, B5): game
   surgery — decide the win-condition anchoring, extractor placement, and
   pseudonym-visibility model first; the proofs then rewrite mechanically.
3. **One-token/one-sentence miswires** (batchable in one pass): B1 asm:q1
   ref; B9 stale 9.4e9; B2 ordinals; D5 abstract sentence; A5 opening clause;
   B12 regime sentence; C6 "graded" antecedent; E6 szk→qrom; F units GB→GiB;
   05:82 TODO/hardcoded ref; 06:89 self-ref; Cell-3 † mark.
4. **Chapter-discipline moves**: eval verdicts out of 05:115/130/132; Aurora
   run stats out of 03:312; 06:177/312/337 judgments to §8; D9 stopping rule
   stated once.
5. **Definition-order pass**: asm:lookup box above the Lemma; appendix
   pointers at first def:ks/szk/zk use; Leak abstracted (A8); thm:precompile-
   sound hypotheses inlined (C3); C5 term list — one cross-ref each at first
   use.
6. **De-duplication pass on §6** (E1–E4) — the caveat-once pattern of
   055:88–89 applied chapter-wide; expected shrink ≥15%.
