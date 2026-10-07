# Introduction referee-panel consensus — 2026-07-18

Six-referee blank-slate panel on `submissions/修論2025_Takumi/01-intro.tex` (abstract treated as fixed).
Panel: math-foundations grad, security-101 student, systems/CE grad, technical-writing expert (zero domain),
Sako-avatar, Wu-avatar. Three rounds: independent reads → convening (endorse/object) → chaired consensus.
13 agents, all findings text-verified with line numbers before ranking.

## Overall verdict

The skeleton is sound: goal–means–axis is present, negatives are owned up front, and every forward
pointer resolves. But §1.3's security paragraph (line 20) failed all six readers on first pass — one
~300-word paragraph carries the headline claim in undefined vocabulary — and the intro is currently
**less honest** (λ=80 unmarked as reduced) and **less concrete** (no timing figure) than its own
abstract, while handing the committee the "just use SHA-3" objection. All fixable at sentence level:
~15 targeted edits, no restructuring.

## Unanimous findings (all six independently, survived objection, text-verified)

1. **Line 20 must be split.** One ~300-word paragraph carries the two-layer split, the cost model,
   the deployable-anonymity triad (knowledge-sound / zero-knowledge / post-quantum-sound — none
   glossed), and the dual obstruction. All six readers stalled there.
2. **Cost vocabulary spent before definition.** "trace" (l.13), "chip area"/"core trace area"
   (l.20, 32), "guest"/"syscalls" (l.13); contribution 2 is priced entirely in these units. One
   defining sentence (prover commits a large table, the trace; cost scales with its area; a
   precompile adds dedicated "chip" rows) unlocks lines 13, 20, and 32.
3. **Pairing-based ⇒ not-post-quantum bridge dropped** at l.20 and l.30, though the abstract states
   it plainly ("relies on elliptic-curve cryptography, which quantum computers break"). Also
   "constraints" → unglossed "circuit" regression at l.5. Restore the abstract's clause at first use.
4. **λ=80 not marked as reduced** (l.32). The abstract admits "at a signature parameter reduced
   because the full level does not complete"; the intro must not be less honest than its own abstract.
   λ itself is never introduced in the intro.
5. **SHA-3 inversion lacks its guardrail** (l.13, 32). Body owns it verbatim (06-evaluation.tex:50
   "the control is not a deployable variant"; :346 "a diagnostic control … not a secure PLUM
   variant"). Without it a referee's first response is "then ship SHA-3-PLUM" — the math-grad
   panelist made exactly this misreading live.
6. **No timing figure anywhere in the intro** (zero hits for "14.24"/"minutes"), while the abstract
   leads with DNF → 14.24 min. Contribution 4 ("first empirical characterisation") is numberless.
   Put the one number into the contributions.

## Majority findings

- Loquat→PLUM carried by the single word "successor" (l.8) — goal-vs-means pothole; one clause
  pulled forward from §2 (what PLUM improves, on what axis) closes it.
- "Circuit" at l.5 has no antecedent — back-connect to the abstract's "algebraic equations, called
  constraints" gloss.
- "Bare receipt … of Section 3" (l.20, 30) promises a term §3 never uses (zero grep hits for "bare"
  in 03-preliminaries.tex). Align the gloss with what §3 actually calls it.
- AIR/chip gloss at l.13 is circular; make it functional: a fixed block of constraint rows appended
  to the trace.
- Contribution 1 (l.30) interleaves result/caveats/unglossed terms: "Horn" unintroduced, "standard
  model", "everlasting", "hash-committed showings"; Horn-1 resolution compressed past inferability.
- 60+-word sentences at l.10, 13, 20, 22 — break them (Sako register rule governs).
- "The wrap the toolchains ship is pairing-based" (l.20) and "a limit of the available primitives"
  (l.30) read universal but are established only for SP1's shipped wraps — scope to the studied stack.

## Contested → resolved (the panel did not rubber-stamp the avatars)

- **Rhetoric flattening: REJECTED as a blocker.** The l.13 rhetorical question and antithesis and
  the l.34 cleft stay — the three blank-slate readers reported the antithesis as the one sentence
  that survived into their summaries, and Sako-avatar herself classified it as goal/means structure,
  not marketing. Only the filler "it turns out" (l.20) goes.
- **State of the art: Sako's minimum, not writing-expert's maximum.** No survey passage (it would
  worsen the unanimous name-density problem). Three single clauses: why PLUM supersedes Loquat
  (l.8), why SP1 (l.13, precompiles as enabling feature), one clause situating BDEC (l.3).
- **Triple-mapping (Wu): adopted via the split, not a bolted-on sentence.** Two of three mappings
  exist but are buried; the third (quantum-secure → post-quantum-sound) is nowhere stated — add it
  when line 20 becomes three paragraphs, one pair per sentence.
- **"host already serves it" (l.32): gloss, don't replace** — "host" is the thesis's own consistent
  term (05-system.tex:116); add "(the host UINT256_MUL chip SP1 already ships)" at first use.
- **"calibrated and measured" (l.22): NO change.** Wu wanted it weakened; verified that
  06-evaluation.tex:233/245 owns the verb and carries the illustrative-only hedge at the pointer's
  destination. Honesty budget goes to λ=80 instead.
- **No definition of "field".** The math-grad calibration says every plausible referee has it; add
  only the missing inference at l.8: the zkVM's constraints are equations over a small prime field,
  which is why the prover has a native field at all.
- **Built-vs-measured reconciliation (l.34): take at demoted priority** — add "built and
  smoke-proved, but only the Griffin chip is on the measured path" (05-system.tex:116 verbatim basis).
- **"A static circuit does deliver both" (l.20): license it** with a back-reference to BDEC (l.3),
  e.g. "as BDEC's own construction shows".

## Paragraph-by-paragraph plan

| Target | Action |
|---|---|
| §1.1 ¶1 (l.3) | Add the mechanism clause the abstract has: showing = proving possession of a valid signature without revealing it — why a credential involves a proving system. Optionally +1 clause situating BDEC. |
| §1.1 ¶2 (l.5) | Gloss "fixed circuit" via the abstract: "— the verification expressed once as algebraic equations, called constraints —". |
| §1.2 ¶1 (l.8) | Three one-clause inserts, keep the praised field-mismatch passage: (a) gloss update-churn inline; (b) reason for Loquat→PLUM + comparability axis; (c) why a prover has a native field (constraints are field equations). Do NOT define "field". |
| §1.2 ¶2 (l.10) | Break the garden-path sentence into two short ones. |
| §1.3 ¶1 (l.13) | (a) functional AIR gloss; (b) gloss "guest"; (c) THE trace-defining sentence before "dominate the trace"; (d) gloss Griffin = PLUM's algebraic hash at first use; (e) SHA-3 guardrail clause ("a diagnostic control, not a deployable PLUM variant"); +1 clause why SP1. Keep the rhetorical question + antithesis. |
| RQ block (l.16–18) | Replace "if it cannot run natively" → "when plain execution cannot finish, what makes it run" ("natively" collides with "native field"). |
| l.20 | Split into three ¶s: (P1) two layers + cost model; (P2) requirement→property mapping, one pair per sentence, ADD the missing quantum-secure→PQ-sound pair; (P3) dual obstruction — fix "bare receipt" gloss to §3's actual term, restore ECC bridge, scope to SP1's shipped wraps, back-reference BDEC for the static-circuit claim. Delete "it turns out". |
| l.22 | Break the ~70-word consortium sentence into 2–3 declaratives. Keep "calibrated and measured". |
| §1.4 lead (l.27) | No structural change; optionally the headline number lives here instead of item 4 — one place only. |
| Item 1 (l.30) | (a) introduce "Horn" in half a clause; (b) ECC bridge; (c) explicit Horn-1 resolution; (d) gloss "standard model" + "everlasting"; consider splitting into dual-obstruction then everlasting-boundary. |
| Item 2 (l.32) | (a) mark λ=80 as reduced + why; (b) repeat SHA-3 guardrail; (c) gloss "host" chip. |
| Item 3 (l.34) | Add "built and smoke-proved, but only the Griffin chip is on the measured path". Keep the cleft. |
| Item 4 (l.36) | Put the numbers in: stopped after five hours precompile-free; five proofs averaging 14.24 min at λ=80 with the Griffin precompile. |
| Scope ¶ (l.39) | Half-clause gloss for "multi-shard receipt". Otherwise leave — panel praised its honesty. |
| §1.5 (l.41–42) | No change; every pointer chased by a panelist resolves. |

## REAL-SAKO COMPLIANCE OVERRIDE (added after panel, 2026-07-18)

Two panel resolutions adjudicated against the *simulated* Sako's concessions. The real Sako's
2026-07-17 DM is binding and overrides them:

1. **Rhetoric — comply literally, overriding the panel.** She wrote "avoid rhetorical phrasing"
   and has flagged register twice. Keep the necessary-vs-worth-building CONTRAST (the load-bearing
   content the blank-slate readers retained) but flatten the FORM: the l.13 rhetorical question
   becomes a declarative ("Building the suite raises a second question: whether a custom
   precompile is worth building."). "It turns out" still deleted.
2. **State of the art — her ask, not the panel's minimum.** She wrote "the introduction section
   should provide more information on state of the art." Deliver the agreed recipe beat: a short
   "who tried what and where they stopped" passage (3–5 sentences, each name glossed), placed
   after the basics are established. The panel's three clauses (why PLUM, why SP1, BDEC's
   neighbourhood) fold into it.

Deviations from her written comments are permitted ONLY when named openly in the cover note as a
pointed question with a proposed answer ("you suggested X; I did Y because Z — acceptable?").
Never silent.

## Hierarchy resolution

Sako approves the thesis: her register and checklist bind every edit (short declaratives, no
original term unexplained, least-informed referee, general-vs-specific tagging, goal/means/axis).
Wu's structural findings govern content emphasis and are all adopted (headline number, SHA-3
guardrail, triple mapping, off-measured-path clause) — none violates her register. Where they
clashed: state-of-the-art resolved at Sako's own round-2 minimum; "calibrated" kept per the
chase-the-pointer test; rhetoric kept where Sako-avatar classified it as goal/means structure.
