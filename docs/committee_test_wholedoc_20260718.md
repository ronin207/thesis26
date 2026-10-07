# Whole-document committee test — 2026-07-18

## FIX BATCH 3 (2026-07-19, Operator-authorized "rest of the changes"; abstract+intro FROZEN, untouched)
APPLIED + build 125pp: A1 (Θ(ℓ²)→at-least-linear/schoolbook-qualified, stmt+proof+§4:44), A2 (retitle
+ retense, decided 10.33×), A3 (precompile-paradox name removed thesis-wide), B1 (§6 answer-first
opening + trimmed closing), B2 (§2 opener split), B3 (two-lists disambiguation ×2 + orientation split),
B4 (chip vs trace roles), B5 (chip↔AIR bridge), B6 (core/compress-tail/shapes housed), B7 (verifying-key
TABLE canonical in §7/§8/§9), B8 (Cell 1/2/3 in rendered rows + tuned-config/DNF caption), B9 (91%
grounding), B11 (soundness-obligation pointer), B14 (§3 Cell-4→ssec:aurora-ref), C1 (execute/prove
gloss), C3 (DNF), C4 (6.9e6 consistency + both dividends), C6 (SHA-3 control named + control-flow
disambiguation), C7 (382=2×191, 261=191+~70), C8 (single-run honesty), C9 (§5:67, §6:173, §9:6 splits),
C10-partial (51h "projected" label).
REVIEW CHAIN RAN: committee reader 19/19 PASS zero regressions; Wu 10/10 SOUND ("batch is clean...
the Prop weakening fixes a real prior falsehood; arithmetic all checks"; verified ≈70 set-bits via
Hamming weight); Sako avatar 12 ACCEPT / 0 REJECT / 5 questions. ALL reviewer catches applied:
"cheap" dropped; caption OOM claim scoped to Cell 2; "at most a few-percent"→"indistinguishable from
free at single-run resolution"; asm:lookup added to §6 opening AND §6:452 closing modulo-lists;
§6:10 orientation sentence split; keystone "run" dropped (§4:107 referent flip); §3:588 condition split
across asm:air+asm:lookup; §9:6 "non-terminating"→"stopped unfinished after five hours" (×2) + axis
resolution clause; §7:236 dividends printed.
HELD FOR OPERATOR (cannot fix without input): (1) Sako-Q4: "control" word doing two jobs — her
preference is a full rename (control overhead→dispatch overhead) across §4/§5/§7/§9; (2) Sako-S1 +
Wu-caveat-5: the ≈51h projection basis — Wu computed 1.6s/setup × 185,862 ≈ 82h ≠ 51h, a REAL numeric
tension needing the run-record per-entry rate; (3) Sako-S2: §2:2 "what no prior work asks" scope
(pre-existing framing); (4) Wu-caveat-2: POW_RES forecast has no pre-run record citation (unlike
keystone's); (5) thermal 1.4–1.6× source + 104-shard record (C10 remainder); (6) Wu-caveat-9 optional:
§9:43 airtight-clause with per-permutation in-circuit cost comparison.

## FIX BATCH 2 (Operator-authorized: A4, B10, B12, B13, C2, C5, C9-§3:47-only) — APPLIED, build 125pp
A4 abstract "+computed in software without a precompile" (grounds: 06-eval:74); B10 intro
"irreducibly large-prime"→"which unlike the hash cannot move to a smaller field (§5)" (grounds:
05-system:116 verbatim); B12 §3:575 STARK expanded + succinct-vs-large resolved via wrapped-receipt
comparison only (NO size number invented — core receipt never serialised per §4:11) + self-ref fixed;
B13 intro criterion-vs-rule separated using §8's own heading "substrate-selection rule"; C2 ROM/QROM
glossed at §3:4 + "standard model" glossed at §6:355 first use; C5 §2: FRI/STIR functional gloss,
SmallWood/Winterfell/NTT glossed, name-torrent sentence split (names KEPT — deletion is Operator's),
⊘/●/○/--- legend added to tab:positioning caption; C9 §3:47 split into 3 paragraphs at sentence
boundaries, zero wording change.
DISCOVERY during C9: §3:47 says "the in-SNARK Cell-$4$ reference" — the body DOES use "Cell-4" once,
partially reversing the earlier declination of the §7 Cell-labeling fix: §3 names the Aurora leg
Cell-4 while §7 never labels it. Now a one-object-naming inconsistency (§3 "Cell-4" vs §7 "Aurora
reference"). NOT fixed (unauthorized); flagged to Operator.

## TIRED-HUMAN LINEAR READ (third pass, notes-sheet-only carry-over)

**Retention test PASSED**: after a full front-to-back read carrying only margin notes, what
survives is exactly the intended takeaway — DNF→14.24; Griffin loses to software SHA-3
(diagnostic, don't ship it); on SP1 a proof is PQ or anonymous, never both (implementations,
not principle); churn = re-audit footprint, not wall-clock; everything conditional is labeled.
The spine holds under human memory decay.

**Novel finding of this pass — position matters more than length**: the worst mega-sentences
sit at SECTION OPENINGS (§2:2 ~70w, §6:2 ~450w), where a tired reader decides whether to
engage or skim the whole chapter. §6:2's best sentence (the three-outcome compression) is its
LAST — inverting it (compression first, elaboration after) fixes the section's first
impression at zero content cost. Mid-section walls (§5:116, §6:173, §3:47) cost a re-read;
opening walls cost the chapter.

**Human-memory confirmations**: the §6 "fives" confusion is real for a human (five open
assumptions vs five/SIX leaf errors — held only by writing it down; a referee won't);
gloss-in-place works — §1–§4's huh→oh-yeah cycles resolve within the sentence; the
never-resolved huhs concentrate exactly where the agents said (§5:116 precompile-paradox,
recursion/verify shapes; §4 Θ(ℓ²) statement vs its own qualified ¶93 one paragraph above).

## RE-RUN VERDICT (second pass, post-fixes, same day — 8 fresh linear readers, §6 excluded as unchanged)

**Convergence on the previous round: ALL seven applied fixes verified landed** — §3 trace/chip/shard
paragraph (readers followed §4's break-even from it alone; §5:114/131 and §7 compress-tail/shard
discussions now parse), STARK bullet ("the word finally carries meaning"), §1 shard pointer resolves,
§2 AIR expansion present, §7:205 arithmetic reconciles one-pass (795,264+276,768=1,072,032 ✓),
§8 exception sentence accurate + "(below)" delivers, §9 SHA-3 paragraph sound/conditional/numerically
consistent. Abstract↔intro↔§3 naming chain verified ("default proof"→"receipt").

**NEW P0 — found precisely BECAUSE readers could now check the math (hand-verified):**
1. **§4 Prop. field-match (04:95) overclaims Θ(ℓ²).** States the removable benefit grows "as Θ(ℓ²) for
   ℓ>1"; but Prop. fmt-lb proves only ≥ℓ (ℓ² is attained by limb-aligned schoolbook), and the thesis's
   OWN measurement is 164 > 49 = ℓ² at ℓ=7 — contradicting Θ(ℓ²) as stated. Fix: "positive, at least
   linear in ℓ (Θ(ℓ²) under limb-aligned schoolbook multiplication)". A mathematical mis-statement in
   a Proposition — highest priority of the re-run. Related: 04:44 asserts the ℓ bound for
   non-limb-aligned paths that the proof only shows for limb-aligned.
2. **§7 stale open-vs-settled framing (hand-verified):** subsection title "an open break-even" (:256)
   and ":248 empirically decidable … rather than as a confirmed prediction" read as pre-measurement
   text, while :257 reports the decided n=3 result (10.33×). Retitle/retense.
3. **§5:116 "the same precompile-paradox this thesis documents" — the name occurs ONCE thesis-wide
   (hand-verified), right there.** Phenomenon exists (§7:205, unnamed). Drop the coined name or name
   it where documented.

**P1 (each one clause):** abstract SHA-3 sentence omits that the control ran in SOFTWARE/precompile-free
(one word restores the logic); §3 my new paragraph collapses chip=trace ("the table is a chip, and the
table is its trace") — separate them; chip↔AIR identity still never stated (one bridging sentence);
STARK acronym never expanded + succinct-vs-large collision in §3:575 + self-ref "Section 3" inside §3;
§8:5 "verifying-key map" vs §7 "table" vs §9 "mechanism" (one object, three names) + wall-clock-only
scope of §8's cost model stated after, not before, its equations; §7 table rows don't carry the Cell
1/2/3 labels the prose claims, caption omits tuned-config disclosure; §9:43 "ruled out by cost in
PLUM's native circuit setting" uncited; §1:32 "irreducibly large-prime" unglossed (home is §5:116);
§4:3 promises §4.3 names the soundness obligation — it doesn't (it's §3/asm:air).

**P2 polish:** execute/prove-mode never defined (load-bearing §4:18); ROM/QROM gloss; DNF unexpanded;
6,603 permutations still uncited (agent reverse-verified plausible: ≈6.9e6 cyc/perm both arms);
"core" as stage-name homeless; §2 FRI-as-replaced-object + SmallWood/Winterfell/NTT + ⊘ legend +
name-torrent ¶29; §4 controls ambiguity (88/103/107 read as 1–3 experiments); mega-sentences.

**Unchanged-and-good:** all arithmetic verifies everywhere checkable; pointer integrity thesis-wide;
honesty/scope discipline repeatedly called exemplary; §1/§2/§9 essentially pass.

Test: "Could a non-ZK professor on the committee read this sentence ONCE, understand what the
author did, and verify it against the section it points to?" Two prongs: one-pass comprehension +
verifiability. 9 parallel blank-slate section readers (§1–§9), each chasing cross-refs into other
files. Top findings verified by hand against the files (grep/read) before recording.

## HEADLINE VERDICT

**The verifiability prong PASSES across all nine sections. The one-pass prong fails in a
concentrated, cheap-to-fix way: one undefined vocabulary cluster + recurring sentence density.
No logic, accuracy, or coherence defect in the argument itself.** Fixable with a glossary pass +
sentence-splitting; no restructuring, no re-measurement.

- Pointers: 200+ cross-references, essentially all resolve. Exactly ONE broken (§1:39, self-inflicted, below).
- Numbers: every headline figure cross-checks arithmetically (agents re-derived; 58.5×, 164×, 10.33×, 1.08×, 34.8%, ablation deltas all recompute).
- Honesty: exemplary and consistent — measured/modeled/postdicted/extrapolated separated, reduced-λ carried everywhere, retired 32.53-min outlier disclosed, threats-to-validity thorough, proved-vs-assumed tagged per item.
- Scope discipline on the dual obstruction: §6/§8/§9 ALL scope it to SP1/studied-stack ("not a standard-model impossibility… we do not claim it is fundamental"). The zkVM-survey lesson is already honored throughout the body.
- The thesis's OWN coined terms (field-mismatch tax, precompile, update churn) are defined WELL and measurably — update-churn is a 4-tuple of explicit counts, clearing Sako's "flexibility" ban outright.

**The through-line of every failure:** the thesis defines its own invented vocabulary well but
treats INHERITED cryptography vocabulary as known.

## STATUS (updated 2026-07-18, end of session)
APPLIED + build-verified: §3 trace/chip/cell/shard definition (P1 #5); §3 STARK gloss (P1 #6);
§1 shard-pointer heal via §3 def + 4-word intro tweak (P0 #1); §2 AIR gloss (P0 #2);
§7:205 provisioned-vs-required disambiguation (P0 #4); §8:14 precompiled-primitive caveat (P2 #10).
DECLINED with reason: P0 #3 Cell 4 — NOT a body bug (body never scaffolds a four-cell scheme; uses
Cell 1/2/3 for table rows + Aurora as separate "Circuit-SNARK Reference Point"; adding "Cell 4"
would be a label with nothing behind it). DNF (P2) — trivial, table-cell overflow risk, left for caption.
LEFT for Operator: §6 two-fives (P2 #9, dense security prose — risky), mega-sentence splits (P2 #7,
editorial), criterion-vs-rule clause (framing), title, SOTA passage.

## PRIORITIZED FIX LIST

### P0 — correctness/coherence, before Sako (all VERIFIED by hand)
1. **§1 line 39 broken pointer (SELF-INFLICTED).** The gloss I added — "multi-shard receipt (a long run's proof is split across shards… Section~\ref{sec:prelim})" — points to §3, but `grep "shard" 03-preliminaries.tex` = 0. "shard" appears nowhere in the whole thesis except this line. Fix: repoint to §5/§6 (where shards/`conj:extract-recursion` live) or drop the section ref.
2. **AIR gloss orphaned (SELF-INFLICTED).** My §1 de-bloat removed the "(algebraic intermediate representation)" expansion. AIR is now first expanded at §3:581 (near the END of preliminaries) but USED at §2:32 (549 lines earlier) and throughout §4/§5. Restore a 3-word gloss at first use (keep one in §1, or add at §2:32).
3. **Cell 4 never labeled (§7).** §7:2 reframes the section around "four findings/cells" but Table `tab:plum-verify` (§7:50) labels only Cell 1/2/3 (no-precompile / Griffin / SHA-3). The Aurora/circuit-SNARK cell — the thesis's own Cell 4 — is present as content (§7:341 "the Aurora reference") but NEVER labeled "Cell 4." A committee member briefed on the four-cell scheme can't map it. Fix: label the Aurora row/subsection Cell 4.
4. **§7 line 205 two numbers unreconciled.** Post-chip "shape is 1,072,032" (= 795,264 + 276,768 provisioned) vs "1,064,022 required height" — 8,010 apart, both post-chip, not distinguished. VERIFIED: these are likely two DISTINCT quantities (provisioned/allocated shape vs actual required height), NOT an arithmetic error, but the text never says so — reads as an inconsistency. Fix: one clause distinguishing provisioned-shape from required-height.

### P1 — the big readability unlock
5. **Define trace / chip / committed-cell once in §3.** VERIFIED: §3 uses "trace" exactly once (§3:581, in passing) and never defines it; "chip"/"committed cell"/"trace area" appear nowhere in §3. Yet this cluster is the CURRENCY of the entire cost model (§4), the construction comparison (§5), and the evaluation (§7). One ~2-sentence definition (a STARK prover commits a rows×columns table of field elements, the trace; cost scales with its cells; a chip is one component's sub-table) unlocks §4/§5/§7 at once. Also state the "AIR = chip = trace-matrix are the same object" identity that §4/§5 assume silently.
6. **Gloss STARK once.** VERIFIED via §3 agent: "STARK" is never expanded anywhere in the thesis. The receipt-mode ZK distinction (§7/§8) rests on it. One inline gloss in §3.

### P2 — readability polish, time-permitting
7. **Split the ~8 mega-sentences** (300–450 words each, each an opening/summary that packs a whole section): §2:2, §3:47, §4:65, §5:67 & 116, §6:2 & 173, §7:2 & 257, §8:5, §9:6. Every one is individually CORRECT; they fail one-pass on length alone.
8. **Gloss inherited terms at first use:** IOP, univariate-sumcheck, random-oracle model/QROM, "standard model" (§6, load-bearing for the impossibility theorem, never glossed in-section), "simulator", "shard", DNF (never expanded — = "did not finish"), BCS.
9. **§6 "two colliding fives":** five leaf error-terms {ε_EUF, ε_KS, ε_AIR, ε_ZK, ε_sZK} vs five open assumptions {air, szk, lookup, qrom, keypriv}. A reader meets two distinct sets of five. Label them distinctly.
10. **§8 line 14 over-credits the zkVM:** "absorbs each such change as a guest-program edit" is false for the signature/hash-family case, which regenerates the Griffin precompile — the thesis corrects this at §8:33 but not at the claim. Also §8 internal tensions: rule says pick-zkVM-for-churn (14) vs wall-clock-static-wins (29); "fixes the sign of every term" (35) vs "sign is a conjecture" (39).

## Untraceable-number flag (for measurement-provenance follow-up, not blocking)
- §7:236 "about 6,603 Griffin permutations" (credential-relation verify) — asserted with no in-section run record or derivation, unlike the well-anchored 1,052 for standalone verify. Load-bearing (justifies 4.56×10^10 cyc).

## What NOT to touch (genuinely strong)
Verifiability, numeric consistency, honesty/scope discipline, proved-vs-assumed separation, the
own-coined-term definitions. §6's theorem/assumption STATEMENTS are readable as English even though
proofs aren't. §1 confirmed committee-ready post-edits. Don't spend effort here.

Related: [[thesis-intro-panel-consensus-20260718]], [[thesis-zkvm-pqzk-survey-20260718]].
