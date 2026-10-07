# Thesis body register audit — 2026-07-20

Read-only Sako-reading-test sweep of §2–§8 (one agent per file). The abstract + intro were already rewritten to plain register; this maps where the **body** still violates it. Flags: **#1** rhetoric/sophistication · **#2** jargon-before-gloss · **#3** weld (`:`/`;` joining two full statements) · **#4** comma-piled claims · **#5** undefined jargon · **#6** literal "Horn" · **#7** altitude (sub-mechanism where behavior would do).

## Section severity (worst → cleanest)
1. **07-discussion** — register weak point of the manuscript
2. **08-conclusion** — rhetoric + 4× "Horn"
3. **055-security** — ~13× "Horn" incl. a section header; self-referential prose
4. **06-evaluation** — summarizing prose welded/piled (numbers-with-setting PASSES)
5. **04-theoretical** — formal content clean; connective prose welded
6. **05-system** — 3 showcase paragraphs welded/piled
7. **02-related** — mid-level; precompile def + CAPSS sentence
8. **03-preliminaries** — cleanest; mostly welds + one forward-ref term

## Cross-cutting cheap fixes (mechanical, zero number/proof risk)
- **"Horn" → "obstruction"** (Horn 1 → first obstruction, Horn 2 → second/remaining obstruction). Spots: 055-security L36, 325 (header "…Reduced to Horn 2"), 326, 328, 330, 352, 354, 355, 357, 383, 389, 452 · 07-discussion L5 · 08-conclusion L9, 15, 33, 55.
- **"postdict"/"postdictively" → "predicts (after the fact)"**: 08-conclusion L6, 12 · 04-theoretical L107 · 06-evaluation L2, 77, 78, 244.
- **"load-bearing" → "essential/required"** (rhetoric): 055-security L4, 12, 102, 125, 129, 133, 146; 03-preliminaries L154.

## Per-section findings (file:line | quote | flag | fix)

### 07-discussion (worst)
- L5 | "the anonymity-providing artefact both runs and binds… : … : … so binding and zero-knowledge combine in one measured proof" | #3+#4 | split into 4–5 sentences; lead "Two results hold."
- L5 | "single remaining horn of the dual obstruction, Horn 2" | #6 | → "the remaining obstruction"
- L5 | "recursion-shape provisioning wall the default path implies does not bind… What withholds it is the primitive" | #1+#5 | "Memory is not the limit. The limit is the primitive: the only wrap the toolchain provides uses pairings again." (gloss "provisioning wall" = need to rebuild a large table in advance)
- L5 | "still cannot have it, and not for want of resources" | #1 | "…still cannot get it here, and the reason is not a shortage of memory or time."
- L10 | "they trade different costs… depends on a single property…: how often the verification predicate changes…" | #3+#4 | split; "The right choice depends on one thing: how often the verification rule changes vs how often proofs are made."
- L7 | "The obstruction is scoped to the zkVM stack: the static-circuit regime does produce…" | #3 | two sentences
- L29 | "At that magnitude… the wall-clock crossover would favour the static circuit… ; the same-scheme sign… settled below as a conjecture" | #4+#3 | three sentences
- L2 / L45 | "the sharpest of these findings… turn the surrounding cost picture into guidance" / "draws these threads together" | #1 | plain restate

### 08-conclusion
- L9, 15, 33, 55 | "horn"/"Horn 2" | #6 | → "obstruction"/"the remaining obstruction"
- L2 | "That ladder is the backbone of this conclusion, and the cost criterion, the hash-cost inversion, and the deployment decision rule fill it in." | #1+#4 | "The following subsections cover the cost criterion, the hash-cost inversion, and the deployment decision rule in turn."
- L2 | "We answer it in layers." | #1 | "The answer has several parts."
- L6, 12 | "postdicts" | #5 | "predicts"
- L15 | "run correctly inside the zkVM: credential generation executes… ; the classical anonymity…" | #3 (colon + semicolon) | split
- L9 | "What binds is a fact about the primitive: the wrap the toolchain ships is pairing-based…" | #3 | split at colon
- L55 | "what we hand to the design of the next such system" / "mapped frontier" | #1 | "the main result this thesis leaves for the next such system"
- L6 | "so this pay too sits on the field-mismatch axis" | #4+#1 | "so this saving is also a field-mismatch effect."

### 055-security
- All "Horn" per cross-cutting list (rename incl. section header L325 → e.g. "Post-quantum anonymity: which obstruction remains"; enumerate labels L354/355 → "First obstruction (…)"/"Second obstruction (…)")
- L4 | "two load-bearing premises we name at the outset rather than leave to a subordinate clause" | #1+#4 | delete meta; state two premises as two plain sentences
- L4 | "we carry each premise as an identified, scoped open condition, not a defect, closing the first being machine-checking… and closing the second a composition proof" | #3+#4 | "We carry each premise as an open condition. The first closes by machine-checking. The second closes by a composition proof."
- L194 | "It is worth stating, term by term,… the honest answer is that none of the five is a… expression: every one resolves to ``negligible''" | #1+#3 | "None of the five error terms is a concrete parameterised expression. Each resolves to `negligible'."
- L318 | "The genuinely dangerous case for Assumption… is silent acceptance of an invalid Griffin trace" | #1 | "The case Assumption… must rule out is the AIR accepting an invalid Griffin trace."
- L36 | "Zero knowledge hides the witness; it cannot hide what the statement itself discloses." | #1+#3 | "Zero knowledge hides the witness. It does not hide what the public statement itself reveals."
- L2 | "Knowledge soundness transfers, modulo Assumptions…" | #2 | gloss knowledge-soundness on first use; drop "modulo"
- L12 | error-terms-vs-assumptions distinction buried in nested parenthetical | #4+#7 | lift into one standalone sentence

### 06-evaluation (numbers-with-setting PASSES — do not touch figures)
- L2 | "the criterion's measured evidence separates three findings (…): Griffin removing 58.5× cycles yet losing…, the matched-field control confirming… (164×…), and the power-residue symbol paying 10.33×…" | #3+#4 (the opening spine) | "The evidence gives three results. First, Griffin removes 58.5× cycles but still loses on committed area. Second,… Third,…"
- L2, 77, 78, 244 | "postdicts" | #5 | "predicts"
- L73 | "explicitly-confounded control… not a curated-setting artefact" | #4+#1 | "The control changes two things at once, the hash and the field, so it does not isolate the hash. It is matched only on security level λ."
- L256 | "In sum: Griffin pays… ; the matched-field control confirms… ; and the power-residue chip… 10.33×" | #3+#4 | "To sum up, two cases pay and one loses." then one sentence each
- L143 | 58.5× sentence carrying five claims | #4 | three sentences
- L78 | "The precompile bought a finite measurement, and the accounting prices why a speedup… was never available." | #1 | "With the precompile the run completes and can be measured. The cost model explains why it is still no faster…"
- L80 | "twenty-six field-operation gadgets… S-box's own arithmetic that no small-field arithmetisation escapes…" | #7+#5 | behavioral restate (only ~10 of 26 per-row ops are true 192-bit mults; rest are additions charged at mult price)

### 04-theoretical (formal content clean)
- L103 | "The pay… is on a different axis: the per-symbol control overhead the chip removes… the syscall-dispatch and cross-shard-bus core area… which the power-residue-PRF case measures as a 10.33× reduction" | #3+#4+#5 | 2–3 sentences; "the chip removes the per-symbol dispatch work of the emulated loop, cutting committed area 10.33×."
- L65 | "commits, per execution shard, one trace matrix per chip… scales quasi-linearly with… committed trace cells" | #2 | gloss trace/shard/chip on first use
- L3 | "…lowers total trace area; the soundness obligation… is the functional-equivalence-plus-trace-binding condition…" | #3+#2 | split; "the precompile computes the same function and its output is tied to the proof"
- L107 | "postdictively" + "the model cannot but predict" | #1+#5 | "after the fact" / "necessarily predicts"
- L18 | "Amdahl ceiling" unglossed + caveat-pile | #5+#4 | "does not by itself cap how much the zkVM cost can improve"; split
- L52 | "suggestive of the field-mismatch tax at work" | #1 | "consistent with the field-mismatch tax, but a whole-workload ratio, not the per-multiplication bound"

### 05-system
- L116 | "The chips' committed dimensions sharpen rather than simply confirm this: … ≈18% narrower… so on per-operation area alone it leans toward paying, and the predicted not-pay verdict rests…" | #3+#4 | four sentences, one claim each
- L2 | "…built around one reusable interface, which we instantiate three times as a small family, and its integration…" | #4 | "…is one reusable interface, instantiated three times. We then integrate it…"
- L2 | "The same Griffin chip that lowers… enlarges the machine that recursively verifies the shards… the wrap's recursive-compression stage (its compress tail)…" | #4+#2 | two sentences; gloss "shards"/"compress tail"
- L70 | "The chip exposes one permutation; hashing needs a mode around it." | #3 | two sentences
- L116 | "FP192_POW_RES is the interesting case." / "three chips evidence for one method rather than three unrelated artefacts" | #1 | plain restate
- L41/64 | "AIR" (subsection title + body) unglossed | #2/#5 | one-clause gloss on first use (verify not already glossed in §prelim)

### 02-related
- L32 | "replaces its emulation with a native AIR (algebraic intermediate representation) sub-circuit invoked by syscall" | #2+#7 | behavioral: "replaces the slow emulated version with a custom accelerator the program calls, so it runs at full speed"
- L26 | CAPSS/SmallWood sentence stacking scheme + 3 numbers + follow-up | #4+#3+#5 | split into 3 sentences; gloss "algebraic hash" here
- L32 | "whether a native large-field AIR removes the field-mismatch tax at all" | #1+#5 | "whether a custom accelerator over the signature's own large field removes the slowdown from the size mismatch"
- L2 | "earns its place… the move that forces a zkVM… become load-bearing" | #1 | plain restate
- L26 | "BDEC… is the closest prior work: it instantiates…" | #3 | two sentences
- L35 | "the masking a FRI-based STARK needs for zero-knowledge is subtle…" | #2+#7 | "the extra step these proof systems need to keep the witness hidden is easy to get wrong…"

### 03-preliminaries (cleanest)
- L257 | "field-mismatch tax" used here but defined 333 lines later at L590 | #2 | gloss in one clause here, or move L590 def earlier
- L47 | width-4/d=3/14-round + truncation + birthday-cap + disclosure in one sentence | #3+#4 | split at `;`, one claim per sentence (keep numbers exact)
- L43 | "low-degree S-box substep… Horst-type quadratic map on the remaining lanes" | #7+#5 | behavioral fact suffices; per-lane S-box belongs in the Griffin-AIR section
- L17 | "eliminating cross-primitive field conversions; PLUM achieves this fully, while Loquat retains the extension-field lifting…" | #3+#5 | two sentences; gloss "extension-field lifting"
- L154 | "We reject that term as a load-bearing descriptor: it conflates…" | #3+#1 | "We do not use that term, because it mixes several separate cost properties."
- L585, 588 | trace/chip/AIR glosses joined by colons | #3 | split (these are otherwise model glosses)
- L268 | "Two orthogonal axes" | #1 | "two independent axes"

## LOOP PROGRESS (2026-07-20, /loop toward Sako-register goal)
- ✅ Tier 1 DONE: "Horn"→"obstruction" (20 spots, incl. §6-security header + item labels), "postdict" glossed once at first use §4:107 (kept — load-bearing epistemic term, NOT swapped to "predict"), "load-bearing"→"essential" (10 spots).
- ✅ §7 discussion DONE — all 6 flagged paragraphs rewritten, verified, compiles 126pp.
- ✅ §8 conclusion DONE — 9 fixes (ladder/backbone/"answer in layers"/"mapped frontier" rhetoric + colon/semicolon welds), verified, compiles 126pp.
- ✅ §6-security (055-security) narration DONE — 7 fixes (knowledge-soundness gloss, meta-paragraph, ZK aphorism, L194/L318 rhetoric, error-terms distinction, last load-bearing), verified, compiles 126pp.
- ✅ §6-evaluation DONE — 6 fixes (three-finding spine, In-sum roll-up, confounded control, 58.5× pile, 26-gadget behavioral, "bought a finite measurement"), verified, compiles 126pp.
- ✅ §2 related DONE — 7 fixes; AIR/sub-circuit/syscall removed from §2 prose (term-order fixed, confirmed case-sensitive AIR=0), CAPSS pile + BDEC colon split, algebraic-hash/masking glossed, "earns its place"/"load-bearing" gone. Compiles 126pp.
- ✅ §5 system DONE — 8 fixes (two opening piles, dimensions weld, interesting-case/unrelated-artefacts rhetoric, log-derivative altitude, L70/L131 welds). AIR gloss NOT needed (already defined §3:588 before §5). Compiles 126pp.
- ✅ §4 theoretical DONE — 5 fixes (soundness-obligation weld, control-overhead weld+pile, Amdahl gloss, "suggestive" rhetoric, Aurora paren-lift). L65 trace/chip/shard left (glossed §3). Compiles 126pp.
- ✅ §3 preliminaries DONE — 5 fixes (extension-field-lifting weld, birthday-cap pile, load-bearing-descriptor weld, field-mismatch-tax first-use gloss, orthogonal→independent). L43 S-box + L585/588 definition-glosses left (legitimate preliminaries).
- ✅ FINAL FULL-DOC RE-AUDIT CLEAN (2026-07-20): Horn=0, load-bearing=0, all 17 rhetoric-tells=0 across §2–§8; thesis compiles 126pp, no undefined refs. Straggler sweep caught + fixed "earns its place" (§8) and 4 more load-bearing (§3/§5).
- ✅ **GOAL MET** — every body section now in the plain least-informed-referee register; layers glossed on first use; all numbers/claims/citations preserved. /loop stopped.
- INVARIANT each iteration: preserve all numbers/claims/citations; compile 126pp; grep-verify.

## Recommended triage for deadline day
- **Tier 1 (safe, mechanical, apply now):** "Horn"→"obstruction" (all ~18 spots), "postdict"→"predict" (~7), "load-bearing"→"essential" on motivational uses. No numbers/proofs touched.
- **Tier 2 (prose rewrite, by severity):** 07-discussion → 08-conclusion → 055-security narration → 06-evaluation roll-ups. Weld-splitting + de-rhetoric, preserving every number/claim/citation.
- **Tier 3 (if time):** 04/05/02 connective welds; 03 field-mismatch-tax gloss forward.
