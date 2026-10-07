# d7 → final: exact changes, then the script

Takumi Otsuka · 5124FG15 · defence 29 July 2026, 10:00, first presenter

**Already fixed in d7:** p11 falsifiability clause trimmed · p12 706 minutes · p3 "total committed area" · p13 exact figures (68.96 / 103.34 / 136.82). Eight changes left, all find-and-replace.

---

## Part 1 — Exact changes

### Change 0 · p2 + p6 · PLUM is never defined — Sako's open comment

Her 26 July note, still unfixed: *"p6 you never wrote on slide what PLUM is, and people would not know that it is a signature scheme."* Reference [8] (PLUM) also sits in p5's footer, on a slide where PLUM is never mentioned — an orphan citation. Both close with one sentence. No new slide.

**p2, second bullet — append:**
```
BDEC[5], a post-quantum anonymous credential protocol, achieves all three
properties together at the signature layer, instantiated with the Loquat[14]
signature scheme. This thesis substitutes PLUM[8], Loquat's successor, which
computes over a 199-bit prime
```

**p2 footer — add reference [8]. p5 footer — remove it.**

**p6 — two words.**
**Find:** `One PLUM verification` → **Replace:** `One PLUM signature verification`

This is the sentence your appendix p20 already carries (*"BDEC is published with Loquat as its signature scheme. This thesis substitutes the protocol with PLUM, Loquat's successor. PLUM computes modulo a 199-bit prime."*) — it just needs to be in the main deck, where the audience meets PLUM for the first time.

**Have ready for Q&A:** why substitute PLUM for Loquat, when BDEC is published with Loquat? Take the answer from your own §3, not from memory.

---

### Change 1 · p7 · typo

**Find:** `A precompile is build only when it removes more proving work than it adds.`
**Replace:** `A precompile is built only when it removes more proving work than it adds.`

---

### Change 2 · p10 · drop "≈" from measured figures

These are exact measured values, not approximations. The ≈ makes them read as estimates.

**Find:** `≈ 68.96 min` → **Replace:** `68.96 min`
**Find:** `≈103.34 min (𝑘 = 1),` → **Replace:** `103.34 min (𝑘 = 1),`
**Find:** `≈ 136.82 min (𝑘 = 2)` → **Replace:** `136.82 min (𝑘 = 2)`

---

### Change 3 · p10 · bottom line — say what each bar proves

This answers Sako's 26 July question directly: *"What is full credential? what is the difference from one PLUM signature verification?"*

**Find:** `The precompile turns a proof that never finished, into a computation that runs in practical time`

**Replace:**
```
The precompile turns a proof that never finished into one that completes in bounded time inside the 24 GB budget

Issue proves two signature verifications. Show proves a fresh pseudonym and the
disclosed attributes, and grows with the number of credentials shown (k).
```

---

### Change 4 · p11 · one name for one quantity

p3 says "total committed area". Make the Evidence column agree.

**Find:** `committed area unmeasurable` → **Replace:** `total committed area unmeasurable`
**Find:** `10.33 × less committed area` → **Replace:** `10.33 × less total committed area`

---

### Change 5 · p12 · add the footnote under the table

Without this, 706 sitting next to 252 invites "why is showing 2.8× issuing?" — and the answer is in your own thesis footnote.

**Add below the table, small type:**
```
BDEC.ShowCre wrapper includes a one-time 2.96 h core-shape pass.
Each wrapped run peaks near 15 GiB, inside the 24 GB budget.
```

---

### Change 6 · p12 · bullet 3 — assumption vs conjecture

**Find:** `Positive security results rest on five open assumptions, plus those inherited from the components`
**Replace:** `Positive security results rest on five open assumptions and one extractor conjecture, plus those inherited from the components`

---

### Change 7 · p13 · RQ2 — "estimated" is wrong, and the wrapper is missing

**Find the whole RQ2 bullet and replace with:**
```
RQ2. PLUM verification completes in 14.24 min. The full credential also runs:
issuance measured at 68.96 min, show at 103.34 min (k=1) and 136.82 min (k=2),
on a 24 GB laptop at 80-bit security. With the zero-knowledge wrapper, all three
complete as well. 128-bit is expected to exceed memory
```

---

### Change 8 · p13 · RQ3 — the wrapper runs; say so

Right now RQ3 reports a limitation and omits that you built and measured the thing.

**Find the whole RQ3 bullet and replace with:**
```
RQ3. On SP1, no proof is both zero-knowledge and post-quantum. The wrapper runs
and fits the budget — the limitation is its pairing, not the zkVM. A static
circuit achieves both in 22 min
```

---

## Part 2 — The script

**Total ≈1,150 words ≈ 8:15 at a calm pace.** Every slide is ≤45 s. Two run over 40: p2 at 45 s, because it now carries PLUM's definition, and p12 at 50 s, because it is the payload. Both are paid for by p4, p9 and p14, which are short.

**Rules:** only "precompile" (never chip, shortcut, accelerator). Only "total committed area". Nothing spoken that is not on the slide.

---

### p1 · Title — 15 s

Good morning. I'm Takumi Otsuka, from Sako Laboratory. This thesis asks one question: when is it worth adding a precompile to a zero-knowledge virtual machine — and what does that decision cost in security?

### p2 · Background — 45 s

An issuer signs a set of attributes. The holder later discloses only part of it, with a zero-knowledge proof that a valid signature covers the whole credential. These last decades, so they need three properties: unforgeable; anonymous — the verifier learns the fact, not the holder; and quantum-safe. BDEC, by other researchers, achieves all three using the Loquat signature. This thesis substitutes PLUM, Loquat's successor, which computes over a 199-bit prime — that number matters shortly. A fourth requirement is practical rather than one of those three: what must be proved keeps changing, and with a fixed circuit every change regenerates the constraint system and must be re-audited.

> *Two clauses here are load-bearing. "This thesis substitutes PLUM… over a 199-bit prime" is the only place PLUM gets defined, and "that number matters shortly" pays for p6 in three words. "A fourth requirement, practical rather than one of those three" closes the seam every reader has fallen into — three properties named, a fourth argued, two concluded.*

### p3 · zkVMs — 42 s

That is why I reach for a zero-knowledge virtual machine. The program is an input, so a change is an edit, not a rebuild and re-audit. To be precise: I measured the static recompile at three tenths of a second. So this is not a speed advantage — it is a re-audit footprint, zero on the zkVM side against at least one per change on the static side. The prover records the run as tables and commits to them; those committed cells are the total committed area. Cycle count is the first estimate. Total committed area is what my criterion prices.

> *Say the 0.3 seconds yourself. Your thesis reports this as a falsified prediction; volunteering it reads as rigour, and it removes the only place a thesis-reading juror can catch you.*

### p4 · Precompile — 28 s

A precompile is a sub-circuit the zkVM recognises as one instruction and proves natively, instead of emulating it step by step. On the left, the emulated version fills many rows of the CPU table. On the right those rows are gone, and one precompile table of fixed size replaces them. Each square is one trace cell. The question is whether that trade is worth taking.

### p5 · Research Goal & Questions — 33 s

My goal: decide, before building, what it costs to prove a post-quantum anonymous credential inside a zkVM on consumer hardware — and measure what that costs in security. Three questions follow. When is a precompile worth building? Can the zkVM verify a post-quantum signature in practical time on consumer hardware? And does the proof it emits stay both post-quantum and zero-knowledge? The first is answered by a rule; the second and third by measurement.

### p6 · The Field-Mismatch Tax — 39 s

I hit a wall immediately. One PLUM signature verification ran over five hours and never finished. The cause is the field mismatch I just mentioned: PLUM computes on 199-bit numbers, and SP1 computes natively on 31-bit numbers. So each number splits into seven pieces, and one multiplication becomes forty-nine partial products — that is this grid. In execute mode a multiply costs nineteen cycles at one piece, and three thousand one hundred twenty-one at seven: a 164-times penalty, measured. That establishes the mismatch is large. What it costs to prove is the next slide.

### p7 · The Cost Criterion — 41 s

When should a precompile be built? Build one only when it removes more proving work than it adds, with work measured in total committed area. Test A is against the program's own emulation: area removed per call, times calls per proof, must exceed the fixed table added. Test B is against a precompile that already exists — the new one is worth building only if total area is lower. Two things are declared first: n, the calls per proof, and the baseline. Then the rule is deterministic. It does not price engineering effort, or the assumptions each precompile adds.

> *That last sentence costs three seconds and buys a lot. Naming the boundary of your own claim is what Sako rewards most.*

### p8 · Precompile Construction — 39 s

I built three precompiles over PLUM's numbers, and they land on three outcomes. The Griffin hash matters most — about ninety-one percent of the verification work — and it is the only one on the end-to-end measurements. The field-multiplication precompile works and proves correctly, but I keep it off the measured path, because SP1 already ships a multiplier for this arithmetic. Third is the power-residue check at PLUM's core, the modular exponentiation the verifier recomputes against the public key. I measured that one alone; it gives the cleanest test of the rule.

### p9 · Machine Specifications — 12 s

Everything that follows was measured on this machine: a fourteen-inch MacBook Pro, M5 Pro, twenty-four gigabytes of memory. That is the consumer-hardware bound in my research question.

### p10 · Feasibility Recovered — 42 s

Every figure here is PLUM at eighty-bit security — the largest level that completes inside twenty-four gigabytes, not a deployment level. Without the precompile, the run was stopped at five hours. With Griffin, a proof finished for the first time in this study: fourteen point two four minutes, mean of five runs. Both halves of the credential also run. Issue proves two signature verifications, sixty-nine minutes. Show proves a fresh pseudonym plus the disclosed attributes — one-oh-three and one-thirty-seven minutes — growing with credentials shown. By practical, I mean it completes in bounded time inside the budget, against a baseline that never finished.

> *Define "practical" yourself. Your RQ2 uses the word and nothing else in the deck says what it means — leave it open and you answer it defensively while the clock runs.*

### p11 · Did the Cost Criterion Work? — 42 s

Did the rule hold? Three measured calls. Griffin against its own emulation: build — and a proof that never finished became fourteen minutes. The evidence there is guest cycles, because the emulated baseline never completed, so its area was unmeasurable. Griffin against a software SHA-3 control at matched security: the rule predicted a disadvantage, and it came in larger by five point six times ten to the seventh cells. The power-residue check: build — priced before I built it, and it came in at ten point three three times less area. The rule is falsifiable, and it did not fail.

### p12 · The Dual Obstruction — 50 s

Feasibility is not what blocks security. This is every proof mode I ran. The top row is the base receipt — quantum-safe, fourteen minutes, but it does not hide the holder's data. The three below add the zero-knowledge wrapper: forty-seven minutes, two hundred fifty-two, seven hundred six. All complete on this laptop, near fifteen gigabytes inside twenty-four. So the wrapper runs. But it is pairing-based, and a quantum computer breaks pairings — so on SP1, every proof gives one guarantee, never both. That this is the wrapper's limit and not the zkVM's, I can show rather than assert: the bottom row is a static circuit giving both, in twenty-two minutes. And I prove a sharper limit — for these showings, everlasting anonymity is unreachable in the standard model.

> *Slow down on "So the wrapper runs" and on "I prove". Those are the two sentences the whole talk is built toward, and no earlier version of this deck contained either.*

### p13 · Conclusion — 41 s

Can a holder do this today? Not yet — for one specific reason. First contribution: a cost criterion that decides before building whether a precompile is worth it, confirmed in advance on the power-residue precompile, eleven point three seven against one hundred seventeen point four six million cells. On the second question, verification and both halves of the credential complete at eighty-bit security inside twenty-four gigabytes, wrapper included. On the third, no proof SP1 produces is both — and the reason is the wrapper's primitive, not any resource limit. Second contribution: the first empirical characterisation of post-quantum credential relations inside a zkVM on consumer hardware.

### p14 · Future Works — 24 s

Four directions. The most informative next measurement is running PLUM on both substrates at matched security, which needs a 199-bit static harness. Then a post-quantum-sound wrapper in place of the pairing-based one. Then re-specifying PLUM over a standard hash and re-deriving its security. And closing the open assumptions and the multi-shard conjecture.

Thank you.

---

## Rehearsal notes

**Time it out loud, twice** — once tonight, once in the morning. Silent reading runs ~20% fast and will lie to you.

**If you are running long,** cut p10's two sentences from "Issue proves" to "growing with credentials shown" down to "Both halves of the credential also run — sixty-nine minutes to issue, one-oh-three and one-thirty-seven to show." Buys 15 seconds; the detail moves to Q&A. **Do not cut p12.**

**Five sentences to say verbatim, not improvise:**
1. p2 — "This thesis substitutes PLUM, Loquat's successor, which computes over a 199-bit prime"
2. p2 — "a fourth requirement, practical rather than one of those three"
3. p3 — the three tenths of a second
4. p10 — "By practical, I mean…"
5. p11 — why row 1's evidence is cycles

Each pre-empts a question that costs more to answer live than to state once.

**Backup slides you may need:** Griffin vs SHA-3 (p23), Multiply (p24), Power-Residue three measures (p25). Know their page numbers cold — jumping confidently to a backup is worth more than any answer you improvise.
