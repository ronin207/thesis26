# Defence Script — d6, 14 slides, ≈9:30

Takumi Otsuka · 5124FG15 · 29 July 2026, 10:00, first presenter

Target 9:30 at a calm pace, leaving 30 s of buffer. Under nerves you will run faster, not slower — if you finish at 8:45 that is fine.

**Rules this script follows, so don't paraphrase away from it:**
- Only "precompile". Never chip, shortcut, or accelerator.
- Only "total trace area". Fix p11's column to match.
- Nothing spoken that isn't on the slide.
- Every number carries measured / stopped / predicted.

---

## Six slide edits before you rehearse

1. **p11** — delete "or if the matched-field operation had shown a large removable cost". That row is no longer in the table.
2. **p12** — 708 → **706 minutes** (matches `tab:proof-mode`).
3. **p12** — footnote: *ShowCre wrapper includes a one-time 2.96 h core-shape pass. Each run peaks near 15 GiB.*
4. **p13** — "estimated at 69 min" → **measured**; and update RQ2/RQ3 to reflect p12 (see the script for the wording).
5. **p3 / p11** — one name for one quantity. Change p11's column header to **total trace area**.
6. **p7** — "is build" → "is built".

---

## The script

### p1 · Title — 15 s

Good morning. I'm Takumi Otsuka from Sako Laboratory. This thesis asks one question: when is it worth adding a precompile to a zero-knowledge virtual machine, and what does that decision cost you in security?

### p2 · Background — 52 s

An anonymous credential works like this. An issuer signs a set of attributes. Later the holder discloses only part of that set — one qualification, say — together with a zero-knowledge proof that a valid signature covers the whole credential. These are meant to last decades, so they need three properties: unforgeable; anonymous, meaning the verifier learns the fact proved and not which holder proved it; and quantum-safe. BDEC, a protocol by other researchers, achieves all three together at the signature layer, instantiated with the Loquat signature.

There is a fourth requirement, and I want to be clear that it is a practical one and not one of those three. What the holder must prove keeps changing over a credential's lifetime — which attributes, the security level, even the signature scheme. With a fixed circuit, every such change regenerates the constraint system, and it has to be re-audited.

> *This paragraph is doing the work that has been missing. Say "a fourth requirement, not one of those three" out loud — it is the seam every reader has fallen into.*

### p3 · zkVMs — 48 s

That is why I reach for a zero-knowledge virtual machine. In a zkVM the program is an input, so a change is an edit rather than a rebuild and a re-audit.

I should be precise about that cost. I measured the static-circuit recompile at about three tenths of a second, so this is not a runtime advantage. It is a re-audit footprint — zero regenerations on the zkVM side against at least one per change on the static side, paid by engineers rather than by the prover.

The prover records the run as tables of field elements and commits to them, and the total number of committed cells is the total trace area. Cycle count is the natural first estimate. Total trace area is what my criterion prices.

> *Saying the 0.3 s yourself converts your weakest slide into a strength. It is one of two predictions your thesis reports as falsified.*

### p4 · Precompile — 35 s

A precompile is a sub-circuit the zkVM recognises as a single instruction and proves natively, instead of emulating the operation step by step. On the left, the emulated version fills many rows of the CPU table. On the right those rows are gone, and one precompile table of fixed size has been added in their place. Each square is one trace cell. So the question is whether that trade is worth taking.

### p5 · Research Goal & Questions — 33 s

My goal is to decide, before building, what it costs to prove a post-quantum anonymous credential inside a zkVM on consumer hardware, and to measure what that costs in security. Three questions follow. When is a precompile worth building? Can the zkVM verify a post-quantum signature in practical time on consumer hardware? And does the proof the zkVM emits stay both post-quantum and zero-knowledge? The first is answered by a rule, the second and third by measurement.

### p6 · The Field-Mismatch Tax — 48 s

I hit a wall immediately. One PLUM verification ran over five hours and never produced a proof. The cause is a field mismatch. PLUM computes on one hundred ninety-nine-bit numbers; SP1 computes natively on thirty-one-bit numbers. So each PLUM number splits into seven pieces, and one multiplication becomes forty-nine partial products — that is the grid on this slide. In execute mode a multiply costs nineteen cycles at one piece and three thousand one hundred twenty-one at seven, a one hundred sixty-four times penalty, measured. That establishes the mismatch is large. What it costs to *prove* is the next slide.

### p7 · The Cost Criterion — 55 s

So when should a precompile be built? Build one only when it removes more proving work than it adds, with work measured in total trace area.

Two tests. Test A is against the program's own emulation: the area removed per call, times the number of calls in one proof, must exceed the area of the fixed table the precompile adds. Test B is against a precompile that already exists for the same operation, where the new one is worth building only if total area comes out lower.

Two things are declared before either test runs — n, the number of calls per proof, and which baseline you compare against. Once those are declared the rule is deterministic. What it does not price is engineering effort, or the soundness assumptions each precompile adds, and that is where a person still has to decide.

> *That last sentence is worth its five seconds. Naming the boundary of your own claim is the single thing Sako rewards most.*

### p8 · Precompile Construction — 43 s

I built three precompiles over PLUM's numbers, and they land on three different outcomes. The Griffin hash matters most — about ninety-one percent of the verification work — and it is the only one on the end-to-end measurements. The field-multiplication precompile works and proves correctly, but I keep it off the measured path, because SP1 already ships a multiplier for this arithmetic. Third is the power-residue check at PLUM's core, the modular exponentiation the verifier recomputes against the public key. I measured that one on its own, and it gives the cleanest test of the rule.

### p9 · Machine Specifications — 12 s

Everything that follows was measured on this machine: a fourteen-inch MacBook Pro, M5 Pro, twenty-four gigabytes. That is the consumer-hardware bound in my research question.

### p10 · Feasibility Recovered — 58 s

Every proof figure here is PLUM at eighty-bit security — the largest level that completes inside twenty-four gigabytes on this machine, and not a deployment security level.

Without the precompile, the run was stopped after five hours having produced nothing. With the Griffin precompile a proof finished for the first time in this study, in fourteen point two four minutes, the mean of five runs.

Both halves of the credential also run. Issuing, measured at sixty-nine minutes, proves two signature verifications. Showing, at one hundred three minutes for one credential and one hundred thirty-seven for two, proves a fresh pseudonym and the disclosed attributes — so it grows with how many credentials are shown.

By practical time I mean it completes inside the memory budget in bounded wall-clock, against a baseline that never finished. Sub-second interactive latency is not what I am claiming.

> *Defining "practical" yourself removes the question. If you leave it undefined, someone asks whether 137 minutes is practical and you answer defensively.*

### p11 · Did the Cost Criterion Work? — 58 s

So did the rule hold? Three measured calls.

Griffin against its own emulation: the rule said build, and it turned a proof that never finished into fourteen minutes. The evidence there is guest cycles, because the emulated baseline never completed, so its total trace area could not be measured.

Griffin against a plain software SHA-3 control at the same security level: the rule said expect a disadvantage, because the precompile's own table still has to be proved — and it came in larger by five point six times ten to the seventh cells.

The power-residue check: the rule said build, and that one was priced *before* I built it, then came in at ten point three three times less area.

And the rule is falsifiable. It would have failed if the power-residue precompile had come in larger on area. It did not.

### p12 · The Dual Obstruction — 70 s

What remains is security — and feasibility is not what blocks it.

This table is every proof mode I ran. The first row is the base receipt: quantum-safe, fourteen minutes, but it does not hide the holder's data. The three rows below are the same workloads with the zero-knowledge wrapper on top — verification at forty-seven minutes, issuance at two hundred fifty-two, showing at seven hundred six. All of them complete on the same laptop, each peaking near fifteen gigabytes inside the twenty-four gigabyte budget. So the wrapper runs.

But it is pairing-based, and a quantum computer breaks pairings. So on SP1, every proof gives one of the two guarantees and never both.

That this is a limitation of the wrapper SP1 ships, rather than of zkVMs, I can show rather than assert — the bottom row is a static circuit producing a proof that is both, in twenty-two minutes.

And there is a sharper limit, which I prove: for the hash-committed showings this construction uses, everlasting anonymity cannot be established in the standard model at all. All the positive results here hold under five open assumptions and one extractor conjecture.

> *Slow down on "the wrapper runs" and on "which I prove". Those are the two sentences that carry the talk.*

### p13 · Conclusion — 45 s

So can a holder do this today? Not yet, and now for one specific reason.

First contribution: a cost criterion that decides, before building, whether a precompile is worth it — confirmed in advance on the power-residue precompile, eleven point three seven against one hundred seventeen point four six million cells.

On the second question, PLUM verification and both halves of the credential complete at eighty-bit security inside twenty-four gigabytes, wrapper included.

On the third, no proof SP1 produces is both post-quantum and zero-knowledge, and the reason is the wrapper's primitive rather than any resource limit.

Second contribution: to my knowledge, the first empirical characterisation of post-quantum credential relations inside a zkVM on consumer hardware.

### p14 · Future Works — 27 s

Four directions. The most informative next measurement is running PLUM on both substrates at matched security, which needs a one hundred ninety-nine-bit static harness. Then a post-quantum-sound wrapper in place of the pairing-based one. Then re-specifying PLUM over a standard hash and re-deriving its security. And closing the open assumptions and the multi-shard conjecture.

Thank you.

---

## Rehearsal notes

**Total ≈ 1,300 words.** At 135 wpm that is 9:38; at 145 wpm, 8:58. Time yourself once out loud before you sleep, and once in the morning. Do not time yourself reading silently — it is always 20% faster than speaking.

**If you are running long at p10,** cut the two sentences beginning "Issuing, measured at sixty-nine minutes" down to "Both halves of the credential also run — issuing at sixty-nine minutes, showing at one hundred three and one hundred thirty-seven." That buys 15 seconds and the detail moves to Q&A.

**If you are running long at p12,** cut nothing. It is the payload.

**Four places you must not improvise:**
- p3, the 0.3 s sentence
- p10, the definition of practical time
- p11, why row 1's evidence is cycles
- p12, "five open assumptions and one extractor conjecture"

Each of these pre-empts a question that costs more to answer live than to state once.
