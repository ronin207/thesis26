# Final defence script — d8, spoken register

Takumi Otsuka · 5124FG15 · 29 July 2026, 10:00, first presenter

No dashes, no colons, no semicolons. Short declarative sentences, the way people actually speak. Nothing spoken that is not on the slide. **Total about 1,130 words, roughly 8:10.**

---

## Three slide edits still to make

**1 · p12, footnote under the table**
```
BDEC.ShowCre wrapper includes a one-time 2.96 h core-shape pass.
Each wrapped run peaks near 15 GiB, inside the 24 GB budget.
```

**2 · p14, bullet 1.** "Hash-based proof" appears nowhere else in the deck. Her comment was "what is hash-based proof? Never explained."
**Find** `Add zero-knowledge to SP1's hash-based proof`
**Replace** `Add zero-knowledge to SP1's own receipt, which is built from hashing alone`

**3 · p14, bullet 4.** A conjecture is not an assumption, and she flagged "multi-shard proofs" as unclear.
**Find** `the soundness arguments for the custom precompiles and multi-shard proof composition`
**Replace** `the soundness arguments for the precompiles, and the conjecture behind how the shard proofs compose`

---

## The script

### p1 · Title · 15 s

Good morning. I'm Takumi Otsuka from Sako Laboratory. This thesis asks one question. When is it worth adding a precompile to a zero-knowledge virtual machine, and what does that decision cost in security?

### p2 · Background · 43 s

This is an anonymous credential. An issuer signs a set of attributes. The holder later discloses only part of that set, with a zero-knowledge proof that a valid signature covers the whole thing. These credentials last decades, so they need three properties. They must be unforgeable. They must be anonymous, so the verifier learns the fact and not the holder. And they must be quantum-safe. BDEC is a protocol by other researchers that achieves all three, using the Loquat signature. This thesis substitutes PLUM, which is Loquat's successor and computes over a 199-bit prime. That number matters shortly. There is a fourth requirement as well, and it is practical rather than one of those three. What the holder must prove keeps changing. With a fixed circuit, every change regenerates the constraint system and it has to be re-audited.

### p3 · zkVMs · 40 s

That is why I use a zero-knowledge virtual machine. The program is an input, so a change is an edit and not a rebuild. I want to be precise about that cost. I measured the static recompile at three tenths of a second, so this is not a speed advantage. It is a re-audit footprint. Zero on the zkVM side, and at least one per change on the static side. The prover records the run as tables and commits to them, and those committed cells are the total committed area. Cycle count is a first estimate. Total committed area is what my criterion prices.

### p4 · Precompile · 30 s

A precompile is a sub-circuit the zkVM recognises as one instruction and proves natively, instead of emulating it step by step. On the left, the emulated version fills many rows of the CPU table. On the right those rows are gone, and one precompile table of fixed size replaces them. Each square is one trace cell. The question is whether that trade is worth taking.

### p5 · Research Goal and Questions · 36 s

My goal is to decide, before building, what it costs to prove a post-quantum anonymous credential inside a zkVM on consumer hardware, and to measure what that costs in security. Three questions follow, in this order. When is a precompile worth building? That one has to come first, because until it is answered nothing finishes at all. Then, can the zkVM verify PLUM in practical time on consumer hardware? And finally, does the proof it emits stay both post-quantum and zero-knowledge?

### p6 · The Field-Mismatch Tax · 40 s

I hit a wall immediately. One PLUM signature verification ran over five hours and never finished. The cause is the field mismatch I mentioned. PLUM computes on 199-bit numbers, and SP1 computes natively on 31-bit numbers. So each number splits into seven pieces, and one multiplication becomes forty-nine partial products. That is the grid on this slide. In execute mode a multiply costs nineteen cycles at one piece and three thousand one hundred twenty-one at seven, which is a 164-times penalty, measured. That establishes the mismatch is large. What it costs to prove is the next slide.

### p7 · The Cost Criterion · 40 s

So when should I build a precompile? Build one only when it removes more proving work than it adds, and measure work in total committed area. Test A compares against the program's own emulation. The area removed per call, times the number of calls in one proof, must exceed the fixed table the precompile adds. Test B compares against a precompile that already exists for the same operation. There the new one is worth building only if total area comes out lower. Two things get declared before either test runs. The number of calls per proof, and the baseline. After that the rule is deterministic.

### p8 · Precompile Construction · 40 s

I built three precompiles over PLUM's 199-bit field, and they land on three different outcomes. The Griffin hash matters most, at about ninety-one percent of the verification work, and it is the only one included in the end-to-end runs. I also built the field-multiplication precompile and verified that it proves correctly, but I left it out of every measured run, because SP1 already ships a multiplier for this arithmetic. The third is the power-residue check at PLUM's core, which is the modular exponentiation the verifier recomputes against the public key. I measured that one on its own.

### p9 · Machine Specifications · 11 s

Everything that follows was measured on this machine. A MacBook Pro, M5 Pro, twenty-four gigabytes. That is the consumer-hardware bound in my research question.

### p10 · Feasibility Recovered · 40 s

Every figure here is PLUM at eighty-bit security. That is the largest level that completes inside twenty-four gigabytes, and it is not a deployment level. Without the precompile, the run was stopped at five hours. With the Griffin precompile, a proof finished for the first time in this study, in fourteen point two four minutes, the mean of five runs. Both halves of the credential also run. Issue proves two signature verifications, at sixty-nine minutes. Show proves a fresh pseudonym and the disclosed attributes, at one-oh-three and one-thirty-seven minutes, and it grows with the number of credentials shown. By practical, I mean it completes in bounded time inside the budget.

### p11 · Did the Cost Criterion Work? · 40 s

Did the rule hold? Three measured calls. The rule is decided in cells, and the minutes in the last column are what followed. Griffin against its own emulation. The rule said build, and a proof that never finished became fourteen minutes. The evidence there is cycles, because the emulated baseline never completed, so its area could not be measured. Griffin against a software SHA-3 control at matched security. The rule predicted a disadvantage, and it came in larger by five point six times ten to the seventh cells. The power-residue check. The rule said build, and I priced it before building it. It came in at ten point three three times less area.

### p12 · The Dual Obstruction · 41 s

Feasibility is not what blocks security. This table is every proof mode I ran. The first row is SP1's default receipt. It is quantum-safe and takes fourteen minutes, but it does not hide the holder's data. The three rows below add the zero-knowledge wrapper, at forty-seven, two hundred fifty-two, and seven hundred six minutes. All of them complete inside twenty-four gigabytes. So the wrapper runs. But it is pairing-based, and a quantum computer breaks pairings. On SP1, every proof gives one guarantee and never both. I can show that this is the wrapper's limit and not the zkVM's. The bottom row is a static circuit giving both, in twenty-two minutes.

### p13 · Conclusion · 41 s

So can a holder do this today? Not yet, and for one specific reason. My first contribution is a cost criterion that decides, before building, whether a precompile is worth it. It was confirmed in advance on the power-residue precompile. On the second question, verification and both halves of the credential complete at eighty-bit security inside twenty-four gigabytes, wrapper included. On the third, no proof SP1 produces is both, and the reason is the wrapper's pairing rather than any resource limit. For these showings I also prove that everlasting anonymity is unreachable in the standard model. My second contribution is the first empirical characterisation of post-quantum credential relations inside a zkVM on consumer hardware.

### p14 · Future Works · 33 s

Four directions. The most informative next measurement is running PLUM on both substrates at matched security, which needs a 199-bit static harness. Then a post-quantum-sound wrapper in place of the pairing-based one. Third, the SHA-3 arm is only a control today. PLUM's security analysis covers its own algebraic hash, so making SHA-3 a real alternative means re-specifying the scheme and re-deriving the bounds. And last, closing the open assumptions, and the conjecture behind how the shard proofs compose.

Thank you.

---

## How this supports the extended summary

The jury reads both. Four places where the talk and the summary now say the same thing in the same words, so nothing reads as a contradiction.

| Summary section | Slide | Same claim, same wording |
|---|---|---|
| §2 The Field-Mismatch Tax | p6 | 199-bit against 31-bit, seven pieces, one multiply becomes forty-nine |
| §3 The Precompile Suite | p7, p8 | Three precompiles, the criterion decided on committed area |
| §4 Evaluation | p10, p11 | 14.24 min, 68.96, 103.34, 136.82, and 10.33 times less area |
| §5 Discussion | p12 | Dual obstruction, defined the same way in both. Receipt does not hide the data, wrapper is not post-quantum |

The one place the talk goes beyond the summary is the Aurora row on p12, giving zero-knowledge and post-quantum together at twenty-two minutes. That is Cell 4 in your summary's Table 1, so it is not new to them, but the talk uses it for something the summary does not. It is the evidence that the obstruction belongs to the wrapper and not to zkVMs.

---

## Rehearsal

Time it out loud twice. Silent reading runs about twenty percent fast.

If you run long, cut p10 from "Issue proves" to "credentials shown" and say instead, "Both halves also run, at sixty-nine minutes to issue and one-oh-three and one-thirty-seven to show." That buys fifteen seconds. Never cut p12.

Six sentences to say as written.

1. p2, "This thesis substitutes PLUM, which is Loquat's successor and computes over a 199-bit prime"
2. p2, "There is a fourth requirement as well, and it is practical rather than one of those three"
3. p3, three tenths of a second
4. p10, "By practical, I mean it completes in bounded time inside the budget"
5. p11, "The rule is decided in cells, and the minutes in the last column are what followed"
6. p12, "So the wrapper runs"

Backup pages in order. Griffin against SHA-3, Multiply, Power-Residue detail, then Loquat, PLUM, BDEC. Know the page numbers cold. Jumping straight to a backup beats any answer you improvise.
