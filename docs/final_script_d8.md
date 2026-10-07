# Final defence script — d8, 14 slides

Takumi Otsuka · 5124FG15 · 29 July 2026, 10:00, first presenter

Written by taking the draft-1 script Sako annotated line by line and closing every comment against the d8 slides. **Total ≈1,110 words ≈ 8:00.** Twelve slides are ≤40 s; p12 and p13 land at 41–42 s.

---

## Three slide edits left

**1 · p12 — add the footnote under the table.** Without it, 706 next to 252 invites "why is showing 2.8× issuing?"
```
BDEC.ShowCre wrapper includes a one-time 2.96 h core-shape pass.
Each wrapped run peaks near 15 GiB, inside the 24 GB budget.
```

**2 · p14, bullet 1 — "SP1's hash-based proof" is never defined anywhere in the deck.** Her comment: *"what is hash-based proof? Never explained."*
**Find:** `Add zero-knowledge to SP1's hash-based proof`
**Replace:** `Add zero-knowledge to SP1's own receipt, which is built from hashing alone`

**3 · p14, bullet 4 — a conjecture is not an assumption**, and "multi-shard proof composition" was flagged as unclear.
**Find:** `the soundness arguments for the custom precompiles and multi-shard proof composition`
**Replace:** `the soundness arguments for the precompiles, and the conjecture behind how the shard proofs compose`

---

## Her comments, and where each one dies

| Sako, 26 July | Closed |
|---|---|
| "Showing is Takumi's action, verifying is the verifier's" | p2 script — the holder discloses; the proof covers the signature. Never conflated |
| "'construction' unclear — call it a protocol / other researchers" | p2 slide + script: "a protocol by other researchers" |
| "Say the lifetime point on page 2, and give a slide why zkVM helps" | p2 bullet 3; p3 answers why |
| "You need not say you used SP1 on this slide" | SP1 first appears on p3 |
| "shortcuts / precompiles / accelerator — same thing?" | Only "precompile", every slide and every sentence |
| "Revisit the very first sentence of your presentation" | p1 rewritten — no "shortcut" |
| "'before building' — building what? who builds?" | p7 script: "before I build one" |
| "Explain how it works before the research question" | p4 now precedes p5 |
| "Why are questions in this order?" | p5 script states the order's logic |
| "BDEC, Loquat, PLUM mentioned without writing on the slide" | All three on p2, with citations |
| "You never wrote what PLUM is" | p2: signature scheme, Loquat's successor, 199-bit prime |
| "Script says size-mismatch, slide says field mismatch" | "Field mismatch" everywhere |
| "You never said PLUM is xx and SP1 is xx" | p6 slide and script: 199-bit vs 31-bit |
| "19 cycles is in the transcript, not the slides" | Now on p6; safe to say |
| "'committed area' is in the script, not the slide" | "Total committed area", p3 / p7 / p11 |
| "How do you measure proving work? When does it add?" | p7 Tests A and B, spoken |
| "You are 'building a hardware' — misleading" | The word never appears |
| "What is PLUM's numbers? What are 'cases'?" | p8 script: "PLUM's 199-bit field", "three outcomes" |
| "'keep it off the measured path' — what did you do?" | p8 script says exactly what was and wasn't run |
| "What is number check? Never explained" | "Power-residue check", defined on p8 |
| "'with Griffin' should mean the precompile for Griffin" | Always "the Griffin precompile" |
| "What is full credential? Difference from one verification?" | p10 bullets + script |
| "Why some in min and others in cells?" | p11 script says which quantity decides and which reports |
| "What does ℓ=1 mean?" | p6: one piece vs seven |
| "win/lose" | Advantage/disadvantage throughout |
| "Finding 3 — were there 1 and 2?" | Gone |
| "What is base proof / privacy wrap?" | "SP1's default receipt" and "zero-knowledge wrapper", both on p12 |
| "RQ2: is this the zero-knowledge version?" | p12 separates base from wrapped; p13 says so |
| "Do we really need to re-derive security?" | p14 script gives the reason |
| "'custom chips' and 'multi-shard proofs' unclear" | Edit 3 above |
| "Terms not consistent or defined carefully" | One name per concept, defined at first use |

---

## The script

### p1 · Title — 15 s

Good morning. I'm Takumi Otsuka, from Sako Laboratory. This thesis asks one question: when is it worth adding a precompile to a zero-knowledge virtual machine — and what does that decision cost in security?

### p2 · Background — 39 s

An issuer signs a set of attributes. The holder later discloses only part of that set, together with a zero-knowledge proof that a valid signature covers the whole credential. These last decades, so they need three properties: unforgeable; anonymous — the verifier learns the fact, not the holder; and quantum-safe. BDEC, a protocol by other researchers, achieves all three, using the Loquat signature. This thesis substitutes PLUM, Loquat's successor, which computes over a 199-bit prime — that number matters shortly. A fourth requirement is practical, not one of those three: what must be proved keeps changing, and with a fixed circuit every change regenerates the constraint system and must be re-audited.

### p3 · zkVMs — 38 s

That is why I use a zero-knowledge virtual machine. The program is an input, so a change is an edit, not a rebuild and re-audit. To be precise about that: I measured the static recompile at three tenths of a second, so this is not a speed advantage — it is a re-audit footprint, zero on the zkVM side against at least one per change on the static side. The prover records the run as tables and commits to them; those committed cells are the total committed area. Cycle count is the first estimate. Total committed area is what my criterion prices.

### p4 · Precompile — 30 s

A precompile is a sub-circuit the zkVM recognises as one instruction and proves natively, instead of emulating it step by step. On the left, the emulated version fills many rows of the CPU table. On the right those rows are gone, and one precompile table of fixed size replaces them. Each square is one trace cell. The question is whether that trade is worth taking.

### p5 · Research Goal & Questions — 36 s

My goal is to decide, before building, what it costs to prove a post-quantum anonymous credential inside a zkVM on consumer hardware — and to measure what that costs in security. Three questions follow, in that order. When is a precompile worth building? That has to come first, because until it is answered nothing finishes. Then: can the zkVM verify PLUM in practical time on consumer hardware? And finally, does the proof it emits stay both post-quantum and zero-knowledge?

### p6 · The Field-Mismatch Tax — 39 s

I hit a wall immediately. One PLUM signature verification ran over five hours and never finished. The cause is the field mismatch I mentioned: PLUM computes on 199-bit numbers, and SP1 computes natively on 31-bit numbers. So each number splits into seven pieces, and one multiplication becomes forty-nine partial products — that is this grid. In execute mode a multiply costs nineteen cycles at one piece and three thousand one hundred twenty-one at seven: a 164-times penalty, measured. That establishes the mismatch is large. What it costs to prove is the next slide.

### p7 · The Cost Criterion — 39 s

So when should I build a precompile? Build one only when it removes more proving work than it adds, with work measured in total committed area. Test A is against the program's own emulation: area removed per call, times calls per proof, must exceed the fixed table the precompile adds. Test B is against a precompile that already exists for the same operation — the new one is worth building only if total area is lower. Two things are declared before either test: n, the calls per proof, and the baseline. Then the rule is deterministic.

### p8 · Precompile Construction — 39 s

I built three precompiles over PLUM's 199-bit field, and they land on three outcomes. The Griffin hash matters most — about ninety-one percent of the verification work — and it is the only one included in the end-to-end runs. The field-multiplication precompile I built and verified proves correctly, but I did not include it in any measured run, because SP1 already ships a multiplier for this arithmetic. Third is the power-residue check at PLUM's core, the modular exponentiation the verifier recomputes against the public key. I measured that one alone.

### p9 · Machine Specifications — 11 s

Everything that follows was measured on this machine: a MacBook Pro, M5 Pro, twenty-four gigabytes. That is the consumer-hardware bound in my research question.

### p10 · Feasibility Recovered — 39 s

Every figure here is PLUM at eighty-bit security — the largest level that completes inside twenty-four gigabytes, and not a deployment level. Without the precompile, the run was stopped at five hours. With the Griffin precompile, a proof finished for the first time in this study: fourteen point two four minutes, mean of five runs. Both halves of the credential also run. Issue proves two signature verifications, sixty-nine minutes. Show proves a fresh pseudonym and the disclosed attributes, at one-oh-three and one-thirty-seven minutes, growing with the number of credentials shown. By practical, I mean it completes in bounded time inside the budget.

### p11 · Did the Cost Criterion Work? — 40 s

Did the rule hold? Three measured calls. The rule is decided in cells; the minutes in the last column are what followed. Griffin against its own emulation: build — and a proof that never finished became fourteen minutes. The evidence there is cycles, because the emulated baseline never completed, so its area could not be measured. Griffin against a software SHA-3 control at matched security: the rule predicted a disadvantage, and it came in larger by five point six times ten to the seventh cells. The power-residue check: build — priced before I built it, then ten point three three times less area.

### p12 · The Dual Obstruction — 41 s

Feasibility is not what blocks security. This is every proof mode I ran. The first row is SP1's default receipt: quantum-safe, fourteen minutes, but it does not hide the holder's data. The three below add the zero-knowledge wrapper — forty-seven, two hundred fifty-two, and seven hundred six minutes — all completing inside twenty-four gigabytes. So the wrapper runs. But it is pairing-based, and quantum computers break pairings: on SP1, every proof gives one guarantee, never both. That this is the wrapper's limit and not the zkVM's, I can show — the bottom row is a static circuit giving both, in twenty-two minutes.

### p13 · Conclusion — 42 s

Can a holder do this today? Not yet — for one specific reason. First contribution: a cost criterion that decides, before building, whether a precompile is worth it, confirmed in advance on the power-residue precompile. Second question: verification and both halves of the credential complete at eighty-bit security inside twenty-four gigabytes, wrapper included. Third: no proof SP1 produces is both — and the reason is the wrapper's pairing, not any resource limit. For these showings I also prove everlasting anonymity is unreachable in the standard model. Second contribution: the first empirical characterisation of post-quantum credential relations inside a zkVM on consumer hardware.

### p14 · Future Works — 32 s

Four directions. The most informative next measurement is running PLUM on both substrates at matched security, which needs a 199-bit static harness. Then a post-quantum-sound wrapper in place of the pairing-based one. Third, the SHA-3 arm is only a control today: PLUM's security analysis covers its own algebraic hash, so making SHA-3 a real alternative means re-specifying the scheme and re-deriving the bounds. And closing the open assumptions, and the conjecture behind how the shard proofs compose.

Thank you.

---

## Rehearsal

Time it out loud twice — tonight and in the morning. Silent reading runs ~20% fast.

**Running long?** Cut p10 from "Issue proves" to "credentials shown" down to *"Both halves also run — sixty-nine minutes to issue, one-oh-three and one-thirty-seven to show."* Buys 15 s. **Never cut p12.**

**Six sentences to say verbatim:**
1. p2 — "This thesis substitutes PLUM, Loquat's successor, which computes over a 199-bit prime"
2. p2 — "A fourth requirement is practical, not one of those three"
3. p3 — three tenths of a second
4. p10 — "By practical, I mean…"
5. p11 — "The rule is decided in cells; the minutes are what followed"
6. p12 — "So the wrapper runs"

**Backup pages:** Griffin vs SHA-3, Multiply, Power-Residue detail, then Loquat / PLUM / BDEC. Know the numbers cold — jumping straight to a backup beats any improvised answer.
