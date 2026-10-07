# Final patch — d8, after Codex and Wu

Only what two or more independent readers flagged, plus the four factual corrections. About twenty minutes of work. Nothing here is a restructure.

---

## Five slide edits

**1 · p11, Verdict cell.** A result cannot be confirmed before it exists.
`Confirmed before building` → **`Predicted before building, confirmed by measurement`**

**2 · p12, Aurora row.** It is Loquat over a different field on a different substrate. Your summary calls it a rough cross-scheme reference. The slide currently reads as a like-for-like race.
`Loquat.Verify + Zero-knowledge` → **`Loquat.Verify + Zero-knowledge (cross-scheme reference)`**

**3 · p12, bullet 1.** Your thesis says SP1 does not *establish* that it hides the data. The slide asserts something stronger.
`does not hide the holder's data` → **`gives no zero-knowledge guarantee, and can leak witness data in this workload`**

**4 · p9.** Your thesis says the SP1 prover is CPU-bound. Listing a GPU invites "why is it there?"
Delete `20-Core GPU`, or write `18-Core CPU (the prover is CPU-bound)`

**5 · p8.** Wu could not tell which part is yours. The precompile mechanism is SP1's. The three precompiles are yours.
Add above the diagram: **`Three precompiles built for this thesis, over PLUM's 199-bit field`**

**6 · p7.** The slide shows the arithmetic but not the inputs, which is why Codex read the criterion as tautological. "Build when savings exceed cost" is obvious. "Here are the three numbers you can know before building anything" is not. No new figure. One line of small type under Test A and Test B, using symbols already on the slide.

> Every input is known before building. A_emulated is measurable today, A_precompile comes from the table's design, and n is declared.

This puts the answer to the room's most dangerous question on the slide, instead of relying on you remembering to say it.

---

## The one sentence, said twice

At p5 after the research questions, and again at p13 as the opening line. It subordinates the three results into one causal chain instead of a list.

> The criterion tells you which precompile to build. Building it makes post-quantum credential proving feasible on a laptop. But the wrapper that makes the proof anonymous is pairing-based, so no SP1 proof is both anonymous and quantum-safe.

---

## Script patches

### p6 — why 164 exceeds 49

**Add after** "a 164-times penalty, measured."

> The forty-nine is only the product count. The rest is reduction, carries, and the bignum library's own overhead.

Without this, anyone who multiplies seven by seven asks where the other factor came from.

### p7 — the answer to "is this predictive or post-hoc?"

**Replace** "After that the rule is deterministic." **with**

> Every input is known before implementation. The emulated cost is already measurable, the table dimensions come from the design, and the call count is declared. So the decision is made on the specification, before anything is built.

This is the most dangerous question in the room and this sentence disarms it.

### p11 — fix the narrative order

**Replace** "Did the rule hold? Three measured calls." **with**

> The rule was written before any of these were built, so this slide is the test of it. Three measured calls.

Wu's point exactly. p10 already showed the precompile working, so p11 reads as justifying a decision you had already made. One clause fixes the direction of time.

**Also, introduce SHA-3 the first time you say it.**
`Griffin against a software SHA-3 control at matched security` →

> Griffin against a plain software SHA-3, which is a standard hash SP1 already supports, at matched security

### p12 — qualify Aurora out loud

**Replace** "The bottom row is a static circuit giving both, in twenty-two minutes." **with**

> The bottom row is a static circuit that gives both, in twenty-two minutes. That is a different scheme over a different field, so it is a rough cross-scheme reference and not a like-for-like race. It is enough to show the obstruction belongs to the wrapper and not to zkVMs.

Say the qualification yourself. If a juror says it first, the row looks like a claim you were hoping to slip past.

### p10 and p13 — drop "practical"

p10, **replace** "By practical, I mean it completes in bounded time inside the budget." **with**

> So it is feasible within the 24 GB budget at 80-bit security. That is the claim. Sub-second interactive latency is not.

p13, **replace** "complete at eighty-bit security inside twenty-four gigabytes" **with**

> are feasible within the 24 GB budget at 80-bit security

---

## Three answers to have ready

**"How can the criterion be used before building, if you don't know the precompile's area yet?"**
Because both inputs are available at specification time. The emulated cost is already measurable, since emulation is the status quo. The precompile table's dimensions follow from the AIR design, its width from the state size and round structure and its height from the call count. Neither requires a finished implementation. The power-residue row is the demonstration. I priced it from the design, then built it, and the measurement matched.

**Follow-up: "That is AIR-specific. Does it work on any zkVM?"**
The criterion is not about trace area. It is about pricing whatever the prover actually commits to on that substrate, and requiring that quantity to be readable from a specification rather than a build. On an AIR or Plonkish substrate it is trace cells, rows times columns, and a custom gate is the precompile. On R1CS it is constraint count. On a lookup-centric design it is lookup table size and call count. The unit changes, the inequality does not. What does not travel is the magnitudes, which are pinned to PLUM's 199-bit field, SP1's prover, and this 24 GB machine. My thesis states the scope as any large-field algebraic-hash signature of this form, verified in any small-field zkVM that exposes application-defined precompiles. I validated it on one substrate, so that is a scope claim rather than a demonstrated result.

**"Isn't 'build it when savings exceed cost' tautological?"**
The inequality is trivial. The contribution is which quantity goes into it. Cycles, field-operation columns, and total committed area disagree with each other on the same precompile. Field-operation columns say the power-residue precompile is worse. Cycles say it wins by eighteen times. Only total committed area gives 10.33, and total committed area is what the prover actually commits. Choosing the quantity is the claim, and it is falsifiable.

**"What did you invent, in one sentence?"** — answer without saying Griffin, PLUM, SP1 or Aurora.
A rule for deciding, before you build it, whether a custom circuit will make a zero-knowledge proof cheaper or more expensive. I used it to make a privacy credential provable on a laptop for the first time, and in doing so found that the tool cannot yet make that proof both private and quantum-safe.

---

## Ignore these

**Moving everlasting anonymity to backup.** It is a theorem you proved, and your §8 calls this the sharpest finding of the thesis. Codex was reading the long parenthetical on p12, not the script, where it is already one sentence at p13. Shorten the slide bullet to `everlasting anonymity is unreachable on this route` and keep the spoken line.

**Rebuilding p7's figure.** The figure is fine and nobody across three reviews failed to follow it. Edit 6 adds the missing line without touching the artwork. A new diagram at this hour is risk without payoff.

**Putting "the metrics disagree" on p7.** That fact is the strongest evidence the criterion has content, and appendix p25 already shows all three metrics on one chart. Answer it verbally, using prepared answer 2, and jump to p25. Better there than crowding the definition slide.

**Renaming CreGen and ShowCre.** p10 already carries both the plain word and the formal name.

---

## Then stop

Wu, at 00:24: *"If you can finish presentation within 10 min with this version, it is good enough."* She is right, and she has read more versions of this than anyone.

Make these edits, time it twice out loud, sleep. There is no d9.
