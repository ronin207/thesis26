# Final consistency audit — p5124fg15.pdf + masterdefence_script

Every number, term and claim traced across 14 slides, the script, the gaiyousho and the thesis. Complete list. Nothing held back.

**Already applied and correct:** Finding 1/2/3 labels · p7 "every input is known before building" · p8 "three precompiles built for this thesis" · p9 CPU-bound note · p11 "Predicted before building, confirmed by measurement" · p12 Aurora "(cross-scheme reference)" · p12 "no zero-knowledge guarantee, and can leak witness data" · p12 "five open assumptions and one extractor conjecture" · p13 "measured at 68.96 min" · p14 "SP1's own receipt" and "the conjecture behind how the shard proofs compose" · script s6 overhead sentence · script s7 predictive-inputs sentence · script s11 prospective framing and SHA-3 introduction · script s12 Aurora qualification.

---

## A · Five that a referee will visibly stumble on

### A1 · p6 — the sentence does not parse

The slide carrying your central problem has a broken sentence. "because since… working… forces" is two conjunctions and a dangling participle.

**Find** `because since PLUM works on 199-bit numbers, and SP1 zkVM working on 31-bit numbers, forces PLUM signature to split into seven pieces, so one multiply becomes 49`

**Replace** `PLUM works on 199-bit numbers and SP1 works natively on 31-bit numbers, so each PLUM number splits into seven pieces and one multiply becomes 49`

*Why it matters:* this is the slide a least-informed referee has to understand or the rest is lost. Your script already says it correctly. Only the slide is wrong.

### A2 · p13 — "within practical time" contradicts your script and your thesis

Script s10 says "feasible within the 24 GB budget at 80-bit security. That is the claim." Slide p13 still says "completed within practical time."

**Find** `PLUM verification was completed within practical time, 14.24 min`
**Replace** `PLUM verification completes in 14.24 min`

And **find** `24 GB laptop at 80-bit security` → **replace** `feasible within the 24 GB budget at 80-bit security`

*Why:* your thesis §8 states the bar as "completion within the target machine's 24 GB envelope in bounded wall-clock" and explicitly says sub-second interactive latency "stays out of reach." A 136-minute showing is not practical by any ordinary meaning, and a referee who reads p12's 706-minute row will notice. Claiming feasibility is defensible; claiming practicality is not.

### A3 · p11 — row 1's Evidence cell has no number

Rows 2 and 3 give a quantity. Row 1 names a metric and gives nothing. A referee reads the column left to right and hits a blank.

**Find** `Guest cycles, total committed area unmeasurable`
**Replace** `58.5 × fewer cycles (execute mode); total committed area unmeasurable`

*Why:* the 58.5× figure was in every deck up to d5 and dropped out. Your thesis §8 Limitations names it explicitly as an execute-mode figure at λ=80, so stating the mode keeps it honest. Without a number the row reads as though you had no evidence for the call you made.

### A4 · p12 vs p13 — the everlasting-anonymity claim is on one slide and spoken on the other

The bullet is on **p12**. The script says it in **s13**. You would be showing the conclusion slide while reading a bullet from the previous one. Sako's most reliable check is exactly this diff.

The wordings also differ. Slide says "unreachable **on this route**." Script says "unreachable **in the standard model**." Your thesis Theorem `thm:no-everlasting` says the standard model. "On this route" is a weaker and vaguer claim than the one you proved.

**Fix, slide p12 bullet 4:** `For BDEC on PLUM, everlasting anonymity is unreachable in the standard model`

**Fix, script:** move the sentence from s13 to the end of s12, worded to match:
> And for these showings I prove a sharper limit. Everlasting anonymity is unreachable in the standard model.

**Delete from s13:** `For these showings I also prove everlasting anonymity is unreachable in the standard model.`

Net time change is zero. s12 gains about eight seconds, s13 loses the same.

### A5 · p12 — the lead line is contradicted by the last row of its own table

The line says "each proof gives one of the two guarantees, never both." Directly beneath it, the Aurora row shows ✓ and ✓. The Substrate column does distinguish them, but a referee reads the sentence, then the table, and sees a counterexample.

**Find** `On SP1, each proof gives one of the two guarantees, never both:`
**Replace** `On SP1, each proof gives one of the two guarantees, never both. The static circuit below shows this is a limit of the wrapper, not of zkVMs:`

*Why:* that row is the strongest thing on the slide. Right now it looks like an inconsistency instead of the evidence for bullet 2.

---

## B · Four terminology splits

Sako's closing line on 26 July was that terms are "not consistent or defined carefully." These are the four that survive. Each is one word.

### B1 · wrap vs wrapper

Table column says **Wrapper**. Bullets 1 and 2 say **wrap**. p13 RQ3 says **wrap**. Script says **wrapper** throughout.

- p12 bullet 1: `The wrap hides it` → `The wrapper hides it`
- p12 bullet 2: `the limitation is in the wrap SP1 ships` → `the limitation is in the wrapper SP1 ships`
- p13 RQ3: `The limitation is the zero-knowledge wrap, utilizing pairing curves` → `The limitation is the zero-knowledge wrapper, which is pairing-based`

The p13 rewrite also fixes the grammar; "utilizing pairing curves" is not idiomatic.

### B2 · three names for the base proof

p12 table row says **PLUM.Verify**. p12 bullet 1 says **base proof**. Script says **SP1's default receipt**. Sako asked "what is base proof?" on 26 July and it is still undefined.

**p12 bullet 1, find** `The base proof is quantum-safe`
**Replace** `SP1's default receipt, the first row, is quantum-safe`

That ties the bullet to the table row and matches the script word for word.

### B3 · p13 says "committed area", p3 and p11 say "total committed area"

**Find** `power-residue precompile committed area: 11.37 M vs 117.46 M cells`
**Replace** `power-residue precompile total committed area: 11.37 M vs 117.46 M cells`

### B4 · p10 says "with Griffin"

Sako, 26 July: *"the term 'with Griffin' in the slide should mean 'accelerators/precompile for Griffin'. Or Griffin the name of the precompile?"* Your script already says "with the Griffin precompile." Only the slide lags.

**Find** `with Griffin` → **Replace** `with Griffin precompile`

---

## B5 · p7 — Test A and Test B are undefined, and p11 inherits the problem

Wu asked this on 27 July and it is still open: *"what is A B? I don't think i understand how to use this criteria."* The labels also propagate — p11's table has a column headed **Cost-Criterion Test** with values A, B, A. Undefined on p7 means undefined on p11.

The script explains both tests correctly, so listeners are fine. Readers are not, and Sako's standard is that a term on a slide is defined on the slide.

**B5a · The slide never says what A is.** p3 defines "total committed area". p7 uses A_emulated, A_precompile and A_total without connecting them to it.

**Find** `A precompile is built only when it removes more proving work than it adds`
**Replace** `A precompile is built only when it removes more proving work than it adds. Work is total committed area, written A`

**B5b · Name the tests rather than lettering them.** What separates them is the baseline, and that is the conceptual content. One asks whether a precompile beats no precompile; the other asks whether yours beats the one already shipped.

`Test A:` → `Test A — against emulating the operation:`
`Test B:` → `Test B — against a precompile that already exists:`

This also fixes p11's column with no edit to p11.

**B5c · A_syscall is never defined.** Four symbols on the slide, three explained in the bullet. Fix it inside the underbrace that already exists.

`area removed` → `area removed per call, net of the call's own cost`

**Leave the figure.** Seventy blue squares against thirty pink is the only thing on p7 a referee reads in one second.

---

## C · Five small ones

**C1 · p2 grammar.** `what needs to be prove keeps changing` → `what needs to be proved keeps changing`

**C2 · p12 — the core-shape footnote, still not added.** This was edit 1 of the last patch and is the only one that did not land. Add under the table, small type:
> BDEC.ShowCre wrapper includes a one-time 2.96 h core-shape pass. Each wrapped run peaks near 15 GiB.

*Why it still matters:* 706 sits next to 252 with no explanation. Anyone who divides gets 2.8× and asks why, and your own `tab:proof-mode` footnote is the answer.

**C3 · p12 — no security level stated.** Five times on that table and no λ. Add to the caption line or the Substrate header:
> All SP1 rows at λ = 80.

Aurora is Loquat over a different field, which the row already flags.

**C4 · p14 bullet 1 — comma changes the meaning.** As written, "built from hashing alone using a post-quantum-sound method" says the receipt is already built with a PQ-sound method, which is the thing you are proposing to do.
**Find** `which is built from hashing alone using a post-quantum-sound method`
**Replace** `which is built from hashing alone, using a post-quantum-sound method`

**C5 · p10 — say these are unwrapped.** p10 shows CreGen at 68.96 and p12 shows CreGen at 252. Both are correct, and p12's row label carries the distinction, but p10 never says its figures exclude the wrapper.
Add to the `Full credential at λ = 80-bit security` heading: `(base proof, no wrapper)`

---

## D · Two things I am not recommending, and why

**The single summary sentence at p5 and p13.** I proposed this when the deck had no visible spine. It now has one. Restoring Finding 1, 2 and 3 as slide titles gives the audience the count and their position, and s5 already carries the causal reason for the ordering: "That has to come first, because until it is answered nothing finishes." Adding a summary sentence on top would be a third statement of the same structure. Sako treats restatement as a defect, not emphasis. Leave it.

**Making the script say "Aurora."** Slide says "Aurora Circuit", script says "static circuit". Strictly this is a script/slide divergence, but it runs in the safe direction. The slide names the tool for anyone reading, and the spoken word describes what it is for anyone listening. Wu's question was "what is Aurora?", and "a static circuit" is the answer. Saying both would cost three seconds for no gain. Leave it.

---

## E · Two things to know, not to change

**p12 bullet 2 says the limitation is "not in zkVMs as such", and your evidence is a static circuit.** A static circuit achieving both does not strictly prove another zkVM could. Your thesis phrases it more carefully as "not an impossibility result for zkVMs", which is what the evidence supports. The slide's wording is fine, but if pushed, retreat to the thesis phrasing rather than defending the stronger claim.

**Script slides 15, 16 and 17 are empty.** That is correct. They are references and the appendix divider. Nothing to say.

---

## Order to do them in

A1 through A5 first, about ten minutes. Then B1 through B4, about five. C1 through C5, about five. Total twenty minutes, all find-and-replace, no layout touched.

After that, time it twice and stop.
