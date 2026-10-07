# Q&A Spoken Cards — short answers only (defence day)
Rule for every answer: **verdict first → one reason → stop.** If they want more, they'll ask — or say "I can go deeper if helpful." Where a slide helps, the card says **[show: …]**. Never scroll while talking; finish the sentence, then navigate.

## The big six
**Novelty?** — "Cycle counts — the standard metric — give the wrong build decision in all three of my cases. My criterion, priced in committed area, gives the right one, and it was confirmed before building. And the security result is precise: the obstruction is the wrapper, not the zkVM."

**Is ZK needed at issuance? Is a proof needed?** — "Yes to both. The proof binds the pseudonym to the master key — without it, links can be forged. Zero-knowledge protects the witness, which is the master public key and the pseudonym secret — revealing those links every pseudonym of the user. The attributes are visible to the authority anyway."

**Is 103–137 minutes practical?** — "Feasible, not yet deployable — and that's the claim. Before this work it did not finish at all. Now everything completes inside 24 gigabytes, and we know exactly where the remaining cost is."

**Why 80-bit?** — "It is the largest level at which prove-mode wall-clock is observable on this machine — a hardware-budget choice, not a security recommendation. The 128-bit analysis is execute-mode, and no number mixes the two levels."
  ↳ *follow-up "but the static SNARK does 128":* "A static circuit commits only the verification arithmetic. A zkVM also commits fetch, decode, and memory columns at every step, and its fixed 31-bit field splits PLUM's numbers into seven limbs. Both overheads grow with the security level — so 128 exceeds this machine's memory, not the architecture."

**Evidence the obstruction is the wrapper, not zkVMs?** — "The thesis includes a static-circuit reference: Loquat verification with zero-knowledge, post-quantum, about 22 minutes. Both guarantees are achievable — just not through SP1's pairing-based wrapper. It's cross-scheme, which is exactly why the matched comparison is my first future-work item."

**Measured or estimated?** — "All measured. Verification is a mean of five runs; the multi-hour runs are single runs, disclosed as such. The one prediction is the multiply row — and it's labelled as one."

## Security & threat model
**Threat model?** — "Three games — unforgeability, anonymity, unlinkability — with adaptive issuance and showing oracles, classical adversary in the random-oracle model. The post-quantum claim enters at the assumption layer." *(offer: "the experiments are in the security chapter, Section 5.5")*

**Who is trusted?** — "The authorities and issuer hold signing keys; the holder proves; the verifier checks; the ledger roots and revocation list are public."

**Is the adversary quantum?** — "The reductions are classical. Post-quantum sits in the assumptions: the power-residue PRF is quantum-hard under classical queries — the Q1 model — and Griffin in the QROM. Q1 is the right model because the signature exposes the PRF only on fixed public indices."

**Do precompiles weaken security?** — "The substitution is value-level, so PLUM's black-box reduction transfers. What must additionally hold is that each precompile's constraints capture exactly its operation, and that lookups bind it to the CPU table — those are two of my five named assumptions. Preserved, conditionally — and the conditions are named on slide 12."

**What are the five assumptions?** — "AIR constraint soundness, PLUM transcript simulatability, lookup binding, key-privacy, and Griffin's oracle instantiation — plus one conjecture: knowledge extraction across SP1's shard recursion. Closing them is future-work four."

**What leaks from the default proof?** — "It has no hiding guarantee, and I measured the symptom: receipt sizes differ across witnesses for the same relation. The wrap closes that — but the wrap is pairing-based. The fix and the gap are the same component."

**Everlasting anonymity?** — "Anonymity against someone who records the proof today and is unbounded later. I prove it cannot be established in the standard model for this construction — the receipt's hiding comes from the random oracle, and that's an idealisation."

## The criterion
**Isn't this just the textbook hardware criterion?** — "The form is — deliberately; I cite Hennessy and Patterson. What's new is the mapping: in a zkVM the fixed cost is recommitted in every proof, and the right unit is area, not cycles. The naive transfer builds the wrong precompiles."

**Area was 'unmeasurable' — how did the rule decide?** — "The rule's inputs are per-call figures from execute mode and the table design — none need a completed proof. What's unmeasurable is the baseline's end-to-end total, because that run never finished." *(never say "ran out of memory" — it was stopped at 5 h, peak 13.6 GiB)*

**Griffin lost to SHA-3 — bad build?** — "Two different questions. Test A: should we accelerate Griffin-PLUM? Yes — unfinished became fourteen minutes. Test B: is Griffin the right hash? The rule predicted no, and it was right. A correctly predicted disadvantage is the rule working."

**More columns yet less area — how?** [show: appendix p.25] — "Area is rows times columns across all tables. The precompile is wider per operation, but it collapses the per-call control overhead — about 261 to one. That's why totals decide and per-operation metrics mislead."

**What is the power-residue check?** — "A modular exponentiation — the verifier recomputes the power-residue symbol against the public key."

**What is A_syscall?** — "The call's own overhead — subtracted so the saving per call isn't overstated."

**91% — how measured?** — "That's PLUM's own circuit accounting — 91 percent of their constraints are hash work. In the zkVM's units the hash also dominates: five million multiplication syscalls without the precompile, seventy thousand with it. Two cost models, same conclusion."

**58.5× / 164× — where from?** — "Execute-mode. They exceed the schoolbook 49 because the whole permutation collapses into one call, and the software path is a general bignum library. Prove-time is reported separately, on purpose."

## Setup & scope
**Why a laptop?** — "The holder proves. Outsourcing the proof hands the witness to a server. Consumer hardware is the honest deployment setting."

**Why not GPU?** — "SP1's GPU path is CUDA-only, and Apple Silicon has no CUDA. CPU-bound by necessity."

**Why not ML-DSA?** — "The signature must verify inside a proof, so it must be SNARK-friendly. I measured the alternative: an ML-DSA verification baseline was killed by the OS in four minutes with an eighty-gigabyte footprint. It doesn't start on this substrate."

**Does it generalize beyond SP1?** — "The criterion's form, yes; the magnitudes, no — they're tied to this field, this machine, this prover. Transfer is testable, and that's future work."

**Is this extensible beyond AIR zkVMs and PRF-family signatures? To what extent?** — "The criterion's form extends to any zkVM with precompiles — the thesis shows the field-mismatch tax is substrate-independent. The unit, committed area, is right for the AIR-and-STARK class; a lookup- or folding-based zkVM would keep the form but need its own unit and constants. The criterion itself is scheme-agnostic — I even ran a lattice baseline, which is how I know ML-DSA doesn't start on this substrate. What doesn't extend is the magnitudes — which is exactly why the matched-substrate comparison is future-work one."

**What breaks at 128?** — "Expected — not measured — to exceed memory: the hash parameters and repetitions grow the committed trace, and the precompile-free arm already fails at 80."

**Wrapper memory peaks?** — "All between fifteen and sixteen gigabytes — inside the budget. The obstruction is cryptographic, not memory."

**Who needs this?** — "Educational credentials: prove the degree, hide the transcript, stay valid for decades — which is why post-quantum."

## If the field size comes up
**"192 or 199?"** — "192 is PLUM's own loose label; the concrete prime is 199 bits. One more thing: the modulus printed in the PLUM paper is composite — a typo — so I substituted a structurally valid 199-bit prime and carry that as an explicit hypothesis in the security chapter."

## Gaiyousho-specific (for jurors who read only the 2 pages)
**"You write 'in a zkSNARK the computation is defined before the system is built; in a zkVM it is an input' — but isn't a zkVM built out of a SNARK/STARK?"** — "Yes — a zkVM is a proof system for one *fixed universal* relation, the instruction set. The circuit is built once; after that, the program is an input. The summary states the fixed-relation versus universal-relation distinction in plain words."

**"Your summary says the zkVM is 'more suitable' — but your own conclusion says only the static circuit achieves both guarantees. Contradiction?"** — "No — two different axes. 'More suitable' is about update churn: a predicate change is a program edit with zero circuit re-audits. The dual obstruction is about the wrapper's cryptography. And the thesis reports honestly that the *speed* version of the flexibility claim was falsified — the defensible advantage is the re-audit footprint."

**"What is 'the pseudorandom check'?"** *(gaiyousho's name)* — "The same object the talk calls the power-residue check — the PRF evaluation at PLUM's core, a modular exponentiation the verifier recomputes against the public key."

**"'Cell 1–4' — what are cells?"** *(watch the double meaning!)* — "In the summary, Cell 1 to 4 name the four measured configurations. Unrelated to 'committed cells' in the talk, which are trace cells — I'll say 'configuration' and 'trace cells' to keep them apart." *(Discipline for the whole Q&A: say "configuration" for runs, "trace cells" for area.)*

**"You say cost rises with the *square* of the number of pieces — but you measured 164×, not 49×?"** — "The square is the product count — 49 partial products at seven pieces. The measured 164× exceeds it because the software path is a general bignum library with reduction and carry overhead; the thesis proves the lower bound and reads 164× as a conservative endpoint, not a scaling law."

**"The hash-based route in your conclusion — how real is it?"** — "Two routes exist as code: masked FRI and a compiler-style approach. The remaining work is wiring them into the multi-shard prover and establishing the zero-knowledge lemma for the low-degree test — that is future-work two, and it is engineering plus one lemma, not a redesign."

## Spoken glosses — first mention only, term–dash–plain words, keep moving
- **zero-knowledge proof** (slide 2): "…a zero-knowledge proof — *a proof that convinces the verifier without revealing anything else* — that a valid signature covers the whole set."
- **execute mode** (slide 6): "…*counting steps without generating a proof*." (already on the slide footnote)
- **pseudonym** (slide 10): "a fresh pseudonym — *a one-time public identity derived from the master key*."
- **sub-second interactive latency** (slide 10): "…*the response time a login-style interaction would need* — that is not feasible."
- **witness** (slide 12): "the holder's data — *the private inputs of the proof*."
- **substrate** (Q&A only): "*the proving system underneath — the zkVM or the static circuit*."

Never gloss on re-mention — define once, then use the bare term. In Q&A prefer the plain words themselves: "counting steps," "the private inputs," "the proving system underneath."

## Appendix map (what to pull up)
p.18 Loquat · p.19 PLUM · p.20–22 BDEC algorithms & actors · p.23 Griffin vs SHA-3 bars · p.24 multiply bars · p.25 power-residue bars + legend definitions.
