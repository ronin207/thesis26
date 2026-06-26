# P5 — Masked PQ-ZK for BDEC-over-zkVM (working derivation)

**POST-DEFENCE. NOT part of the thesis.** Goal: prove the masked construction
achieves PQ zero-knowledge (statistical in the QROM), hence BDEC anonymity,
closing the ZK prong of the dual obstruction. Meticulous, grounded, no false
positives — every claim traces to a paper §/Thm or to code file:line, and where
the derivation is stuck the blocker is stated, not papered over.

## Ground truth (verified against local PDFs, 2026-06-25)
- **masked-FRI** [`2024/1037`, Haböck–Al Kindi]: **perfect HVZK**, Thm 4 (p7, toy
  FRI), Thm 6 (p13, AIR/DEEP-ALI). Condition: degree-of-freedom bound **Eq (3)
  p9**: `2d(e·n_F + n_D) + n_D ≤ h ≤ |H|` (d=AIR degree, e=ext degree, n_F=DEEP
  queries, n_D=FRI rounds, h=randomiser degree). Decoupling Lemma 2 (p7) is the
  engine. **FRI / univariate-RS only. HVZK not full ZK. Exact (no ε).**
- **STIR** [`2024/390`, Arnon–Chiesa–Fenzi–Yogev]: round-by-round soundness
  `2^{-λ}`, **Thm 5.1 (p22)**, **Lemma 5.4 (p24)** (per-message error tuple).
  RBR ⟹ state-restoration ⟹ BCS/FS (p3 fn1). Folding `k≥4`; thesis pins **η=4**
  (floor, off STIR's recommended η=16). Covers the **inner RS-proximity IOPP**;
  PLUM's *composed* IOP RBR via STIR's compiler §7 / App B (open for PLUM).
- **CMS** [`2019/834`, Chiesa–Manohar–Spooner]: BCS **Thm 8.6**: (1) soundness ←
  RBR `O(t²ε + t³/2^λ)`; (2) knowledge ← RBR; (3) **ZK ← HVZK of IOP, STATISTICAL,
  requires SALTED leaves** (Lemma 7.3, §2.8).
- **DFMS** [`2019/190`]: measure-and-reprogram Thm 2, `O(q²)` loss — **soundness/
  extraction, NOT ZK**.
- **BDLOP** [`2016/997`]: comp-hiding (Lemma 6, M-LWE) + comp-binding (Lemma 7,
  M-SIS); stat-hiding regime exists but stat-both impossible (Fig 1, Lemmas 4–5);
  opening is **interactive / relaxed / norm-mismatched Σ-protocol (§4.1)** — NOT
  RS-proximity-compatible.

## The reduction skeleton (from the grounding)
ZK of masked zkVM proof = **CMS Thm 8.6(3)**: `HVZK(masked IOP) + salted leaves
⟹ statistical ZK in QROM`. Two inputs are open for the PLUM instance ⇒ Steps 1, 2.
Anonymity = existing thesis **C1** games (G0/G1/G2) with `ε_ZK` discharged ⇒ Step 3.

## Step 1 — masked-HVZK for STIR at η=4, Fp192  [THE HARD ONE — algebraic, not games]
Target: the STIR analog of `2024/1037` Thm 6. Deliver (a) STIR's per-round queried
oracles (folded + quotiented), (b) the randomiser/masking for STIR's k-fold step,
(c) the degree-of-freedom bound (analog of Eq 3) at η=4, (d) the decoupling lemma
⟹ exact witness-independence under (c).

### Iteration 1 attempt (2026-06-25)

**How Haböck's FRI argument works (the thing to transfer).** Randomize once at the
start: `ŵ_i = w_i + v_H·r_i`, `r_i ←$ F_p[X]^{<h}` (Protocol 3, p9). HVZK is two
lemmas: **Lemma 3 (Quotient components, p11)** — the queried values of `ŵ_i` *and*
the FFT-decomposition components `q_1..q_d` of the **single** DEEP quotient lie in
the image of the evaluation map `E: F_p[X] → K^Q̄`, which `v_H·F_p[X]^{<h}` fills
*exactly* when `h ≥ |Q̄|`; and **Lemma 2 (Decoupling, p7)** — the batch-FRI mask
`R(X)` isolates the FRI tail. Bound **Eq (3)**: `2d(e·n_F+n_D)+n_D ≤ h ≤ |H|`.
Load-bearing fact (footnote 3, p5): the randomizer rides **one** folding chain, and
its protection *halves each FRI step*; the single `h` budget covers the whole chain.

**(a) STIR's per-round queried oracles (Construction §2.2, p9).** STIR is *not* one
folding chain. Each of the `M = O(log_k d)` iterations: (1) verifier sends
`r^fold`; (2) prover sends a **fresh oracle** `g ≈ Fold(f, r^fold)`, degree `<d/k`;
(3) verifier sends out-of-domain `r^out ← F\L'` **after `g` is committed**; (4)
prover replies `β = ĝ(r^out)`; (5) `t` shift queries `y_i = Fold(f,r^fold)(r_i^shift)`
to the *previous* oracle. Next oracle: `f' = Quotient(g, G, p)`,
`G = {r^out, r_1^shift,…,r_t^shift}`, i.e. `f'(x) = (g(x) − p̂(x))/∏_{a∈G}(x−a)`.

**(b) Randomizer attempt.** The natural analog is a *per-round* randomizer on each
fresh `g_i` (not Haböck's single start `v_H·r`): `ĝ_i = g_i + v_{L'}·s_i`. This is
already a departure — STIR commits a new low-degree-`d/k` function each round, so
one start randomizer does not propagate into `g_i`.

**(c) Degree-of-freedom bound.** Not a constant substitution into Eq (3). k-wise
folding (η=4 ⇒ k=4) shrinks the randomizer budget by a factor `k` **per round**
over `M ≈ log_4 d` rounds (for PLUM d*=128 ⇒ M≈4, a 4^4≈256× shrink), and each of
the `M` fresh oracles needs its own budget. The bound becomes a per-round system,
not a single inequality.

**(d) Decoupling — STUCK, precise blocker.** Haböck's Lemma 3 covers the **single**
start-of-protocol DEEP quotient and its FFT components. STIR applies an
**iterated** quotient: `f'_i = Quotient(g_i, G_i, p)` and `g_{i+1} = Fold(f'_i,·)`,
so witness-dependence chains through `M` *quotient-then-fold* compositions, each
introducing an out-of-domain point `r^out` **sampled after `g_i` is committed**.
There is no published analog of Lemma 3 for (i) a freshly-committed per-round oracle
or (ii) the iterated quotient-fold composition with post-commitment OOD points. The
quotient numerator `g_i` is queried in the next round, so the randomizer must keep
the queried distribution in the evaluation-map image *through every round's
division by ∏(x−a)* — exactly what Lemma 3 does not establish past round 1.

**Status: STUCK.** Blocker: STIR's iterated *fresh-oracle-commit + per-round
quotient* structure (M rounds), vs FRI's single folding chain. Haböck's single
start-randomizer + single-DEEP-quotient HVZK (Lemma 3) does not cover (i) per-round
oracle randomization or (ii) the iterated quotient-fold decoupling with
post-commitment OOD points. **Not a constants problem — a missing lemma.**

**Next iteration should attack:** (1) randomize each STIR round's fresh oracle `g_i`
independently and check consistency with the fold/quotient soundness relations
(does `ĝ_i = g_i + v_{L'}·s_i` survive STIR's degree-correction and round-by-round
soundness?); (2) prove a **single-iteration** Lemma-3 analog for one STIR round
(fold + OOD + shift + quotient) — if that holds, attempt to compose it across the M
rounds; (3) only then derive the per-round d.o.f. system at η=4. Verify any
single-round claim with proof-checker before composing (the OOD-after-commit
ordering is the most likely place a decoupling argument silently fails).

### Iteration 1.5 — verification of the blocker (2026-06-25): REDIRECTED
The fork's negative claim ("no published analog of Lemma 3") is **REFUTED** by a
literature check (Exa, non-eprint sources):
- **ZK-WHIR** (ProveKit / `worldfnd/whir`, following the "WHIR ZK documentation").
  **WHIR** [`2024/1586`, Arnon–Chiesa–Fenzi–Yogev, EUROCRYPT 2025] is the STIR
  **successor** — "a direct replacement for FRI, STIR, BaseFold." ProveKit
  implements **zero-knowledge WHIR**: two-phase **masked witness** `f̂` +
  **blinding polynomial** `g` + sumcheck. Its **two-phase commit** ("prover cannot
  choose w2 until after committing to w1") **directly addresses the
  post-commitment-OOD ordering** the iter-1 blocker called unsolvable.
- **hc-stark v4** (`logannye/hc-stark`, engineering spec): masked trace oracle
  `T'(X)=T(X)+Z_H(X)·R(X)` → quotient from the masked trace, FS-independent mask.
  An engineering template for masked-quotient ZK.

**Consequence — Step 1 reshapes.** It is *not* a from-scratch missing lemma. The
route is now: (i) verify whether ZK-WHIR's HVZK is **PROVEN** (peer-reviewed
theorem with simulator + bound) or only **CLAIMED** (ProveKit engineering docs,
"bounded query model"); (ii) either **adapt** its two-phase masking to STIR's
iterated quotient, or **switch** PLUM's proximity test STIR→WHIR (a "direct STIR
replacement", but it changes PLUM's inner IOP — not a free swap).

**Needed for the rigorous check:** WHIR PDF `2024/1586` + the ProveKit ZK-WHIR
docs. **Status: Step 1 → REDIRECTED** (candidate template found; verify + adapt/switch).

### Iteration 4 — WHIR PDF read (2026-06-25): proven-vs-claimed settled, route chosen
WHIR paper read directly (`2024-1586.pdf`; Arnon–Chiesa–Fenzi–Yogev, EUROCRYPT 2025).
- **(1) WHIR has NO ZK theorem — ZK-WHIR is CLAIMED, not PROVEN.** ToC (pp.2-3) and
  §1.1 contributions (pp.7-8) have no ZK/hiding/masking section; the only proven
  security property is round-by-round soundness (Thm 5.2, p.34; Thm 1, p.5). The
  honest prover (§2.1.3 p.12; Construction 5.1 p.32) commits the **raw** evaluation
  f/g with **no blinding polynomial**. So "ZK-WHIR" lives only in unrefereed
  ProveKit / `WizardOfMenlo/whir` docs = CLAIMED.
- **(2) WHIR sidesteps HALF the STIR blocker.** REMOVED (the hard half): STIR's
  iterated quotient-then-fold chain — WHIR enforces OOD+shift consistency "directly
  ... **without the use of quotients**" (§2.2, p.16), recursing via a weight-poly
  update `ŵ′` on a new constrained-RS code (§2.1.3 step 6). KEPT: **post-commitment
  OOD** — §2.1.3 step 3 samples `z₀←F` *after* `g` is committed (step 2), identical
  to STIR. ⇒ "WHIR masks like VEIL automatically" REFUTED; "WHIR is a more
  masking-tractable substrate" PROVEN (structural). [Corrects iter-1.5's overclaim.]
- **(3) Route.** (a) adapt-STIR: OPEN (missing decoupling lemma), but NO change to
  PLUM. (b) switch PLUM STIR→WHIR: dissolves the hard quotient half (PROVEN, §2.2)
  and lands on a Basefold/VEIL-shaped object (aligns Step 2), but NOT a free swap —
  changes PLUM's inner IOP (replaces STIR verifier gadgets in
  `src/signatures/loquat/r1cs_circuit.rs`; maybe signature size — INFERRED-needs-read
  PLUM §3.3/§4.2 + `src/signatures/plum/{verify,transcript,sign}.rs`). Comparability
  favorable: WHIR pins k=4 (§6.2 p.44) ≈ PLUM η=4; WHIR benchmarks a 192-bit prime
  (fn 7 p.43) = PLUM's bit-width class.

**Recommended route: (b) switch-to-WHIR — but it RELOCATES the open obligation, not
closes it.** The single remaining proof obligation is a **refereed masked-WHIR HVZK
theorem** (a simulator over the post-commitment OOD + shift queries), currently
CLAIMED-only. Kazuesako flag: STIR→WHIR is a PLUM-inner-IOP change (C≠D), a scope
decision in itself, and even post-swap PQ-ZK is not free.

**Status: Step 1 → ROUTE CHOSEN (b switch-to-WHIR). Open theorem = masked-WHIR HVZK
(post-commitment-OOD simulator). ZK-WHIR = CLAIMED. Blocker sidestep = HALF
(quotient PROVEN-removed; OOD remains).**

### Iteration 5 — masked-WHIR HVZK attempt via VEIL blinding (2026-06-25)
Read WHIR §2.1.3 + SP1 `whir/prover.rs:263-534` (round loop) + VEIL
`inner/prover.rs:586-599`, `stacked_pcs/prover.rs:122-405`.
- **(c)(i) OOD ordering — SOLVED.** VEIL commits the mask columns in
  `zk_commit_mles` (`stacked_pcs/prover.rs:145-166`) BEFORE any eval point; WHIR
  samples `z₀` only after observing the commitment (`whir/prover.rs:340,348-355`).
  And the OOD answer `ĝ(z₀)` is NOT an independent opening — it folds into the next
  sumcheck's claimed sum (`whir/prover.rs:440-454`; paper §2.2 "without quotients").
  One masked-sumcheck per round covers it. **PROVEN-compatible.**
- **(c)(ii) Remaining sub-blocker — SHARPENED + SMALLER.** The `t` shift queries
  return `t` RAW Merkle-leaf values of the committed `g_i` per round
  (`whir/prover.rs:385-437`). VEIL's invariant is ONE mask MLE per commitment = one
  masked evaluation (`inner/prover.rs:586-599`). `t` leaf openings ≠ one masked
  eval → **Step-2's multi-opening reappears one level DOWN, inside the WHIR round.**
  STIR→WHIR removed the quotient chain (iter-4) but NOT the t-query-per-oracle
  structure. Granularity mismatch (kazuesako): VEIL masks at *eval-claim*
  granularity; WHIR queries at *leaf* granularity (t per oracle).
- **Next thread (may shrink to a counting check, not a lemma):** VEIL's
  `zk_commit_mles` already appends `query_count` random padding ROWS
  (`stacked_pcs/prover.rs:141-147`), sized to the query count. IF those rows land on
  WHIR's `t` shift-query indices, the per-leaf masking may already exist → a
  wiring/counting check, not a missing lemma. Needs: `slop/crates/basefold/` opening
  path + VEIL `protocols/sumcheck.rs`.
- **Caveat:** SP1 WHIR runs over KoalaBear, not Fp192; structure transfers, the
  Fp192 d.o.f. budget for the masked-sumcheck is INFERRED.

**Status: Step 1 → masked-WHIR HVZK OPEN; sub-blocker = the t shift-query leaf
maskings (OOD SOLVED). Next = test the VEIL padding-rows hypothesis (counting check
vs missing lemma).**

### Iteration 6 — DECISIVE padding-row test (2026-06-25): REFUTED → exact residual lemma
Read VEIL `stacked_pcs/prover.rs:122-405`; WHIR `prover.rs:329-393,440-454,547-587`;
`merkle-tree/p3sync.rs:191-223`; `basefold-prover/prover.rs:185-230`.
- **(a) The t shift-query leaves are RAW witness-dependent; VEIL's padding does NOT
  mask them.** (i) **WHIR is NOT wired to VEIL** — WHIR merkle-commits the RAW DFT
  codeword (`whir/prover.rs:329-337,574-577`); grep VEIL crate for `whir` = 0, grep
  WHIR crate for `zk_commit_mles` = 0; disjoint PCS backends; reads are raw leaves
  (`p3sync.rs:215` `tensor.get(idx)`). (ii) Even in VEIL's own basefold path,
  padding is appended pre-encoding AFTER the data rows
  (`stacked_pcs/prover.rs:142,158`); the FRI query hits the ENCODED codeword domain
  (`basefold-prover/prover.rs:195-196`) — post-RS-encoding each leaf is a lin-comb of
  ALL input rows, so "padding lands on query indices" is ill-posed.
- **(b) STUCK — the `query_count ≥ t` counting hypothesis is REFUTED.** Necessary
  (d.o.f.) but NOT sufficient: VEIL masks at EVAL-CLAIM granularity (one masked RLC
  eval, `stacked_pcs/prover.rs:284-287`); the obligation is at CODEWORD-LEAF
  granularity (joint distribution of the t opened RS leaves witness-independent).

**Exact residual lemma (OPEN) — the single theorem P5 must prove.** For each WHIR
round `i` with committed `Ĉ_i = RS-encode(DFT(Fold(f_{i-1}, r_i^fold)))`, there must
be a randomizer on `g_i` added BEFORE commit such that, for any `t` post-commit query
positions, the joint leaf distribution `(Ĉ_i[q_1],…,Ĉ_i[q_t])` — together with the
OOD answer folded into the next sumcheck claim — is witness-independent. This is the
WHIR / η=4 / Fp192 analog of Haböck `2024/1037` Lemma 3 (eval-map image, `h ≥ |Q̄|`),
which is proven only for a single start-of-protocol DEEP quotient, not for a per-round
freshly-committed folded oracle with post-commitment OOD. **OOD half stays SOLVED**
(iter-5); the **t-leaf half is the irreducible residual.**

**Kazuesako:** VEIL (C) ≠ WHIR (D) — disjoint objects, not even wired; "transfer the
mask" was never a counting/wiring check. **INFERRED:** SP1 WHIR = KoalaBear; the
Fp192 d.o.f. budget for the lemma is INFERRED, not read.

**Status: Step 1 → masked-WHIR HVZK OPEN; the single residual lemma stated EXACTLY
(per-round t-leaf masking). Counting route REFUTED. OOD SOLVED.
=== P5 RESEARCH PHASE COMPLETE: the one theorem to prove is now precisely scoped. ===**

## Step 2 — multi-shard single-opening  [engineering / protocol]
Target: reconcile VEIL's one-eval-claim-per-commitment (`veil/.../prover.rs:586`)
with SP1's multi-shard prover (multiple openings per commitment). Map the solution
space (per-shard commitments? batched single-opening preserving the invariant?).

### Iteration 2 (2026-06-25)
**Framing correction.** The conflict is NOT "one commitment opened at multiple
points within a shard" — each SP1 shard commits and opens its OWN trace once
(`hypercube/.../shard.rs:678-681` commit, `:769-780` single open). Two real
shapes: (1) a *reused* commitment recurs across shards/recursion; (2) decisively,
**VEIL is UNWIRED** — zero refs under `sp1/crates/` (Grep); production uses the
non-ZK `JaggedProver`, not VEIL's `ZkBasefoldProver`. So "reconcile" is first a
*category* question: at which single-opening boundary do you attach VEIL?

**The invariant (why one opening).** VEIL commits one mask MLE per commitment
(`veil/.../stacked_pcs/prover.rs:136-147`); a masked opening is `data + α^k·mask`.
One opening leaks nothing (fresh uniform mask); a *second* opening of the same
commitment reuses the *same* committed mask, so the witness re-emerges from the
difference (`zk/inner/prover.rs:586-599`). Soundness untouched.

**Solution space.** (a) per-shard mask — PROVEN for leaves, incomplete for the
aggregate; (b) same-point batching (`prove_multi_eval`) — PLAUSIBLE but parasitic
on (c) (shards open at *different* FS points); (c) **mask only the final recursive
aggregation proof** (SP1 already recurses via `RecursiveShardVerifier`,
`prover/.../core.rs:27`) — MOST PROMISING, one commitment / one point; (d)=(a)+(c).

**Next obstacle.** Confirm the final recursion proof opens every commitment ≤1×
— read `sp1/crates/recursion/`. If it opens any commitment at two points, (c)
trips the invariant one level up and **falls back into Step 1's masked-LDT
problem** (per-opening fresh mask). So Steps 1 and 2 are coupled.

### Iteration 3 (2026-06-25) — recursion opening multiplicity: route (c) CONFIRMED
The FINAL recursion proof (shrink→wrap, the one fed to Groth16/PLONK) is a
**single root shard** (shrink/wrap "only verify the single root shard",
`recursion.rs:284-360`; Groth16 input singleton `vks_and_proofs: vec![(vk,proof)]`,
`worker/prover/recursion.rs:742-745`). That shard proof has **exactly two PCS
commitments** (`vk.preprocessed_commit` + `main_commitment`,
`recursion/circuit/src/shard.rs:253-254`), **each opened once at one point**
(`shard.rs:274-281`): no local/next pair (`.local` only, `:215,218-221`;
row-rotation is in the zerocheck sumcheck, `next_pc` is a public value), and the
jagged→stacked→basefold stack collapses the batch to **one opening at one sumcheck
point** (`jagged/verifier.rs:170-178`, `basefold/stacked.rs:31,38-49`).

**Verdict: route (c) invariant-COMPATIBLE.** Masking only the final recursive proof
respects VEIL's one-mask-per-commitment invariant; **Step 2 does NOT collapse into
Step 1.** Caveats (kazuesako): (1) CONFIRMED for the proof *structure*; the basefold
*prover*-side VEIL wiring is unbuilt (VEIL unwired, iter-2) — feasibility is
structural, not implemented; (2) children's commitments verified in the compress
loop (`shard/compress.rs:159-186`) are inputs, not the final proof's masked
commitments; (3) VERSION-DEPENDENT on the single-shard root topology — re-check on
any SP1 recursion-layer bump.

**Status: Step 2 → FEASIBLE (route c, structural; iter 3); (a) proven for leaves;
VEIL recursion-prover wiring unbuilt.**

## Step 3 — anonymity corollary  [easy composition, once 1+2 hold]
Target: BDEC-over-masked-zkVM anonymity = thesis C1 games with `ε_ZK` from Step 1
(via CMS 8.6(3)). Write the game-based composition.

### Conditional corollary (writeable now)
**Corollary (conditional masked anonymity).** Assume (C1) the thesis preservation
theorem — anonymity reduces to `ε_ZK + ε_sZK` via games G0/G1/G2; (Claim 1) the
masked construction is statistical ZK in the QROM — i.e. the Step-1 STIR/η=4
masked-HVZK derivation holds and leaves are salted (CMS Thm 8.6(3)); and (Step 2,
route c) masking attaches at the single-opening final recursive proof (iter 3).
Then BDEC-over-masked-zkVM is anonymous in the QROM: discharge C1's `ε_ZK` with
Claim 1's simulator; the games are unchanged. The composition is **mechanical**
once Claim 1's two open premises (the STIR-HVZK derivation; the VEIL
recursion-prover wiring) are met — confirming the earlier judgement that Step 3 is
not where the difficulty lives.

**Status: Step 3 → conditional corollary stated; unconditional once Steps 1+2 are
built. Step 2 structurally feasible (iter 3); Step 1 the sole open derivation.**

## Log
- 2026-06-25: seeded; ground truth verified against local PDFs. Loop begins on Step 1.
- 2026-06-25 (iter 1, Step 1): read Haböck Thms 4/6, Lemmas 2/3, Eq (3); STIR §2.2 anatomy. Attempt → **STUCK**: STIR's iterated fresh-oracle-commit + per-round quotient (M=O(log_k d) rounds, OOD sampled post-commit) has no analog of Haböck Lemma 3; not a constants problem, a missing decoupling lemma. Next: per-round randomizer consistency + single-iteration Lemma-3 analog, then compose.
- 2026-06-25 (iter 1.5, Step 1 verification): negative claim REFUTED via lit check — ZK-WHIR (ProveKit, WHIR 2024/1586, STIR's successor) two-phase masking addresses the post-commitment-OOD blocker; hc-stark v4 = masked-quotient template. Step 1 → REDIRECTED (verify proven-vs-claimed + adapt-to-STIR or switch-to-WHIR; needs WHIR PDF).
- 2026-06-25 (iter 2, Step 2): VEIL is UNWIRED in sp1/crates/ (Grep, zero refs) → conflict is a category question, not a live panic. One-mask-per-commitment = one ZK opening (veil stacked_pcs/prover.rs:136-147, inner/prover.rs:586-599). Route (c) — mask only the final recursive proof (RecursiveShardVerifier) — MOST PROMISING; (a) proven for leaves. Next: read sp1/crates/recursion/ opening multiplicity; if >1 per commitment, falls back into Step 1's masked-LDT gap. Steps 1+2 coupled.
- 2026-06-25 (iter 3, Step 2): route (c) CONFIRMED invariant-compatible. Final recursion proof = single root shard (shrink/wrap recursion.rs:284-360; Groth16 singleton vec worker/prover/recursion.rs:742-745); 2 commitments (preprocessed+main, shard.rs:253-254) each opened ONCE at one point (shard.rs:274-281); no local/next; jagged→stacked = one basefold opening at one sumcheck point (jagged/verifier.rs:170-178, basefold/stacked.rs:31,38-49). Step 2 → FEASIBLE (structural); VEIL prover-side wiring unbuilt; version-dependent on single-shard root.
- 2026-06-25 (Step 3): conditional corollary stated (anonymity = C1 games with ε_ZK from Claim 1; mechanical once Steps 1+2 built). Loop status: Step 2 feasible; Step 1 the sole open derivation, REDIRECTED to ZK-WHIR, awaiting WHIR 2024/1586 PDF. PAUSED pending that download.
- 2026-06-25 (iter 4, Step 1): WHIR PDF read. WHIR has NO ZK theorem (Thm 5.2 p34 = RBR-soundness only; raw f/g, no blinding) ⇒ ZK-WHIR = CLAIMED (ProveKit, unrefereed). WHIR sidesteps HALF the blocker: quotient-chain REMOVED (§2.2 p16 "without quotients") = the hard half PROVEN-gone; post-commitment OOD KEPT (§2.1.3 step3, identical to STIR) ⇒ iter-1.5's "directly addresses" overclaim CORRECTED. Route (b) switch PLUM→WHIR chosen (dissolves hard half, Basefold/VEIL-shaped, aligns Step 2) but RELOCATES the obligation → open theorem = refereed masked-WHIR HVZK (post-commit-OOD simulator); NOT a free swap (changes PLUM inner IOP / r1cs gadgets, maybe sig size). Comparability: WHIR k=4≈PLUM η=4 (§6.2 p44); WHIR benchmarks 192-bit prime (fn7 p43). **P5 MAPPING COMPLETE: single open theorem located.**
- 2026-06-25 (iter 5, Step 1): masked-WHIR HVZK attempt via VEIL blinding. OOD answer SOLVED (VEIL mask committed before z₀ in zk_commit_mles:145-166; OOD folds into next sumcheck claim whir/prover.rs:440-454, not an independent opening). Sub-blocker SHARPENED + SMALLER: the t shift queries = t RAW Merkle-leaf openings of committed g_i per round (whir/prover.rs:385-437); VEIL's one mask masks ONE eval not t leaves → Step-2 multi-opening reappears INSIDE the WHIR round (granularity mismatch: VEIL eval-claim vs WHIR leaf). Next decisive test: VEIL's query_count padding rows (stacked_pcs/prover.rs:141-147) may already mask the t leaves → counting/wiring check vs missing lemma. Caveat: SP1 WHIR=KoalaBear not Fp192 (structure transfers, d.o.f. INFERRED).
- 2026-06-25 (iter 6, Step 1): DECISIVE padding-row test → REFUTED, residual lemma fixed. (i) WHIR NOT wired to VEIL (raw DFT codeword commit whir/prover.rs:329-337,574-577; zero cross-refs; raw-leaf reads p3sync.rs:215); (ii) VEIL padding is pre-encoding rows (stacked_pcs/prover.rs:142,158), query hits encoded domain (basefold-prover/prover.rs:195-196) → no index collision. query_count≥t necessary-not-sufficient (eval-claim vs codeword-leaf granularity). masked-WHIR HVZK does NOT close to a counting check. EXACT residual lemma stated: per-round t-leaf masking (Haböck-Lemma-3 analog for a per-round freshly-committed folded oracle + post-commit OOD, η=4/Fp192). OOD half SOLVED. Verdict STUCK-missing-lemma (kazuesako: VEIL C ≠ WHIR D). === P5 RESEARCH PHASE COMPLETE; loop STOPPED. ===
