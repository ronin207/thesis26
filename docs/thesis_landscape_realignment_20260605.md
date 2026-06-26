# Goal-level landscape + realignment (2026-06-05)

Output of the broad-goal deep research (`w0ccwr762`, 11 agents: 8 solution-family
researchers + angle comparison + pivot adversary + integrator). Answers "is the
direction forced?" by mapping the whole space. Provenance caveat: eprint.iacr.org
returned HTTP 403 to the fetch tool, so several "verified" tags rest on co-author
theses, author/vendor mirrors, local `/tmp/eprint` PDFs, or >=2 independent search
corroborations, not cover-to-cover reads. Treat citations as strong leads.

## The reframe
You did **not** force one direction. The space has six families:
TS (relation-specific transparent zkSNARK: Aurora/Fractal/STIR), UU (universal/updatable:
Plonk/Marlin), **ZKVM (you)**, FOLD (Nova/HyperNova; PQ: Neo/SuperNeo), LAT (lattice-native
anon-cred: JRS/BLNS/Argo CCS'24), MPC (MPCitH/symmetric: Picnic/FAEST/Pegasus). You occupy
the **flexibility corner of a known trade-off**, not a uniquely-forced point.

## Where you sit (6 angles)
| Angle | You | Deciding fact | Dominant rival |
|---|---|---|---|
| Flexibility / crypto-agility | **WIN** | one fixed VM circuit; φ/λ/structure/signature late-bind as runtime guest data | (FOLD only in principle, unbuilt for creds) |
| Performance | **LOSE decisively** | 13.3 min PLUM-SHA3; Cell 1 DNF @24GB/3h; even 10× lands min vs LAT ~0.5 s | LAT (2-3 orders), MPC |
| PQ (whole stack) | **LOSE** | FRI core PQ but Groth16/BN254 wrap broken by Shor → shipped proof not PQ | MPC (no wrap), LAT, TS |
| ZK / anonymity | **LOSE/contested** | SP1 default not ZK; RISC0 ZK contested by its own advisory | MPC ≈ LAT ≈ TS ≈ UU |
| 24 GB deployability | **LOSE on the real workload** | Cell 1 DNF @24GB/3h without precompile | MPC (µs-ms), LAT |
| Maturity / tooling | **WIN (damning caveat)** | SP1/RISC0 "Prod" — but mature where you don't need it, absent where the contribution lives | UU ties |

Flexibility is the **only** axis you own outright. Four of six are dominated by LAT/MPC.

## Pivot verdict: pivot the CLAIM, not the codebase
There is **no strictly better bet** in ~2 months, but a strictly better **framing**.
- **→ LAT (2024/131, the strongest rival):** REJECT. The headline is already published (Argo et al., CCS 2024: 79.58 KB, ~0.35 s show / ~0.15 s verify, with C code); pivoting = reimplementing it, and your only wedge (signature-agility) is LAT's *weakest* axis.
- **→ FOLD:** REJECT (but cite as the rival most likely to subsume you in ~2 yrs and pre-empt "why not folding?"). PQ folding is <2 yrs old, makes no ZK claim, has no consumer benchmark, and **relocates rather than eliminates the field-mismatch** (Neo/SuperNeo work over Goldilocks, so a 192-bit PLUM field is still multi-limb-emulated); a credential *show* is folding's worst case (shallow).
- **→ UU:** REJECT the pivot, steal its baseline weapon. Its advantage (const-size, ms verify) is *lost* the moment you make it PQ (you fall into Fractal/TS).
- **→ F7 native AO-signature prover:** lowest cost (you own PLUM/Griffin/Cell 4); don't fully pivot, **promote Cell 4 to a first-class result**.

## The open / defensible niche
Least-occupied cell in the matrix: **{genuinely-ZK + end-to-end-PQ (no pairing wrap) +
late-bindable-φ + runs a PLUM-class predicate inside 24 GB}**. Every family hits at most
**3 of these 4**; **none has a measured artifact hitting all 4.** Your four-cell design
already isolates the right datapoints (Cell 4 = the PQ+ZK in-SNARK reference).

## The two measurements that are genuinely yours (no one across the six families has published them)
1. **Native-prover crossover** — native CAPSS/PLUM, or native-field Plonkish-Griffin (a
   199-bit prime fits in a ~255-bit scalar field, dissolving the multi-limb tax), **vs.**
   zkVM-with-precompile, same M5 Pro 24 GB. The empirical answer to "why pay the zkVM tax."
   Cell 4 supplies one endpoint; finish the line.
2. **Amortization crossover (the flexibility claim, quantified)** — shows-per-φ-change at
   which late-binding (pay arithmetization + audit *once*) beats per-relation
   re-arithmetization (pay it *per φ*). Low crossover (φ stable) → LAT/MPC win outright;
   high crossover (φ/signature churns, the broad goal's premise) → your niche is real.
   This is the generalized R_static, and the single most decision-relevant unrun experiment.

## De-forced goal (one sentence)
*Among post-quantum anonymous-credential constructions, the general-purpose zkVM+precompile
is the only family that late-binds the disclosure predicate, security parameter, credential
structure, AND the underlying signature as runtime guest data over a single proven relation;
this work quantifies the prover-time/memory cost of that crypto-agility on commodity hardware
against the relation-specific provers that are faster but rigid.*

## The contribution that is actually open (not "precompiles help")
1. **The artifact + its soundness argument**: the 192-bit-prime Griffin AIR. Exhaustive
   search found **no Griffin/AO-hash precompile over a ~192-bit application prime in any
   zkVM** (production precompiles cover SHA/Keccak/secp/ed25519/bn254/bls12-381 and Poseidon2
   over *small recursion fields* only). Novelty = the audited artifact, not the idea.
2. **The native-prover crossover** (measurement #1 above).
3. **The amortization crossover** (measurement #2 above) — the quantitative flexibility claim.
4. **An honest ZK/PQ trilemma statement**: SP1 default is neither ZK nor PQ; the Groth16 wrap
   buys ZK but loses PQ; RISC0's STARK-ZK is contested by its own advisory; the only
   end-to-end ZK+PQ in-family config is Cell 4 (Aurora). Name FOLD as the future subsumer.

## Prior-art ledger (highlights)
- **S-two "28-39× beats precompiles" (eprint 2026/532): VERIFIED but a CATEGORY ERROR** — it
  is a Keccak chain, general Cairo0 vs hand-tuned precompiles, *not* a large-field PQ workload;
  it says nothing about a 199-bit power-residue/Griffin load. **The fear was misplaced.**
- **Policharla 2023/414 (PQ Privacy Pass via PQ anon-creds, transparent STARK, no pairing):
  VERIFIED — the closest rival to your broad goal.** Fast (85-175 KB, 0.3-5 s) precisely by
  hand-rolling a STARK, giving up recompile-free flexibility. Must engage explicitly.
- **2024/131 (Practical PQ Sigs for Privacy, Argo et al. CCS'24): VERIFIED, LATTICE-native**
  (it was mis-supplied earlier as MPCitH). The strongest performance rival: 79.58 KB / ~0.5 s.
- **Pegasus 2025/1841: VERIFIED — first QROM proof for the power-residue-PRF family**,
  post-dating Loquat/PLUM. This is the QROM soft spot; cite it (resolves the C5 stale "QROM open").
- **S2morrow (StarkWare): VERIFIED** — Falcon/SPHINCS+ in Cairo, but reports on-chain gas, not
  laptop prover time/mem; does not kill your consumer-hardware-prover angle.
- **Kota ML-DSA-in-SP1: VERIFIED** — 5.6M cyc, 22 s, but **260 B Groth16/BN254 ⇒ NOT PQ**, and
  22 s was via managed "SP1 Network", not a confirmed 24 GB laptop. Distinguish on PQ + hardware.
- **CAPSS 2025/061: VERIFIED** — Anemoi 9-13.3 KB, 5-8× fewer constraints than Loquat; standalone
  signatures, never in a zkVM.
- **zk-creds (Rosenberg et al., S&P 2023): NOT independently verified this pass** — treat as
  unverified pending a primary check (it does exist in general knowledge).
- **Coconut, BBS+: not verified here AND disqualified by the PQ requirement** (pairing-based).
- **Novelty-protecting negative results** (state these in the thesis): (a) no public Loquat/PLUM
  inside a zkVM; (b) no Griffin/AO-hash precompile over a ~192-bit application prime in any zkVM;
  (c) no folding scheme bound to a credential disclosure predicate; (d) no PQ-folding consumer
  benchmark exists.

## Companion
`docs/thesis_revision_audit_20260605.md` (claim/prior-art audit + fix-list),
`docs/thesis_journey_2025-07_to_2026-06.md` (timeline), memory
`[[thesis-precompile-framing-forced]]`.
