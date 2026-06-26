# Rescoped thesis spine (2026-06-15, verified)

Produced by the `rescope-spine` workflow (code-grounded read of SP1/veil + web sources + adversarial
verification of every load-bearing claim). Companion to `docs/thesis_checkpoint_20260615.md`.

## Headline feasibility verdict (READ FIRST)
A **working, measured post-quantum zero-knowledge proof of PLUM-in-SP1 is NOT feasible by 2026-07-20.** The
blocker is not effort — it is a large, unbuilt integration (see "bridge" below). **What IS feasible and
defensible by 7/20:** (1) the *characterization* of the zero-knowledge obstruction, backed by existing
measurements; (2) the *security sketch* (bounded-query masking → ZK + soundness + PQ-via-QROM), once the 4 primary
PDFs are read; (3) a precise delimitation of the veil→jagged *bridge* as the open engineering gap, framed relative
to Succinct's own VEIL effort. The thesis shape = **obstruction-characterization + principled-fix-direction**,
which is a recognized legitimate form when the obstruction is measured and the mechanism explained (both hold).

## Problem statement (defensible, no overclaims)
A deployable anonymous credential that survives quantum adversaries needs two things at once on the hardware a
user actually owns: a post-quantum signature whose verification can be proven, and a proof of that verification
that is zero-knowledge (revealing nothing about which credential/signature was checked). This thesis fixes the PQ
signature as PLUM (hash/PRF-based, verified inside the BDEC framework) and asks whether a general-purpose zkVM
(SP1, on a Hypercube/Basefold/sumcheck prover; RISC Zero as a second substrate) can produce such a zero-knowledge
proof on consumer hardware — a single 24 GB Apple M5 Pro laptop. The answer is: not yet, and **the binding
constraint is zero-knowledge, not raw proving time.** The affordable proof (the standalone PLUM-verify succinct
STARK receipt) is NOT zero-knowledge (per Succinct's own security docs); the only ZK wraps the toolchain exposes
are pairing-based (Groth16/PLONK over BN254), hence not post-quantum, and the PLONK wrap exhausts memory at ~20 GB
of 24 GB on this workload. So the obstruction is structural: the affordable proof lacks the security property the
application requires, and the toolchain's route to that property abandons post-quantumness and, on this workload,
the memory budget. The thesis characterizes this obstruction, situates the precompile work as the feasibility
prerequisite that makes the base proof runnable (32.5 min, memory-tuned), and identifies a principled fix
direction — a native hash-based masked zk-STARK that adds ZK by blinding rather than a pairing wrap. It does NOT
claim that fix is built or measured. Bounded: consumer hardware (a 24 GB laptop), not edge devices; an obstruction
characterized by measurement, not a quantified assurance cost.

## Contributions
1. **A PLUM-instantiated PQ-credential artifact + frontier measurements** on consumer hardware. PLUM↔Loquat in
   BDEC CreGen/ShowCre (execute mode); standalone PLUM-verify in prove mode on SP1: 32.5 min, ~19.5 GB peak
   (81.3% of 24 GB), verified, λ=80, documented reduced-memory config (defaults OOM via macOS Jetsam ~3 min).
   First standalone PLUM-verify prove-mode measurement inside a general-purpose zkVM.
2. **The zero-knowledge obstruction as the central finding** (its own treatment). Affordable proof = succinct
   STARK, not ZK; only ZK wraps are pairing-based (not PQ); PLONK wrap OOMs at ~20 GB of 24 GB on this workload.
   RISC Zero: blinded, no formal ZK guarantee (vendor docs verbatim). PQ-ZK unreached, part resource limit / part
   toolchain fact more memory does not move.
3. **The precompile as a supporting feasibility instrument + a falsified prediction.** Griffin-Fp192 precompile
   makes the OOM base proof finite (32.5 min vs precompile-free OOM ~1m45s); but proves SLOWER than a software
   SHA-3 control at matched λ=80 (sign robust May+June; magnitude 1.10×–2.45×). Trace-area cost model postdicts
   both the recovery and the inversion sign.
4. **A grounded, honestly-bounded fix direction: a native masked zk-STARK.** ZK via additive bounded-query masking
   (hash-based, KoalaBear-native, no pairings), not a pairing wrap. Exactly such a mechanism (Succinct's veil /
   VEIL, eprint 2026/683) is present in the SP1 tree as experimental, unaudited, not-wired-in code on the same
   KoalaBear/Basefold substrate. Security sketch + a precise statement of what stands between candidate and a
   working PQ-ZK proof of PLUM-in-SP1: the bridge is large and unbuilt; nothing measured.
5. **Update churn as a measured dimension** (DEMOTED to secondary). zkVM flexibility advantage absent in wall-clock
   vs non-preprocessing Aurora (~0.3 s recompile); survives only vs a preprocessing baseline (Fractal, indexing
   OOMs at BDEC size) and as a re-audit footprint COUNT (not a measured effort figure).

## Deck outline (15 beats; ZK load-bearing, precompile supporting; honors senior's skeleton)
1. Title — "PQ ZK proof of credential verification on consumer hardware: characterizing the ZK wall for
   PLUM-in-zkVM + a hash-based masking fix direction." Frame: binding constraint is ZK, not proving time.
2. The need (external, not BDEC-internal) — privacy-preserving auth surviving quantum, on a laptop; why PQ, why ZK
   is non-negotiable. BDEC = the use case, not the motivation.
3. Goal (Sako A→B) — produce a PQ + ZK proof that PLUM verification holds, on a 24 GB laptop, inside a zkVM. State
   the TWO simultaneous requirements; foreshadow the second is the wall.
4. Background: zkVM as the proving substrate — RISC-V guest + STARK prover; SP1 Hypercube (sumcheck + Jagged PCS
   over KoalaBear) + RISC Zero. Define ZK vs succinctness as DISTINCT up front.
5. Background: PLUM + BDEC setting — PLUM (hash/PRF + STIR, 192-bit prime) replaces Loquat (resolves protocol-level
   mismatch A); CreGen/ShowCre relations. Tight setup.
6. Eval BEFORE — base proof barely runs: precompile-free standalone PLUM-verify OOMs ~1m45s. A feasibility problem,
   distinct from the ZK problem.
7. Problem of the zkVM, part 1: the field mismatch — 192-bit over 31-bit KoalaBear limbs (~7/operand); Griffin
   algebraic hash dominates (~91% hash share). Why the base proof OOMs. Sets up the precompile.
8. **Problem of the zkVM, part 2: zero-knowledge (LOAD-BEARING).** Affordable SP1 proof not ZK (docs verbatim); ZK
   wraps Groth16/PLONK over BN254 = not PQ. Succinct-but-not-ZK vs ZK-but-not-PQ. RISC Zero blinded, no formal ZK.
   The zero-knowledge obstruction. Thesis center of gravity.
9. Precompile construction (supporting) — Griffin-Fp192 AIR + UINT256_MUL/sys_bigint. The FEASIBILITY prerequisite,
   not the headline. AIR adds trusted component (premise T2). Feasibility evidence (Plonky3 Poseidon2, Zirgen).
10. Eval AFTER, part 1: feasibility recovered, prediction falsified — 32.5 min, ~19.5 GB. But SLOWER than SHA-3
    control (the inversion). Trace-area model postdicts both. A falsified prediction reported as a finding.
11. Eval AFTER, part 2: the ZK obstruction is real and measured — PLONK wrap OOMs ~20 GB of 24 GB on this workload
    (workload-specific, not universal). PQ-ZK unreached. eval-after honestly shows an obstruction, not a finished zkp.
12. Fix direction: native masked zk-STARK (CANDIDATE, not result) — add ZK by additive bounded-query masking
    (hash-based, KoalaBear, no pairings). veil (eprint 2026/683) in the SP1 tree, working commit→prove→verify
    (mle_eval.rs). HEDGE: experimental, unaudited, dead code; masks dense single-MLE while SP1 opens a JAGGED PCS
    with GKR/zerocheck in the clear; panics on multiple claims/commitment; bridge large + unbuilt; frame RELATIVE
    to VEIL. Nothing measured.
13. Security sketch (masked path) — bounded-query additive masking (Chiesa-Forbes-Spooner): encode witness with a
    random degree-raised-by-b polynomial → any b evals outside the interpolating set uniform → perfect ZK vs ≤b
    queries; mask itself low-degree-tested → soundness unchanged; residual = one simulatable eval. PQ rests on the
    QROM compiler (Chiesa-Manohar-Spooner 2019/834), NOT classical-ROM FS. Hedges: bounded-query; HV-statistical
    (rlc_coeff∉{0,-1}); QROM = premise T4; the Basefold/veil mask-size condition is the genuine open gap.
14. Discussion: update churn + decision framework (secondary) — flexibility advantage absent vs non-preprocessing
    Aurora (~0.3 s); survives vs preprocessing (Fractal OOMs at BDEC size) + as a footprint COUNT. NOT a
    "prohibitive assurance cost" claim.
15. Conclusion + feasibility — wall = ZK, located: succinct-not-ZK vs ZK-not-PQ-and-OOM. Precompile recovers
    feasibility, no speedup (inversion). Fix = hash-based masked zk-STARK, validated as a direction by veil/VEIL
    but unbuilt/unmeasured. By 7/20: characterization + security sketch + bounded fix direction, NOT a working
    PQ-ZK proof. State what is measured / candidate / open (the Basefold mask-size condition; the large veil→jagged bridge).

## Security argument sketch (the math — the actual 7/20 deliverable)
Argue masking the base PLUM-in-SP1 STARK yields (a) ZK, (b) preserved soundness, (c) PQ, at additive (not
pairing-multiplicative) overhead. Grounded in Chiesa-Forbes-Spooner (zero-knowledge sumcheck, arXiv 1704.02086,
read directly) + the in-repo veil mechanism (read directly); remaining cites corroborated at snippet level only and
MUST be verified against primary PDFs before committing.
(1) **ZK by bounded-query masking.** Encode the low-degree witness with a RANDOM polynomial of degree |H|−1+b
agreeing on H; any b evaluations outside H are uniform & independent → perfect ZK vs a ≤b-query verifier. In
sumcheck: prover sends random low-degree mask R, verifier sends ρ, sumcheck runs on ρ·F+R; residual leakage = one
evaluation of F, simulatable. veil realises this: additive transcript masking value+mask[i] before any FS
(inner/prover.rs:318-332), + EF::D mask columns + query_count padding rows per MLE before Basefold
(stacked_pcs/prover.rs:136-158). **Crux:** added degree/redundancy ≥ number of opened evaluations across all
Basefold/FRI rounds, else openings over-determine the encoding and leak.
(2) **Soundness preserved** — ZK layered on an unchanged proximity argument; mask R itself low-degree/proximity
tested; random combiner ρ keeps a false claim false on ρ·F+R w.h.p. Code: failures documented as "break ZK but not
soundness" (inner/prover.rs:586-599).
(3) **PQ at additive overhead** — additive KoalaBear blinding + Poseidon2 Merkle + Basefold; no pairings/curves.
Qualitatively distinct from Groth16/PLONK recursive re-proving in a BN254 pairing circuit (not PQ, OOMs). State
the contrast QUALITATIVELY (not a literal additive-vs-multiplicative theorem). PQ rests on the QROM compiler
(Chiesa-Manohar-Spooner 2019/834), which establishes QROM security AND ZK-preservation — DIFFERENT from
classical-ROM FS of FRI (Block 2023/1071); classical ROM ⇏ QROM (Don-Fehr-Majenz-Schaffner 2019/190).
**Required hedges:** bounded-query (never unbounded); veil = HV STATISTICAL ZK only (rlc_coeff∉{0,-1};
one-claim-per-commitment else PANIC — real SP1 shards prove many claims/shard → live integration hazard); PQ is
QROM-conditional (premise T4); FRI/STARK quotient-and-DEEP masking is a known implementation-pitfall area
(Haböck-Al Kindi 2024/1037); the exact Basefold/veil mask-size condition on SP1's jagged path is the one genuinely
unverified gap.

## The bridge (why a working PQ-ZK proof is not a 7/20 deliverable)
SP1 Hypercube opens its PCS at hypercube/src/prover/shard.rs:771-779 (JaggedProver); dense Basefold open at
jagged/prover.rs:300-310. veil's ZkBasefoldProver mirrors that WITH masking, same KoalaBear substrate — but: veil
masks a DENSE single-MLE open and has no jagged layer (slop-jagged is a dev-dependency only); the shard proof emits
opened_values, logup_gkr_proof, zerocheck_proof IN THE CLEAR upstream of any veil masking (shard.rs:782-789). Real
ZK requires re-expressing the WHOLE shard verifier (GKR + zerocheck + jagged sumcheck) through veil's compiler, plus
resolving veil's panic on multiple eval claims per commitment (multi-table shards trigger it). Effort = LARGE,
unbuilt. veil = experimental/unaudited dead code, zero prove-path callers.

## NEXT STEP (math, not code — the 7/20 deliverable)
Read 4 primary PDFs to harden the security sketch BEFORE any coding: Chiesa-Manohar-Spooner 2019/834 (QROM + ZK
preservation), Aurora 2018/828 (the |H|+b bounded-query constant), Basefold 2023/1705 (is zk-Basefold built-in or
follow-up); CFS 1704.02086 already read. Then instrument veil's `compute_mask_length` on mle_eval.rs to confirm the
mask length = (num_data per claim + EF::D mask cols) matches the bounded-independence requirement b ≥ total opened
evaluations across Basefold rounds. Read-and-verify only; does NOT touch the SP1 prove path; supplies the one
genuinely unverified element of the sketch. Jagged-bridge prototyping is explicitly OUT OF SCOPE for 7/20.

## Dangerous claims to AVOID (the senior's exact concern)
- NOT "edge devices"/IoT/phones — only a 24 GB M5 Pro laptop was tested. Use "consumer hardware / a 24 GB laptop".
- NOT "prohibitive assurance costs" or any quantified assurance/re-audit cost — effort was never measured; only a
  footprint COUNT. The 0.3 s is wall-clock recompile, a different axis. Keep flexibility QUALITATIVE.
- NOT "veil is a functional prove-path-compatible PQ-ZK PCS / drop-in" — say "a candidate masking mechanism present
  in the SP1 tree on the same KoalaBear/Basefold substrate", framed RELATIVE to Succinct's VEIL.
- NOT any speed/memory figure for a masked/ZK path — nothing built/run. The ~3%/22%/12% overhead is vendor-blog
  only (eprint 2026/683 PDF returned 403); attribute as vendor-stated, unmeasured-on-our-workload.
- NOT "the pairing wrap requires ~24 GB" universally — Succinct lists single gen at "16GB+"; state OOM as
  workload-specific ("PLONK wrap of standalone PLUM-verify OOMs at ~20 GB of 24 GB on our workload").
- NOT "perfect"/"unconditional" ZK — HV STATISTICAL, bounded-query.
- NOT conflate classical-ROM FS (2023/1071) with the QROM ZK result (2019/834); classical ROM ⇏ QROM.
- NOT "additive vs multiplicative overhead" as a literal theorem — keep the contrast qualitative.
- NOT "base proof comfortably fits 24 GB" — 81%-tight (~19.5 GB), bought by 4× memory tuning; defaults OOM ~3 min.
- NOT label the outer/circuit-SNARK "Aurora/STIR" as PLUM's prover — STIR is PLUM's OWN inner IOP; the outer proxy
  is Loquat-BDEC in Aurora/Fp127.

## Open uncertainties (carry, do not paper over)
- Exact Basefold/veil mask-size-vs-query condition on SP1's jagged path — unverified at primary level (the genuine gap).
- eprint 2026/683 (VEIL) not read at primary level (PDF 403); overhead figures + "plausibly PQ" vendor-stated only.
- Whether masked KoalaBear Basefold fits 24 GB/time for PLUM-in-SP1 — entirely unmeasured.
- Size of the veil→jagged bridge — assessed "large", not scoped/attempted.
- QROM ZK-preservation (2019/834) + Aurora constant (2018/828) — snippet-level only; read before committing.
- 0.3 s R_static and ~20 GB OOM are Loquat-BDEC/Fp127/zk=false proxies, not PLUM (PLUM-in-Aurora not runnable).
- CreGen succinct-prove internal-verifier anomaly (under diagnosis) — no claim rests on it.
- zk-Basefold built-in vs follow-up — unresolved; affects framing.
- Lighter PQ-unlinkable alternatives (lattice ACs, KVAC) — survey-level only; research-grade, not an obvious faster route.
