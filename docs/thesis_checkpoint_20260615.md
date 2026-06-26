# Thesis + deck checkpoint — 2026-06-15

**Security-chapter spine (2026-06-16): `docs/security_spine_it_anonymity_20260616.md`** — the information-theoretic
anonymity asymmetry (anonymity = forever threat → info-theoretic hiding; unforgeability = bounded window →
computational-PQ OK), with a hard ledger (implemented/measured · peer-reviewed · unsettled · open-to-audit). Bounded
claim: the thesis CHARACTERIZES + SPECIFIES the masked-zk-STARK fix; it does NOT achieve/measure it. Grounded in the
two compass artifacts (Haböck–Kindi 2024/1037 info-theoretic ZK; the 2025 proximity-gaps disproof affecting PLUM's STIR).

**How to resume:** read **`docs/thesis_rescope_spine_20260615.md` FIRST** (the verified rescope spine: problem
statement, contributions, 15-beat outline, security sketch, feasibility, dangerous-claims), then this doc, then
`docs/sako_audits/log.md` (Audits 1–14). The big decision on this date: **rescope the thesis around post-quantum
zero-knowledge on consumer hardware; the fix DIRECTION is a native masked zk-STARK.**

**CORRECTED FEASIBILITY VERDICT (rescope-spine workflow, code-grounded):** a *working, measured* PQ-ZK proof of
PLUM-in-SP1 is **NOT feasible by 2026-07-20.** The veil→prove-path bridge is LARGE: veil masks a DENSE single-MLE
Basefold open, but SP1 Hypercube opens a JAGGED PCS and emits GKR/zerocheck/jagged-sumcheck transcript IN THE CLEAR
upstream (shard.rs:782-789) — real ZK needs the WHOLE shard verifier re-expressed through veil's compiler (+ veil
panics on multiple eval-claims/commitment, which multi-table shards trigger). veil = experimental/unaudited dead
code, zero prove-path callers. So the 7/20 deliverable is the MATH (characterization + security sketch + bounded
fix direction), not a built system. NEXT STEP = read 4 primary PDFs (QROM 2019/834, Aurora 2018/828, Basefold
2023/1705; CFS 1704.02086 done) to harden the security sketch. This SHARPENS §3d/§4 below.

---

## 1. State of the deck (presentation)
- Live file: `~/Downloads/修論進捗報告20260616_大塚.pptx`, **md5 `e3576e8e168ba022e4cf90e4124f6762`**, 26 slides.
- Durable backups in `/tmp/deck_backups/` (ephemeral — copy any you want to keep) and the durable
  `~/Downloads/修論進捗報告20260616_大塚_PRETUNE_backup_20260614.pptx`.
- Recent passes (all in `docs/sako_audits/log.md`):
  - Audit 11/12: tri-audit + confirmation; fixed the Griffin cycle-units contradiction (Cell 1 no-precompile
    7,082,608,888 cyc / 1052 perms ≈ 6.7M/perm; Cell 2 with-precompile 125,504,123 cyc; 56.4× cycle reduction).
  - Audit 13: REGISTER realignment — functional titles, agenda 1:1, S15 factual fix (per-row PROVEN, lookup OPEN).
  - Audit 14: CLARITY/STORY — S3 rebuilt (research-grounded, story in speaker notes), S10/S11/S12/S18 de-densed,
    S10 native limb-emulation visual (v2 stat-card design), S4 signpost line.
- **Deck is on hold.** Per the 2026-06-15 senior feedback, no more slide polish until the thesis is rescoped.

## 2. The crisis (2026-06-15 senior feedback) — verbatim sense
- The whole deck AND thesis feels **非常乱 (very disordered)**.
- **S3 makes dangerous claims**: the universal negative "no system gives all three today" + it promises
  PQ+private+on-device that S9 then fails to deliver (promise-then-fail).
- **S4** is too high-level: a motivational Venn with informal glosses, **no formal definitions**.
- **S9 "no zero-knowledge at the moment" is the biggest problem and breaks the thesis** — because for an
  *anonymous* credential, zero-knowledge IS the product; no ZK = not anonymous = not an anonymous credential.
- The topic is too big: **three problems at once** (flexible + post-quantum + private).

## 3. THE DECISION (2026-06-15)
**Pursue the real implementation to achieve zero-knowledge** (the user's call: without ZK the claim/defence
fails regardless of any other result). And **narrow scope 3 → 1**.

### 3a. Scope narrowing (3 → 1)
- **post-quantum** is given (adopt PLUM). **on a laptop** is the setting. **flexible** (update churn) is a
  *footprint*, not a wall-clock win → demote to a secondary finding.
- The ONE thesis question: *Can a general-purpose zkVM produce a post-quantum **zero-knowledge** proof of
  credential verification on consumer hardware — and does a native masked zk-STARK move the wall the standard
  (pairing-wrap) pipeline hits?*

### 3b. The ZK/OOM diagnosis — two failures, one root
The system misses PQ-ZK for two reasons that share ONE cause, the **pairing-SNARK wrap (Groth16/PLONK)**:
- it OOMs (~20 of 24 GB) — the wrap's recursion circuit is the memory hog;
- the wrap is pairing-based → **not post-quantum**.
Key leverage from our OWN data: the standalone succinct STARK **FITS** (32.5 min, no OOM); only the WRAP OOMs.
The wrap only buys ~200-byte on-chain succinctness — which a credential verified by a *verifier service*
(not a blockchain) does not need.

### 3c. The fix — native (masked) zk-STARK, skip the wrap
- A STARK (FRI IOP) is made zero-knowledge by **masking the witness**: add fresh random low-degree masking
  (random padding rows / a random multiple of the vanishing polynomial added to the quotient) so the bounded
  set of opened FRI query points is distributed independently of the witness.
- **Security lemma to prove (the math-major contribution):** ZK holds iff `#masking randomness ≥ #opened
  queries`; build a simulator that, knowing only the statement, samples consistent openings indistinguishable
  from real. **Soundness unchanged** (masking lives in the low-degree code / zerofier-multiple; FRI proximity
  still binds).
- **Post-quantum:** FRI rests on hash collision-resistance + proximity-gap soundness (no pairings); quantum
  costs a hash-size adjustment, not a redesign. Caveat = Fiat–Shamir in the QROM, which is the SAME open
  premise the thesis already carries (T4) — no new hole.
- **Memory:** masking adds a few columns, NOT a recursion circuit → peak RAM ≈ the base prover (already fits)
  + small overhead → should stay within 24 GB because the OOM-causing wrap is gone.

### 3d. Feasibility by 2026-07-20 (honest tiers)
- Tier A (ambitious): full masking implementation in the prover + measured-fits + ZK proof.
- Tier B (strong, realistic): the **theory** — masking construction for the PLUM-verify STARK + rigorous
  ZK/soundness proof + memory analysis — plus a PoC or a careful estimate. Self-contained math thesis.
- Tier C (safe fallback): honest reframe — the wall, the single-root diagnosis, the zk-STARK direction analyzed.
- Lighter alternatives are a dead end on this timeline (BBS not PQ; lattice anon-creds = tens-of-KB proofs,
  single-message) — this reinforces zk-STARK as the clean route.

## 4. Implementation plan (next actions)
1. **CRITICAL FIRST CHECK:** does SP1 / its Plonky3 backend (or RISC Zero) already expose a native
   zero-knowledge STARK mode (e.g., a `zero_knowledge` config in Plonky2/3)? If YES → enable + prove + measure.
   If NO → adding masking IS the contribution. Investigate `submodules/sp1` + the Plonky3 dependency.
   (RISC Zero "blinds" but, per our finding, has no FORMAL ZK guarantee.)
2. If a ZK mode exists: enable it on the PLUM-verify guest; measure prove time + peak RAM at λ=80; confirm it
   stays within 24 GB and produces a PQ-ZK (non-wrapped) proof.
3. If not: implement witness masking on the trace/quotient; write the ZK simulator + soundness argument.
4. Re-run the verified research workflow (SP1/RISC0 ZK state, masking math, memory, alternatives) when the
   Anthropic 529 overload clears — script at
   `…/workflows/scripts/pqzk-on-laptop-research-wf_2ab87167-ca8.js` (resume via `scriptPath`).

## 5. Deck fixes pending the rescope (do AFTER the thesis question is settled)
- S3: drop the universal negative + promise-then-fail; motivate the QUESTION, not the answer.
- S4: add FORMAL definitions (private = ZK simulator / unlinkability game; PQ = QPT adversary). Keep the Venn
  as one intuition slide only.
- S9: reframe from "wall we hit" to "obstruction diagnosed to one cause (the pairing wrap) and attacked with a
  masked zk-STARK."
- Demote "flexible"/update-churn from a headline trilemma axis to a side-finding throughout.

## 6. Verified measurement anchors (do not drift)
- PLUM-verify + precompile (SP1, λ=80): 32.5 min prove, succinct, NOT ZK. SHA-3 control: 13.3 min.
- Cell 1 (no precompile) 7,082,608,888 execute cyc; Cell 2 (precompile) 125,504,123 cyc; 56.4× (docs/four_scheme_benchmark.md).
- BDEC CreGen ~27 min; ShowCre k=1 ~40 min (SP1). Aurora proxy (Loquat-Fp127): 3.76 min zk-disabled core,
  ~22 min zk-enabled PQ-ZK reference; 44–64 min SP1 same-scheme.
- Security premises: T1 lookup-binding (assumed); T2 Griffin AIR (per-row PROVEN, lookup-borne OPEN);
  T3 black-box PRF; T4 PLUM simulator / QROM (open). Griffin 14-round margin unvalidated vs FreeLunch (CRYPTO 2024).

## 7. Infra note (2026-06-15)
The multi-agent research workflow failed twice on server-side `API Error: 529 Overloaded` (zero data); the Bash
safety classifier was also briefly unavailable. Transient Anthropic capacity, unrelated to the work. Retry the
research workflow when capacity returns.

## 8. Implementation investigation — findings (2026-06-15, shell-verified)
SP1 submodule rev `8bf0248bc` (the thesis's own Griffin-Fp192 fork).
- The thesis builds on **SP1 Hypercube** (`crates/prover` deps: `slop-basefold`, `sp1-hypercube`, `slop-jagged`,
  `slop-multilinear`) — the newer multilinear / Basefold prover, NOT the old Plonky3 `p3-uni-stark` path
  (p3-uni-stark in cargo is leftover, not the main prove path).
- **`slop/crates/veil`** ("Verifiable Encapsulation of Interactive proofs with Low overhead") is a **transparent,
  hash-based (Basefold + sumcheck + Merkle, KoalaBear) ZERO-KNOWLEDGE PCS** — exposes `ZkPcsProver` /
  `ZkPcsVerifier` / `ZkProof`. **Post-quantum** (384 hash refs, 0 pairing refs in its src). `zk/mask_counter.rs`
  implements the masking-randomness bookkeeping: `compute_mask_length` counts transcript reads = the
  "#masking ≥ #opened" condition. So the witness-masking ZK mechanism is ALREADY IMPLEMENTED in SP1's own stack.
  → This VALIDATES the rescope direction: Succinct's own next-gen stack does PQ-ZK via masking, not a pairing wrap.
- **GAP:** veil's ZkPcs is NOT wired into the Hypercube machine prover (no non-slop crate uses `ZkPcsProver`; no
  ZK toggle in the `sp1-sdk` 6.0.1 `prove()` API). `veil/lib.rs` carries `#![allow(dead_code)]` → likely
  experimental / partial. So default `prove()` stays non-ZK (matches the measured finding).
- **THE PATH (thesis contribution):** route the Hypercube prover's PCS openings through veil's masked ZkPcs
  (same slop-basefold substrate) to produce a transparent PQ-ZK proof of PLUM-verify — instead of the
  Groth16/PLONK pairing wrap. PQ (Basefold/hash), memory-bounded (masking, no recursion-to-pairing),
  security-preserving (masking on the openings; soundness unchanged).
- **veil IS functional (step-1 confirmed, code-level):** ~1300 lines real prover+verifier in `zk/inner` +
  dot_product/hadamard_product/stacked_pcs subprotocols; NO stub markers (no todo!/unimplemented!/unreachable!);
  masking randomness threaded as a `CryptoRng`. The example `slop/crates/veil/examples/mle_eval.rs` is a complete
  commit→prove→verify round-trip on the ZK backend (`vctx.verify().expect("zk verification failed")` →
  "ZK backend: PASSED"), over KoalaBear + Poseidon2KoalaBear16 Merkle (transparent/PQ). It is a ZK **multilinear-
  evaluation PCS** (commit MLE, open at a point, prove the eval in ZK via masking) — exactly the primitive the
  Hypercube prover needs for its MLE-eval openings. NOT YET RUN (needs a ~min build) and NOT wired into the guest
  prove path (dead_code allowed; no external callers). 
- **NEXT (verify):** run `cargo run --release -p slop-veil --example mle_eval` to confirm PASS + get prover time +
  mask length; find the Hypercube/jagged MLE-opening site to bridge veil's ZkPcs in; measure peak RAM. Web-verify
  SP1's veil/ZK roadmap when the 529 overload clears.
- **THREADING:** the thesis prove is MULTI-threaded (rayon). Tuned config `RAYON_NUM_THREADS=8` (32.5-min figure);
  headroom probe 12; low-memory config 4. Threads ↔ memory are coupled (more threads = more in-flight trace RAM),
  so thread count is one of the OOM-avoidance knobs alongside SHARD_SIZE=2^22.
- **Feasibility by 7/20:** full end-to-end wiring is ambitious (prover-internals surgery in a large codebase).
  Realistic strong contribution (Tier B): analyze veil's masking construction, prove ZK + soundness + PQ for the
  PLUM-verify openings, a component-level PoC, and a memory estimate.
