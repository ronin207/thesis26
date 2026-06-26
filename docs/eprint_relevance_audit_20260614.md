# ePrint relevance audit (Sako reading rigor) — 2026-06-14

Deep reads (local PDF or fetched) of 11 candidate papers, judged against the thesis
contribution. Source: wf_63d3bab6. **Bottom line: the thesis is NOT scooped, but the BROAD
claim is. Defend on the substrate axis.**

## THREE high novelty-threats (must cite AND distinguish)

### Argo et al., "Practical Post-Quantum Signatures for Privacy", eprint 2024/131 (CCS 2024) — the real one
- **What it actually does:** the FIRST full implementation of a lattice ZK PQ anonymous
  credential; MEASURED on a laptop, **sub-second** (issuance ~221–400 ms, showing ~355–500 ms),
  at **λ=128**, zero-knowledge (HVZK), under standard M-SIS/M-LWE. Credential proof <80 KB.
- **Why it threatens:** it REFUTES "is PQ anon-cred even feasible on a laptop?" (yes, fast) AND
  "competitors only report sizes" (they implemented + measured). Both predate the thesis.
- **How the thesis is distinct (the ONE axis):** Argo hand-builds a **bespoke** lattice ZK
  prover (LNP22/ABDLOP in C/FLINT) welded to one signature — **no general-purpose substrate,
  no field-mismatch tax, not flexible.** It is the existence proof that the dual obstruction is
  escapable *only by abandoning generality*. → Cite Argo as the bespoke-lattice contrast that
  shows the obstruction is a property of the **general-purpose toolchain**, not of cryptography.

### Policharla et al., "Post-Quantum Privacy Pass via PQ Anonymous Credentials", eprint 2023/414
- **What it actually does:** self-claims "first implementation of a PQ anonymous credential";
  measured prover **0.3–5 s** on a 2019 MacBook, single-threaded, zkDilithium over a STARK.
- **How the thesis is distinct (verified PDF p.9 verbatim):** "the Winterfell library does not
  support computing proofs with zero-knowledge… a ZK version will be **very close** to plain
  STARK." → **Their measured numbers are NOT zero-knowledge** — ZK is only *projected*. The
  thesis measures the ZK point they skipped. Also: Dilithium (not Legendre/power-residue PRF),
  single substrate. "115 bits" = conjectured STARK *proof* soundness, NOT credential security.

### CAPSS (Feneuil, Rivain), eprint 2025/061
- **What it actually does:** generic framework for SNARK-friendly PQ signatures from AO
  permutations (incl. **Griffin**), **5–8× fewer R1CS than Loquat**, with an anonymous-credential
  application and MEASURED **Aurora** proving.
- **How the thesis is distinct:** **no zkVM, no consumer hardware, no wall-clock on any substrate
  but Aurora.** Owns the constraint-count corner; the thesis owns the cross-substrate wall-clock
  wall + the Griffin-Fp192 zkVM precompile + the dual obstruction. CAVEAT: 5–8× is constraint
  count at 128-bit, CAPSS-Anemoi vs **Loquat** (not vs PLUM, not its Griffin instance) — never
  let prose imply "CAPSS beats PLUM" or that it is a prover-time advantage.

## Foundations (cite as what we build on; low threat)
- Loquat 2024/868 — the scheme family. GUARD: don't quote its SHA headline (5.04 s / 0.21 s /
  57 KB) as the algebraic-hash cost; the Griffin config is 105 s sign / 11 s verify (Table 3).
- PLUM (978-981-95-2961-2) — the scheme under measurement.
- SoK zkVM 2026/525 — the substrate taxonomy (ISA/VM/proving). CAVEAT: PDF 403; cite no number
  from it without opening the tables (the SP1 1.8MB / RISC0 209KB figures were blog-blended).
- Verifying Jolt Lookup Semantics 2024/1841 — the exemplar for the open T2 (AIR soundness) premise.
- Aurora 2018/828 + Fractal 2019/1076 — the static-SNARK baseline + preprocessing contrast.

## Adjacent (cite for context; low/none threat)
- BLNS 2023/560 — size-optimized lattice anon-cred, NO implementation/timing. "Practical" = size.
- LaZer 2024/1846 — native-lattice tooling, sub-second ZK showing on x86 (AVX-512, not Apple
  silicon); its succinct LaBRADOR path is NOT ZK. MEDIUM threat, dissolves on the substrate axis.
- Anonymous Counting Tokens 2023/320 — CLASSICAL (not PQ); rejects the SNARK route.
- Dutto et al. 2022/1297 — conceptual "toward" SSI paper, no benchmarks.
- Polynomial IOPs for Memory Consistency 2023/1555 — orthogonal zkVM internals; one-line aside.

## The biggest novelty risk + the defense
- **Risk:** Argo + Policharla together make an unqualified "first measured prover-time wall for a
  full ZK PQ anonymous credential on consumer hardware" claim **FALSE** on a plain reading. A
  reviewer reading only their abstracts sees the headline as preempted.
- **The thesis prose is ALREADY scoped correctly** (02-related.tex line 56, 01-intro.tex line 69):
  "the first reported execution-and-proving study of an algebraic-hash PQ anonymous credential
  inside a **general-purpose zkVM**." The danger is ONLY if a broader phrasing leaks into the
  abstract or the talk. (The broad phrasing came from the audit brief, NOT the thesis.)
- **Defense (the defensible claim):** "the first measured **cross-substrate** (general-purpose
  zkVM vs static SNARK circuit) proving-cost study of an **unmodified** algebraic-hash /
  Legendre-power-residue-PRF post-quantum anonymous-credential predicate on consumer hardware,
  reporting the **dual obstruction**." All three high-threat papers either sidestep the dual
  obstruction (Argo, CAPSS) or leave it unmeasured (Policharla). The dual obstruction is the
  single most defensible contribution.

## Surgical thesis edits the audit prescribes
1. Move the precise substrate-scoped sentence (02-related.tex:56) into the ABSTRACT; never use the
   broad "first measured wall" phrasing anywhere.
2. 02-related.tex:17 (Policharla): ADD that their measured numbers are non-ZK projections.
3. 02-related.tex:56 (Argo): explicitly acknowledge it as a prior MEASURED full-ZK PQ-anon-cred
   wall, escaped via a bespoke (non-general-purpose) prover.
4. Every numeric head-to-head must hold the security axis fixed (thesis λ=80 vs Argo 128 /
   Policharla 115) and must NOT frame the thesis's slower wall as "proof of impracticality."

## Related-work synthesis paragraph (ready to land in 02-related.tex)
> The closest prior work establishes that a measured, full, zero-knowledge, post-quantum
> anonymous credential on a laptop already exists — Argo et al. (CCS 2024) report sub-second
> issuance and showing at 128-bit — but it is delivered by a bespoke lattice ZK proof system
> (LNP22/ABDLOP) hand-co-designed with the signature, with no general-purpose substrate and
> hence no field-mismatch tax. Policharla et al. (2023) likewise measure a PQ anonymous-credential
> prover on a laptop (0.3–5 s), but their published numbers are plain, non-zero-knowledge STARKs
> over a STARK-friendly Dilithium variant — the library (Winterfell) does not support ZK, and a
> ZK version is only projected. CAPSS (2025) owns the SNARK-friendly PQ-signature corner, beating
> Loquat 5–8× on R1CS with Griffin among its instantiations and a measured-Aurora anon-cred
> application, yet never enters a general-purpose zkVM or consumer hardware. None runs an
> unmodified predicate inside a general-purpose zkVM, compares it against a static SNARK circuit
> on the same predicate, or reports the point at which zero-knowledge and post-quantumness must
> hold simultaneously on a 24 GB laptop. That is the wall this thesis locates.
