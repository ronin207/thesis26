# Thesis revision audit — merged (2026-06-05)

Synthesis of two adversarial multi-agent passes run 2026-06-05: the **zkVM-literature
gap audit** (`wpu2v20c9`, 14 agents, 9 papers) and the **claim-by-claim prior-art
audit** (`wffvpwhdl`, 24 agents, 11 claim clusters). Both treated the thesis +
NotebookLM as motivated reasoning and were instructed to commit to verdicts.

> **Caveat — verify before citing.** The prior-art hits below were found by agents via
> web/ePrint search. The audit caught *its own* brief's factual error (it wrongly said
> Loquat's benchmark was on a Xeon W-2155; the paper actually uses M1 Max 32 GB,
> single-thread, Table 3). So treat every external citation here as a **lead to confirm
> against the primary source** before it enters the thesis — especially the load-bearing
> ones (S2morrow, Policharla 2023/414, zk-creds S&P 2023, Pegasus 2025/1841, Kota
> Dilithium-in-SP1, Neo 2025/294, Haböck–Al Kindi 2024/1037, CertiPlonk).

---

## 0. Bottom line

**The "precompile is the contribution" framing is forced — drop it as the headline.**
Three independent lines converge: (1) the technique is prior art (Plonky3 ships
Poseidon2/Rescue/Monolith AIR chips *inside SP1's own stack*; Griffin is natively a
large-prime hash, eprint 2022/403); (2) the thesis's own control refutes it — the
bespoke Griffin-Fp192 precompile is **1.13× slower in cycles and 2.45× slower in
prove-wall than software SHA-3** (Cell 2 32.5 min vs Cell 3 13.3 min) at claimed
matched λ=80; (3) the precompile's headline effect was never demonstrated on the actual
target — the 32.5 min is *standalone* PLUM-verify on SP1; no run combines the bespoke
AIR with a BDEC relation, and the BDEC proves either rejected (CreGen) or were never
attempted (ShowCre). Your own text already concedes this (05-system L3 "instrument of
the measurement, not the contribution"; 02-related L44 "sits within this pattern").

**The defensible thesis (lead with A, pair with B):**
> *A quantified measurement of the field-mismatch ("agility") tax for a PQ anonymous
> credential whose signature uses a 192/199-bit prime + algebraic hash, run inside a
> general-purpose zkVM — including the counter-intuitive finding that a bespoke
> algebraic-hash precompile does not beat a software standard hash (SHA-3) in this
> regime — together with a measured dual obstruction: along the deployed RISC0/SP1
> route there is no realizable PQ-sound zero-knowledge path on 24 GB consumer hardware
> (the default receipt is not ZK; the only ZK wrap is pairing-based, forfeiting PQ
> anonymity; the PQ-safe alternative OOMs). The custom precompile is the instrument that
> made the measurement possible, not the contribution.*

This is exactly Sako's "problem → asset → measure the cost," and it is the version that
survives prior art.

---

## 1. Novelty × correctness (merged verdicts)

| Cluster | Novelty | Deciding prior work (verify) | Status |
|---|---|---|---|
| C1 Precompile-for-algebraic-hash | technique already-done | Plonky3 Poseidon2/Rescue/Monolith AIR; Griffin 2022/403 | Narrow "no SP1 chip for Griffin over a 199-bit prime" SAFE; technique-as-contribution ALREADY-DONE |
| C2 First PQ-sig/anon-cred verify in a general-purpose zkVM | incremental | **S2morrow** (Falcon+SPHINCS+ in Cairo); **Kota Dilithium-ZK in SP1** | execute-mode narrow claim SAFE *if fenced*; **"prove-mode costs for BDEC" UNSUPPORTED (no BDEC prove ever succeeded)**; unqualified first-ness CONTRADICTED |
| C3 Agility/field-mismatch tax | mechanism already-done | SoK:zkVM 2026/525 §3/§4.3; Gassmann 2508.17518; foreign-field ~500× | quantification at *this* granularity SAFE; **FMT metric is unit-incoherent (cycles ÷ R1CS rows)** — broken as written |
| C4 Dual obstruction (STARK≠ZK + pairing-wrap≠PQ) | components published | SoK 2026/525 §2.1+Table1; **Policharla 2023/414** (PQ anon-cred on transparent STARK, no pairing) | "novel conjunction" CONTRADICTED; **toolchain-instantiation + resource-frontier framing SAFE** |
| C5 BDEC/PLUM security preservation | template already-done | **zk-creds, Rosenberg et al. S&P 2023** | theorem-as-novelty ALREADY-DONE; "generic over EU-CMA" UNVERIFIED (BDEC paywalled); **QPT header UNSUPPORTED (classical-ROM only); QROM-open claim STALE** (Pegasus 2025/1841) |
| C6 Update churn / rigidity | concept anticipated | NIST crypto-agility; 2022/1297 | "literature doesn't capture this" CONTRADICTED; **zero-churn-zkVM CONTRADICTED by own shipped AIR** (a hash/field change re-audits the precompile → N_circ≥1) |
| C7 Griffin-AIR soundness vs CreGen rejection | not novel | **Arguzz 2509.10819** ($50k RISC0 missing-constraint bug = cause iii) | **load-bearing internal contradiction (below); security Theorem premise possibly FALSE, not merely open** |
| C8 S-two/Circle-STARK/folding obsoletes precompile | refuted worry | SoK 2026/525; Neo 2025/294 | precompile NOT obsoleted (fields trend *smaller* → emulation persists; folding amortizes recursion, not per-step foreign-field cost; EC-folding is non-PQ). But thesis must *show why alternatives lose* |
| C9 Small-field STARK soundness floor | re-statement | Fenzi–Sanso 2025/2197 | floor-as-finding already-done; **miscast: it hits ε_KS (unforgeability), NOT anonymity**; don't bundle the Fp127 107.5-bit static datum with the 31-bit floor |
| C10 Proxy-workload validity / Cell 4 | incremental | Kota full ML-DSA-65 in SP1 (5.6M cyc/22s) | proxies SAFE only if relabeled "dominant-primitive shape"; **Cell 4 (Aurora over Fp192) UNMEASURED — defense-critical** |
| C11 Precompile slower than SHA-3 | this data point novel | a16z "Understanding Jolt" (general principle) | **this PQ-workload inversion is SAFE/novel but BURIED** (omitted from 01/08 contributions); matched-λ premise UNCONFIRMED (06 L113 "†SHA-3 control security level to be confirmed") |

## 2. The defensible core (ranked by survival)

1. **The quantified agility tax + the slower-than-SHA-3 inversion** (C3+C11+C2-narrow). Best survivor. Claim only the *quantification at this granularity* and the *PQ-workload inversion* — both unoccupied. Must cite SoK/Gassmann, fix FMT, confirm matched λ.
2. **The dual obstruction as a measured toolchain-instantiation** (C4). Survives only reframed: drop "novel conjunction"; claim "first measured for the deployed RISC0/SP1 pipeline" + argue why the pairing-free PQ wrap (which exists in principle) isn't realizable on target hardware.
3. **Update churn as a *measured* dimension** (C6) — survives weakly, and only after fixing the zero-churn contradiction and **measuring R_static** (see §6).
4. **Security-preservation theorem** (C5) — not novel (zk-creds); premise possibly false (C7); demote to conjecture.
5. **The precompile** (C1) — instrument only.

## 3. The 3 most dangerous existing works (cite head-on or be sunk)

1. **SoK:zkVM (eprint 2026/525)** — threatens C3, C4, C8, C9 at once, and you already own the PDF (cited only in a figure). States the emulation tax + precompile mitigation, both halves of the dual obstruction, and imports the small-field floor. As written (phenomenon presented uncited) the contribution reads as already-systematized. **Cite it in §2/§4 and claim only quantification.**
2. **StarkWare S2morrow** (Falcon+SPHINCS+ in Cairo) + **Kota full ML-DSA-65 in SP1** — kill the unqualified "first PQ-sig in a zkVM." Add a negative-survey paragraph distinguishing them (not PLUM, not anon-cred).
3. **Arguzz (arXiv 2509.10819)** — double-edged: its $50k RISC0 missing-constraint bug *is* candidate-cause-(iii), so the CreGen rejection is **not** epistemically inert w.r.t. AIR soundness; and it's the off-the-shelf instrument that would resolve the question you currently defer. (Companion: CertiPlonk Lean-verifies Plonky3 AIRs, and SP1 *is* Plonky3 — so "constraint-level verification is out of reach" is weak.)

## 4. Internal contradictions to fix — HIGH severity

- **C7 — the security firewall contradiction (most dangerous).** 055-security L96–98 uses *execute-mode acceptance* to "confirm the guest computes the intended predicate," and the preservation Theorem's premise T2 is "the AIR admits only the reference permutation" — while 06-evaluation L282/563 says the CreGen rejection is "deliberately not used." But execute mode does **not** run the AIR constraints (so it can't confirm T2), and the same relation's *prove* run was **rejected**. **Fix:** (a) delete the execute-mode "confirms the predicate" sentence from the constraint-level argument; (b) **downgrade the Theorem to a Conjecture** conditioned on the unverified T2; (c) run Arguzz/CertiPlonk on the Griffin-Fp192 AIR, or resolve the CreGen rejection cause — a confirmed cause (iii) is evidence *against* T2.
- **C2 — prove-mode first-ness overclaim.** 08-conclusion L25 says "first reported execute- and **prove**-mode costs for PLUM-based BDEC," but **no BDEC relation was ever successfully proven.** **Fix:** restate to "first **execute-mode** cycle figures for PLUM-based BDEC, and the first **standalone PLUM-verify** prove time, in a general-purpose RISC-V zkVM," + negative survey (S2morrow, Kota, 2024/131, BDEC-Loquat-Aurora).
- **C6 — zero-churn vs shipped AIR.** Churn table says N_circ=0/N_audit=0 for the zkVM, but the shipped Griffin-Fp192 AIR is itself relation-specific. **Fix:** re-derive the table — N_circ≥1/N_audit≥1 for hash-family or field-width changes; N_circ=0 only for field-untouched changes (e.g. presentation k:1→2). Reword "zkVM update cost is zero" → "zero regenerations of the *universal* relation."
- **C5 — generic-over-EU-CMA unverified; QPT header; stale QROM.** Get the BDEC primary source; quote the exact signature hypothesis. Change the Theorem scope from "every QPT adversary" to classical-ROM (the EUF reduction is classical-ROM only), or carry the QROM lift citing Pegasus 2025/1841.
- **C11 — confirm matched λ, then un-bury.** Confirm Cell 3 is λ=80 (06 L113 flags it unconfirmed); then promote the 1.13×/2.45× inversion into the contributions and 06-eval, and explain the unflagged ~2.16× superlinear cycle→prove gap.
- **C10 — Cell 4 (Aurora over Fp192) unmeasured (D8).** Port the Fp127 Aurora runner to Fp192 on M5 Pro, or label the static reference everywhere as "Loquat/Fp127, 107.5-bit, zk=false" and don't present the four-cell design as complete.

## 5. Discrepancy fix-list — MEDIUM / LOW

- **Aurora verifier complexity (MED, verbatim contradiction).** 02-related L24 "linear verifier [Thm 1.2]" vs 03-prelim L323 "polylogarithmic." Aurora = **linear verifier, polylog proof size**. Fix 03-prelim L323.
- **FMT unit incoherence (MED).** 04 L24/L32: FMT(op)=cost_em(cycles)/cost_nat(R1CS rows) is dimensionless-broken; FMT(Pred) is a bare cycle sum with the same symbol. Make both the same unit, or rename. Demote FMT from "central contribution" to "cost-accounting frame building on SoK 2026/525."
- **91% hash-share (MED).** It's an R1CS ratio, not a zkVM-cycle ratio; 06 cautions, 04 L21 doesn't. Add the caution at 04, or stop using 91% as a zkVM-cycle/Amdahl claim. You have the syscall count (1052) — measure the real cycle share.
- **37M trace-cell error (MED).** 33×14×1052 = 486,024, not 37M (off ~76×). Recompute four_scheme_benchmark.md L135–144 before citing.
- **cycles/mul caption (MED).** 06 L228 6,625/1,826 vs back-computed ~2,122/~1,594 — state the source or correct.
- **Small-field floor miscast (MED).** It enters ε_KS (unforgeability), not anonymity; SP1 Hypercube (KoalaBear, unique-decoding) is outside the Fenzi–Sanso capacity-regime attack.
- **Aurora zk-config (MED).** Your reference is zk=false/107.5-bit; surface "ZK disabled in our measured config" where Aurora is introduced.
- **λ-mixing / D1 (HIGH-ish).** 1.5×/4×/1.28× PLUM-vs-Loquat and the 116,285/91% decomposition are λ=128; prove measurements are λ=80. Label every figure with λ.
- **Loquat hardware correction.** Where the thesis (or memory/CLAUDE.md) says Loquat's numbers are on Xeon W-2155: the paper's §6.2 is **M1 Max 32 GB single-thread, Table 3** — same Apple-Silicon family as M5 Pro, so the cross-hardware concern is *smaller* than stated. Don't conflate Loquat's Python/Sagemath Table 3 with your own libiop-C++ 3.78 min Fp127 figure.
- **Bit-width naming (LOW but pervasive).** Implementation prime is **199-bit** (≈135-bit p₀), but "Griffin-Fp192"/"192-bit" naming pervades; 04 writes F_p192, 06 writes F_{p^199}. Pick one (199-bit is the verified truth), use it everywhere, footnote PLUM's own prose-vs-printed inconsistency.
- **LOW:** bdec_v1 2k+1 vs implemented k+2 (D5); ZK-wrap attempt count 4-claimed vs 3-logged (D9); adversarial-probe "six" but enumerates five (→ 12/12 not 14/14); ML-DSA proxy "mod 2^23" doc-label typo (code uses correct q=8,380,417); disambiguate "implemented ShowCre" = execute-only.

## 6. The 2-month plan (ranked by payoff/effort)

**Tier 1 — text-only, do this week (closes the worst attacks by conceding them):**
1. Downgrade the security Theorem → Conjecture; delete the execute-mode "confirms the AIR" sentence; state the silent-acceptance case is untested (C7).
2. Fix the C2 prove-mode overclaim + add the negative-survey paragraph (S2morrow, Kota, 2024/131).
3. Re-derive the churn table (C6); reword "zero update cost."
4. Promote the SHA-3-beats-precompile inversion into the contributions; demote the precompile to "instrument" everywhere (01/03/08).
5. Fix Aurora linear-vs-polylog, FMT units, the 37M and cycles/mul numbers, the bit-width naming, the λ labels.

**Tier 2 — the two measurements that decide the thesis:**
6. **Measure R_static** (the #1 item from the literature audit): take the in-repo Noir/Aurora BDEC circuit (`platforms/compilers/noir/bdec_showver/`), make N representative changes (swap φ; bump λ 80→128; change disclosed-attribute count k), wall-clock each recompile. This is the *only* axis the zkVM can win and the only top-threat fully closeable before July; Sako mandated it.
7. **Per-phase decomposition of the 32.5 min** (execution / VM-circuit / compression / Groth16) to explain the loss to SHA-3 — the program-independent backend may dominate (SoK §7.2.1).

**Tier 3 — research-grade, partly out of reach:**
8. Resolve the CreGen rejection cause: single PLUM-verify prove *with* the Griffin precompile (the discriminator the current `sys_bigint` run leaves open) + CreGen on SP1; or run Arguzz/CertiPlonk on the AIR.
9. One completed ZK-wrapped credential proof on a ≥64 GB machine (or Boundless) → turns the OOM into a measured gap.
10. Measure Cell 4 (Aurora over Fp192) for a same-field static-vs-zkVM point.

## Sources
Workflow outputs `wpu2v20c9` (zkVM-literature gap audit) and `wffvpwhdl` (claim/prior-art
audit), 2026-06-05. Repo files cited inline. Thesis chapters in `修論2025_Takumi/`.
Companion: `docs/thesis_journey_2025-07_to_2026-06.md`.
