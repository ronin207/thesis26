# Completeness sweep verdict + the Griffin cryptanalysis finding — 2026-06-14

Source: wf_3183cd0b (8-lens web+proceedings sweep) + native ePrint browser searches +
primary-source verification of the decisive item. Supersedes nothing; adds the security finding.

## 1. NOVELTY: the thesis cell is STILL OPEN (confirmed)
After ~100 queries / 8 lenses + native ePrint search, **no paper** conjoins {post-quantum} +
{zero-knowledge} + {anon-cred or PQ-sig-verify} + {inside a general-purpose proving substrate} +
{measured prover time on consumer hardware} in the Legendre/power-residue (Loquat/PLUM) or Griffin
family. Every near-miss breaks exactly one conjunct → a clean novelty boundary.

Near-misses (all already tracked in `external_validity_findings_20260610.md` lines 76-82):
- **HAPPIER** (LightSec 2025) — PQ XMSS *aggregate* sig in RISC Zero on a laptop, built-in SHA
  precompile, Groth16 disabled (so STARK, not ZK). Closest substrate peer; breaks the cell on
  family (XMSS not power-residue), property (aggregation not anonymity/ZK), use case. CITE as
  independent corroboration of "PQ-sig in RISC0 → STARK, ZK only via SNARK wrap"; not a threat.
- **Pegasus/PegaRing** (2025/1841), **DualRing-PRF** (2024/985) — power-residue/Legendre-PRF
  *native* signatures from the Monash/Steinfeld-Liu group (same lineage as Loquat/BDEC); no
  substrate measurement. Near-certain reviewer references for the scheme-family related work.

## 2. THE REAL FIND — a security-chapter gap (NOT a novelty threat)
**Verified at primary source (eprint 2024/347, CRYPTO 2024):** "The Algebraic Freelunch"
(Bariant, Boeuf, Lemoine, Manterola Ayala, Øygarden, **Perrin**, Raddum). Verbatim abstract:
*"the FreeLunch approach challenges the security of full-round instances of Anemoi, Arion and
Griffin… using the FreeLunch attack combined with a new technique to bypass 3 rounds of Griffin,
we recover a CICO solution for 7 out of 10 rounds of Griffin in less than four hours on one core
of AMD EPYC 7352."* Active line: CheapLunch (eprint 2025/2040), Improved-Resultant (eprint 2025/259).

**The gap:** the thesis rests **91% of its cost on Griffin**, instantiates it at **14 rounds, deg-3
S-box, width-4 state, 199-bit field** (055-security.tex:251-253), carries its security as a bare
**"open"** question, and cites **ZERO** AO-hash cryptanalysis (grep of the whole tree: no
FreeLunch / Gröbner / CICO / Bariant). A symmetric-crypto committee member will know this line
and ask why the load-bearing primitive's margin is asserted-open-but-unexamined.

**The required fix (citation + margin statement, NOT a novelty defense):**
1. Cite 2024/347 (CRYPTO 2024) + CheapLunch + Resultant in 055-security.tex.
2. State the broken instance (7/10 rounds of a 10-round Griffin) vs the thesis instance (14 rounds, F_p199).
3. Confirm the 14-round margin is set per the *current* cryptanalytic state, not left as a bare "open."

**HONEST CAVEAT (do NOT skip before writing any margin sentence):** the 14-round vs 10-round
comparison is across DIFFERENT Griffin parameterizations (round count scales with field size /
security level). Whether 14 rounds in F_p199 has adequate margin against the FreeLunch family is
**UNVERIFIED** — it requires reading the attack's complexity table (2024/347 PDF + successors) and
the Griffin spec's round-selection formula. Do NOT claim "safe" or "broken" until that check is done.
This is a proof-checker task. (Note this also bears on premise T4 / the QRO-replacement of Griffin
in PLUM's EU-CMA argument — the cryptanalysis is exactly what makes that premise non-trivial.)

## 3. New citations worth adding (verified provenance noted)
- **Gold OPRF** (Yang, Benhamouda, Halevi, Krawczyk, Rabin; IEEE S&P 2025 / eprint 2024/1955) —
  strongest FOUNDATIONAL reference for the power-residue PRF (Gold/Damgård a^g mod p) PLUM rests on.
- **Vega** (Kaviani, Setty; eprint 2025/2094) — low-latency ZK over EXISTING (classical ECDSA/RSA)
  credentials; Setty is high-visibility. The strongest NON-PQ credential-prover neighbor; PQ is the
  thesis's differentiator against it.
- **Mombelli MSc** (ETH 2025) — independent Aurora (libiop) prover/proof-size benchmark on a
  consumer laptop for ECDSA-in-circuit anon-cred; external datapoint comparable to Cell 4 (classical).
- **FibRace** (arXiv 2510.14693) — large-scale client-side proving benchmark; anchor for the
  "consumer-hardware ZK proving is studied at scale" framing.
- **Methodology controls:** Gassmann et al. "Compiler Optimization Impacts on zkVM Performance"
  (arXiv 2508.17518; up to 45% exec-time swing from LLVM passes) — a confounder Cell-1-vs-Cell-2
  must hold constant; **vApps** (arXiv 2504.14809; precompiles >95% proof acceleration) — corroborates
  the ~10x precompile premise.

## 4. Completeness caveats (Sako rigor on the sweep itself)
- PROVENANCE: eprint/ACM/Springer/ScienceDirect 403'd the fetch tool; most figures are
  snippet-level and UNVERIFIED-at-passage. Verified at source here: FreeLunch 2024/347 (browser).
- Re-run the sweep within ~30 days of submission (a same-month competitor could be missed; no
  page-by-page walk of USENIX'26 / S&P'26 / CCS'26 accepted lists).
- WATCH pq.ethereum.org / leanVM (SNARK-aggregation of PQ signatures) — most likely future source
  of a cell-occupying result; engineering, not yet a measured paper.

## 5. MARGIN CHECK VERDICT (wf_0110bd5b, 3 proof-checker lenses + synthesis)
**Verdict: CANNOT-ESTABLISH-WITHOUT-ESTIMATOR.** The 14-round count is UNVALIDATED against the
FreeLunch frontier — not falsified, not established.

- WHY: 14 rounds is derived (VERIFIED, griffin_p192.rs:458-491) from the FGLM/Gröbner binomial CICO
  model (target 2^64 = 2^(128/2), +20% margin over the rgb=10 floor). FreeLunch's resolution is
  explicitly "complexity LOWER THAN applicable state-of-the-art FGLM algorithms." Model-category
  mismatch, not a margin-size question → the 20% does NOT establish 128-bit vs the current attacker.
- AGGRAVATING (all same direction): (i) the 20% margin = exactly 3 rounds = FreeLunch's demonstrated
  "bypass 3 rounds of Griffin" — if structural, margin fully consumed; (ii) d=3 < the analysed d=5;
  lower S-box degree generically eases per-round solving — never a cushion; (iii) frontier advancing
  (CheapLunch 2025/2040, Improved-Resultant 2025/259).
- MITIGATING (steelman): the instance FreeLunch ACTUALLY broke is a TOY — ~2^55-bit prime, state
  width t=12 (VERIFIED from authors' repo aurelbof/algebraic-freelunch), one core <4h. NOT a 2^128
  statement. Whether 14 rounds at d=3 over 2^199 (t=4) still costs ≥2^128 depends on the complexity
  exponent f(r,d,t,log p), which lives in paper bodies that are Cloudflare/Anubis-blocked to ALL
  fetch tools (eprint, Springer, HAL). Genuinely needs the authors' estimator.
- ROUND INCREASE? Not numberable without the estimator; re-running the existing formula is NOT a fix
  (wrong model). Two options:
  - OPTION A (ecosystem-preferred): migrate Griffin → Poseidon2. TaceoLabs noir-griffin deprecation
    note recommends Poseidon2; Plonky3 Poseidon2 AIR is SOLVED (thesis already cites it). Removes the
    cryptanalysis question AND simplifies T2. Bigger change; viable only if PLUM does not mandate Griffin.
  - OPTION B (keep Griffin for PLUM fidelity): cite the attack line, drop the "128-bit" claim, name
    the estimator-instantiation as future work, widen T4. Defensive minimum; forecloses nothing.
- COUPLES TO T4: a FreeLunch CICO/reduced-round solution IS a non-random structural property →
  directly undermines Griffin-as-QRO (T4). Two views of one gap. Closing the round question
  (estimator or Poseidon2) is a precondition for T4 being closable classically. Thesis's own note:
  "AIR cannot rescue Griffin if Griffin is QROM-distinguishable."

### Ready-to-paste 055-security.tex margin sentence (Option B; adjust to house style)
> The $14$-round count is derived from the FGLM-based Gröbner-resistance heuristic of the original
> Griffin proposal (target $2^{64}$, a $20\%$ margin over the $\mathsf{rgb}=10$ floor). The FreeLunch
> attack family~\cite{freelunch2024,resultant2025,cheaplunch2025} solves the CICO problem with
> complexity lower than the FGLM model from which this count is derived, recovering CICO solutions
> for $7$ of $10$ rounds of standard ($d{=}5$) Griffin instances. Our instantiation uses a
> degree-$3$ S-box, lower than the analysed $d{=}5$ instances, which does not improve and may reduce
> per-round algebraic resistance. We therefore do not claim the $14$-round count establishes a
> $128$-bit floor against the current algebraic-attack frontier; doing so requires instantiating the
> FreeLunch/resultant complexity estimator at $(\text{rounds}=14, d=3, t=4, \log_2 p \approx 199)$,
> which we identify as required future work, and which couples to premise~(T4): a reduced-round CICO
> solution is exactly the non-random structure (T4) assumes absent.

### Citations to add to ref.bib
- FreeLunch: Bariant, Boeuf, Lemoine, Manterola Ayala, Øygarden, Perrin, Raddum, "The Algebraic
  FreeLunch…", CRYPTO 2024, eprint 2024/347.
- Improved Resultant Attack: eprint 2025/259. CheapLunch: eprint 2025/2040.
- (optional) TaceoLabs noir-griffin deprecation note (ecosystem signal for Option A).

### Honest caveats (what still needs primary-source work)
Per-round complexity formula NOT retrieved (all mirrors blocked); "8/10 rounds" successor is
secondary-sourced; whether the bypass is 2 or 3 rounds is unverified (authors' README inconsistent);
whether "10 rounds" is the full recommended instance is unverified; the d3<d5 easing is a
general-principle conservative default, not a retrieved number. The structural params
(14, d=3, t=4, target 2^64, 199-bit prime) ARE verified from code this session.
