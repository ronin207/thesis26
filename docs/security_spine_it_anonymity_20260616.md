# Security spine: the information-theoretic anonymity asymmetry (PLUM-BDEC in a zkVM)

> ⚠️ **SUPERSEDED 2026-06-17 — DO NOT propagate this note's IT/everlasting framing into the
> thesis.** A `proof-checker` adversarial pass refuted the composition this note assumes. The
> masked zk-STARK does **NOT** deliver information-theoretic / everlasting anonymity: proving
> the attribute commitment `c=H(w‖r)` in-circuit forces `w` into the witness trace, whose
> Poseidon2 root is only **computationally** hiding (standard model); the IOP-layer IT-HVZK
> does **not** lift to IT-hiding of the compiled proof, and the (Q)ROM rescue is vacuous against
> the harvest-now adversary (Canetti–Goldreich–Halevi). **Honest claim = computational
> post-quantum anonymity in the (Q)ROM** — which is exactly what `055-security.tex` already
> states (`Adv^anon ≤ ε_ZK + ε_sZK`, classical ROM, conditional). Everlasting anonymity is a
> NAMED OPEN OBSTRUCTION (needs a standard-model statistically-hiding *trace* commitment;
> collides with the non-interactive-SH impossibility boundary). Full record + the refuted
> lemma + the two repairs: `~/vault/wiki/concepts/d7-sh-commitment.md`; corrected principle:
> `~/vault/wiki/concepts/it-anonymity-asymmetry.md`. The §1 "the resulting hiding is
> information-theoretic … the right kind for anonymity" sentences below are the refuted claim;
> read them as the *motivation/requirement*, not as a property the construction delivers.

Built 2026-06-16. This is the thesis security-chapter spine. Its discipline: **the claim is bounded by the
ledger.** Every sentence in §1 is constrained by §3 (implemented/measured) and §4 (peer-reviewed), and anything
in §5 (open) is stated as open, never as done. NOT a deck artifact; thesis (7/20).

---

## 1. The argument (the spine)
An anonymous credential needs two security properties, and they have **different temporal threat models** — this
asymmetry is the organizing principle.

- **Unforgeability (soundness)** must hold while a forgery would matter: the credential's validity window. That
  window reaches into the quantum era, so it needs **post-quantum soundness — but a *computational* PQ assumption
  is sufficient** (collision-resistant hashing for the STARK; the power-residue-PRF assumption for PLUM). A forger
  must succeed *during* validity; an assumption believed to hold over that window is enough.
- **Anonymity (hiding / unlinkability)** must hold **for all time**. A presentation transcript captured today can
  be stored and **deanonymized later** ("harvest now, deanonymize later"), once a quantum computer exists or a
  computational hiding assumption falls. Hiding that rests on *any* computational assumption is therefore unsafe
  in the limit. Anonymity must be **information-theoretic (statistical/perfect) hiding**.

**The impossibility that forces the choice (peer-reviewed):** no commitment is simultaneously *statistically
hiding* and *statistically binding* (Haitner–Nguyen–Ong–Reingold–Vadhan). One property is information-theoretic,
the other computational. For a credential you take **statistical hiding** (anonymity = forever) and accept
**computational binding** (soundness = a bounded window). This is the same direction the asymmetry already points.

**The consequence — and the production gap.**
- A masked zk-STARK adds zero-knowledge by *randomization* (witness randomizers + a FRI mask polynomial), and the
  resulting hiding is **information-theoretic** (perfect/statistical HVZK) — it does not rest on the hash being a
  random oracle. This is the *right* kind of hiding for anonymity.
- SP1/RISC Zero's **production** ZK path is a **Groth16/PLONK wrap over a pairing-friendly curve**, whose hiding is
  **computational and curve-based**. It is the *wrong* kind: a future quantum adversary breaks the curve assumption
  and **retroactively deanonymizes** every transcript ever produced through it. It also is not post-quantum-*sound*.
- So the credential's anonymity requirement and the substrate's production ZK path are **structurally
  incompatible**: the only ZK you can turn on today gives you exactly the hiding flavor anonymity cannot use.

**What is the thesis's contribution here (stated precisely, not inflated).** The asymmetry itself is *known* (it
is the statistically-hiding-commitment principle plus the harvest-now-deanonymize-later threat; not invented here).
**This thesis's contribution is to apply it to the PLUM-BDEC-in-a-general-purpose-zkVM setting and to characterize,
by measurement and analysis, that the production substrate's only available ZK violates the anonymity side, while
the information-theoretic alternative (masked zk-STARK) is specified but not yet available in production.** It is a
*characterization + specification*, not an achieved system.

---

## 2. What this thesis CAN claim, exactly (the bounded statement)
> Unforgeability of the zkVM-proved BDEC credential reduces to PLUM's EU-CMA security and the STARK's
> collision-resistance soundness — computational post-quantum assumptions sufficient for the credential's validity
> window — **under the open premises T1–T3** (lookup binding; Griffin-AIR soundness, per-row proven / lookup-borne
> open; black-box PRF transfer).
>
> Anonymity requires **information-theoretic** hiding of the witness. The production ZK path (Groth16/PLONK wrap)
> provides only **computational, non-post-quantum** hiding and is therefore unsuitable; a masked zk-STARK
> (witness randomization + FRI mask polynomial) provides information-theoretic hiding and is the suitable
> construction. **This thesis specifies that construction and characterizes the gap; it does not implement or
> measure an information-theoretically-anonymous PLUM-BDEC proof.**

No sentence beyond this is licensed by what exists. In particular the thesis does **not** claim to *achieve*
post-quantum anonymity, nor to have *measured* a masked-zk-STARK PLUM proof.

---

## 3. Ledger A — IMPLEMENTED / MEASURED (the thesis stands on these)
- PLUM-verify on SP1, **succinct STARK, NOT zero-knowledge**: 32.5 min prove, ~19.5 GB peak (81% of 24 GB), λ=80,
  tuned reduced-memory config; defaults OOM ~3 min. [measured]
- Griffin-Fp192 precompile makes the otherwise-DNF base proof finite; the precompile proves **slower** than a SHA-3
  control (the inversion; sign robust, 1.10–2.45× build-sensitive). [measured]
- The SP1 succinct STARK is **not** zero-knowledge, and SP1's only ZK path is the Groth16/PLONK wrap. [SP1 docs — fact]
- The Groth16/PLONK wrap is **pairing-based (BN254) → not post-quantum**. [SP1 docs — fact]
- `slop/crates/veil` exists in the SP1 tree as an experimental ZK PCS (Basefold/KoalaBear, masking-based),
  **not wired into the prove path, dead-code, not peer-reviewed**. [code — fact]
- The witness-hiding (ZK) path was **never obtained on 24 GB**: a PLONK attempt peaked ~20 GB; not cleanly
  characterized; Boundless outsourcing set up but exports empty. [measured-absence — fact, NOT "it OOM'd"]

## 4. Ledger B — PEER-REVIEWED LITERATURE (cite as established)
- **Information-theoretic ZK for STARKs by randomization** — Aurora (Ben-Sasson–Chiesa–Riabzev–Spooner–Virza–Ward,
  EUROCRYPT 2019). The small-field formalization (witness randomizer + FRI mask polynomial, degree budget
  h ≥ 2d(e·n_DEEP+n_FRI)+n_FRI, ~few-% cost, perfect-HVZK theorems) is **Haböck–Kindi, ePrint 2024/1037** — an
  ePrint *note*, widely used, formalizing the peer-reviewed Aurora result; cite as "the established small-field
  construction," not as peer-reviewed itself.
- **No commitment is both statistically hiding and statistically binding** — Haitner et al. [peer-reviewed; textbook]
- PLUM (Springer 2025) / Loquat (CRYPTO 2024) parameters; STIR (CRYPTO 2024). [peer-reviewed]

## 5. Ledger C — UNSETTLED LITERATURE (cite ONLY with the unsettled flag)
- **VEIL (ePrint 2026/683)** — info-theoretic hiding for SP1-class multilinear systems, ~3%/22%/12%
  prover/verifier/size overhead, "planned replacement for SP1's Groth16 wrap." **NOT peer-reviewed; ~30 pages of
  arguments; Lean formalization contains `sorry` placeholders; one sub-protocol already downgraded perfect →
  statistical HVZK; not shipped in production SP1.** Use as "an in-progress mechanism that confirms the direction,"
  never as a usable or proven feature.
- **The 2025 proximity-gaps results** (Diamond–Gruen 2025/2010; Crites–Stewart; collected 2025/2046) — **disprove**
  the up-to-capacity correlated-agreement conjectures (BCIKS), WHIR's mutual-correlated-agreement, and DEEP-FRI
  list-decodability up to capacity. Proven-regime parameters → ~2× larger proofs / verifier time. **PLUM bakes in
  STIR**, so this bears directly on PLUM's soundness parameters.

## 6. Ledger D — OPEN / TO-BE-AUDITED (state as OPEN; never as done)
1. **The masked zk-STARK is NOT implemented for PLUM-verify.** Information-theoretic anonymity is therefore a
   *design + analysis*, not a built or measured result. (Upgrade path: implement witness randomizers + FRI mask on
   the SP1/Plonky3 prove path — large; or analyze veil's mechanism + a security argument. The thesis does the latter.)
2. **The degree budget for the SP1/PLUM instantiation is unverified at primary level.** h ≥ 2d(e·n_DEEP+n_FRI)+n_FRI
   must be instantiated with PLUM-verify's actual d, e, query counts, and checked against |H|. (Upgrade: read
   Haböck–Kindi + the SP1 FRI parameters; derive h; confirm the ~few-% cost holds for this trace.)
2b. **SP1's LogUp/permutation sub-arguments may be only *statistical* (not perfect) HVZK**, and one run can leak
   bounded witness info (Haböck–Kindi flag this explicitly). (Upgrade: identify which SP1 sub-arguments are perfect
   vs statistical; confirm the leak is within a statistical-ZK bound; switch any that exceed it.)
3. **The composition is novel and UNBUILT.** Every composed-system size/memory figure (~50–150 KB final proof; ~few-%
   ZK overhead; per-segment RAM bound) is an **estimate** assembled from component benchmarks; mark as such.
4. **T2 (Griffin AIR soundness): per-row layer proven, lookup-borne layer OPEN.** [carry as open premise]
5. **T4 (PLUM signature-transcript simulator / the QROM Fiat–Shamir lift): OPEN.** Anonymity's information-theoretic
   *IOP* hiding still composes with PLUM's own simulator (e_sZK) and the QROM compiler; both are open premises.
6. **PLUM's STIR soundness parameters need re-derivation in the proven regime** (per Ledger C, the 2025 disproof),
   or explicit reliance on the *modified* up-to-list-decoding-capacity conjectures, with a documented margin.
7. **The Merkle-commitment hiding is the one computational component**: a plain hash-based Merkle leaf is only
   computationally hiding. For information-theoretic anonymity the attribute secret must enter a *statistically-
   hiding* commitment (veil's zk-codes + masking row, or a lattice/Pedersen-style commitment) **before** any plain
   Merkle leaf. (Upgrade: specify and justify the statistically-hiding commitment for the attribute secret.)

---

## 7. Dangerous assumptions / overclaims to AVOID (specific to this spine)
- Do NOT claim the thesis **achieves** or **measures** information-theoretic anonymity for PLUM. It specifies and
  characterizes; it does not build/measure it (Ledger D-1).
- Do NOT present the **asymmetry as a novel theorem**. It is the known statistically-hiding-commitment principle
  applied to this setting; the contribution is the application + the zkVM-production-gap characterization.
- Do NOT cite **VEIL** as a usable, proven, or shipped feature (Ledger C). "Confirms the direction," not "available."
- Do NOT quote **conjectured-regime** FRI/STIR/WHIR sizes/soundness as if proven; the up-to-capacity conjectures
  were disproved in 2025 (Ledger C). Re-derive in the proven regime or cite the modified conjectures with a margin.
- Do NOT claim the masked-STARK ZK is **perfect** through SP1 end-to-end; some sub-arguments are only **statistical**
  (Ledger D-2b). Say "statistical (information-theoretic) HVZK" unless perfect is verified per sub-argument.
- Do NOT let a **lattice final compressor** (LaBRADOR/Greyhound) be the only thing hiding the secret: its hiding is
  *computational* under Module-SIS. The anonymity-critical hiding must be information-theoretic upstream (Ledger D-7).
- Do NOT say the ZK wrap **"OOM'd"** as a clean measured fact; it was never cleanly characterized (Ledger A — a
  PLONK attempt peaked ~20 GB; not completed/verified).
- Do NOT label PLUM's outer setting **"Aurora/STIR"** as its prover; STIR is PLUM's own *inner* IOP. The static-circuit
  comparison is a Loquat-Fp127 proxy (PLUM-in-Aurora not runnable).
- Do NOT call the 24 GB target **"edge devices"** or assert a **"prohibitive"** assurance cost (unmeasured).

---

## 8. The one-line claim, and the one-line gap
**Claim:** *anonymity is a forever threat, so it needs information-theoretic hiding; the production zkVM ZK path
provides only computational, non-post-quantum hiding; the suitable construction is a masked zk-STARK, which this
thesis specifies and whose production gap it characterizes.*
**Gap (open work, named):** *implement/instantiate the masked zk-STARK degree budget for PLUM-verify, establish the
statistically-hiding attribute commitment, and re-derive PLUM's STIR soundness in the proven regime — none of which
this thesis completes; each is stated as open with its upgrade path.*
