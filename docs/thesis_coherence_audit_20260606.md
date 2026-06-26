# Thesis coherence audit (2026-06-06) — Sako's lens

Section-by-section audit (workflow `wx54vb4rc`, 11 agents, all high-severity findings
re-verified against the `.tex`). Verdict: **the spine and cryptographic substance are
sound; the failures are connective tissue + framing currency + one unsourced number.
Fixable in a focused writing pass, not a restructure.**

## The 3 places the thread fully snaps
1. **G1** — Intro contribution 3 (01:42) promises an execute-cycle inversion (1.13×, 1.255e8/1.108e8) that ch.6 does not contain; the eval methodology (06:119–125) treats the contrast as qualitative. Unsourced precise number. → **strike the cycle prong, keep the 2.45× prove-wall** (32.53/13.28).
2. **G2** — The SHA-3 inversion (headline contribution 3 / proposition (ii)) is never *stated* in ch.6: present as raw table rows (06:104), framed only in the expected "standard hash cheaper" direction (06:129–132), never computed as 2.45× or called an inversion. → state it at the table.
3. **S2** — The PQ-primitive prong of the dual obstruction lives only in 055:238–245; the intro (01:51) frames the obstruction as two *resource* problems and the discussion (07:71–82) steers the deployer to a "lighter wrap" that does **not** recover PQ anonymity. → propagate the PQ prong to intro + discussion.

## Flaw ledger (ranked)
### A. Stale-framing (corrections that didn't reach the prose — writing-only)
- **S1 [HIGH]** 06:565–567/612, 07:63–69: R_static asserted "measured ≈0.3s & decisive" AND "the priority remaining measurement" in the same chapters. → delete the "recompile is the remaining measurement" sentences; the only missing term is a same-scheme per-proof static prover time (06:556).
- **S2 [HIGH]** 07:71–82, 01:51: dual obstruction reported as memory-only; "lighter wrap" offered as a non-solution. → add the PQ prong; strike the "lighter wrap solves it" implication.
- **S3 [HIGH]** 05:12,69: CreGen "does not complete on the target hardware" imports the resource-frontier reading ch.6 retracts. → "internal-verifier rejection, not a resource limit."
- **S4 [MED]** 02:53: static advantage "overstated" in wall-clock sense — refuted by R_static≈0.3s. → reword to "omits the re-audit/regeneration footprint."
- **S5 [MED]** 04:17/82/102: churn as "central conceptual contribution"; re-anchor to the re-audit footprint; demote from headline.
- **S6 [MED]** 06:113: stale "SHA-3 control λ to be confirmed" dagger — it IS confirmed at λ=80. → drop dagger.
- **S7 [LOW]** 03:765: update-churn gloss still "recompiling is the cost." → forward-ref the re-audit-footprint def.

### B. Genuine flaws (substance/consistency)
- **G1 [HIGH]** 01:42: unsourced cycle-inversion number; strike cycle prong, keep 2.45× prove-wall.
- **G2 [HIGH]** 06:104/129–132: SHA-3 inversion never stated; add the finding sentence.
- **G3 [HIGH]** 055:236,253: "exceeds 24 GB" wrong → killed ≈20 GB under pressure; the 82.7 GB is an unrelated ML-DSA proxy.
- **G4 [HIGH]** 055:138 vs app:148–165: ε_AIR "bounded in Appendix" but appendix declines to bound it. → "open premise T2."
- **G5 [HIGH]** 05:41 → app B-2 → Rem 3.5: p₀≡1 (mod 3) bijectivity "derived in App B-2" — derived nowhere; soundness-critical. → add the one-line check for the implemented prime + fix the cross-ref.
- **G6 [HIGH]** 055:162: `% TODO` swallows "Section ssec:zk-gap shows that" → subjectless proof sentence. → move the comment to its own line.
- **G7 [HIGH]** 02:15 / 01:11: "first lattice-based AC" — Libert et al. (Asiacrypt'16) is prior. → "first practical/efficient."
- **G8 [MED]** 06:402: k=14 mislabelled "largest disclosure-set in running examples" (examples k=1,2; target k≤4). → relabel as stress/extrapolation.
- **G9 [MED]** 02:10: "drop-in replacement" asserts a C↔D equivalence the SHA-3 inversion undercuts. → "motivates evaluating PLUM as a replacement."
- **G10 [MED]** 03:63 vs 03:628/693/728: Merkle "used inside the BDEC relations" but base relation checks membership outside the proof; MerkleVerify never called. → reword.
- **G11 [MED]** 04:26–31 vs 06:536: FMT defined against an unmeasurable native-Fp idealisation; eval measures a different ratio but says "FMT made concrete." → bridge to the measured proxy, or redefine against the precompile-free baseline.
- **G12 [MED]** 04:42–51: guest-cycle cost-model has no prover-side AIR term → cannot represent the SHA-3 inversion (predicts the opposite of the headline). → add a prover-side AIR proving-cost term.
- **G13 [MED]** 05:35: "6 single-field tamper cases" lists 5; "14 cases" → should be 12. → reconcile.
- **G14 [MED]** 05:20 vs 03:208: p₀ "135-bit" flat vs "approximately 135-bit." → align precision.
- **G15 [MED]** 055:159/162: BDEC genericity + Thm 1/2/3 mapping asserted; primary source paywalled. → mark "supported-by-abstract; unverified."
- **G16 [MED]** 08:58: "deployability frontier carried by memory-exhaustion measurements" — CreGen failure was NOT memory-limited; cite the actual OOM points (Cell-1, ZK-wrap ≈20 GB); fix the 06:299 vs 410–411 inconsistency.
- **G17–G20 [LOW]** Falcon "produced standard" (draft FIPS 206); Marlin/Fractal lumped with Aurora's rigidity (they are preprocessing, opposite recompile behaviour); engineering-scope line near a soundness claim; 32.5 vs 32.53 consistency.

### C. Unverified provenance (must not ship as support)
First-ness (01:38, 06:2, 08:25) rests on a negative survey entirely in TODO comments (02:55–65, four unverified works); Aurora Thm 1.2 number (02:24); FMT possibly pre-existing in SoK:zkVM 2026/525 (04:24); RSA-precompile figure uncited (02:42); Haböck/Al-Kindi cited via aggregator not primary (055:223).

## Fix order
- **Tier 1 (sentence/transition, no new data — do first):** G1 (strike cycle prong), G2 (state inversion), S2/G3 (PQ prong + memory number), S1 (R_static contradiction), S3 (CreGen reword), G6 (LaTeX hazard), G4 (ε_AIR ref), then S4/S5/S6/S7/G8/G9/G10/G17/G18/G20, then the first-ness hedges (G15 + 01:38/06:2/08:25), and restore the decision-framework contribution to the conclusion's restatement.
- **Tier 2 (cross-ref/conceptual — writing but needs a derivation/decision):** G5 (the p₀≡1 mod 3 check + cross-ref), G11/G12 (FMT proxy bridge + prover-side AIR cost term), G13/G14 (counts/precision), the 02:25/01:57 Aurora-baseline-is-a-Loquat-proxy foreshadowing, G16 (08:58 + 06:410–411).
- **Tier 3 (real change — defer, do not block the writing pass):** the cycle prong's alternative (measure the λ=80 Griffin-vs-SHA-3 execute-cycle row + the per-component split at 06:247 — recommended: strike, not measure); 13.0s smoke-proof provenance; resolve premise T2 (machine-check); verify the four negative-survey prior works.

## Companions
`docs/thesis_defense_pivot_plan_20260605.md`, `docs/r_static_finding_20260605.md`,
`docs/thesis_landscape_realignment_20260605.md`. Memory `[[thesis-precompile-framing-forced]]`.
