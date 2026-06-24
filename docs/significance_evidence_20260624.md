# Significance / external-need evidence (2026-06-24)

> Research-gathered EVIDENCE for the "why is this crucial / why now" question. The Operator
> FRAMES the motivation; this is raw material + which hooks are strongest. Tags:
> [official]=govt/standards · [peer-reviewed] · [measured] · [reported] · [conjectured].
> Sources to primary-verify before quoting verbatim are listed at the end.

## The 3 strongest hooks (committee-grabbers)

1. **The EU has frozen the decision and admits it has no answer.** Reg (EU) 2024/1183
   (eIDAS 2.0) forces a credential substrate into production for ~450M people: wallet by
   **24 Dec 2026**, regulated-party acceptance ~**2027**. The leading privacy primitive
   (BBS+) is **discrete-log, not PQ**, and the Commission's own **EUDI TS4 (ZKP)** spec
   (v1.0 2025-05-21) says verbatim *"no existing ZKP approach can be deemed fully suitable
   or mature enough for direct integration into the EUDI Wallet."* Named cryptographers
   (June-2024 feedback; Lehmann/Seiler, PQC-migration conf. 2025) are arguing the
   everlasting-vs-computational axis on the live EU record. [official]
2. **Harvest-now-deanonymize-later — in its defensible form.** A recorded anonymous
   presentation that embeds a *computationally-hiding* commitment can be retroactively
   deanonymized once a CRQC arrives; a broken anonymity is permanent (unlike a re-keyable
   secret). Foundation: Moran–Naor CRYPTO 2006 (everlasting privacy), Vadhan SZK,
   Buchmann/Demirel/van de Graaf FC 2013; policy: BSI 2024, US FED FEDS 2025-093. Positive
   anchor: **ePrint 2025/1030 "Everlasting Anonymous Rate-Limited Tokens"
   (Lysyanskaya et al., ASIACRYPT 2025)** — the thesis's exact motivation, top venue, by
   the definer of anonymous credentials. [peer-reviewed]
3. **"Practically acceptable on consumer hardware" now has an external referent.** EUDI
   **TS13** (zkSNARKs, v1.0 2025-12-15): *"the Wallet Unit executes the zkSNARK prover
   algorithm over the circuit"* — proving is mandated on the holder's device. Google's
   **Longfellow** does an `age_over_18` mdoc proof in **~800 ms on a Pixel** (per TS13),
   while zkVM-style PQ workloads still run tens of seconds / hundreds of MB on consumer
   silicon. **This answers the thesis's open AQ7 (what counts as "practically acceptable")
   with an external sub-second bar.** [official/reported]

## ⚠ The counter-source you MUST pre-empt (defence trap)
**Justin Thaler (a16z/Georgetown), Dec 2025** + **Slamanig (CTB 2025)**: a ZK proof posted
today is fine even against a future QC, because hiding is established at proving time and
the simulator carried no extractable secret; AC authentication is "short-lived" so PQ
*soundness* is less urgent than PQ *confidentiality*. **Reconciliation (matches your own
2026-06-17 checkpoint):** Thaler is right for *statistically-hiding* transcripts or ones
where the secret never entered the transcript; he is silent on presentations embedding a
*computationally-hiding commitment* (Poseidon2/Merkle root, EC commitment) a future
quantum adversary can open — which is exactly the everlasting-privacy gap. **Lead with this
boundary; never make a blanket "anonymity must be PQ today" claim.**

## Angle detail (condensed)
- **A1 decider:** EU Commission eIDAS Expert Group / EDICG (EUDI ARF). DC4EU pilot = live
  diploma credentials across 25+ named universities under the same deadline. W3C "VC
  Quantum-Resistant Cryptosuites v1.0" FPWD **16 Jun 2026** (days old).
- **A2 drivers:** NIST FIPS 203/204/205 (announced 13 Aug 2024); NSA CNSA 2.0 (2030/2033/
  2035); EU roadmap (NIS CG, 23 Jun 2025: national roadmaps end-2026, high-risk end-2030);
  Mosca/GRI timeline (optimistic 10-yr CRQC odds 34%→49%, 2024→2025). **Structural hook:
  none of the 3 NIST signature standards is privacy-preserving — the thesis's niche is an
  absence in the standardized suite, framed as a gap.** (Mosca HNDL framing is about
  confidentiality; the anonymity version is the everlasting-privacy literature, A3 — do not conflate.)
- **A4 holder-side:** W3C VC 2.0 (proofs "typically calculated by the holder"); OpenID4VP;
  consumer-hardware ZK is real but fragile (Mopro Keccak ~630ms; Ingonyama Aptos-keyless
  ~30–60s on a Samsung A54; ZPiE on a Pi Zero).
- **A5 landscape:** incumbents non-PQ (Idemix, U-Prove, BBS+); lattice PQ-AC line
  (BLNS/CCS 2024, QUBIP); generic-ZK line (PQ Privacy Pass/zkDilithium ePrint 2023/414,
  zk-creds S&P 2023, Loquat CRYPTO 2024 = PLUM's lineage).

## Primary-verify before quoting verbatim
- GRI 2025 full PDF (form-gated; 34→49% from abstract+secondary).
- CNSA 2.0 V2.1 enforcement dates (secondary FAQ analysis; the 2030/2033/2035 category dates ARE primary).
- Google Longfellow "~800ms on Pixel" + Google quantum-AI privacy whitepaper (via TS13/secondary; exact Pixel model truncated).
- No anon-cred-specific (non-voting/non-blockchain) everlasting-privacy paper at a top venue — the e-voting→anon-cred transfer is the author's to make.
- IACR PDFs (Moran–Naor, 2025/1030) read at abstract/highlight via Exa — verify page-specific quotes.
