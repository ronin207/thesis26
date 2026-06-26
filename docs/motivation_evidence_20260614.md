# Broader (non-BDEC) motivation evidence + the gap — 2026-06-14

Assembled from a verified web sweep (wf_6f0542cb) + a manual eprint.iacr.org search.
BDEC is the **use case we instantiate**, NOT the motivation. Every claim below is
attributable; confidence noted. Honesty guards at the bottom (what NOT to put on a slide).

## The gap (verdict: PARTIALLY-DISCUSSED — a real, narrow open measurement)

The three requirements — **post-quantum**, **unlinkable / zero-knowledge**, **runs on the
user's own device** — have each been studied in *pairs*, never measured *together* at a
deployable bar. Two camps each drop one axis:

1. **Lattice anonymous-credential camp** (PQ + unlinkable, reports SIZE not time):
   - Argo, Güneysu, Jeudy, Land, Roux-Langlois, Sanders, "Practical Post-Quantum Signatures
     for Privacy", eprint **2024/131**, p.4 *verbatim*: the field "has so far only considered
     the size metric… there is no public implementation of these schemes, which prevents us
     to assess their actual computational complexity… it is still impossible to affirm that
     they provide a real-world solution." (high confidence, read from PDF)
   - Bootle, Lyubashevsky, Nguyen, Sorniotti (IBM), "A Framework for Practical Anonymous
     Credentials from Lattices", eprint **2023/560**, footnote 1: dismisses the STARK/general-ZK
     route on proof SIZE ("hundreds of kilobytes"), never on prover wall-clock.
2. **General-purpose ZK / zkVM camp** (PQ-via-STARK + prover-time-on-hardware, but generic
   workloads): zkVM benchmarks (Jolt, SP1, RISC Zero) measure Fibonacci/SHA-256/ECDSA, NOT
   an anonymity/anon-credential predicate. (eprint zkVM corpus: 2026/525 SoK, 1217 Jolt,
   387 Ceno, 1555 memory-consistency, etc. — all blockchain/ML/rollup applications.)

**The single closest three-way result:** Policharla, Westerbaan, Faz-Hernández, Wood,
"Post-Quantum Privacy Pass via Post-Quantum Anonymous Credentials", eprint **2023/414** —
the *first implemented* PQ anonymous credential, prover time 304–4822 ms on a 2019 MacBook
Pro (Core i9, 16 GB). BUT: **single-threaded**, **115-bit** (not 128), and **on plain
(non-zero-knowledge) STARK** (Winterfell ZK unsupported) — the ZK cost is only *asserted*
"very close," not measured. So the consumer-hardware proving wall for a **full, actually-ZK,
standard-security** PQ anonymous credential is an **unmeasured cell** — which is exactly why
nobody states it as a number. That cell is this thesis.

→ "Why don't people talk about my nitpicking?" Because each camp drops one axis and tacitly
assumes the third composes. The silence is the gap, and it is defensible (not "unrecognized").

## Closest prior art to cite + distinguish (from eprint)
- **2023/414** Policharla et al. — distinguish: single-threaded, 115-bit, non-ZK STARK; we
  measure the ZK case and locate the wall.
- **2022/1297** Dutto, Margaria, Sanna, Vesco, "Toward a Post-Quantum Zero-Knowledge
  Verifiable Credential System for SSI" (Applications) — closest on PQ+ZK+credential-for-real-identity.
- **2024/868** Zhang, Steinfeld, Esgin, Liu, Liu, Ruj, "Loquat: A SNARK-Friendly PQ Signature
  based on the Legendre PRF" — the scheme lineage; its "SNARK-friendly" design premise is
  exactly what our inversion finding overturns at the zkVM substrate.
- **2025/061** Feneuil, Rivain, "CAPSS: SNARK-Friendly Post-Quantum Signatures" — the family.
- **2024/131** Argo et al.; **2023/560** BLNS — the size-only lattice camp.

## Load-bearing motivation citations (HIGH confidence — slide-ready)
- NIST finalized FIPS 204 (ML-DSA) + 205 (SLH-DSA) on 13 Aug 2024; "integrate immediately,
  because full integration will take time" (Moody). https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
- **eIDAS Art. 5a(4)** legally mandates the EU Digital Identity Wallet prevent linking/
  correlation ("unlinkability"); 16 cryptographers (incl. Camenisch, Lysyanskaya) told the
  EU the ARF "falls short" (salted-hash design fails IdP↔RP unlinkability). Lysyanskaya, NIST
  WPEC 2024. https://csrc.nist.gov/csrc/media/presentations/2024/wpec2024-3b5/images-media/wpec2024-3b5-slides-anna--anon-cred-EUDI.pdf
- **BBS** (the leading standardized unlinkable selective-disclosure primitive) states in its
  own IETF CFRG draft: "it is not post-quantum secure." https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/
- eIDAS 2.0 (Reg (EU) 2024/1183) obliges all 27 member states to ship an EUDI Wallet by late
  2026; US mDLs (ISO 18013-5) live in 20+ states in Apple/Google Wallet, accepted at TSA.
- EU June-2025 roadmap: PQC transition start by end-2026, critical-infra by end-2030 — inside
  a 10-year-passport window. https://digital-strategy.ec.europa.eu/en/news/eu-reinforces-its-cybersecurity-post-quantum-cryptography
- Ethereum Foundation "real-time proving" assumes up to **$100k / 10 kW** on-prem hardware
  (10 Jul 2025). https://blog.ethereum.org/en/2025/07/10/realtime-proving
- **FibRace** (arXiv 2510.14693): 2.2M client-side proofs across 1,420 phone models; a phone
  needs ≥3 GB RAM just for a trivial native-field proof — and PQ primitives are far heavier.

## Opening that surfaces the goal FROM the need (no findings-first, no defence)
- **S1 THE NEED:** "A digital ID issued in 2026 must still be safe in 2036." Timeline bar
  (2026 issue → 2036 expiry) with EU-2030 / NSA-2030s PQC deadlines inside it. Three fixed
  facts: NIST PQ sig standards (Aug 2024); eIDAS legally mandates unlinkability + wallets ship
  2026; wallets live on phones today.
- **S2 PICK TWO OF THREE (real-world):** columns PQ | Unlinkable | Runs-on-device; rows
  mdoc/SD-JWT (device ✓, PQ ✗, unlinkable ✗), BBS (unlinkable ✓ device ✓, PQ ✗ per its IETF
  spec), PQ-ZK (PQ ✓ unlinkable ✓, device ??). The ?? is the thesis.
- **S3 THE QUESTION (goal from the need):** "Can a person generate a flexible, post-quantum,
  private credential proof on an ordinary laptop — and if not, what stops them?" BDEC named
  here as "the use case we instantiate," one line.
- **S4 ROADMAP:** (1) find the dominant cost (field-mismatch tax); (2) build precompiles +
  measure; (3) report vs an operational "practically acceptable on 24 GB" bar. No results.

## Honesty guards (do NOT put on slides / do NOT claim)
- DON'T lean on "harvest-now-decrypt-later" — that's a *confidentiality* argument; the thesis
  object is a *signature* (forgery/impersonation). Use "a long-lived credential must resist
  forgery for its whole validity window."
- DROP OMB $7.1B and "e-waste/crypto-agility" from motivation slides (medium/weak confidence);
  the eIDAS/BBS/NIST/FibRace chain is stronger and current. (NB: current deck rigidity slide
  uses OMB $7.1B + e-waste — replace with these.)
- DROP NSA CNSA 2.0 per-category year table (primary 403); use "exclusive PQC across NSS by
  early-mid 2030s" + the EU roadmap (high confidence) as the load-bearing deadline.
- Policharla 2023/414 IS a full anon-cred (not "just a blind signature") — distinguish on
  single-threaded / 115-bit / non-ZK STARK, NOT on the primitive.
- We measure λ=80, not 128-bit; frame the gap as "the ZK PQ-credential wall on consumer
  hardware is unmeasured," which our dual-obstruction answers, rather than claiming a 128-bit number.

## CORRECTION 2026-06-14 (after the deep relevance audit — supersedes the gap framing above)
The deep read of **Argo et al. 2024/131** corrects an error in the gap framing above. Argo's
verbatim "only considered the size metric / no public implementation" describes **prior** lattice
work — **Argo itself then IMPLEMENTS and MEASURES** a full ZK PQ anonymous credential on a laptop,
**sub-second at λ=128**. So:
- WRONG (do not use): "no one has implemented / measured a PQ anon-cred on a laptop" — Argo did.
- WRONG (do not use): "PQ anon-creds are too slow on consumer hardware" — Argo refutes it.
- The defensible gap is NARROWER: no one measures the wall for an **unmodified predicate inside a
  GENERAL-PURPOSE zkVM**, compared against a static SNARK circuit (the substrate axis). Argo escapes
  the dual obstruction precisely by using a **bespoke** lattice prover (no general-purpose substrate).
The "pick two of three" motivation (mdoc / BBS / PQ-ZK) still stands — but the thesis's CONTRIBUTION
is the general-purpose-substrate cost/wall, NOT "first to make it feasible." See
`eprint_relevance_audit_20260614.md` for the full competitor map and the surgical thesis edits.
