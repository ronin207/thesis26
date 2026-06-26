# External-validity findings — 2026-06-10

Source: `external-validity-sweep` workflow (run `wf_6d5cb9d2-ad4`), 15/16
load-bearing claims verified against primary sources by independent
fetch-and-reproduce agents. Full structured data with verbatim quotes and
URLs: `docs/external_validity_findings_20260610.json`.

## 1. RISC Zero ZK status — the dual-obstruction prong must be rescoped

**Verdict: ZK formally NO (disclaimed), mechanistically YES for succinct
receipts; PQ conjectured-yes for the STARK path.**

- RISC Zero succinct (recursion) receipts DO include zero-knowledge
  blinding: the recursion circuit appends `ZK_CYCLES = 1024` rows of random
  noise to data and accum columns (code-verified at tag v3.0.5 and main as
  of 2026-05-18). Docs: "recursion proofs leak no information about
  execution length."
- RISC Zero explicitly disclaims a formal ZK guarantee, identically across
  versioned docs 1.0–3.0 and the live page (fetched 2026-06-10): "targets
  perfect zero-knowledge. Nevertheless, we have not written a mathematical
  argument to prove that our system is zero-knowledge … urge those with
  critical privacy requirements to take caution."
- Code-level finding (no third-party source): the v2 rv32im SEGMENT circuit
  used in risc0 2.x/3.x contains no blinding in witness generation —
  composite (per-segment) receipts appear UNblinded; only the recursion
  layer blinds. (v1.x segment circuit did blind; v1.1.0 strengthened it via
  Haböck–Kindi ePrint 2024/1037.)
- PQ: official security table marks RISC-V Prover (96 bits) and Recursion
  Prover (99 bits) "Quantum Safe? Yes" under ROM + Toy Problem Conjecture;
  Groth16 BN254 wrap marked NOT quantum safe.
- Bonus wall: RISC Zero's Groth16 wrap "only works on x86 architecture, and
  so Apple Silicon is currently unsupported" — on the target hardware the
  pairing wrap is architecturally unavailable, not merely OOM.

**Consequence for the thesis.** The strong claim "the only ZK path from a
zkVM receipt is a pairing-based wrap, hence no PQ-ZK path" is FALSE for
RISC Zero. The defensible (and stronger) formulation is per-substrate:

- SP1: no ZK at the STARK layer at all (documented); wrap attempts OOM at
  ~20/24 GB; available wraps pairing-based, not PQ.
- RISC Zero: the succinct receipt is blinded, hash-based, plausibly PQ, and
  the 6 h 19 m single-verification run produced exactly such a receipt. BUT
  (a) RISC Zero disclaims a proven ZK property, so the BDEC anonymity
  theorems (which require the underlying zkSNARK to be ZK) still cannot be
  formally discharged on it; (b) the credential relation itself (CreGen)
  remains blocked by the prove anomaly and a ~4.6-day projection; (c) the
  pairing wrap is unavailable on Apple Silicon regardless.

So "deployable PQ anonymity is not reached on the target hardware"
SURVIVES, but through three substrate-specific walls instead of one
categorical wrap argument.

## 2. Prior art — no kill; novelty must be scoped

- **CAPSS (Feneuil & Rivain, ePrint 2025/061, rev. Oct 2025)** — the
  closest competitor, previously unknown to the thesis. SNARK-friendly PQ
  signatures from AO permutations including Griffin, anonymous-credential
  application, MEASURED Aurora/libiop proving numbers with zk-enabled
  executables, claims 5–8× fewer R1CS than Loquat. Does NOT touch zkVMs.
  → cannot claim "first measured Aurora proving of an AO-hash PQ
  signature" nor constraint-count SOTA; CAN claim the zkVM arm + the
  cross-substrate comparison + the precompile.
- **s2morrow** (starkware-bitcoin GitHub, 2025): Falcon512 + SPHINCS+-128s
  batch verification in Cairo/Stwo (NOT Dilithium as previously believed).
  No published benchmarks, no comparison arm, no custom precompile, no
  credentials. Narrows "PQ signature in a zkVM" primacy only.
- **Policharla et al., ePrint 2023/414**: PQ Privacy Pass via zkDilithium
  in a hand-written Winterfell STARK; pre-empts "PQ anoncreds via
  general-purpose ZK proof of signature verification" (2023). No zkVM,
  modified scheme. The thesis novelty must rest on substrate comparison +
  unmodified-scheme measurement + precompile.
- **zk-creds (S&P 2023)**: orthogonal (pairing-based, BDEC's lineage).
- **Arguzz (arXiv 2509.10819)**: zkVM soundness/completeness FUZZER, found
  11 bugs incl. a $50k RISC Zero bounty — cite as motivation for written
  AIR soundness arguments, not a threat.
- **Pegasus/PegaRing (ePrint 2025/1841)**: new Σ-protocol signature from
  the same PRF family (Monash group overlapping Loquat authors) — narrows
  the PLUM/Loquat motivation, orthogonal to the measurement claim.
- **HAPPIER (LightSec 2025/LNCS 16216)**: XMSS aggregation in RISC Zero on
  a laptop (built-in SHA precompile only). **Kota (Medium, 2025-12-08)**:
  Dilithium verify in SP1, 5.6M cycles, guest-code NTT (not a precompile),
  network proving. **leanMultisig**: XMSS on M4 Max, special-purpose zkVM.
- **Corroboration to cite**: Anoma forum benchmark (Feb 2026) — k256
  precompile cuts cycles 17–39× with only modest prove-time gains; the
  thesis's cycle-vs-wall-clock divergence is independently observed.
- Confirmed absences (search angles that returned nothing): no PQ-signature
  custom precompile in any zkVM; no PQ anoncred measured inside a
  general-purpose zkVM; no third-party PLUM implementation; SP1 issue
  #2315 confirms absence of + demand for large-field AO-hash precompiles.

**Scoped novelty claim that survives:** first same-hardware, same-scheme
measured proving-cost comparison of an (unmodified) PQ signature
verification between a general-purpose zkVM and a static circuit-SNARK;
first custom large-prime-field algebraic-hash precompile in a
general-purpose zkVM; a cost model explaining why cycle reduction does not
deliver wall-clock reduction.

## 3. Version drift — no invalidating changes as of 2026-06-10

- SP1 latest v6.2.4 (2026-06-08); since the v6.2.1 pin only minor
  memory-hygiene fixes, no shard streaming, no Metal/Apple-silicon proving
  (GPU = CUDA only); official guidance "CPU 16 GB+, Groth16/PLONK
  aggregation 32 GB+" is CONSISTENT with (citable for) the 24 GB OOM wall.
- RISC Zero stable 3.0.5 (2026-02-03). One item to disclose: 3.0.5
  backports "Avoid unbounded host buffer allocation during execution" — the
  anomaly run was on 3.0.3, so a 3.0.5 re-run could shift host RSS
  behaviour. v5.0.0-rc.1 exists but is empty of prover changes.
- No hash-based ZK wrap shipped or announced by either project.

## Actions these findings force (queued)

1. Rescope the dual obstruction per-substrate (combine with the
   claim-graph workflow's edit plan).
2. Related-work additions: CAPSS (mandatory), Policharla, s2morrow,
   HAPPIER, Arguzz, PegaRing, Anoma corroboration.
3. Scope every "first" in abstract/intro to the surviving conjunction.
4. Threats-to-validity: version pins (SP1 v6.2.1-fork/v6.2.4 landscape,
   risc0 3.0.3 vs 3.0.5 host-buffer fix), RISC Zero composite-vs-succinct
   blinding distinction.
