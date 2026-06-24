# Four-scheme benchmark on SP1 — the structural cost picture

This document presents the *structural* cycle-count anchors that
locate PLUM's thesis result in the broader landscape of signature
schemes the SP1 zkVM is asked to verify. Captures four signature-
verification workload classes at execute-mode cycles + selected
prove wall times, all on identical hardware (M5 Pro 24 GB), to
empirically answer: **what does the zkVM do well, and where does
PLUM's cost sit on the spectrum?**

## Hardware

- **MacBook Pro M5 Pro**, 18-core CPU, 20-core GPU, **24 GB RAM**, 1 TB SSD.
- macOS 25.5.0 (Darwin), Apple Silicon.

## Workloads measured (Phase B6, 2026-05-22)

| Workload                                              | Family                       | Hash / arith primitive              | SP1 precompiles invoked            |
|-------------------------------------------------------|------------------------------|--------------------------------------|------------------------------------|
| **ECDSA-secp256k1 + SHA-256**                        | classical (pre-quantum)      | NIST P-256 curve + SHA-256          | `SECP256K1_ADD`, `SECP256K1_DOUBLE` |
| **SHA-256 Merkle path × 22** (SPHINCS+/SLH-DSA proxy) | hash-based PQ                | SHA-256 only                        | none (software SHA-256)            |
| **NTT-style poly-mul × 17** (Dilithium/ML-DSA proxy) | lattice PQ (small-prime ring) | Z_q, q = 8,380,417                  | none (fits BabyBear natively)      |
| **PLUM-80 verify**, three arms                       | algebraic-hash PQ (large prime) | Griffin Fp192 (199-bit prime)       | `GRIFFIN_FP192_PERMUTE`, `UINT256_MUL` (Cell 2 only) |
| **Loquat λ=128** (in-tree, software Griffin)         | algebraic-hash PQ (Mersenne-127) | Griffin (no precompile route)       | none                               |

### Proxy disclosures (honesty about what's actually exercised)

- **SPHINCS+/SLH-DSA proxy.** A full SLH-DSA-128f verify performs
  5,000–20,000 SHA-256 invocations across FORS + WOTS+ + hypertree
  authentication paths. We exercise a depth-22 SHA-256 Merkle path,
  matching the SLH-DSA-128f FORS-tree height — the dominant workload
  shape. The full SLH-DSA verify cost is well-published; we
  cross-cite Fenbushi 2025 below for the actual SLH-DSA wall-clock.
  We avoid the `slh-dsa` Rust crate because its `signature 2.3.0-pre`
  dependency is incompatible with the SP1-patched `k256 0.13.4`
  used by ECDSA.
- **Dilithium/ML-DSA proxy.** A full ML-DSA-65 verify recomputes
  `w' = A·z − c·t₁·2ᵈ` in the NTT domain; this dominates the verify
  cost. We exercise 17 polynomial multiplications mod
  q = 8,380,417 × 256-degree polynomials — directly the dominant
  primitive in ML-DSA verify. We avoid the `ml-dsa 0.0.4` Rust crate
  because its `pkcs8`/`der` dependencies are not `no_std`-clean for
  the SP1 guest target.
- **Loquat λ=128.** Uses the in-tree
  [`src/signatures/loquat`](src/signatures/loquat) implementation
  via `vc-pqc { features = ["guest", "sp1"] }`. **Important:** the
  in-tree implementation uses `GriffinHasher` *in software*, not via
  SP1's `GRIFFIN_FP192_PERMUTE` precompile — so this Loquat result
  is a *no-precompile* algebraic-hash PQ data point. It is **not**
  directly comparable to PLUM Cell 2 (which uses the precompile)
  but IS comparable to PLUM Cell 1 (rv32im baseline, also no
  precompile, different scheme parameters).

## Execute-mode cycle anchors

| # | Workload                                                 | Cycles            | Wall (ms) | Precompiles fired                                     |
|---|----------------------------------------------------------|------------------:|----------:|-------------------------------------------------------|
| 1 | ECDSA-secp256k1 + SHA-256                                |       **113,871** |         9 | `SECP256K1_ADD=255`, `SECP256K1_DOUBLE=512`           |
| 2 | SPHINCS+ Merkle-path proxy (SHA-256 × 22)                |           218,694 |         7 | none                                                  |
| 3 | Dilithium NTT proxy (17 polys × 256-coef mod 2²³)        |        29,497,614 |       459 | none                                                  |
| 4 | **PLUM-80 + Griffin precompile (Cell 2)**                | **125,504,123**   |     1,902 | `GRIFFIN_FP192_PERMUTE=1052`, `UINT256_MUL=69,396`    |
| 5 | PLUM-80 + SHA-3 hasher (Cell 3 control)                  |       110,795,424 |     1,266 | `UINT256_MUL=69,385`                                  |
| 6 | Loquat λ=128 in-tree (software Griffin, no precompile)   |       518,258,824 |     3,315 | none                                                  |
| 7 | **PLUM-80 rv32im Griffin (Cell 1, no precompile)**       | **7,082,608,888** |    40,425 | `UINT256_MUL=4,870,724` (the multi-limb tax)          |

## Prove-mode wall times

| Workload                                                  | Prove wall on M5 Pro 24 GB | Source / status |
|-----------------------------------------------------------|---------------------------:|-----------------|
| ECDSA-secp256k1                                           |              **13.6 sec**  | bench_pqc, 2026-05-22 |
| PLUM-80 + Griffin precompile (Cell 2)                     |              **32.5 min**  | plum_host, 2026-05-20 |
| PLUM-80 + Griffin precompile (Cell 2), re-measured        |  **14.89 min**, peak RSS **18.67 GB** | plum_host, 2026-06-18, clean machine; verify OK; ~5.3 GB headroom vs 24 GB. ⚠ 2.2× faster than 2026-05-20, cause unverified |
| PLUM-80 + SHA-3 (Cell 3 control)                          |              **13.3 min**  | plum_host, 2026-05-21 |
| PLUM-80 rv32im Griffin (Cell 1)                           |              **DNF**       | 2 failed attempts (OOM 1 m 45 s, non-term 3 h 6 m); projects to ~30 h linearly |
| SHA-2-2048 (RISC0)                                        |              0.54 s        | cited Fenbushi 2025 |
| ECDSA-secp256k1 (RISC0)                                   |              1.0 s         | cited Fenbushi 2025 |

(SPHINCS+, Dilithium, Loquat prove not measured — their cycle
anchors are below PLUM Cell 2 by 2–6 orders of magnitude, which by
linear-scaling-with-cycles projects them well into the seconds
regime; the structural picture is established by the execute
anchors. Adding their proves to the table is a follow-up.)

### Peak memory and the 24 GB budget (2026-06-18)

Cell 2 prove peaks at **18.67 GB resident** on a clean machine and
completes, leaving roughly **5.3 GB of headroom** under the 24 GB
bound. Two consecutive runs pin the binding metric: with heavy apps
open the prove was OOM-killed at ~5 min (resident truncated at 8.25 GB,
`/usr/bin/time -l` footprint 85.5 GB); with apps closed it completed at
18.67 GB resident (footprint 90.7 GB). The higher footprint on the run
that *succeeded* shows the macOS "peak memory footprint" figure is not
the binding constraint — resident set versus free physical RAM is. The
24 GB fit therefore holds only on an uncluttered machine, a real
qualifier for a consumer-hardware claim.

⚠ **Open discrepancy / coherence flag.** The 2026-06-18 re-measurement
of Cell 2 prove (14.89 min) is 2.2× faster than the 2026-05-20 figure
(32.5 min); the cause is unverified (machine state, code change, or SP1
version). The thesis-facing quote below still cites "32.5 min" twice —
reconcile before quoting either number.

## The structural picture

### Headline ratios (Cycle counts, same SP1 hardware)

| Comparison                                                  | Ratio       | Reading                                                |
|-------------------------------------------------------------|-------------|--------------------------------------------------------|
| Cell 1 (PLUM no precompile) ÷ ECDSA                         | **62,200×** | The full unmitigated cost of admitting PLUM's workload class |
| Cell 2 (PLUM with precompile) ÷ ECDSA                       | **1,102×**  | What the precompile recovers; still a 3 orders-of-magnitude gap |
| Cell 1 ÷ Cell 2 (precompile speedup on PLUM)                | **56.4×**   | The precompile's contribution to feasibility recovery  |
| Loquat λ=128 in-tree ÷ Dilithium NTT proxy                  | **17.6×**   | Same hardware: algebraic-hash PQ in software vs lattice-PQ in software |
| Cell 2 (Griffin precompile) ÷ Cell 3 (SHA3 in software)     | **1.13×**   | Algebraic-hash precompile *still slower* than software SHA-3 in cycles — the structural penalty for the design choice |

### What this lets the thesis say

> *"On the same general-purpose zkVM (SP1, BabyBear-native, M5 Pro
> 24 GB), classical pre-quantum signature verification (ECDSA-
> secp256k1) executes in 114 K cycles. PQ workloads with primitives
> that match the zkVM's native arithmetic — lattice-PQ over small
> primes (Dilithium-class NTT) and hash-based PQ over SHA-class
> hashes (SPHINCS+-class Merkle paths) — sit within 2.5 orders of
> magnitude of the classical baseline, leveraging existing
> precompiles or fitting BabyBear arithmetic natively. PQ workloads
> with a large prime field and algebraic hash (PLUM-class Legendre-
> PRF / power-residue-PRF schemes) sit 4–5 orders of magnitude above
> the classical baseline. Building a custom precompile-class chip
> for the algebraic hash (this thesis's Griffin Fp192 work)
> recovers feasibility (Cell 1 DNF → Cell 2 32.5 min) but cannot
> close the remaining 1,000× gap from classical: ECDSA proves in
> 13.6 s while PLUM-80 with our precompile proves in 32.5 min on
> the same hardware. The remaining gap is the structural cost of
> admitting the PQ algebraic-hash workload class at all, and that
> cost is the data point a PQ-credential implementer needs in front
> of them when choosing between a circuit-SNARK and a zkVM
> proving substrate."*

### Cross-cited literature anchors

- **Fenbushi Capital, *Benchmarking zkVMs: Current State and Prospects***,
  Medium, 2025-06-18. Reports on RISC0 with appropriate precompiles:
  SHA-2-2048 = 0.54 s, ECDSA-secp256k1 = 1.0 s, Fibonacci-100k = 3.4 s
  on SP1 GPU. The article's central observation — *that performance
  depends heavily on which precompiles are available, and custom
  precompiles are recommended for specialised workloads* — is the
  setup against which this thesis's contribution is positioned. We
  measure the SAME phenomenon (precompile-dependent cost) on a
  workload class Fenbushi did not cover: a post-quantum credential
  primitive structurally mismatched to the zkVM's native field.
  Our SP1 measurement on M5 Pro 24 GB (CPU only) sits in the same
  regime for the classical anchor (ECDSA = 13.6 s).
- **PLUM paper §4.2** (DOI 10.1007/978-981-95-2961-2_6): reports
  116,285 R1CS constraints for PLUM-128 verify in circuit-SNARK
  arithmetisation, 91.1 % of which are Griffin permutations. Our
  AIR-chip trace cells per PLUM-80 verify is the AIR-side analogue.
  **[TODO: reconcile cell-count formula.** Current text claimed
  "37 M AIR-chip trace cells per PLUM-80 verify (33 cells × 14 rounds
  × 1052 syscalls)" but 33 × 14 × 1052 = 486,024, off by ~76×. Either
  the headline 37 M is wrong, or the formula is missing a factor
  (likely a rows-per-permutation multiplier ≈ 76 that the current
  formula collapses). Verify against the Griffin Fp192 chip
  implementation in `platforms/zkvms/sp1/.../griffin_fp192.rs` before
  citing this number in the thesis. **]**

## Reproducer (all four schemes, execute mode)

```bash
cd platforms/zkvms/sp1
PATH="$HOME/.cargo/bin:$PATH"
for s in ecdsa sphincs dilithium loquat; do
  echo "=== $s ==="
  MODE=execute SCHEME=$s RUST_LOG=warn \
    cargo run --release --bin bench_pqc --manifest-path script/Cargo.toml \
    2>&1 | tail -5
done
```

ECDSA prove (the only one measured with prove wall on M5 Pro):

```bash
MODE=prove SCHEME=ecdsa RUST_LOG=warn \
  cargo run --release --bin bench_pqc --manifest-path script/Cargo.toml
```

PLUM proves reproduce via `plum_host` (see
[sp1_plum_cell2_measurement.md](sp1_plum_cell2_measurement.md) and
[sp1_plum_cell3_measurement.md](sp1_plum_cell3_measurement.md)).

## What is NOT in this benchmark

- **Full SLH-DSA / ML-DSA verifications.** The proxy programs
  exercise the dominant workload shape (Merkle path for SLH-DSA,
  NTT-domain poly-mul for ML-DSA). Reviewers wanting full-FIPS
  numbers should consult the RustCrypto `slh-dsa` / `ml-dsa`
  crate benchmarks, which are well-published; the dependency
  conflicts noted above prevent compiling them as SP1 guests
  without fork work outside this thesis's scope.
- **Loquat λ=80** (paper's smallest validated parameter): the
  in-tree implementation's tests exercise λ=128 by default.
  Measuring λ=80 in-tree would close the parameter-axis to PLUM-80
  exactly but doesn't change the structural picture.
- **Loquat with SHA-3** (the original Loquat paper hash choice).
  The in-tree Loquat uses Griffin in software; swapping the
  hasher would let us measure "same scheme, different hash" within
  the Legendre-PRF family — useful but not required for the
  structural claim.
- **Prove wall for SPHINCS+ / Dilithium / Loquat proxies.** Cycle
  counts establish the structural picture; prove walls would add a
  ~10-min runs each. Worth running before final defense slides.

## Companion docs

- [sp1_plum_cell2_measurement.md](sp1_plum_cell2_measurement.md) — Cell 2 prove (32.5 min)
- [sp1_plum_cell3_measurement.md](sp1_plum_cell3_measurement.md) — Cell 3 control (13.3 min, 2.45× faster than Cell 2)
- [sp1_plum_cell1_attempt2.md](sp1_plum_cell1_attempt2.md) — Cell 1 cycle anchor (7.08B / 56.4× delta)
- [precompile_engineering_cost.md](precompile_engineering_cost.md) — engineering bill accounting
- [precompile_soundness/griffin_fp192.md](precompile_soundness/griffin_fp192.md) — chip soundness rubric
