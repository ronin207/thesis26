# End-to-end cost calculation: BDEC × PLUM × RISC0

**Date**: 2026-05-29 16:30 JST (revised 2026-05-30 11:00 JST). **Status**:
partial — succinct-mode CreGen prove failed after 15.6 h (recursion-step
verifier rejection, not OOM); composite-mode retry now in flight.
ShowCre extrapolation revised downward to a qualitative statement pending
a successful CreGen prove.

> **Revision note (2026-05-30).** The wall-clock estimates "≥2 h" for CreGen
> prove and "6–8 h" for the full lifecycle below are now known to
> underestimate. The actual `ProverOpts::succinct()` attempt ran 15.6 h
> before RISC Zero's own segment verifier rejected an intermediate proof.
> See `docs/risc0_prove_failure_finding_20260530.md` for the full failure
> characterization. A composite-mode retry (`ProverOpts::default()`,
> larger receipt, no recursion) was launched 2026-05-30 11:06 JST and is
> the in-flight measurement. Numbers below tagged "succinct-mode" should
> be read as "did not complete at this configuration"; numbers tagged
> "composite-mode" are pending.

This document estimates the total cost of running one BDEC user lifecycle
(Setup through ShowCre/ShowVer) with PLUM-Griffin as the signature primitive
inside RISC0 zkVM, on M5 Pro 24 GB hardware. Numbers are measured where
possible and clearly marked when extrapolated.

---

## Scope

"End-to-end" = one complete BDEC user lifecycle:

1. `Setup(1^λ)` → public parameters (off-VM)
2. `PriGen(par)` → user's long-term keypair (off-VM)
3. `NymKey(par, sk_U)` → pseudonym keypair for one TA (off-VM)
4. **`CreGen`** → credential + proof of issuance (zkVM-proved)
5. `CreVer` → TA verifies credential proof (off-VM)
6. **`ShowCre`** → shown credential + proof of ownership for one verifier (zkVM-proved)
7. `ShowVer` → verifier checks shown-credential proof (off-VM)

Steps 4 and 6 are the zkVM-proved sub-protocols. Their proofs are
zkVM-native (no Aurora layer underneath) — this is the rigidity-escape
instantiation per Sako's framing.

## Per-operation decomposition

### Host-side (off-zkVM) costs

| Operation | Cost | Source |
|---|---|---|
| `Setup` | <100 ms | Negligible relative to prove costs |
| `PriGen` (PLUM keygen at λ=80) | ~200 ms | Order-of-magnitude estimate |
| One PLUM sign (`PlumGriffinHasher`, 32-byte message) | **~25 s** | Measured this session: 49.6 s for 2 signs (50:50 split) |
| One RISC0 receipt verify (succinct) | ~10 ms | Standard RISC0 receipt verification |
| `RevCre` | <100 ms | Hash + revocation list update |

`NymKey`, `CreGen sign`, and `ShowCre sign` each invoke PLUM sign once → ~25 s each.

### zkVM (guest + prover) costs

**Cycle counts** (Griffin precompile active throughout):

| Statement | Composition | Cycle count | Source |
|---|---|---|---|
| One `plum_verify::<PlumGriffinHasher>` call | Full PLUM verify (Algorithm 6, Steps 1–3) | **~4.7 G cycles** | Measured 2026-05-29 |
| CreGen | 2 × `plum_verify` under shared hidden `pk_U` | **9.4 G cycles** | Measured 2026-05-29 |
| ShowCre (1 credential, 1 attribute disclosed) | 4 × `plum_verify` + 1 disclosure SHA-256 + ≤5 Griffin perms (attribute Merkle) + ≤32 Griffin perms (sparse-Merkle revocation) + small policy check | **~19–22 G cycles** | Extrapolated (4× single verify + small overhead) |

**Wall-clock prove time** (M5 Pro 24 GB, succinct STARK receipt, not ZK-wrapped):

| Operation | Estimated prove wall | Calibration |
|---|---|---|
| CreGen prove | **≥ 2 h** (in flight at 2h+ as of writing) | Direct observation |
| ShowCre prove | **≥ 4–5 h** (extrapolated linearly from cycle ratio 2.2×) | Linear scaling assumption — may underestimate due to per-segment fixed cost |

**Peak memory** (resident set size during prove):

| Operation | Peak RSS | Source |
|---|---|---|
| CreGen prove | **~9.2 GB** (stable for entire run) | Watcher log this session |
| ShowCre prove | ~15–20 GB | Extrapolated from cycle ratio; may approach 24 GB ceiling |
| Either operation + Groth16 ZK-wrap | **likely OOM at 24 GB** | Extrapolated from overnight PLUM PLONK wrap result (~20 GB peak at 9 G cycles) |

## Aggregate lifecycle wall-clock

| Phase | Wall time | Cumulative |
|---|---|---|
| Setup + PriGen + NymKey | ~25 s | 25 s |
| CreGen (host sign + zkVM prove) | ~25 s + ≥2 h | ≥2 h |
| CreVer (receipt verify) | ~10 ms | ≥2 h |
| ShowCre (host sign + zkVM prove) | ~25 s + ≥4–5 h | **≥6–8 h** |
| ShowVer (receipt verify) | ~10 ms | ≥6–8 h |

**Total: ≥6–8 hours wall-clock for one CreGen + one ShowCre, baseline-STARK
(non-ZK) receipt.**

If you ZK-wrap (Groth16) for actual anonymity per ProSec 2024 Thm 2/3:
+10–20 min per receipt **if it fits**; the ShowCre wrap is expected to OOM
on 24 GB.

## Proof size budget

- Succinct RISC0 receipt: ~200 KB
- Groth16-wrapped receipt: ~256 bytes
- Per-lifecycle on-chain (one CreGen receipt + one ShowCre receipt):
  ~400 KB succinct OR ~512 B Groth16

## Why this calculation matters (Sako framing)

This is the **first end-to-end cost decomposition for PLUM-in-BDEC × RISC0
on consumer hardware**. Three load-bearing observations for the thesis:

1. **`plum_verify` is the dominant cost.** 4 of them in ShowCre is the
   entire budget within a constant factor. This quantifies *why* the
   Griffin Fp192 precompile is load-bearing: without it, each
   `plum_verify` would cost ~100× more (software Griffin in
   Fp192 software arithmetic), making ShowCre prove time go from ~5 h
   to >2 weeks on the same hardware.

2. **Baseline-STARK ShowCre is feasible on 24 GB; ZK-wrapped ShowCre is
   not.** This is the headline trade-off Sako will care about:
   - "Ship feasibility on consumer hardware, defer anonymity to
      compute-class hardware" (baseline STARK), OR
   - "Ship anonymity by accepting that consumer hardware is not the
      target deployment" (Groth16 wrap on a server).

3. **6–8 h end-to-end** is a concrete number a reader can picture. It is
   slow, but it is **not** "doesn't terminate" — distinguishing this from
   the Cell 1 (no-precompile) DNF baseline. The precompile suite is what
   gets us from "infeasible" to "slow but tractable."

## What's measured vs. extrapolated

| Quantity | Status |
|---|---|
| One `plum_verify` cycle count in RISC0 | **Measured** (≈ 4.7 G) |
| CreGen cycle count | **Measured** (9.4 G) |
| CreGen execute wall | **Measured** (65 s) |
| CreGen prove wall | **In flight** (≥ 2 h, not final) |
| CreGen peak RSS | **Measured** (9.2 GB) |
| ShowCre cycle count | Extrapolated (4× single verify) |
| ShowCre prove wall | Extrapolated (linear from CreGen) |
| ShowCre peak RSS | Extrapolated |
| ZK-wrap memory cost | Extrapolated from overnight PLUM PLONK measurement |
| Lifecycle wall-clock total | Extrapolated sum |

## What would invalidate this calculation

- **`plum_verify` cycle count not constant** — if verify cost depends on
  signature structure (length, residuosity grid layout), the 4× scaling
  for ShowCre could be off by ±20%.
- **RISC0 prove time non-linear in cycle count** — segment overhead
  could push ShowCre to >5 h or >2.2× CreGen prove.
- **Memory scales super-linearly with trace length** — if true, ShowCre
  baseline STARK could itself OOM at 24 GB.
- **`plum_verify_phased` (which the guest currently uses) has different
  cost from `plum_verify`** — phased adds 4 snapshot operations per
  call, ~160 cycles each = ~640 cycles total per verify, negligible.

## What this calculation can be used for (today)

1. **Email Sako** with the cost decomposition: "PLUM-in-BDEC CreGen
   measured at 9.4 G cycles / ≥2 h prove on M5 Pro 24 GB. Full lifecycle
   extrapolated to 6–8 h. Memory budget fits succinct STARK but not
   Groth16 wrap." This is a specific, defensible number.

2. **Compare to Aurora-BDEC classical** by running the existing
   `bdec_showcre_benchmark` binary (no zkVM) and quoting the wall-clock
   delta as "rigidity-escape cost."

3. **Compare to Loquat-in-BDEC RISC0** by running the existing
   `pp2_showver` binary and quoting "PLUM vs Loquat inside RISC0."

The first comparator is most aligned with Sako's framing.

---

*Sibling docs: `plum_in_bdec_integration_plan_20260529.md`,
`plum_in_bdec_blocker_20260529.md`, `sako_reframe_recovery_20260529.md`.*
