# Finding: RISC Zero succinct STARK prove does not complete for PLUM-in-BDEC CreGen on M5 Pro 24 GB

**Date**: 2026-05-30 06:00 JST. **Status**: reproducible failure, root cause undetermined.

This document records a quantitative negative result: the default RISC Zero `ProverOpts::succinct()` prove path does not produce a valid receipt for the PLUM-in-BDEC CreGen guest on Apple M5 Pro, 24 GB, within a 15.6-hour wall-clock budget. The failure is not a memory OOM; it is RISC Zero's own recursive verifier rejecting one of its intermediate STARK proofs.

---

## Setup

| Parameter | Value |
|---|---|
| Hardware | Apple M5 Pro, 18-core CPU, 24 GB unified memory |
| OS | macOS 25.5.0 (Darwin) |
| zkVM | RISC Zero 3.0.3 |
| Guest binary | `bdec_credgen_plum_griffin` (two `plum_verify` under shared `pk_u`, Griffin-Fp192 precompile active) |
| Host binary | `bdec_credgen_plum_host`, `BDEC_HOST_MODE=prove`, `BDEC_HOST_SECURITY=80` |
| Prover options | `ProverOpts::succinct()` (default succinct-STARK path) |
| Workload size | 9.4 × 10⁹ guest cycles (execute-mode-measured) |
| Reproducibility | Deterministic ChaCha20 seeds for keygen, signing, nym sampling |

## Observed outcome

The host raised `prove failed: verify segment / verification indicates proof is invalid` at line 260 of `bdec_credgen_plum_host.rs`, which is the `prover.prove_with_opts(...).expect("prove failed")` call site. The Rust process exited with status 101 (panic).

| Resource | Value at exit |
|---|---|
| Wall clock real time | 56,145.32 s ≈ **15.6 h** |
| CPU time used | 883,226 s ≈ **245 CPU-hours** (≈ 16 cores × 15.6 h) |
| Peak RSS | 11.24 GB |
| Peak memory footprint | 13.02 GB |
| M-series cycles elapsed | 3.28 × 10¹⁵ |
| Instructions retired | 7.45 × 10¹⁵ |
| Page faults | 95 (system was not under memory pressure) |
| Receipt produced | None |

## What the failure is not

- **Not an OOM.** Peak RSS 11.24 GB on a 24 GB machine; kernel memory free percentage remained ≥ 70 % throughout.
- **Not a guest-program bug.** Execute mode for the same guest with the same input produces both `Sig.Verify = Accept` deterministically in 65 s. The host-side reproduction of both signatures verifies before submission.
- **Not a host-side serialisation issue.** Earlier serialisation issues were diagnosed and fixed (decoder mismatch between `bincode` and `risc0_zkvm::serde`); the in-flight prove uses the corrected decoder.
- **Not a sleep / interruption issue.** Pre-`caffeinate` sleep gaps totalled ≈ 70 min out of 15.6 h; the failure occurred during normal compute, not at a wake-up boundary. The CPU dipped briefly from 1781 % to 1390 % at elapsed ≈ 883 m, ~ 30–60 s before the panic, but this is consistent with prover internal phase transitions and is not on its own evidence of corruption.

## What the failure is

A soundness check internal to RISC Zero's recursive STARK aggregation step rejected one of its own intermediate proofs. The error message `prove failed: verify segment / verification indicates proof is invalid` is produced by the prover's own verifier, applied to a segment proof during composition.

Candidate causes, in order of plausibility:

1. **A bug in RISC Zero's recursion or segment-composition logic at this workload scale.** At 9.4 × 10⁹ guest cycles the segment count is well past what most public RISC Zero benchmarks exercise; an edge-case bug at high segment counts would be consistent with the observation.
2. **A hardware bit-flip during the 15.6-hour run on non-ECC RAM.** Plausible but rare; would require regeneration to confirm.
3. **A serialisation or numerical edge case at a specific segment boundary.** The fact that the failure happened after many hours rather than at a clean repeatable cycle index argues against a deterministic guest-code bug.

Distinguishing among these requires re-running with `RUST_BACKTRACE=1` and `RUST_LOG=risc0_zkvm=debug` to identify which segment failed. A second 15.6 h gamble is not warranted without a structural reason to expect a different outcome.

## Implications for the thesis

This is a finding, not a failure.

1. **The execute-mode measurement stands.** PLUM-in-BDEC CreGen on RISC Zero, λ=80, with the Griffin-Fp192 precompile active, costs 9.4 × 10⁹ guest cycles and 65 s execute-mode wall on M5 Pro 24 GB. This number is reproducible and is what should be reported.

2. **The prove-mode measurement cannot be reported as a single wall-clock number under this configuration.** The honest statement is: *the default succinct-STARK prove path does not complete within a 15.6-hour budget on M5 Pro 24 GB for this workload.*

3. **The cost calculation in `docs/bdec_plum_risc0_cost_calculation_20260529.md` over-estimates feasibility.** That document predicted ≥ 2 h prove time and a 6–8 h full-lifecycle wall clock. The actual lower bound is now ≥ 15.6 h *without completing.* The full-lifecycle estimate should be revised to a qualitative statement: *the current consumer-hardware zkVM stack does not produce a valid receipt for this workload at all.*

4. **Sako's framing strengthens.** The thesis already argues that consumer-hardware deployability is the bottleneck. The failure of the default prove path makes this argument stronger, not weaker. The story shifts from "slow but tractable" to "not tractable at this configuration; what does it take to make it tractable?"

## Recommended next experiments

In order of cost / informational yield:

1. **Single-`plum_verify` prove on RISC Zero.** Use the existing `plum_verify_griffin` guest, which has been benchmarked single-call. Estimated wall: 30–90 min (half the workload). Outcome:
   - **If it succeeds**: confirms that the precompile and prove pipeline work at single-verify scale; the failure above is specifically a recursion / scale issue.
   - **If it fails the same way**: the precompile or guest has a deeper issue than scale.

2. **Same CreGen guest on SP1.** SP1 uses a different prover pipeline (Plonky3, not recursive STARK). If SP1 prove succeeds where RISC Zero fails, the cross-substrate finding is itself a thesis result.

3. **If both fail, retry on RISC Zero with `RUST_LOG=risc0_zkvm=debug`** to identify the failing segment. Higher diagnostic value, ~ 15 h cost.

The first two are independent experiments and can be queued sequentially overnight. The third is a follow-up if both fail.

## Logs and artefacts

- Driver log: `docs/measurements/risc0_cregen_prove_failed_20260529/bdec_credgen_prove.log`
- Watcher trace: `docs/measurements/risc0_cregen_prove_failed_20260529/prove_watch.log`
- Watcher trace includes elapsed, RSS, CPU %, compressor bytes, swap, kernel free % at 60 s intervals across the 15.6 h run.

---

*Sibling docs: `plum_in_bdec_blocker_20260529.md` (re: deserialisation diagnosis),
`bdec_plum_risc0_cost_calculation_20260529.md` (re: the cost extrapolation that needs revision).*

---
## Correction (2026-06-11)
The "RISC Zero 3.0.3" in the Setup table above is the Cargo.toml *constraint*
(`^3.0.3`), not the resolved version. The repository lockfile (mtime 2026-05-16,
unchanged through the run) resolves risc0-zkvm **3.0.5**, and the compiled
`librisc0_zkvm` rmeta in `target/release` (fingerprint 2026-05-16 17:01) embeds
`risc0-zkvm-3.0.5` source paths. The failing run therefore executed on 3.0.5.
Forensic localization (2026-06-10, desk analysis): the error context
`verify segment` attaches at a single site, `prover_impl.rs:280`, the base-
segment integrity self-check after `prove_core` (identical code in 3.0.3-3.0.5);
the recursion contexts (`verify lift`, `verify join`) never appeared. At the
measured ~40 s/segment, 15.6 h corresponds to ~segment 1,400 of 9,936 — below
the ~4,500 the single-verification workload clears, refuting a segment-count
threshold. The composite re-run (same lockfile, same guest, same seeded input)
covered the failing region without rejection, disfavouring content-deterministic
causes. Surviving candidates: transient error on non-ECC memory over the
~245 CPU-hour run, or a concurrency-sensitive defect in the succinct path's
overlapped prove/lift/join pipeline (the one element composite mode does not
exercise).
