# Personal-computer prove-time and proof-size methodology

The full prove does not complete on the M5 Pro (24 GB). But the two numbers the
narrative needs — **prove time** and **proof size** — are both obtainable on the
personal computer, the first by extrapolation from a measured per-segment rate,
the second because it is a constant of the proof system. Neither needs the
multi-day run or an outsourced prover.

## Three layers, increasing difficulty

| layer | how | status on M5 Pro |
|---|---|---|
| execution: cycles + segments | execute / dev mode (no proof) | **measured**, free, minutes |
| prove time | extrapolate: `segments × per-segment-time` | **estimated** from a measured rate |
| proof size (Groth16/PLONK) | constant of the SNARK, relation-independent | **known**, ~260 B / ~868 B |

## Prove-time extrapolation

RISC0 composite proving proves each segment independently, so the dominant cost
is linear in the segment count:

    prove_time ≈ overhead + (number of segments) × (time per segment)

The per-segment rate was **measured on the M5 Pro** from the composite CreGen
run (terminated). Analysing all 2,452 `prove_segment_core` timestamps gives a
**median 43.5 s/segment** (overall 50.9, p10–p90 = 41–71 s; no non-monotonic
gaps), in `docs/measurements/risc0_cregen_composite_20260531_1553/`. Segment
counts are dev-mode-measured per relation (padded prove cycles / 2²⁰), and are
linear at **~4,963 segments per signature verification**.

| relation | verifications | execute cycles | segments (measured) | est. composite prove (× 43.5 s) |
|---|---|---|---|---|
| PLUM verify | 1 | 4.70e9 | ~4,963 | completes directly (see note) |
| CreGen | 2 | 9.40e9 | 9,933 | ~5.0 days |
| ShowCre k=1 | 3 | 1.41e10 | 14,886 | ~7.5 days |
| ShowCre k=2 | 4 | 1.88e10 | 19,851 | ~10.0 days |

A single PLUM verify proves *much faster per segment* than this (RISC0
`sys_bigint`: 6 h 19 m for ~4,500 segments ≈ 5 s/segment, §6 Table), so it does
not need extrapolation. The ~43.5 s/segment rate is specific to the larger
CreGen/ShowCre composite workloads, where the non-recursive composite receipt's
growing in-memory working set slows per-segment proving. The rate is therefore
config-/workload-dependent; these estimates use the directly measured
CreGen-composite rate.

These are **segment-proving** estimates (composite). A *deployable* Groth16 proof
needs, on top of this, the composite→succinct recursion and the STARK-to-SNARK
wrap — and the wrap is exactly what exceeds the 24 GB budget. So the honest
statement is: on the M5 Pro the deployable proof is **infeasible to generate**
(segment-proving alone is multi-day, and the wrap OOMs), while its **size** is the
known constant below.

## Proof size (a constant, not a measurement)

A SNARK proof is succinct: its size does **not** depend on the relation, the cycle
count, or the segment count. So it is identical for PLUM, CreGen, and ShowCre, and
can be stated directly:

| receipt | size | depends on relation? |
|---|---|---|
| Groth16 seal (RISC0 / SP1) | ~260 B | no (constant) |
| PLONK seal (SP1) | ~868 B | no (constant) |
| succinct STARK receipt | bounded (~hundreds of KB) | weakly |
| composite STARK receipt | scales with segments (GB-scale here) | yes |

The deployable, on-chain-verifiable proof is the ~260 B Groth16 seal, the same for
every relation. That is the proof-size result.

## What this gives the thesis (all on the personal computer)

- execution cost (cycles, segments) — measured;
- prove-time estimate — extrapolated from the measured ≈40 s/segment rate;
- proof size — the SNARK constant (~260 B Groth16 / ~868 B PLONK);
- the frontier finding — the Mac cannot *generate* the deployable proof
  (multi-day segment proving + the 24 GB wrap OOM), even though its size is known.

An outsourced prover (Boundless) or a larger machine would *confirm* the
extrapolation with one completed proof, but is not required for these numbers.
