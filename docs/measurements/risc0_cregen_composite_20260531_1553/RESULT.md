# RISC0 BDEC CreGen composite prove — terminated partial run

- Config: RISC Zero, BDEC CreGen, **prove mode, composite prover, λ=80**.
- Started 2026-05-31 15:53; terminated 2026-06-02 (elapsed ~01-10:40:29).
- Progress at kill: **2452 / 9936 segments (~24.6%)** proved.
- Steady rate ~40 s/segment throughout (no slowdown, no thermal throttle); RSS ~9.9 GB of 24; swap stable ~2.9 GB system-wide.
- Projection at this rate: ~4.6 days for all 9936 segment proofs, then the final composite recursion (lift/join of 9936 receipts; untested at scale; the earlier *succinct* run failed at the analogous final verify step).
- Terminated to restructure the benchmark for a correct full-system run (CreGen + ShowCre inside the zkVM; Setup/PriGen/NymKey/CreVer/ShowVer/RevCre outside) with a zero-knowledge wrap of the succinct receipts.
