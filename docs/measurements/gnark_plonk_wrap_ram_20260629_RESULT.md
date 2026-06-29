# gnark PLONK wrap-stage peak RAM — trivial-guest probe (RESULT)

Date: 2026-06-29 (run 2026-06-28T17:14–17:28 UTC)
Machine: M5 Pro, 18-core, 24 GB RAM (hw.memsize 25769803776). SP1_PROVER=cpu.
SP1 fork: submodules/sp1 @ 98a376e (v6.2.1), SP1_CIRCUIT_VERSION=v6.1.0.
Circuit: v6.1.0-plonk (BN254), downloaded from sp1-circuits S3 (2.30 GB tar;
  plonk_pk.bin 2.1 GB, plonk_circuit.bin 664 MB), extracted to ~/.sp1/circuits/plonk/v6.1.0.
Recursion shape: STOCK compress_shape.json (restored from committed/.bak for the run;
  NOT the regenerated PLUM shape) so the trivial guest's vks are in the stock vk_map allowlist.
Guest: trivial Fibonacci (100 iters), pure rv32im, NO precompile / NO custom syscall.
Path: client.prove(&pk, stdin).plonk().run()  (core -> compress -> shrink -> wrap -> gnark PLONK).
Build note: workspace [profile.release] lto="fat" FAILS to link the host
  (reqwest/tonic "required in rlib format, not found in this form") once the prover
  cache is invalidated; built with CARGO_PROFILE_RELEASE_LTO=false (host LTO is
  irrelevant to gnark-stage RAM, which is native cgo/BN254).
Runs: n=1 (single run; gated probe).

## Numbers (program-INDEPENDENT wrap circuit)
- gnark PLONK circuit size: nbConstraints = 27,576,375 (BN254). Fixed wrap circuit;
  verifies a fixed shrink-proof shape -> independent of the guest program.
- gnark prover wall: 688,036 ms = 688.0 s = 11.47 min (gnark "prover done" log).
- whole .plonk().run() wall: 839.3 s = 13.99 min.
- PEAK RSS (getrusage RUSAGE_SELF ru_maxrss, whole run): 15,398,699,008 B = 15.40 GB.
- Peak phase: the gnark PLONK stage. SP1 "Memory usage is high: 80–83%" warnings fire
  ONLY in the 17:21–17:28 gnark window; the pre-gnark recursion phase showed no high-mem
  warning and ps-sampled ~10.1 GB. (Coarse 2 s ps sampler under-sampled the true peak at
  ~10.5 GB; getrusage 15.40 GB is authoritative.)
- FITS 24 GB: YES (15.40 GB peak; ~64% of 24 GB). Real PLONK proof emitted (964 bytes).

## Scope / honesty
- This measures the RESOURCE cost (peak RAM, time) of the program-independent gnark PLONK
  wrap stage. It is NOT a valid PLUM ZK proof. Because the wrap circuit is fixed (it verifies
  a fixed shrink-proof, not PLUM witness data), this 15.40 GB transfers to the gnark stage of
  a PLUM ZK-wrap.
- The PLUM-specific soundness path (51 h vk_map / shape regen for the PLUM core+recursion vks)
  is a SEPARATE cost not measured here.
- Recursion-stage peak (~10.1 GB) and gnark-stage peak (15.40 GB) are both < 24 GB on this run,
  for the trivial guest. A real PLUM core proof's core/recursion RAM is larger and is the
  separately-measured constraint; this probe isolates only the wrap (gnark) stage.
