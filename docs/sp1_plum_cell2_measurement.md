# SP1 PLUM measurements

End-to-end SP1 proof-generation measurements for PLUM signature
verification on the thesis's target hardware.

## Hardware

- **MacBook Pro M5 Pro**, 18-core CPU, 20-core GPU, **24 GB RAM**, 1 TB SSD.
- macOS 25.5.0 (Darwin), Apple Silicon.

## Four-cell evaluation (per thesis goal)

| Cell | Configuration                                                      | Status |
|------|--------------------------------------------------------------------|--------|
| 1    | PLUM-Griffin in SP1 zkVM, Griffin in rv32im (no precompile)        | OOM-killed at 87.94% RAM, ~1m45s |
| 2    | PLUM-Griffin in SP1 zkVM, Griffin via `GRIFFIN_FP192_PERMUTE` precompile | **PASSES** with memory-tuned env vars (this dir) |
| 3    | PLUM-SHA in SP1 zkVM (control)                                     | not run |
| 4    | PLUM-Griffin in Aurora/STIR (in-SNARK reference)                   | from paper Table 1 |

## Cell 2 result (2026-05-20)

| Metric | Value |
|---|---|
| Configuration | PLUM-80, SP1 v6.2.1 (forked), Griffin Fp192 precompile active |
| setup_ms | 788 |
| **prove_ms** | **1,952,069** (= 32.53 min = 0.54 h) |
| verify_ms | 3,058 (≈ 3 seconds) |
| Peak memory | 81.31% (~19.5 GB of 24 GB) |
| Outcome | proof verified ✓ |

Log: `cell2_prove_syscall_tuned.log`.

### Memory-tuning env vars that made it fit

Default SP1 settings OOM-kill on M5 Pro 24GB at ~3 minutes (silently,
via macOS Jetsam — no log message). The configuration below kept
peak memory at ~81% (within Jetsam's tolerance) at the cost of more
shards = more sequential prove time:

```bash
SHARD_SIZE=4194304            # 2^22 (default 2^24 = 16M cycles/shard)
ELEMENT_THRESHOLD=67108864    # 2^26 (default 2^28 + 2^27 = 384M elements/shard's traces)
HEIGHT_THRESHOLD=1048576      # 2^20 (default 2^22 = 4M rows/chip-per-shard)
TRACE_CHUNK_SLOTS=2           # 2 (default 5; saves ~768 MB shared-memory ring)
RAYON_NUM_THREADS=8           # 8 (default = 18 cores on M5 Pro; fewer concurrent buffers)
```

Each env var documented in `sp1_core_executor::opts` (`SP1CoreOpts::default`,
`MAX_SHARD_SIZE`, `ELEMENT_THRESHOLD`, `HEIGHT_THRESHOLD`,
`MINIMAL_TRACE_CHUNK_THRESHOLD`, `DEFAULT_TRACE_CHUNK_SLOTS`).

### Reproducer

```bash
cd platforms/zkvms/sp1
SHARD_SIZE=4194304 ELEMENT_THRESHOLD=67108864 HEIGHT_THRESHOLD=1048576 \
  TRACE_CHUNK_SLOTS=2 RAYON_NUM_THREADS=8 \
  PLUM_HOST_MODE=prove PLUM_PROVE_ARM=syscall \
  RUST_LOG=warn cargo run --release --bin plum_host
```

Run takes ~5 min build + ~33 min prove + ~3 s verify.

## Cell 1 baseline (2026-05-18)

| Metric | Value |
|---|---|
| Configuration | PLUM-80, SP1 default settings, Griffin in rv32im (`griffin-emulated` feature) |
| setup_ms | 465 |
| prove_ms | DNF — OOM-killed at ~1m45s wall, peak 87.94% memory |
| Outcome | proof not produced |

Log: `cell1_prove_rv32im_griffin.log` + `cell1_prove_rv32im_griffin_retry.log`.

Cell 1 was not retried with the Cell 2 memory-tuning env vars; the
expected outcome would be very slow (more cycles to prove) but
possibly fitting on M5 Pro. Not measured because the precompile's
proof-time advantage is more directly measurable via Cell 2.

## Headline finding (thesis goal)

> "Reduce the proof-generation time for PLUM signature verification
> inside a general-purpose zero-knowledge virtual machine (RISC Zero
> and SP1) to a practically acceptable time on a personal PC."

**Cell 2 with the custom Griffin Fp192 precompile produces a valid
proof in 32.53 minutes wall time on M5 Pro 24GB.** Cell 1 (the
rv32im baseline) doesn't complete on the same hardware due to
memory pressure.

Whether 32.53 min is "practically acceptable" remains to be settled
operationally (per Wu AQ7). This document records the measurement;
the answer to the open question lies with the Operator's downstream
use case.

### Comparison context

Per PLUM paper Table 1 (p. 113), Plum-80's verify time WITHOUT
SNARK is **0.04 seconds** (native verifier). The 32.53-minute SP1
prove time represents the cost of producing a zero-knowledge
*succinct argument* that the verification ran correctly — a
different security model (post-quantum, zero-knowledge, succinct)
than the native verifier.

Comparison to other PLUM/Loquat SNARK times in the paper depends on
whether they're (a) signing time tP, (b) verify time tV, (c) proof
generation in a zkVM. The thesis goal is specifically (c).

## Notes on the precompile

- Phase 3d-stage-3 (Griffin Fp192 AIR) completed 2026-05-20 (commit
  `1eed767` in parent repo).
- Smoke prove (single Griffin syscall, no PLUM context) completes
  in 13.04 s — establishes the chip's per-syscall lower bound.
- Adversarial probe (7 cases: honest + 6 tamper) passes — chip is
  integrated correctly with PLUM verify.
