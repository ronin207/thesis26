# SP1 PLUM-SHA3 (Cell 3) — execute-mode measurement

Cell 3 is the **control arm** that isolates whether Cell 2's
feasibility win is Griffin-specific (algebraic-hash precompile) or
generic to any precompile-class hash. This document records the
execute-mode (no-proof) cycle baseline for PLUM-SHA3 on SP1, captured
side-by-side with Cell 2's Griffin-via-precompile path.

## Hardware

- **MacBook Pro M5 Pro**, 18-core CPU, 20-core GPU, **24 GB RAM**, 1 TB SSD.
- macOS 25.5.0 (Darwin), Apple Silicon.

## Build configuration

- SP1 v6.2.1 (forked at `submodules/sp1`), Griffin Fp192 chip active.
- Cell 3 ELF built with `--features plum-sha3-hasher` in the `program/`
  crate; cfg-gate in [program/src/main.rs](platforms/zkvms/sp1/program/src/main.rs)
  swaps the guest's `Hasher` from `PlumGriffinHasher` to `PlumSha3Hasher`.
- See [build.rs](platforms/zkvms/sp1/script/build.rs) — three build
  invocations produce three ELFs (`elf-syscall/`, `elf-emulated/`,
  `elf-sha3/`). Host driver in
  [plum_host.rs](platforms/zkvms/sp1/script/src/bin/plum_host.rs)
  routes `PLUM_HASHER=sha3` (or `PLUM_PROVE_ARM=sha3`) to the SHA3 ELF
  and signs with `PlumSha3Hasher` to match the guest's expected hash.

## Result (2026-05-21, execute mode, PLUM-80)

| Arm                                       | Cycles      | Wall (s) | Griffin syscalls | UINT256_MUL syscalls | Total syscalls |
|------------------------------------------:|------------:|---------:|-----------------:|---------------------:|---------------:|
| Cell 2 — Griffin via `GRIFFIN_FP192_PERMUTE` | 125,504,123 |     1.90 |            1,052 |               69,396 |         70,448 |
| Cell 3 — PLUM-SHA3 control                | 110,795,424 |     1.27 |                0 |               69,385 |         69,385 |
| Delta (Cell 3 − Cell 2)                   |  −14,708,699 |    −0.63 |          −1,052 |                  −11 |         −1,063 |
| Relative delta                            |       −11.7 % |  −33.2 % |          −100.0 % |               −0.02 % |       −1.51 % |

Honest signature: both arms accept (the host signs with the hasher
matching the guest's cfg-gated `Hasher` type; a mismatch causes
universal rejection).

## What execute-mode tells us — and does not

**Tells us:**
- The cfg-gate works end-to-end: SHA3 arm fires exactly 0 Griffin syscalls.
- UINT256_MUL count is essentially identical on both arms — Fp192
  modular arithmetic happens in both PLUM verifications regardless of
  which hash is in use. The Griffin precompile saves cycles by
  replacing software permutation, not by changing the modular
  arithmetic load.
- In raw RISC-V cycle count, SHA3-256 in software is *cheaper* than
  Griffin-via-syscall. The syscall boundary itself has a non-trivial
  cost per invocation; 1,052 syscalls × ~14,000 cycles/syscall
  (= 14.7 M cycles ≈ the observed delta) suggests the precompile
  *loses* on execute cycles for this workload.

**Does not tell us:**
- Prove-time delta. The Cell 2 win is on the **prover** side: the
  Griffin precompile collapses what would be many thousands of native
  rv32im cycles per permutation into a fixed-rows AIR chip with
  cheaper constraint cost. Execute cycles are only the input-counter;
  the prover's FFT, commitment, and lookup-argument work is what the
  precompile actually reduces. The Cell 3 prove-time measurement
  (B2.5) is required to characterize the prove-side delta.
- Whether the Cell 3 prove completes on M5 Pro 24 GB. Higher rv32im
  cycle count under SHA3 may translate into more shards / higher peak
  memory than Cell 2's 81 %. To be measured.

## Headline reframe for the thesis

The execute-mode result is *evidence against* a naive "precompile is
faster" narrative. Cell 2's 32.5 min prove time vs. a (yet-unmeasured)
Cell 3 prove time will determine whether the precompile actually
reduces prover cost for this workload, or only relocates it. This
matters: the thesis claim is workload feasibility (the abstraction
admits the workload class) — not raw speedup. Cell 3 is the control
that lets us distinguish those two.

## Reproducer

```bash
cd platforms/zkvms/sp1
PATH="$HOME/.cargo/bin:$PATH" \
  PLUM_HOST_MODE=execute PLUM_HASHER=sha3 PLUM_SECURITY=80 \
  RUST_LOG=warn cargo run --release --bin plum_host --manifest-path script/Cargo.toml

# For Cell 2 side-by-side: PLUM_HASHER=griffin (default).
```

## Next step

**B2.5 — Full Cell 3 prove with memory tuning.** Mirrors the Cell 2
prove command, swapping `PLUM_PROVE_ARM=syscall` for
`PLUM_PROVE_ARM=sha3`. Expected: completes in roughly the same
order-of-magnitude wall time as Cell 2 (32.5 min) but the comparison
will reveal whether the prove-side cost is hash-class-specific or
generic to any precompile-class workload.
