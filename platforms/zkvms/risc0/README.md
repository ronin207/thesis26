# RISC Zero — PLUM verify

PLUM-128 verification + Loquat verification inside RISC Zero v3.0.5,
with `sys_bigint(OP_MULTIPLY)` precompile routing for the
`Fp192::mul` hot path.

## Layout

- `host/` — drives the prover. `plum_host` runs both SHA3 and Griffin
  hasher variants by default; override with `PLUM_HOST_HASHER=sha3` or
  `griffin`. Set `RISC0_DEV_MODE=1` for fast executor measurement
  (skips real proof gen; useful for cycle-count work).
- `methods/guest/src/bin/` — guest binaries: `plum_verify` (SHA3),
  `plum_verify_griffin`, `loquat_only`, plus microbenches
  (`fp_mul_microbench`, `fp2_microbench`, `griffin_microbench`).

## Measurements (PLUM-128 verify, SHA3 hasher, RISC0_DEV_MODE=1 executor)

| Variant                                  | Total cycles    | Verify cycles   | Δ vs baseline |
|------------------------------------------|----------------:|----------------:|--------------:|
| Baseline (Fp192 mul emulated)            | 812,646,400     | 748,012,443     | —            |
| + `Fp192::mul → sys_bigint(OP_MULTIPLY)` | 239,599,616     | 206,113,267     | **−70.5 %**  |

Per-Fp192-mul implied cost: 6,625 cycles (baseline) → 1,826 cycles
(with precompile). Same 112,903 Fp192::mul invocations counted in
both runs. The PRF (Phase 2 — `pow_biguint` rewritten as
square-and-multiply over the now-syscall-backed `Fp192::mul`) plus
the skip-mod optimisation (Path A — drop the redundant `% MODULUS`
on the syscall return path) are folded into the same precompile path.

Soundness arg: same reduction as SP1's `UINT256_MUL` version,
documented in `docs/precompile_soundness/uint256_mul_for_fp192.md`.

## Cross-platform comparison

| zkVM   | Baseline cycles | With precompile | Reduction |
|--------|----------------:|----------------:|----------:|
| RISC0  | 812,646,400     | 239,599,616     | −70.5 %   |
| SP1    | 289,778,709     | 179,952,920     | −37.9 %   |

RISC0 sees a larger relative reduction because the baseline-emulation
cost per Fp192::mul was already ~2.6× higher than SP1's (6,625 vs
~2,400 cyc). Absolute final cycle counts are similar (240 M vs 180 M),
suggesting per-mul precompile overhead is the new floor on both
platforms.

## Not yet built

- Griffin precompile (the load-bearing AIR per CLAUDE.md). Open
  question whether the current 240 M / 180 M cycle counts already meet
  "practically acceptable" on the M5 Pro target — needs a real-proof
  wall-clock measurement (drop `RISC0_DEV_MODE=1`) before deciding.

## Toolchain prerequisites

- `cargo-risczero` v3.0.5 (`~/.cargo/bin/`)
- `r0vm` v3.0.5 (`~/.risc0/bin/`)
- `risc0` rustup toolchain (auto-installed by cargo-risczero)

## Running

```bash
cd platforms/zkvms/risc0
VC_PQC_SKIP_LIBIOP=1 cargo build --release --bin plum_host
RISC0_DEV_MODE=1 PLUM_HOST_HASHER=sha3 ./target/release/plum_host  # executor (fast)
PLUM_HOST_HASHER=sha3 ./target/release/plum_host                   # real proof (slow)
```

The `VC_PQC_SKIP_LIBIOP=1` is to skip libiop's C++ build, which the
host link path would otherwise drag in via `vc-pqc`'s build.rs.
