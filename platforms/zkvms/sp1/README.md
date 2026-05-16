# SP1 — PLUM smoke

PLUM-128 verify with the `PlumSha3Hasher` (no Griffin variant yet),
running in the SP1 zkVM. Mirrors RISC0's `plum_verify` binary.

## Layout

- `program/` — SP1 guest. `#![no_main]` + `sp1_zkvm::entrypoint!(main)`.
  Reads bincode-encoded `GuestInput`, calls `plum_verify::<PlumSha3Hasher>`,
  commits a `bool`.
- `script/` — SP1 host. Generates keypair, signs, drives the program.
  `build.rs` compiles `program/` via `sp1-build`.
- `rust-toolchain` — pins to stable so the workspace builds with the
  user's normal Rust; SP1's build script switches to the `succinct`
  toolchain internally when compiling the program.

## Running

```bash
cd platforms/zkvms/sp1/script
cargo build --release
PLUM_HOST_MODE=execute ./target/release/plum_host   # executor (fast, no proof)
PLUM_HOST_MODE=prove   ./target/release/plum_host   # real proof + verify
```

## Measurements (PLUM-128 verify, SHA3 hasher, executor mode)

| Variant                                  | Cycles      | UINT256_MUL | Δ vs baseline |
|------------------------------------------|------------:|------------:|--------------:|
| Baseline (Fp192 mul emulated, no precompile) | 289,778,709 | 0          | —            |
| + Phase 1: `Fp192::mul → UINT256_MUL`        | 276,643,994 | 16,920     | −4.5 %       |
| + Phase 2: PRF as square-and-multiply over Fp192::mul | 240,857,140 | 112,902 | −16.9 %      |
| + skip redundant `% MODULUS` on syscall return | 179,952,920 | 112,902  | **−37.9 %**  |

All measurements: fixed RNG seed `0x504C554D5F535031`, message
`"sp1 smoke: plum verify with SHA3 hasher"`, executor mode (no proof).
M-series Mac wall-clock ~1.78 s (full Phase-A stack) vs 3.2 s (baseline).
The last step is a one-line fix: SP1's UINT256_MUL AIR already
constrains the result to `[0, modulus)`, so `from_limbs`'s call into
`from_biguint`'s `bi % MODULUS.clone()` was a wasted BigUint allocation
×113K syscalls. Saves ~540 cycles per syscall.

The remaining ~83 % of cycles is Griffin permutation work (matrix-mul
+ d=3 S-box layer). The Griffin AIR (Phase 3, not yet built) is the
targeted optimisation for that share.

Soundness arg for Phase 1 + Phase 2 lives at
`docs/precompile_soundness/uint256_mul_for_fp192.md`.

## Not yet ported from RISC0

- `plum_verify_griffin` — Griffin-hasher variant (the 91 %-share target).
- `loquat_only` — Loquat verify guest (depends on no_std refactor of vc-pqc
  if we want it on a strict no_std zkVM later, but on SP1 std is available
  so this should port cleanly).
- Microbenches (`fp_mul`, `fp2`, `griffin`).
- Three-level cycle-attribution counters from
  `vc_pqc::signatures::plum::*::*_COUNT` statics.

## Toolchain prerequisites

- `sp1up` + `cargo prove` (`~/.sp1/bin/`)
- Real `rustup` proxies (`~/.cargo/bin/{rustc,cargo,rustup}`). Homebrew rust
  is **not** a rustup proxy; if `rustc +succinct --version` returns the
  Homebrew rustc version (instead of `rustc 1.93.0-dev`), reinstall rustup
  via `https://sh.rustup.rs` and ensure `$HOME/.cargo/bin` precedes
  `/opt/homebrew/bin` in `PATH`.
