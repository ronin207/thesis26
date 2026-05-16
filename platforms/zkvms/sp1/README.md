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

## Last measured baseline

- Executor mode: `accepted=true`, **289,778,709 cycles**, ~3.2 s wall-clock
  on M-series Mac. This is the field-mismatch baseline — every PLUM Fp192
  operation is emulated as multi-limb arithmetic over BabyBear.

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
