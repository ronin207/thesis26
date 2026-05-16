# Jolt — Loquat smoke (BLOCKED)

Scaffolded but **not building**. Lives here as a stub for the eventual
4-cell evaluation; needs more work before it runs end-to-end.

## What's here

- `Cargo.toml`, `src/main.rs` — host driver. Generates a Loquat keypair,
  signs a fixed message, drives the Jolt `loquat_smoke` provable function,
  and verifies the resulting proof.
- `guest/Cargo.toml`, `guest/src/lib.rs` — guest crate. Single `#[jolt::provable]`
  function `loquat_smoke(input_bytes: Vec<u8>) -> bool` that postcard-decodes
  the input and calls `loquat_verify`.
- `rust-toolchain.toml` — pins to Rust 1.94 + `riscv32imac-unknown-none-elf`
  and `riscv64imac-unknown-none-elf` targets, per Jolt convention.

## Status: blocks at guest compile

`cargo build --release` (host) succeeds. Running the host triggers Jolt's
in-process guest recompile, which fails with:

```
error[E0463]: can't find crate for `std`
 --> getrandom-0.2.17/src/error_impls.rs:1:1
  | extern crate std;
```

## Root cause

`vc-pqc`'s root `Cargo.toml` lists std-only crates (`flate2`, `rmpv`, `toml`,
`bincode` 1.x, `tracing-subscriber`, ...) as unconditional `[dependencies]`.
Even with `default-features = false, features = ["guest"]`, the **dep tree
itself** drags `std` in transitively (e.g. `getrandom` ends up with its
`std` feature enabled by feature unification, then errors when compiled
for the no_std target).

RISC0 v3 and SP1 v6 both allow `std` in the guest, so vc-pqc's tree works
there. Jolt's `#[jolt::provable]` forces `no_std` on the guest, so the same
tree fails.

## Path forward (when picked back up)

1. Refactor the root `Cargo.toml` to make std-leaking deps **optional** and
   gate them behind features (e.g. `flate2`, `rmpv`, `toml`, `tracing-subscriber`
   probably only needed by the Noir / bench / evaluation paths — they
   should be feature-gated, not unconditional).
2. Pin `getrandom` to a version compatible with no_std + `custom` backend,
   OR drop the `rand` transitive dep from the Loquat-verify code path (the
   verifier shouldn't need an RNG; only the signer does).
3. Retry the build.

PLUM on Jolt is a separate (larger) refactor — PLUM uses `std::collections`
(`HashMap`, `HashSet`) and is gated `#[cfg(feature = "std")]` in `src/lib.rs`.
That refactor would replace `HashMap` / `HashSet` with `BTreeMap` /
`BTreeSet`, then re-audit the PLUM verify path for any other std touches.

## Why this is committed despite not building

The scaffold itself is correct against Jolt v0.1.0's APIs (host pattern
matches the official template, `#[jolt::provable]` attribute is valid,
postcard is used for no_std serde). The blocker is a workspace-level
Cargo.toml refactor — out of scope for "smoke" and worth surfacing as
a deliberate next-stage task rather than burying it.
