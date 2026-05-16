# Jolt — Loquat smoke (build OK, runtime deserialize fails)

Loquat-128 verify in the Jolt zkVM. PLUM is **not** included here —
PLUM's `signatures::plum::*` is gated `#[cfg(feature = "std")]` in
`src/lib.rs` (uses `HashMap`/`HashSet`); Jolt's `#[jolt::provable]`
forces strict `no_std`, so PLUM-on-Jolt is blocked on a `no_std`
refactor of the PLUM module itself.

## Status

- `cargo build --release` — clean (host + guest both compile).
- `cargo run --release` — guest ELF builds inside `jolt build`, dory
  PCS setup loads, prover runs through all 8 stages, BUT the guest
  panics ~4248 cycles in with `postcard decode failed:
  DeserializeUnexpectedEnd`, so the proof verifies the panic state
  rather than an accepted signature. Proof `valid: false`.

## What's working (vs. the previous commit's state)

- The workspace `Cargo.toml` deps refactor (this commit) unblocked the
  earlier `getrandom → extern crate std` failure. `vc-pqc`'s `rand`,
  `rand_chacha`, `bincode`, `tracing`, `tracing-subscriber`,
  `serde_json`, `toml`, `base64`, `flate2`, `rmpv` are now optional
  and only pulled in by the `std` feature. The Jolt guest builds
  `--no-default-features --features guest` and the dep tree drops
  cleanly.
- `guest/src/main.rs` (mirrors the Jolt template's `#![no_main]` +
  `use guest::*;` shim) added — that's what makes `cargo build` emit
  the `guest` binary rather than just `libguest.rlib`. Without this
  file the host's `compile_loquat_smoke` panics on "Built ELF not
  found".
- `stack_size = 4194304`, `heap_size = 16777216`, `max_input_size =
  1048576`, `max_trace_length = 16777216` on the `#[jolt::provable]`
  attribute (defaults are 4 KB / 4 MB and trip immediately on Loquat
  verify's stack usage).

## Outstanding bug

`DeserializeUnexpectedEnd` from postcard when the guest tries to
decode the 83-KB serialized `(params, message, public_key, signature)`
input. Bytes are being passed but truncated or framed differently
than postcard expects. Likely Jolt's `&[u8]` argument marshalling
adds a length prefix or wraps the bytes; needs digging into
`jolt-sdk-macros/src/lib.rs` to confirm the exact wire format. The
build pipeline (compile → ELF → prove → verify) works end-to-end on
the failing case, so this is now a narrower API-detail problem, not a
workspace-level issue.

## Running

```bash
cd platforms/zkvms/jolt
VC_PQC_SKIP_LIBIOP=1 cargo build --release   # host + guest
VC_PQC_SKIP_LIBIOP=1 RUST_LOG=info ./target/release/loquat_host
```

(The `VC_PQC_SKIP_LIBIOP=1` is to skip libiop's C++ build, which the
host link path would otherwise drag in via `vc-pqc`'s build.rs.)
