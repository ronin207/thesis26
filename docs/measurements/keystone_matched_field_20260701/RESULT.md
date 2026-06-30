# Keystone matched-field control — RESULT (per-multiplication field-mismatch tax)

Tests the necessity direction of `prop:field-match` (§4, `04-theoretical.tex`):
the emulated cost a precompile removes is large at field-mismatch width `ℓ=7`
(Fp192 / 199-bit on a 31-bit prover) and collapses toward native single-limb
cost at `ℓ=1` (KoalaBear). Held-out predictions in `FORECAST.md` (recorded
before the guest existed); this file is the test of those predictions.

- **Date:** 2026-07-01
- **Hardware:** Apple M5 Pro, 24 GB
- **zkVM:** SP1 v6.2.1 forked (submodule `8bf0248bc5b6b7ba7c820253c3918ea277008641`), succinct rustc 1.93.0-dev
- **Mode:** execute — guest instruction count (`report.total_instruction_count()`), **NOT prove time**
- **What is measured:** per-multiplication guest cycles for a software (non-precompile, multi-limb `num_bigint`) Fp192 multiply (`ℓ=7`) vs a native single-limb KoalaBear `u64` multiply (`ℓ=1`)

## Method

Guest `program_fmt_keystone` reads `mode: u8`, `m: u64` and runs a dependency
chain of `m` multiplications (`x = x*c`), committing one `u32` derived from the
final state so the chain is live (defeats dead-code elimination):

- `mode 0` — Fp192 over PLUM's 199-bit prime, **software** path
  (`src/primitives/field/p192.rs`, the `#[cfg(not(all(target_os="zkvm", feature="sp1")))]`
  arm; guest crate omits the `sp1` feature so the `UINT256_MUL` precompile route
  is NOT taken). Backed by `num_bigint::BigUint`.
- `mode 1` — KoalaBear `p = 2³¹−2²⁴+1 = 0x7f000001`, naive `(a·b) % p` over `u64`.

Per-multiplication cost is the slope across two operand counts, which cancels
fixed loop / IO / setup overhead:
`c_F = (cyc_F(20000) − cyc_F(10000)) / 10000`.

## Results

| field (mode) | M=10,000 cycles | M=20,000 cycles | per-mult cycles |
|---|---|---|---|
| Fp192 software multi-limb (mode 0, ℓ=7) | 31,202,131 | 62,413,061 | **3121.0930** |
| KoalaBear native single-limb (mode 1, ℓ=1) | 191,203 | 381,203 | **19.0000** |

**Field-mismatch tax ratio** `c_Fp192 / c_KoalaBear = 3121.09 / 19.00 =`
**164.27**.

(The slope is clean: each field's M=20,000 count is almost exactly twice the
M=10,000 count, so the per-mult figure is not contaminated by fixed overhead.
KoalaBear lands at an exact 19.0 cycles/mul.)

## Findings

1. **The per-mult tax scales steeply with field width.** Going from the matched
   field (`ℓ=1`, KoalaBear, 19 cyc/mul) to the mismatched field (`ℓ=7`, Fp192,
   3,121 cyc/mul) is a **164×** increase in guest cycles per multiplication.
2. **The benefit is ~0 at the matched field.** A native single-limb multiply
   costs 19 cycles; there is no multi-limb emulation tax to remove. This is the
   necessity direction of `prop:field-match` made concrete: the field-mismatch
   cost a precompile could remove collapses toward the native cost at `ℓ=1`.
3. **The magnitude sits above `ℓ²=49`,** consistent with the apparatus note in
   `FORECAST.md`: the software path is `num_bigint::BigUint` (heap-allocating,
   general-purpose bignum), not the limb-aligned `4×u64` schoolbook routine the
   `ℓ²` bound assumes. `num_bigint ≥ schoolbook`, so a measured ratio well above
   49 is CONSISTENT with the lower bound, not a violation of it.

## Forecast vs measured

| FORECAST.md prediction | measured | verdict |
|---|---|---|
| ratio `≥ ℓ=7` (necessity of `prop:field-match`) | 164.27 | **CONFIRMED** |
| ratio above `ℓ²=49` due to `num_bigint` overhead (apparatus note, lines 80–86) | 164.27 (> 49) | **as predicted** |
| ratio `≈ 1` would falsify necessity | 164.27 ≠ 1 | not falsified |
| benefit `≈ 1·cyc_nat` at `ℓ=1`, `≈ ℓ²·cyc_nat` at `ℓ=7` (forecast pt. 2) | 19 vs 3121 cyc/mul | direction matches |

**Necessity direction of `prop:field-match`: CONFIRMED** (ratio 164.27 ≫ 1, and
≥ `ℓ=7`). The ratio sitting above `ℓ²=49` is the `num_bigint` implementation
datum the forecast already flagged, not a model violation.

## Honesty / scope

- **This is the necessity direction only, NOT the schoolbook `ℓ²` bound.** The
  software Fp192 path is `num_bigint::BigUint`, an upper bound on a limb-aligned
  schoolbook multiply. The schoolbook-tight test (ratio near 49) needs the
  Phase-1.5 limb-aligned `4×u64` multiply (`p192.rs:54–62`) and is deferred. The
  absolute 164× is therefore an implementation datum, not the `prop:fmt-lb`
  `ℓ²` end.
- **The KoalaBear baseline is a naive `u64` `(a·b) % p` — an upper bound on the
  true native-field cost.** A Montgomery/Barrett single-limb routine would be
  cheaper, which would only *widen* the ratio; 164× is conservative on this axis.
- **Execute cycles ≠ prove time.** This counts guest instructions, not prover
  wall-clock or trace area. The prove-mode corollary (forecast pt. 3 — no
  field-mismatch prove-time benefit at `ℓ=1`) is a separate test on target
  hardware and is NOT established here.
- **Algebraic operation only.** This measures the FIELD-mismatch tax for a
  multiplication, the class `prop:field-match` governs. Bitwise primitives
  (SHA/Keccak) carry a separate bit-emulation tax and are out of scope.
- The Fp192 prime is the 199-bit substitute prime (`p192.rs` doc-comment), not
  PLUM's canonical `p₀`; cycle cost depends on bit-width and 2-adicity (both
  preserved), so the substitution does not affect this measurement.

## Reproduce

```sh
cd <repo-root>                       # the thesis worktree
export PATH="$HOME/.cargo/bin:$PATH" # succinct toolchain must precede Homebrew rustc
export VC_PQC_SKIP_LIBIOP=1
cargo build --release \
  --manifest-path platforms/zkvms/sp1/script/Cargo.toml --bin fmt_keystone_host
cargo run --release \
  --manifest-path platforms/zkvms/sp1/script/Cargo.toml --bin fmt_keystone_host
```

Artifacts:
- guest: `platforms/zkvms/sp1/program_fmt_keystone/{Cargo.toml,src/main.rs}`
  (vc-pqc dep is `default-features=false, features=["guest","std"]` — **no `sp1`** —
  to force the software multi-limb path)
- host: `platforms/zkvms/sp1/script/src/bin/fmt_keystone_host.rs`
- wiring: workspace member in `platforms/zkvms/sp1/Cargo.toml`; ELF env var
  `FMT_KEYSTONE_ELF_PATH` in `platforms/zkvms/sp1/script/build.rs`; `[[bin]]`
  in `platforms/zkvms/sp1/script/Cargo.toml`.

Build note (worktree only): the forked `submodules/sp1` was not populated in
this worktree (its commit is not on a fetchable remote), so it was symlinked to
the main checkout's populated `submodules/sp1` (read-only source; build
artifacts go to `target/`). A normal checkout with the submodule present does
not need this.
