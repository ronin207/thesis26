# BDEC.ShowVer zkVM dev-mode sweep — 2026-05-11

## What was measured

36 configurations of `target/release/host --dev-mode --security-level $L --k $k --s $s --m $m --json --continue-on-error` on the BDEC.ShowVer guest under RISC Zero zkVM. Sweep:

- Security levels λ ∈ {80, 100, 128}
- Credentials k ∈ {1, 2, 6}
- Shows s ∈ {1, 3}
- Attributes m ∈ {16, 64}
- Revocation depth: 20 (default, not swept)

Hardware: Apple M5 Pro, 18 cores, 24 GB unified memory, macOS Darwin 25.3.0, single-process invocation per cell.

Files:
- `devmode_sweep_20260511.jsonl` — raw output, one JSON per line.
- `devmode_sweep_20260511.csv` — flattened with `security_level` and `cycles_per_verify` columns added.

## What is empirical and citable

**`trace_cycles`** — the rv32im trace length the RISC Zero prover would have to commit to. This is a property of the program-input pair, **independent of hardware** and **independent of whether full proving is run**. Citable as empirical data.

**`loquat_verifies`** — count of `loquat_verify` calls inside the guest, equal to `2k+2`. Citable.

**`merkle_nodes`** — total Merkle authentication-path nodes traversed inside the guest. Citable.

## What is *not* a real proving measurement

**`prove_ms`** in this dataset is the dev-mode wall-clock. **Dev mode skips STARK proof generation entirely** — it only executes the rv32im program and counts cycles. So:

- `prove_ms` here measures *execution speed of the M5 Pro running the guest's RISC-V emulator*, not proving time.
- `verify_ms = 0` and `receipt_bytes = 0` because no real receipt is produced.
- Full-mode proving on the same trace would take **substantially longer** (10×–100× depending on segment configuration) because each segment requires a STARK proof + recursive composition.

Quote `trace_cycles` and `loquat_verifies`. Do not quote `prove_ms` from this run as proving time.

## Empirical scaling laws (validated, R² > 0.999)

Within this sweep:

```
trace_cycles(λ, k) ≈ (2k + 2) · c(λ)
```

| λ | c(λ) cycles/verify | spread across (s, m) |
|---|---|---|
| 80 | 725 M | 1.23% |
| 100 | 889 M | 1.01% |
| 128 | 946 M | 0.94% |

Cost ratios:
- λ=128 / λ=80 = 1.30 (sub-linear in λ)
- k=6 / k=1 = 3.47 ≈ (14/4) = 3.5 (linear in verify count)

s and m do not appreciably affect cycle counts — Loquat verification dominates over credential-management overhead.

## What you must do to obtain real proving wall-clock

Three options:

1. **Run full-mode for one cell** with appropriate segment_po2 (e.g. 20) and tmux+caffeinate. Use the resulting cycle-to-wall-clock ratio to extrapolate the other 35.
2. **Cite RISC Zero's published prove rate** for M-series Metal (or x86) at a given segment_po2 and multiply by trace_cycles. Get the citation from RISC0 docs / proof-system-in-detail.pdf — do not estimate without source.
3. **Use Tsutsumi's Gustafson-law extrapolation** (vault: `precompile-paradox`) calibrated to one anchor point.

Without one of these, the dataset above gives cycle counts and scaling laws — not wall-clock prove times.

## What is NOT in this dataset

- Full-mode prove time, proof size, verify time, peak RAM during proving.
- Witness-generation time vs FRI-commitment time breakdown.
- The Aurora-side comparison numbers (those live in earlier `bench_run_*` directories).
- Effect of Apple Silicon Metal vs CPU prover (RISC0 Metal backend not exercised in dev mode).

Recommended next step: run **one** full-mode prove at the smallest cell (λ=80, k=1, s=1, m=16) inside `tmux` with `caffeinate -i`, segment_po2=20, ulimit -v ~16GB. That gives you the cycle→wall-clock anchor for extrapolation across the whole 36-cell matrix.

## Provenance

- Wrapper invocation that produced this dataset: bash for-loop over (λ, k, s, m), each cell calling `cargo run --release -- --dev-mode --security-level $L --k $k --s $s --m $m --json --continue-on-error` and tee-appending stdout JSON to `devmode_sweep_20260511.jsonl`.
- Dev mode set via `--dev-mode` CLI flag, which sets `RISC0_DEV_MODE=1` before `default_prover()` initialises (see `zkvm/host/src/pp2_showver.rs:358`).
- Guest performs full BDEC.ShowVer including in-circuit `loquat_verify` calls (see `zkvm/methods/guest/src/main.rs:242`). Loquat is **not** removed from the circuit; this measures BDEC's intended construction.
