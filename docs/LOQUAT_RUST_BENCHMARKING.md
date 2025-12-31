## Goal

Measure **Rust Loquat** performance in this repo in a way that’s directly comparable to the
**Python results reported in** `references/2024-868.pdf` (**Table 3**).

## Paper baseline (no Python re-run)

- Baseline values are transcribed into:
  - `docs/LOQUAT_PAPER_2024-868_TABLE3.md`
  - `docs/LOQUAT_PAPER_2024-868_TABLE3.json`

## Rust: how to run

All commands should be run from the repo root.

### Table-3-style row (signature-only)

This prints:
`Security & κ & |σ| (KiB) & tP (s) & tV (s) & Hash \\`

Examples (run one security level):

```bash
cargo run --release --bin loquat_snark_stats -- 80 32 --paper-table3 --iters 5 --skip-aurora
```

Run all three paper levels:

```bash
bash scripts/run_loquat_table3_griffin.sh
```

Notes:
- This repo’s current Loquat implementation uses **Griffin hashing throughout**, so you should compare against the paper’s **“Griffin”** rows.
- Size is computed from `bincode`-serialized `LoquatSignatureArtifact` (so it may differ slightly from the paper’s counting).

### SNARK harness metrics (Aurora)

This emits a **single-line JSON object** containing:
- Loquat sign/verify (seconds, size in bytes)
- R1CS size (#vars/#constraints)
- Aurora prove/verify (seconds) + proof size (bytes)

Example:

```bash
cargo run --release --bin loquat_snark_stats -- 80 32 --json --iters 1 --aurora-iters 1 --queries 8
```

## Parameter alignment with 2024-868 (Table 3)

- **Security level**: pass `80`, `100`, or `128` as the first positional argument.
- **Message length**: pass `32` as the second positional argument (Table 3 uses 32 bytes).
- **κ (query complexity)**: selected by `loquat_setup(λ)` as:
  - 80 → κ=20
  - 100 → κ=25
  - 128 → κ=32
  You can override with `--kappa <value>` if needed.











