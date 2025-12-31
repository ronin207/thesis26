## Source

- **Paper**: `references/2024-868.pdf` (IACR ePrint 2024/868), **Table 3** “Performance Evaluation of Loquat”.
- **Implementation environment (per paper)**: Python + SageMath, single-thread, **2021 MacBook Pro (M1 Max), 32GB RAM**.

## Table 3 (as reported)

Notes:
- The paper reports **|σ| in “KB”**. This repo’s Rust tooling reports sizes in bytes; converting with \(1\,\mathrm{KiB}=1024\,\mathrm{B}\) may differ slightly depending on the paper’s convention and serialization format.
- Columns: **κ** (query complexity), **|σ|** (signature size), **tP** (sign/prove time), **tV** (verify time).

### Loquat (conjectured LDT soundness), SHA/SHAKE

| Security | κ | |σ| (KB) | tP (s) | tV (s) |
|---|---:|---:|---:|---:|
| Loquat-80  | 20 | 37 | 4.64 | 0.16 |
| Loquat-100 | 25 | 46 | 4.77 | 0.19 |
| Loquat-128 | 32 | 57 | 5.04 | 0.21 |

### Loquat (conjectured LDT soundness), Griffin

| Security | κ | |σ| (KB) | tP (s) | tV (s) |
|---|---:|---:|---:|---:|
| Loquat-80  | 20 | 37 | 104 | 7.40 |
| Loquat-100 | 25 | 46 | 105 | 9.15 |
| Loquat-128 | 32 | 57 | 105 | 11 |

### Loquat* (proven FRI-style bounds), SHA/SHAKE

| Security | κ | |σ| (KB) | tP (s) | tV (s) |
|---|---:|---:|---:|---:|
| Loquat*-80  | 40 | 75  | 11.51 | 0.27 |
| Loquat*-100 | 50 | 90  | 12.08 | 0.31 |
| Loquat*-128 | 64 | 114 | 13.22 | 0.37 |

### Loquat* (proven FRI-style bounds), Griffin

| Security | κ | |σ| (KB) | tP (s) | tV (s) |
|---|---:|---:|---:|---:|
| Loquat*-80  | 40 | 75  | 209 | 15 |
| Loquat*-100 | 50 | 90  | 210 | 18 |
| Loquat*-128 | 64 | 114 | 214 | 25 |











