# Noir Integration Scaffold

This directory contains the initial Noir sources used for the
`Noir -> ACIR JSON -> R1CS -> Aurora` integration path.

## Packages

- `loquat_lib`: Noir library with foreign function declarations for Loquat and
  revocation-related operations.
- `bdec_showver`: ShowVer circuit scaffold that references `loquat_lib`.

## Notes

- The Rust-side ACIR bridge supports:
  - `AssertZero` conversion
  - `BlackBoxFuncCall` parsing
  - `RANGE` black-box conversion
  - `merkle_non_member` subcircuit merge (payload-driven)
  - `loquat_verify` subcircuit merge (payload-driven)
- `griffin_hash` currently supports constant-input mode (payload/constant-driven).
