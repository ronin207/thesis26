//! Engineering benchmark suites (one module per `B`-suite).
//!
//! | Module | Suite | Gaps addressed |
//! |--------|-------|---------------|
//! | [`aurora_rerun`] | B7 — statistical re-run of existing Aurora data | Gap 9 |
//! | [`backend`]      | B4 — Aurora vs Fractal comparison | Gap 5 |
//! | [`circuit_scale`]| B3 — circuit size scaling | Gap 4 |
//! | [`griffin`]      | B5 — Griffin hash cost breakdown | Gap 7 |
//! | [`noir`]         | B1 — Noir compiler pipeline | Gaps 1, 3, 6 |
//! | [`pp3_policy`]   | B9 — PP3 policy prove/verify timing | Gap (D2 sheet) |
//! | [`r1cs_compare`] | B2 — Noir vs hand-written R1CS | Gap 2 |
//! | [`zkvm`]         | B6 — RISC Zero zkVM sweep | Gap 8 |

pub mod aurora_rerun;
pub mod backend;
pub mod circuit_scale;
pub mod griffin;
pub mod noir;
pub mod pp3_policy;
pub mod r1cs_compare;
pub mod zkvm;
