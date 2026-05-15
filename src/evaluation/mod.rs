//! Thesis-oriented evaluation helpers.
//!
//! This module keeps PP-scenario runners and D-metric models out of binary entrypoints.

pub mod instrument;
pub mod metrics;
pub mod pp2;
pub mod pp3;

pub use instrument::{PhaseSpan, PhaseTimer};
pub use metrics::{D1ChurnEntry, D2CostMetrics, D3PrivacyResult};
pub use pp2::{
    Pp2AuroraBenchmarkResult, Pp2AuroraRunConfig, run_pp2_aurora_cli, run_pp2_aurora_single,
    run_pp2_aurora_single_opts, run_pp2_aurora_with_security, run_pp2_constraint_count_single,
};
pub use pp3::{
    PolicyInput, PolicyPredicate, Pp3AuroraBenchmarkResult, default_pp3_policies,
    evaluate_policy_input, parse_attribute_map, pp3_policy_only_d1_churn_rows,
    run_pp3_aurora_single, run_pp3_aurora_single_opts, run_pp3_aurora_with_security,
    run_pp3_constraint_count_single, run_pp3_default_policy_comparison,
};
