use serde::{Deserialize, Serialize};

/// D1 artifact churn entry for a single event/back-end/artifact tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct D1ChurnEntry {
    pub backend: String,
    pub event: String,
    pub artifact: String,
    pub regenerated: bool,
}

/// D2 cost metrics for a single benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct D2CostMetrics {
    pub indexer_s: f64,
    pub prove_s: f64,
    pub verify_s: f64,
    pub instance_rebuild_s: f64,
    pub proof_verify_s: f64,
    pub constraint_count: usize,
    pub proof_bytes: usize,
    pub signature_bytes: usize,
}

/// D3 privacy gate result for one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct D3PrivacyResult {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}
