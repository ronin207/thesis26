//! B9 — PP3 Policy timing: prove/verify cost as a function of policy predicate set.
//!
//! Motivation. The `Constraint Scaling` sheet (B3) reports constraint counts for
//! `policy ∈ {none, gpa, gpa_degree}` but no prove/verify timing. The
//! `PP3 Policy (D2)` template in `bench_results.xlsx` expects `prove_s`,
//! `verify_s`, and `proof_bytes` keyed by policy. This suite fills that gap.
//!
//! Design. Fixed pivot {k, lr_size, rev_depth} (from config). Varies ONLY the
//! policy predicate set across three points:
//!
//!   * `none`       — no policy (calls the PP2 pipeline: `run_pp2_aurora_single_opts`)
//!   * `gpa`        — single GPA ≥ threshold predicate (PP3 pipeline)
//!   * `gpa_degree` — GPA ≥ threshold ∧ degree ∈ allowed set (PP3 pipeline)
//!
//! Run cost. 3 configs × (warmup + runs) × ~90 s ≈ 45–60 min at default
//! (warmup=2, runs=10).
//!
//! Output. JSONL with `suite: "B9"`, `variant: "pp3_policy"`, and
//! `config_key: "pol={none|gpa|gpa_degree}"`. Summary metrics:
//!   - indexer_ms, prove_ms, verify_ms (wall-clock, per run)
//!   - constraint_count, proof_bytes (should be constant per policy)
//!
//! Why a separate suite rather than reusing B3's `tier = "aurora_prove"`?
//! B3's config sweeps k × attr × rev × policy = 180 configs; running that at
//! full `aurora_prove` tier is multi-hour. B9 is targeted: one pivot, three
//! policies, 10 runs each, bounded runtime.

use crate::bench::{BenchWriter, Pp3PolicyConfig, RunnerConfig, SampleRecord, emit_summaries};
use crate::bench::{
    PolicyInput, PolicyPredicate, run_pp2_aurora_single_opts, run_pp3_aurora_single_opts,
};
use crate::LoquatError;

pub fn run(
    runner: &RunnerConfig,
    cfg: &Pp3PolicyConfig,
    w: &mut BenchWriter,
) -> crate::LoquatResult<()> {
    let k = cfg.k;
    let lr_size = cfg.lr_size;
    let rev_depth = cfg.rev_depth;
    let variant = "pp3_policy";

    // Policy specs enumerated in a fixed order so downstream tables are
    // deterministic. The keys mirror B3's policy_configs values.
    let policies: Vec<(&'static str, Option<PolicyInput>)> = vec![
        ("none", None),
        (
            "gpa",
            Some(PolicyInput {
                predicates: vec![PolicyPredicate::GteI64 {
                    key: "gpa".to_string(),
                    min_value: cfg.gpa_min,
                }],
            }),
        ),
        (
            "gpa_degree",
            Some(PolicyInput {
                predicates: vec![
                    PolicyPredicate::GteI64 {
                        key: "gpa".to_string(),
                        min_value: cfg.gpa_min,
                    },
                    PolicyPredicate::OneOf {
                        key: "degree".to_string(),
                        allowed_values: cfg.degree_set.clone(),
                    },
                ],
            }),
        ),
    ];

    for (pol_name, policy_opt) in &policies {
        let config_key = format!("k={k}_lr={lr_size}_rev{rev_depth}_pol={pol_name}");
        let config_val = serde_json::json!({
            "k":         k,
            "lr_size":   lr_size,
            "rev_depth": rev_depth,
            "policy":    pol_name,
            "gpa_min":   cfg.gpa_min,
            "degree_set": cfg.degree_set,
        });

        let mut indexer_ms_v = Vec::new();
        let mut prove_ms_v   = Vec::new();
        let mut verify_ms_v  = Vec::new();
        let mut constraint_v = Vec::new();
        let mut proof_bytes_v = Vec::new();

        let total = runner.warmup + runner.runs;
        for run_idx in 0..total {
            let is_warmup = run_idx < runner.warmup;

            // Dispatch: policy=none → PP2 pipeline; otherwise → PP3 pipeline.
            // This mirrors how `aurora_rerun::run_pp2_policy_combined` picks
            // the correct path in the existing harness.
            let d2 = match policy_opt {
                None => {
                    let (res, _t) = run_pp2_aurora_single_opts(k, false, lr_size, rev_depth, false)
                        .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                    res.d2
                }
                Some(pol) => {
                    let (res, _t) = run_pp3_aurora_single_opts(
                        pol_name, k, false, lr_size, rev_depth, pol, false,
                    )
                    .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                    res.d2
                }
            };

            let t_i_ms = d2.indexer_s * 1000.0;
            let t_p_ms = d2.prove_s   * 1000.0;
            let t_v_ms = d2.verify_s  * 1000.0;

            w.emit_sample(&SampleRecord {
                r#type: "sample",
                suite: "B9".to_string(),
                variant: variant.to_string(),
                config_key: config_key.clone(),
                config: config_val.clone(),
                run: run_idx,
                is_warmup,
                wall_ms: t_i_ms + t_p_ms + t_v_ms,
                phases: serde_json::json!({
                    "indexer_ms":          t_i_ms,
                    "prove_ms":            t_p_ms,
                    "verify_ms":           t_v_ms,
                    "instance_rebuild_ms": d2.instance_rebuild_s * 1000.0,
                }),
                metrics: serde_json::json!({
                    "constraint_count": d2.constraint_count,
                    "proof_bytes":      d2.proof_bytes,
                }),
            })?;

            if !is_warmup {
                indexer_ms_v.push(t_i_ms);
                prove_ms_v.push(t_p_ms);
                verify_ms_v.push(t_v_ms);
                constraint_v.push(d2.constraint_count as f64);
                proof_bytes_v.push(d2.proof_bytes as f64);
            }
        }

        emit_summaries(w, "B9", variant, &config_key, runner.warmup, &[
            ("indexer_ms",       indexer_ms_v),
            ("prove_ms",         prove_ms_v),
            ("verify_ms",        verify_ms_v),
            ("constraint_count", constraint_v),
            ("proof_bytes",      proof_bytes_v),
        ])?;
    }

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}
