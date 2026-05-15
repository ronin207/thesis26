//! B3 — Circuit size scaling analysis.
//!
//! Sweeps k, revocation depth, and policy complexity, recording the R1CS
//! constraint count (fast, deterministic) and optionally Aurora prove/verify time.
//!
//! Two tiers (controlled by `[circuit_scale].tier`):
//!   - `"constraints_only"` — reports constraint count only, using a fast path
//!     that builds the R1CS without running aurora_prove. Runs in seconds even
//!     for large k. This is what the thesis uses for the N_C(k) regression.
//!   - `"aurora_prove"` — also records prove/verify timing. Caps k at
//!     `max_k_for_local_prove` so large-k configs don't run for hours.

use crate::bench::{BenchWriter, CircuitScaleConfig, RunnerConfig, SampleRecord, emit_summaries};
use crate::bench::{
    PolicyInput, PolicyPredicate, run_pp2_aurora_single_opts, run_pp2_constraint_count_single,
    run_pp3_aurora_single_opts, run_pp3_constraint_count_single,
};
use crate::{LoquatError, LoquatResult};
use std::time::Instant;

pub fn run(runner: &RunnerConfig, cfg: &CircuitScaleConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    let do_prove = matches!(cfg.tier.as_str(), "aurora_prove" | "both");

    for &k in &cfg.k_values {
        let is_large_k = k > cfg.max_k_for_local_prove;

        for &rev_depth in &cfg.rev_depth_values {
            for policy_name in &cfg.policy_configs {
                let config_key = format!("k={k}_rev{rev_depth}_pol={policy_name}");
                let policy = build_policy(policy_name);

                if !do_prove {
                    // Fast path: constraints_only tier. Build the R1CS once and
                    // record just the constraint count. No aurora_prove, so
                    // this returns in seconds even at k=14.
                    let start = Instant::now();
                    let constraint_count = if let Some(ref p) = policy {
                        let (_, _, c) = run_pp3_constraint_count_single(
                            policy_name, k, false, 0, rev_depth, p,
                        )
                        .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                        c
                    } else {
                        let (_, _, c) = run_pp2_constraint_count_single(k, false, 0, rev_depth)
                            .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                        c
                    };
                    let wall_ms = start.elapsed().as_secs_f64() * 1000.0;

                    let config_val = serde_json::json!({
                        "k": k,
                        "rev_depth": rev_depth,
                        "policy": policy_name,
                        "tier": cfg.tier,
                        "constraint_count": constraint_count,
                    });

                    w.emit_sample(&SampleRecord {
                        r#type: "sample",
                        suite: "B3".to_string(),
                        variant: cfg.tier.clone(),
                        config_key: config_key.clone(),
                        config: config_val,
                        run: 0,
                        is_warmup: false,
                        wall_ms,
                        phases: serde_json::json!({
                            "r1cs_build_ms": wall_ms,
                        }),
                        metrics: serde_json::json!({
                            "constraint_count": constraint_count,
                        }),
                    })?;

                    emit_summaries(w, "B3", &cfg.tier, &config_key, 0, &[
                        ("constraint_count", vec![constraint_count as f64]),
                    ])?;
                    continue;
                }

                // aurora_prove / both tier: run full aurora pipeline with
                // statistical rigour, but only for k ≤ max_k_for_local_prove.
                if is_large_k {
                    eprintln!(
                        "[B3] skipping aurora timing for k={k} (exceeds max_k_for_local_prove={}); use tier=constraints_only for N_C",
                        cfg.max_k_for_local_prove
                    );
                    continue;
                }

                let runs = runner.runs;
                let warmup = runner.warmup;
                let total = warmup + runs;

                let mut constraint_v = Vec::new();
                let mut prove_ms_v = Vec::new();
                let mut verify_ms_v = Vec::new();
                let mut proof_bytes_v = Vec::new();
                let mut build_ms_v = Vec::new();

                for run_idx in 0..total {
                    let is_warmup = run_idx < warmup;

                    let (d2, wall_ms) = if let Some(ref p) = policy {
                        let (res, _timer) = run_pp3_aurora_single_opts(
                            policy_name, k, false, 0, rev_depth, p, false,
                        )
                        .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                        let wms = (res.d2.indexer_s + res.d2.prove_s + res.d2.verify_s) * 1000.0;
                        (res.d2, wms)
                    } else {
                        let (res, _timer) = run_pp2_aurora_single_opts(k, false, 0, rev_depth, false)
                            .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
                        let wms = (res.d2.indexer_s + res.d2.prove_s + res.d2.verify_s) * 1000.0;
                        (res.d2, wms)
                    };

                    let config_val = serde_json::json!({
                        "k": k,
                        "rev_depth": rev_depth,
                        "policy": policy_name,
                        "tier": cfg.tier,
                        "constraint_count": d2.constraint_count,
                    });

                    w.emit_sample(&SampleRecord {
                        r#type: "sample",
                        suite: "B3".to_string(),
                        variant: cfg.tier.clone(),
                        config_key: config_key.clone(),
                        config: config_val,
                        run: run_idx,
                        is_warmup,
                        wall_ms,
                        phases: serde_json::json!({
                            "indexer_ms":          d2.indexer_s * 1000.0,
                            "prove_ms":            d2.prove_s * 1000.0,
                            "verify_ms":           d2.verify_s * 1000.0,
                            "instance_rebuild_ms": d2.instance_rebuild_s * 1000.0,
                        }),
                        metrics: serde_json::json!({
                            "constraint_count": d2.constraint_count,
                            "proof_bytes":      d2.proof_bytes,
                        }),
                    })?;

                    if !is_warmup {
                        constraint_v.push(d2.constraint_count as f64);
                        prove_ms_v.push(d2.prove_s * 1000.0);
                        verify_ms_v.push(d2.verify_s * 1000.0);
                        proof_bytes_v.push(d2.proof_bytes as f64);
                        build_ms_v.push(d2.instance_rebuild_s * 1000.0);
                    }
                }

                emit_summaries(w, "B3", &cfg.tier, &config_key, warmup, &[
                    ("constraint_count", constraint_v),
                    ("prove_ms",    prove_ms_v),
                    ("verify_ms",   verify_ms_v),
                    ("proof_bytes", proof_bytes_v),
                    ("instance_rebuild_ms", build_ms_v),
                ])?;
            }
        }
    }

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

fn build_policy(name: &str) -> Option<PolicyInput> {
    match name {
        "none" => None,
        "gpa" => Some(PolicyInput {
            predicates: vec![PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            }],
        }),
        "gpa_degree" => Some(PolicyInput {
            predicates: vec![
                PolicyPredicate::GteI64 {
                    key: "gpa".to_string(),
                    min_value: 30,
                },
                PolicyPredicate::OneOf {
                    key: "degree".to_string(),
                    allowed_values: vec!["CS".to_string(), "EE".to_string(), "Math".to_string()],
                },
            ],
        }),
        other => {
            eprintln!("[B3] unknown policy config '{other}', treating as 'none'");
            None
        }
    }
}
