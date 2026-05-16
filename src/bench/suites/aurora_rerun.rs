//! B7 — Aurora statistical re-run.
//!
//! Re-runs the PP2 (revocation) and PP3 (policy) Aurora benchmarks with proper
//! statistical rigour: n=10 measured runs, 2 warm-up runs, IQR outlier filtering.
//!
//! Supports a security-level sweep: every (variant × security_level) pair is
//! run independently, producing labelled JSONL records that downstream analysis
//! can group into cost-vs-security curves.  The sweep levels are taken from
//! `aurora_rerun.security_levels` in `bench_config.toml` (defaults to `[128]`
//! for backwards compatibility).

use crate::bench::{AuroraRerunConfig, BenchWriter, RunnerConfig, SampleRecord, emit_summaries};
use crate::bench::{
    PolicyInput, PolicyPredicate, run_pp2_aurora_with_security, run_pp3_aurora_with_security,
};
use crate::LoquatError;
use crate::LoquatResult;

pub fn run(runner: &RunnerConfig, cfg: &AuroraRerunConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    let levels: Vec<usize> = if cfg.security_levels.is_empty() {
        vec![128]
    } else {
        cfg.security_levels.clone()
    };

    for &security_level in &levels {
        run_pp2(runner, cfg, w, false, security_level)?;
        run_pp3(runner, cfg, w, security_level)?;
        if cfg.run_combined {
            run_pp2(runner, cfg, w, true, security_level)?;
        }
    }
    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

fn run_pp2(
    runner: &RunnerConfig,
    cfg: &AuroraRerunConfig,
    w: &mut BenchWriter,
    combined: bool,
    security_level: usize,
) -> LoquatResult<()> {
    let (k, lr_size, rev_depth, variant, policy_opt) = if combined {
        let p = build_policy(cfg.combined_policy_gpa_min, &cfg.combined_policy_degree_set);
        (cfg.combined_k, cfg.pp2_lr_size, cfg.pp2_rev_depth, "pp2_combined", Some(p))
    } else {
        (cfg.pp2_k, cfg.pp2_lr_size, cfg.pp2_rev_depth, "pp2_aurora", None)
    };

    let config_key = format!("sec={security_level}_k={k}_lr={lr_size}_rev{rev_depth}");
    let config_val = serde_json::json!({
        "security_level": security_level,
        "k": k, "lr_size": lr_size, "rev_depth": rev_depth,
        "policy": policy_opt.is_some(), "tiny": cfg.tiny
    });

    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut indexer_ms_v = Vec::new();
    let mut constraint_v = Vec::new();
    let mut proof_bytes_v = Vec::new();

    let total = runner.warmup + runner.runs;
    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let d2 = if let Some(ref policy) = policy_opt {
            let (res, _timer) = run_pp3_aurora_with_security(
                "combined",
                k,
                security_level,
                lr_size,
                rev_depth,
                policy,
                false,
            )
            .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
            res.d2
        } else {
            let (res, _timer) =
                run_pp2_aurora_with_security(k, security_level, lr_size, rev_depth, false)
                    .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
            res.d2
        };

        let t_i_ms = d2.indexer_s * 1000.0;
        let t_p_ms = d2.prove_s * 1000.0;
        let t_v_ms = d2.verify_s * 1000.0;
        let wall_ms = t_i_ms + t_p_ms + t_v_ms;

        let phases_val = serde_json::json!({
            "indexer_ms":          t_i_ms,
            "prove_ms":            t_p_ms,
            "verify_ms":           t_v_ms,
            "instance_rebuild_ms": d2.instance_rebuild_s * 1000.0,
            "proof_verify_ms":     d2.proof_verify_s * 1000.0,
        });
        let metrics_val = serde_json::json!({
            "security_level":   security_level,
            "constraint_count": d2.constraint_count,
            "proof_bytes":      d2.proof_bytes,
            "signature_bytes":  d2.signature_bytes,
        });

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B7".to_string(),
            variant: variant.to_string(),
            config_key: config_key.clone(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms,
            phases: phases_val,
            metrics: metrics_val,
        })?;

        if !is_warmup {
            prove_ms_v.push(t_p_ms);
            verify_ms_v.push(t_v_ms);
            indexer_ms_v.push(t_i_ms);
            constraint_v.push(d2.constraint_count as f64);
            proof_bytes_v.push(d2.proof_bytes as f64);
        }
    }

    emit_summaries(w, "B7", variant, &config_key, runner.warmup, &[
        ("indexer_ms",       indexer_ms_v),
        ("prove_ms",         prove_ms_v),
        ("verify_ms",        verify_ms_v),
        ("constraint_count", constraint_v),
        ("proof_bytes",      proof_bytes_v),
    ])?;
    Ok(())
}

fn run_pp3(
    runner: &RunnerConfig,
    cfg: &AuroraRerunConfig,
    w: &mut BenchWriter,
    security_level: usize,
) -> LoquatResult<()> {
    let policy = build_policy(cfg.pp3_policy_gpa_min, &cfg.pp3_policy_degree_set);
    let k = cfg.pp3_k;
    let lr_size = cfg.pp3_lr_size;
    let rev_depth = cfg.pp3_rev_depth;
    let variant = "pp3_aurora";
    let config_key = format!("sec={security_level}_k={k}_lr={lr_size}_rev{rev_depth}_policy");
    let config_val = serde_json::json!({
        "security_level": security_level,
        "k": k, "lr_size": lr_size, "rev_depth": rev_depth,
        "policy_gpa_min": cfg.pp3_policy_gpa_min,
        "policy_degree_set": cfg.pp3_policy_degree_set,
        "tiny": cfg.tiny
    });

    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut indexer_ms_v = Vec::new();
    let mut constraint_v = Vec::new();
    let mut proof_bytes_v = Vec::new();

    let total = runner.warmup + runner.runs;
    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let (result, _timer) = run_pp3_aurora_with_security(
            variant,
            k,
            security_level,
            lr_size,
            rev_depth,
            &policy,
            false,
        )
        .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
        let d2 = result.d2;

        let t_i_ms = d2.indexer_s * 1000.0;
        let t_p_ms = d2.prove_s * 1000.0;
        let t_v_ms = d2.verify_s * 1000.0;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B7".to_string(),
            variant: variant.to_string(),
            config_key: config_key.clone(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: t_i_ms + t_p_ms + t_v_ms,
            phases: serde_json::json!({
                "indexer_ms": t_i_ms, "prove_ms": t_p_ms, "verify_ms": t_v_ms,
                "instance_rebuild_ms": d2.instance_rebuild_s * 1000.0,
                "proof_verify_ms": d2.proof_verify_s * 1000.0,
            }),
            metrics: serde_json::json!({
                "security_level": security_level,
                "constraint_count": d2.constraint_count,
                "proof_bytes": d2.proof_bytes,
                "signature_bytes": d2.signature_bytes,
            }),
        })?;

        if !is_warmup {
            prove_ms_v.push(t_p_ms);
            verify_ms_v.push(t_v_ms);
            indexer_ms_v.push(t_i_ms);
            constraint_v.push(d2.constraint_count as f64);
            proof_bytes_v.push(d2.proof_bytes as f64);
        }
    }

    emit_summaries(w, "B7", variant, &config_key, runner.warmup, &[
        ("indexer_ms",       indexer_ms_v),
        ("prove_ms",         prove_ms_v),
        ("verify_ms",        verify_ms_v),
        ("constraint_count", constraint_v),
        ("proof_bytes",      proof_bytes_v),
    ])?;
    Ok(())
}

fn build_policy(gpa_min: i64, degree_set: &[String]) -> PolicyInput {
    let mut predicates = Vec::new();
    if gpa_min > 0 {
        predicates.push(PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: gpa_min,
        });
    }
    if !degree_set.is_empty() {
        predicates.push(PolicyPredicate::OneOf {
            key: "degree".to_string(),
            allowed_values: degree_set.to_vec(),
        });
    }
    PolicyInput { predicates }
}
