//! B5 — Griffin hash cost breakdown.
//!
//! Measures the fraction of the ShowCre circuit cost attributable to Griffin
//! hashing, using three reference circuits:
//!
//! 1. **Loquat-only** — one Loquat sig-verify circuit (Griffin-heavy)
//!    via `build_loquat_r1cs_pk_sig_witness_instance`.
//! 2. **Merkle-only** — a Merkle revocation path circuit (pure Griffin Merkle)
//!    via `build_revocation_r1cs_pk_witness_instance`.
//! 3. **Full credential** — complete ShowCre (k=1) via `run_pp2_aurora_single_opts`.
//!
//! The full-credential constraint count is the 100% reference; the other two
//! are expressed as fractions of it.

use std::time::Instant;

use crate::bench::{BenchWriter, GriffinConfig, RunnerConfig, SampleRecord, emit_summaries};
use crate::evaluation::run_pp2_aurora_single_opts;
use crate::snarks::{
    AuroraParams, aurora_prove, aurora_verify,
    build_loquat_r1cs_pk_witness, build_loquat_r1cs_pk_sig_witness_instance,
    build_revocation_r1cs_pk_witness_instance, take_last_r1cs_breakdown,
};
use crate::{keygen_with_params, loquat_setup, loquat_sign};
use crate::{LoquatError, LoquatResult};

pub fn run(runner: &RunnerConfig, cfg: &GriffinConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    // ── Full credential reference (constraint count + timing) ─────────────────
    let (full_constraints, full_prove_ms, full_verify_ms, full_proof_bytes) =
        measure_full_credential(runner, cfg, w)?;

    eprintln!(
        "[B5] full credential: k={}, m={}, rev_depth={} → {full_constraints} constraints",
        cfg.full_k, cfg.full_attr, cfg.full_rev_depth
    );

    // ── Loquat-only sub-circuit (Griffin inside Loquat sig verify) ────────────
    // Build the instance-only form so we don't need a valid witness.
    let loquat_params = loquat_setup(128usize)?;
    let keypair = keygen_with_params(&loquat_params)?;
    let msg = b"b5_griffin_bench";
    let signature = loquat_sign(msg, &keypair, &loquat_params)?;
    let loquat_instance =
        build_loquat_r1cs_pk_sig_witness_instance(msg, &loquat_params)?;
    let loquat_constraints = loquat_instance.num_constraints();
    let loquat_fraction = loquat_constraints as f64 / full_constraints as f64;

    w.emit_sample(&SampleRecord {
        r#type: "sample",
        suite: "B5".to_string(),
        variant: "loquat_only".to_string(),
        config_key: "loquat_sig_verify".to_string(),
        config: serde_json::json!({
            "variant": "loquat_only",
            "description": "one Loquat sig-verify circuit (Griffin-heavy)"
        }),
        run: 0,
        is_warmup: false,
        wall_ms: 0.0,
        phases: serde_json::json!({}),
        metrics: serde_json::json!({
            "constraint_count":    loquat_constraints,
            "full_constraint_ref": full_constraints,
            "fraction_of_full":    loquat_fraction,
        }),
    })?;

    // ── Per-phase Griffin breakdown (B5 component rows) ───────────────────────
    // Trigger a single `build_loquat_r1cs` with a valid signature so the
    // `ConstraintTracker` inside populates the thread-local. We emit one
    // `variant: "breakdown_phase"` sample per (label, Δconstraints, Δvariables)
    // entry — downstream aggregators sum these to reconstruct the coarse
    // Loquat-only total, and the fractions go straight into the Griffin
    // cost-breakdown table in bench_results.xlsx.
    match build_loquat_r1cs_pk_witness(msg, &signature, &keypair.public_key, &loquat_params) {
        Ok((_inst, _wit)) => {
            if let Some(breakdown) = take_last_r1cs_breakdown() {
                let total_constraints: usize =
                    breakdown.iter().map(|(_, dc, _)| *dc).sum();
                for (phase, delta_c, delta_v) in &breakdown {
                    let fraction_of_loquat = if total_constraints == 0 {
                        0.0
                    } else {
                        *delta_c as f64 / total_constraints as f64
                    };
                    let fraction_of_full = if full_constraints == 0 {
                        0.0
                    } else {
                        *delta_c as f64 / full_constraints as f64
                    };
                    w.emit_sample(&SampleRecord {
                        r#type: "sample",
                        suite: "B5".to_string(),
                        variant: "breakdown_phase".to_string(),
                        config_key: (*phase).to_string(),
                        config: serde_json::json!({
                            "phase": phase,
                            "source": "build_loquat_r1cs",
                        }),
                        run: 0,
                        is_warmup: false,
                        wall_ms: 0.0,
                        phases: serde_json::json!({}),
                        metrics: serde_json::json!({
                            "delta_constraints":  delta_c,
                            "delta_variables":    delta_v,
                            "loquat_total":       total_constraints,
                            "fraction_of_loquat": fraction_of_loquat,
                            "full_constraint_ref": full_constraints,
                            "fraction_of_full":   fraction_of_full,
                        }),
                    })?;
                }
            } else {
                eprintln!("[B5] breakdown: thread-local empty after build_loquat_r1cs");
            }
        }
        Err(e) => {
            eprintln!("[B5] breakdown: build_loquat_r1cs failed ({e}); skipping phase rows");
        }
    }

    // ── Merkle-only sub-circuit (Griffin path) ────────────────────────────────
    let root = [0u8; 32];
    let pk_len = loquat_params.l;
    let merkle_instance =
        build_revocation_r1cs_pk_witness_instance(&root, cfg.merkle_depth, pk_len)?;
    let merkle_constraints = merkle_instance.num_constraints();
    let merkle_fraction = merkle_constraints as f64 / full_constraints as f64;
    let merkle_config_key = format!("merkle_depth={}", cfg.merkle_depth);

    w.emit_sample(&SampleRecord {
        r#type: "sample",
        suite: "B5".to_string(),
        variant: "merkle_only".to_string(),
        config_key: merkle_config_key.clone(),
        config: serde_json::json!({
            "variant": "merkle_only",
            "depth": cfg.merkle_depth,
        }),
        run: 0,
        is_warmup: false,
        wall_ms: 0.0,
        phases: serde_json::json!({}),
        metrics: serde_json::json!({
            "constraint_count":    merkle_constraints,
            "full_constraint_ref": full_constraints,
            "fraction_of_full":    merkle_fraction,
        }),
    })?;

    // ── Aurora timing for the Loquat-only sub-circuit ─────────────────────────
    // Build the full witness form for proving.
    // Note: build_loquat_r1cs_pk_sig_witness_inner uses an in-circuit transcript
    // that may diverge from the signing transcript (different I_{j,i} indices),
    // making QR targets non-square.  We handle the failure gracefully so B5 still
    // records the constraint-fraction results even when the proving step is skipped.
    match crate::snarks::build_loquat_r1cs_pk_sig_witness(msg, &signature, &keypair.public_key, &loquat_params) {
        Ok((loquat_instance_w, loquat_witness)) => {
            run_aurora_on(
                runner, w, "B5", "loquat_only", "loquat_sig_verify",
                &serde_json::json!({"variant":"loquat_only","constraint_count":loquat_constraints}),
                &loquat_instance_w, &loquat_witness,
            )?;
        }
        Err(e) => {
            eprintln!("[B5] loquat_only_aurora: witness build failed ({e}); skipping Aurora timing");
            w.emit_sample(&SampleRecord {
                r#type: "sample",
                suite: "B5".to_string(),
                variant: "loquat_only_aurora".to_string(),
                config_key: "loquat_sig_verify".to_string(),
                config: serde_json::json!({
                    "variant": "loquat_only",
                    "constraint_count": loquat_constraints,
                }),
                run: 0,
                is_warmup: false,
                wall_ms: 0.0,
                phases: serde_json::json!({
                    "skip_reason": e.to_string(),
                    "note": "in-circuit transcript diverges from signing transcript; QR target non-square"
                }),
                metrics: serde_json::json!({}),
            })?;
        }
    }

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

/// Run the full credential (k=1) and return (constraint_count, prove_ms, verify_ms, proof_bytes).
fn measure_full_credential(
    runner: &RunnerConfig,
    cfg: &GriffinConfig,
    w: &mut BenchWriter,
) -> LoquatResult<(usize, f64, f64, usize)> {
    let config_key = format!(
        "full_k={}_m={}_rev{}", cfg.full_k, cfg.full_attr, cfg.full_rev_depth
    );

    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut proof_bytes_v = Vec::new();
    let mut constraint_count = 0usize;

    let total = runner.warmup + runner.runs;
    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let (result, _timer) = run_pp2_aurora_single_opts(
            cfg.full_k, false, 0, cfg.full_rev_depth, false,
        )
        .map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
        let d2 = result.d2;

        constraint_count = d2.constraint_count;
        let prove_ms = d2.prove_s * 1000.0;
        let verify_ms = d2.verify_s * 1000.0;
        let proof_bytes = d2.proof_bytes;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B5".to_string(),
            variant: "full_credential".to_string(),
            config_key: config_key.clone(),
            config: serde_json::json!({
                "k": cfg.full_k, "attr_count": cfg.full_attr, "rev_depth": cfg.full_rev_depth,
                "constraint_count": constraint_count,
            }),
            run: run_idx,
            is_warmup,
            wall_ms: prove_ms + verify_ms,
            phases: serde_json::json!({"prove_ms": prove_ms, "verify_ms": verify_ms}),
            metrics: serde_json::json!({"constraint_count": constraint_count, "proof_bytes": proof_bytes}),
        })?;

        if !is_warmup {
            prove_ms_v.push(prove_ms);
            verify_ms_v.push(verify_ms);
            proof_bytes_v.push(proof_bytes as f64);
        }
    }

    emit_summaries(w, "B5", "full_credential", &config_key, runner.warmup, &[
        ("prove_ms",         prove_ms_v.clone()),
        ("verify_ms",        verify_ms_v.clone()),
        ("proof_bytes",      proof_bytes_v.clone()),
        ("constraint_count", vec![constraint_count as f64; prove_ms_v.len()]),
    ])?;

    let mean_prove = if prove_ms_v.is_empty() { 0.0 } else {
        prove_ms_v.iter().sum::<f64>() / prove_ms_v.len() as f64
    };
    let mean_verify = if verify_ms_v.is_empty() { 0.0 } else {
        verify_ms_v.iter().sum::<f64>() / verify_ms_v.len() as f64
    };
    let mean_bytes = if proof_bytes_v.is_empty() { 0.0 } else {
        proof_bytes_v.iter().sum::<f64>() / proof_bytes_v.len() as f64
    };

    Ok((constraint_count, mean_prove, mean_verify, mean_bytes as usize))
}

fn run_aurora_on(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    suite: &str,
    variant: &str,
    config_key: &str,
    config_val: &serde_json::Value,
    instance: &crate::snarks::R1csInstance,
    witness: &crate::snarks::R1csWitness,
) -> LoquatResult<()> {
    let params = AuroraParams::default();
    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut proof_bytes_v = Vec::new();

    let total = runner.warmup + runner.runs;
    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let prove_start = Instant::now();
        let proof = aurora_prove(instance, witness, &params)?;
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let proof_bytes = bincode::serialize(&proof).unwrap_or_default().len();

        let verify_start = Instant::now();
        aurora_verify(instance, &proof, &params, None)?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: suite.to_string(),
            variant: format!("{variant}_aurora"),
            config_key: config_key.to_string(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: prove_ms + verify_ms,
            phases: serde_json::json!({"prove_ms": prove_ms, "verify_ms": verify_ms}),
            metrics: serde_json::json!({"proof_bytes": proof_bytes}),
        })?;

        if !is_warmup {
            prove_ms_v.push(prove_ms);
            verify_ms_v.push(verify_ms);
            proof_bytes_v.push(proof_bytes as f64);
        }
    }

    emit_summaries(w, suite, &format!("{variant}_aurora"), config_key, runner.warmup, &[
        ("prove_ms",    prove_ms_v),
        ("verify_ms",   verify_ms_v),
        ("proof_bytes", proof_bytes_v),
    ])?;
    Ok(())
}
