//! B4 — Aurora vs Fractal backend comparison.
//!
//! Builds a Loquat verification R1CS (k=1 credential, security_level from config)
//! and runs it through both Aurora and Fractal, reporting prove time, verify time,
//! and proof size.

use std::time::Instant;

use crate::bench::{BackendConfig, BenchWriter, RunnerConfig, SampleRecord, emit_summaries};
use crate::snarks::{AuroraParams, FractalParams, aurora_prove, aurora_verify, fractal_prove, fractal_verify};
use crate::snarks::build_loquat_r1cs_pk_witness;
use crate::{keygen_with_params, loquat_setup, loquat_setup_tiny, loquat_sign};
use crate::{LoquatError, LoquatResult};

pub fn run(runner: &RunnerConfig, cfg: &BackendConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    // Build a real Loquat verification R1CS instance with the configured security level.
    let params = if cfg.security_level <= 80 {
        loquat_setup_tiny()?
    } else {
        loquat_setup(cfg.security_level as usize)?
    };
    let keypair = keygen_with_params(&params)?;
    let msg = b"bench_backend_message_fixed";
    let signature = loquat_sign(msg, &keypair, &params)?;
    let (instance, witness) = build_loquat_r1cs_pk_witness(msg, &signature, &keypair.public_key, &params)?;

    let constraint_count = instance.num_constraints();
    let config_val = serde_json::json!({
        "security_level": cfg.security_level,
        "constraint_count": constraint_count,
    });

    if cfg.backends.iter().any(|b| b == "aurora") {
        run_aurora(runner, w, &config_val, &instance, &witness)?;
    }

    if cfg.backends.iter().any(|b| b == "fractal") {
        run_fractal(runner, w, &config_val, &instance, &witness)?;
    }

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

fn run_aurora(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    config_val: &serde_json::Value,
    instance: &crate::snarks::R1csInstance,
    witness: &crate::snarks::R1csWitness,
) -> LoquatResult<()> {
    let params = AuroraParams::default();
    let config_key = "aurora_loquat_r1cs".to_string();
    let total = runner.warmup + runner.runs;

    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut proof_bytes_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let prove_start = Instant::now();
        let proof = aurora_prove(instance, witness, &params)?;
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let proof_bytes = bincode::serialize(&proof)
            .unwrap_or_default()
            .len();

        let verify_start = Instant::now();
        aurora_verify(instance, &proof, &params, None)?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B4".to_string(),
            variant: "aurora".to_string(),
            config_key: config_key.clone(),
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

    emit_summaries(w, "B4", "aurora", &config_key, runner.warmup, &[
        ("prove_ms",    prove_ms_v),
        ("verify_ms",   verify_ms_v),
        ("proof_bytes", proof_bytes_v),
    ])?;
    Ok(())
}

fn run_fractal(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    config_val: &serde_json::Value,
    instance: &crate::snarks::R1csInstance,
    witness: &crate::snarks::R1csWitness,
) -> LoquatResult<()> {
    let params = FractalParams::default();
    let config_key = "fractal_loquat_r1cs".to_string();
    let total = runner.warmup + runner.runs;

    let mut prove_ms_v = Vec::new();
    let mut verify_ms_v = Vec::new();
    let mut proof_bytes_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let prove_start = Instant::now();
        let proof = fractal_prove(instance, witness, &params)?;
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
        let proof_bytes = bincode::serialize(&proof)
            .unwrap_or_default()
            .len();

        let verify_start = Instant::now();
        fractal_verify(instance, &proof, &params)?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B4".to_string(),
            variant: "fractal".to_string(),
            config_key: config_key.clone(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: prove_ms + verify_ms,
            phases: serde_json::json!({"prove_ms": prove_ms, "verify_ms": verify_ms}),
            metrics: serde_json::json!({
                "proof_bytes":  proof_bytes,
                "fold_layers":  proof.fold_layers.len(),
            }),
        })?;

        if !is_warmup {
            prove_ms_v.push(prove_ms);
            verify_ms_v.push(verify_ms);
            proof_bytes_v.push(proof_bytes as f64);
        }
    }

    emit_summaries(w, "B4", "fractal", &config_key, runner.warmup, &[
        ("prove_ms",    prove_ms_v),
        ("verify_ms",   verify_ms_v),
        ("proof_bytes", proof_bytes_v),
    ])?;
    Ok(())
}
