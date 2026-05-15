//! B2 — Noir-generated vs hand-written R1CS comparison.
//!
//! **Hand-written** path: `build_loquat_r1cs_pk_witness(msg, sig, pk, params)` from
//!   `src/snarks/loquat_r1cs.rs` (Algorithm 7 Loquat verification circuit).
//!
//! **Noir-generated** path: read the compiled ACIR JSON from
//!   `noir/bdec_showver/target/bdec_showver.json` and convert via
//!   `convert_acir_to_r1cs`.
//!
//! Metrics: constraint count, witness variable count, Aurora prove time,
//! verify time, and proof size.

use std::time::Instant;

use crate::bench::{BenchWriter, R1csCompareConfig, RunnerConfig, SampleRecord, emit_summaries};
use crate::compilers::noir::{convert_acir_to_r1cs, parse_acir_json};
use crate::snarks::{AuroraParams, aurora_prove, aurora_verify, build_loquat_r1cs_pk_witness};
use crate::{keygen_with_params, loquat_setup, loquat_setup_tiny, loquat_sign};
use crate::{LoquatError, LoquatResult};

pub fn run(runner: &RunnerConfig, cfg: &R1csCompareConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    let params = if cfg.security_level <= 80 {
        loquat_setup_tiny()?
    } else {
        loquat_setup(cfg.security_level as usize)?
    };
    let keypair = keygen_with_params(&params)?;
    let msg = b"r1cs_compare_bench_msg";
    let signature = loquat_sign(msg, &keypair, &params)?;

    // ── Hand-written R1CS ─────────────────────────────────────────────────────
    let hw_start = Instant::now();
    let (hw_instance, hw_witness) =
        build_loquat_r1cs_pk_witness(msg, &signature, &keypair.public_key, &params)?;
    let hw_build_ms = hw_start.elapsed().as_secs_f64() * 1000.0;
    let hw_constraints = hw_instance.num_constraints();
    let hw_vars = hw_instance.num_variables;

    let config_key = format!("security={}", cfg.security_level);
    let hw_config = serde_json::json!({
        "source": "hand_written",
        "security_level": cfg.security_level,
        "constraint_count": hw_constraints,
        "witness_vars": hw_vars,
    });

    w.emit_sample(&SampleRecord {
        r#type: "sample",
        suite: "B2".to_string(),
        variant: "hand_written_build".to_string(),
        config_key: config_key.clone(),
        config: hw_config.clone(),
        run: 0,
        is_warmup: false,
        wall_ms: hw_build_ms,
        phases: serde_json::json!({}),
        metrics: serde_json::json!({
            "constraint_count": hw_constraints,
            "witness_vars": hw_vars,
        }),
    })?;

    // ── Noir-generated R1CS ───────────────────────────────────────────────────
    let noir_artifact = "noir/bdec_showver/target/bdec_showver.json";
    let noir_package_dir = "noir/bdec_showver";

    // Try to parse the artifact as the old JSON R1CS format.
    // On failure (binary ACIR from nargo >= 1.0.0-beta.17, schema mismatch, etc.)
    // fall back to `nargo info` for a gate-count proxy.
    match load_noir_r1cs(noir_artifact) {
        Ok((noir_instance, noir_witness_opt, noir_build_ms)) => {
            let noir_constraints = noir_instance.num_constraints();
            let noir_vars = noir_instance.num_variables;

            let noir_config = serde_json::json!({
                "source": "noir_generated",
                "artifact": noir_artifact,
                "constraint_count": noir_constraints,
                "witness_vars": noir_vars,
            });

            w.emit_sample(&SampleRecord {
                r#type: "sample",
                suite: "B2".to_string(),
                variant: "noir_generated_build".to_string(),
                config_key: config_key.clone(),
                config: noir_config.clone(),
                run: 0,
                is_warmup: false,
                wall_ms: noir_build_ms,
                phases: serde_json::json!({}),
                metrics: serde_json::json!({
                    "constraint_count": noir_constraints,
                    "witness_vars": noir_vars,
                    "overhead_vs_hw": noir_constraints as i64 - hw_constraints as i64,
                    "overhead_pct": (noir_constraints as f64 / hw_constraints as f64 - 1.0) * 100.0,
                }),
            })?;

            // Comparison diff record.
            w.emit_sample(&SampleRecord {
                r#type: "sample",
                suite: "B2".to_string(),
                variant: "comparison".to_string(),
                config_key: config_key.clone(),
                config: serde_json::json!({"security_level": cfg.security_level}),
                run: 0,
                is_warmup: false,
                wall_ms: 0.0,
                phases: serde_json::json!({}),
                metrics: serde_json::json!({
                    "hw_constraints":   hw_constraints,
                    "noir_constraints": noir_constraints,
                    "overhead_absolute": noir_constraints as i64 - hw_constraints as i64,
                    "overhead_pct": (noir_constraints as f64 / hw_constraints as f64 - 1.0) * 100.0,
                    "hw_vars":   hw_vars,
                    "noir_vars": noir_vars,
                }),
            })?;

            // Aurora comparison (optional).
            if cfg.run_aurora {
                run_aurora_comparison(
                    runner, w, &config_key,
                    &hw_config, &hw_instance, &hw_witness,
                    &noir_config, &noir_instance, &noir_witness_opt,
                )?;
            }
        }
        Err(load_err) => {
            // R1CS load failed — could be binary ACIR (nargo >= 1.0.0-beta.17),
            // a schema mismatch, or the artifact simply not compiling the real circuit.
            // Fall back to `nargo info` for a gate-count proxy.
            eprintln!("[B2] Noir R1CS load failed ({noir_artifact}): {load_err}.");
            match query_nargo_gate_count("nargo", noir_package_dir) {
                Some((acir_opcodes, brillig_opcodes)) => {
                    eprintln!(
                        "[B2] nargo info fallback: acir_opcodes={acir_opcodes}, \
                         brillig_opcodes={brillig_opcodes}"
                    );
                    w.emit_sample(&SampleRecord {
                        r#type: "sample",
                        suite: "B2".to_string(),
                        variant: "noir_info_only".to_string(),
                        config_key: config_key.clone(),
                        config: serde_json::json!({
                            "source": "nargo_info_json",
                            "artifact": noir_artifact,
                        }),
                        run: 0,
                        is_warmup: false,
                        wall_ms: 0.0,
                        phases: serde_json::json!({}),
                        metrics: serde_json::json!({
                            "acir_opcodes": acir_opcodes,
                            "brillig_opcodes": brillig_opcodes,
                            "hw_constraints_ref": hw_constraints,
                            // Why this comparison is structurally apples-to-oranges:
                            //   (a) nargo >= 1.0.0-beta.17 emits binary ACIR (gzip'd); the
                            //       JSON ACIR parser used below cannot decode it. Fix would
                            //       need the `acir` crate + flate2 (~75 LoC).
                            //   (b) Even with a working binary ACIR decoder, the Noir
                            //       `loquat_lib` crate stubs the heavy ops (loquat_verify,
                            //       griffin_hash, merkle_non_member all return true/zeros).
                            //       The Rust ACIR->R1CS converter re-expands those black
                            //       boxes into real Loquat constraints, so the Noir side
                            //       would STILL undercount when measured at compile time.
                            // Upshot: the honest cross-backend comparison is between the
                            // hand-written R1CS (this suite) and a Noir circuit whose
                            // loquat_lib is fully inlined -- a separate engineering task.
                            "note": "R1CS conversion unavailable (nargo>=1.0.0-beta.17 binary \
                                     ACIR). Independent of that, noir/loquat_lib stubs the \
                                     heavy ops, so acir_opcodes is a lower bound only and is \
                                     NOT directly comparable to hw_constraints_ref."
                        }),
                    })?;
                }
                None => {
                    eprintln!(
                        "[B2] nargo info also failed; skipping Noir comparison entirely"
                    );
                }
            }
        }
    }

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

fn load_noir_r1cs(
    artifact_path: &str,
) -> LoquatResult<(crate::snarks::R1csInstance, Option<crate::snarks::R1csWitness>, f64)> {
    let json = std::fs::read_to_string(artifact_path).map_err(|e| {
        LoquatError::invalid_parameters(&format!("cannot read {artifact_path}: {e}"))
    })?;
    let start = Instant::now();
    let program = parse_acir_json(&json)?;
    let build = convert_acir_to_r1cs(&program, None)?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    Ok((build.instance, build.witness, elapsed))
}

/// Run `nargo info --json` and return `(acir_opcodes, brillig_opcodes)` for the main function.
///
/// nargo >= 1.0.0-beta.17 JSON output format:
/// ```json
/// {"programs":[{"package_name":"...","functions":[{"name":"main","opcodes":N}],
///               "unconstrained_functions":[...]}]}
/// ```
/// The `opcodes` field is ACIR opcodes; Brillig opcodes come from the matching
/// unconstrained function named "main" (or the first unconstrained entry).
fn query_nargo_gate_count(nargo_bin: &str, package_dir: &str) -> Option<(usize, usize)> {
    let bin = if nargo_bin.is_empty() { "nargo" } else { nargo_bin };
    let output = std::process::Command::new(bin)
        .arg("info")
        .arg("--json")
        .current_dir(package_dir)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let program = json.get("programs")?.as_array()?.first()?;
    let acir_opcodes = program
        .get("functions")?
        .as_array()?
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("main"))
        .and_then(|f| f.get("opcodes")?.as_u64())
        .map(|n| n as usize)?;
    let brillig_opcodes = program
        .get("unconstrained_functions")
        .and_then(|uf| uf.as_array())
        .and_then(|arr| arr.iter().find(|f| f.get("name").and_then(|n| n.as_str()) == Some("main")))
        .and_then(|f| f.get("opcodes")?.as_u64())
        .map(|n| n as usize)
        .unwrap_or(0);
    Some((acir_opcodes, brillig_opcodes))
}

#[allow(clippy::too_many_arguments)]
fn run_aurora_comparison(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    config_key: &str,
    hw_config: &serde_json::Value,
    hw_instance: &crate::snarks::R1csInstance,
    hw_witness: &crate::snarks::R1csWitness,
    noir_config: &serde_json::Value,
    noir_instance: &crate::snarks::R1csInstance,
    noir_witness_opt: &Option<crate::snarks::R1csWitness>,
) -> LoquatResult<()> {
    // Hand-written aurora: we always have a valid witness.
    prove_aurora_timed(runner, w, "B2", "hand_written_aurora", config_key, hw_config,
                       hw_instance, hw_witness)?;

    // Noir-generated aurora: only run if we got a witness from the conversion.
    if let Some(noir_witness) = noir_witness_opt {
        prove_aurora_timed(runner, w, "B2", "noir_generated_aurora", config_key, noir_config,
                           noir_instance, noir_witness)?;
    } else {
        eprintln!("[B2] Noir witness not available (no concrete inputs); skipping Aurora prove");
    }
    Ok(())
}

fn prove_aurora_timed(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    suite: &str,
    variant: &str,
    config_key: &str,
    config: &serde_json::Value,
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
            variant: variant.to_string(),
            config_key: config_key.to_string(),
            config: config.clone(),
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

    emit_summaries(w, suite, variant, config_key, runner.warmup, &[
        ("prove_ms",    prove_ms_v),
        ("verify_ms",   verify_ms_v),
        ("proof_bytes", proof_bytes_v),
    ])?;
    Ok(())
}
