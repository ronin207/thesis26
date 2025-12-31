use std::{env, time::Duration, time::Instant};

use bincode::serialize;
use serde::{Deserialize, Serialize};
use vc_pqc::snarks::{
    AuroraParams, AuroraProverOptions, aurora_prove_with_options, aurora_verify, build_loquat_r1cs,
};
use vc_pqc::{
    LoquatSignature, LoquatSignatureArtifact, LoquatSigningTranscript, keygen_with_params,
    loquat_setup, loquat_setup_tiny, loquat_sign, loquat_verify,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FullTranscriptView {
    artifact: LoquatSignatureArtifact,
    transcript: Option<LoquatSigningTranscript>,
}

fn serialized_artifact_len(signature: &LoquatSignature) -> bincode::Result<usize> {
    Ok(serialize(&signature.artifact())?.len())
}

fn serialized_full_transcript_len(signature: &LoquatSignature) -> bincode::Result<usize> {
    let view = FullTranscriptView {
        artifact: signature.artifact(),
        transcript: signature.transcript.clone(),
    };
    Ok(serialize(&view)?.len())
}

fn serialize_artifact(signature: &LoquatSignature) -> bincode::Result<Vec<u8>> {
    serialize(&signature.artifact())
}

fn serialize_full_transcript(signature: &LoquatSignature) -> bincode::Result<Vec<u8>> {
    let view = FullTranscriptView {
        artifact: signature.artifact(),
        transcript: signature.transcript.clone(),
    };
    serialize(&view)
}

/// Simple run-length encoding for quick, dependency-free compression.
fn rle_compress(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let byte = data[i];
        let mut run_len = 1usize;
        while i + run_len < data.len() && data[i + run_len] == byte && run_len < 255 {
            run_len += 1;
        }
        out.push(run_len as u8);
        out.push(byte);
        i += run_len;
    }
    out
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() == 0 {
        format!("{:.2} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} s", duration.as_secs_f64())
    }
}

struct RunConfig {
    security: usize,
    message_len: usize,
    run_aurora: bool,
    aurora_queries: Option<usize>,
    tiny: bool,
    compress: bool,
    aurora_stats_only: bool,
    kappa: Option<usize>,
    paper_row: bool,
    paper_table3: bool,
    json: bool,
    iters: usize,
    aurora_iters: usize,
}

fn parse_args() -> Result<RunConfig, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let security = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(80);
    let message_len = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(32);
    let mut run_aurora = true;
    let mut aurora_queries = None;
    let mut tiny = false;
    let mut compress = false;
    let mut aurora_stats_only = false;
    let mut kappa = None;
    let mut paper_row = false;
    let mut paper_table3 = false;
    let mut json = false;
    let mut iters = 1usize;
    let mut aurora_iters = 1usize;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--skip-aurora" | "--no-aurora" => run_aurora = false,
            "--tiny" | "--test-params" => tiny = true,
            "--compress" => compress = true,
            "--aurora-stats-only" => aurora_stats_only = true,
            "--paper-row" => paper_row = true,
            "--paper-table3" | "--table3" => paper_table3 = true,
            "--json" | "--jsonl" => json = true,
            "--kappa" => {
                if let Some(next) = args.next() {
                    if let Ok(value) = next.parse::<usize>() {
                        kappa = Some(value);
                    } else {
                        eprintln!("Ignoring invalid --kappa value '{next}'");
                    }
                } else {
                    eprintln!("Missing value for --kappa, ignoring");
                }
            }
            "--iters" | "--iterations" => {
                if let Some(next) = args.next() {
                    if let Ok(value) = next.parse::<usize>() {
                        iters = value.max(1);
                    } else {
                        eprintln!("Ignoring invalid --iters value '{next}'");
                    }
                } else {
                    eprintln!("Missing value for --iters, ignoring");
                }
            }
            "--aurora-iters" | "--aurora-iterations" => {
                if let Some(next) = args.next() {
                    if let Ok(value) = next.parse::<usize>() {
                        aurora_iters = value.max(1);
                    } else {
                        eprintln!("Ignoring invalid --aurora-iters value '{next}'");
                    }
                } else {
                    eprintln!("Missing value for --aurora-iters, ignoring");
                }
            }
            "--queries" => {
                if let Some(next) = args.next() {
                    if let Ok(q) = next.parse() {
                        aurora_queries = Some(q);
                    } else {
                        eprintln!("Ignoring invalid --queries value '{next}'");
                    }
                }
            }
            _ if arg.starts_with("--queries=") => {
                if let Some(val) = arg.split_once('=').map(|(_, v)| v) {
                    if let Ok(q) = val.parse() {
                        aurora_queries = Some(q);
                    } else {
                        eprintln!("Ignoring invalid --queries value '{val}'");
                    }
                }
            }
            _ if arg.starts_with("--iters=") || arg.starts_with("--iterations=") => {
                if let Some(val) = arg.split_once('=').map(|(_, v)| v) {
                    if let Ok(value) = val.parse::<usize>() {
                        iters = value.max(1);
                    } else {
                        eprintln!("Ignoring invalid --iters value '{val}'");
                    }
                }
            }
            _ if arg.starts_with("--aurora-iters=") || arg.starts_with("--aurora-iterations=") => {
                if let Some(val) = arg.split_once('=').map(|(_, v)| v) {
                    if let Ok(value) = val.parse::<usize>() {
                        aurora_iters = value.max(1);
                    } else {
                        eprintln!("Ignoring invalid --aurora-iters value '{val}'");
                    }
                }
            }
            _ if arg.starts_with("--kappa=") => {
                if let Some(val) = arg.split_once('=').map(|(_, v)| v) {
                    if let Ok(value) = val.parse::<usize>() {
                        kappa = Some(value);
                    } else {
                        eprintln!("Ignoring invalid --kappa value '{val}'");
                    }
                }
            }
            other => eprintln!("Unrecognised argument '{other}', ignoring"),
        }
    }
    Ok(RunConfig {
        security,
        message_len,
        run_aurora,
        aurora_queries,
        tiny,
        compress,
        aurora_stats_only,
        kappa,
        paper_row,
        paper_table3,
        json,
        iters,
        aurora_iters,
    })
}

fn synthetic_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131) & 0xff) as u8).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;
    let message = synthetic_message(config.message_len);
    let quiet = config.paper_row || config.paper_table3 || config.json;

    if !quiet {
        println!("=== Loquat SNARK Stats ===\n");
        println!(
            "security level: {}-bit   message bytes: {}",
            config.security, config.message_len
        );
    }

    let tiny_env = std::env::var("LOQUAT_TINY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let effective_security = if config.tiny || tiny_env {
        if !quiet {
            println!("(tiny debug parameters enabled)");
        }
        80
    } else {
        config.security
    };
    let params = if let Some(kappa) = config.kappa {
        vc_pqc::loquat::setup::loquat_setup_with_kappa(effective_security, kappa)?
    } else if config.tiny || tiny_env {
        loquat_setup_tiny()?
    } else {
        loquat_setup(config.security)?
    };
    let keypair = keygen_with_params(&params)?;

    let mut total_sign_s = 0.0f64;
    let mut total_verify_s = 0.0f64;
    let mut artifact_bytes = 0usize;
    let mut transcript_bytes = 0usize;
    let mut signature: Option<LoquatSignature> = None;
    for iter in 0..config.iters {
    let sign_start = Instant::now();
        let sig = loquat_sign(&message, &keypair, &params)?;
    let sign_time = sign_start.elapsed();

    let verify_start = Instant::now();
        let is_valid = loquat_verify(&message, &sig, &keypair.public_key, &params)?;
    let verify_time = verify_start.elapsed();
    if !is_valid {
        eprintln!("signature failed to verify; aborting");
        return Ok(());
    }

        total_sign_s += sign_time.as_secs_f64();
        total_verify_s += verify_time.as_secs_f64();
        if iter == 0 {
            artifact_bytes = serialized_artifact_len(&sig)?;
            transcript_bytes = serialized_full_transcript_len(&sig)?;
        }
        signature = Some(sig);
    }
    let signature = signature.expect("signature loop always runs at least once");

    let avg_sign_s = total_sign_s / config.iters as f64;
    let avg_verify_s = total_verify_s / config.iters as f64;

    if config.paper_table3 {
        let sig_kib = artifact_bytes as f64 / 1024.0;
        println!(
            "Loquat-{} & {} & {:.1} & {:.3} & {:.3} & {} \\\\",
            effective_security,
            params.kappa,
            sig_kib,
            avg_sign_s,
            avg_verify_s,
            "Griffin"
        );
        return Ok(());
    }

    if !quiet {
        println!("\n--- Loquat signature ---");
        if config.iters == 1 {
            println!("  sign time:            {}", format_duration(Duration::from_secs_f64(avg_sign_s)));
            println!("  verify time:          {}", format_duration(Duration::from_secs_f64(avg_verify_s)));
        } else {
            println!(
                "  sign time (avg, n={}): {}",
                config.iters,
                format_duration(Duration::from_secs_f64(avg_sign_s))
            );
            println!(
                "  verify time (avg, n={}): {}",
                config.iters,
                format_duration(Duration::from_secs_f64(avg_verify_s))
            );
        }
        println!("  artifact size (B):    {:>10}", artifact_bytes);
        println!("  transcript size (B):  {:>10}", transcript_bytes);
        if config.compress {
            let artifact_raw = serialize_artifact(&signature)?;
            let artifact_compressed = rle_compress(&artifact_raw);
            let transcript_raw = serialize_full_transcript(&signature)?;
            let transcript_compressed = rle_compress(&transcript_raw);
            println!(
                "  artifact (RLE):       {:>10} (raw {})",
                artifact_compressed.len().min(artifact_raw.len()),
                artifact_raw.len()
            );
            println!(
                "  transcript (RLE):     {:>10} (raw {})",
                transcript_compressed.len().min(transcript_raw.len()),
                transcript_raw.len()
            );
        }
    }

    let sign_ms = avg_sign_s * 1000.0;
    let verify_ms = avg_verify_s * 1000.0;

    let print_paper_row = |r1cs_vars: Option<usize>,
                           r1cs_constraints: Option<usize>,
                           aurora_query_count: Option<usize>,
                           aurora_prove_s: Option<f64>,
                           aurora_verify_s: Option<f64>,
                           aurora_proof_bytes: Option<usize>,
                           aurora_ok: Option<bool>| {
        // LaTeX-friendly row with stable column ordering.
        // Columns:
        //   λ, |M|, κ, t_sign(ms), t_verify(ms), |σ_art|(B), |σ_full|(B),
        //   #vars, #constraints, q, t_aurora_prove(s), t_aurora_verify(s), |π|(B), ok
        let dash = "-";
        let fmt_usize = |v: Option<usize>| v.map(|x| x.to_string()).unwrap_or_else(|| dash.into());
        let fmt_f64_3 = |v: Option<f64>| v.map(|x| format!("{x:.3}")).unwrap_or_else(|| dash.into());
        let fmt_bool = |v: Option<bool>| {
            v.map(|b| if b { "1".to_string() } else { "0".to_string() })
                .unwrap_or_else(|| dash.into())
        };
        println!(
            "{} & {} & {} & {:.2} & {:.2} & {} & {} & {} & {} & {} & {} & {} & {} & {} \\\\",
            effective_security,
            config.message_len,
            params.kappa,
            sign_ms,
            verify_ms,
            artifact_bytes,
            transcript_bytes,
            fmt_usize(r1cs_vars),
            fmt_usize(r1cs_constraints),
            fmt_usize(aurora_query_count),
            fmt_f64_3(aurora_prove_s),
            fmt_f64_3(aurora_verify_s),
            fmt_usize(aurora_proof_bytes),
            fmt_bool(aurora_ok),
        );
    };

    if !config.run_aurora || config.aurora_stats_only {
        if config.paper_row {
            print_paper_row(None, None, None, None, None, None, None);
        } else if config.json {
            println!(
                "{{\"security\":{},\"message_len\":{},\"kappa\":{},\"iters\":{},\"sign_s\":{:.6},\"verify_s\":{:.6},\"artifact_bytes\":{},\"transcript_bytes\":{},\"r1cs_vars\":null,\"r1cs_constraints\":null,\"aurora_queries\":null,\"aurora_prove_s\":null,\"aurora_verify_s\":null,\"aurora_proof_bytes\":null,\"aurora_ok\":null}}",
                effective_security,
                config.message_len,
                params.kappa,
                config.iters,
                avg_sign_s,
                avg_verify_s,
                artifact_bytes,
                transcript_bytes
            );
        } else {
            println!(
                "\nAurora skipped ({}).",
                if !config.run_aurora {
                    "--skip-aurora"
                } else {
                    "--aurora-stats-only"
                }
            );
        }
        return Ok(());
    }

    let query_count = config.aurora_queries.unwrap_or(8);
    let (instance, witness) =
        build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)?;
    if !quiet {
        println!("\n--- R1CS stats ---");
        println!("  variables:            {}", instance.num_variables);
        println!("  constraints:          {}", instance.constraints.len());
    }
    let aurora_params = AuroraParams {
        constraint_query_count: query_count,
        witness_query_count: query_count,
    };
    let aurora_opts = AuroraProverOptions::default();

    let mut total_aurora_prove_s = 0.0f64;
    let mut total_aurora_verify_s = 0.0f64;
    let mut proof_bytes = 0usize;
    let mut aurora_ok = None;
    for _ in 0..config.aurora_iters {
    let prove_start = Instant::now();
    let proof = aurora_prove_with_options(&instance, &witness, &aurora_params, &aurora_opts)?;
    let aurora_prove_time = prove_start.elapsed();
        total_aurora_prove_s += aurora_prove_time.as_secs_f64();

        proof_bytes = serialize(&proof)?.len();
    let aurora_verify_start = Instant::now();
    let verify_result = aurora_verify(&instance, &proof, &aurora_params, None)?;
    let aurora_verify_time = aurora_verify_start.elapsed();
        total_aurora_verify_s += aurora_verify_time.as_secs_f64();
        aurora_ok = Some(verify_result.is_some());
    }
    let avg_aurora_prove_s = total_aurora_prove_s / config.aurora_iters as f64;
    let avg_aurora_verify_s = total_aurora_verify_s / config.aurora_iters as f64;

    if config.paper_row {
        print_paper_row(
            Some(instance.num_variables),
            Some(instance.constraints.len()),
            Some(query_count),
            Some(avg_aurora_prove_s),
            Some(avg_aurora_verify_s),
            Some(proof_bytes),
            aurora_ok,
        );
    } else if config.json {
        println!(
            "{{\"security\":{},\"message_len\":{},\"kappa\":{},\"iters\":{},\"sign_s\":{:.6},\"verify_s\":{:.6},\"artifact_bytes\":{},\"transcript_bytes\":{},\"r1cs_vars\":{},\"r1cs_constraints\":{},\"aurora_queries\":{},\"aurora_iters\":{},\"aurora_prove_s\":{:.6},\"aurora_verify_s\":{:.6},\"aurora_proof_bytes\":{},\"aurora_ok\":{}}}",
            effective_security,
            config.message_len,
            params.kappa,
            config.iters,
            avg_sign_s,
            avg_verify_s,
            artifact_bytes,
            transcript_bytes,
            instance.num_variables,
            instance.constraints.len(),
            query_count,
            config.aurora_iters,
            avg_aurora_prove_s,
            avg_aurora_verify_s,
            proof_bytes,
            aurora_ok.unwrap_or(false)
        );
    } else {
        println!("\n--- Aurora proof ---");
        if config.aurora_iters == 1 {
        println!(
            "  prove time:           {}",
                format_duration(Duration::from_secs_f64(avg_aurora_prove_s))
        );
        println!(
            "  verify time:          {}",
                format_duration(Duration::from_secs_f64(avg_aurora_verify_s))
            );
        } else {
            println!(
                "  prove time (avg, n={}): {}",
                config.aurora_iters,
                format_duration(Duration::from_secs_f64(avg_aurora_prove_s))
            );
            println!(
                "  verify time (avg, n={}): {}",
                config.aurora_iters,
                format_duration(Duration::from_secs_f64(avg_aurora_verify_s))
        );
        }
        println!("  proof size (B):       {:>10}", proof_bytes);
        println!(
            "  verification result:  {}",
            if aurora_ok.unwrap_or(false) {
                "success"
            } else {
                "failure"
            }
        );
    }

    Ok(())
}
