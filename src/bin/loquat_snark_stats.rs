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
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--skip-aurora" | "--no-aurora" => run_aurora = false,
            "--tiny" | "--test-params" => tiny = true,
            "--compress" => compress = true,
            "--aurora-stats-only" => aurora_stats_only = true,
            "--paper-row" => paper_row = true,
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
    })
}

fn synthetic_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131) & 0xff) as u8).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;
    let message = synthetic_message(config.message_len);

    if !config.paper_row {
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
        if !config.paper_row {
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

    let sign_start = Instant::now();
    let signature = loquat_sign(&message, &keypair, &params)?;
    let sign_time = sign_start.elapsed();

    let verify_start = Instant::now();
    let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params)?;
    let verify_time = verify_start.elapsed();
    if !is_valid {
        eprintln!("signature failed to verify; aborting");
        return Ok(());
    }

    let artifact_bytes = serialized_artifact_len(&signature)?;
    let transcript_bytes = serialized_full_transcript_len(&signature)?;

    if !config.paper_row {
        println!("\n--- Loquat signature ---");
        println!("  sign time:            {}", format_duration(sign_time));
        println!("  verify time:          {}", format_duration(verify_time));
        println!("  artifact size (B):    {:>10}", artifact_bytes);
        println!("  transcript size (B):  {:>10}", transcript_bytes);
        if config.compress {
            let artifact_bytes = serialize_artifact(&signature)?;
            let artifact_compressed = rle_compress(&artifact_bytes);
            let transcript_bytes = serialize_full_transcript(&signature)?;
            let transcript_compressed = rle_compress(&transcript_bytes);
            println!(
                "  artifact (RLE):       {:>10} (raw {})",
                artifact_compressed.len().min(artifact_bytes.len()),
                artifact_bytes.len()
            );
            println!(
                "  transcript (RLE):     {:>10} (raw {})",
                transcript_compressed.len().min(transcript_bytes.len()),
                transcript_bytes.len()
            );
        }
    }

    let sign_ms = sign_time.as_secs_f64() * 1000.0;
    let verify_ms = verify_time.as_secs_f64() * 1000.0;

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

    let query_count = config.aurora_queries.unwrap_or(4);
    let (instance, witness) =
        build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)?;
    if !config.paper_row {
        println!("\n--- R1CS stats ---");
        println!("  variables:            {}", instance.num_variables);
        println!("  constraints:          {}", instance.constraints.len());
    }
    let aurora_params = AuroraParams {
        constraint_query_count: query_count,
        witness_query_count: query_count,
    };
    let aurora_opts = AuroraProverOptions::default();

    let prove_start = Instant::now();
    let proof = aurora_prove_with_options(&instance, &witness, &aurora_params, &aurora_opts)?;
    let aurora_prove_time = prove_start.elapsed();

    let proof_bytes = serialize(&proof)?.len();
    let aurora_verify_start = Instant::now();
    let verify_result = aurora_verify(&instance, &proof, &aurora_params, None)?;
    let aurora_verify_time = aurora_verify_start.elapsed();

    if config.paper_row {
        print_paper_row(
            Some(instance.num_variables),
            Some(instance.constraints.len()),
            Some(query_count),
            Some(aurora_prove_time.as_secs_f64()),
            Some(aurora_verify_time.as_secs_f64()),
            Some(proof_bytes),
            Some(verify_result.is_some()),
        );
    } else {
        println!("\n--- Aurora proof ---");
        println!(
            "  prove time:           {}",
            format_duration(aurora_prove_time)
        );
        println!(
            "  verify time:          {}",
            format_duration(aurora_verify_time)
        );
        println!("  proof size (B):       {:>10}", proof_bytes);
        println!(
            "  verification result:  {}",
            if verify_result.is_some() {
                "success"
            } else {
                "failure"
            }
        );
    }

    Ok(())
}
