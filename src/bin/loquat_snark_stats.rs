//! Run with `RUST_LOG=vc_pqc=trace cargo run --bin loquat_snark_stats -- [security_levels] [msg_len]`.
//! `security_levels` may be a single value (e.g. `100`) or a comma-separated list such as
//! `80,100,128`. When omitted, the default trio `[80, 100, 128]` from Table 3 is used.

use std::{env, time::Duration, time::Instant};

use bincode::serialize;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;
use vc_pqc::loquat::setup::{SUPPORTED_SECURITY_LEVELS, security_profile};
use vc_pqc::snarks::{
    AuroraParams, AuroraProverOptions, aurora_prove_with_options, aurora_verify, build_loquat_r1cs,
};
use vc_pqc::{
    LoquatSignature, LoquatSignatureArtifact, LoquatSigningTranscript, keygen_with_params,
    loquat_setup, loquat_sign, loquat_verify,
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

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() == 0 {
        format!("{:.2} ms", duration.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.3} s", duration.as_secs_f64())
    }
}

const DEFAULT_SECURITY_LEVELS: [usize; 3] = [80, 100, 128];

fn supported_levels_display() -> String {
    SUPPORTED_SECURITY_LEVELS
        .iter()
        .map(|lvl| format!("{}-bit", lvl))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_security_token(raw: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty security level token".into());
    }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(format!(
            "Could not parse security level '{raw}'. Try values like 80 or LOQUAT-100."
        )
        .into());
    }
    Ok(digits.parse::<usize>()?)
}

fn parse_security_levels(raw: Option<String>) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    let tokens: Vec<String> = if let Some(raw_value) = raw {
        if raw_value.eq_ignore_ascii_case("all")
            || raw_value.eq_ignore_ascii_case("default")
            || raw_value.is_empty()
        {
            DEFAULT_SECURITY_LEVELS
                .iter()
                .map(|lvl| lvl.to_string())
                .collect()
        } else {
            raw_value
                .split(',')
                .map(|chunk| chunk.trim().to_string())
                .filter(|chunk| !chunk.is_empty())
                .collect()
        }
    } else {
        DEFAULT_SECURITY_LEVELS
            .iter()
            .map(|lvl| lvl.to_string())
            .collect()
    };

    let mut deduped = Vec::with_capacity(tokens.len());
    for token in tokens {
        let level = parse_security_token(&token)?;
        if !SUPPORTED_SECURITY_LEVELS.contains(&level) {
            return Err(format!(
                "Unsupported security level {}. Supported levels: {}",
                level,
                supported_levels_display()
            )
            .into());
        }
        if !deduped.contains(&level) {
            deduped.push(level);
        }
    }
    Ok(deduped)
}

fn parse_args() -> Result<(Vec<usize>, usize), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let security_levels = parse_security_levels(args.next())?;
    let message_len = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(32);
    Ok((security_levels, message_len))
}

fn synthetic_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131) & 0xff) as u8).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("vc_pqc=trace"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .compact()
        .try_init()
        .ok();

    let (security_levels, message_len) = parse_args()?;
    for (idx, security_level) in security_levels.iter().copied().enumerate() {
        if idx > 0 {
            println!();
        }
        run_for_security_level(security_level, message_len)?;
    }

    Ok(())
}

fn run_for_security_level(
    security_level: usize,
    message_len: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let message = synthetic_message(message_len);

    println!(
        "=== Loquat SNARK Stats (λ={} bits, message={} bytes) ===\n",
        security_level, message_len
    );

    if let Some(profile) = security_profile(security_level) {
        println!("  public key bits (L): {}", profile.l);
        println!("  query complexity κ:  {}", profile.kappa);
    }

    let params = loquat_setup(security_level)?;
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

    println!("\n--- Loquat signature ---");
    println!("  sign time:            {}", format_duration(sign_time));
    println!("  verify time:          {}", format_duration(verify_time));
    println!("  artifact size (B):    {:>10}", artifact_bytes);
    println!("  transcript size (B):  {:>10}", transcript_bytes);

    let (instance, witness) =
        build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)?;
    println!("\n--- R1CS stats ---");
    println!("  variables:            {}", instance.num_variables);
    println!("  constraints:          {}", instance.constraints.len());

    let aurora_params = AuroraParams {
        constraint_query_count: 8,
        witness_query_count: 8,
    };
    let aurora_opts = AuroraProverOptions::default();

    let prove_start = Instant::now();
    let proof = aurora_prove_with_options(&instance, &witness, &aurora_params, &aurora_opts)?;
    let aurora_prove_time = prove_start.elapsed();

    let proof_bytes = serialize(&proof)?.len();
    let aurora_verify_start = Instant::now();
    let verify_result = aurora_verify(&instance, &proof, &aurora_params, None)?;
    let aurora_verify_time = aurora_verify_start.elapsed();

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

    Ok(())
}
