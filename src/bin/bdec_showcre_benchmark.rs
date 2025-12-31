//! Benchmark for BDEC ShowCre performance across varying numbers of TA credentials.
//!
//! Measures:
//! - t_I: Indexer/setup time (credential issuance from k TAs)
//! - t_P: Proving time (ShowCre proof generation)
//! - t_V: Verification time (ShowVer proof verification)
//! - |σ|: Loquat signature size (the shown credential signature c_U_V)
//!
//! Usage:
//!   cargo run --release --bin bdec_showcre_benchmark [--json] [--tiny]

use std::time::Instant;

use bincode::serialize;
use vc_pqc::bdec::{
    bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_setup,
    bdec_show_credential_paper, bdec_verify_shown_credential_paper,
    BdecCredential,
};

#[derive(Debug, Clone)]
struct BenchmarkResult {
    k: usize,
    indexer_time_s: f64,
    prove_time_s: f64,
    verify_time_s: f64,
    signature_size_bytes: usize,
}

fn run_showcre_benchmark(k: usize, tiny: bool) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    // Setup BDEC system
    let system = bdec_setup(if tiny { 80 } else { 128 }, 5)?;

    // Generate user keypair (single user with multiple TA credentials)
    let user_keypair = bdec_prigen(&system)?;

    // === t_I: Indexer time (credential issuance from k TAs) ===
    let indexer_start = Instant::now();

    // Generate k credentials from k different TAs
    let mut credentials: Vec<BdecCredential> = Vec::with_capacity(k);
    for i in 0..k {
        let pseudonym_ta = bdec_nym_key(&system, &user_keypair)?;
        let attributes = vec![
            format!("TA{}:Credential", i),
            format!("Degree:Certificate_{}", i),
            format!("Year:202{}", i % 10),
        ];
        let credential = bdec_issue_credential(&system, &user_keypair, &pseudonym_ta, attributes)?;
        credentials.push(credential);
    }

    let indexer_time = indexer_start.elapsed();

    // Disclosed attributes (subset from first credential)
    let disclosed = vec![
        credentials[0].attributes[0].clone(),
        credentials[0].attributes[1].clone(),
    ];

    // === t_P: Proving time (ShowCre proof generation) ===
    let prove_start = Instant::now();
    let shown_credential = bdec_show_credential_paper(
        &system,
        &user_keypair,
        &credentials,
        disclosed,
    )?;
    let prove_time = prove_start.elapsed();

    // Loquat signature size (c_U_V - the shown credential signature)
    let signature_artifact = shown_credential.shown_credential_signature.artifact();
    let signature_size_bytes = serialize(&signature_artifact)?.len();

    // === t_V: Verification time (ShowVer proof verification) ===
    let verify_start = Instant::now();
    let verify_result = bdec_verify_shown_credential_paper(
        &system,
        &shown_credential,
        &shown_credential.verifier_pseudonym.public,
    )?;
    let verify_time = verify_start.elapsed();

    if !verify_result {
        return Err("Verification failed".into());
    }

    Ok(BenchmarkResult {
        k,
        indexer_time_s: indexer_time.as_secs_f64(),
        prove_time_s: prove_time.as_secs_f64(),
        verify_time_s: verify_time.as_secs_f64(),
        signature_size_bytes,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let json_output = args.iter().any(|a| a == "--json" || a == "--jsonl");
    let tiny = args.iter().any(|a| a == "--tiny" || a == "--test-params");

    let k_values = vec![2, 6, 14, 30, 62];

    if !json_output {
        println!("=== BDEC ShowCre Benchmark ===\n");
        println!("Measuring credential proof performance with varying number of TAs (k)\n");
        println!("{:>4} | {:>12} | {:>12} | {:>12} | {:>12}",
                 "k", "t_I (s)", "t_P (s)", "t_V (s)", "|σ| (KB)");
        println!("{:-<4}-+-{:-<12}-+-{:-<12}-+-{:-<12}-+-{:-<12}",
                 "", "", "", "", "");
    }

    let mut results = Vec::new();

    for k in k_values {
        if !json_output {
            eprint!("Running k={:<3}... ", k);
        }

        match run_showcre_benchmark(k, tiny) {
            Ok(result) => {
                if json_output {
                    println!(
                        "{{\"k\":{},\"t_I_s\":{:.6},\"t_P_s\":{:.6},\"t_V_s\":{:.6},\"signature_bytes\":{}}}",
                        result.k,
                        result.indexer_time_s,
                        result.prove_time_s,
                        result.verify_time_s,
                        result.signature_size_bytes,
                    );
                } else {
                    eprintln!("done");
                    println!(
                        "{:>4} | {:>12.3} | {:>12.3} | {:>12.3} | {:>12.2}",
                        result.k,
                        result.indexer_time_s,
                        result.prove_time_s,
                        result.verify_time_s,
                        result.signature_size_bytes as f64 / 1024.0,
                    );
                }
                results.push(result);
            }
            Err(e) => {
                if json_output {
                    println!("{{\"k\":{},\"error\":\"{}\"}}", k, e);
                } else {
                    eprintln!("error: {}", e);
                    println!("{:>4} | ERROR: {}", k, e);
                }
            }
        }
    }

    if !json_output && !results.is_empty() {
        println!("\n=== Summary ===");
        println!("t_I = Indexer time (credential issuance from k TAs, includes NymKey + CreGen)");
        println!("t_P = Proving time (ShowCre: NymKey + sign + Aurora prove for k+2 signatures)");
        println!("t_V = Verification time (ShowVer: Aurora verify + revocation check)");
        println!("|σ| = Loquat signature size (c_U_V artifact, backend-independent)");
        println!("\nNote: ShowCre proves knowledge of k TA credentials + 1 verifier pseudonym + 1 shown credential signature");
        println!("Total signatures verified in SNARK: k + 2");
    }

    Ok(())
}
