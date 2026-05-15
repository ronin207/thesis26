//! PP2 (revocation) Aurora benchmark runner.

use crate::anoncreds::bdec::{
    BdecCredential, bdec_build_showver_instance_paper, bdec_issue_credential,
    bdec_issue_credential_with_existing_proof, bdec_nym_key, bdec_prigen,
    bdec_public_key_prefix_index, bdec_revoke, bdec_setup_zk, bdec_show_credential_paper,
    bdec_show_credential_paper_constraint_count, bdec_synthetic_public_key_with_prefix,
    bdec_verify_show_proof_paper, bdec_verify_shown_credential_paper,
};
use crate::evaluation::instrument::PhaseTimer;
use crate::evaluation::metrics::D2CostMetrics;
use crate::{BdecSystem, LoquatKeyPair};
use bincode::serialize;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pp2AuroraBenchmarkResult {
    pub k: usize,
    pub lr_size: usize,
    pub revocation_depth: usize,
    pub d2: D2CostMetrics,
}

#[derive(Debug, Clone)]
pub struct Pp2AuroraRunConfig {
    pub json_output: bool,
    pub tiny: bool,
    pub selected_k: Option<usize>,
    pub lr_size: usize,
    pub revocation_depth: usize,
    /// Skip SNARK proof generation/verification; measure only credential ops.
    pub exec_only: bool,
    /// Number of warm-up iterations to discard before the measured run.
    pub warmup_rounds: usize,
}

impl Default for Pp2AuroraRunConfig {
    fn default() -> Self {
        Self {
            json_output: false,
            tiny: false,
            selected_k: None,
            lr_size: 0,
            revocation_depth: 20,
            exec_only: false,
            warmup_rounds: 0,
        }
    }
}

impl Pp2AuroraRunConfig {
    pub fn from_args<I>(args: I) -> Result<Self, Box<dyn Error>>
    where
        I: IntoIterator<Item = String>,
    {
        let args: Vec<String> = args.into_iter().collect();
        let mut config = Self {
            json_output: args.iter().any(|a| a == "--json" || a == "--jsonl"),
            tiny: args.iter().any(|a| a == "--tiny" || a == "--test-params"),
            exec_only: args.iter().any(|a| a == "--exec-only"),
            ..Self::default()
        };

        let mut idx = 1usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--k" => {
                    let value = args
                        .get(idx + 1)
                        .ok_or("missing value after --k")?
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --k")?;
                    if value == 0 {
                        return Err("k must be greater than zero".into());
                    }
                    config.selected_k = Some(value);
                    idx += 2;
                }
                flag if flag.starts_with("--k=") => {
                    let value = flag
                        .split_once('=')
                        .ok_or("invalid --k argument")?
                        .1
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --k")?;
                    if value == 0 {
                        return Err("k must be greater than zero".into());
                    }
                    config.selected_k = Some(value);
                    idx += 1;
                }
                "--lr-size" => {
                    config.lr_size = args
                        .get(idx + 1)
                        .ok_or("missing value after --lr-size")?
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --lr-size")?;
                    idx += 2;
                }
                flag if flag.starts_with("--lr-size=") => {
                    config.lr_size = flag
                        .split_once('=')
                        .ok_or("invalid --lr-size argument")?
                        .1
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --lr-size")?;
                    idx += 1;
                }
                "--rev-depth" => {
                    config.revocation_depth = args
                        .get(idx + 1)
                        .ok_or("missing value after --rev-depth")?
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --rev-depth")?;
                    if config.revocation_depth == 0 {
                        return Err("revocation depth must be greater than zero".into());
                    }
                    idx += 2;
                }
                flag if flag.starts_with("--rev-depth=") => {
                    config.revocation_depth = flag
                        .split_once('=')
                        .ok_or("invalid --rev-depth argument")?
                        .1
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --rev-depth")?;
                    if config.revocation_depth == 0 {
                        return Err("revocation depth must be greater than zero".into());
                    }
                    idx += 1;
                }
                "--warmup" => {
                    config.warmup_rounds = args
                        .get(idx + 1)
                        .ok_or("missing value after --warmup")?
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --warmup")?;
                    idx += 2;
                }
                flag if flag.starts_with("--warmup=") => {
                    config.warmup_rounds = flag
                        .split_once('=')
                        .ok_or("invalid --warmup argument")?
                        .1
                        .parse::<usize>()
                        .map_err(|_| "invalid integer for --warmup")?;
                    idx += 1;
                }
                _ => idx += 1,
            }
        }

        Ok(config)
    }
}

pub fn run_pp2_aurora_single(
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
) -> Result<Pp2AuroraBenchmarkResult, Box<dyn Error>> {
    run_pp2_aurora_single_opts(k, tiny, lr_size, revocation_depth, false).map(|(r, _)| r)
}

/// Extended entry-point that honours `exec_only` and returns the [`PhaseTimer`].
pub fn run_pp2_aurora_single_opts(
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
    exec_only: bool,
) -> Result<(Pp2AuroraBenchmarkResult, PhaseTimer), Box<dyn Error>> {
    let security_level = if tiny { 80 } else { 128 };
    run_pp2_aurora_with_security(k, security_level, lr_size, revocation_depth, exec_only)
}

/// Security-level-aware variant. Accepts `security_level ∈ {80, 100, 128}`
/// (the Loquat paper's parameter sets). Used by B7's security-level sweep.
pub fn run_pp2_aurora_with_security(
    k: usize,
    security_level: usize,
    lr_size: usize,
    revocation_depth: usize,
    exec_only: bool,
) -> Result<(Pp2AuroraBenchmarkResult, PhaseTimer), Box<dyn Error>> {
    let mut timer = PhaseTimer::new();

    timer.start("setup");
    let mut system = bdec_setup_zk(security_level, 5, revocation_depth)?;
    timer.stop();

    timer.start("prigen");
    let user_keypair = bdec_prigen(&system)?;
    timer.stop();

    timer.start("populate_revocation");
    populate_revocation_state(&mut system, &user_keypair, lr_size)?;
    timer.stop();

    timer.start("indexer");
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
    let indexer_time = timer.stop();

    let disclosed = vec![
        credentials[0].attributes[0].clone(),
        credentials[0].attributes[1].clone(),
    ];

    timer.start("prove");
    let shown_credential =
        bdec_show_credential_paper(&system, &user_keypair, &credentials, disclosed)?;
    let prove_time = timer.stop();

    let proof_bytes = serialize(&shown_credential.show_proof)?.len();
    let signature_bytes = serialize(&shown_credential.shown_credential_signature.artifact())?.len();

    let mut constraint_count = 0usize;
    let mut instance_rebuild_time = std::time::Duration::ZERO;
    let mut proof_verify_time = std::time::Duration::ZERO;

    if !exec_only {
        timer.start("instance_rebuild");
        let showver_instance = bdec_build_showver_instance_paper(&system, &shown_credential)?;
        instance_rebuild_time = timer.stop();
        constraint_count = showver_instance.num_constraints();

        timer.start("proof_verify");
        let proof_verify_ok =
            bdec_verify_show_proof_paper(&system, &shown_credential, &showver_instance)?;
        proof_verify_time = timer.stop();
        if !proof_verify_ok {
            return Err("proof verification failed".into());
        }
    }

    timer.start("verify");
    let verify_ok = bdec_verify_shown_credential_paper(
        &system,
        &shown_credential,
        &shown_credential.verifier_pseudonym.public,
    )?;
    let verify_time = timer.stop();
    if !verify_ok {
        return Err("semantic verification failed".into());
    }

    let result = Pp2AuroraBenchmarkResult {
        k,
        lr_size,
        revocation_depth,
        d2: D2CostMetrics {
            indexer_s: indexer_time.as_secs_f64(),
            prove_s: prove_time.as_secs_f64(),
            verify_s: verify_time.as_secs_f64(),
            instance_rebuild_s: instance_rebuild_time.as_secs_f64(),
            proof_verify_s: proof_verify_time.as_secs_f64(),
            constraint_count,
            proof_bytes,
            signature_bytes,
        },
    };
    Ok((result, timer))
}

/// Constraints-only variant of [`run_pp2_aurora_single_opts`]. Builds the full
/// R1CS instance exactly as the full aurora run would but skips the actual
/// `aurora_prove` / `aurora_verify` steps, so it returns in seconds even for
/// large `k`. Returns `(k, rev_depth, constraint_count)`.
///
/// Used by B3 (circuit-scale) when `tier = "constraints_only"` — the thesis
/// uses this suite only for the `N_C(k)` linear-regression curve, which is
/// fully determined by the R1CS structure. Timing data for large-k aurora is
/// collected separately by the `aurora_prove` tier.
pub fn run_pp2_constraint_count_single(
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
) -> Result<(usize, usize, usize), Box<dyn Error>> {
    let mut system = bdec_setup_zk(if tiny { 80 } else { 128 }, 5, revocation_depth)?;
    let user_keypair = bdec_prigen(&system)?;
    populate_revocation_state(&mut system, &user_keypair, lr_size)?;

    // Pay aurora_prove ONCE for the seed credential, then clone its proof for the
    // remaining k-1 credentials. The constraint_count helper does not call
    // aurora_verify, so the cloned (cryptographically invalid) proofs are safe
    // here. This drops B3 constraints_only cost from O(k) to O(1) aurora proves
    // per config.
    let mut credentials: Vec<BdecCredential> = Vec::with_capacity(k);
    let seed_pseudonym = bdec_nym_key(&system, &user_keypair)?;
    let seed_attrs = vec![
        "TA0:Credential".to_string(),
        "Degree:Certificate_0".to_string(),
        "Year:2020".to_string(),
    ];
    let seed_credential =
        bdec_issue_credential(&system, &user_keypair, &seed_pseudonym, seed_attrs)?;
    let stub_proof = seed_credential.proof.aurora_proof.clone();
    credentials.push(seed_credential);
    for i in 1..k {
        let pseudonym_ta = bdec_nym_key(&system, &user_keypair)?;
        let attributes = vec![
            format!("TA{}:Credential", i),
            format!("Degree:Certificate_{}", i),
            format!("Year:202{}", i % 10),
        ];
        let credential = bdec_issue_credential_with_existing_proof(
            &system,
            &user_keypair,
            &pseudonym_ta,
            attributes,
            stub_proof.clone(),
        )?;
        credentials.push(credential);
    }

    let disclosed = vec![
        credentials[0].attributes[0].clone(),
        credentials[0].attributes[1].clone(),
    ];

    let constraint_count = bdec_show_credential_paper_constraint_count(
        &system,
        &user_keypair,
        &credentials,
        disclosed,
    )?;
    Ok((k, revocation_depth, constraint_count))
}

pub fn run_pp2_aurora_cli<I>(args: I) -> Result<Vec<Pp2AuroraBenchmarkResult>, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let config = Pp2AuroraRunConfig::from_args(args)?;
    let k_values = config
        .selected_k
        .map_or_else(|| vec![2, 6, 14, 30, 62], |k| vec![k]);

    if !config.json_output {
        println!("=== BDEC PP2 Benchmark (Aurora) ===\n");
        println!(
            "Revocation config: |LR_t|={}, depth={}\n",
            config.lr_size, config.revocation_depth
        );
        println!(
            "{:>4} | {:>12} | {:>12} | {:>12} | {:>12}",
            "k", "t_I (s)", "t_P (s)", "t_V (s)", "|epsilon| (KB)"
        );
        println!(
            "{:-<4}-+-{:-<12}-+-{:-<12}-+-{:-<12}-+-{:-<12}",
            "", "", "", "", ""
        );
    }

    // Calibration: warm-up rounds (results discarded)
    if config.warmup_rounds > 0 && !config.json_output {
        eprintln!(
            "Calibration: running {} warm-up round(s)...",
            config.warmup_rounds
        );
    }
    for w in 0..config.warmup_rounds {
        let warmup_k = k_values.first().copied().unwrap_or(1);
        if !config.json_output {
            eprint!("  warmup {}/{}... ", w + 1, config.warmup_rounds);
        }
        let _ = run_pp2_aurora_single_opts(
            warmup_k,
            config.tiny,
            config.lr_size,
            config.revocation_depth,
            config.exec_only,
        );
        if !config.json_output {
            eprintln!("done");
        }
    }

    let mut results = Vec::new();
    for k in k_values {
        if !config.json_output {
            eprint!("Running k={:<3}... ", k);
        }

        match run_pp2_aurora_single_opts(
            k,
            config.tiny,
            config.lr_size,
            config.revocation_depth,
            config.exec_only,
        ) {
            Ok((result, timer)) => {
                if config.json_output {
                    println!(
                        "{{\"status\":\"ok\",\"k\":{},\"lr_size\":{},\"revocation_depth\":{},\"exec_only\":{},\"constraint_count\":{},\"t_I_s\":{:.6},\"t_P_s\":{:.6},\"t_V_s\":{:.6},\"instance_rebuild_s\":{:.6},\"proof_verify_s\":{:.6},\"proof_bytes\":{},\"signature_bytes\":{},\"phases\":{}}}",
                        result.k,
                        result.lr_size,
                        result.revocation_depth,
                        config.exec_only,
                        result.d2.constraint_count,
                        result.d2.indexer_s,
                        result.d2.prove_s,
                        result.d2.verify_s,
                        result.d2.instance_rebuild_s,
                        result.d2.proof_verify_s,
                        result.d2.proof_bytes,
                        result.d2.signature_bytes,
                        timer.to_json(),
                    );
                } else {
                    eprintln!("done");
                    println!(
                        "{:>4} | {:>12.3} | {:>12.3} | {:>12.3} | {:>12.2}",
                        result.k,
                        result.d2.indexer_s,
                        result.d2.prove_s,
                        result.d2.verify_s,
                        result.d2.proof_bytes as f64 / 1024.0,
                    );
                    timer.print_summary();
                }
                results.push(result);
            }
            Err(error) => {
                if config.json_output {
                    println!(
                        "{{\"status\":\"error\",\"k\":{},\"lr_size\":{},\"revocation_depth\":{},\"error\":\"{}\"}}",
                        k, config.lr_size, config.revocation_depth, error
                    );
                } else {
                    eprintln!("error: {}", error);
                    println!("{:>4} | ERROR: {}", k, error);
                }
            }
        }
    }

    if !config.json_output && !results.is_empty() {
        println!("\n=== Summary ===");
        println!("t_I = issuance/indexer time");
        println!("t_P = ShowCre prove time");
        println!("t_V = full semantic verify + proof check");
        println!("|epsilon| = Aurora proof size");
        println!("|c| = shown Loquat signature artifact size");
        println!(
            "\nPer-row JSON includes: constraint_count, instance_rebuild_s, proof_verify_s, proof_bytes, signature_bytes"
        );
    }

    Ok(results)
}

fn populate_revocation_state(
    system: &mut BdecSystem,
    user_keypair: &LoquatKeyPair,
    lr_size: usize,
) -> Result<(), Box<dyn Error>> {
    if lr_size == 0 {
        return Ok(());
    }
    let accumulator = system
        .revocation_accumulator
        .as_ref()
        .ok_or("revocation accumulator is not configured")?;
    let depth = accumulator.depth();
    let key_len = system.params.loquat_params.l;
    let capacity = 1u64
        .checked_shl(depth as u32)
        .ok_or("revocation depth overflow while computing capacity")?;
    if (lr_size as u64) >= capacity {
        return Err(format!(
            "lr_size={} exceeds revocation capacity-1={} for depth={}",
            lr_size,
            capacity.saturating_sub(1),
            depth
        )
        .into());
    }
    let user_prefix = bdec_public_key_prefix_index(&user_keypair.public_key, depth)?;
    let mut inserted = 0u64;
    let mut prefix = 0u64;
    while inserted < lr_size as u64 {
        if prefix >= capacity {
            return Err("insufficient revocation prefixes to populate LR_t".into());
        }
        if prefix != user_prefix {
            let synthetic_pk = bdec_synthetic_public_key_with_prefix(prefix, depth, key_len)?;
            bdec_revoke(system, &synthetic_pk)?;
            inserted += 1;
        }
        prefix += 1;
    }
    Ok(())
}
