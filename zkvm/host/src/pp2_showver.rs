use std::collections::HashSet;
use std::time::Instant;

use methods::{ZKVM_RISC0_ELF, ZKVM_RISC0_ID};
use risc0_zkvm::{
    default_prover, ExecutorEnv, InnerReceipt, ProverOpts, SegmentReceiptVerifierParameters,
    SuccinctReceiptVerifierParameters, VerifierContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use vc_pqc::{
    bdec_attribute_merkle_proof, bdec_attribute_merkle_root, bdec_nym_key, bdec_prigen,
    bdec_public_key_prefix_index, bdec_revoke, bdec_setup_zk,
    bdec_synthetic_public_key_with_prefix,
    loquat::{field_utils::F, LoquatPublicParams, LoquatSignature},
    loquat_sign, BdecAttributeMerkleProof, BdecPseudonymKey, BdecSystem, LoquatError,
    LoquatKeyPair, LoquatResult,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BdecPseudonymKeyInput {
    public: Vec<u8>,
    signature: LoquatSignature,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
enum AttributeCommitmentTypeInput {
    HashListSha256,
    MerkleRootGriffin,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BdecCredentialInput {
    pseudonym: BdecPseudonymKeyInput,
    attributes: Vec<String>,
    attribute_hash: [u8; 32],
    attribute_commitment_type: AttributeCommitmentTypeInput,
    credential_signature: LoquatSignature,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BdecAttributeMerkleProofInput {
    credential_index: usize,
    attribute: String,
    leaf_index: usize,
    auth_path: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum PolicyPredicateInput {
    GteI64 {
        key: String,
        min_value: i64,
    },
    OneOf {
        key: String,
        allowed_values: Vec<String>,
    },
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct PolicyInputData {
    predicates: Vec<PolicyPredicateInput>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct GuestInput {
    params: LoquatPublicParams,
    user_public_key: Vec<F>,
    credentials: Vec<BdecCredentialInput>,
    verifier_pseudonym: BdecPseudonymKeyInput,
    disclosed_attributes: Vec<String>,
    attribute_proofs: Vec<BdecAttributeMerkleProofInput>,
    disclosure_hash: [u8; 32],
    shown_credential_signature: LoquatSignature,
    revocation_root: [u8; 32],
    revocation_depth: usize,
    revocation_auth_path: Vec<[u8; 32]>,
    policy: Option<PolicyInputData>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Counters {
    loquat_verifies: u32,
    hash_calls: u32,
    merkle_nodes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicStatement {
    verifier_pseudonym_public: Vec<u8>,
    shown_credential_signature_hash: [u8; 32],
    disclosure_hash: [u8; 32],
    disclosed_attributes: Vec<String>,
    ta_pseudonym_publics: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GuestOutput {
    statement: PublicStatement,
    credential_checks_passed: bool,
    attribute_checks_passed: bool,
    revocation_check_passed: bool,
    policy_checks_passed: bool,
    counters: Counters,
}

#[derive(Debug)]
struct SweepResult {
    k: usize,
    s: usize,
    m: usize,
    trace_length: u64,
    prove_time_ms: f64,
    verify_time_ms: f64,
    proof_size_bytes: usize,
    counters: Counters,
}

#[derive(Debug, Clone)]
struct RunConfig {
    single_case: Option<(usize, usize, usize)>,
    lr_size: usize,
    revocation_depth: usize,
    json_output: bool,
    policy: Option<PolicyInputData>,
    /// If true, set `RISC0_DEV_MODE=1` (execute-only, no ZK proof).
    dev_mode: bool,
    /// If true, continue the sweep on per-combination errors instead of aborting.
    continue_on_error: bool,
    /// Loquat security level λ passed to `bdec_setup_zk`.  Defaults to 128.
    security_level: usize,
}

const K_VALUES: &[usize] = &[1, 2, 6, 14, 30];
const S_VALUES: &[usize] = &[1, 3, 10];
const M_VALUES: &[usize] = &[16, 64, 256];

pub fn run_from_env() -> LoquatResult<()> {
    run(parse_run_config())
}

fn parse_run_config() -> RunConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut parsed_k: Option<usize> = None;
    let mut parsed_s: Option<usize> = None;
    let mut parsed_m: Option<usize> = None;
    let mut lr_size = 0usize;
    let mut revocation_depth = 20usize;
    let json_output = args.iter().any(|a| a == "--json" || a == "--jsonl");
    let dev_mode = args.iter().any(|a| a == "--dev-mode");
    let continue_on_error = args.iter().any(|a| a == "--continue-on-error");
    let mut security_level = 128usize;
    let mut policy_gpa_min: Option<i64> = None;
    let mut policy_degree_set: Option<Vec<String>> = None;

    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--k" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    parsed_k = Some(value);
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--k=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    parsed_k = Some(value);
                    idx += 1;
                    continue;
                }
            }
            "--s" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    parsed_s = Some(value);
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--s=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    parsed_s = Some(value);
                    idx += 1;
                    continue;
                }
            }
            "--m" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    parsed_m = Some(value);
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--m=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    parsed_m = Some(value);
                    idx += 1;
                    continue;
                }
            }
            "--lr-size" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    lr_size = value;
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--lr-size=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    lr_size = value;
                    idx += 1;
                    continue;
                }
            }
            "--rev-depth" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    if value > 0 {
                        revocation_depth = value;
                    }
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--rev-depth=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    if value > 0 {
                        revocation_depth = value;
                    }
                    idx += 1;
                    continue;
                }
            }
            "--policy-gpa-min" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<i64>().ok()) {
                    policy_gpa_min = Some(value);
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--policy-gpa-min=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<i64>().ok())
                {
                    policy_gpa_min = Some(value);
                    idx += 1;
                    continue;
                }
            }
            "--policy-degree-set" => {
                if let Some(raw) = args.get(idx + 1) {
                    let values = raw
                        .split(',')
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>();
                    policy_degree_set = Some(values);
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--policy-degree-set=") => {
                if let Some(raw) = flag.split_once('=').map(|(_, value)| value) {
                    let values = raw
                        .split(',')
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>();
                    policy_degree_set = Some(values);
                    idx += 1;
                    continue;
                }
            }
            "--security-level" => {
                if let Some(value) = args.get(idx + 1).and_then(|v| v.parse::<usize>().ok()) {
                    if value > 0 {
                        security_level = value;
                    }
                    idx += 2;
                    continue;
                }
            }
            flag if flag.starts_with("--security-level=") => {
                if let Some(value) = flag
                    .split_once('=')
                    .and_then(|(_, v)| v.parse::<usize>().ok())
                {
                    if value > 0 {
                        security_level = value;
                    }
                    idx += 1;
                    continue;
                }
            }
            _ => {}
        }
        idx += 1;
    }

    let single_case = match (parsed_k, parsed_s, parsed_m) {
        (Some(k), Some(s), Some(m)) if k > 0 && s > 0 && m > 0 => Some((k, s, m)),
        _ => None,
    };

    let mut predicates = Vec::new();
    if let Some(min_value) = policy_gpa_min {
        predicates.push(PolicyPredicateInput::GteI64 {
            key: "gpa".to_string(),
            min_value,
        });
    }
    if let Some(allowed_values) = policy_degree_set {
        predicates.push(PolicyPredicateInput::OneOf {
            key: "degree".to_string(),
            allowed_values,
        });
    }
    let policy = if predicates.is_empty() {
        None
    } else {
        Some(PolicyInputData { predicates })
    };

    RunConfig {
        single_case,
        lr_size,
        revocation_depth,
        json_output,
        policy,
        dev_mode,
        continue_on_error,
        security_level,
    }
}

fn run(config: RunConfig) -> LoquatResult<()> {
    // Apply dev mode: must be set before `default_prover()` is called so that
    // the RISC Zero runtime picks it up during its lazy global initialisation.
    if config.dev_mode {
        // SAFETY: single-threaded at this point; no other threads read this var.
        unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };
        info!("RISC0_DEV_MODE=1 enabled (execute-only, no ZK proof)");
    }

    info!("configuring BDEC system parameters");
    let max_attributes = config
        .single_case
        .map(|(_, _, m)| m)
        .unwrap_or_else(|| M_VALUES.iter().copied().max().unwrap_or(0));
    let mut system = bdec_setup_zk(config.security_level, max_attributes, config.revocation_depth)?;
    let user_keypair = bdec_prigen(&system)?;
    populate_revocation_state(&mut system, &user_keypair, config.lr_size)?;
    info!(
        "revocation state initialised: |LR_t|={}, depth={}",
        config.lr_size, config.revocation_depth
    );
    if config.policy.is_some() {
        info!("policy predicates enabled in guest input");
    }

    let prover_opts = ProverOpts::succinct();
    let stark_verifier_ctx = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::default())
        .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::default());

    let combinations: Vec<(usize, usize, usize)> = if let Some((k, s, m)) = config.single_case {
        vec![(k, s, m)]
    } else {
        let mut combos = Vec::new();
        for &k in K_VALUES {
            for &s in S_VALUES {
                for &m in M_VALUES {
                    combos.push((k, s, m));
                }
            }
        }
        combos
    };

    // Estimated run time hint printed before the sweep starts so the user can
    // plan their wait.  Rough empirical baselines (λ=128, CPU prover):
    //   dev mode:  ~15 s / combination
    //   full mode: ~5–10 min / combination
    let n = combinations.len();
    if !config.json_output {
        let (est_secs_lo, est_secs_hi) = if config.dev_mode {
            (n * 10, n * 20)
        } else {
            (n * 300, n * 600)
        };
        eprintln!(
            "[pp2-showver] Starting sweep: {} combination(s), λ={}, mode={}.  \
             Estimated wall time: {}–{} min.",
            n,
            config.security_level,
            if config.dev_mode { "dev" } else { "full" },
            est_secs_lo / 60,
            (est_secs_hi + 59) / 60,
        );
    }

    let mut results = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for (k, s, m) in combinations {
        info!("running ShowCre guest with k={k}, s={s}, m={m}");
        let outcome = execute_combination(
            &system,
            &user_keypair,
            &prover_opts,
            &stark_verifier_ctx,
            config.policy.as_ref(),
            k,
            s,
            m,
            config.dev_mode,
        );
        match outcome {
            Ok(sweep_result) => {
                debug!(
                    "combination (k={k}, s={s}, m={m}) counters: {:?}",
                    sweep_result.counters
                );
                results.push(sweep_result);
            }
            Err(err) => {
                let msg = format!("combination (k={k}, s={s}, m={m}) failed: {err}");
                if config.continue_on_error {
                    warn!("{msg}");
                    if config.json_output {
                        println!(
                            "{{\"status\":\"error\",\"k\":{k},\"s\":{s},\"m\":{m},\"error\":{}}}",
                            serde_json::to_string(&err.to_string()).unwrap_or_default()
                        );
                    }
                    errors.push(msg);
                } else {
                    return Err(err);
                }
            }
        }
    }

    print_summary(&results, config.json_output);

    if !errors.is_empty() {
        warn!(
            "{} combination(s) failed during sweep (--continue-on-error was set):",
            errors.len()
        );
        for e in &errors {
            warn!("  {e}");
        }
    }

    Ok(())
}

fn execute_combination(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    prover_opts: &ProverOpts,
    verifier_ctx: &VerifierContext,
    policy: Option<&PolicyInputData>,
    k: usize,
    s: usize,
    m: usize,
    dev_mode: bool,
) -> LoquatResult<SweepResult> {
    if s > m {
        return Err(LoquatError::invalid_parameters(
            "attribute proofs requested exceed Merkle leaves",
        ));
    }

    let attributes = if policy.is_some() {
        build_policy_attributes(m)
    } else {
        build_attributes(m)
    };
    let disclosure_seed = select_disclosure_attributes(&attributes, s, policy)?;
    let disclosed_attributes = canonicalize_attributes(&disclosure_seed)?;

    let mut credentials = Vec::with_capacity(k);
    for _ in 0..k {
        let pseudonym = bdec_nym_key(system, user_keypair)?;
        credentials.push(build_credential_input(
            system,
            user_keypair,
            &pseudonym,
            attributes.clone(),
        )?);
    }

    let mut proofs = Vec::with_capacity(disclosed_attributes.len());
    for attribute in &disclosed_attributes {
        proofs.push(bdec_attribute_merkle_proof(0, &attributes, attribute)?);
    }

    let verifier_pseudonym = bdec_nym_key(system, user_keypair)?;
    let disclosure_hash = hash_attributes(&disclosed_attributes);
    let shown_credential_signature =
        loquat_sign(&disclosure_hash, user_keypair, &system.params.loquat_params)?;
    let revocation_accumulator = system.revocation_accumulator.as_ref().ok_or_else(|| {
        LoquatError::invalid_parameters("zkVM benchmark requires revocation accumulator")
    })?;
    let revocation_root = revocation_accumulator.root();
    let revocation_depth = revocation_accumulator.depth();
    let revocation_auth_path = revocation_accumulator.auth_path(&user_keypair.public_key)?;

    let guest_input = GuestInput {
        params: system.params.loquat_params.clone(),
        user_public_key: user_keypair.public_key.clone(),
        credentials,
        verifier_pseudonym: map_pseudonym(&verifier_pseudonym),
        disclosed_attributes: disclosed_attributes.clone(),
        attribute_proofs: proofs.iter().map(map_attribute_proof).collect(),
        disclosure_hash,
        shown_credential_signature,
        revocation_root,
        revocation_depth,
        revocation_auth_path,
        policy: policy.cloned(),
    };

    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .map_err(|err| LoquatError::SerializationError {
            details: format!("failed to serialise guest input: {err}"),
        })?
        .build()
        .map_err(|err| LoquatError::crypto_error("build_executor_env", &err.to_string()))?;

    let prover = default_prover();
    let start = Instant::now();
    let prove_info = prover
        .prove_with_ctx(env, verifier_ctx, ZKVM_RISC0_ELF, prover_opts)
        .map_err(|err| LoquatError::crypto_error("prove_execution", &err.to_string()))?;
    let prove_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    let receipt = prove_info.receipt;
    let receipt_kind = match &receipt.inner {
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Groth16(_) => "groth16",
        InnerReceipt::Fake(_) => "fake",
        _ => "unknown",
    };
    let acceptable = match receipt_kind {
        "succinct" => true,
        // In dev mode the RISC Zero runtime returns a Fake receipt instead of
        // a real STARK; accept it so benchmarks can run without the prover.
        "fake" if dev_mode => true,
        _ => false,
    };
    if !acceptable {
        return Err(LoquatError::verification_failure(&format!(
            "expected succinct STARK receipt, got {receipt_kind}"
        )));
    }

    // In dev mode the receipt is a no-op Fake; skip cryptographic verification.
    let verify_start = Instant::now();
    if !dev_mode {
        receipt
            .verify_with_context(verifier_ctx, ZKVM_RISC0_ID)
            .map_err(|err| {
                LoquatError::verification_failure(&format!("receipt verification failed: {err}"))
            })?;
    }
    let verify_time_ms = verify_start.elapsed().as_secs_f64() * 1000.0;

    let journal: GuestOutput =
        receipt
            .journal
            .decode()
            .map_err(|err| LoquatError::SerializationError {
                details: format!("failed to decode guest journal: {err}"),
            })?;

    if !journal.credential_checks_passed || !journal.attribute_checks_passed {
        return Err(LoquatError::verification_failure(
            "guest reported ShowCre verification failure",
        ));
    }

    if !journal.revocation_check_passed {
        return Err(LoquatError::verification_failure(
            "guest reported revocation check failure",
        ));
    }

    if !journal.policy_checks_passed {
        return Err(LoquatError::verification_failure(
            "guest reported policy check failure",
        ));
    }

    let proof_size_bytes = receipt.seal_size();
    let trace_length = prove_info.stats.total_cycles;

    Ok(SweepResult {
        k,
        s,
        m,
        trace_length,
        prove_time_ms,
        verify_time_ms,
        proof_size_bytes,
        counters: journal.counters,
    })
}

fn populate_revocation_state(
    system: &mut BdecSystem,
    user_keypair: &LoquatKeyPair,
    lr_size: usize,
) -> LoquatResult<()> {
    if lr_size == 0 {
        return Ok(());
    }
    let accumulator = system.revocation_accumulator.as_ref().ok_or_else(|| {
        LoquatError::invalid_parameters("revocation accumulator is not configured")
    })?;
    let depth = accumulator.depth();
    let key_len = system.params.loquat_params.l;
    let capacity = 1u64.checked_shl(depth as u32).ok_or_else(|| {
        LoquatError::invalid_parameters("revocation depth overflow while computing capacity")
    })?;
    if (lr_size as u64) >= capacity {
        return Err(LoquatError::invalid_parameters(
            "lr_size exceeds revocation capacity-1 for configured depth",
        ));
    }
    let user_prefix = bdec_public_key_prefix_index(&user_keypair.public_key, depth)?;
    let mut inserted = 0u64;
    let mut prefix = 0u64;
    while inserted < lr_size as u64 {
        if prefix >= capacity {
            return Err(LoquatError::invalid_parameters(
                "insufficient unique prefixes to populate requested LR_t size",
            ));
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

fn build_attributes(m: usize) -> Vec<String> {
    (0..m).map(|i| format!("attribute-{i:04}")).collect()
}

fn build_policy_attributes(m: usize) -> Vec<String> {
    let mut attributes = Vec::with_capacity(m.max(2));
    attributes.push("gpa:35".to_string());
    attributes.push("degree:CS".to_string());
    while attributes.len() < m {
        attributes.push(format!("attribute-{:04}", attributes.len() - 2));
    }
    attributes
}

fn select_disclosure_attributes(
    attributes: &[String],
    s: usize,
    policy: Option<&PolicyInputData>,
) -> LoquatResult<Vec<String>> {
    if s == 0 {
        return Err(LoquatError::invalid_parameters(
            "disclosure size s must be greater than zero",
        ));
    }

    if let Some(policy) = policy {
        let mut selected: Vec<String> = Vec::new();
        for predicate in &policy.predicates {
            let key = match predicate {
                PolicyPredicateInput::GteI64 { key, .. } => key,
                PolicyPredicateInput::OneOf { key, .. } => key,
            };
            let needle = format!("{key}:");
            if let Some(value) = attributes.iter().find(|entry| entry.starts_with(&needle)) {
                if !selected.iter().any(|existing| existing == value) {
                    selected.push(value.clone());
                }
            } else {
                return Err(LoquatError::invalid_parameters(
                    "policy predicate key missing from benchmark attributes",
                ));
            }
        }
        if selected.len() > s {
            return Err(LoquatError::invalid_parameters(
                "s must be >= number of policy-bound disclosed attributes",
            ));
        }
        for value in attributes {
            if selected.len() >= s {
                break;
            }
            if !selected.iter().any(|existing| existing == value) {
                selected.push(value.clone());
            }
        }
        return Ok(selected);
    }

    Ok(attributes.iter().take(s).cloned().collect())
}

fn map_pseudonym(pseudonym: &BdecPseudonymKey) -> BdecPseudonymKeyInput {
    BdecPseudonymKeyInput {
        public: pseudonym.public.clone(),
        signature: pseudonym.signature.clone(),
    }
}

fn map_attribute_proof(proof: &BdecAttributeMerkleProof) -> BdecAttributeMerkleProofInput {
    BdecAttributeMerkleProofInput {
        credential_index: proof.credential_index,
        attribute: proof.attribute.clone(),
        leaf_index: proof.leaf_index,
        auth_path: proof.auth_path.clone(),
    }
}

fn print_summary(results: &[SweepResult], json_output: bool) {
    if results.is_empty() {
        warn!("no results collected during sweep");
        return;
    }

    if json_output {
        for result in results {
            println!(
                "{{\"status\":\"ok\",\"k\":{},\"s\":{},\"m\":{},\"trace_cycles\":{},\"prove_ms\":{:.2},\"verify_ms\":{:.2},\"receipt_bytes\":{},\"loquat_verifies\":{},\"hash_calls\":{},\"merkle_nodes\":{}}}",
                result.k,
                result.s,
                result.m,
                result.trace_length,
                result.prove_time_ms,
                result.verify_time_ms,
                result.proof_size_bytes,
                result.counters.loquat_verifies,
                result.counters.hash_calls,
                result.counters.merkle_nodes,
            );
        }
        return;
    }

    println!("\n=== ShowCre zkVM Sweep Results ===");
    println!(
        "{:<4} {:<4} {:<5} {:>12} {:>12} {:>12} {:>12} {:>16} {:>14} {:>16}",
        "k",
        "s",
        "m",
        "trace(cyc)",
        "prove(ms)",
        "verify(ms)",
        "proof(bytes)",
        "loquat verifications",
        "hash calls",
        "merkle nodes"
    );

    for result in results {
        println!(
            "{:<4} {:<4} {:<5} {:>12} {:>12.2} {:>12.2} {:>12} {:>16} {:>14} {:>16}",
            result.k,
            result.s,
            result.m,
            result.trace_length,
            result.prove_time_ms,
            result.verify_time_ms,
            result.proof_size_bytes,
            result.counters.loquat_verifies,
            result.counters.hash_calls,
            result.counters.merkle_nodes,
        );
    }
}

fn build_credential_input(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    pseudonym: &BdecPseudonymKey,
    attributes: Vec<String>,
) -> LoquatResult<BdecCredentialInput> {
    let attribute_hash = bdec_attribute_merkle_root(&attributes)?;
    let credential_signature =
        loquat_sign(&attribute_hash, user_keypair, &system.params.loquat_params)?;

    Ok(BdecCredentialInput {
        pseudonym: map_pseudonym(pseudonym),
        attributes,
        attribute_hash,
        attribute_commitment_type: AttributeCommitmentTypeInput::MerkleRootGriffin,
        credential_signature,
    })
}

fn canonicalize_attributes(attributes: &[String]) -> LoquatResult<Vec<String>> {
    let mut unique = HashSet::with_capacity(attributes.len());
    for value in attributes {
        if !unique.insert(value.clone()) {
            return Err(LoquatError::invalid_parameters(
                "duplicate attribute in disclosure set",
            ));
        }
    }
    let mut ordered: Vec<String> = unique.into_iter().collect();
    ordered.sort();
    Ok(ordered)
}

fn hash_attributes(attributes: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for attribute in attributes {
        hasher.update(attribute.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.finalize().into()
}
