//! PP3 policy/schema-evolution helpers.
//!
//! Policy-only updates should be represented as data and evaluated over already-disclosed
//! attributes so that churn is explicit in experiments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

use crate::bench::instrument::PhaseTimer;

use crate::anoncreds::bdec::{
    BdecCredential, bdec_build_showver_instance_with_policy_paper, bdec_issue_credential,
    bdec_issue_credential_with_existing_proof, bdec_nym_key, bdec_prigen,
    bdec_public_key_prefix_index, bdec_revoke, bdec_setup_zk,
    bdec_show_credential_with_policy_paper,
    bdec_show_credential_with_policy_paper_constraint_count,
    bdec_synthetic_public_key_with_prefix, bdec_verify_show_proof_paper,
    bdec_verify_shown_credential_with_policy_paper,
};
use crate::bench::metrics::{D1ChurnEntry, D2CostMetrics};
use crate::{BdecSystem, LoquatKeyPair};
use bincode::serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyPredicate {
    /// Numeric threshold predicate over `key:value` attributes where value parses as i64.
    GteI64 { key: String, min_value: i64 },
    /// Set-membership predicate over string-valued `key:value` attributes.
    OneOf {
        key: String,
        allowed_values: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyInput {
    pub predicates: Vec<PolicyPredicate>,
}

/// Parse `key:value` strings into a map. First occurrence wins for deterministic behaviour.
pub fn parse_attribute_map(attributes: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(attributes.len());
    for item in attributes {
        let Some((key, value)) = item.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }
        out.entry(key.to_string())
            .or_insert_with(|| value.to_string());
    }
    out
}

/// Evaluate all policy predicates against disclosed attributes.
pub fn evaluate_policy_input(attributes: &[String], policy: &PolicyInput) -> bool {
    let map = parse_attribute_map(attributes);
    for predicate in &policy.predicates {
        match predicate {
            PolicyPredicate::GteI64 { key, min_value } => {
                let Some(raw) = map.get(key) else {
                    return false;
                };
                let Ok(value) = raw.parse::<i64>() else {
                    return false;
                };
                if value < *min_value {
                    return false;
                }
            }
            PolicyPredicate::OneOf {
                key,
                allowed_values,
            } => {
                let Some(raw) = map.get(key) else {
                    return false;
                };
                if !allowed_values.iter().any(|allowed| allowed == raw) {
                    return false;
                }
            }
        }
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pp3AuroraBenchmarkResult {
    pub label: String,
    pub k: usize,
    pub lr_size: usize,
    pub revocation_depth: usize,
    pub policy: PolicyInput,
    pub d2: D2CostMetrics,
}

pub fn default_pp3_policies() -> (PolicyInput, PolicyInput) {
    let policy_v1 = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 30,
        }],
    };
    let policy_v2 = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            },
            PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: vec!["CS".to_string(), "EE".to_string()],
            },
        ],
    };
    (policy_v1, policy_v2)
}

pub fn pp3_policy_only_d1_churn_rows() -> Vec<D1ChurnEntry> {
    vec![
        D1ChurnEntry {
            backend: "aurora".to_string(),
            event: "policy_v1_to_v2".to_string(),
            artifact: "r1cs_instance".to_string(),
            regenerated: true,
        },
        D1ChurnEntry {
            backend: "aurora".to_string(),
            event: "policy_v1_to_v2".to_string(),
            artifact: "aurora_proof".to_string(),
            regenerated: true,
        },
        D1ChurnEntry {
            backend: "zkvm".to_string(),
            event: "policy_v1_to_v2".to_string(),
            artifact: "guest_input".to_string(),
            regenerated: true,
        },
        D1ChurnEntry {
            backend: "zkvm".to_string(),
            event: "policy_v1_to_v2".to_string(),
            artifact: "guest_elf".to_string(),
            regenerated: false,
        },
    ]
}

pub fn run_pp3_aurora_single(
    label: &str,
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
    policy: &PolicyInput,
) -> Result<Pp3AuroraBenchmarkResult, Box<dyn Error>> {
    run_pp3_aurora_single_opts(label, k, tiny, lr_size, revocation_depth, policy, false)
        .map(|(r, _)| r)
}

/// Extended entry-point that honours `exec_only` and returns the [`PhaseTimer`].
pub fn run_pp3_aurora_single_opts(
    label: &str,
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
    policy: &PolicyInput,
    exec_only: bool,
) -> Result<(Pp3AuroraBenchmarkResult, PhaseTimer), Box<dyn Error>> {
    let security_level = if tiny { 80 } else { 128 };
    run_pp3_aurora_with_security(
        label,
        k,
        security_level,
        lr_size,
        revocation_depth,
        policy,
        exec_only,
    )
}

/// Security-level-aware variant. Accepts `security_level ∈ {80, 100, 128}`
/// (the Loquat paper's parameter sets). Used by B7's security-level sweep.
pub fn run_pp3_aurora_with_security(
    label: &str,
    k: usize,
    security_level: usize,
    lr_size: usize,
    revocation_depth: usize,
    policy: &PolicyInput,
    exec_only: bool,
) -> Result<(Pp3AuroraBenchmarkResult, PhaseTimer), Box<dyn Error>> {
    if k == 0 {
        return Err("k must be greater than zero".into());
    }

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
        let ta_pseudonym = bdec_nym_key(&system, &user_keypair)?;
        let attributes = vec![
            format!("TA{}:Credential", i),
            "gpa:35".to_string(),
            "degree:CS".to_string(),
        ];
        let credential = bdec_issue_credential(&system, &user_keypair, &ta_pseudonym, attributes)?;
        credentials.push(credential);
    }
    let indexer_time = timer.stop();

    let disclosed = vec!["gpa:35".to_string(), "degree:CS".to_string()];

    timer.start("prove");
    let shown = bdec_show_credential_with_policy_paper(
        &system,
        &user_keypair,
        &credentials,
        disclosed,
        policy,
    )?;
    let prove_time = timer.stop();

    let proof_bytes = serialize(&shown.show_proof)?.len();
    let signature_bytes = serialize(&shown.shown_credential_signature.artifact())?.len();

    let mut constraint_count = 0usize;
    let mut instance_rebuild_time = std::time::Duration::ZERO;
    let mut proof_verify_time = std::time::Duration::ZERO;

    if !exec_only {
        timer.start("instance_rebuild");
        let instance = bdec_build_showver_instance_with_policy_paper(&system, &shown, policy)?;
        instance_rebuild_time = timer.stop();
        constraint_count = instance.num_constraints();

        timer.start("proof_verify");
        let proof_ok = bdec_verify_show_proof_paper(&system, &shown, &instance)?;
        proof_verify_time = timer.stop();
        if !proof_ok {
            return Err("policy-bound proof verification failed".into());
        }
    }

    timer.start("verify");
    let verify_ok = bdec_verify_shown_credential_with_policy_paper(
        &system,
        &shown,
        &shown.verifier_pseudonym.public,
        policy,
    )?;
    let verify_time = timer.stop();
    if !verify_ok {
        return Err("policy-bound semantic verification failed".into());
    }

    let result = Pp3AuroraBenchmarkResult {
        label: label.to_string(),
        k,
        lr_size,
        revocation_depth,
        policy: policy.clone(),
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

/// Constraints-only variant of [`run_pp3_aurora_single_opts`]. Builds the full
/// policy-bound R1CS instance exactly as the full aurora run would but skips
/// the actual `aurora_prove` / `aurora_verify` steps, so it returns in seconds
/// even for large `k`. Returns `(k, rev_depth, constraint_count)`.
///
/// Used by B3 (circuit-scale) when `tier = "constraints_only"` — see docstring
/// on `run_pp2_constraint_count_single` for rationale.
pub fn run_pp3_constraint_count_single(
    _label: &str,
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
    policy: &PolicyInput,
) -> Result<(usize, usize, usize), Box<dyn Error>> {
    if k == 0 {
        return Err("k must be greater than zero".into());
    }

    let mut system = bdec_setup_zk(if tiny { 80 } else { 128 }, 5, revocation_depth)?;
    let user_keypair = bdec_prigen(&system)?;
    populate_revocation_state(&mut system, &user_keypair, lr_size)?;

    // Pay aurora_prove ONCE for the seed credential, then clone its proof for the
    // remaining k-1 credentials. See PP2 counterpart for rationale.
    let mut credentials: Vec<BdecCredential> = Vec::with_capacity(k);
    let seed_pseudonym = bdec_nym_key(&system, &user_keypair)?;
    let seed_attrs = vec![
        "TA0:Credential".to_string(),
        "gpa:35".to_string(),
        "degree:CS".to_string(),
    ];
    let seed_credential =
        bdec_issue_credential(&system, &user_keypair, &seed_pseudonym, seed_attrs)?;
    let stub_proof = seed_credential.proof.aurora_proof.clone();
    credentials.push(seed_credential);
    for i in 1..k {
        let ta_pseudonym = bdec_nym_key(&system, &user_keypair)?;
        let attributes = vec![
            format!("TA{}:Credential", i),
            "gpa:35".to_string(),
            "degree:CS".to_string(),
        ];
        let credential = bdec_issue_credential_with_existing_proof(
            &system,
            &user_keypair,
            &ta_pseudonym,
            attributes,
            stub_proof.clone(),
        )?;
        credentials.push(credential);
    }

    let disclosed = vec!["gpa:35".to_string(), "degree:CS".to_string()];

    let constraint_count = bdec_show_credential_with_policy_paper_constraint_count(
        &system,
        &user_keypair,
        &credentials,
        disclosed,
        policy,
    )?;
    Ok((k, revocation_depth, constraint_count))
}

pub fn run_pp3_default_policy_comparison(
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
) -> Result<Vec<Pp3AuroraBenchmarkResult>, Box<dyn Error>> {
    let (policy_v1, policy_v2) = default_pp3_policies();
    let first = run_pp3_aurora_single("policy_v1", k, tiny, lr_size, revocation_depth, &policy_v1)?;
    let second =
        run_pp3_aurora_single("policy_v2", k, tiny, lr_size, revocation_depth, &policy_v2)?;
    Ok(vec![first, second])
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

#[cfg(test)]
mod tests {
    use super::{PolicyInput, PolicyPredicate, evaluate_policy_input};

    #[test]
    fn pp3_policy_update_still_accepts_same_holder() {
        let attrs = vec!["gpa:35".to_string(), "degree:CS".to_string()];
        let v1 = PolicyInput {
            predicates: vec![PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            }],
        };
        let v2 = PolicyInput {
            predicates: vec![
                PolicyPredicate::GteI64 {
                    key: "gpa".to_string(),
                    min_value: 30,
                },
                PolicyPredicate::OneOf {
                    key: "degree".to_string(),
                    allowed_values: vec!["CS".to_string(), "EE".to_string()],
                },
            ],
        };

        assert!(evaluate_policy_input(&attrs, &v1));
        assert!(evaluate_policy_input(&attrs, &v2));
    }

    #[test]
    fn pp3_rejects_missing_or_invalid_attribute_value() {
        let attrs = vec!["degree:CS".to_string()];
        let policy = PolicyInput {
            predicates: vec![PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            }],
        };

        assert!(!evaluate_policy_input(&attrs, &policy));
    }
}
