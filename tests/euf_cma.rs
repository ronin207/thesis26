#![cfg(feature = "euf_cma_harness")]

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use vc_pqc::loquat::{
    LoquatKeyPair, LoquatPublicParams, LoquatSignature,
    field_utils::{F, F2},
    keygen::keygen_with_params,
    loquat_setup, loquat_sign, loquat_verify,
};

/// Tracks forged messages and enforces the signing-query budget.
struct SigningOracle<'a> {
    keypair: &'a LoquatKeyPair,
    params: &'a LoquatPublicParams,
    max_queries: usize,
    query_count: usize,
    signed_messages: HashSet<Vec<u8>>,
}

impl<'a> SigningOracle<'a> {
    fn new(keypair: &'a LoquatKeyPair, params: &'a LoquatPublicParams, max_queries: usize) -> Self {
        Self {
            keypair,
            params,
            max_queries,
            query_count: 0,
            signed_messages: HashSet::new(),
        }
    }

    fn sign(&mut self, message: &[u8]) -> LoquatSignature {
        assert!(
            self.query_count < self.max_queries,
            "signing oracle exhausted (max {})",
            self.max_queries
        );
        self.query_count += 1;
        self.signed_messages.insert(message.to_vec());
        loquat_sign(message, self.keypair, self.params)
            .expect("signing oracle should not fail under EUF-CMA assumptions")
    }

    fn was_signed(&self, message: &[u8]) -> bool {
        self.signed_messages.contains(message)
    }
}

/// Simple programmable random-oracle facade with bounded queries.
struct RandomOracle {
    cache: HashMap<Vec<u8>, [u8; 32]>,
    max_queries: usize,
    query_count: usize,
}

impl RandomOracle {
    fn new(max_queries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_queries,
            query_count: 0,
        }
    }

    fn query(&mut self, label: &[u8], payload: &[u8]) -> [u8; 32] {
        assert!(
            self.query_count < self.max_queries,
            "random oracle exhausted (max {})",
            self.max_queries
        );
        self.query_count += 1;

        let mut key = Vec::with_capacity(label.len() + 1 + payload.len());
        key.extend_from_slice(label);
        key.push(0xff);
        key.extend_from_slice(payload);

        *self.cache.entry(key).or_insert_with(|| {
            let mut hasher = Sha256::new();
            hasher.update(label);
            hasher.update(payload);
            hasher.finalize().into()
        })
    }
}

/// Context shared with adversaries during a single EUF-CMA trial.
struct ExperimentContext<'a> {
    security_level: usize,
    params: &'a LoquatPublicParams,
    public_key: &'a [F],
}

#[derive(Default)]
struct ExperimentStats {
    attempts: usize,
    successes: usize,
}

impl ExperimentStats {
    fn record(&mut self, success: bool) {
        self.attempts += 1;
        if success {
            self.successes += 1;
        }
    }
}

trait EufCmaAdversary {
    fn label(&self) -> &'static str;
    fn signing_budget(&self) -> usize {
        8
    }
    fn oracle_budget(&self) -> usize {
        64
    }
    fn attempt(
        &mut self,
        ctx: &ExperimentContext,
        oracle: &mut SigningOracle,
        random_oracle: &mut RandomOracle,
    ) -> Option<(Vec<u8>, LoquatSignature)>;
}

fn run_trials<A: EufCmaAdversary>(
    security_level: usize,
    trials: usize,
    mut adversary: A,
) -> ExperimentStats {
    let mut stats = ExperimentStats::default();
    for _ in 0..trials {
        let params = loquat_setup(security_level).expect("parameter setup");
        let keypair = keygen_with_params(&params).expect("key generation");
        let mut signing_oracle = SigningOracle::new(&keypair, &params, adversary.signing_budget());
        let mut random_oracle = RandomOracle::new(adversary.oracle_budget());
        let ctx = ExperimentContext {
            security_level,
            params: &params,
            public_key: &keypair.public_key,
        };

        let forged = adversary.attempt(&ctx, &mut signing_oracle, &mut random_oracle);
        let success = if let Some((message, signature)) = forged {
            let verified =
                loquat_verify(&message, &signature, &keypair.public_key, &params).unwrap_or(false);
            verified && !signing_oracle.was_signed(&message)
        } else {
            false
        };
        stats.record(success);
    }
    stats
}

#[derive(Default)]
struct ReplayAdversary;

impl EufCmaAdversary for ReplayAdversary {
    fn label(&self) -> &'static str {
        "replay"
    }

    fn signing_budget(&self) -> usize {
        1
    }

    fn attempt(
        &mut self,
        ctx: &ExperimentContext,
        oracle: &mut SigningOracle,
        _random_oracle: &mut RandomOracle,
    ) -> Option<(Vec<u8>, LoquatSignature)> {
        let known_message = b"EUF-CMA replay baseline";
        let signature = oracle.sign(known_message);
        // Attempt to reuse σ on a fresh message without re-running the signer.
        let forged_message = format!(
            "EUF-CMA new target λ{}-L{}",
            ctx.security_level,
            ctx.public_key.len()
        )
        .into_bytes();
        Some((forged_message, signature))
    }
}

#[derive(Default)]
struct SumcheckSwapAdversary;

impl EufCmaAdversary for SumcheckSwapAdversary {
    fn label(&self) -> &'static str {
        "sumcheck-swap"
    }

    fn signing_budget(&self) -> usize {
        2
    }

    fn attempt(
        &mut self,
        ctx: &ExperimentContext,
        oracle: &mut SigningOracle,
        _random_oracle: &mut RandomOracle,
    ) -> Option<(Vec<u8>, LoquatSignature)> {
        let sigma_a = oracle.sign(b"sumcheck-alpha");
        let sigma_b = oracle.sign(b"sumcheck-beta");
        let mut forged = sigma_a;
        forged.pi_us = sigma_b.pi_us.clone();
        forged.message_commitment = sigma_b.message_commitment.clone();
        let forged_message = format!("sumcheck-gamma-L{}", ctx.params.l).into_bytes();
        Some((forged_message, forged))
    }
}

#[derive(Default)]
struct TranscriptSpliceAdversary;

impl EufCmaAdversary for TranscriptSpliceAdversary {
    fn label(&self) -> &'static str {
        "transcript-splice"
    }

    fn attempt(
        &mut self,
        ctx: &ExperimentContext,
        oracle: &mut SigningOracle,
        random_oracle: &mut RandomOracle,
    ) -> Option<(Vec<u8>, LoquatSignature)> {
        let mut forged = oracle.sign(b"transcript-anchor");
        let forged_message = format!(
            "forged-message-{}-k{}",
            ctx.security_level, ctx.params.kappa
        )
        .into_bytes();
        let new_commitment = random_oracle.query(b"message", &forged_message);
        forged.message_commitment = new_commitment.to_vec();
        if let Some(first_chunk) = forged
            .ldt_proof
            .openings
            .get_mut(0)
            .and_then(|opening| opening.codeword_chunks.get_mut(0))
            .and_then(|chunk| chunk.get_mut(0))
        {
            *first_chunk = *first_chunk + F2::one();
        }
        Some((forged_message, forged))
    }
}

fn assert_no_forgery_at_level<A: EufCmaAdversary + Default>(lambda: usize, trials: usize) {
    let adversary = A::default();
    let label = adversary.label();
    let stats = run_trials(lambda, trials, adversary);
    assert_eq!(
        stats.successes, 0,
        "{} adversary at λ={} forged {} out of {} attempts",
        label, lambda, stats.successes, stats.attempts
    );
}

fn assert_no_forgery<A: EufCmaAdversary + Default>(trials: usize) {
    assert_no_forgery_at_level::<A>(128, trials);
}

#[test]
fn euf_cma_adversaries_fail_to_forge() {
    assert_no_forgery::<ReplayAdversary>(8);
    assert_no_forgery::<SumcheckSwapAdversary>(8);
    assert_no_forgery::<TranscriptSpliceAdversary>(8);
}

// ── Security level sweep ──────────────────────────────────────────────────────

#[test]
fn euf_cma_adversaries_fail_at_level_80() {
    assert_no_forgery_at_level::<ReplayAdversary>(80, 4);
    assert_no_forgery_at_level::<SumcheckSwapAdversary>(80, 4);
    assert_no_forgery_at_level::<TranscriptSpliceAdversary>(80, 4);
}

#[test]
fn euf_cma_adversaries_fail_at_level_100() {
    assert_no_forgery_at_level::<ReplayAdversary>(100, 4);
    assert_no_forgery_at_level::<SumcheckSwapAdversary>(100, 4);
    assert_no_forgery_at_level::<TranscriptSpliceAdversary>(100, 4);
}

// ── root_c corruption adversary ───────────────────────────────────────────────
//
// Corrupts the Merkle root of LDT codewords (root_c) and attempts to forge a
// signature on a new message.  The LDT commitment is the first Fiat-Shamir
// commitment in the protocol, so any corruption must propagate through the
// challenge derivation and break all subsequent transcript bindings.

#[derive(Default)]
struct RootCCorruptionAdversary;

impl EufCmaAdversary for RootCCorruptionAdversary {
    fn label(&self) -> &'static str { "root-c-corruption" }
    fn signing_budget(&self) -> usize { 1 }

    fn attempt(
        &mut self,
        ctx: &ExperimentContext,
        oracle: &mut SigningOracle,
        _random_oracle: &mut RandomOracle,
    ) -> Option<(Vec<u8>, LoquatSignature)> {
        let mut forged = oracle.sign(b"root-c-anchor");
        // Flip every bit in root_c.  A valid signature's LDT Merkle root cannot
        // remain consistent with the LDT query openings after this mutation.
        for byte in forged.root_c.iter_mut() {
            *byte ^= 0xff;
        }
        let forged_message =
            format!("root-c-target-λ{}", ctx.security_level).into_bytes();
        Some((forged_message, forged))
    }
}

#[test]
fn root_c_corruption_adversary_fails_to_forge() {
    assert_no_forgery::<RootCCorruptionAdversary>(8);
}

#[test]
fn root_c_corruption_adversary_fails_at_level_80() {
    assert_no_forgery_at_level::<RootCCorruptionAdversary>(80, 4);
}

// ── Multi-key adversary ───────────────────────────────────────────────────────
//
// The adversary observes signatures from *two independent keypairs* and attempts
// a cross-key forgery: use components from σ_A (signed under pk_A) to forge a
// valid signature on a fresh message that verifies under pk_B.
//
// Because Loquat binds the public key implicitly through the quadratic-residuosity
// witnesses (the t/o matrices depend on the key values via the IOP key-ID step),
// a signature produced under pk_A should not satisfy the verification equation for
// pk_B.

fn run_multi_key_forgery_trial(lambda: usize) -> bool {
    let params_a = loquat_setup(lambda).expect("params A");
    let keypair_a = keygen_with_params(&params_a).expect("keygen A");
    let params_b = loquat_setup(lambda).expect("params B");
    let keypair_b = keygen_with_params(&params_b).expect("keygen B");

    // Obtain one signature from each key.
    let sigma_a = loquat_sign(b"multi-key-source-A", &keypair_a, &params_a)
        .expect("sign A");
    let sigma_b = loquat_sign(b"multi-key-source-B", &keypair_b, &params_b)
        .expect("sign B");

    // Attempt 1: splice σ_A's sumcheck proof into σ_B and target keypair_b's params.
    let mut attempt_ab = sigma_b.clone();
    attempt_ab.pi_us = sigma_a.pi_us.clone();
    let target_ab = b"multi-key-forged-ab".to_vec();
    let verified_ab = loquat_verify(&target_ab, &attempt_ab, &keypair_b.public_key, &params_b)
        .unwrap_or(false);

    // Attempt 2: take σ_B's t/o matrices but σ_A's root_c.
    let mut attempt_ba = sigma_a.clone();
    attempt_ba.t_values = sigma_b.t_values.clone();
    attempt_ba.o_values = sigma_b.o_values.clone();
    let target_ba = b"multi-key-forged-ba".to_vec();
    let verified_ba = loquat_verify(&target_ba, &attempt_ba, &keypair_a.public_key, &params_a)
        .unwrap_or(false);

    // Either forgery succeeding constitutes a break.
    verified_ab || verified_ba
}

#[test]
fn multi_key_adversary_fails_cross_key_forgery() {
    let mut successes = 0usize;
    let trials = 4;
    for _ in 0..trials {
        if run_multi_key_forgery_trial(128) {
            successes += 1;
        }
    }
    assert_eq!(
        successes, 0,
        "multi-key cross-key forgery succeeded {} out of {} trials",
        successes, trials
    );
}

#[test]
fn multi_key_adversary_fails_at_level_80() {
    let mut successes = 0usize;
    for _ in 0..4 {
        if run_multi_key_forgery_trial(80) {
            successes += 1;
        }
    }
    assert_eq!(successes, 0, "multi-key forgery at λ=80 must not succeed");
}
