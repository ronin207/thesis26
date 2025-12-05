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

fn assert_no_forgery<A: EufCmaAdversary + Default>(trials: usize) {
    let adversary = A::default();
    let intrinsic_label = adversary.label();
    let stats = run_trials(128, trials, adversary);
    assert_eq!(
        stats.successes, 0,
        "{} adversary forged {} out of {} attempts",
        intrinsic_label, stats.successes, stats.attempts
    );
}

#[test]
fn euf_cma_adversaries_fail_to_forge() {
    assert_no_forgery::<ReplayAdversary>(8);
    assert_no_forgery::<SumcheckSwapAdversary>(8);
    assert_no_forgery::<TranscriptSpliceAdversary>(8);
}
