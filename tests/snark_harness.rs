#![cfg(feature = "snark_harness")]

use std::sync::OnceLock;

use vc_pqc::{
    loquat::{
        field_utils::F, keygen::keygen_with_params, loquat_setup, loquat_sign, LoquatKeyPair,
        LoquatPublicParams, LoquatSignature,
    },
    snarks::{
        aurora_prove_with_options, aurora_verify, build_loquat_r1cs, AuroraParams,
        AuroraProverOptions, R1csInstance, R1csWitness,
    },
};

const HARNESS_SECURITY_LEVEL: usize = 80;

struct HarnessFixture {
    params: LoquatPublicParams,
    keypair: LoquatKeyPair,
    message: Vec<u8>,
    signature: LoquatSignature,
    instance: R1csInstance,
    witness: R1csWitness,
    aurora_params: AuroraParams,
}

static FIXTURE: OnceLock<HarnessFixture> = OnceLock::new();

fn harness_fixture() -> &'static HarnessFixture {
    FIXTURE.get_or_init(|| {
        let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"SNARK harness message for aggregate soundness".to_vec();
        let signature =
            loquat_sign(&message, &keypair, &params).expect("Signature generation must succeed");
        let (instance, witness) =
            build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)
                .expect("R1CS construction must succeed for valid signature");
        let aurora_params = AuroraParams {
            constraint_query_count: 8,
            witness_query_count: 8,
        };
        HarnessFixture {
            params,
            keypair,
            message,
            signature,
            instance,
            witness,
            aurora_params,
        }
    })
}

#[test]
fn aurora_accepts_valid_signature_witness() {
    let fixture = harness_fixture();
    let proof = aurora_prove_with_options(
        &fixture.instance,
        &fixture.witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should succeed for honest witness");
    let verification = aurora_verify(&fixture.instance, &proof, &fixture.aurora_params, None)
        .expect("Aurora verification should not error");
    assert!(
        verification.is_some(),
        "Valid witness must yield an accepting Aurora proof"
    );
}

#[test]
fn tampered_signature_cannot_enter_snark() {
    let fixture = harness_fixture();
    let mut signature = fixture.signature.clone();
    signature.root_c[0] ^= 1;
    let build_result = build_loquat_r1cs(
        &fixture.message,
        &signature,
        &fixture.keypair.public_key,
        &fixture.params,
    );
    assert!(
        build_result.is_err(),
        "Tampered signature should fail before R1CS construction"
    );
}

#[test]
fn tampered_witness_fails_aurora_verification() {
    let fixture = harness_fixture();
    let instance = &fixture.instance;
    let mut witness = fixture.witness.clone();
    if let Some(slot) = witness.assignment.get_mut(0) {
        *slot += F::one();
    }

    let proof = aurora_prove_with_options(
        &instance,
        &witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should emit a proof even for malformed witnesses");
    let verification = aurora_verify(&instance, &proof, &fixture.aurora_params, None)
        .expect("Aurora verification should not error");
    assert!(
        verification.is_none(),
        "Aggregated proof with inconsistent witness must be rejected"
    );
}

