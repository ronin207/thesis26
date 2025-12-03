use std::time::Instant;

use vc_pqc::{
    keygen_with_params, loquat_setup, loquat_sign,
    snarks::{
        aurora_prove_with_options, aurora_verify, build_loquat_r1cs, AuroraParams,
        AuroraProverOptions,
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let security_level = 80;
    let message = b"Aurora smoke test for Loquat-80".to_vec();

    println!("=== Aurora smoke test (Loquat-{security_level}) ===");
    let params = loquat_setup(security_level)?;
    let keypair = keygen_with_params(&params)?;
    let signature = loquat_sign(&message, &keypair, &params)?;

    let (instance, witness) = build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)?;
    instance.is_satisfied(&witness)?;
    println!(
        "R1CS ready: {} variables, {} constraints",
        instance.num_variables,
        instance.constraints.len()
    );

    let aurora_params = AuroraParams {
        constraint_query_count: 8,
        witness_query_count: 8,
    };

    let prove_start = Instant::now();
    let proof = aurora_prove_with_options(
        &instance,
        &witness,
        &aurora_params,
        &AuroraProverOptions::default(),
    )?;
    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    let verification = aurora_verify(&instance, &proof, &aurora_params, None)?;
    let verify_time = verify_start.elapsed();

    println!("Aurora prove:   {:.2?}", prove_time);
    println!("Aurora verify:  {:.2?}", verify_time);
    println!("Verification result: {}", if verification.is_some() { "success" } else { "failure" });

    Ok(())
}
