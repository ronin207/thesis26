//! Witness-dump for the DEMO artifact runs: the ShowCre k=2 witness with the
//! REAL W3C-VC-style attributes of `bdec_e2e_host.rs` (two issuers, disclosed
//! subset {gpa, employer} across both), so the persisted receipt/wrap bind the
//! demo's actual attribute statement `h_{U,V} = H(A_down)`.
//!
//! Construction (seed 0x4244_4543_4532_4531 "BDECE2E1", attribute lists,
//! attr_hash, pseudonym generation) is copied VERBATIM from `bdec_e2e_host.rs`
//! so the dumped bytes reproduce the measured e2e ShowCre k=2 statement
//! (`bdec_e2e_20260710`, 127.94 min jbind prove). Before dumping, the JBIND
//! ELF is EXECUTED once and the journal bind-checked, validating the witness
//! before a prover spends hours on it.
//!
//! Env: `BDEC_DUMP_OUT` (output path), `BDEC_HOST_SECURITY` (default 80).

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const SHOWCRE_JBIND_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_JBIND_ELF_PATH"));

// Mirror of program_bdec_showcre guest GuestInput (field order MUST match).
#[derive(Serialize, Deserialize)]
struct ShowCreInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

/// Verbatim from `bdec_e2e_host.rs`.
fn attr_hash(attrs: &[&str]) -> Vec<u8> {
    let mut h = Sha256::new();
    for a in attrs {
        h.update(a.as_bytes());
        h.update(b"\n");
    }
    h.finalize().to_vec()
}

fn rand_bytes(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let out_path = std::env::var("BDEC_DUMP_OUT").expect("set BDEC_DUMP_OUT");
    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    // --- VERBATIM witness construction from bdec_e2e_host.rs main() ---
    let pp = plum_setup(security).expect("setup");
    let mut rng = ChaCha20Rng::seed_from_u64(0x4244_4543_4532_4531); // "BDECE2E1"
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

    let vc_degree = [
        "type:UniversityDegreeCredential",
        "issuer:did:web:waseda.jp",
        "issuanceDate:2021-03-25",
        "credentialSubject.name:Takumi Otsuka",
        "credentialSubject.degree:Bachelor of Science",
        "credentialSubject.major:Computer Science",
        "credentialSubject.gradYear:2021",
        "credentialSubject.gpa:3.7",
    ];
    let vc_employment = [
        "type:EmploymentCredential",
        "issuer:did:web:acme.example",
        "issuanceDate:2022-04-01",
        "credentialSubject.name:Takumi Otsuka",
        "credentialSubject.employer:Acme Corporation",
        "credentialSubject.role:Software Engineer",
    ];
    let attrs_disclosed = [
        "credentialSubject.gpa:3.7",
        "credentialSubject.employer:Acme Corporation",
    ];
    let show_msg = attr_hash(&attrs_disclosed); // H(A_down) = h_{U,V}

    let ppk_u_ta_1 = rand_bytes(&mut rng, 32);
    let psk_u_ta_1 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta_1, &mut rng);
    let ppk_u_ta_2 = rand_bytes(&mut rng, 32);
    let psk_u_ta_2 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta_2, &mut rng);
    let ppk_u_v = rand_bytes(&mut rng, 32);
    let psk_u_v = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_v, &mut rng);

    // NOTE: bdec_e2e_host signs the two CreGen credentials (c_u_ta_1/2) between
    // the pseudonym block and c_u_v, advancing the RNG; replicate EXACTLY so
    // c_{U,V} matches the measured e2e statement byte-for-byte.
    let h_u_ta_1 = attr_hash(&vc_degree);
    let h_u_ta_2 = attr_hash(&vc_employment);
    let _c_u_ta_1 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta_1, &mut rng);
    let _c_u_ta_2 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta_2, &mut rng);
    let c_u_v = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &show_msg, &mut rng);

    let input = ShowCreInput {
        pp,
        pk_u,
        nym_msgs: vec![ppk_u_ta_1, ppk_u_ta_2],
        nym_sigs: vec![psk_u_ta_1, psk_u_ta_2],
        nym_uv_msg: ppk_u_v,
        nym_uv_sig: psk_u_v,
        show_msg: show_msg.clone(),
        show_sig: c_u_v,
    };
    let bytes = bincode::serialize(&input).expect("serialize ShowCreInput");
    println!("witness_bytes={} h_UV=H({:?})", bytes.len(), attrs_disclosed);

    // --- Validate: execute the JBIND ELF once, bind-check the journal ---
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let (output, report) = client
        .execute(Elf::Static(SHOWCRE_JBIND_ELF), stdin)
        .run()
        .expect("execute failed");
    let ((nym_msgs, nym_uv_msg, journal_show_msg), accepted): (
        (Vec<Vec<u8>>, Vec<u8>, Vec<u8>),
        bool,
    ) = bincode::deserialize(output.as_slice()).expect("decode journal");
    assert!(accepted, "jbind guest rejected the W3C witness");
    assert!(
        nym_msgs == input.nym_msgs
            && nym_uv_msg == input.nym_uv_msg
            && journal_show_msg == show_msg,
        "journal does not bind the W3C statement"
    );
    println!(
        "VALIDATED accepted=true statement_bound=true instructions={}",
        report.total_instruction_count()
    );

    std::fs::write(&out_path, &bytes).expect("write witness");
    println!("DUMPED -> {out_path}");
}
