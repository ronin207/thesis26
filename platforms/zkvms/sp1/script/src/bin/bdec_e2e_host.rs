//! SP1 BDEC end-to-end THREADED host (real attributes) — statement-bound.
//!
//! Walks ONE user's credential lifecycle under a single hidden PLUM key `sk_U`,
//! following thesis Section 3 (Setup -> KeyGen -> NymGen -> CreGen -> ShowCre),
//! then runs THREE statement-bound (`jbind`) proves off the shared, threaded
//! witnesses:
//!   - CreGen x2: issue two W3C-VC-style credentials from two DISTINCT issuers
//!     (a university degree + an employment credential), both under `sk_U`.
//!   - ShowCre (k=2): disclose a subset drawn ACROSS both credentials, under the
//!     SAME key and the SAME issuance-time pseudonyms (k = two issuer relations).
//!
//! HONESTY (base BDEC, per Section 3): selective disclosure here is the user
//! RE-SIGNING the chosen subset (`c_{U,V}=Sign(sk_U,H(A_down))`). The proof does
//! NOT re-verify the issuer-signed credentials and does NOT enforce
//! `A_down ⊆ A`; W3C-style cryptographic selective disclosure is the Appendix-B
//! Merkle variant, OUT of scope (03-preliminaries.tex:468). Present as
//! "anonymous, unlinkable presentation of a user-chosen self-attested
//! cross-issuer subset," NOT "cryptographically-bound selective disclosure of
//! issuer-signed attributes."
//!
//! Fidelity notes (Section 3):
//!   * All credential/pseudonym signatures are the user's own, under `sk_U`
//!     (03-prelim:442,445): `c_{U,TA}=Sign(sk_U,H(A))`, `psk=Sign(sk_U,ppk)`,
//!     `c_{U,V}=Sign(sk_U,H(A_down))`.
//!   * The shown credential `c_{U,V}` stays a PRIVATE witness (Option B); the
//!     receipts bind `x_cre=(c_{U,TA},h_{U,TA},ppk_{U,TA})` and
//!     `x_show=((ppk_{U,TA})_j,ppk_{U,V},h_{U,V})`.
//!   * The predicate phi (gpa>3.5) is the verifier's IN-THE-CLEAR check
//!     (03-prelim:513, "No in-circuit predicate enforces it"), NOT in-circuit.
//!   * Prove-time is identical to the synthetic runs — real attributes and
//!     threading do not change the in-circuit relation.
//!
//! Env: `BDEC_HOST_SECURITY` (PLUM lambda, default 80). Memory-tuning env
//! (SHARD_SIZE, SP1_PROVER, ...) is read by SP1 at runtime — set it as in
//! `scripts/run_showcre_wrap.sh`, and use `CARGO_TARGET_DIR=$REPO/.build-cache.nosync`.

use std::time::Instant;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

// jbind ELFs (built by build.rs; env vars are crate-wide).
const CREGEN_JBIND_ELF: &[u8] = include_bytes!(env!("BDEC_CREGEN_JBIND_ELF_PATH"));
const SHOWCRE_JBIND_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_JBIND_ELF_PATH"));

// Mirror of program_bdec_cregen guest GuestInput (field order MUST match).
#[derive(Serialize, Deserialize)]
struct CreGenInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

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

/// H(attributes): digest of a real attribute set, serialized as a CANONICAL
/// fixed-order field list (one field per line) — a stand-in for JCS / JSON-LD
/// canonicalization, sufficient because BDEC consumes only H(A). Deterministic
/// only if field order is fixed (it is: callers pass ordered arrays).
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

/// CreGen jbind prove: bind x_cre=(c,h,ppk), keep w_cre=(pk_U,psk) private.
fn prove_jbind_cregen(client: &impl Prover, input: &CreGenInput) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bincode::serialize(input).expect("serialize cregen"));
    let pk = client.setup(Elf::Static(CREGEN_JBIND_ELF)).expect("cregen setup");
    let t = Instant::now();
    let proof = client.prove(&pk, stdin).run().expect("cregen prove");
    let ms = t.elapsed().as_millis();
    client.verify(&proof, pk.verifying_key(), None).expect("cregen verify");
    let ((c, h, ppk), accepted): ((PlumSignature, Vec<u8>, Vec<u8>), bool) =
        bincode::deserialize(proof.public_values.as_slice()).expect("cregen journal");
    let bound = bincode::serialize(&c).unwrap() == bincode::serialize(&input.c_u_ta).unwrap()
        && h == input.h_u_ta
        && ppk == input.ppk_u_ta;
    println!(
        "CREGEN accepted={accepted} statement_bound={bound} prove_ms={ms} (= {:.2} min)",
        ms as f64 / 60_000.0
    );
    assert!(accepted, "CreGen guest rejected the honest witness");
    assert!(bound, "CreGen committed x_cre does not match input");
}

/// ShowCre jbind prove: bind x_show=((ppk_TA)_j,ppk_UV,h_UV), keep
/// w_show=(pk_U,psk...,c_UV) private.
fn prove_jbind_showcre(client: &impl Prover, input: &ShowCreInput) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bincode::serialize(input).expect("serialize showcre"));
    let pk = client.setup(Elf::Static(SHOWCRE_JBIND_ELF)).expect("showcre setup");
    let t = Instant::now();
    let proof = client.prove(&pk, stdin).run().expect("showcre prove");
    let ms = t.elapsed().as_millis();
    client.verify(&proof, pk.verifying_key(), None).expect("showcre verify");
    let ((nym_msgs, nym_uv_msg, show_msg), accepted): ((Vec<Vec<u8>>, Vec<u8>, Vec<u8>), bool) =
        bincode::deserialize(proof.public_values.as_slice()).expect("showcre journal");
    let bound = nym_msgs == input.nym_msgs
        && nym_uv_msg == input.nym_uv_msg
        && show_msg == input.show_msg;
    println!(
        "SHOWCRE accepted={accepted} statement_bound={bound} prove_ms={ms} (= {:.2} min)",
        ms as f64 / 60_000.0
    );
    assert!(accepted, "ShowCre guest rejected the honest witness");
    assert!(bound, "ShowCre committed x_show does not match input");
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    // 1. Setup.
    let pp = plum_setup(security).expect("setup");
    // 2. KeyGen: ONE user, threaded through the whole lifecycle.
    let mut rng = ChaCha20Rng::seed_from_u64(0x4244_4543_4532_4531); // "BDECE2E1"
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

    // Two W3C-VC-style credentials from two DISTINCT issuers, both bound to the
    // SAME hidden sk_U. Attributes are a canonical fixed-order field list hashed
    // to the credential digest (BDEC consumes only H(A); see module doc).
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
    // Disclosed subset drawn ACROSS both credentials (phi_2-class, k=2).
    let attrs_disclosed = [
        "credentialSubject.gpa:3.7",                   // from the degree VC (phi: gpa>3.5)
        "credentialSubject.employer:Acme Corporation", // from the employment VC
    ];
    let h_u_ta_1 = attr_hash(&vc_degree); // H(A_1)
    let h_u_ta_2 = attr_hash(&vc_employment); // H(A_2)
    let show_msg = attr_hash(&attrs_disclosed); // H(A_down) = h_{U,V}

    // 3. NymGen: one pseudonym per issuer relationship (bound to sk_U), plus a
    //    fresh verifier-facing pseudonym for this showing.
    let ppk_u_ta_1 = rand_bytes(&mut rng, 32);
    let psk_u_ta_1 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta_1, &mut rng);
    let ppk_u_ta_2 = rand_bytes(&mut rng, 32);
    let psk_u_ta_2 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta_2, &mut rng);
    let ppk_u_v = rand_bytes(&mut rng, 32);
    let psk_u_v = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_v, &mut rng);

    // 4. CreGen x2: issue BOTH credentials (each c_{U,TA}=Sign(sk_U,H(A_i))).
    //    BOTH issuances are proved, so the second issuer relationship is real,
    //    not a pseudonym with no backing credential.
    let c_u_ta_1 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta_1, &mut rng);
    let cregen_1 = CreGenInput {
        pp: pp.clone(),
        pk_u: pk_u.clone(),
        h_u_ta: h_u_ta_1.clone(),
        c_u_ta: c_u_ta_1,
        ppk_u_ta: ppk_u_ta_1.clone(),
        psk_u_ta: psk_u_ta_1.clone(),
    };
    let c_u_ta_2 = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta_2, &mut rng);
    let cregen_2 = CreGenInput {
        pp: pp.clone(),
        pk_u: pk_u.clone(),
        h_u_ta: h_u_ta_2.clone(),
        c_u_ta: c_u_ta_2,
        ppk_u_ta: ppk_u_ta_2.clone(),
        psk_u_ta: psk_u_ta_2.clone(),
    };

    // 6. ShowCre (k=2): disclose A_down across BOTH credentials, under the SAME
    //    key and the SAME issuance-time pseudonyms. ONE aggregated shown
    //    credential c_{U,V} over H(A_down); c_{U,V} stays a private witness.
    let c_u_v = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &show_msg, &mut rng);
    let showcre = ShowCreInput {
        pp,
        pk_u,
        nym_msgs: vec![ppk_u_ta_1, ppk_u_ta_2], // k = 2 issuer relationships
        nym_sigs: vec![psk_u_ta_1, psk_u_ta_2],
        nym_uv_msg: ppk_u_v,
        nym_uv_sig: psk_u_v,
        show_msg,
        show_sig: c_u_v, // c_{U,V}: PRIVATE witness, never committed
    };

    println!("=== BDEC end-to-end THREADED, k=2 two-issuer (W3C-VC-style attrs), lambda={security} ===");
    println!("one user pk_U; Cred1 (degree VC)     A_1 = {vc_degree:?}");
    println!("             ; Cred2 (employment VC) A_2 = {vc_employment:?}");
    println!("disclosed A_down (across both) = {attrs_disclosed:?}");
    println!("SCOPE: anonymous, unlinkable presentation of a self-attested cross-issuer subset;");
    println!("       NOT cryptographic selective disclosure (A_down subset-of A NOT enforced; base BDEC).");

    let client = ProverClient::from_env();
    println!("--- 4a. CreGen jbind prove (issue degree VC) ---");
    prove_jbind_cregen(&client, &cregen_1);
    println!("--- 4b. CreGen jbind prove (issue employment VC) ---");
    prove_jbind_cregen(&client, &cregen_2);
    println!("--- 6. ShowCre k=2 jbind prove (disclose across both under same key) ---");
    prove_jbind_showcre(&client, &showcre);
    println!("=== BDEC end-to-end DONE ===");
}
