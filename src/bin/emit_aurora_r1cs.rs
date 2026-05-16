//! Emit a BDEC R1CS + witness to a binary wire format consumable by the
//! C++ Aurora runner at `scripts/fp127_aurora_runner.cpp`.
//!
//! Wire format v1 ("BR1S"):
//!
//! ```text
//! [header, 40 bytes]
//!   magic           "BR1S"        4 B
//!   version         u32 LE = 1    4 B
//!   field_id        u32 LE = 1    4 B   (Fp127 coeffs; lifted to Fp2 via (c,0))
//!   elem_bytes      u32 LE = 16   4 B
//!   num_variables   u64 LE        8 B   (includes const-1 at var_idx 0)
//!   num_inputs      u64 LE        8 B   (public; var_idx 1..=num_inputs)
//!   num_constraints u64 LE        8 B
//!
//! [constraints, num_constraints rows of:]
//!   for row in (A, B, C):
//!     nnz         u32 LE          4 B
//!     { var_idx u32 LE, coeff 16 B Fp127 canonical LE } * nnz
//!
//! [witness, num_variables - 1 Fp127 elements, 16 B each]
//!   positions 1..num_variables (const-1 is implicit).
//!   First num_inputs entries are PRIMARY (public); rest are AUXILIARY.
//! ```
//!
//! Modes:
//!   * `synthetic` — mirrors `libiop::generate_r1cs_example` exactly, so the
//!     wire format can be end-to-end validated against the in-memory probe.
//!   * `bdec` — (TBD) serializes a real BDEC R1CS built via `build_loquat_r1cs`.
//!
//! Usage:
//!   cargo run --release --bin emit_aurora_r1cs -- \
//!       --mode synthetic --log-n 10 --num-inputs 0 \
//!       --out target/aurora_synth_10.bdec-r1cs
//!
//! All integers on the CLI are decimal. `--seed` controls determinism of the
//! synthetic witness (default 0).

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use vc_pqc::loquat::field_p127::Fp127;
use vc_pqc::loquat::field_utils::field_to_bytes;
use vc_pqc::primitives::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
use vc_pqc::snarks::build_loquat_r1cs_pk_witness;
use vc_pqc::{keygen_with_params, loquat_setup, loquat_setup_tiny, loquat_sign};

const MAGIC: &[u8; 4] = b"BR1S";
const VERSION: u32 = 1;
const FIELD_ID_FP127_EMBED_FP2: u32 = 1;
const ELEM_BYTES: u32 = 16;

/// Small xorshift-style PRNG so the Rust witness is reproducible without an
/// external rand dependency / feature flag. Matches nothing in particular on
/// the C++ side — we only require determinism + satisfaction.
struct DetRng(u64);

impl DetRng {
    fn new(seed: u64) -> Self {
        // Avoid the degenerate zero state of xorshift64.
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn next_u128(&mut self) -> u128 {
        let lo = self.next_u64() as u128;
        let hi = self.next_u64() as u128;
        (hi << 64) | lo
    }
    /// Uniform Fp127 sample by rejection. Fp127 has modulus 2^127 - 1; the
    /// rejection probability is ~2^-127, so in practice the loop runs once.
    fn next_fp127(&mut self) -> Fp127 {
        const MODULUS: u128 = (1u128 << 127) - 1;
        loop {
            let v = self.next_u128() & ((1u128 << 127) - 1);
            if v < MODULUS {
                return Fp127::new(v);
            }
        }
    }
}

/// Mirror of `libiop::generate_r1cs_example<FieldT>` (see
/// `libiop/relations/examples/r1cs_examples.tcc:23-78`), but over Fp127 only.
/// Produces an R1CS that is *guaranteed satisfied* by construction.
fn build_synthetic_r1cs(
    num_constraints: usize,
    num_inputs: usize,
    num_variables: usize, // number of non-const-1 variables (libiop convention)
    seed: u64,
) -> (R1csInstance, R1csWitness) {
    assert!(num_inputs <= num_variables);
    assert!(num_variables >= 1);

    let mut rng = DetRng::new(seed);

    // Full assignment for libiop var indices 1..=num_variables.
    let assignment: Vec<Fp127> = (0..num_variables).map(|_| rng.next_fp127()).collect();

    let mut constraints = Vec::with_capacity(num_constraints);
    for i in 0..num_constraints {
        let a_idx = i % num_variables; // 0-based into `assignment`
        let b_idx = (i + 7) % num_variables;
        let c_idx = (2 * i + 1) % num_variables;

        // libiop indexing: assignment[k] <-> var_idx (k + 1); var_idx 0 == const-1.
        let a_terms = vec![(a_idx + 1, Fp127::one())];
        let b_terms = vec![(b_idx + 1, Fp127::one())];
        let ab_val = assignment[a_idx] * assignment[b_idx];
        let c_terms = if assignment[c_idx].is_zero() {
            vec![(0usize, ab_val)]
        } else {
            let coeff = ab_val / assignment[c_idx];
            vec![(c_idx + 1, coeff)]
        };

        constraints.push(R1csConstraint::from_sparse(a_terms, b_terms, c_terms));
    }

    // R1csInstance.num_variables includes the const-1 slot, so it's num_variables + 1.
    let instance = R1csInstance::new(num_variables + 1, constraints)
        .expect("valid synthetic R1CS instance");
    let witness = R1csWitness::new(assignment);

    // Defence in depth: validate that the R1CS we just built is satisfied.
    instance
        .is_satisfied(&witness)
        .expect("synthetic R1CS must be satisfied by construction");
    assert_eq!(witness.assignment.len(), num_variables);
    let _ = num_inputs; // num_inputs only affects the wire header partitioning.
    (instance, witness)
}

fn write_u32_le(w: &mut impl Write, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u64_le(w: &mut impl Write, v: u64) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_fp127(w: &mut impl Write, v: &Fp127) -> std::io::Result<()> {
    w.write_all(&field_to_bytes(v))
}

fn write_wire(
    path: &PathBuf,
    instance: &R1csInstance,
    witness: &R1csWitness,
    num_inputs: usize,
) -> std::io::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);

    // --- header ---
    w.write_all(MAGIC)?;
    write_u32_le(&mut w, VERSION)?;
    write_u32_le(&mut w, FIELD_ID_FP127_EMBED_FP2)?;
    write_u32_le(&mut w, ELEM_BYTES)?;
    write_u64_le(&mut w, instance.num_variables as u64)?;
    write_u64_le(&mut w, num_inputs as u64)?;
    write_u64_le(&mut w, instance.constraints.len() as u64)?;

    // --- constraints ---
    for c in &instance.constraints {
        for row in [&c.a, &c.b, &c.c] {
            write_u32_le(&mut w, row.len() as u32)?;
            for (idx, coeff) in row.iter() {
                write_u32_le(&mut w, *idx as u32)?;
                write_fp127(&mut w, coeff)?;
            }
        }
    }

    // --- witness (positions 1..num_variables; const-1 implicit) ---
    assert_eq!(witness.assignment.len() + 1, instance.num_variables);
    for v in &witness.assignment {
        write_fp127(&mut w, v)?;
    }

    w.flush()?;
    Ok(())
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut mode = String::from("synthetic");
    let mut log_n: u32 = 10;
    let mut num_inputs: usize = 0;
    let mut seed: u64 = 0;
    let mut out: Option<PathBuf> = None;
    let mut tiny = false;
    let mut security: usize = 80;
    let mut message: String = String::from("emit_aurora_r1cs::bdec");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => mode = args.next().expect("--mode needs value"),
            "--log-n" => log_n = args.next().expect("--log-n needs value").parse().unwrap(),
            "--num-inputs" => {
                num_inputs = args
                    .next()
                    .expect("--num-inputs needs value")
                    .parse()
                    .unwrap()
            }
            "--seed" => seed = args.next().expect("--seed needs value").parse().unwrap(),
            "--out" => out = Some(PathBuf::from(args.next().expect("--out needs value"))),
            "--tiny" => tiny = true,
            "--security" => security = args.next().expect("--security needs value").parse().unwrap(),
            "--message" => message = args.next().expect("--message needs value"),
            other => panic!("unknown arg: {other}"),
        }
    }
    let out = out.unwrap_or_else(|| {
        let tag = if mode == "bdec" {
            if tiny { "tiny".to_string() } else { format!("s{}", security) }
        } else {
            format!("{}", log_n)
        };
        PathBuf::from(format!("target/aurora_{mode}_{tag}.bdec-r1cs"))
    });
    Args {
        mode,
        log_n,
        num_inputs,
        seed,
        out,
        tiny,
        security,
        message,
    }
}

struct Args {
    mode: String,
    log_n: u32,
    num_inputs: usize,
    seed: u64,
    out: PathBuf,
    tiny: bool,
    security: usize,
    message: String,
}

fn main() {
    let a = parse_args();
    match a.mode.as_str() {
        "synthetic" => {
            let n = 1usize << a.log_n;
            // Match probe defaults: num_constraints = n, num_variables = n - 1.
            let num_constraints = n;
            let num_variables = n - 1;
            assert!(
                a.num_inputs <= num_variables,
                "--num-inputs > num_variables"
            );
            // Aurora expects (num_inputs + 1) to be a power of two. 0 or 2^k-1 works.
            if a.num_inputs != 0 {
                let sum = a.num_inputs + 1;
                assert!(sum.is_power_of_two(), "num_inputs + 1 must be a power of 2");
            }
            let (instance, witness) =
                build_synthetic_r1cs(num_constraints, a.num_inputs, num_variables, a.seed);
            write_wire(&a.out, &instance, &witness, a.num_inputs).expect("write wire file");
            let bytes = std::fs::metadata(&a.out).map(|m| m.len()).unwrap_or(0);
            println!(
                "[emit] mode=synthetic log_n={} num_constraints={} num_variables={} (incl. const-1={}) num_inputs={} seed={} -> {:?} ({} B)",
                a.log_n,
                num_constraints,
                num_variables,
                instance.num_variables,
                a.num_inputs,
                a.seed,
                a.out,
                bytes,
            );
        }
        "bdec" => {
            // ---- 1. Loquat params + signature over Fp127 ----
            let params = if a.tiny {
                loquat_setup_tiny().expect("loquat_setup_tiny")
            } else {
                loquat_setup(a.security).expect("loquat_setup")
            };
            let keypair = keygen_with_params(&params).expect("keygen_with_params");
            let message = a.message.as_bytes().to_vec();
            let signature = loquat_sign(&message, &keypair, &params).expect("loquat_sign");

            // ---- 2. Build real BDEC R1CS (satisfied by construction) ----
            let (instance, witness) =
                build_loquat_r1cs_pk_witness(&message, &signature, &keypair.public_key, &params)
                    .expect("build_loquat_r1cs_pk_witness");
            instance
                .is_satisfied(&witness)
                .expect("unpadded BDEC R1CS must be satisfied");

            let raw_num_constraints = instance.num_constraints();
            let raw_num_variables_incl_const1 = instance.num_variables;
            // libiop/Aurora wants num_constraints and num_variables power-of-two.
            // num_inputs=0, so (num_inputs+1)=1 is already pow2. Pad both up.
            let padded_num_constraints = raw_num_constraints.next_power_of_two().max(2);
            let padded_num_variables = raw_num_variables_incl_const1.next_power_of_two().max(2);

            // Clone the constraints + witness and pad.
            let mut padded_constraints = instance.constraints.clone();
            while padded_constraints.len() < padded_num_constraints {
                // Trivial 0 * 0 = 0 constraint — satisfied by any assignment.
                padded_constraints.push(R1csConstraint::from_sparse(vec![], vec![], vec![]));
            }
            let mut padded_assignment = witness.assignment.clone();
            // assignment length = num_variables - 1 (const-1 is implicit).
            while padded_assignment.len() < padded_num_variables - 1 {
                padded_assignment.push(Fp127::zero());
            }

            let padded_instance = R1csInstance::new(padded_num_variables, padded_constraints)
                .expect("padded R1csInstance");
            let padded_witness = R1csWitness::new(padded_assignment);
            padded_instance
                .is_satisfied(&padded_witness)
                .expect("padded BDEC R1CS must still be satisfied");

            write_wire(&a.out, &padded_instance, &padded_witness, 0).expect("write wire file");
            let bytes = std::fs::metadata(&a.out).map(|m| m.len()).unwrap_or(0);
            println!(
                "[emit] mode=bdec tiny={} security={} raw_constraints={} raw_vars_incl_c1={} \
                 -> padded_constraints={} padded_vars_incl_c1={} num_inputs=0 msg={:?} -> {:?} ({} B)",
                a.tiny,
                a.security,
                raw_num_constraints,
                raw_num_variables_incl_const1,
                padded_num_constraints,
                padded_num_variables,
                a.message,
                a.out,
                bytes,
            );
        }
        other => panic!("unknown --mode: {other}"),
    }
}
