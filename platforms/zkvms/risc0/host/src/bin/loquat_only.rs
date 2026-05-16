//! Loquat-only host: clean `loquat_setup(λ) → n × {keygen, sign} → guest`
//! pipeline. Generates `n` distinct keypairs and signs `n` distinct messages,
//! then runs the loquat-only guest in dev mode and prints a JSON line with
//! per-phase cycle totals summed across all `n` verifies.
//!
//! Usage:
//!   cargo run --release --bin loquat_only -- --security-level 80 --n 1
//!   cargo run --release --bin loquat_only -- --security-level 128 --n 32

use methods::{LOQUAT_ONLY_ELF, LOQUAT_ONLY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use vc_pqc::loquat::{
    field_utils::F, keygen_with_params, loquat_setup, loquat_sign, LoquatPublicParams,
    LoquatSignature,
};

#[derive(Serialize, Deserialize)]
struct LoquatItem {
    message: Vec<u8>,
    signature: LoquatSignature,
    public_key: Vec<F>,
}

#[derive(Serialize, Deserialize)]
struct LoquatOnlyInput {
    items: Vec<LoquatItem>,
    params: LoquatPublicParams,
}

#[derive(Serialize, Deserialize)]
struct LoquatOnlyOutput {
    status: String,
    n_sigs: usize,
    n_accepted: usize,
    start_cycle: u64,
    end_cycle: u64,
    /// (phase_name, cycles, griffin_perms, fp127_muls, fp2_adds, fp2_subs, fp2_muls) across n verifies.
    phase_totals: Vec<(String, u64, u64, u64, u64, u64, u64)>,
    per_verify_cycles: Vec<u64>,
    total_griffin_perms: u64,
    total_fp127_muls: u64,
    total_fp2_adds: u64,
    total_fp2_subs: u64,
    total_fp2_muls: u64,
}

#[derive(Serialize)]
struct PhaseDelta {
    name: String,
    cycles_total: u64,
    pct: f64,
    cycles_per_sig: u64,
    griffin_perms_total: u64,
    griffin_perms_per_sig: u64,
    fp127_muls_total: u64,
    fp127_muls_per_sig: u64,
    fp2_adds_total: u64,
    fp2_subs_total: u64,
    fp2_muls_total: u64,
}

#[derive(Serialize)]
struct Report {
    status: String,
    accepted: bool,
    security_level: usize,
    n_sigs: usize,
    n_accepted: usize,
    total_cycles: u64,
    cycles_per_sig: u64,
    total_griffin_perms: u64,
    griffin_perms_per_sig: u64,
    total_fp127_muls: u64,
    fp127_muls_per_sig: u64,
    total_fp2_adds: u64,
    total_fp2_subs: u64,
    total_fp2_muls: u64,
    setup_ms: f64,
    keygen_total_ms: f64,
    sign_total_ms: f64,
    prove_wallclock_ms: f64,
    receipt_kind: String,
    phases: Vec<PhaseDelta>,
    per_verify_cycles: Vec<u64>,
}

fn parse_args() -> (usize, usize) {
    let args: Vec<String> = std::env::args().collect();
    let mut sec: usize = 80;
    let mut n: usize = 1;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--security-level" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) {
                    if v > 0 {
                        sec = v;
                    }
                }
                i += 2;
            }
            flag if flag.starts_with("--security-level=") => {
                if let Some(v) = flag
                    .split_once('=')
                    .and_then(|(_, s)| s.parse::<usize>().ok())
                {
                    if v > 0 {
                        sec = v;
                    }
                }
                i += 1;
            }
            "--n" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<usize>().ok()) {
                    if v > 0 {
                        n = v;
                    }
                }
                i += 2;
            }
            flag if flag.starts_with("--n=") => {
                if let Some(v) = flag
                    .split_once('=')
                    .and_then(|(_, s)| s.parse::<usize>().ok())
                {
                    if v > 0 {
                        n = v;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    (sec, n)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let (security_level, n_sigs) = parse_args();

    // Dev mode: cycle counts only, no real STARK.
    unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };

    // 1. Setup (once, shared across all n)
    let t = Instant::now();
    let params = loquat_setup(security_level)
        .unwrap_or_else(|e| panic!("loquat_setup({security_level}) failed: {e:?}"));
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;

    // 2 & 3. n × (keygen + sign) on host
    let t_kg = Instant::now();
    let mut keypairs = Vec::with_capacity(n_sigs);
    for _ in 0..n_sigs {
        keypairs.push(
            keygen_with_params(&params)
                .unwrap_or_else(|e| panic!("keygen failed: {e:?}")),
        );
    }
    let keygen_total_ms = t_kg.elapsed().as_secs_f64() * 1000.0;

    let t_sg = Instant::now();
    let mut items: Vec<LoquatItem> = Vec::with_capacity(n_sigs);
    for (i, kp) in keypairs.iter().enumerate() {
        let msg = format!("loquat-only-{:08x}", i).into_bytes();
        let sig = loquat_sign(&msg, kp, &params)
            .unwrap_or_else(|e| panic!("sign #{i} failed: {e:?}"));
        items.push(LoquatItem {
            message: msg,
            signature: sig,
            public_key: kp.public_key.clone(),
        });
    }
    let sign_total_ms = t_sg.elapsed().as_secs_f64() * 1000.0;

    // 4. Drive guest
    let guest_input = LoquatOnlyInput { items, params };

    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .expect("write guest input")
        .build()
        .expect("build executor env");

    let prover = default_prover();
    let t_pv = Instant::now();
    let prove_info = prover
        .prove(env, LOQUAT_ONLY_ELF)
        .expect("guest execution failed");
    let prove_wallclock_ms = t_pv.elapsed().as_secs_f64() * 1000.0;

    let receipt_kind = match &prove_info.receipt.inner {
        InnerReceipt::Fake(_) => "fake",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Groth16(_) => "groth16",
        _ => "unknown",
    };

    let journal: LoquatOnlyOutput = prove_info
        .receipt
        .journal
        .decode()
        .expect("decode guest journal");

    let total_cycles = journal.end_cycle.saturating_sub(journal.start_cycle);
    let phases: Vec<PhaseDelta> = journal
        .phase_totals
        .iter()
        .map(|(name, c, g, f, a2, s2, m2)| PhaseDelta {
            name: name.clone(),
            cycles_total: *c,
            pct: if total_cycles > 0 {
                (*c as f64 / total_cycles as f64) * 100.0
            } else {
                0.0
            },
            cycles_per_sig: if n_sigs > 0 { *c / n_sigs as u64 } else { 0 },
            griffin_perms_total: *g,
            griffin_perms_per_sig: if n_sigs > 0 { *g / n_sigs as u64 } else { 0 },
            fp127_muls_total: *f,
            fp127_muls_per_sig: if n_sigs > 0 { *f / n_sigs as u64 } else { 0 },
            fp2_adds_total: *a2,
            fp2_subs_total: *s2,
            fp2_muls_total: *m2,
        })
        .collect();

    let _ = LOQUAT_ONLY_ID; // silence unused warning

    let report = Report {
        status: journal.status,
        accepted: journal.n_accepted == journal.n_sigs,
        security_level,
        n_sigs: journal.n_sigs,
        n_accepted: journal.n_accepted,
        total_cycles,
        cycles_per_sig: if n_sigs > 0 {
            total_cycles / n_sigs as u64
        } else {
            0
        },
        total_griffin_perms: journal.total_griffin_perms,
        griffin_perms_per_sig: if n_sigs > 0 {
            journal.total_griffin_perms / n_sigs as u64
        } else {
            0
        },
        total_fp127_muls: journal.total_fp127_muls,
        fp127_muls_per_sig: if n_sigs > 0 {
            journal.total_fp127_muls / n_sigs as u64
        } else {
            0
        },
        total_fp2_adds: journal.total_fp2_adds,
        total_fp2_subs: journal.total_fp2_subs,
        total_fp2_muls: journal.total_fp2_muls,
        setup_ms,
        keygen_total_ms,
        sign_total_ms,
        prove_wallclock_ms,
        receipt_kind: String::from(receipt_kind),
        phases,
        per_verify_cycles: journal.per_verify_cycles,
    };

    println!(
        "{}",
        serde_json::to_string(&report).expect("serialize report")
    );
}
