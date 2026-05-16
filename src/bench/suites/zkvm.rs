//! B6 — RISC Zero zkVM parameter sweep.
//!
//! Invokes the zkvm host binary (`zkvm/target/release/host`) for every
//! (k, s, m) combination in the configured sweep.  The host binary is built
//! automatically if it does not exist.
//!
//! # Execution modes
//!
//! | `mode`    | Env var             | What happens                           |
//! |-----------|---------------------|----------------------------------------|
//! | `"dev"`   | `RISC0_DEV_MODE=1`  | Execute-only; no ZK proof generated.   |
//! |           |                     | Returns `trace_cycles` in ~15s/combo.  |
//! | `"full"`  | (none)              | Full succinct STARK proof.             |
//! |           |                     | Uses CPU prover; slow (~5+ min/combo). |
//! | `"bonsai"`| `BONSAI_API_KEY`    | Cloud proving via Bonsai API.          |
//!
//! **Primary metric:** `trace_cycles` — deterministic, hardware-independent.
//! **Secondary metric:** `prove_ms`, `verify_ms`, `receipt_bytes`.
//!
//! # zkVM cycle count interpretation
//!
//! Cycle counts scale linearly with:
//!   - `loquat_verifies` ≈ k (one verification per credential)
//!   - `hash_calls` ≈ k × internal_loquat_hashes + s × rev_depth
//!   - `merkle_nodes` ≈ (s + 1) × rev_depth
//!
//! Cross-referencing cycles with op-counts in the journal yields a per-op
//! cycle budget table — a useful secondary contribution.

use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::bench::{BenchWriter, RunnerConfig, SampleRecord, ZkvmConfig, emit_summaries};
use crate::{LoquatError, LoquatResult};

pub fn run(runner: &RunnerConfig, cfg: &ZkvmConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    let host_bin = resolve_host_bin(cfg)?;
    
    // Build a flat list of all (k, s, m) combinations, skipping invalid ones
    // (s must be ≤ m).
    let combos: Vec<(usize, usize, usize)> = cfg
        .k_values
        .iter()
        .flat_map(|&k| {
            cfg.s_values.iter().flat_map(move |&s| {
                cfg.m_values
                    .iter()
                    .filter(move |&&m| s <= m)
                    .map(move |&m| (k, s, m))
            })
        })
        .collect();

    eprintln!(
        "[B6] zkVM sweep: {} combos × {} runs (mode={})",
        combos.len(),
        runner.runs,
        cfg.mode
    );

    for (k, s, m) in &combos {
        run_combo(runner, cfg, w, &host_bin, *k, *s, *m)?;
    }

    w.flush()?;
    Ok(())
}

fn run_combo(
    runner: &RunnerConfig,
    cfg: &ZkvmConfig,
    w: &mut BenchWriter,
    host_bin: &str,
    k: usize,
    s: usize,
    m: usize,
) -> LoquatResult<()> {
    let config_key = format!("k={k}_s={s}_m={m}");
    let config_val = serde_json::json!({
        "k": k, "s": s, "m": m,
        "lr_size": cfg.lr_size,
        "rev_depth": cfg.rev_depth,
        "mode": cfg.mode,
    });

    let total = runner.warmup + runner.runs;
    let mut cycles_vec = Vec::new();
    let mut prove_ms_vec = Vec::new();
    let mut verify_ms_vec = Vec::new();
    let mut receipt_bytes_vec = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        let wall_start = Instant::now();
        let result = invoke_host_with_retry(cfg, host_bin, k, s, m)?;
        let wall_ms = wall_start.elapsed().as_secs_f64() * 1000.0;

        let metrics_val = serde_json::json!({
            "trace_cycles":      result.trace_cycles,
            "loquat_verifies":   result.loquat_verifies,
            "hash_calls":        result.hash_calls,
            "merkle_nodes":      result.merkle_nodes,
            "receipt_bytes":     result.receipt_bytes,
        });
        let phases_val = serde_json::json!({
            "prove_ms":  result.prove_ms,
            "verify_ms": result.verify_ms,
        });

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B6".to_string(),
            variant: "zkvm_sweep".to_string(),
            config_key: config_key.clone(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms,
            phases: phases_val,
            metrics: metrics_val,
        })?;

        if !is_warmup {
            cycles_vec.push(result.trace_cycles as f64);
            prove_ms_vec.push(result.prove_ms);
            verify_ms_vec.push(result.verify_ms);
            receipt_bytes_vec.push(result.receipt_bytes as f64);
        }
    }

    emit_summaries(w, "B6", "zkvm_sweep", &config_key, runner.warmup, &[
        ("trace_cycles",   cycles_vec),
        ("prove_ms",       prove_ms_vec),
        ("verify_ms",      verify_ms_vec),
        ("receipt_bytes",  receipt_bytes_vec),
    ])?;

    Ok(())
}

// ── Host invocation ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct HostResult {
    trace_cycles: u64,
    prove_ms: f64,
    verify_ms: f64,
    receipt_bytes: usize,
    loquat_verifies: u32,
    hash_calls: u32,
    merkle_nodes: u32,
}

/// Retry wrapper around `invoke_host`.  Retries up to `cfg.max_retries` times
/// on any transient (non-zero exit) failure, logging a warning on each attempt.
fn invoke_host_with_retry(
    cfg: &ZkvmConfig,
    host_bin: &str,
    k: usize,
    s: usize,
    m: usize,
) -> LoquatResult<HostResult> {
    let max_attempts = cfg.max_retries + 1;
    let mut last_err = LoquatError::invalid_parameters("no attempts made");
    for attempt in 1..=max_attempts {
        match invoke_host(cfg, host_bin, k, s, m) {
            Ok(result) => return Ok(result),
            Err(err) => {
                last_err = err;
                if attempt < max_attempts {
                    eprintln!(
                        "[B6] (k={k}, s={s}, m={m}) attempt {attempt}/{max_attempts} failed: {last_err}; retrying"
                    );
                }
            }
        }
    }
    Err(last_err)
}

/// Invoke `host` as a subprocess with an optional wall-clock timeout, parse
/// its JSONL output.  When `cfg.timeout_secs > 0` the child process is
/// spawned on a background thread and joined via a channel; if the timeout
/// fires the child is abandoned and an error is returned.
fn invoke_host(
    cfg: &ZkvmConfig,
    host_bin: &str,
    k: usize,
    s: usize,
    m: usize,
) -> LoquatResult<HostResult> {
    let mut cmd = Command::new(host_bin);
    cmd.arg(format!("--k={k}"))
        .arg(format!("--s={s}"))
        .arg(format!("--m={m}"))
        .arg(format!("--lr-size={}", cfg.lr_size))
        .arg(format!("--rev-depth={}", cfg.rev_depth))
        .arg("--json");

    match cfg.mode.as_str() {
        "dev" => {
            // Two switches needed for dev mode:
            //   * RISC0_DEV_MODE=1 tells the risc0 runtime to skip real
            //     STARK generation and return a "fake" receipt.
            //   * --dev-mode tells the host binary to accept a fake receipt
            //     instead of rejecting it in the post-prove check.
            cmd.env("RISC0_DEV_MODE", "1");
            cmd.arg("--dev-mode");
        }
        "bonsai" => {
            // Pass the Bonsai credentials to the child process.  Prefer the
            // config fields; fall back to the current process's environment.
            let api_key = if cfg.bonsai_api_key.is_empty() {
                std::env::var("BONSAI_API_KEY").unwrap_or_default()
            } else {
                cfg.bonsai_api_key.clone()
            };
            let api_url = if cfg.bonsai_api_url.is_empty() {
                std::env::var("BONSAI_API_URL").unwrap_or_default()
            } else {
                cfg.bonsai_api_url.clone()
            };
            if api_key.is_empty() {
                return Err(LoquatError::invalid_parameters(
                    "bonsai mode requires BONSAI_API_KEY (set in config or env)",
                ));
            }
            cmd.env("BONSAI_API_KEY", api_key);
            if !api_url.is_empty() {
                cmd.env("BONSAI_API_URL", api_url);
            }
        }
        _ => {} // "full" and unknown modes: no extra env vars
    }

    // Run with optional timeout via a background thread + channel.
    let timeout = if cfg.timeout_secs > 0 {
        Some(Duration::from_secs(cfg.timeout_secs))
    } else {
        None
    };

    if let Some(timeout) = timeout {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = cmd.output();
            let _ = tx.send(result);
        });
        match rx.recv_timeout(timeout) {
            Ok(output_result) => {
                let output = output_result.map_err(|e| {
                    LoquatError::invalid_parameters(&format!(
                        "failed to invoke zkvm host ({host_bin}): {e}"
                    ))
                })?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(LoquatError::invalid_parameters(&format!(
                        "zkvm host exited with {}: {stderr}",
                        output.status
                    )));
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_host_output(&stdout)
            }
            Err(_) => Err(LoquatError::invalid_parameters(&format!(
                "zkvm host timed out after {}s (k={k}, s={s}, m={m})",
                cfg.timeout_secs
            ))),
        }
    } else {
        let output = cmd.output().map_err(|e| {
            LoquatError::invalid_parameters(&format!(
                "failed to invoke zkvm host ({host_bin}): {e}"
            ))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(LoquatError::invalid_parameters(&format!(
                "zkvm host exited with {}: {stderr}",
                output.status
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_host_output(&stdout)
    }
}

/// Parse the JSON line emitted by `pp2_showver::print_summary`.
/// Expected format:
/// ```json
/// {"status":"ok","k":1,"s":1,"m":16,"trace_cycles":12345678,"prove_ms":1234.56,
///  "verify_ms":45.6,"receipt_bytes":123456,"loquat_verifies":1,"hash_calls":42,"merkle_nodes":40}
/// ```
fn parse_host_output(output: &str) -> LoquatResult<HostResult> {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            LoquatError::invalid_parameters(&format!("cannot parse host JSON line: {e}\nLine: {line}"))
        })?;

        if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
            return Err(LoquatError::invalid_parameters(&format!(
                "host reported error: {line}"
            )));
        }

        return Ok(HostResult {
            trace_cycles:    v["trace_cycles"].as_u64().unwrap_or(0),
            prove_ms:        v["prove_ms"].as_f64().unwrap_or(0.0),
            verify_ms:       v["verify_ms"].as_f64().unwrap_or(0.0),
            receipt_bytes:   v["receipt_bytes"].as_u64().unwrap_or(0) as usize,
            loquat_verifies: v["loquat_verifies"].as_u64().unwrap_or(0) as u32,
            hash_calls:      v["hash_calls"].as_u64().unwrap_or(0) as u32,
            merkle_nodes:    v["merkle_nodes"].as_u64().unwrap_or(0) as u32,
        });
    }

    Err(LoquatError::invalid_parameters(
        "zkvm host produced no parseable JSON line in stdout",
    ))
}

// ── Build the zkvm workspace if needed ───────────────────────────────────────

fn resolve_host_bin(cfg: &ZkvmConfig) -> LoquatResult<String> {
    if Path::new(&cfg.host_bin).is_file() {
        return Ok(cfg.host_bin.clone());
    }

    eprintln!(
        "[B6] host binary not found at '{}', building zkvm workspace ...",
        cfg.host_bin
    );

    let status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&cfg.workspace_dir)
        .status()
        .map_err(|e| {
            LoquatError::invalid_parameters(&format!(
                "failed to run `cargo build` in {}: {e}",
                cfg.workspace_dir
            ))
        })?;

    if !status.success() {
        return Err(LoquatError::invalid_parameters(&format!(
            "`cargo build --release` failed in {}",
            cfg.workspace_dir
        )));
    }

    if !Path::new(&cfg.host_bin).is_file() {
        return Err(LoquatError::invalid_parameters(&format!(
            "build succeeded but host binary still not found at '{}'",
            cfg.host_bin
        )));
    }

    Ok(cfg.host_bin.clone())
}
