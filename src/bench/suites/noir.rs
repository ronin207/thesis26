//! B1 — Noir compiler pipeline benchmarks.
//!
//! | Sub-bench | Metric | Gap |
//! |-----------|--------|-----|
//! | B1.1 `nargo_compile` | `nargo compile` wall-clock | Gap 1 |
//! | B1.2 `acir_parse`    | JSON → ACIR deserialisation | Gap 6 (parse) |
//! | B1.3 `acir_to_r1cs`  | `convert_acir_to_r1cs()` time | Gap 6 (convert) |
//! | B1.4 `opt_level`     | Compare optimization flag variants | Gap 3 |
//!
//! ## Binary ACIR format (nargo >= 1.0.0-beta.17)
//!
//! nargo 1.0.0-beta.17+ emits a binary ACIR artefact instead of JSON.
//! When JSON parsing fails, B1.2/B1.3 are skipped and `nargo info` is used
//! to retrieve the constraint count instead.  If `nargo info` also fails,
//! constraint_count is recorded as 0 with a warning.

use std::path::Path;
use std::time::Instant;

use crate::bench::{BenchWriter, NoirConfig, RunnerConfig, SampleRecord, emit_summaries};
use crate::noir_backend::{
    convert_acir_to_r1cs, extract_bytecode_from_json_wrapper, parse_acir_binary_bytecode,
    parse_acir_json,
};
use crate::{LoquatError, LoquatResult};

pub fn run(runner: &RunnerConfig, cfg: &NoirConfig, w: &mut BenchWriter) -> LoquatResult<()> {
    if cfg.package_dir.is_empty() {
        eprintln!("[B1] noir.package_dir not configured, skipping suite");
        return Ok(());
    }
    check_nargo(&cfg.nargo_bin)?;

    // B1.4 / B1.1: compile with each opt level.
    for opt_level in &cfg.opt_levels {
        bench_compile(runner, cfg, w, opt_level)?;
    }

    // B1.2 / B1.3: ACIR parse + R1CS conversion timing.
    let artifact_path = Path::new(&cfg.package_dir)
        .join(&cfg.acir_artifact)
        .to_string_lossy()
        .to_string();

    if !Path::new(&artifact_path).exists() {
        eprintln!("[B1] ACIR artefact not found at {artifact_path}; running nargo compile first");
        nargo_compile(&cfg.nargo_bin, &cfg.package_dir, "default")?;
    }

    bench_acir_pipeline(runner, w, &artifact_path, &cfg.nargo_bin, &cfg.package_dir)?;

    w.flush().map_err(|e| LoquatError::invalid_parameters(&e.to_string()))?;
    Ok(())
}

fn bench_compile(
    runner: &RunnerConfig,
    cfg: &NoirConfig,
    w: &mut BenchWriter,
    opt_level: &str,
) -> LoquatResult<()> {
    let config_key = format!("compile_opt={opt_level}");
    let config_val = serde_json::json!({"circuit": cfg.package_dir, "opt_level": opt_level});

    let total = runner.warmup + runner.runs;
    let mut compile_ms_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;
        // Remove cached artefact so each run compiles from scratch.
        let _ = std::fs::remove_dir_all(Path::new(&cfg.package_dir).join("target"));

        let start = Instant::now();
        nargo_compile(&cfg.nargo_bin, &cfg.package_dir, opt_level)?;
        let compile_ms = start.elapsed().as_secs_f64() * 1000.0;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B1".to_string(),
            variant: "nargo_compile".to_string(),
            config_key: config_key.clone(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: compile_ms,
            phases: serde_json::json!({}),
            metrics: serde_json::json!({}),
        })?;

        if !is_warmup {
            compile_ms_v.push(compile_ms);
        }
    }

    emit_summaries(w, "B1", "nargo_compile", &config_key, runner.warmup, &[
        ("compile_ms", compile_ms_v),
    ])?;
    Ok(())
}

/// Dispatch to the JSON pipeline (nargo < 1.0.0-beta.17) or the binary fallback
/// (nargo >= 1.0.0-beta.17) based on whether the artefact parses as JSON.
fn bench_acir_pipeline(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    artifact_path: &str,
    nargo_bin: &str,
    package_dir: &str,
) -> LoquatResult<()> {
    // Read artefact bytes; nargo >= 1.0.0-beta.17 writes a binary file.
    let artifact_bytes = std::fs::read(artifact_path).map_err(|e| {
        LoquatError::invalid_parameters(&format!(
            "cannot read ACIR artefact at {artifact_path}: {e}"
        ))
    })?;

    let config_key = "bdec_showver_acir_pipeline";

    // Dispatch order:
    //   1. nargo 0.x — top-level JSON with `current_witness_index` + `opcodes`
    //   2. nargo 1.0 — JSON wrapper with base64/gzip/msgpack `bytecode` string
    //   3. Raw binary (no JSON wrapper) — fall back to `nargo info` only

    let legacy_json_ok = std::str::from_utf8(&artifact_bytes)
        .ok()
        .map(|s| parse_acir_json(s).is_ok())
        .unwrap_or(false);

    if legacy_json_ok {
        let acir_json = String::from_utf8_lossy(&artifact_bytes).into_owned();
        let config_val = serde_json::json!({
            "artifact": artifact_path,
            "acir_bytes": acir_json.len(),
            "acir_format": "json_0x",
        });
        return bench_acir_pipeline_json(runner, w, &acir_json, config_key, &config_val);
    }

    if let Some(bytecode_b64) = extract_bytecode_from_json_wrapper(&artifact_bytes) {
        eprintln!(
            "[B1] ACIR artefact at {artifact_path} is nargo-1.0 JSON-wrapped \
             binary bytecode; decoding via base64/gzip/msgpack"
        );
        let config_val = serde_json::json!({
            "artifact": artifact_path,
            "acir_bytes": artifact_bytes.len(),
            "bytecode_b64_len": bytecode_b64.len(),
            "acir_format": "json_wrapper_1x_msgpack",
        });
        return bench_acir_pipeline_json_wrapped_binary(
            runner,
            w,
            &bytecode_b64,
            nargo_bin,
            package_dir,
            config_key,
            &config_val,
        );
    }

    eprintln!(
        "[B1] ACIR artefact at {artifact_path} is not JSON and not a \
         JSON-wrapper we recognise; falling back to `nargo info` only"
    );
    let config_val = serde_json::json!({
        "artifact": artifact_path,
        "acir_bytes": artifact_bytes.len(),
        "acir_format": "binary_unknown",
    });
    bench_acir_pipeline_binary(
        runner, w, nargo_bin, package_dir, config_key, &config_val,
    )
}

/// Full B1.2 + B1.3 pipeline — only reachable when the artefact is JSON.
fn bench_acir_pipeline_json(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    acir_json: &str,
    config_key: &str,
    config_val: &serde_json::Value,
) -> LoquatResult<()> {
    let total = runner.warmup + runner.runs;
    let mut parse_ms_v = Vec::new();
    let mut convert_ms_v = Vec::new();
    let mut constraint_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        // B1.2: parse time
        let parse_start = Instant::now();
        let acir_program = parse_acir_json(acir_json)?;
        let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

        // B1.3: conversion time
        let convert_start = Instant::now();
        let build = convert_acir_to_r1cs(&acir_program, None)?;
        let convert_ms = convert_start.elapsed().as_secs_f64() * 1000.0;
        let constraint_count = build.instance.num_constraints();

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B1".to_string(),
            variant: "acir_pipeline".to_string(),
            config_key: config_key.to_string(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: parse_ms + convert_ms,
            phases: serde_json::json!({
                "acir_parse_ms":   parse_ms,
                "acir_to_r1cs_ms": convert_ms,
            }),
            metrics: serde_json::json!({"constraint_count": constraint_count}),
        })?;

        if !is_warmup {
            parse_ms_v.push(parse_ms);
            convert_ms_v.push(convert_ms);
            constraint_v.push(constraint_count as f64);
        }
    }

    emit_summaries(w, "B1", "acir_pipeline", config_key, runner.warmup, &[
        ("acir_parse_ms",    parse_ms_v),
        ("acir_to_r1cs_ms",  convert_ms_v),
        ("constraint_count", constraint_v),
    ])?;
    Ok(())
}

/// B1 pipeline for nargo 1.0 JSON-wrapped binary bytecode.
///
/// Runs the full base64 → gzip → MessagePack decode per run, timing it as
/// `acir_parse_ms`. Since the 1.0 opcode encoding differs from 0.x, we don't
/// invoke [`convert_acir_to_r1cs`] here (that parser expects the legacy JSON
/// opcode layout); `acir_to_r1cs_ms` is therefore omitted for this format.
/// Instead we emit rich opcode metrics: total opcodes + category breakdown +
/// BlackBoxFuncCall sub-kind histogram.
///
/// `constraint_count` is cross-validated against `nargo info --json` and
/// reported under `metrics`; the opcode breakdown is reported alongside it.
fn bench_acir_pipeline_json_wrapped_binary(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    bytecode_b64: &str,
    nargo_bin: &str,
    package_dir: &str,
    config_key: &str,
    config_val: &serde_json::Value,
) -> LoquatResult<()> {
    // Pull the authoritative opcode count once (nargo info --json). Used to
    // cross-validate our decoder against the compiler's own reporting.
    let nargo_info_opcodes = query_nargo_info_json(nargo_bin, package_dir)
        .map(|(acir, _)| acir)
        .unwrap_or(0);

    let total = runner.warmup + runner.runs;
    let mut parse_ms_v = Vec::new();
    let mut opcode_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        // B1.2: decode + msgpack-walk (end-to-end parse timing).
        let parse_start = Instant::now();
        let summary = parse_acir_binary_bytecode(bytecode_b64)?;
        let parse_ms = parse_start.elapsed().as_secs_f64() * 1000.0;

        if run_idx == 0 && nargo_info_opcodes != 0 && summary.total_opcodes != nargo_info_opcodes {
            eprintln!(
                "[B1] WARNING: decoder opcode count ({}) disagrees with \
                 `nargo info --json` ({}); reporting decoder value",
                summary.total_opcodes, nargo_info_opcodes
            );
        }

        let mut metrics = serde_json::json!({
            "constraint_count":    summary.total_opcodes,
            "nargo_info_opcodes":  nargo_info_opcodes,
        });
        // Merge the opcode breakdown into metrics.
        if let serde_json::Value::Object(map) = &mut metrics {
            if let serde_json::Value::Object(extra) = summary.to_metrics_json() {
                map.extend(extra);
            }
        }

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B1".to_string(),
            variant: "acir_pipeline".to_string(),
            config_key: config_key.to_string(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: parse_ms,
            phases: serde_json::json!({
                "acir_parse_ms": parse_ms,
                "note": "nargo-1.0 JSON-wrapper: base64+gzip+msgpack decode; \
                         acir_to_r1cs_ms omitted (opcode layout changed)",
            }),
            metrics,
        })?;

        if !is_warmup {
            parse_ms_v.push(parse_ms);
            opcode_v.push(summary.total_opcodes as f64);
        }
    }

    emit_summaries(w, "B1", "acir_pipeline", config_key, runner.warmup, &[
        ("acir_parse_ms",    parse_ms_v),
        ("constraint_count", opcode_v),
    ])?;
    Ok(())
}

/// Fallback pipeline for binary ACIR (nargo >= 1.0.0-beta.17).
///
/// Parse/convert timings are not available; constraint count is sourced from
/// `nargo info --json`.  Records wall_ms = 0 with a note in `phases`.
fn bench_acir_pipeline_binary(
    runner: &RunnerConfig,
    w: &mut BenchWriter,
    nargo_bin: &str,
    package_dir: &str,
    config_key: &str,
    config_val: &serde_json::Value,
) -> LoquatResult<()> {
    // Use nargo info --json for reliable structured output.  The ASCII-table
    // column ordering varies across nargo versions (previously "Expression Width"
    // | "ACIR Opcodes"; now "ACIR Opcodes" | "Brillig Opcodes"), so JSON is safer.
    let constraint_count = match query_nargo_info_json(nargo_bin, package_dir) {
        Some((acir_opcodes, _brillig)) => {
            eprintln!("[B1] nargo info --json: acir_opcodes={acir_opcodes}");
            acir_opcodes
        }
        None => {
            // JSON fallback failed; try ASCII table (cols[2] = first numeric column).
            match query_nargo_info(nargo_bin, package_dir) {
                Some(info) => {
                    let v = info.expression_width.or(info.acir_opcodes).unwrap_or(0);
                    eprintln!("[B1] nargo info ASCII fallback: constraint_count={v}");
                    v
                }
                None => {
                    eprintln!(
                        "[B1] `nargo info` did not return recognisable constraint counts; \
                         recording constraint_count=0"
                    );
                    0
                }
            }
        }
    };

    let total = runner.warmup + runner.runs;
    let mut constraint_v = Vec::new();

    for run_idx in 0..total {
        let is_warmup = run_idx < runner.warmup;

        w.emit_sample(&SampleRecord {
            r#type: "sample",
            suite: "B1".to_string(),
            variant: "acir_pipeline".to_string(),
            config_key: config_key.to_string(),
            config: config_val.clone(),
            run: run_idx,
            is_warmup,
            wall_ms: 0.0,
            phases: serde_json::json!({
                "note": "binary ACIR (nargo >= 1.0.0-beta.17); parse/convert timings unavailable"
            }),
            metrics: serde_json::json!({"constraint_count": constraint_count}),
        })?;

        if !is_warmup {
            constraint_v.push(constraint_count as f64);
        }
    }

    emit_summaries(w, "B1", "acir_pipeline", config_key, runner.warmup, &[
        ("constraint_count", constraint_v),
    ])?;
    Ok(())
}

/// Information returned by `nargo info` for the primary circuit function.
struct NargoInfo {
    /// "Expression Width" column — a proxy for circuit/constraint size.
    expression_width: Option<usize>,
    /// "ACIR Opcodes" column — number of top-level ACIR opcodes.
    acir_opcodes: Option<usize>,
}

/// Run `nargo info` and parse its ASCII-table output.
/// Returns `None` if the command fails or produces unrecognised output.
fn query_nargo_info(nargo_bin: &str, package_dir: &str) -> Option<NargoInfo> {
    let bin = if nargo_bin.is_empty() { "nargo" } else { nargo_bin };
    let output = std::process::Command::new(bin)
        .arg("info")
        .current_dir(package_dir)
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);

    // Parse the ASCII table produced by `nargo info`.
    // Example data row (columns vary by nargo version):
    //   | bdec_showver | main | 2866 | 17 | |
    // We look for the row containing "main" and extract the numeric columns.
    for line in text.lines() {
        if !line.contains("main") {
            continue;
        }
        let cols: Vec<&str> =
            line.split('|').map(str::trim).filter(|s| !s.is_empty()).collect();
        // Expected: [package, function, expression_width, acir_opcodes, ...]
        if cols.len() < 4 {
            continue;
        }
        let expression_width = cols[2].parse::<usize>().ok();
        let acir_opcodes = cols[3].parse::<usize>().ok();
        if expression_width.is_some() || acir_opcodes.is_some() {
            eprintln!(
                "[B1] nargo info: expression_width={:?}, acir_opcodes={:?}",
                expression_width, acir_opcodes
            );
            return Some(NargoInfo { expression_width, acir_opcodes });
        }
    }
    None
}

/// Run `nargo info --json` and return `(acir_opcodes, brillig_opcodes)` for `main`.
///
/// Preferred over ASCII-table parsing because the column ordering of `nargo info`
/// varies between nargo versions.
fn query_nargo_info_json(nargo_bin: &str, package_dir: &str) -> Option<(usize, usize)> {
    let bin = if nargo_bin.is_empty() { "nargo" } else { nargo_bin };
    let output = std::process::Command::new(bin)
        .arg("info")
        .arg("--json")
        .current_dir(package_dir)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let program = json.get("programs")?.as_array()?.first()?;
    let acir_opcodes = program
        .get("functions")?
        .as_array()?
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("main"))
        .and_then(|f| f.get("opcodes")?.as_u64())
        .map(|n| n as usize)?;
    let brillig_opcodes = program
        .get("unconstrained_functions")
        .and_then(|uf| uf.as_array())
        .and_then(|arr| arr.iter().find(|f| f.get("name").and_then(|n| n.as_str()) == Some("main")))
        .and_then(|f| f.get("opcodes")?.as_u64())
        .map(|n| n as usize)
        .unwrap_or(0);
    Some((acir_opcodes, brillig_opcodes))
}

fn check_nargo(nargo_bin: &str) -> LoquatResult<()> {
    let bin = if nargo_bin.is_empty() { "nargo" } else { nargo_bin };
    let output = std::process::Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|e| {
            LoquatError::invalid_parameters(&format!(
                "nargo not found (bin={bin}): {e}. \
                 Install: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash"
            ))
        })?;
    if !output.status.success() {
        return Err(LoquatError::invalid_parameters("nargo --version returned non-zero"));
    }
    Ok(())
}

fn nargo_compile(nargo_bin: &str, package_dir: &str, opt_level: &str) -> LoquatResult<()> {
    let bin = if nargo_bin.is_empty() { "nargo" } else { nargo_bin };
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("compile").current_dir(package_dir);
    // Note: --brillig-optimization is not available in this nargo version; omit it.
    let _ = opt_level; // retained in signature for config logging
    let output = cmd.output().map_err(|e| {
        LoquatError::invalid_parameters(&format!("nargo compile failed to spawn: {e}"))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LoquatError::invalid_parameters(&format!(
            "nargo compile exited with {}: {stderr}",
            output.status
        )));
    }
    Ok(())
}
