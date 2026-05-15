use vc_pqc::{
    PolicyInput, PolicyPredicate, run_pp3_aurora_single_opts, run_pp3_default_policy_comparison,
};

#[derive(Debug, Clone)]
struct RunConfig {
    k: usize,
    tiny: bool,
    lr_size: usize,
    revocation_depth: usize,
    json_output: bool,
    exec_only: bool,
    warmup_rounds: usize,
    single_policy: Option<PolicyInput>,
}

fn parse_run_config() -> Result<RunConfig, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut k = 1usize;
    let tiny = args.iter().any(|a| a == "--tiny" || a == "--test-params");
    let json_output = args.iter().any(|a| a == "--json" || a == "--jsonl");
    let exec_only = args.iter().any(|a| a == "--exec-only");
    let mut lr_size = 0usize;
    let mut revocation_depth = 20usize;
    let mut warmup_rounds = 0usize;
    let mut gpa_min: Option<i64> = None;
    let mut degree_set: Option<Vec<String>> = None;

    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--k" => {
                k = args
                    .get(idx + 1)
                    .ok_or("missing value after --k")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --k")?;
                idx += 2;
            }
            flag if flag.starts_with("--k=") => {
                k = flag
                    .split_once('=')
                    .ok_or("invalid --k")?
                    .1
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --k")?;
                idx += 1;
            }
            "--lr-size" => {
                lr_size = args
                    .get(idx + 1)
                    .ok_or("missing value after --lr-size")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --lr-size")?;
                idx += 2;
            }
            flag if flag.starts_with("--lr-size=") => {
                lr_size = flag
                    .split_once('=')
                    .ok_or("invalid --lr-size")?
                    .1
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --lr-size")?;
                idx += 1;
            }
            "--rev-depth" => {
                revocation_depth = args
                    .get(idx + 1)
                    .ok_or("missing value after --rev-depth")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --rev-depth")?;
                idx += 2;
            }
            flag if flag.starts_with("--rev-depth=") => {
                revocation_depth = flag
                    .split_once('=')
                    .ok_or("invalid --rev-depth")?
                    .1
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --rev-depth")?;
                idx += 1;
            }
            "--policy-gpa-min" => {
                gpa_min = Some(
                    args.get(idx + 1)
                        .ok_or("missing value after --policy-gpa-min")?
                        .parse::<i64>()
                        .map_err(|_| "invalid integer for --policy-gpa-min")?,
                );
                idx += 2;
            }
            flag if flag.starts_with("--policy-gpa-min=") => {
                gpa_min = Some(
                    flag.split_once('=')
                        .ok_or("invalid --policy-gpa-min")?
                        .1
                        .parse::<i64>()
                        .map_err(|_| "invalid integer for --policy-gpa-min")?,
                );
                idx += 1;
            }
            "--policy-degree-set" => {
                let raw = args
                    .get(idx + 1)
                    .ok_or("missing value after --policy-degree-set")?;
                degree_set = Some(
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                idx += 2;
            }
            flag if flag.starts_with("--policy-degree-set=") => {
                let raw = flag.split_once('=').ok_or("invalid --policy-degree-set")?.1;
                degree_set = Some(
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                idx += 1;
            }
            "--warmup" => {
                warmup_rounds = args
                    .get(idx + 1)
                    .ok_or("missing value after --warmup")?
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --warmup")?;
                idx += 2;
            }
            flag if flag.starts_with("--warmup=") => {
                warmup_rounds = flag
                    .split_once('=')
                    .ok_or("invalid --warmup")?
                    .1
                    .parse::<usize>()
                    .map_err(|_| "invalid integer for --warmup")?;
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    if k == 0 {
        return Err("k must be greater than zero".into());
    }
    if revocation_depth == 0 {
        return Err("revocation depth must be greater than zero".into());
    }

    let single_policy = if gpa_min.is_some() || degree_set.is_some() {
        let mut predicates = Vec::new();
        if let Some(min) = gpa_min {
            predicates.push(PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: min,
            });
        }
        if let Some(set) = degree_set {
            predicates.push(PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: set,
            });
        }
        Some(PolicyInput { predicates })
    } else {
        None
    };

    Ok(RunConfig {
        k,
        tiny,
        lr_size,
        revocation_depth,
        json_output,
        exec_only,
        warmup_rounds,
        single_policy,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_run_config()?;

    // Calibration: warm-up rounds (results discarded)
    if config.warmup_rounds > 0 {
        if !config.json_output {
            eprintln!(
                "Calibration: running {} warm-up round(s)...",
                config.warmup_rounds
            );
        }
        let warmup_policy = config
            .single_policy
            .as_ref()
            .cloned()
            .unwrap_or_else(|| vc_pqc::default_pp3_policies().0);
        for w in 0..config.warmup_rounds {
            if !config.json_output {
                eprint!("  warmup {}/{}... ", w + 1, config.warmup_rounds);
            }
            let _ = run_pp3_aurora_single_opts(
                "warmup",
                config.k,
                config.tiny,
                config.lr_size,
                config.revocation_depth,
                &warmup_policy,
                config.exec_only,
            );
            if !config.json_output {
                eprintln!("done");
            }
        }
    }

    let (results, timers): (Vec<_>, Vec<_>) = if let Some(policy) = &config.single_policy {
        let (r, t) = run_pp3_aurora_single_opts(
            "custom_policy",
            config.k,
            config.tiny,
            config.lr_size,
            config.revocation_depth,
            policy,
            config.exec_only,
        )?;
        (vec![r], vec![t])
    } else {
        // Use the original comparison when not in exec_only mode and no custom policy
        if config.exec_only {
            let (p1, p2) = vc_pqc::default_pp3_policies();
            let (r1, t1) = run_pp3_aurora_single_opts(
                "policy_v1",
                config.k,
                config.tiny,
                config.lr_size,
                config.revocation_depth,
                &p1,
                true,
            )?;
            let (r2, t2) = run_pp3_aurora_single_opts(
                "policy_v2",
                config.k,
                config.tiny,
                config.lr_size,
                config.revocation_depth,
                &p2,
                true,
            )?;
            (vec![r1, r2], vec![t1, t2])
        } else {
            let rs = run_pp3_default_policy_comparison(
                config.k,
                config.tiny,
                config.lr_size,
                config.revocation_depth,
            )?;
            let empty_timers: Vec<vc_pqc::PhaseTimer> =
                rs.iter().map(|_| vc_pqc::PhaseTimer::new()).collect();
            (rs, empty_timers)
        }
    };

    if config.json_output {
        for (row, timer) in results.iter().zip(timers.iter()) {
            println!(
                "{{\"status\":\"ok\",\"label\":\"{}\",\"k\":{},\"lr_size\":{},\"revocation_depth\":{},\"exec_only\":{},\"constraint_count\":{},\"t_I_s\":{:.6},\"t_P_s\":{:.6},\"t_V_s\":{:.6},\"instance_rebuild_s\":{:.6},\"proof_verify_s\":{:.6},\"proof_bytes\":{},\"signature_bytes\":{},\"phases\":{}}}",
                row.label,
                row.k,
                row.lr_size,
                row.revocation_depth,
                config.exec_only,
                row.d2.constraint_count,
                row.d2.indexer_s,
                row.d2.prove_s,
                row.d2.verify_s,
                row.d2.instance_rebuild_s,
                row.d2.proof_verify_s,
                row.d2.proof_bytes,
                row.d2.signature_bytes,
                timer.to_json(),
            );
        }
    } else {
        println!("=== BDEC PP3 Benchmark (Aurora policy-bound) ===");
        if config.exec_only {
            println!("  [exec-only mode: SNARK proof/verify skipped]");
        }
        println!(
            "{:>12} | {:>4} | {:>12} | {:>12} | {:>12} | {:>12}",
            "label", "k", "t_I (s)", "t_P (s)", "t_V (s)", "|epsilon| (KB)"
        );
        println!(
            "{:-<12}-+-{:-<4}-+-{:-<12}-+-{:-<12}-+-{:-<12}-+-{:-<12}",
            "", "", "", "", "", ""
        );
        for (row, timer) in results.iter().zip(timers.iter()) {
            println!(
                "{:>12} | {:>4} | {:>12.3} | {:>12.3} | {:>12.3} | {:>12.2}",
                row.label,
                row.k,
                row.d2.indexer_s,
                row.d2.prove_s,
                row.d2.verify_s,
                row.d2.proof_bytes as f64 / 1024.0,
            );
            if !timer.spans().is_empty() {
                timer.print_summary();
            }
        }
    }

    Ok(())
}
