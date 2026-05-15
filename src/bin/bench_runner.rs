//! Unified benchmark runner for vc-pqc.
//!
//! # Quick start
//!
//! ```bash
//! # Run priority-1 suite (Aurora statistical re-run) — ~3 hours
//! cargo run --release --bin bench_runner -- --suite aurora-rerun
//!
//! # Run zkVM cycle-count sweep in dev mode — ~1 hour
//! cargo run --release --bin bench_runner -- --suite zkvm
//!
//! # Run everything overnight
//! cargo run --release --bin bench_runner -- --suite all --output results/bench_full.jsonl
//!
//! # Dry run — list all configurations without executing
//! cargo run --release --bin bench_runner -- --dry-run --suite all
//!
//! # Faster CI run with test-size params
//! cargo run --release --bin bench_runner -- --suite aurora-rerun --runs 3 --warmup 1 --tiny
//! ```
//!
//! # Output
//!
//! JSONL to the path in `bench_config.toml` (`[runner].output`) or `--output`.
//! Each file starts with a `{"type":"header",...}` record, followed by
//! `{"type":"sample",...}` and `{"type":"summary",...}` records.
//!
//! # Configuration
//!
//! Reads `bench_config.toml` in the current directory by default.
//! Use `--config <path>` to override.

use std::time::Instant;

use vc_pqc::bench::{
    AuroraRerunConfig, BackendConfig, BenchConfig, BenchSuite, BenchWriter, CircuitScaleConfig,
    GriffinConfig, NoirConfig, R1csCompareConfig, RunnerConfig, ZkvmConfig,
    aurora_rerun, backend, circuit_scale, griffin, noir, pp3_policy, r1cs_compare, zkvm,
};

fn main() {
    // Initialise tracing so library-level logs appear.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "warn".to_string()),
        )
        .init();

    if let Err(e) = run() {
        eprintln!("[bench_runner] fatal error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_args();

    if cli.help {
        print_help();
        return Ok(());
    }

    // ── Load config ───────────────────────────────────────────────────────────
    let mut config = BenchConfig::load(&cli.config_path);

    // CLI overrides.
    apply_cli_overrides(&mut config, &cli);

    // Resolve suites.
    let suites = resolve_suites(&cli, &config.runner);
    if suites.is_empty() {
        eprintln!("[bench_runner] no suites selected. Use --suite <name> or set [runner].suites in bench_config.toml");
        return Ok(());
    }

    // ── Resolve output path ───────────────────────────────────────────────────
    let ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    };
    let output_path = config.runner.output.replace("{ts}", &ts);

    if config.runner.dry_run {
        print_dry_run(&suites, &config);
        return Ok(());
    }

    // ── Open output file ──────────────────────────────────────────────────────
    let mut writer = BenchWriter::open(&output_path, "bench_runner")?;
    writer.emit_header()?;

    eprintln!(
        "[bench_runner] starting {} suite(s) → {}",
        suites.len(),
        output_path
    );
    let total_start = Instant::now();

    // ── Dispatch ──────────────────────────────────────────────────────────────
    for suite in &suites {
        let suite_start = Instant::now();
        eprintln!("[bench_runner] ── suite: {} ──", suite.name());

        let result = match suite {
            BenchSuite::AuroraRerun => aurora_rerun::run(
                &config.runner,
                &config.aurora_rerun,
                &mut writer,
            ),
            BenchSuite::Backend => backend::run(
                &config.runner,
                &config.backend,
                &mut writer,
            ),
            BenchSuite::CircuitScale => circuit_scale::run(
                &config.runner,
                &config.circuit_scale,
                &mut writer,
            ),
            BenchSuite::Griffin => griffin::run(
                &config.runner,
                &config.griffin,
                &mut writer,
            ),
            BenchSuite::Noir => noir::run(
                &config.runner,
                &config.noir,
                &mut writer,
            ),
            BenchSuite::Pp3Policy => pp3_policy::run(
                &config.runner,
                &config.pp3_policy,
                &mut writer,
            ),
            BenchSuite::R1csCompare => r1cs_compare::run(
                &config.runner,
                &config.r1cs_compare,
                &mut writer,
            ),
            BenchSuite::Zkvm => zkvm::run(
                &config.runner,
                &config.zkvm,
                &mut writer,
            ),
        };

        let elapsed = suite_start.elapsed().as_secs_f64();
        match result {
            Ok(()) => eprintln!(
                "[bench_runner] suite {} done in {:.1}s",
                suite.name(),
                elapsed
            ),
            Err(e) => eprintln!(
                "[bench_runner] suite {} FAILED after {:.1}s: {e}",
                suite.name(),
                elapsed
            ),
        }
    }

    let total_elapsed = total_start.elapsed().as_secs_f64();
    eprintln!(
        "[bench_runner] all suites done in {:.1}s ({} JSONL records written) → {}",
        total_elapsed,
        writer.n_total_written,
        output_path
    );

    Ok(())
}

// ── CLI ───────────────────────────────────────────────────────────────────────

struct CliArgs {
    help: bool,
    config_path: String,
    suites: Vec<String>,
    output: Option<String>,
    runs: Option<usize>,
    warmup: Option<usize>,
    dry_run: bool,
    tiny: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut cli = CliArgs {
        help: false,
        config_path: "bench_config.toml".to_string(),
        suites: Vec::new(),
        output: None,
        runs: None,
        warmup: None,
        dry_run: false,
        tiny: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => { cli.help = true; i += 1; }
            "--dry-run" => { cli.dry_run = true; i += 1; }
            "--tiny" => { cli.tiny = true; i += 1; }

            "--config" => {
                if let Some(v) = args.get(i + 1) { cli.config_path = v.clone(); i += 2; } else { i += 1; }
            }
            flag if flag.starts_with("--config=") => {
                cli.config_path = flag["--config=".len()..].to_string(); i += 1;
            }

            "--suite" => {
                if let Some(v) = args.get(i + 1) { cli.suites.push(v.clone()); i += 2; } else { i += 1; }
            }
            flag if flag.starts_with("--suite=") => {
                cli.suites.push(flag["--suite=".len()..].to_string()); i += 1;
            }

            "--output" => {
                if let Some(v) = args.get(i + 1) { cli.output = Some(v.clone()); i += 2; } else { i += 1; }
            }
            flag if flag.starts_with("--output=") => {
                cli.output = Some(flag["--output=".len()..].to_string()); i += 1;
            }

            "--runs" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) { cli.runs = Some(v); i += 2; } else { i += 1; }
            }
            flag if flag.starts_with("--runs=") => {
                cli.runs = flag["--runs=".len()..].parse().ok(); i += 1;
            }

            "--warmup" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse().ok()) { cli.warmup = Some(v); i += 2; } else { i += 1; }
            }
            flag if flag.starts_with("--warmup=") => {
                cli.warmup = flag["--warmup=".len()..].parse().ok(); i += 1;
            }

            _ => { i += 1; }
        }
    }

    cli
}

fn apply_cli_overrides(config: &mut BenchConfig, cli: &CliArgs) {
    if let Some(runs) = cli.runs { config.runner.runs = runs; }
    if let Some(warmup) = cli.warmup { config.runner.warmup = warmup; }
    if let Some(ref output) = cli.output { config.runner.output = output.clone(); }
    if cli.dry_run { config.runner.dry_run = true; }
    if cli.tiny { config.aurora_rerun.tiny = true; }
    if !cli.suites.is_empty() { config.runner.suites = cli.suites.clone(); }
}

fn resolve_suites(cli: &CliArgs, runner: &RunnerConfig) -> Vec<BenchSuite> {
    let names = if !cli.suites.is_empty() {
        cli.suites.clone()
    } else {
        runner.suites.clone()
    };

    let mut out = Vec::new();
    for name in &names {
        if name == "all" {
            return BenchSuite::all();
        }
        match BenchSuite::from_str(name) {
            Some(s) => out.push(s),
            None => eprintln!("[bench_runner] unknown suite '{name}', skipping"),
        }
    }
    out
}

fn print_help() {
    println!("bench_runner — vc-pqc unified benchmark runner

USAGE:
    bench_runner [OPTIONS]

OPTIONS:
    --config <FILE>         Config file (default: bench_config.toml)
    --suite <NAME>          Suite to run (repeatable); 'all' for everything
    --output <FILE>         JSONL output file (overrides config)
    --runs <N>              Measured runs per config (overrides config)
    --warmup <N>            Warm-up runs per config (overrides config)
    --dry-run               List configurations without running
    --tiny                  Use tiny/test params (fast but not thesis-quality)
    --help                  Show this message

SUITES:
    aurora-rerun            B7: statistical re-run of existing Aurora results
    backend                 B4: Aurora vs Fractal backend comparison
    circuit-scale           B3: circuit size scaling analysis
    griffin                 B5: Griffin hash cost breakdown
    noir                    B1: Noir compiler pipeline benchmarks
    r1cs-compare            B2: Noir vs hand-written R1CS comparison
    zkvm                    B6: RISC Zero zkVM parameter sweep
    pp3-policy              B9: prove/verify timing vs policy (none|gpa|gpa_degree)
    all                     All of the above

EXAMPLES:
    # Fastest meaningful run (priority-1, ~3 hours on MacBook)
    bench_runner --suite aurora-rerun

    # zkVM cycle counts in dev mode (~1 hour)
    bench_runner --suite zkvm

    # Quick smoke test (tiny params, all suites)
    bench_runner --suite all --tiny --runs 2 --warmup 1

    # Full overnight run
    bench_runner --suite all --runs 10 --warmup 2

    # View results
    jq 'select(.type==\"summary\")' results/bench_*.jsonl | less
");
}

fn print_dry_run(suites: &[BenchSuite], config: &BenchConfig) {
    println!("=== DRY RUN — configurations that would be executed ===");
    println!("runs={}, warmup={}\n", config.runner.runs, config.runner.warmup);

    for suite in suites {
        println!("── {} ──", suite.name());
        match suite {
            BenchSuite::AuroraRerun => {
                let c = &config.aurora_rerun;
                let levels: Vec<usize> = if c.security_levels.is_empty() {
                    vec![128]
                } else {
                    c.security_levels.clone()
                };
                println!("  security_levels: {:?}  (×{} on each variant below)", levels, levels.len());
                println!("  pp2_aurora: k={}, lr={}, rev_depth={}", c.pp2_k, c.pp2_lr_size, c.pp2_rev_depth);
                println!("  pp3_aurora: k={}, gpa_min={}", c.pp3_k, c.pp3_policy_gpa_min);
                if c.run_combined {
                    println!("  pp2_combined: k={}", c.combined_k);
                }
            }
            BenchSuite::Backend => {
                let c = &config.backend;
                println!("  backends: {:?}", c.backends);
                println!("  k={}, rev_depth={}, m={}", c.k, c.rev_depth, c.attr_count);
            }
            BenchSuite::CircuitScale => {
                let c = &config.circuit_scale;
                let n = c.k_values.len() * c.attr_values.len()
                    * c.rev_depth_values.len() * c.policy_configs.len();
                println!("  {} configs: k={:?}, m={:?}, rev={:?}, policy={:?}",
                    n, c.k_values, c.attr_values, c.rev_depth_values, c.policy_configs);
                println!("  tier={}", c.tier);
            }
            BenchSuite::Griffin => {
                let c = &config.griffin;
                println!("  griffin-only sizes: {:?}", c.hash_input_sizes);
                println!("  merkle depth={}", c.merkle_depth);
                println!("  full credential: k={}, m={}, rev_depth={}",
                    c.full_k, c.full_attr, c.full_rev_depth);
            }
            BenchSuite::Noir => {
                let c = &config.noir;
                println!("  package: {}", c.package_dir);
                println!("  opt levels: {:?}", c.opt_levels);
            }
            BenchSuite::Pp3Policy => {
                let c = &config.pp3_policy;
                println!("  pivot: k={}, lr={}, rev_depth={}", c.k, c.lr_size, c.rev_depth);
                println!("  3 configs: policy ∈ {{none, gpa, gpa_degree}}");
                println!("  gpa_min={}, degree_set={:?}", c.gpa_min, c.degree_set);
            }
            BenchSuite::R1csCompare => {
                let c = &config.r1cs_compare;
                let n = c.k_values.len() * c.rev_depth_values.len();
                println!("  {} configs: k={:?}, rev_depth={:?}", n, c.k_values, c.rev_depth_values);
                println!("  run_aurora={}", c.run_aurora);
            }
            BenchSuite::Zkvm => {
                let c = &config.zkvm;
                let combos: usize = c.k_values.len() * c.s_values.len() * c.m_values.len();
                println!("  ~{} combos: k={:?}, s={:?}, m={:?}",
                    combos, c.k_values, c.s_values, c.m_values);
                println!("  mode={}", c.mode);
            }
        }
        println!();
    }
}
