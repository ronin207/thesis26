//! Benchmark harness infrastructure for vc-pqc.
//!
//! # Structure
//!
//! - [`suites`] — engineering benchmark suites (one module per `B`-suite).
//! - [`scenarios`] — thesis protocol scenarios (PP2, PP3) with shared
//!   D-metric runners that the suites and CLI binaries reuse.
//! - [`instrument`] — `PhaseTimer` for span-level timing.
//! - [`metrics`] — D1 / D2 / D3 metric types used by scenarios.
//!
//! # Usage
//!
//! Normally invoked via `cargo run --release --bin bench_runner`. All
//! state passes through [`BenchConfig`] + [`BenchWriter`].

pub mod instrument;
pub mod metrics;
pub mod scenarios;
pub mod suites;

// Re-export each suite at the bench:: namespace so existing callers like
// `crate::bench::griffin::run_griffin` keep resolving.
pub use suites::{
    aurora_rerun, backend, circuit_scale, griffin, noir, pp3_policy, r1cs_compare, zkvm,
};

// Re-export scenarios' runner functions and types at the `bench::` root
// for backwards compatibility with callers that imported via the old
// `crate::evaluation::*` paths.
pub use instrument::{PhaseSpan, PhaseTimer};
pub use metrics::{D1ChurnEntry, D2CostMetrics, D3PrivacyResult};
pub use scenarios::pp2::{
    Pp2AuroraBenchmarkResult, Pp2AuroraRunConfig, run_pp2_aurora_cli, run_pp2_aurora_single,
    run_pp2_aurora_single_opts, run_pp2_aurora_with_security, run_pp2_constraint_count_single,
};
pub use scenarios::pp3::{
    PolicyInput, PolicyPredicate, Pp3AuroraBenchmarkResult, default_pp3_policies,
    evaluate_policy_input, parse_attribute_map, pp3_policy_only_d1_churn_rows,
    run_pp3_aurora_single, run_pp3_aurora_single_opts, run_pp3_aurora_with_security,
    run_pp3_constraint_count_single, run_pp3_default_policy_comparison,
};

use crate::LoquatError;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write as IoWrite};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level benchmark configuration, loaded from `bench_config.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BenchConfig {
    #[serde(default)]
    pub runner: RunnerConfig,
    #[serde(default)]
    pub noir: NoirConfig,
    #[serde(default)]
    pub r1cs_compare: R1csCompareConfig,
    #[serde(default)]
    pub circuit_scale: CircuitScaleConfig,
    #[serde(default)]
    pub backend: BackendConfig,
    #[serde(default)]
    pub griffin: GriffinConfig,
    #[serde(default)]
    pub zkvm: ZkvmConfig,
    #[serde(default)]
    pub aurora_rerun: AuroraRerunConfig,
    #[serde(default)]
    pub pp3_policy: Pp3PolicyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunnerConfig {
    pub runs: usize,
    pub warmup: usize,
    pub output: String,
    pub suites: Vec<String>,
    pub dry_run: bool,
    pub resume: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            runs: 10,
            warmup: 2,
            output: "results/bench_{ts}.jsonl".to_string(),
            suites: vec!["aurora-rerun".to_string()],
            dry_run: false,
            resume: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NoirConfig {
    pub package_dir: String,
    pub nargo_bin: String,
    pub opt_levels: Vec<String>,
    pub acir_artifact: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct R1csCompareConfig {
    pub k_values: Vec<usize>,
    pub rev_depth_values: Vec<usize>,
    pub security_level: u32,
    pub run_aurora: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CircuitScaleConfig {
    pub k_values: Vec<usize>,
    pub attr_values: Vec<usize>,
    pub rev_depth_values: Vec<usize>,
    pub policy_configs: Vec<String>,
    pub tier: String,
    pub max_k_for_local_prove: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BackendConfig {
    pub k: usize,
    pub rev_depth: usize,
    pub attr_count: usize,
    pub security_level: u32,
    pub backends: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GriffinConfig {
    pub hash_input_sizes: Vec<usize>,
    pub merkle_depth: usize,
    pub full_k: usize,
    pub full_attr: usize,
    pub full_rev_depth: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ZkvmConfig {
    pub workspace_dir: String,
    pub k_values: Vec<usize>,
    pub s_values: Vec<usize>,
    pub m_values: Vec<usize>,
    pub mode: String,
    pub lr_size: usize,
    pub rev_depth: usize,
    pub host_bin: String,
    /// Per-invocation wall-clock timeout in seconds (0 = no limit).  Defaults to 600.
    #[serde(default = "default_zkvm_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum number of retry attempts on transient (non-zero exit) failures.  Defaults to 1.
    #[serde(default = "default_zkvm_max_retries")]
    pub max_retries: usize,
    /// Bonsai API key.  Read from `BONSAI_API_KEY` env var if not set here.
    #[serde(default)]
    pub bonsai_api_key: String,
    /// Bonsai API endpoint URL.  Read from `BONSAI_API_URL` env var if not set here.
    #[serde(default)]
    pub bonsai_api_url: String,
}

fn default_zkvm_timeout_secs() -> u64 { 600 }
fn default_zkvm_max_retries() -> usize { 1 }

/// B9 — PP3 Policy timing (prove/verify per policy at a fixed pivot).
/// See `bench::pp3_policy` for the runner. The degree_set / gpa_min values
/// are taken from the `[pp3_policy]` TOML section; default via `Default`
/// yields an empty degree set and gpa_min=0 which, if you forget to fill in
/// the config, still produces valid (but trivial) measurements.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Pp3PolicyConfig {
    pub k: usize,
    pub lr_size: usize,
    pub rev_depth: usize,
    pub gpa_min: i64,
    pub degree_set: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuroraRerunConfig {
    pub pp2_k: usize,
    pub pp2_lr_size: usize,
    pub pp2_rev_depth: usize,
    pub pp3_k: usize,
    pub pp3_lr_size: usize,
    pub pp3_rev_depth: usize,
    pub pp3_policy_gpa_min: i64,
    pub pp3_policy_degree_set: Vec<String>,
    pub run_combined: bool,
    pub combined_k: usize,
    pub combined_policy_gpa_min: i64,
    pub combined_policy_degree_set: Vec<String>,
    pub tiny: bool,
    /// Security-level sweep (Loquat paper parameter sets: 80, 100, 128).
    /// Each listed level is run independently through PP2 + PP3. If empty,
    /// defaults to `[128]` (single-point, published-baseline behaviour).
    #[serde(default = "default_aurora_security_levels")]
    pub security_levels: Vec<usize>,
}

fn default_aurora_security_levels() -> Vec<usize> {
    vec![128]
}

impl BenchConfig {
    /// Load from a TOML file, falling back to defaults on parse error.
    pub fn load(path: &str) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|src| toml::from_str(&src).ok())
            .unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record types (JSONL schema)
// ─────────────────────────────────────────────────────────────────────────────

/// Written once at the start of each output file.
#[derive(Debug, Serialize)]
pub struct HeaderRecord {
    pub r#type: &'static str,
    pub timestamp: String,
    pub hostname: String,
    pub cpu: String,
    pub os: String,
    pub rustc: String,
    pub git_commit: String,
    pub bench_runner_version: &'static str,
}

impl HeaderRecord {
    pub fn collect() -> Self {
        Self {
            r#type: "header",
            timestamp: chrono_now(),
            hostname: hostname(),
            cpu: cpu_model(),
            os: os_version(),
            rustc: rustc_version(),
            git_commit: git_commit(),
            bench_runner_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// One measured run of a single configuration.
#[derive(Debug, Serialize)]
pub struct SampleRecord {
    pub r#type: &'static str,
    pub suite: String,
    pub variant: String,
    pub config_key: String,
    pub config: serde_json::Value,
    pub run: usize,
    pub is_warmup: bool,
    pub wall_ms: f64,
    pub phases: serde_json::Value,
    pub metrics: serde_json::Value,
}

/// Aggregated statistics for one (suite, variant, config_key, metric) quadruple.
#[derive(Debug, Serialize)]
pub struct SummaryRecord {
    pub r#type: &'static str,
    pub suite: String,
    pub variant: String,
    pub config_key: String,
    pub metric: String,
    pub n_total: usize,
    pub n_warmup: usize,
    pub n_measured: usize,
    pub n_after_filter: usize,
    pub outliers_removed: usize,
    pub suspect: bool,
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics engine
// ─────────────────────────────────────────────────────────────────────────────

/// Computed statistics for a slice of measurements.
#[derive(Debug, Clone)]
pub struct RunStats {
    pub n_total: usize,
    pub n_after_filter: usize,
    pub outliers_removed: usize,
    /// More than 40% of samples were removed — requires inspection.
    pub suspect: bool,
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
}

/// Compute [`RunStats`] from a raw sample slice using IQR outlier filtering.
///
/// Samples outside `[Q1 − 1.5·IQR, Q3 + 1.5·IQR]` are excluded from the
/// aggregate statistics but their count is reported.
pub fn compute_stats(raw: &[f64]) -> RunStats {
    if raw.is_empty() {
        return RunStats {
            n_total: 0,
            n_after_filter: 0,
            outliers_removed: 0,
            suspect: true,
            mean: 0.0,
            std_dev: 0.0,
            median: 0.0,
            p95: 0.0,
            min: 0.0,
            max: 0.0,
        };
    }

    let mut sorted = raw.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;
    let lower = q1 - 1.5 * iqr;
    let upper = q3 + 1.5 * iqr;

    let clean: Vec<f64> = sorted
        .iter()
        .copied()
        .filter(|&x| x >= lower && x <= upper)
        .collect();

    let n_clean = clean.len();
    let outliers = n - n_clean;
    let suspect = n_clean < ((n as f64 * 0.6).ceil() as usize);

    let mean = clean.iter().sum::<f64>() / n_clean as f64;
    let variance =
        clean.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n_clean as f64;
    let std_dev = variance.sqrt();
    let median = percentile(&clean, 50.0);
    let p95 = percentile(&clean, 95.0);
    let min = clean[0];
    let max = clean[n_clean - 1];

    RunStats {
        n_total: n,
        n_after_filter: n_clean,
        outliers_removed: outliers,
        suspect,
        mean,
        std_dev,
        median,
        p95,
        min,
        max,
    }
}

/// Linear interpolation percentile (0–100).
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let rank = p / 100.0 * (n - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

// ─────────────────────────────────────────────────────────────────────────────
// Simple wall-clock timer
// ─────────────────────────────────────────────────────────────────────────────

/// Measure the wall-clock time of a closure.
pub fn time_it<F, T>(f: F) -> (T, f64)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    (result, elapsed_ms)
}

/// Run `f` `warmup` times (discarding results) then `runs` times, returning
/// only the measured samples in milliseconds.
pub fn timed_runs<F, T>(warmup: usize, runs: usize, mut f: F) -> (Vec<T>, Vec<f64>)
where
    F: FnMut() -> T,
{
    for _ in 0..warmup {
        let _ = f();
    }
    let mut results = Vec::with_capacity(runs);
    let mut timings = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let result = f();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
        results.push(result);
    }
    (results, timings)
}

// ─────────────────────────────────────────────────────────────────────────────
// JSONL output writer
// ─────────────────────────────────────────────────────────────────────────────

/// Buffered JSONL writer.  Every `emit_*` call serialises one record and writes
/// it as a single line followed by `\n`.
pub struct BenchWriter {
    inner: BufWriter<Box<dyn IoWrite>>,
    pub n_total_written: usize,
    pub suite: String,
}

impl BenchWriter {
    /// Create a writer that appends to `path`, creating parent directories as
    /// needed.  Pass `"-"` to write to stdout.
    pub fn open(path: &str, suite: impl Into<String>) -> std::io::Result<Self> {
        let inner: Box<dyn IoWrite> = if path == "-" {
            Box::new(std::io::stdout())
        } else {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            Box::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            )
        };
        Ok(Self {
            inner: BufWriter::new(inner),
            n_total_written: 0,
            suite: suite.into(),
        })
    }

    fn io_err(e: impl std::fmt::Display) -> LoquatError {
        LoquatError::invalid_parameters(&format!("bench writer I/O error: {e}"))
    }

    /// Emit a header record (call once per file).
    pub fn emit_header(&mut self) -> crate::LoquatResult<()> {
        self.emit_value(&HeaderRecord::collect())
    }

    /// Emit a raw-sample record.
    pub fn emit_sample(&mut self, rec: &SampleRecord) -> crate::LoquatResult<()> {
        self.emit_value(rec)
    }

    /// Emit a summary record.
    pub fn emit_summary(&mut self, rec: &SummaryRecord) -> crate::LoquatResult<()> {
        self.emit_value(rec)
    }

    fn emit_value<S: Serialize>(&mut self, value: &S) -> crate::LoquatResult<()> {
        let line = serde_json::to_string(value).map_err(Self::io_err)?;
        self.inner.write_all(line.as_bytes()).map_err(Self::io_err)?;
        self.inner.write_all(b"\n").map_err(Self::io_err)?;
        self.n_total_written += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> crate::LoquatResult<()> {
        self.inner.flush().map_err(Self::io_err)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BenchSuite {
    AuroraRerun,
    Backend,
    CircuitScale,
    Griffin,
    Noir,
    Pp3Policy,
    R1csCompare,
    Zkvm,
}

impl BenchSuite {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "aurora-rerun"  => Some(Self::AuroraRerun),
            "backend"       => Some(Self::Backend),
            "circuit-scale" => Some(Self::CircuitScale),
            "griffin"       => Some(Self::Griffin),
            "noir"          => Some(Self::Noir),
            "pp3-policy"    => Some(Self::Pp3Policy),
            "r1cs-compare"  => Some(Self::R1csCompare),
            "zkvm"          => Some(Self::Zkvm),
            _ => None,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::AuroraRerun,
            Self::Backend,
            Self::CircuitScale,
            Self::Griffin,
            Self::Noir,
            Self::Pp3Policy,
            Self::R1csCompare,
            Self::Zkvm,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AuroraRerun  => "aurora-rerun",
            Self::Backend      => "backend",
            Self::CircuitScale => "circuit-scale",
            Self::Griffin      => "griffin",
            Self::Noir         => "noir",
            Self::Pp3Policy    => "pp3-policy",
            Self::R1csCompare  => "r1cs-compare",
            Self::Zkvm         => "zkvm",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Environment / system info helpers
// ─────────────────────────────────────────────────────────────────────────────

fn chrono_now() -> String {
    // Use a simple timestamp without the chrono crate dependency.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    format!("{secs}")
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn cpu_model() -> String {
    // macOS
    std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // Linux fallback
        .or_else(|| {
            std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn os_version() -> String {
    std::process::Command::new("uname")
        .args(["-sr"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: emit summaries from a vec of (metric_name, samples) pairs
// ─────────────────────────────────────────────────────────────────────────────

/// Build and emit [`SummaryRecord`]s for every `(metric, samples)` pair.
pub fn emit_summaries(
    writer: &mut BenchWriter,
    suite: &str,
    variant: &str,
    config_key: &str,
    n_warmup: usize,
    metrics: &[(&str, Vec<f64>)],
) -> crate::LoquatResult<()> {
    for (metric, samples) in metrics {
        let stats = compute_stats(samples);
        writer.emit_summary(&SummaryRecord {
            r#type: "summary",
            suite: suite.to_string(),
            variant: variant.to_string(),
            config_key: config_key.to_string(),
            metric: metric.to_string(),
            n_total: stats.n_total + n_warmup,
            n_warmup,
            n_measured: stats.n_total,
            n_after_filter: stats.n_after_filter,
            outliers_removed: stats.outliers_removed,
            suspect: stats.suspect,
            mean: stats.mean,
            std_dev: stats.std_dev,
            median: stats.median,
            p95: stats.p95,
            min: stats.min,
            max: stats.max,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_basic() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let s = compute_stats(&samples);
        assert_eq!(s.n_total, 10);
        assert!((s.mean - 5.5).abs() < 1e-9);
        assert!((s.median - 5.5).abs() < 0.5);
    }

    #[test]
    fn stats_outlier_removed() {
        // 9 normal values + 1 extreme outlier
        let mut samples = vec![100.0_f64; 9];
        samples.push(10000.0);
        let s = compute_stats(&samples);
        assert_eq!(s.outliers_removed, 1);
        assert!((s.mean - 100.0).abs() < 1e-6);
    }

    #[test]
    fn stats_empty() {
        let s = compute_stats(&[]);
        assert!(s.suspect);
        assert_eq!(s.n_total, 0);
    }

    #[test]
    fn percentile_single() {
        assert_eq!(percentile(&[42.0], 50.0), 42.0);
    }
}
