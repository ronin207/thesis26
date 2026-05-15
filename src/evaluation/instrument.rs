//! Lightweight phase-level instrumentation for benchmark runs.
//!
//! Wrap each logical phase (setup, keygen, prove, verify, …) in
//! [`PhaseTimer::start`] / [`PhaseTimer::stop`] calls.  The timer collects
//! named spans that can be printed, serialised to JSON, or fed into
//! `D2CostMetrics`.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// A single recorded phase span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseSpan {
    pub name: String,
    pub duration: Duration,
}

impl PhaseSpan {
    pub fn as_secs_f64(&self) -> f64 {
        self.duration.as_secs_f64()
    }

    pub fn as_millis_f64(&self) -> f64 {
        self.duration.as_secs_f64() * 1000.0
    }
}

/// Accumulates named timing spans for a single benchmark invocation.
#[derive(Debug, Clone, Default)]
pub struct PhaseTimer {
    spans: Vec<PhaseSpan>,
    open: Option<(String, Instant)>,
}

impl PhaseTimer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin timing a named phase.  Panics if a phase is already open.
    pub fn start(&mut self, name: &str) {
        assert!(
            self.open.is_none(),
            "PhaseTimer: cannot start '{}' while '{}' is still open",
            name,
            self.open.as_ref().unwrap().0,
        );
        self.open = Some((name.to_string(), Instant::now()));
    }

    /// Stop the currently open phase and record its duration.
    pub fn stop(&mut self) -> Duration {
        let (name, started) = self
            .open
            .take()
            .expect("PhaseTimer::stop called with no open phase");
        let duration = started.elapsed();
        self.spans.push(PhaseSpan {
            name,
            duration,
        });
        duration
    }

    /// Time a closure as a named phase and return its result.
    pub fn time<F, T>(&mut self, name: &str, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.start(name);
        let result = f();
        self.stop();
        result
    }

    /// Return all recorded spans.
    pub fn spans(&self) -> &[PhaseSpan] {
        &self.spans
    }

    /// Look up a span by name (first match).
    pub fn get(&self, name: &str) -> Option<&PhaseSpan> {
        self.spans.iter().find(|s| s.name == name)
    }

    /// Total wall-clock time across all recorded phases.
    pub fn total(&self) -> Duration {
        self.spans.iter().map(|s| s.duration).sum()
    }

    /// Emit a human-readable summary to stderr.
    pub fn print_summary(&self) {
        eprintln!("--- phase timing ---");
        for span in &self.spans {
            eprintln!("  {:<24} {:.6} s", span.name, span.as_secs_f64());
        }
        eprintln!("  {:<24} {:.6} s", "TOTAL", self.total().as_secs_f64());
    }

    /// Serialise spans as a JSON array string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.spans).unwrap_or_else(|_| "[]".to_string())
    }
}

impl std::fmt::Display for PhaseTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for span in &self.spans {
            writeln!(f, "{:<24} {:.6} s", span.name, span.as_secs_f64())?;
        }
        write!(f, "{:<24} {:.6} s", "TOTAL", self.total().as_secs_f64())
    }
}
