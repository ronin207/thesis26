//! Binary ACIR decoder for nargo >= 1.0.0-beta.17.
//!
//! # Artefact format
//!
//! nargo 1.0 emits a JSON wrapper whose `bytecode` field is a string. That
//! string is:
//!
//! ```text
//! base64 → gzip-compressed blob
//!        → 1-byte version prefix (0x03)
//!        → MessagePack-encoded ACIR Program
//! ```
//!
//! We don't try to reconstruct the full [`crate::noir_backend::AcirProgram`]
//! structure (opcode variants differ from the 0.x JSON schema), but we do walk
//! the MessagePack tree and count opcodes by category. That's enough to power
//! B1's timing / opcode-breakdown story.
//!
//! # Output
//!
//! [`BinaryAcirSummary`] reports:
//! - `total_opcodes` — sum across all constrained functions
//! - per-category counts: AssertZero, BlackBoxFuncCall, BrilligCall, MemoryOp,
//!   MemoryInit, Call, other
//! - `blackbox_kinds` — sub-breakdown of BlackBoxFuncCall by kind
//!   (RANGE, SHA256, PedersenCommitment, etc.)

use crate::signatures::loquat::errors::{LoquatError, LoquatResult};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::read::GzDecoder;
use rmpv::Value;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

/// Opcode kinds that identify a MessagePack map as an ACIR opcode (rather
/// than a Brillig VM opcode or some unrelated 1-key map in the tree).
const ACIR_OPCODE_KINDS: &[&str] = &[
    "AssertZero",
    "BlackBoxFuncCall",
    "BrilligCall",
    "MemoryOp",
    "MemoryInit",
    "Call",
];

#[derive(Debug, Clone, Default)]
pub struct BinaryAcirSummary {
    pub total_opcodes: usize,
    pub assert_zero: usize,
    pub blackbox: usize,
    pub brillig_call: usize,
    pub memory_op: usize,
    pub memory_init: usize,
    pub call: usize,
    pub other: usize,
    /// Per-kind breakdown for BlackBoxFuncCall (RANGE, SHA256, ...).
    pub blackbox_kinds: BTreeMap<String, usize>,
    /// Count of distinct constrained functions (Program::functions.len()).
    pub function_count: usize,
    /// Size of the gzip-decompressed MessagePack payload (bytes).
    pub decompressed_bytes: usize,
}

impl BinaryAcirSummary {
    /// Render as a serde_json::Value suitable for embedding in the benchmark
    /// record's `metrics` object.
    pub fn to_metrics_json(&self) -> serde_json::Value {
        let kinds: serde_json::Map<String, serde_json::Value> = self
            .blackbox_kinds
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(v)))
            .collect();
        serde_json::json!({
            "total_opcodes":      self.total_opcodes,
            "assert_zero":        self.assert_zero,
            "blackbox":           self.blackbox,
            "brillig_call":       self.brillig_call,
            "memory_op":          self.memory_op,
            "memory_init":        self.memory_init,
            "call":               self.call,
            "other":              self.other,
            "function_count":     self.function_count,
            "decompressed_bytes": self.decompressed_bytes,
            "blackbox_kinds":     kinds,
        })
    }
}

/// Decode a base64-encoded, gzip-compressed, MessagePack-serialised ACIR
/// program and summarise its opcodes.
///
/// This is the end-to-end B1.2 parse path for nargo 1.0 artefacts; the caller
/// is expected to `Instant::now()` around the call to measure parse time.
pub fn parse_acir_binary_bytecode(bytecode_b64: &str) -> LoquatResult<BinaryAcirSummary> {
    // 1. base64-decode
    let gzipped =
        BASE64
            .decode(bytecode_b64.trim())
            .map_err(|e| LoquatError::SerializationError {
                details: format!("ACIR bytecode base64-decode failed: {e}"),
            })?;

    // 2. gunzip
    let mut decoder = GzDecoder::new(&gzipped[..]);
    let mut raw = Vec::new();
    decoder
        .read_to_end(&mut raw)
        .map_err(|e| LoquatError::SerializationError {
            details: format!("ACIR bytecode gunzip failed: {e}"),
        })?;
    let decompressed_bytes = raw.len();

    // 3. strip 1-byte version prefix (current nargo: 0x03); tolerate its absence
    //    for forward/backward compatibility if future versions drop or change it.
    let payload: &[u8] = if raw.first().copied() == Some(0x03) {
        &raw[1..]
    } else {
        &raw[..]
    };

    // 4. msgpack-deserialise into a generic rmpv::Value tree
    let mut cursor = Cursor::new(payload);
    let root = rmpv::decode::read_value(&mut cursor).map_err(|e| {
        LoquatError::SerializationError {
            details: format!("ACIR MessagePack decode failed: {e}"),
        }
    })?;

    // 5. walk the tree, counting opcodes
    let mut summary = BinaryAcirSummary {
        decompressed_bytes,
        ..Default::default()
    };
    walk_for_opcodes(&root, &mut summary);
    Ok(summary)
}

/// Recursively walk a MessagePack value tree, detecting arrays whose elements
/// are all ACIR opcode-shaped maps. For each such array we bump
/// `function_count` and tally its opcodes.
fn walk_for_opcodes(value: &Value, summary: &mut BinaryAcirSummary) {
    match value {
        Value::Array(arr) => {
            if !arr.is_empty() && arr.iter().all(is_acir_opcode_map) {
                summary.function_count += 1;
                for op in arr {
                    tally_opcode(op, summary);
                }
                // Don't recurse into opcodes — their internals contain nested
                // maps / arrays that would otherwise be double-counted.
            } else {
                for v in arr {
                    walk_for_opcodes(v, summary);
                }
            }
        }
        Value::Map(entries) => {
            for (_k, v) in entries {
                walk_for_opcodes(v, summary);
            }
        }
        _ => {}
    }
}

/// `true` iff `v` is a single-key map whose key is one of [`ACIR_OPCODE_KINDS`].
fn is_acir_opcode_map(v: &Value) -> bool {
    let Value::Map(entries) = v else {
        return false;
    };
    if entries.len() != 1 {
        return false;
    }
    let Value::String(key) = &entries[0].0 else {
        return false;
    };
    let Some(kind) = key.as_str() else {
        return false;
    };
    ACIR_OPCODE_KINDS.contains(&kind)
}

/// Increment the appropriate counter(s) in `summary` for one opcode.
fn tally_opcode(op: &Value, summary: &mut BinaryAcirSummary) {
    let Value::Map(entries) = op else {
        summary.other += 1;
        return;
    };
    if entries.len() != 1 {
        summary.other += 1;
        return;
    }
    let Value::String(key) = &entries[0].0 else {
        summary.other += 1;
        return;
    };
    let Some(kind) = key.as_str() else {
        summary.other += 1;
        return;
    };

    summary.total_opcodes += 1;
    match kind {
        "AssertZero" => summary.assert_zero += 1,
        "BlackBoxFuncCall" => {
            summary.blackbox += 1;
            // Drill one level to tally the black-box kind (RANGE, SHA256, ...).
            if let Value::Map(inner) = &entries[0].1 {
                if inner.len() == 1 {
                    if let Value::String(bk) = &inner[0].0 {
                        if let Some(bkind) = bk.as_str() {
                            *summary
                                .blackbox_kinds
                                .entry(bkind.to_string())
                                .or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        "BrilligCall" => summary.brillig_call += 1,
        "MemoryOp" => summary.memory_op += 1,
        "MemoryInit" => summary.memory_init += 1,
        "Call" => summary.call += 1,
        _ => summary.other += 1,
    }
}

/// If `artifact_bytes` is a nargo 1.0 JSON wrapper (`{"bytecode": "<base64>", ...}`),
/// extract the bytecode string. Otherwise return `None`.
pub fn extract_bytecode_from_json_wrapper(artifact_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(artifact_bytes).ok()?;
    let root: serde_json::Value = serde_json::from_str(text).ok()?;
    let bytecode = root.get("bytecode")?.as_str()?;
    Some(bytecode.to_string())
}
