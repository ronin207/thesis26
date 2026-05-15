//! Noir integration entry points.
//!
//! This module provides a minimal ACIR -> R1CS bridge so that Noir-compiled
//! relations can be consumed by the existing Aurora proving pipeline.

pub mod acir_binary;
pub mod acir_parser;
pub mod backend;
pub mod black_box;
pub mod opcode_to_r1cs;

pub use acir_binary::{
    BinaryAcirSummary, extract_bytecode_from_json_wrapper, parse_acir_binary_bytecode,
};
pub use acir_parser::{
    AcirOpcode, AcirProgram, AssertZeroOpcode, BlackBoxFuncCallOpcode, BlackBoxInput, LinTerm,
    MulTerm, parse_acir_json,
};
pub use backend::NoirAuroraBackend;
pub use opcode_to_r1cs::{AcirR1csBuild, compile_acir_json_to_r1cs, convert_acir_to_r1cs};
