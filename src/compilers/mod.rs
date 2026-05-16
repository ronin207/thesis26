//! Rust-side adapters for circuits produced by external compilers.
//!
//! Each submodule parses a compiler's intermediate representation and
//! lowers it to R1CS that vc-pqc's Aurora prover can consume. Mirrors
//! the layout of `platforms/compilers/<name>/` where the source circuits
//! (e.g. `*.nr` for Noir) live.

pub mod noir;
