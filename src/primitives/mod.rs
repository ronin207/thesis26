//! Cryptographic primitives grouped by category.
//!
//! Each subdirectory holds one or more concrete instantiations of a
//! primitive. Files are labelled by their scheme (`*_loquat` / `*_plum`
//! / `p127` / `p192`) when more than one variant exists.

pub mod fft;
pub mod field;
pub mod hash;
pub mod merkle;
pub mod prf;
#[cfg(feature = "std")]
pub mod r1cs;
