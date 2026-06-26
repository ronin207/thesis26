#[cfg(feature = "std")]
pub mod power_residue;

/// Parameterised power-residue PRF *family* demonstration (Loquat t=2 over
/// Fp127 + PLUM t=256 over Fp192). The cheap, tractable axis of the family
/// generalisation; see `family.rs` for scope.
#[cfg(feature = "std")]
pub mod family;
