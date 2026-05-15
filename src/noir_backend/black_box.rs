use crate::loquat::errors::{LoquatError, LoquatResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoirBlackBoxOp {
    Range,
    LoquatVerify,
    GriffinHash,
    MerkleNonMember,
}

impl NoirBlackBoxOp {
    pub fn from_name(name: &str) -> Option<Self> {
        let normalized = name.to_ascii_lowercase();
        match normalized.as_str() {
            "range" => Some(Self::Range),
            "loquat_verify" => Some(Self::LoquatVerify),
            "griffin_hash" => Some(Self::GriffinHash),
            "merkle_non_member" => Some(Self::MerkleNonMember),
            _ => None,
        }
    }
}

pub fn ensure_supported_black_box(name: &str) -> LoquatResult<NoirBlackBoxOp> {
    NoirBlackBoxOp::from_name(name).ok_or_else(|| {
        LoquatError::invalid_parameters(&format!(
            "unsupported Noir black box `{name}` for ACIR->R1CS conversion"
        ))
    })
}
