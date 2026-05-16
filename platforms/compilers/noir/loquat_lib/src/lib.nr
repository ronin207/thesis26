global LOQUAT_SIG_SIZE: u32 = 512;
global LOQUAT_PK_WORDS: u32 = 64;

pub struct LoquatSignature {
    data: [u8; LOQUAT_SIG_SIZE],
}

pub struct LoquatPublicKey {
    elements: [Field; LOQUAT_PK_WORDS],
}

pub fn loquat_verify(
    _message: [u8; 32],
    _signature: LoquatSignature,
    _public_key: LoquatPublicKey,
) -> bool {
    // Placeholder for host-side black-box integration.
    // The real implementation is enforced in the Rust ACIR -> R1CS pipeline.
    true
}

pub fn griffin_hash<let N: u32>(_input: [u8; N]) -> [u8; 32] {
    [0; 32]
}

pub fn merkle_non_member<let D: u32>(
    _public_key: LoquatPublicKey,
    _root: [u8; 32],
    _auth_path: [[u8; 32]; D],
) -> bool {
    true
}
