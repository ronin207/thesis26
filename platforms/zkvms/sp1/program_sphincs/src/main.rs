//! Phase B6.2 stub — SPHINCS+/SLH-DSA guest. Implementation wired in
//! a successive commit; this stub exists so the workspace builds.
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    sp1_zkvm::io::commit(&true);
}
