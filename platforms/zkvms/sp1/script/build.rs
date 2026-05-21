//! Build BOTH guest ELFs for the Phase 3f A/B measurement.
//!
//! ### The trap we fell into first
//!
//! `sp1_build::build_program_with_args` always writes the compiled
//! ELF to `<target>/elf-compilation/<triple>/release/<bin>`. The
//! `elf_name` / `output_directory` args just COPY the ELF to a
//! custom location after compile. Calling `build_program_with_args`
//! twice with the same bin name (`plum_verify`) thus has the SECOND
//! invocation overwrite the FIRST in `target/elf-compilation`. The
//! standard `include_elf!("plum_verify")` macro reads from THAT
//! location, so both ELFs collapse to whichever build ran last.
//!
//! ### Fix
//!
//! Force-copy each build to its own dedicated directory, emit a
//! `PLUM_VERIFY_*_ELF_PATH` cargo env directive for each, and use
//! `include_bytes!(env!(...))` in the host instead of `include_elf!`.

use std::path::{Path, PathBuf};

use sp1_build::{BuildArgs, build_program_with_args};

fn main() {
    let syscall_dir = "../program/elf-syscall";
    let emulated_dir = "../program/elf-emulated";
    let sha3_dir = "../program/elf-sha3";

    // Syscall arm — Griffin routes through GRIFFIN_FP192_PERMUTE.
    build_program_with_args(
        "../program",
        BuildArgs {
            elf_name: Some("plum_verify".into()),
            output_directory: Some(syscall_dir.into()),
            ..Default::default()
        },
    );

    // Emulated arm — `griffin-emulated` feature pipes through to
    // `vc-pqc/sp1-no-griffin-syscall`, falling back to rv32im.
    build_program_with_args(
        "../program",
        BuildArgs {
            features: vec!["griffin-emulated".into()],
            elf_name: Some("plum_verify".into()),
            output_directory: Some(emulated_dir.into()),
            ..Default::default()
        },
    );

    // Cell 3 arm — `plum-sha3-hasher` feature swaps the PLUM hasher
    // to SHA3-256. Griffin is not invoked on this arm at all (cfg
    // gate in `program/src/main.rs` selects `PlumSha3Hasher as
    // Hasher`).
    build_program_with_args(
        "../program",
        BuildArgs {
            features: vec!["plum-sha3-hasher".into()],
            elf_name: Some("plum_verify".into()),
            output_directory: Some(sha3_dir.into()),
            ..Default::default()
        },
    );

    fn canonical(dir: &str, bin: &str) -> PathBuf {
        let p = Path::new(dir).join(bin);
        p.canonicalize().unwrap_or(p)
    }
    println!(
        "cargo:rustc-env=PLUM_VERIFY_SYSCALL_ELF_PATH={}",
        canonical(syscall_dir, "plum_verify").display(),
    );
    println!(
        "cargo:rustc-env=PLUM_VERIFY_EMULATED_ELF_PATH={}",
        canonical(emulated_dir, "plum_verify").display(),
    );
    println!(
        "cargo:rustc-env=PLUM_VERIFY_SHA3_ELF_PATH={}",
        canonical(sha3_dir, "plum_verify").display(),
    );

    // ─── Griffin Fp192 smoke-prove guest (C4 end-to-end validation) ─
    let smoke_dir = "../program_griffin_smoke/elf-out";
    build_program_with_args(
        "../program_griffin_smoke",
        BuildArgs {
            elf_name: Some("griffin_smoke".into()),
            output_directory: Some(smoke_dir.into()),
            ..Default::default()
        },
    );
    println!(
        "cargo:rustc-env=GRIFFIN_SMOKE_ELF_PATH={}",
        canonical(smoke_dir, "griffin_smoke").display(),
    );

    // ─── Phase B6 PQ-bench guests (classical + 3 PQ schemes) ────────
    //
    // Each guest verifies one signature; the bench_pqc host generates
    // a valid (pk, msg, sig) triple, feeds it via SP1Stdin, and the
    // guest commits a bool. ELFs land in dedicated dirs so the host
    // can include them by path-name without colliding through the
    // shared `target/elf-compilation/...` location.
    let ecdsa_dir = "../program_ecdsa/elf-out";
    build_program_with_args(
        "../program_ecdsa",
        BuildArgs {
            elf_name: Some("ecdsa_verify".into()),
            output_directory: Some(ecdsa_dir.into()),
            ..Default::default()
        },
    );
    println!(
        "cargo:rustc-env=ECDSA_VERIFY_ELF_PATH={}",
        canonical(ecdsa_dir, "ecdsa_verify").display(),
    );
}
