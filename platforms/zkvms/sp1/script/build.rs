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

    fn canonical(dir: &str) -> PathBuf {
        let p = Path::new(dir).join("plum_verify");
        p.canonicalize().unwrap_or(p)
    }
    println!(
        "cargo:rustc-env=PLUM_VERIFY_SYSCALL_ELF_PATH={}",
        canonical(syscall_dir).display(),
    );
    println!(
        "cargo:rustc-env=PLUM_VERIFY_EMULATED_ELF_PATH={}",
        canonical(emulated_dir).display(),
    );
}
