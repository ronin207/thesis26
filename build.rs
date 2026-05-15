fn main() {
    let has_std = std::env::var("CARGO_FEATURE_STD").is_ok();
    let multicore_feature = std::env::var("CARGO_FEATURE_LIBIOP_MULTICORE").is_ok();
    let multicore_env = std::env::var("VC_PQC_LIBIOP_MULTICORE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let libiop_multicore = multicore_feature || multicore_env;
    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // Opt-out for environments that need only the pure-Rust portions of the
    // crate (e.g. PLUM Fp192 development on machines where libiop's C++
    // build is broken — known issue on Apple Silicon with -msse4.1).
    let skip_libiop = std::env::var("VC_PQC_SKIP_LIBIOP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !has_std
        || target.contains("riscv32im-risc0-zkvm-elf")
        || target_os == "zkvm"
        || skip_libiop
    {
        println!("cargo:rerun-if-env-changed=VC_PQC_SKIP_LIBIOP");
        if skip_libiop {
            // Expose the opt-out as a cfg flag so source modules can drop
            // the FFI bridge when libiop isn't being built.
            println!("cargo:rustc-cfg=vc_pqc_skip_libiop");
        }
        println!("cargo:rustc-check-cfg=cfg(vc_pqc_skip_libiop)");
        return;
    }
    println!("cargo:rustc-check-cfg=cfg(vc_pqc_skip_libiop)");
    println!("cargo:rerun-if-env-changed=VC_PQC_LIBIOP_MULTICORE");
    println!("cargo:rerun-if-env-changed=VC_PQC_LIBIOP_C_COMPILER");
    println!("cargo:rerun-if-env-changed=VC_PQC_LIBIOP_CXX_COMPILER");
    println!("cargo:rerun-if-changed=libiop/CMakeLists.txt");
    println!("cargo:rerun-if-changed=libiop/libiop");
    println!("cargo:rerun-if-changed=libiop/libiop_c_api.cpp");
    println!("cargo:rerun-if-changed=libiop/libiop_c_api.h");
    println!("cargo:rerun-if-changed=libiop/depends/CMakeLists.txt");
    println!("cargo:rerun-if-changed=libiop/depends/libff/libff");
    println!("cargo:rerun-if-changed=libiop/depends/libff/libff/CMakeLists.txt");

    let mut cfg = cmake::Config::new("libiop");
    cfg.profile("RelWithDebInfo");
    // cmake 3.5+ policy compat: libiop's CMakeLists.txt specifies VERSION 3.1 which
    // cmake >= 4.0 no longer supports without this policy override.
    cfg.define("CMAKE_POLICY_VERSION_MINIMUM", "3.5");
    // CURVE=EDWARDS avoids the BN128/ate-pairing dependency (zm uses x86 SSE
    // intrinsics that don't build on arm64).
    cfg.define("CURVE", "EDWARDS");
    // libff defaults USE_ASM=ON which adds -mpclmul/-msse4.1 (x86-only).
    cfg.define("USE_ASM", "OFF");
    cfg.define("BUILD_TESTING", "OFF");
    cfg.define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");
    cfg.define("MULTICORE", if libiop_multicore { "ON" } else { "OFF" });
    // libiop's USE_ASM=ON path appends `-mpclmul -msse4.1` to global CXXFLAGS,
    // which clang rejects on aarch64-apple-darwin (`unsupported option ...
    // for target 'arm64-apple-macosx'`). Disable the ASM path on aarch64.
    //
    // Separately, the CURVE=BN128 path pulls libff's bn128_*.cpp, which link
    // against the `zm` static lib built from `depends/ate-pairing/src/zm.cpp`.
    // ate-pairing is x86-only (uses xbyak JIT and references PairingCode/Data
    // types that don't compile on arm64). Selecting CURVE=EDWARDS matches the
    // historical CMakeCache that built successfully on this machine and avoids
    // the dependency entirely. The C API stub does not exercise pairings, so
    // the curve choice is compile-only.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64") {
        cfg.define("USE_ASM", "OFF");
        cfg.define("CURVE", "EDWARDS");
    }
    // We only need the C API bridge + core library for the Rust bindings.
    // Skip libiop's benchmark dependency/targets (cuts build time and avoids toolchain issues).
    cfg.define("LIBIOP_BUILD_BENCHMARKS", "OFF");

    // On macOS, AppleClang typically does not support `-fopenmp`. When MULTICORE is enabled,
    // prefer Homebrew LLVM clang/clang++ (which does), or allow the user to override.
    if libiop_multicore && target_os == "macos" {
        if let Ok(cc) = std::env::var("VC_PQC_LIBIOP_C_COMPILER") {
            cfg.define("CMAKE_C_COMPILER", cc);
        }
        if let Ok(cxx) = std::env::var("VC_PQC_LIBIOP_CXX_COMPILER") {
            cfg.define("CMAKE_CXX_COMPILER", cxx);
        }

        if std::env::var("VC_PQC_LIBIOP_C_COMPILER").is_err()
            || std::env::var("VC_PQC_LIBIOP_CXX_COMPILER").is_err()
        {
            let candidates = [
                ("/opt/homebrew/opt/llvm/bin/clang", "/opt/homebrew/opt/llvm/bin/clang++"),
                ("/usr/local/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang++"),
            ];
            for (cc, cxx) in candidates {
                if std::path::Path::new(cc).exists() && std::path::Path::new(cxx).exists() {
                    cfg.define("CMAKE_C_COMPILER", cc);
                    cfg.define("CMAKE_CXX_COMPILER", cxx);
                    println!(
                        "cargo:warning=libiop_multicore enabled: using {} / {} for OpenMP",
                        cc, cxx
                    );
                    break;
                }
            }
        }
    }
    cfg.build_target("libiop_c_api");
    let dst = cfg.build();

    let lib_dir = dst.join("build/libiop");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=libiop_c_api");

    if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }
}
