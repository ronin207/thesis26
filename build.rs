fn main() {
    let has_std = std::env::var("CARGO_FEATURE_STD").is_ok();
    let multicore_feature = std::env::var("CARGO_FEATURE_LIBIOP_MULTICORE").is_ok();
    let multicore_env = std::env::var("VC_PQC_LIBIOP_MULTICORE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let libiop_multicore = multicore_feature || multicore_env;
    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !has_std || target.contains("riscv32im-risc0-zkvm-elf") || target_os == "zkvm" {
        return;
    }
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
