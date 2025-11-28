fn main() {
    let has_std = std::env::var("CARGO_FEATURE_STD").is_ok();
    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !has_std || target.contains("riscv32im-risc0-zkvm-elf") || target_os == "zkvm" {
        return;
    }
    println!("cargo:rerun-if-changed=libiop/CMakeLists.txt");
    println!("cargo:rerun-if-changed=libiop/libiop");

    let mut cfg = cmake::Config::new("libiop");
    cfg.profile("RelWithDebInfo");
    cfg.define("BUILD_TESTING", "OFF");
    cfg.define("CMAKE_POSITION_INDEPENDENT_CODE", "ON");
    cfg.build_target("libiop_c_api");
    let dst = cfg.build();

    let lib_dir = dst.join("build/libiop");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=libiop_c_api");

    if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
    }
}
