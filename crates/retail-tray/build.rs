fn main() {
    // Windows loads the DLLs a program imports from the program's own folder
    // first: for an installer run from Downloads, a planted DLL would run as
    // administrator. System32 only (Windows 10 1607 and later).
    let target = |k: &str| std::env::var(k).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") == "windows" && target("CARGO_CFG_TARGET_ENV") == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
