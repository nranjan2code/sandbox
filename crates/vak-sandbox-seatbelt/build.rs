use std::{env, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=native/supervisor.c");
    println!("cargo:rerun-if-changed=native/supervisor_linux.c");
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os == "linux" {
        let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing build directory")?)
            .join("vaksb-linux-supervisor");
        let compiler = env::var("CC").unwrap_or_else(|_| "cc".into());
        let status = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg("native/supervisor_linux.c")
            .arg("-o")
            .arg(output)
            .status()?;
        if !status.success() {
            return Err("Linux native supervisor compilation failed".into());
        }
        return Ok(());
    }
    if target_os != "macos" {
        return Ok(());
    }
    let target = env::var("CARGO_CFG_TARGET_ARCH")?;
    let arch = match target.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => return Err("unsupported macOS architecture".into()),
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing build directory")?)
        .join("vaksb-supervisor");
    let status = Command::new("/usr/bin/xcrun")
        .args([
            "--sdk", "macosx", "clang", "-arch", arch, "-O2", "-Wall", "-Wextra", "-Werror",
        ])
        .arg("native/supervisor.c")
        .arg("-o")
        .arg(output)
        .status()?;
    if !status.success() {
        return Err("native supervisor compilation failed".into());
    }
    Ok(())
}
