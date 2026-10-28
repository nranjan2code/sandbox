use std::{env, path::PathBuf, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=native/supervisor.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
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
