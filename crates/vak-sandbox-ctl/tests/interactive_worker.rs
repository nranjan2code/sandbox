#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn worker_cli_relays_private_descriptor_without_using_target_stdin() {
    let workspace = tempfile::tempdir().unwrap();
    let store = workspace.path().join("must-not-be-created");
    let script = "if read -r line <&0; then exit 77; fi; read -r line <&3; printf 'echo:%s\\n' \"$line\" >&3";
    let mut child = Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .arg("--store")
        .arg(&store)
        .args([
            "worker",
            "--cwd",
            workspace.path().to_str().unwrap(),
            "--read",
            workspace.path().to_str().unwrap(),
            "--write",
            workspace.path().to_str().unwrap(),
            "--env",
            "PATH=/usr/bin:/bin",
            "--command",
            "/bin/sh",
            "--",
            "-c",
            script,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"private-channel\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"echo:private-channel\n");
    assert!(!store.exists(), "worker startup must not create host state");
}
