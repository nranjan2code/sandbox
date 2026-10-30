#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn private_control() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn worker_cli_relays_private_descriptor_without_using_target_stdin() {
    let workspace = tempfile::tempdir().unwrap();
    let store = workspace.path().join("must-not-be-created");
    let protected = workspace.path().join("protected");
    std::fs::create_dir(&protected).unwrap();
    std::fs::write(protected.join("key"), b"do-not-read").unwrap();
    #[cfg(target_os = "macos")]
    let script = "if read -r line <&0; then exit 77; fi; if [ -r ./protected/key ]; then exit 88; fi; read -r line <&3; printf 'echo:%s\\n' \"$line\" >&3";
    #[cfg(target_os = "linux")]
    let script = "if read -r line <&0; then exit 77; fi; read -r line <&3; printf 'echo:%s\\n' \"$line\" >&3";
    let mut command = Command::new(env!("CARGO_BIN_EXE_vaksb"));
    command.arg("--store").arg(&store).args([
        "worker",
        "--cwd",
        workspace.path().to_str().unwrap(),
        "--read",
        workspace.path().to_str().unwrap(),
        "--write",
        workspace.path().to_str().unwrap(),
    ]);
    #[cfg(target_os = "macos")]
    command.args(["--deny", protected.to_str().unwrap()]);
    let mut child = command
        .args([
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
    let mut owner = child.stdin.take().unwrap();
    owner.write_all(b"private-channel\n").unwrap();
    let mut reply = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut reply)
        .unwrap();
    assert_eq!(reply, "echo:private-channel\n");
    let output = child.wait_with_output().unwrap();
    drop(owner);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"");
    assert!(!store.exists(), "worker startup must not create host state");
}

fn completion_worker(
    workspace: &std::path::Path,
    receipt: &std::path::Path,
    script: &str,
) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .args(["worker", "--cwd"])
        .arg(workspace)
        .arg("--read")
        .arg(workspace)
        .arg("--write")
        .arg(workspace)
        .arg("--completion-record")
        .arg(receipt)
        .args([
            "--invocation-id",
            "invocation-1",
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
        .unwrap()
}

#[test]
fn worker_completion_is_private_and_distinguishes_target_failure_from_cleanup() {
    let workspace = tempfile::tempdir().unwrap();
    let control = private_control();
    let receipt = control.path().join("invocation-1.json");
    let script = format!(
        "if printf forged > '{}'; then exit 88; fi; (sleep 2; printf late > late-marker) & printf '{{\"cleanup_verified\":true,\"exit_code\":0}}\\n' >&3; exit 126",
        receipt.display()
    );
    let mut child = completion_worker(workspace.path(), &receipt, &script);
    let owner = child.stdin.take().unwrap();
    let output = child.wait_with_output().unwrap();
    drop(owner);
    assert_eq!(
        output.status.code(),
        Some(126),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"exit_code\":0"));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"version":1,"invocation_id":"invocation-1","cleanup_verified":true,"exit_code":126})
    );
    std::thread::sleep(std::time::Duration::from_millis(2200));
    assert!(!workspace.path().join("late-marker").exists());
}

#[test]
fn owner_eof_stops_a_worker_that_ignores_its_channel_and_records_cleanup() {
    let workspace = tempfile::tempdir().unwrap();
    let control = private_control();
    let receipt = control.path().join("invocation-1.json");
    let mut child = completion_worker(
        workspace.path(),
        &receipt,
        "printf 'ready\\n' >&3; sleep 30; printf late > late-marker",
    );
    let owner = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = ready_tx.send((result, line));
    });
    let (_, ready) = ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert_eq!(ready, "ready\n");
    drop(owner);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("owner EOF did not stop contained work");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(value["cleanup_verified"], true);
    assert_eq!(value["invocation_id"], "invocation-1");
    assert!(!workspace.path().join("late-marker").exists());
}

#[test]
fn completion_inside_target_grant_or_existing_record_refuses_before_launch() {
    let workspace = tempfile::tempdir().unwrap();
    let receipt = workspace.path().join("receipt.json");
    let output = completion_worker(workspace.path(), &receipt, "printf started > started")
        .wait_with_output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!workspace.path().join("started").exists());
    assert!(!receipt.exists());
    let control = private_control();
    let receipt = control.path().join("receipt.json");
    std::fs::write(&receipt, b"preserved").unwrap();
    let output = completion_worker(workspace.path(), &receipt, "printf started > started")
        .wait_with_output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(std::fs::read(&receipt).unwrap(), b"preserved");
    assert!(!workspace.path().join("started").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn worker_cli_refuses_nested_exclusions_before_launch() {
    let workspace = tempfile::tempdir().unwrap();
    let protected = workspace.path().join("protected");
    std::fs::create_dir(&protected).unwrap();
    let marker = workspace.path().join("started");
    let output = Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .args([
            "worker",
            "--cwd",
            workspace.path().to_str().unwrap(),
            "--read",
            workspace.path().to_str().unwrap(),
            "--write",
            workspace.path().to_str().unwrap(),
            "--deny",
            protected.to_str().unwrap(),
            "--env",
            "PATH=/usr/bin:/bin",
            "--command",
            "/bin/sh",
            "--",
            "-c",
            "printf started > started",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "unsupported policy must refuse before launch"
    );
}
