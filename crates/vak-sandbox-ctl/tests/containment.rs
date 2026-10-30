#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;
fn run(work: &Path, command: &str, args: &[&str]) -> Output {
    run_timeout(work, command, args, "10")
}
fn run_timeout(work: &Path, command: &str, args: &[&str], seconds: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .args(["run", "--workspace"])
        .arg(work)
        .args(["--timeout-seconds", seconds, "--", command])
        .args(args)
        .output()
        .unwrap()
}
fn probe(work: &Path) -> String {
    let output = work.join("probe");
    let status = Command::new("/usr/bin/xcrun")
        .args(["clang", "-Wall", "-Wextra", "-Werror"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/probe.c"
        ))
        .arg("-o")
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    output.to_str().unwrap().into()
}
#[test]
fn concurrent_startup_keeps_group_admission_before_target_execution() {
    let mut jobs = Vec::new();
    for _ in 0..4 {
        jobs.push(std::thread::spawn(|| {
            let work = TempDir::new().unwrap();
            for _ in 0..8 {
                let output = run(work.path(), "/bin/echo", &["group-ready"]);
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.stdout, b"group-ready\n");
            }
        }));
    }
    for job in jobs {
        job.join().unwrap();
    }
}

#[test]
fn command_arguments_never_expand_read_permissions() {
    let temp = TempDir::new().unwrap();
    let work = temp.path().join("work");
    fs::create_dir(&work).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, "synthetic-canary").unwrap();
    let output = run(&work, "/bin/cat", &[outside.to_str().unwrap()]);
    assert!(!output.status.success());
    assert_eq!(output.stdout, Vec::<u8>::new());
    let output = run(&work, "/bin/ls", &[temp.path().to_str().unwrap()]);
    assert!(!output.status.success());
    fs::write(work.join("inside"), "allowed").unwrap();
    assert_eq!(run(&work, "/bin/cat", &["inside"]).stdout, b"allowed");
}
#[test]
fn deadline_remains_active_with_closed_streams() {
    let work = TempDir::new().unwrap();
    let binary = probe(work.path());
    let start = Instant::now();
    let output = run_timeout(work.path(), &binary, &["hold"], "1");
    assert_eq!(output.status.code(), Some(124));
    assert!(start.elapsed() < Duration::from_secs(4));
}
#[test]
fn detached_and_background_work_cannot_outlive_completion() {
    let work = TempDir::new().unwrap();
    let binary = probe(work.path());
    let output = run(work.path(), &binary, &["detach"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"detachment denied\n");
    let output = run(work.path(), &binary, &["fork"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"fork-exec-ok\n");
    assert!(run(work.path(), &binary, &["descendant"]).status.success());
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!work.path().join("late-marker").exists());
}
#[test]
fn owner_death_still_tears_down_the_group() {
    let work = TempDir::new().unwrap();
    let binary = probe(work.path());
    let mut child = Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .args(["run", "--workspace"])
        .arg(work.path())
        .args(["--", &binary, "owner"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !work.path().join("owner-ready").exists() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!work.path().join("late-marker").exists());
    // Completion of a second command does not depend on the vanished owner.
    assert_eq!(run(work.path(), "/bin/echo", &["ready"]).stdout, b"ready\n");
}
#[test]
fn environment_is_filtered_and_shell_syntax_is_explicit() {
    let work = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vaksb"))
        .env("SYNTHETIC_SECRET", "fixture-only")
        .args(["run", "--workspace"])
        .arg(work.path())
        .args(["--", "/usr/bin/env"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_SECRET"));
    assert_eq!(
        run(work.path(), "/bin/echo", &["$(touch injected)"]).stdout,
        b"$(touch injected)\n"
    );
    assert!(!work.path().join("injected").exists());
}

#[test]
fn realm_target_exit_126_keeps_its_receipt_and_verified_readiness() {
    let temp = TempDir::new().unwrap();
    let project = temp.path().join("project");
    fs::create_dir(&project).unwrap();
    let store = temp.path().join("control");
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_vaksb"))
            .arg("--store")
            .arg(&store)
            .arg("realm")
            .args(args)
            .output()
            .unwrap()
    };
    let created: serde_json::Value =
        serde_json::from_slice(&call(&["create", "--project", project.to_str().unwrap()]).stdout)
            .unwrap();
    let id = created["realm_id"].as_str().unwrap();
    let result = call(&["exec", id, "--", "/bin/sh", "-c", "exit 126"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(receipt["result"]["exit_code"], 126);
    let status: serde_json::Value = serde_json::from_slice(&call(&["status", id]).stdout).unwrap();
    assert_eq!(status["ready"], true);
}
