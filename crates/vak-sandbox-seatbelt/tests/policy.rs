#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::{collections::HashMap, fs, path::Path};
use vak_sandbox_core::{Policy, ProcessPlan, RealmPlan, SandboxBackend};
use vak_sandbox_seatbelt::SeatbeltBackend;
fn system_policy() -> Policy {
    [
        "/usr",
        "/bin",
        "/System",
        "/Library",
        "/opt",
        "/private/etc",
    ]
    .into_iter()
    .fold(Policy::deny_all(), |policy, root| {
        policy.allow_path_read(root.into())
    })
}
async fn execute(policy: Policy, cwd: &Path, command: &str, args: &[&str]) -> (i32, String) {
    let args: Vec<_> = args.iter().map(|s| (*s).into()).collect();
    let env = SeatbeltBackend
        .create_process(&ProcessPlan {
            command: command.into(),
            args: args.clone(),
            cwd: Some(cwd.into()),
            env: HashMap::new(),
            policy,
        })
        .await
        .unwrap();
    let mut h = env.exec(command, &args, &HashMap::new()).await.unwrap();
    let mut output = String::new();
    while let Some(chunk) = h.stdout.recv().await {
        output.push_str(&chunk);
    }
    let code = h.exit_code.await.unwrap();
    if code != 0 {
        while let Some(err) = h.stderr.recv().await {
            eprintln!("{err}");
        }
    }
    env.destroy().await.unwrap();
    (code, output)
}
#[tokio::test]
async fn explicit_deny_overrides_parent_grants_including_future_paths() {
    let work = tempfile::tempdir().unwrap();
    let denied = work.path().join("denied");
    let mut policy = system_policy()
        .allow_path_read(work.path().into())
        .allow_path_write(work.path().into());
    policy.fs.deny.push(denied.clone());
    fs::write(&denied, "synthetic").unwrap();
    assert_ne!(
        execute(
            policy.clone(),
            work.path(),
            "/bin/cat",
            &[denied.to_str().unwrap()]
        )
        .await
        .0,
        0
    );
    fs::remove_file(&denied).unwrap();
    assert_ne!(
        execute(
            policy,
            work.path(),
            "/usr/bin/touch",
            &[denied.to_str().unwrap()]
        )
        .await
        .0,
        0
    );
    assert!(!denied.exists());
}
#[tokio::test]
async fn quotes_in_paths_are_data_and_unavailable_allow_roots_are_not_silently_ignored() {
    let work = tempfile::tempdir().unwrap();
    let file = work.path().join("quote\"back\\slash");
    fs::write(&file, "allowed").unwrap();
    let (code, output) = execute(
        system_policy().allow_path_read(file.clone()),
        work.path(),
        "/bin/cat",
        &[file.to_str().unwrap()],
    )
    .await;
    assert_eq!(code, 0);
    assert_eq!(output, "allowed");
    let invalid = Policy::deny_all().allow_path_read("../escape".into());
    let plan = ProcessPlan {
        command: "/bin/true".into(),
        args: vec![],
        cwd: None,
        env: HashMap::new(),
        policy: invalid,
    };
    assert!(SeatbeltBackend.create_process(&plan).await.is_err());
}
#[tokio::test]
async fn enabled_network_is_limited_to_selected_localhost_ports() {
    let work = tempfile::tempdir().unwrap();
    let allowed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = allowed.local_addr().unwrap().port().to_string();
    let other = denied.local_addr().unwrap().port().to_string();
    let mut policy = system_policy();
    policy.network.allow = true;
    policy.network.allow_outbound = true;
    policy.network.allow_localhost = true;
    policy.network.allow_hosts = vec!["127.0.0.1".into()];
    policy.network.allow_ports = vec![port.parse().unwrap()];
    assert_eq!(
        execute(
            policy.clone(),
            work.path(),
            "/usr/bin/nc",
            &["-n", "-z", "-w", "1", "127.0.0.1", &port]
        )
        .await
        .0,
        0
    );
    assert_ne!(
        execute(
            policy,
            work.path(),
            "/usr/bin/nc",
            &["-n", "-z", "-w", "1", "127.0.0.1", &other]
        )
        .await
        .0,
        0
    );
}
#[tokio::test]
async fn unsupported_network_and_legacy_realm_fail_before_execution() {
    for policy in [Policy::deny_all().allow_network_full(), {
        let mut p = system_policy();
        p.network.allow = true;
        p.network.allow_outbound = true;
        p.network.allow_hosts = vec!["bad:\"profile".into()];
        p.network.allow_ports = vec![443];
        p
    }] {
        let plan = ProcessPlan {
            command: "/bin/true".into(),
            args: vec![],
            cwd: None,
            env: HashMap::new(),
            policy,
        };
        assert!(SeatbeltBackend.create_process(&plan).await.is_err());
    }
    let work = tempfile::tempdir().unwrap();
    let plan = RealmPlan {
        id: "legacy".into(),
        base_path: work.path().into(),
        realm_root: work.path().into(),
        policy: system_policy(),
        snapshot_on_create: false,
    };
    assert!(SeatbeltBackend.create_realm(&plan).await.is_err());
    assert!(!SeatbeltBackend.capabilities().realm_isolation);
}

#[tokio::test]
async fn supervisor_cannot_be_placed_in_writable_scope_or_load_target_injections() {
    let mut policy = system_policy().allow_path_write("/private/tmp".into());
    let mut plan = ProcessPlan {
        command: "/bin/true".into(),
        args: vec![],
        cwd: None,
        env: HashMap::new(),
        policy: policy.clone(),
    };
    assert!(SeatbeltBackend.create_process(&plan).await.is_err());
    policy.fs.allow_write.clear();
    policy.env.set.insert(
        "DYLD_INSERT_LIBRARIES".into(),
        "/nonexistent-fixture".into(),
    );
    plan.policy = policy;
    assert!(SeatbeltBackend.create_process(&plan).await.is_err());
}
