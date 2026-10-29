//! Bounded one-shot execution shared by persistent Realm commands.
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::path::Path;
#[cfg(target_os = "macos")]
use vak_sandbox_core::{Policy, ProcessPlan, SandboxBackend};
#[cfg(target_os = "macos")]
use vak_sandbox_seatbelt::SeatbeltBackend;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub stopped: Option<String>,
}

/// # Errors
/// Returns backend, setup, signal-handler or verified-cleanup errors. Command failures remain in the returned receipt.
#[cfg_attr(not(target_os = "macos"), allow(clippy::unused_async))]
pub async fn execute(
    workspace: &Path,
    cwd: &Path,
    command: &str,
    args: &[String],
) -> Result<CommandResult, String> {
    #[cfg(target_os = "macos")]
    {
        execute_inner(workspace, cwd, command, args, None, None).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (workspace, cwd, command, args);
        Err("OS-isolated command execution requires macOS Seatbelt; no command was run".into())
    }
}

/// Execute while the native supervisor retains the Realm lease through cleanup.
///
/// # Errors
/// Returns lease handoff, policy, launch, execution-setup or cleanup errors.
#[cfg_attr(not(target_os = "macos"), allow(clippy::unused_async))]
pub async fn execute_leased(
    lease: &mut crate::realm::RealmLease,
    cwd: &Path,
    command: &str,
    args: &[String],
) -> Result<CommandResult, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (lease, cwd, command, args);
        Err("OS-isolated command execution requires macOS Seatbelt; no command was run".into())
    }
    #[cfg(target_os = "macos")]
    {
        if lease.record.status != "running" {
            return Err("Call RealmStore::begin_execution before leased execution".into());
        }
        let metadata = std::fs::symlink_metadata(lease.execution_receipt())
            .map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > 256 {
            return Err("Invalid initial execution receipt".into());
        }
        let initial: vak_sandbox_core::backend::ProcessCompletion = serde_json::from_slice(
            &std::fs::read(lease.execution_receipt()).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if initial.cleanup_verified || initial.exit_code != -1 {
            return Err("Leased execution requires a fresh unverified completion receipt".into());
        }
        let lock = lease.execution_lock().map_err(|error| error.to_string())?;
        execute_inner(
            &lease.record.workspace,
            cwd,
            command,
            args,
            Some(&lock),
            Some(lease.execution_receipt()),
        )
        .await
    }
}

#[cfg(target_os = "macos")]
async fn execute_inner(
    workspace: &Path,
    cwd: &Path,
    command: &str,
    args: &[String],
    lease: Option<&Path>,
    completion: Option<&Path>,
) -> Result<CommandResult, String> {
    let backend = SeatbeltBackend;
    if !backend.available() {
        return Err("OS-isolated execution requires macOS Seatbelt".into());
    }
    let mut policy = Policy::deny_all()
        .allow_path_read(workspace.into())
        .allow_path_write(workspace.into());
    for root in [
        "/usr", "/bin", "/etc", "/System", "/Library", "/opt", "/dev",
    ] {
        policy = policy.allow_path_read(root.into());
    }
    let mut path_entries = vec![
        "/opt/homebrew/bin".to_string(),
        "/usr/local/bin".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "/usr/sbin".to_string(),
        "/sbin".to_string(),
    ];

    // Discover user toolchain directories (e.g. .local/bin, .cargo/bin, .nvm) from host environment
    if let Ok(host_path) = std::env::var("PATH") {
        for entry in std::env::split_paths(&host_path) {
            if entry.is_dir() {
                let s = entry.to_string_lossy();
                if s.contains(".local/bin")
                    || s.contains(".cargo/bin")
                    || s.contains(".nvm")
                    || s.contains(".pyenv")
                    || s.contains("homebrew")
                {
                    policy = policy.allow_path_read(entry.clone());
                    let p_str = entry.display().to_string();
                    if !path_entries.contains(&p_str) {
                        path_entries.insert(0, p_str);
                    }
                }
            }
        }
    }
    if let Ok(user_home) = std::env::var("HOME") {
        for sub in [".local/bin", ".cargo/bin"] {
            let p = Path::new(&user_home).join(sub);
            if p.is_dir() {
                policy = policy.allow_path_read(p.clone());
                let p_str = p.display().to_string();
                if !path_entries.contains(&p_str) {
                    path_entries.insert(0, p_str);
                }
            }
        }
    }

    policy.env.set.insert("PATH".into(), path_entries.join(":"));
    policy
        .env
        .set
        .insert("HOME".into(), workspace.display().to_string());
    policy
        .env
        .set
        .insert("TMPDIR".into(), workspace.display().to_string());
    let plan = ProcessPlan {
        command: command.into(),
        args: args.into(),
        cwd: Some(cwd.into()),
        env: HashMap::new(),
        policy,
    };
    let environment = backend
        .create_process_with_lease(&plan, lease, completion)
        .await
        .map_err(|e| e.to_string())?;
    let handle = environment
        .exec(command, args, &HashMap::new())
        .await
        .map_err(|e| e.to_string())?;
    let mut stdout = handle.stdout;
    let mut stderr = handle.stderr;
    let mut exit = handle.exit_code;
    let mut result = CommandResult {
        exit_code: -1,
        stdout: String::new(),
        stderr: String::new(),
        stopped: None,
    };
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
    tokio::pin!(deadline);
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    let mut out_done = false;
    let mut err_done = false;
    let mut exited = false;
    loop {
        tokio::select! {
            () = &mut deadline => { result.stopped = Some("30 second runtime limit".into()); result.exit_code = 124; break; },
            _ = tokio::signal::ctrl_c() => { result.stopped = Some("cancelled".into()); result.exit_code = 130; break; },
            () = async { #[cfg(unix)] { term.recv().await; } #[cfg(not(unix))] { std::future::pending::<()>().await; } } => { result.stopped = Some("cancelled".into()); result.exit_code = 143; break; },
            code = &mut exit, if !exited => { result.exit_code = code.unwrap_or(-1); exited = true; },
            chunk = stdout.recv(), if !out_done => { if let Some(chunk) = chunk { result.stdout.push_str(&chunk); } else { out_done = true; } },
            chunk = stderr.recv(), if !err_done => { if let Some(chunk) = chunk { result.stderr.push_str(&chunk); } else { err_done = true; } },
        }
        if result.stdout.len() + result.stderr.len() > 32768 {
            result.stopped = Some("32 KiB output limit".into());
            result.exit_code = 125;
            // Keep UTF-8 valid while bounding the returned receipt.
            while result.stdout.len() + result.stderr.len() > 32768 {
                if result.stderr.is_empty() {
                    result.stdout.pop();
                } else {
                    result.stderr.pop();
                }
            }
            break;
        }
        if exited && out_done && err_done {
            break;
        }
    }
    environment.destroy().await.map_err(|e| e.to_string())?;
    Ok(result)
}
