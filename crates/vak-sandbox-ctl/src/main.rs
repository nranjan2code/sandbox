#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use vak_sandbox_env::EnvStore;
use vak_sandbox_runtime::{CreateRealmRequest, SandboxManager};

#[derive(Parser)]
#[command(name = "vaksb")]
#[command(about = "vak-sandbox CLI - Safe agent code execution with reviewable promotion", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Private durable control store, outside every Realm workspace
    #[arg(long, global = true)]
    store: Option<PathBuf>,
}

fn capability_report() -> serde_json::Value {
    let execution_available = vak_sandbox_runtime::process::execution_available();
    serde_json::json!({
        "contract": 2,
        "execution_available": execution_available,
        "supervised_processes": execution_available,
        "detachment_denied": execution_available,
        "posix_spawn_denied": cfg!(target_os = "macos") && execution_available,
    })
}

#[cfg(target_os = "linux")]
fn validate_linux_workspace(path: PathBuf) -> anyhow::Result<PathBuf> {
    let workspace = std::fs::canonicalize(path)?;
    if !workspace.is_dir() {
        anyhow::bail!("workspace must be an existing directory");
    }
    let system_roots = [
        "/", "/home", "/root", "/usr", "/bin", "/sbin", "/etc", "/lib", "/lib64", "/opt", "/var",
        "/var/tmp", "/boot", "/mnt", "/media", "/proc", "/sys", "/dev", "/run", "/tmp",
    ];
    if system_roots
        .iter()
        .any(|root| workspace == PathBuf::from(root))
    {
        anyhow::bail!("workspace must be a specific project directory, not a system root");
    }
    Ok(workspace)
}

#[derive(Subcommand)]
enum Commands {
    /// Machine-readable containment contract (not a runtime execution probe)
    Capabilities,
    /// Run a command in the sandbox (OS-level process containment)
    Run {
        /// Directory in the isolated workspace where the command starts
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// Workspace read/write scope, separate from system runtime read grants
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Stop the process after this many seconds (1–300)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout_seconds: Option<u64>,
        /// Maximum combined stdout and stderr bytes (1 KiB–256 KiB)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1024..=262144))]
        max_output_bytes: Option<u64>,
        /// Command to execute
        #[arg(help = "Command to run")]
        command: String,
        /// Command arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Environment management
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Realm operations
    Realm {
        #[command(subcommand)]
        action: RealmAction,
    },
    /// Status and monitoring
    Status {
        #[arg(help = "Optional realm ID")]
        realm_id: Option<String>,
    },
    /// Send heartbeat ping
    Ping {
        #[arg(help = "Realm ID")]
        realm_id: String,
    },
    /// Health check
    Health,
}

#[derive(Subcommand)]
enum EnvAction {
    /// List environments
    List,
    /// Check environment spec
    Check {
        #[arg(help = "Path to env spec TOML")]
        spec: String,
    },
}

#[derive(Subcommand)]
enum RealmAction {
    /// Copy one project into a durable isolated workspace
    Create {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        env: Option<String>,
    },
    List,
    Status {
        realm_id: String,
    },
    /// Execute a bounded command in an existing workspace
    Exec {
        realm_id: String,
        #[arg(long, default_value = ".")]
        cwd: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Review the current candidate and record a fingerprint
    Snapshot {
        realm_id: String,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read a bounded page of a candidate file
    Read {
        realm_id: String,
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long)]
        original: bool,
    },
    /// Apply exactly the reviewed paths after external approval
    Promote {
        realm_id: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long, num_args = 1..)]
        paths: Vec<String>,
    },
    Rollback {
        realm_id: String,
        transaction_id: String,
        #[arg(long, num_args = 1..)]
        paths: Vec<String>,
    },
    /// Recover interrupted execution/promotion without replaying a command
    Recover {
        realm_id: String,
        #[arg(long, num_args = 1..)]
        paths: Vec<String>,
    },
    Destroy {
        realm_id: String,
    },
}

#[allow(
    clippy::too_many_lines,
    reason = "Explicit command dispatch keeps the platform and approval boundaries visible."
)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let store = Arc::new(EnvStore::new(
        cli.store.unwrap_or_else(EnvStore::default_root),
    )?);
    let mgr = Arc::new(SandboxManager::new(store));

    match cli.command {
        Commands::Capabilities => println!("{}", capability_report()),
        Commands::Run {
            cwd,
            workspace,
            timeout_seconds,
            max_output_bytes,
            command,
            args,
        } => {
            // Run command under OS-level sandbox, forwarding I/O
            #[cfg(target_os = "macos")]
            {
                use std::collections::HashMap;
                use vak_sandbox_core::{Policy, ProcessPlan, SandboxBackend};
                use vak_sandbox_seatbelt::SeatbeltBackend;
                let backend = SeatbeltBackend;
                if !backend.available() {
                    eprintln!("Seatbelt backend not available");
                    std::process::exit(1);
                }
                let inherited = std::env::var("VAK_SANDBOX").as_deref() == Ok("1");
                let default_workspace = if inherited {
                    std::env::current_dir()?
                } else {
                    PathBuf::from("/tmp")
                };
                let workspace = workspace.unwrap_or(default_workspace);
                let workspace = std::fs::canonicalize(&workspace)?;
                if [
                    "/", "/Users", "/home", "/System", "/Library", "/private", "/var",
                ]
                .iter()
                .any(|root| workspace == PathBuf::from(root))
                {
                    anyhow::bail!(
                        "workspace must be a specific project directory, not a filesystem root"
                    );
                }
                let cwd = cwd.unwrap_or_else(|| workspace.clone());
                let cwd = std::fs::canonicalize(&cwd)?;
                if !cwd.starts_with(&workspace) {
                    anyhow::bail!("working directory must be inside the sandbox workspace");
                }
                let mut policy = Policy::deny_all()
                    .allow_path_read("/usr".into())
                    .allow_path_read("/bin".into())
                    .allow_path_read("/etc".into())
                    .allow_path_read("/System".into())
                    .allow_path_read("/Library".into())
                    .allow_path_read("/opt".into())
                    .allow_path_read("/usr/local".into())
                    .allow_path_read(workspace.clone())
                    .allow_path_write(workspace.clone());
                let path = if inherited {
                    std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
                } else {
                    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()
                };
                policy.env.set.insert("PATH".into(), path);
                policy
                    .env
                    .set
                    .insert("HOME".into(), workspace.display().to_string());
                policy
                    .env
                    .set
                    .insert("TMPDIR".into(), workspace.display().to_string());
                let mut command_env = HashMap::new();
                if inherited {
                    for (key, value) in std::env::vars() {
                        if key == "VAK_SANDBOX" {
                            continue;
                        }
                        policy = policy.allow_env(key.clone());
                        command_env.insert(key, value);
                    }
                }
                if let Ok(executable) = std::fs::canonicalize(&command)
                    && executable.is_file()
                {
                    policy = policy.allow_path_read(executable);
                }
                let plan = ProcessPlan {
                    command: command.clone(),
                    args: args.clone(),
                    cwd: Some(cwd),
                    env: command_env,
                    policy,
                };
                let env = backend.create_process(&plan).await.unwrap_or_else(|e| {
                    eprintln!("Failed to create sandbox: {e}");
                    std::process::exit(1);
                });
                let handle = env
                    .exec(&command, &args, &HashMap::new())
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("Failed to exec: {e}");
                        std::process::exit(1);
                    });
                let deadline = async {
                    if let Some(seconds) = timeout_seconds {
                        tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::pin!(deadline);
                let mut stdout = handle.stdout;
                let mut stderr = handle.stderr;
                let exit = handle.exit_code;
                let mut exit_task = tokio::spawn(async move { exit.await.unwrap_or(-1) });
                let mut output_bytes = 0usize;
                let mut code = -1;
                let mut exited = false;
                let mut stdout_done = false;
                let mut stderr_done = false;
                let mut timed_out = false;
                let mut interrupted = false;
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                let mut int =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
                while !(stdout_done && stderr_done && exited) {
                    tokio::select! {
                        () = &mut deadline => { timed_out = true; break; }
                        _ = term.recv() => { interrupted = true; break; }
                        _ = int.recv() => { interrupted = true; break; }
                        line = stdout.recv(), if !stdout_done => match line {
                            Some(line) => {
                                output_bytes = output_bytes.saturating_add(line.len());
                                if max_output_bytes.is_some_and(|max| output_bytes as u64 > max) { break; }
                                print!("{line}");
                            }
                            None => stdout_done = true,
                        },
                        line = stderr.recv(), if !stderr_done => match line {
                            Some(line) => {
                                output_bytes = output_bytes.saturating_add(line.len());
                                if max_output_bytes.is_some_and(|max| output_bytes as u64 > max) { break; }
                                eprint!("{line}");
                            }
                            None => stderr_done = true,
                        },
                        result = &mut exit_task, if !exited => {
                            code = result.unwrap_or(-1);
                            exited = true;
                        }
                    }
                }
                if interrupted {
                    finish_process(env.as_ref()).await;
                    std::process::exit(143);
                }
                if timed_out || max_output_bytes.is_some_and(|max| output_bytes as u64 > max) {
                    eprintln!(
                        "{}",
                        if timed_out {
                            "sandbox execution timed out"
                        } else {
                            "sandbox output limit exceeded"
                        }
                    );
                    finish_process(env.as_ref()).await;
                    std::process::exit(if timed_out { 124 } else { 125 });
                }
                finish_process(env.as_ref()).await;
                std::process::exit(code);
            }
            #[cfg(target_os = "linux")]
            {
                let inherited = std::env::var("VAK_SANDBOX").as_deref() == Ok("1");
                let selected =
                    workspace.or_else(|| inherited.then(|| std::env::current_dir().ok()).flatten());
                let Some(workspace) = selected else {
                    anyhow::bail!("Select a specific --workspace directory for Linux execution");
                };
                let workspace = validate_linux_workspace(workspace)?;
                let cwd = cwd.unwrap_or_else(|| workspace.clone());
                let cwd = std::fs::canonicalize(cwd)?;
                if !cwd.starts_with(&workspace) {
                    anyhow::bail!("working directory must be inside the sandbox workspace");
                }
                let result = vak_sandbox_runtime::process::execute_configured(
                    &workspace,
                    &cwd,
                    &command,
                    &args,
                    timeout_seconds,
                    Some(usize::try_from(max_output_bytes.unwrap_or(256 * 1024))?),
                )
                .await
                .map_err(anyhow::Error::msg)?;
                print!("{}", result.stdout);
                eprint!("{}", result.stderr);
                if let Some(stopped) = result.stopped {
                    eprintln!("sandbox execution stopped: {stopped}");
                }
                std::process::exit(result.exit_code);
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (
                    cwd,
                    workspace,
                    timeout_seconds,
                    max_output_bytes,
                    command,
                    args,
                );
                eprintln!("OS-level sandbox backend not available on this platform");
                std::process::exit(1);
            }
        }
        Commands::Env { action } => match action {
            EnvAction::List => {
                println!(
                    "Environments stored in: {}",
                    EnvStore::default_root().join("envs").display()
                );
                println!("(Use env specs to define environments)");
            }
            EnvAction::Check { spec } => {
                println!("Checking spec: {spec}");
                let s = vak_sandbox_env::load_spec(std::path::Path::new(&spec))?;
                println!("✓ Loaded: {} v{}", s.env.id, s.env.version);
                println!("  Description: {}", s.env.description);
            }
        },
        Commands::Realm { action } => {
            let realms = mgr.realms()?;
            let value = match action {
                RealmAction::Create { project, env } => {
                    let handle = mgr
                        .create_realm(CreateRealmRequest {
                            env_sha256: env,
                            env_id: None,
                            base_path: project,
                            policy_overrides: None,
                        })
                        .await?;
                    vak_sandbox_runtime::realm::RealmStore::summary(
                        &realms.lease(&handle.realm_id)?.record,
                    )
                }
                RealmAction::List => serde_json::Value::Array(
                    realms
                        .list()?
                        .iter()
                        .map(vak_sandbox_runtime::realm::RealmStore::summary)
                        .collect(),
                ),
                RealmAction::Status { realm_id } => {
                    let lease = realms.lease(&realm_id)?;
                    serde_json::json!({"realm": vak_sandbox_runtime::realm::RealmStore::summary(&lease.record), "change_count": realms.review(&lease.record).ok().map(|r| r.changes.len()), "ready": realms.ensure_ready(&lease.record).is_ok(), "last_receipt": realms.last_receipt(&lease.record)?, "recovery_paths": realms.recovery_paths(&lease.record)?})
                }
                RealmAction::Exec { realm_id, cwd, cmd } => {
                    let (command, args) = cmd
                        .split_first()
                        .ok_or_else(|| anyhow::anyhow!("Provide a command and arguments"))?;
                    if command.is_empty()
                        || command.len() > 256
                        || args.len() > 64
                        || args.iter().any(|a| a.len() > 4096)
                        || args.iter().map(String::len).sum::<usize>() > 16384
                    {
                        anyhow::bail!("Command arguments exceed execution bounds");
                    }
                    let mut lease = realms.lease(&realm_id)?;
                    realms.ensure_ready(&lease.record)?;
                    let working = vak_sandbox_core::path::confined(&lease.record.workspace, &cwd)?;
                    if !working.is_dir() {
                        anyhow::bail!("Working directory is unavailable");
                    }
                    realms.audit(
                        "exec_started",
                        &realm_id,
                        serde_json::json!({"command": command, "args": args, "cwd": cwd}),
                    )?;
                    realms.begin_execution(&mut lease)?;
                    let result = vak_sandbox_runtime::process::execute_leased(
                        &mut lease, &working, command, args,
                    )
                    .await;
                    lease.record.status = if result.is_ok() {
                        "ready"
                    } else {
                        "cleanup_failed"
                    }
                    .into();
                    realms.save(&lease.record)?;
                    let result = result.map_err(|e| anyhow::anyhow!(e))?;
                    realms.audit("exec_finished", &realm_id, serde_json::json!({"exit_code": result.exit_code, "stopped": result.stopped}))?;
                    serde_json::json!({"realm_id": realm_id, "result": result})
                }
                RealmAction::Snapshot { realm_id, offset } => {
                    let lease = realms.lease(&realm_id)?;
                    let review = realms.snapshot(&lease.record)?;
                    serde_json::json!({"realm_id": realm_id, "fingerprint": review.fingerprint, "can_promote": review.can_promote, "total": review.changes.len(), "offset": offset, "next_offset": (offset + 20).min(review.changes.len()), "changes": review.changes.iter().skip(offset).take(20).collect::<Vec<_>>()})
                }
                RealmAction::Read {
                    realm_id,
                    path,
                    offset,
                    original,
                } => {
                    let lease = realms.lease(&realm_id)?;
                    realms.read_file(&lease.record, &path, offset, original)?
                }
                RealmAction::Promote {
                    realm_id,
                    fingerprint,
                    paths,
                } => {
                    let mut lease = realms.lease(&realm_id)?;
                    serde_json::to_value(realms.promote(&mut lease, &fingerprint, &paths)?)?
                }
                RealmAction::Rollback {
                    realm_id,
                    transaction_id,
                    paths,
                } => {
                    let mut lease = realms.lease(&realm_id)?;
                    serde_json::to_value(realms.rollback(&mut lease, &transaction_id, &paths)?)?
                }
                RealmAction::Recover { realm_id, paths } => {
                    let mut lease = realms.lease(&realm_id)?;
                    serde_json::to_value(realms.recover(&mut lease, &paths)?)?
                }
                RealmAction::Destroy { realm_id } => {
                    let lease = realms.lease(&realm_id)?;
                    realms.destroy(&lease)?;
                    serde_json::json!({"realm_id": realm_id, "destroyed": true})
                }
            };
            println!("{}", serde_json::to_string(&value)?);
        }
        Commands::Status { realm_id } => {
            if let Some(id) = realm_id {
                if let Some(r) = mgr.get_realm(&id).await {
                    println!("Realm {}: {:?}", id, r.status);
                } else {
                    println!("Not found");
                }
            } else {
                let realms = mgr.list_realms().await;
                println!("Total realms: {}", realms.len());
            }
        }
        Commands::Ping { realm_id } => {
            mgr.ping(&realm_id).await;
            if mgr.heartbeat_monitor().is_alive(&realm_id) {
                println!("✓ Pong from {realm_id}");
            } else {
                println!("✓ Ping sent to {realm_id}");
            }
        }
        Commands::Health => {
            let realms = mgr.list_realms().await;
            let alive = realms
                .iter()
                .filter(|r| mgr.heartbeat_monitor().is_alive(&r.realm_id))
                .count();
            println!("Health:");
            println!("  Realms: {}", realms.len());
            println!("  Alive: {alive}");
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
async fn finish_process(environment: &dyn vak_sandbox_core::SandboxEnv) {
    if let Err(error) = environment.destroy().await {
        eprintln!("Sandbox cleanup was not verified: {error}");
        std::process::exit(126);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn capability_report_does_not_claim_unavailable_platform_controls() {
        let report = capability_report();
        let available = report["execution_available"].as_bool().unwrap();
        assert_eq!(report["supervised_processes"], available);
        assert_eq!(report["detachment_denied"], available);
        assert_eq!(
            report["posix_spawn_denied"],
            cfg!(target_os = "macos") && available
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            available,
            vak_sandbox_runtime::process::execution_available()
        );
        #[cfg(target_os = "macos")]
        assert!(available);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert!(!available);
        assert!(report.get("posix_spawn").is_none());
    }

    #[test]
    fn bounded_process_options_parse_without_treating_them_as_the_command() {
        let cli = Cli::try_parse_from([
            "vaksb",
            "run",
            "--workspace",
            "/tmp/project",
            "--cwd",
            "/tmp/project",
            "--timeout-seconds",
            "30",
            "--max-output-bytes",
            "32768",
            "--",
            "/bin/echo",
            "ready",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Commands::Run { timeout_seconds: Some(30), max_output_bytes: Some(32768), command, .. } if command == "/bin/echo")
        );
    }

    #[test]
    fn process_limits_reject_values_outside_the_supported_bounds() {
        for (flag, value) in [
            ("--timeout-seconds", "0"),
            ("--timeout-seconds", "301"),
            ("--max-output-bytes", "1023"),
            ("--max-output-bytes", "262145"),
        ] {
            assert!(Cli::try_parse_from(["vaksb", "run", flag, value, "--", "/bin/echo"]).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_workspace_requires_specific_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(
            validate_linux_workspace(temp.path().to_path_buf()).unwrap(),
            temp.path()
        );
        assert!(validate_linux_workspace(PathBuf::from("/home")).is_err());
        assert!(validate_linux_workspace(PathBuf::from("/tmp")).is_err());
        assert!(validate_linux_workspace(PathBuf::from("/var/tmp")).is_err());
        let file = temp.path().join("file");
        std::fs::write(&file, "not a directory").unwrap();
        assert!(validate_linux_workspace(file).is_err());
    }
}
