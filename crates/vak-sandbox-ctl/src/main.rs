use clap::{Parser, Subcommand};
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
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command in the sandbox (OS-level process containment)
    Run {
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
    /// Create a new realm
    Create {
        #[arg(long, help = "Environment SHA256")]
        env: Option<String>,
    },
    /// List all realms
    List,
    /// Get realm status
    Status {
        #[arg(help = "Realm ID")]
        realm_id: String,
    },
    /// Execute command in realm
    Exec {
        #[arg(help = "Realm ID")]
        realm_id: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Create snapshot
    Snapshot {
        #[arg(help = "Realm ID")]
        realm_id: String,
    },
    /// Promote realm changes
    Promote {
        #[arg(help = "Realm ID")]
        realm_id: String,
    },
    /// Destroy realm
    Destroy {
        #[arg(help = "Realm ID")]
        realm_id: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let store = Arc::new(EnvStore::new(EnvStore::default_root())?);
    let mgr = Arc::new(SandboxManager::new(store));

    match cli.command {
        Commands::Run { command, args } => {
            // Run command under OS-level sandbox, forwarding I/O
            #[cfg(target_os = "macos")]
            {
                use vak_sandbox_core::{ProcessPlan, Policy, SandboxBackend};
                use vak_sandbox_seatbelt::SeatbeltBackend;
                use std::collections::HashMap;
                let backend = SeatbeltBackend;
                if !backend.available() {
                    eprintln!("Seatbelt backend not available");
                    std::process::exit(1);
                }
                let policy = Policy::deny_all()
                    .allow_path_read("/usr".into())
                    .allow_path_read("/bin".into())
                    .allow_path_read("/etc".into())
                    .allow_path_read("/System".into())
                    .allow_path_read("/Library".into())
                    .allow_path_write("/tmp".into())
                    .allow_path_write("/dev".into());
                let plan = ProcessPlan {
                    command: command.clone(),
                    args: args.clone(),
                    cwd: Some("/tmp".into()),
                    env: HashMap::new(),
                    policy,
                };
                let env = backend.create_process(&plan).await
                    .unwrap_or_else(|e| { eprintln!("Failed to create sandbox: {}", e); std::process::exit(1); });
                let mut handle = env.exec(&command, &args, &HashMap::new()).await
                    .unwrap_or_else(|e| { eprintln!("Failed to exec: {}", e); std::process::exit(1); });
                // Forward stdout
                let stdout_task = tokio::spawn(async move {
                    while let Some(line) = handle.stdout.recv().await {
                        println!("{}", line);
                    }
                    handle.exit_code.await.unwrap_or(-1)
                });
                // Forward stderr
                let stderr_task = tokio::spawn(async move {
                    while let Some(line) = handle.stderr.recv().await {
                        eprintln!("{}", line);
                    }
                });
                let code = stdout_task.await.unwrap_or(-1);
                let _ = stderr_task.await;
                env.destroy().await.ok();
                std::process::exit(code);
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("OS-level sandbox backend not available on this platform");
                std::process::exit(1);
            }
        }
        Commands::Env { action } => match action {
            EnvAction::List => {
                println!("Environments stored in: {:?}", EnvStore::default_root().join("envs"));
                println!("(Use env specs to define environments)");
            }
            EnvAction::Check { spec } => {
                println!("Checking spec: {}", spec);
                let s = vak_sandbox_env::load_spec(std::path::Path::new(&spec))?;
                println!("✓ Loaded: {} v{}", s.env.id, s.env.version);
                println!("  Description: {}", s.env.description);
            }
        },
        Commands::Realm { action } => match action {
            RealmAction::Create { env } => {
                let realm = mgr.create_realm(CreateRealmRequest {
                    env_sha256: env,
                    env_id: None,
                    base_path: None,
                    policy_overrides: None,
                }).await?;
                println!("✓ Created realm");
                println!("  ID: {}", realm.realm_id);
                println!("  Root: {}", realm.realm_root.display());
                println!("  Status: {:?}", realm.status);
            }
            RealmAction::List => {
                let realms = mgr.list_realms().await;
                if realms.is_empty() {
                    println!("No realms found");
                } else {
                    println!("Realms ({}):", realms.len());
                    for r in realms {
                        println!("  {} - {:?} - {}", r.realm_id, r.status, r.realm_root.display());
                    }
                }
            }
            RealmAction::Status { realm_id } => {
                if let Some(r) = mgr.get_realm(&realm_id).await {
                    println!("Realm: {}", r.realm_id);
                    println!("  Status: {:?}", r.status);
                    println!("  Root: {}", r.realm_root.display());
                    println!("  Writable: {}", r.writable_layer.display());
                    println!("  Created: {}", r.created_at);
                } else {
                    println!("Realm not found: {}", realm_id);
                }
            }
            RealmAction::Exec { realm_id, cmd } => {
                println!("Executing in realm {}: {:?}", realm_id, cmd);
                println!("(Exec implementation in progress)");
            }
            RealmAction::Snapshot { realm_id } => {
                println!("Creating snapshot of realm: {}", realm_id);
                println!("(Snapshot implementation in progress)");
            }
            RealmAction::Promote { realm_id } => {
                println!("Promoting realm: {}", realm_id);
                println!("(Promotion implementation in progress - will be crash-safe with journal)");
            }
            RealmAction::Destroy { realm_id } => {
                println!("Destroying realm: {}", realm_id);
                println!("(Destroy implementation in progress)");
            }
        },
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
                println!("✓ Pong from {}", realm_id);
            } else {
                println!("✓ Ping sent to {}", realm_id);
            }
        }
        Commands::Health => {
            let realms = mgr.list_realms().await;
            let alive = realms.iter().filter(|r| mgr.heartbeat_monitor().is_alive(&r.realm_id)).count();
            println!("Health:");
            println!("  Realms: {}", realms.len());
            println!("  Alive: {}", alive);
        }
    }

    Ok(())
}
