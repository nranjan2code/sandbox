use crate::{Policy, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// Jail a single process with OS restrictions only
    Process,
    /// Isolated realm with reviewable promotion workflow
    Realm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent serialized capabilities preserve the public policy schema."
)]
pub struct BackendCaps {
    pub process_jail: bool,
    pub realm_isolation: bool,
    pub promotion: bool,
    pub rollback: bool,
    pub network_control: bool,
    pub resource_limits: bool,
    pub symlink_protection: bool,
}

pub type SandboxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

pub trait SandboxBackend: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn platforms(&self) -> &[&str];
    fn available(&self) -> bool;
    fn capabilities(&self) -> BackendCaps;

    fn create_process(&self, plan: &ProcessPlan) -> SandboxFuture<'_, Box<dyn SandboxEnv>>;
    /// Creates a supervised process with an invocation-scoped, bidirectional
    /// private I/O descriptor 3. The target's stdin remains `/dev/null`; the
    /// supervisor lifetime channel is separate and never reaches the target.
    fn create_interactive_process(
        &self,
        _plan: &ProcessPlan,
    ) -> SandboxFuture<'_, Box<dyn SandboxEnv>> {
        Box::pin(async {
            Err(crate::Error::BackendNotAvailable(
                "Interactive contained processes are not supported by this backend".into(),
            ))
        })
    }
    fn create_realm(&self, plan: &RealmPlan) -> SandboxFuture<'_, Box<dyn SandboxEnv>>;
}

pub trait SandboxEnv: Send + Sync {
    fn id(&self) -> &str;
    fn mode(&self) -> SandboxMode;

    fn exec(
        &self,
        cmd: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> SandboxFuture<'_, ExecHandle>;
    /// Starts the process with its private I/O descriptor. The target must opt
    /// into descriptor 3; ordinary stdin remains `/dev/null`.
    fn exec_interactive(
        &self,
        _cmd: &str,
        _args: &[String],
        _env: &HashMap<String, String>,
    ) -> SandboxFuture<'_, ExecHandle> {
        Box::pin(async {
            Err(crate::Error::BackendNotAvailable(
                "Interactive contained processes are not supported by this backend".into(),
            ))
        })
    }
    fn destroy(&self) -> SandboxFuture<'_, ()>;
}

pub struct ExecHandle {
    /// Host writer for target descriptor 3; absent for ordinary one-shot exec.
    pub worker_io: Option<Box<dyn AsyncReadWrite + Send + Unpin>>,
    pub stdout: tokio::sync::mpsc::Receiver<String>,
    pub stderr: tokio::sync::mpsc::Receiver<String>,
    pub exit_code: tokio::sync::oneshot::Receiver<i32>,
}

impl std::fmt::Debug for ExecHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecHandle")
            .field(
                "worker_io",
                &self.worker_io.as_ref().map(|_| "private stream"),
            )
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPlan {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmPlan {
    pub id: String,
    pub base_path: PathBuf,  // Real workspace
    pub realm_root: PathBuf, // Isolated copy location
    pub policy: Policy,
    pub snapshot_on_create: bool,
}

/// Private supervisor completion receipt, separate from the target's exit status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCompletion {
    pub cleanup_verified: bool,
    pub exit_code: i32,
}
impl ProcessCompletion {
    #[must_use]
    pub fn verified(&self) -> bool {
        self.cleanup_verified && (0..=255).contains(&self.exit_code)
    }
}
