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

pub trait SandboxBackend: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn platforms(&self) -> &[&str];
    fn available(&self) -> bool;
    fn capabilities(&self) -> BackendCaps;

    fn create_process(&self, plan: &ProcessPlan) -> SandboxFuture<'_, Box<dyn SandboxEnv>>;
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
    fn destroy(&self) -> SandboxFuture<'_, ()>;
}

#[derive(Debug)]
pub struct ExecHandle {
    pub stdout: tokio::sync::mpsc::Receiver<String>,
    pub stderr: tokio::sync::mpsc::Receiver<String>,
    pub exit_code: tokio::sync::oneshot::Receiver<i32>,
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
