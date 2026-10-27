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
pub struct BackendCaps {
    pub process_jail: bool,
    pub realm_isolation: bool,
    pub promotion: bool,
    pub rollback: bool,
    pub network_control: bool,
    pub resource_limits: bool,
    pub symlink_protection: bool,
}

pub trait SandboxBackend: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn platforms(&self) -> &[&str];
    fn available(&self) -> bool;
    fn capabilities(&self) -> BackendCaps;

    fn create_process(
        &self,
        plan: &ProcessPlan,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>>;
    fn create_realm(
        &self,
        plan: &RealmPlan,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>>;
}

pub trait SandboxEnv: Send + Sync {
    fn id(&self) -> &str;
    fn mode(&self) -> SandboxMode;

    fn exec(
        &self,
        cmd: &str,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>>;
    fn destroy(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
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
