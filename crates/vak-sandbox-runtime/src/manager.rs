use crate::realm::{RealmRecord, RealmStore};
use crate::{Heartbeat, HeartbeatMonitor};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use vak_sandbox_env::EnvStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRealmRequest {
    pub env_sha256: Option<String>,
    pub env_id: Option<String>,
    pub base_path: Option<PathBuf>,
    pub policy_overrides: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmHandle {
    pub realm_id: String,
    pub realm_root: PathBuf,
    pub writable_layer: PathBuf,
    pub status: RealmStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RealmStatus {
    Creating,
    Ready,
    Running,
    Stopped,
    Promoted,
    Destroyed,
    Error(String),
}
#[derive(Debug)]
pub struct SandboxManager {
    store: Arc<EnvStore>,
    heartbeat: Arc<HeartbeatMonitor>,
}
impl SandboxManager {
    pub fn new(store: Arc<EnvStore>) -> Self {
        Self {
            store,
            heartbeat: Arc::new(HeartbeatMonitor::new(30)),
        }
    }
    pub fn realms(&self) -> Result<RealmStore> {
        RealmStore::open(self.store.root()).map_err(|e| Error::Manager(e.to_string()))
    }
    fn handle(record: RealmRecord) -> RealmHandle {
        RealmHandle {
            realm_id: record.realm_id,
            realm_root: record.workspace.clone(),
            writable_layer: record.workspace,
            status: if record.status == "ready" {
                RealmStatus::Ready
            } else {
                RealmStatus::Error(record.status)
            },
            created_at: chrono::DateTime::parse_from_rfc3339(&record.created_at)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
        }
    }
    pub async fn create_realm(&self, req: CreateRealmRequest) -> Result<RealmHandle> {
        if req.policy_overrides.is_some() || req.env_id.is_some() {
            return Err(Error::Manager(
                "Policy overrides and environment aliases are not supported".into(),
            ));
        }
        if req.env_sha256.is_some() && req.base_path.is_some() {
            return Err(Error::Manager(
                "Choose either an environment or a project".into(),
            ));
        }
        let source = if let Some(sha) = req.env_sha256 {
            Some(
                self.store
                    .get_env_base(&sha)
                    .map_err(|e| Error::Manager(e.to_string()))?,
            )
        } else {
            req.base_path
        };
        let record = self
            .realms()?
            .create(source.as_deref())
            .map_err(|e| Error::Manager(e.to_string()))?;
        self.ping(&record.realm_id).await;
        Ok(Self::handle(record))
    }
    pub async fn get_realm(&self, realm_id: &str) -> Option<RealmHandle> {
        self.realms()
            .ok()?
            .lease(realm_id)
            .ok()
            .map(|l| Self::handle(l.record))
    }
    pub async fn list_realms(&self) -> Vec<RealmHandle> {
        self.realms()
            .and_then(|r| r.list().map_err(|e| Error::Manager(e.to_string())))
            .unwrap_or_default()
            .into_iter()
            .map(Self::handle)
            .collect()
    }
    pub async fn destroy_realm(&self, realm_id: &str) -> Result<()> {
        let store = self.realms()?;
        let lease = store
            .lease(realm_id)
            .map_err(|e| Error::Manager(e.to_string()))?;
        store
            .destroy(&lease)
            .map_err(|e| Error::Manager(e.to_string()))
    }
    pub async fn ping(&self, realm_id: &str) {
        self.heartbeat.ping(Heartbeat {
            realm_id: realm_id.into(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            pid: None,
            load: 0.0,
            mem_mb: 0,
            alive: true,
        });
    }
    pub fn heartbeat_monitor(&self) -> Arc<HeartbeatMonitor> {
        self.heartbeat.clone()
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manager error: {0}")]
    Manager(String),
}
pub type Result<T> = std::result::Result<T, Error>;
