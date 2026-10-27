use crate::{Heartbeat, HeartbeatMonitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use vak_sandbox_env::{materialize, EnvStore};

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
    realms: Arc<RwLock<HashMap<String, RealmHandle>>>,
    heartbeat: Arc<HeartbeatMonitor>,
}

impl SandboxManager {
    pub fn new(store: Arc<EnvStore>) -> Self {
        Self {
            store,
            realms: Arc::new(RwLock::new(HashMap::new())),
            heartbeat: Arc::new(HeartbeatMonitor::new(30)),
        }
    }

    pub async fn create_realm(&self, req: CreateRealmRequest) -> Result<RealmHandle> {
        let realm_id = Uuid::new_v4().to_string();
        let handle = RealmHandle {
            realm_id: realm_id.clone(),
            realm_root: self.store.realms_dir().join(&realm_id),
            writable_layer: self
                .store
                .realms_dir()
                .join(&realm_id)
                .join(".vak-sandbox-writable"),
            status: RealmStatus::Creating,
            created_at: chrono::Utc::now(),
        };

        self.realms
            .write()
            .await
            .insert(realm_id.clone(), handle.clone());

        if let Some(sha) = req.env_sha256 {
            let mat = materialize(&self.store, &sha, &realm_id)
                .map_err(|e| Error::Manager(e.to_string()))?;
            let mut updated = handle.clone();
            updated.realm_root = mat.realm_root;
            updated.writable_layer = mat.writable_layer;
            updated.status = RealmStatus::Ready;
            self.realms
                .write()
                .await
                .insert(realm_id.clone(), updated.clone());
            self.heartbeat.ping(Heartbeat {
                realm_id: realm_id.clone(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                pid: None,
                load: 0.0,
                mem_mb: 0,
                alive: true,
            });
            return Ok(updated);
        }

        tokio::fs::create_dir_all(&handle.realm_root)
            .await
            .map_err(|e| Error::Manager(e.to_string()))?;
        tokio::fs::create_dir_all(&handle.writable_layer)
            .await
            .map_err(|e| Error::Manager(e.to_string()))?;
        let mut updated = handle;
        updated.status = RealmStatus::Ready;
        self.realms
            .write()
            .await
            .insert(updated.realm_id.clone(), updated.clone());
        self.heartbeat.ping(Heartbeat {
            realm_id: updated.realm_id.clone(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            pid: None,
            load: 0.0,
            mem_mb: 0,
            alive: true,
        });
        Ok(updated)
    }

    pub async fn get_realm(&self, realm_id: &str) -> Option<RealmHandle> {
        self.realms.read().await.get(realm_id).cloned()
    }

    pub async fn list_realms(&self) -> Vec<RealmHandle> {
        self.realms.read().await.values().cloned().collect()
    }

    pub async fn destroy_realm(&self, realm_id: &str) -> Result<()> {
        let mut realms = self.realms.write().await;
        if let Some(mut h) = realms.remove(realm_id) {
            h.status = RealmStatus::Destroyed;
            // Clean up
            let _ = tokio::fs::remove_dir_all(&h.realm_root).await;
            Ok(())
        } else {
            Err(Error::Manager("Realm not found".into()))
        }
    }

    pub async fn ping(&self, realm_id: &str) {
        self.heartbeat.ping(Heartbeat {
            realm_id: realm_id.to_string(),
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
