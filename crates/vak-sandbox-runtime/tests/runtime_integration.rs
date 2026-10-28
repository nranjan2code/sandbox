#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for runtime manager and heartbeat

#[cfg(test)]
mod integration {
    use std::sync::Arc;
    use tempfile::TempDir;
    use vak_sandbox_env::EnvStore;
    use vak_sandbox_runtime::{CreateRealmRequest, SandboxManager};

    #[tokio::test]
    async fn create_minimal_realm() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store.clone());
        let h = mgr
            .create_realm(CreateRealmRequest {
                env_sha256: None,
                env_id: None,
                base_path: None,
                policy_overrides: None,
            })
            .await
            .unwrap();
        assert!(matches!(h.status, vak_sandbox_runtime::RealmStatus::Ready));
        assert!(h.realm_root.exists());
        assert!(h.writable_layer.exists());
    }

    #[tokio::test]
    async fn heartbeat_lifecycle() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store);
        let h = mgr
            .create_realm(CreateRealmRequest {
                env_sha256: None,
                env_id: None,
                base_path: None,
                policy_overrides: None,
            })
            .await
            .unwrap();
        let monitor = mgr.heartbeat_monitor();
        assert!(monitor.is_alive(&h.realm_id)); // Creation records the first observation.
        mgr.ping(&h.realm_id).await;
        assert!(monitor.is_alive(&h.realm_id));
        let all = monitor.get_all();
        assert!(!all.is_empty());
    }

    #[tokio::test]
    async fn list_realms() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store);
        let h1 = mgr
            .create_realm(CreateRealmRequest {
                env_sha256: None,
                env_id: None,
                base_path: None,
                policy_overrides: None,
            })
            .await
            .unwrap();
        let h2 = mgr
            .create_realm(CreateRealmRequest {
                env_sha256: None,
                env_id: None,
                base_path: None,
                policy_overrides: None,
            })
            .await
            .unwrap();
        let list = mgr.list_realms().await;
        assert_eq!(list.len(), 2);
        assert!(list.iter().any(|r| r.realm_id == h1.realm_id));
        assert!(list.iter().any(|r| r.realm_id == h2.realm_id));
    }

    #[tokio::test]
    async fn get_realm() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store);
        let h = mgr
            .create_realm(CreateRealmRequest {
                env_sha256: None,
                env_id: None,
                base_path: None,
                policy_overrides: None,
            })
            .await
            .unwrap();
        let fetched = mgr.get_realm(&h.realm_id).await.unwrap();
        assert_eq!(fetched.realm_id, h.realm_id);
        assert!(mgr.get_realm("nonexistent").await.is_none());
    }
}

#[tokio::test]
async fn verified_environment_realms_do_not_promote_into_the_cache() {
    use std::{fs, sync::Arc};
    use vak_sandbox_env::{EnvStore, sha256_tree};
    use vak_sandbox_runtime::{CreateRealmRequest, SandboxManager};
    let temp = tempfile::tempdir().unwrap();
    let envs = Arc::new(EnvStore::new(temp.path()).unwrap());
    let staging = envs.envs_dir().join("staging");
    fs::create_dir(&staging).unwrap();
    fs::write(staging.join("readme"), "environment").unwrap();
    let digest = sha256_tree(&staging).unwrap();
    fs::rename(&staging, envs.envs_dir().join(&digest)).unwrap();
    let manager = SandboxManager::new(envs);
    let handle = manager
        .create_realm(CreateRealmRequest {
            env_sha256: Some(digest),
            env_id: None,
            base_path: None,
            policy_overrides: None,
        })
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(handle.realm_root.join("readme")).unwrap(),
        "environment"
    );
    let realms = manager.realms().unwrap();
    let lease = realms.lease(&handle.realm_id).unwrap();
    assert!(lease.record.base_path.is_none());
    fs::write(handle.realm_root.join("readme"), "changed").unwrap();
    assert!(!realms.review(&lease.record).unwrap().can_promote);
}
