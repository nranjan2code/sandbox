//! Integration tests for runtime manager and heartbeat

#[cfg(test)]
mod integration {
    use vak_sandbox_runtime::{SandboxManager, CreateRealmRequest};
    use vak_sandbox_env::EnvStore;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[tokio::test]
    async fn create_minimal_realm() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store.clone());
        let h = mgr.create_realm(CreateRealmRequest { 
            env_sha256: None, 
            env_id: None, 
            base_path: None, 
            policy_overrides: None 
        }).await.unwrap();
        assert!(matches!(h.status, vak_sandbox_runtime::RealmStatus::Ready));
        assert!(h.realm_root.exists());
        assert!(h.writable_layer.exists());
    }

    #[tokio::test]
    async fn heartbeat_lifecycle() {
        let td = TempDir::new().unwrap();
        let store = Arc::new(EnvStore::new(td.path()).unwrap());
        let mgr = SandboxManager::new(store);
        let h = mgr.create_realm(CreateRealmRequest { 
            env_sha256: None, 
            env_id: None, 
            base_path: None, 
            policy_overrides: None 
        }).await.unwrap();
        let monitor = mgr.heartbeat_monitor();
        assert!(!monitor.is_alive(&h.realm_id)); // No ping yet
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
        let h1 = mgr.create_realm(CreateRealmRequest { env_sha256: None, env_id: None, base_path: None, policy_overrides: None }).await.unwrap();
        let h2 = mgr.create_realm(CreateRealmRequest { env_sha256: None, env_id: None, base_path: None, policy_overrides: None }).await.unwrap();
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
        let h = mgr.create_realm(CreateRealmRequest { env_sha256: None, env_id: None, base_path: None, policy_overrides: None }).await.unwrap();
        let fetched = mgr.get_realm(&h.realm_id).await.unwrap();
        assert_eq!(fetched.realm_id, h.realm_id);
        assert!(mgr.get_realm("nonexistent").await.is_none());
    }
}
