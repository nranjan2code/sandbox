#[cfg(test)]
mod cases {
    use crate::{CreateRealmRequest, SandboxManager};
    use std::sync::Arc;
    use tempfile::TempDir;
    use vak_sandbox_env::EnvStore;

    #[tokio::test]
    async fn create_realm_minimal() {
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
        assert!(matches!(h.status, crate::RealmStatus::Ready));
        assert!(h.realm_root.exists());
    }

    #[tokio::test]
    async fn heartbeat_ping() {
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
        mgr.ping(&h.realm_id).await;
        assert!(mgr.heartbeat_monitor().is_alive(&h.realm_id));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_contract {
    use std::path::Path;

    #[tokio::test]
    async fn unsupported_execution_fails_before_running_a_command() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("must-not-exist");
        let result = crate::process::execute(
            temp.path(),
            temp.path(),
            "/usr/bin/touch",
            &[marker.display().to_string()],
        )
        .await;

        assert!(result.unwrap_err().contains("no command was run"));
        assert!(!Path::new(&marker).exists());
    }
}
