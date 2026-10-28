#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for environment management

#[cfg(test)]
mod integration {
    use std::fs;
    use tempfile::TempDir;
    use vak_sandbox_env::{EnvStore, sha256_bytes, sha256_file};

    #[test]
    fn store_creates_full_layout() {
        let td = TempDir::new().unwrap();
        let store = EnvStore::new(td.path()).unwrap();
        assert!(store.artifacts_dir().exists());
        assert!(store.envs_dir().exists());
        assert!(store.realms_dir().exists());
        assert!(store.state_dir().exists());
        assert_eq!(store.artifacts_dir(), td.path().join("artifacts"));
    }

    #[test]
    fn hash_consistency() {
        let data = b"test data for hashing";
        let h1 = sha256_bytes(data);
        let h2 = sha256_bytes(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_file_matches_bytes() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("test.bin");
        let data = b"hello world";
        fs::write(&p, data).unwrap();
        assert_eq!(sha256_file(&p).unwrap(), sha256_bytes(data));
    }

    #[test]
    fn put_artifact_verifies_hash() {
        let td = TempDir::new().unwrap();
        let store = EnvStore::new(td.path()).unwrap();
        let data = b"artifact content";
        let h = sha256_bytes(data);
        let path = store.put_artifact(data, &h).unwrap();
        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), data);
    }

    #[test]
    fn put_artifact_rejects_bad_hash() {
        let td = TempDir::new().unwrap();
        let store = EnvStore::new(td.path()).unwrap();
        let data = b"artifact content";
        let result = store.put_artifact(data, "deadbeef");
        assert!(result.is_err());
    }
}

#[test]
fn environment_identifiers_and_cached_artifacts_are_verified() {
    use vak_sandbox_env::{EnvStore, sha256_bytes, sha256_tree};
    let temp = tempfile::tempdir().unwrap();
    let store = EnvStore::new(temp.path()).unwrap();
    for id in ["../outside", "/tmp", "not-a-digest"] {
        assert!(store.get_env_base(id).is_err());
    }
    let staging = store.envs_dir().join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(staging.join("file"), "original").unwrap();
    let digest = sha256_tree(&staging).unwrap();
    let base = store.envs_dir().join(&digest);
    std::fs::rename(staging, &base).unwrap();
    assert!(store.get_env_base(&digest).is_ok());
    assert!(vak_sandbox_env::materialize(&store, &digest, "../escape").is_err());
    let id = uuid::Uuid::new_v4().to_string();
    let materialized = vak_sandbox_env::materialize(&store, &digest, &id).unwrap();
    assert_eq!(
        std::fs::read_to_string(materialized.realm_root.join("file")).unwrap(),
        "original"
    );
    assert!(vak_sandbox_env::materialize(&store, &digest, &id).is_err());
    std::fs::write(base.join("file"), "changed").unwrap();
    assert!(store.get_env_base(&digest).is_err());
    let digest = sha256_bytes(b"artifact");
    let artifact = store.put_artifact(b"artifact", &digest).unwrap();
    std::fs::write(artifact, "corrupted").unwrap();
    assert!(store.put_artifact(b"artifact", &digest).is_err());
}

#[test]
fn environment_post_checks_never_execute_on_the_host() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("must-not-exist");
    let spec: vak_sandbox_env::EnvSpec = toml::from_str(&format!(
        r#"
[env]
id = "fixture"
version = "1"
description = "Static checking fixture"
[base]
kind = "prebuilt"
artifact = "fixture"
sha256 = "unused"
[checks]
required_bins = ["sh"]
post_check = ["/usr/bin/touch {}"]
"#,
        marker.display()
    ))
    .unwrap();
    let report = vak_sandbox_env::check_env(&spec, temp.path()).unwrap();
    assert!(!report.ok);
    assert!(!marker.exists());
    assert!(report.checks.iter().all(|check| !check.ok));
}
