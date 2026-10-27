//! Integration tests for environment management

#[cfg(test)]
mod integration {
    use vak_sandbox_env::{EnvStore, sha256_bytes, sha256_file};
    use std::fs;
    use tempfile::TempDir;

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
        fs::read(&path).unwrap().eq(data);
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
