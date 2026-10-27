#[cfg(test)]
mod tests {
    use crate::{EnvStore, sha256_bytes, sha256_file};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn hash_bytes() {
        let h = sha256_bytes(b"hello");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn store_layout() {
        let td = TempDir::new().unwrap();
        let store = EnvStore::new(td.path()).unwrap();
        assert!(store.artifacts_dir().exists());
        assert!(store.envs_dir().exists());
        assert!(store.realms_dir().exists());
    }

    #[test]
    fn hash_file() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("x.txt");
        fs::write(&p, b"test").unwrap();
        let h = sha256_file(&p).unwrap();
        assert_eq!(h.len(), 64);
    }
}
