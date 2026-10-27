use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct EnvStore {
    root: PathBuf,
}

impl EnvStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("artifacts"))?;
        fs::create_dir_all(root.join("envs"))?;
        fs::create_dir_all(root.join("realms"))?;
        fs::create_dir_all(root.join("state"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join("envs")
    }
    pub fn realms_dir(&self) -> PathBuf {
        self.root.join("realms")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    pub fn has_env(&self, sha256: &str) -> bool {
        self.envs_dir().join(sha256).exists()
    }

    pub fn get_env_base(&self, sha256: &str) -> Result<PathBuf> {
        let base = self.envs_dir().join(sha256);
        if !base.exists() {
            return Err(Error::NotFound(format!("env base {sha256}")));
        }
        Ok(base)
    }

    pub fn put_artifact(&self, bytes: &[u8], expected_sha: &str) -> Result<PathBuf> {
        let got = crate::hash::sha256_bytes(bytes);
        if got != expected_sha {
            return Err(Error::HashMismatch {
                expected: expected_sha.to_string(),
                got,
            });
        }
        let path = self.artifacts_dir().join(expected_sha);
        if !path.exists() {
            fs::write(&path, bytes)?;
        }
        Ok(path)
    }

    pub fn default_root() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".cache").join("vak-sandbox")
        } else {
            PathBuf::from("/tmp/vak-sandbox")
        }
    }
}
