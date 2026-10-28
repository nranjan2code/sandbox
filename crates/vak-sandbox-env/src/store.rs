use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use vak_sandbox_core::path::confined;

#[derive(Debug, Clone)]
pub struct EnvStore {
    root: PathBuf,
}

impl EnvStore {
    /// # Errors
    /// Returns filesystem errors creating the environment store layout.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("artifacts"))?;
        fs::create_dir_all(root.join("envs"))?;
        fs::create_dir_all(root.join("realms"))?;
        fs::create_dir_all(root.join("state"))?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    #[must_use]
    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }
    #[must_use]
    pub fn envs_dir(&self) -> PathBuf {
        self.root.join("envs")
    }
    #[must_use]
    pub fn realms_dir(&self) -> PathBuf {
        self.root.join("realms")
    }
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    #[must_use]
    pub fn has_env(&self, sha256: &str) -> bool {
        self.get_env_base(sha256).is_ok()
    }

    /// # Errors
    /// Rejects malformed digests, unsafe/missing paths and environment digest mismatches.
    pub fn get_env_base(&self, sha256: &str) -> Result<PathBuf> {
        validate_digest(sha256)?;
        let base =
            confined(&self.envs_dir(), sha256).map_err(|e| Error::Materialize(e.to_string()))?;
        if !base.is_dir() {
            return Err(Error::NotFound(format!("env base {sha256}")));
        }
        let got = crate::hash::sha256_tree(&base)?;
        if got != sha256 {
            return Err(Error::HashMismatch {
                expected: sha256.into(),
                got,
            });
        }
        Ok(base)
    }

    /// # Errors
    /// Rejects invalid digests, corrupt cached bytes, unsafe paths and persistence failures.
    pub fn put_artifact(&self, bytes: &[u8], expected_sha: &str) -> Result<PathBuf> {
        validate_digest(expected_sha)?;
        let got = crate::hash::sha256_bytes(bytes);
        if got != expected_sha {
            return Err(Error::HashMismatch {
                expected: expected_sha.into(),
                got,
            });
        }
        let directory = self.artifacts_dir();
        let path =
            confined(&directory, expected_sha).map_err(|e| Error::Materialize(e.to_string()))?;
        if path.exists() {
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(Error::Materialize("Artifact is not a regular file".into()));
            }
            let got = crate::hash::sha256_file(&path)?;
            if got != expected_sha {
                return Err(Error::HashMismatch {
                    expected: expected_sha.into(),
                    got,
                });
            }
            return Ok(path);
        }
        let mut file = tempfile::NamedTempFile::new_in(&directory)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        match file.persist_noclobber(&path) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A competing writer must satisfy the same integrity contract.
                return self.put_artifact(bytes, expected_sha);
            }
            Err(e) => return Err(e.error.into()),
        }
        std::fs::File::open(directory)?.sync_all()?;
        Ok(path)
    }

    #[must_use]
    pub fn default_root() -> PathBuf {
        std::env::var("HOME").map_or_else(
            |_| PathBuf::from("/tmp/vak-sandbox"),
            |home| PathBuf::from(home).join(".cache").join("vak-sandbox"),
        )
    }
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Materialize(
            "Expected a lowercase SHA-256 identifier".into(),
        ));
    }
    Ok(())
}
