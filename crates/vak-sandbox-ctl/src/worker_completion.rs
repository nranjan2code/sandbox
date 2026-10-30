//! Host-owned completion evidence never travels through target protocol or log
//! streams. An absent, partial or unverified record cannot authorize a refund.
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

pub struct CompletionRequest {
    pub path: PathBuf,
    pub invocation_id: String,
}

pub struct CompletionRecord {
    file: File,
    invocation_id: String,
}

#[derive(serde::Serialize)]
struct Receipt<'a> {
    version: u8,
    invocation_id: &'a str,
    cleanup_verified: bool,
    exit_code: Option<i32>,
}

impl CompletionRecord {
    pub fn prepare(request: CompletionRequest, grants: &[PathBuf]) -> anyhow::Result<Self> {
        if request.invocation_id.is_empty()
            || request.invocation_id.len() > 128
            || !request
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            anyhow::bail!("invalid worker completion invocation identity");
        }
        let parent = request
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("completion record needs a private parent directory"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!("worker completion parent must be a real private directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                anyhow::bail!("worker completion parent must be owner-only");
            }
        }
        let parent = parent.canonicalize()?;
        if grants.iter().any(|root| parent.starts_with(root)) {
            anyhow::bail!("worker completion record must be outside every target grant");
        }
        let name = request
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid worker completion filename"))?;
        if name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            anyhow::bail!("invalid worker completion filename");
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut record = Self {
            file: options.open(parent.join(name))?,
            invocation_id: request.invocation_id,
        };
        record.write(None)?;
        File::open(parent)?.sync_all()?;
        Ok(record)
    }

    pub fn complete(mut self, exit_code: i32) -> anyhow::Result<()> {
        if !(0..=255).contains(&exit_code) {
            anyhow::bail!("worker cleanup has no verified target exit status");
        }
        self.write(Some(exit_code))
    }

    fn write(&mut self, exit_code: Option<i32>) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(&Receipt {
            version: 1,
            invocation_id: &self.invocation_id,
            cleanup_verified: exit_code.is_some(),
            exit_code,
        })?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(&bytes)?;
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_is_exclusive_private_and_unverified_until_trusted_completion() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("run-1.json");
        let request = || CompletionRequest {
            path: path.clone(),
            invocation_id: "run-1".into(),
        };
        let record = CompletionRecord::prepare(request(), &[]).unwrap();
        let before: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(before["cleanup_verified"], false);
        assert!(before["exit_code"].is_null());
        assert!(CompletionRecord::prepare(request(), &[]).is_err());
        assert!(
            CompletionRecord::prepare(
                CompletionRequest {
                    path: root.path().join("covered.json"),
                    invocation_id: "run-2".into()
                },
                &[root.path().canonicalize().unwrap()]
            )
            .is_err()
        );
        record.complete(126).unwrap();
        let after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(after["cleanup_verified"], true);
        assert_eq!(after["exit_code"], 126);
        assert_eq!(after["invocation_id"], "run-1");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
