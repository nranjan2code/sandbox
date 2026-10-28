use crate::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// # Errors
/// Returns errors opening or reading the file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash regular environment content, paths and permissions in deterministic order.
/// Symlinks and special files cannot become executable environment inputs.
///
/// # Errors
/// Rejects non-UTF-8 paths, symlinks, special files, size/count limits and filesystem errors.
pub fn sha256_tree(root: &Path) -> Result<String> {
    use std::collections::BTreeMap;
    use vak_sandbox_core::path::confined;
    let mut entries = BTreeMap::new();
    let mut total = 0u64;
    for entry in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = entry.map_err(|e| crate::Error::Materialize(e.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| crate::Error::Materialize(e.to_string()))?
            .to_str()
            .ok_or_else(|| crate::Error::Materialize("Environment paths must be UTF-8".into()))?;
        let path =
            confined(root, relative).map_err(|e| crate::Error::Materialize(e.to_string()))?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(crate::Error::Materialize(
                "Environment entries must be regular files or directories".into(),
            ));
        }
        let size = if metadata.is_file() {
            metadata.len()
        } else {
            0
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| crate::Error::Materialize("Environment size overflow".into()))?;
        if total > 512 * 1024 * 1024 || entries.len() >= 50_000 || relative.len() > 512 {
            return Err(crate::Error::Materialize(
                "Environment exceeds copy bounds".into(),
            ));
        }
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = 0u32;
        entries.insert(
            relative.to_owned(),
            (
                metadata.is_dir(),
                size,
                mode,
                if metadata.is_file() {
                    sha256_file(&path)?
                } else {
                    String::new()
                },
            ),
        );
    }
    let bytes =
        serde_json::to_vec(&entries).map_err(|e| crate::Error::Materialize(e.to_string()))?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(crate::Error::Materialize(
            "Environment manifest too large".into(),
        ));
    }
    Ok(sha256_bytes(&bytes))
}
