//! Path confinement - stolen in spirit from Vak/code's vak-sandbox
//!
//! Defense against path traversal, absolute paths, symlink escapes

use crate::{Error, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Confine a relative path to a root, rejecting escapes and symlinks
///
/// This is critical for security - prevents `../../../etc/passwd` style attacks
pub fn confined(root: &Path, relative: &str) -> Result<PathBuf> {
    let rel = Path::new(relative);

    // Reject absolute paths
    if rel.is_absolute() {
        return Err(Error::PathEscape(relative.to_string()));
    }

    // Reject parent directory traversal
    for component in rel.components() {
        if matches!(component, Component::ParentDir) {
            return Err(Error::PathEscape(relative.to_string()));
        }
    }

    // Canonicalize root
    let root = root
        .canonicalize()
        .map_err(|e| Error::Backend(format!("root unavailable: {e}")))?;

    let mut current = root.clone();

    // Walk each component checking for symlinks
    for component in rel.components() {
        match component {
            Component::Normal(name) => {
                current.push(name);
                // Check if current path is a symlink
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(Error::SymlinkEscape(relative.to_string()));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // File doesn't exist yet - that's ok for new files
                    }
                    Err(e) => return Err(Error::Io(e)),
                }
            }
            Component::CurDir => {}
            _ => return Err(Error::PathEscape(relative.to_string())),
        }
    }

    Ok(current)
}

/// Check if a path is safely contained within root
pub fn is_contained(root: &Path, path: &Path) -> Result<bool> {
    let root = root.canonicalize().map_err(|e| Error::Io(e))?;
    let path = path.canonicalize().map_err(|e| Error::Io(e))?;

    Ok(path.starts_with(&root))
}

/// Canonicalize and verify path doesn't escape
pub fn safe_canonicalize(root: &Path, path: &Path) -> Result<PathBuf> {
    let root = root.canonicalize().map_err(|e| Error::Io(e))?;
    let canonical = path.canonicalize().map_err(|e| Error::Io(e))?;

    if !canonical.starts_with(&root) {
        return Err(Error::PathEscape(path.display().to_string()));
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn rejects_parent_traversal() {
        let tmp = TempDir::new().unwrap();
        assert!(confined(tmp.path(), "../etc/passwd").is_err());
        assert!(confined(tmp.path(), "foo/../../etc/passwd").is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        let tmp = TempDir::new().unwrap();
        assert!(confined(tmp.path(), "/etc/passwd").is_err());
    }

    #[test]
    fn allows_normal_paths() {
        let tmp = TempDir::new().unwrap();
        let result = confined(tmp.path(), "foo/bar.txt");
        assert!(result.is_ok());
    }
}
