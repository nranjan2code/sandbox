use crate::{Error, Result, EnvStore};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct MaterializedEnv {
    pub realm_root: PathBuf,
    pub base_root: PathBuf,
    pub writable_layer: PathBuf,
}

pub fn materialize(store: &EnvStore, sha256: &str, realm_id: &str) -> Result<MaterializedEnv> {
    let base_root = store.get_env_base(sha256)?;
    let realm_root = store.realms_dir().join(realm_id);
    let writable_layer = realm_root.join(".vak-sandbox-writable");
    
    fs::create_dir_all(&realm_root)?;
    fs::create_dir_all(&writable_layer)?;
    
    // Try CoW on macOS (clonefile), fallback to hardlinks
    #[cfg(target_os = "macos")]
    {
        if let Err(_) = clonefile_materialize(&base_root, &realm_root) {
            fallback_materialize(&base_root, &realm_root)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback_materialize(&base_root, &realm_root)?;
    }
    
    // Make realm_root read-only except writable_layer
    harden_base(&realm_root, &writable_layer)?;
    
    Ok(MaterializedEnv { realm_root, base_root, writable_layer })
}

#[cfg(target_os = "macos")]
fn clonefile_materialize(src: &Path, dst: &Path) -> Result<()> {
    use std::ffi::CString;
    // Use cp -c as reliable fallback for now, can optimize to clonefile syscall later
    let status = std::process::Command::new("cp")
        .args(["-cR", &src.to_string_lossy(), &dst.to_string_lossy()])
        .status()?;
    if !status.success() {
        return Err(Error::Materialize("clonefile/cp -c failed".to_string()));
    }
    Ok(())
}

fn fallback_materialize(src: &Path, dst: &Path) -> Result<()> {
    // Try hardlinks where possible for speed/space
    let status = std::process::Command::new("cp")
        .args(["-R", &src.to_string_lossy(), &dst.to_string_lossy()])
        .status()?;
    if !status.success() {
        return Err(Error::Materialize("copy failed".to_string()));
    }
    Ok(())
}

fn harden_base(realm_root: &Path, writable_layer: &Path) -> Result<()> {
    // Make everything read-only except writable_layer
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Walk and make read-only (best effort)
        let _ = walkdir::WalkDir::new(realm_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path();
                !p.starts_with(writable_layer)
            })
            .for_each(|e| {
                if let Ok(meta) = e.metadata() {
                    let mut perms = meta.permissions();
                    let mode = perms.mode() & 0o555;
                    perms.set_mode(mode);
                    let _ = fs::set_permissions(e.path(), perms);
                }
            });
    }
    Ok(())
}
