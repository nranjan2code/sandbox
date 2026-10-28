use crate::{EnvStore, Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct MaterializedEnv {
    pub realm_root: PathBuf,
    pub base_root: PathBuf,
    pub writable_layer: PathBuf,
}

/// # Errors
/// Rejects invalid IDs, unverified environments, existing destinations, copy errors and hardening failures.
pub fn materialize(store: &EnvStore, sha256: &str, realm_id: &str) -> Result<MaterializedEnv> {
    let base_root = store.get_env_base(sha256)?;
    if uuid::Uuid::parse_str(realm_id).is_err() {
        return Err(Error::Materialize("Invalid Realm UUID".into()));
    }
    let realm_root = vak_sandbox_core::path::confined(&store.realms_dir(), realm_id)
        .map_err(|e| Error::Materialize(e.to_string()))?;
    let writable_layer = realm_root.join(".vak-sandbox-writable");

    fs::create_dir(&realm_root)?;
    if base_root.join(".vak-sandbox-writable").exists() {
        return Err(Error::Materialize(
            "Reserved writable layer in environment".into(),
        ));
    }
    fs::create_dir(&writable_layer)?;

    // Copy base environment contents into realm root
    #[cfg(target_os = "macos")]
    {
        if clonefile_materialize_contents(&base_root, &realm_root).is_err() {
            fallback_materialize_contents(&base_root, &realm_root)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback_materialize_contents(&base_root, &realm_root)?;
    }

    // The writable layer is not part of the immutable environment digest.
    fs::remove_dir(&writable_layer)?;
    if crate::hash::sha256_tree(&realm_root)? != sha256 {
        return Err(Error::Materialize(
            "Materialized environment integrity failed".into(),
        ));
    }
    fs::create_dir(&writable_layer)?;
    harden_base(&realm_root, &writable_layer)?;

    Ok(MaterializedEnv {
        realm_root,
        base_root,
        writable_layer,
    })
}

#[cfg(target_os = "macos")]
fn clonefile_materialize_contents(src: &Path, dst: &Path) -> Result<()> {
    // Copy contents of src into dst using clonefile where possible.
    // Use cp -c with explicit args to avoid shell interpolation of paths.
    let status = std::process::Command::new("/bin/cp")
        .env_clear()
        .arg("-cR")
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()?;
    if !status.success() {
        return Err(Error::Materialize("clonefile/cp -c failed".to_string()));
    }
    Ok(())
}

fn fallback_materialize_contents(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("/bin/cp")
        .env_clear()
        .arg("-R")
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()?;
    if !status.success() {
        return Err(Error::Materialize("copy failed".to_string()));
    }
    Ok(())
}

fn harden_base(realm_root: &Path, writable_layer: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in walkdir::WalkDir::new(realm_root)
            .contents_first(true)
            .follow_links(false)
        {
            let entry = entry.map_err(|e| Error::Materialize(e.to_string()))?;
            if entry.path().starts_with(writable_layer) {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            if !meta.is_dir() && !meta.is_file() {
                return Err(Error::Materialize("Unsafe environment entry".into()));
            }
            fs::set_permissions(
                entry.path(),
                fs::Permissions::from_mode(meta.permissions().mode() & 0o555),
            )?;
        }
    }
    Ok(())
}
