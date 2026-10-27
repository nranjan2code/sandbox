use crate::{EnvStore, Error, Result};
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

    // Copy base environment contents into realm root
    #[cfg(target_os = "macos")]
    {
        if let Err(_) = clonefile_materialize_contents(&base_root, &realm_root) {
            fallback_materialize_contents(&base_root, &realm_root)?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback_materialize_contents(&base_root, &realm_root)?;
    }

    harden_base(&realm_root, &writable_layer)?;

    Ok(MaterializedEnv {
        realm_root,
        base_root,
        writable_layer,
    })
}

#[cfg(target_os = "macos")]
fn clonefile_materialize_contents(src: &Path, dst: &Path) -> Result<()> {
    // Copy contents of src into dst using clonefile where possible
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("cp -cR \"{}\"/. \"{}\"/", src.display(), dst.display()))
        .status()?;
    if !status.success() {
        return Err(Error::Materialize("clonefile/cp -c failed".to_string()));
    }
    Ok(())
}

fn fallback_materialize_contents(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("cp -R \"{}\"/. \"{}\"/", src.display(), dst.display()))
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
