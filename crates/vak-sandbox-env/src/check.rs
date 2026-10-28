use crate::{EnvSpec, Result};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckReport {
    pub ok: bool,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub output: String,
}

/// Inspect declared binaries without executing environment- or spec-owned code.
/// Executable post-checks need the caller's explicit sandbox process plan.
///
/// # Errors
/// Returns filesystem errors if the environment root cannot be inspected.
pub fn check_env(spec: &EnvSpec, realm_root: &std::path::Path) -> Result<CheckReport> {
    let mut results = Vec::new();
    if let Some(checks) = &spec.checks {
        for bin in &checks.required_bins {
            let found = if bin.is_empty() || bin.contains('/') || bin.contains('\\') {
                None
            } else {
                [format!("bin/{bin}"), format!("usr/bin/{bin}")]
                    .into_iter()
                    .find_map(|relative| {
                        let candidate =
                            vak_sandbox_core::path::confined(realm_root, &relative).ok()?;
                        let metadata = std::fs::symlink_metadata(&candidate).ok()?;
                        #[cfg(unix)]
                        let executable = {
                            use std::os::unix::fs::PermissionsExt;
                            metadata.permissions().mode() & 0o111 != 0
                        };
                        #[cfg(not(unix))]
                        let executable = true;
                        (metadata.is_file() && executable).then_some(relative)
                    })
            };
            results.push(CheckResult {
                name: format!("bin:{bin}"),
                ok: found.is_some(),
                output: found.unwrap_or_else(|| "not found in environment".into()),
            });
        }
        for command in &checks.post_check {
            results.push(CheckResult {
                name: format!("check:{command}"),
                ok: false,
                output: "Post-check not executed: authorize an explicit sandbox process plan"
                    .into(),
            });
        }
    }
    Ok(CheckReport {
        ok: results.iter().all(|result| result.ok),
        checks: results,
    })
}
