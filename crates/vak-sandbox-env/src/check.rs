use crate::{Result, EnvSpec, Error};
use std::process::Command;

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

pub fn check_env(spec: &EnvSpec, realm_root: &std::path::Path) -> Result<CheckReport> {
    let mut results = Vec::new();
    
    if let Some(checks) = &spec.checks {
        // Check required bins
        for bin in &checks.required_bins {
            let which = Command::new("which")
                .arg(bin)
                .current_dir(realm_root)
                .output();
            match which {
                Ok(o) if o.status.success() => {
                    results.push(CheckResult {
                        name: format!("bin:{bin}"),
                        ok: true,
                        output: String::from_utf8_lossy(&o.stdout).trim().to_string(),
                    });
                }
                _ => {
                    results.push(CheckResult {
                        name: format!("bin:{bin}"),
                        ok: false,
                        output: "not found".to_string(),
                    });
                }
            }
        }
        
        // Run post checks
        for cmd in &checks.post_check {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() { continue; }
            let out = Command::new(parts[0])
                .args(&parts[1..])
                .current_dir(realm_root)
                .env("PATH", format!("{}/usr/bin:{}/bin:{}", realm_root.display(), realm_root.display(), std::env::var("PATH").unwrap_or_default()))
                .output();
            match out {
                Ok(o) => {
                    let output = if o.status.success() {
                        String::from_utf8_lossy(&o.stdout).trim().to_string()
                    } else {
                        String::from_utf8_lossy(&o.stderr).trim().to_string()
                    };
                    results.push(CheckResult {
                        name: format!("check:{cmd}"),
                        ok: o.status.success(),
                        output,
                    });
                }
                Err(e) => {
                    results.push(CheckResult {
                        name: format!("check:{cmd}"),
                        ok: false,
                        output: e.to_string(),
                    });
                }
            }
        }
    }
    
    let ok = results.iter().all(|r| r.ok);
    Ok(CheckReport { ok, checks: results })
}
