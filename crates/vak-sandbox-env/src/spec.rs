use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSpec {
    pub env: EnvMeta,
    pub base: BaseSpec,
    #[serde(default)]
    pub tools: HashMap<String, ToolSpec>,
    #[serde(default)]
    pub policy_defaults: Option<PolicyDefaults>,
    #[serde(default)]
    pub checks: Option<Checks>,
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvMeta {
    pub id: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub arch: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseSpec {
    pub kind: String, // "prebuilt"
    pub artifact: String,
    pub sha256: String,
    #[serde(default)]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub check: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    #[serde(default)]
    pub network: Option<NetworkDefault>,
    #[serde(default)]
    pub fs_allow_write: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDefault {
    #[serde(default)]
    pub egress: bool,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checks {
    #[serde(default)]
    pub required_bins: Vec<String>,
    #[serde(default)]
    pub post_check: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    pub src: String,
    pub dst: String,
    #[serde(default)]
    pub ro: bool,
}

/// # Errors
/// Returns file-read or TOML decoding errors. It never executes spec commands.
pub fn load_spec(path: &Path) -> Result<EnvSpec> {
    let content = fs::read_to_string(path)?;
    let spec: EnvSpec = toml::from_str(&content)?;
    Ok(spec)
}
