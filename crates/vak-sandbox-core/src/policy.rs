use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    pub fs: FsPolicy,
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
    pub resources: ResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FsPolicy {
    /// Paths allowed for reading (deny all others)
    #[serde(default)]
    pub allow_read: Vec<PathBuf>,

    /// Paths allowed for writing (deny all others)
    #[serde(default)]
    pub allow_write: Vec<PathBuf>,

    /// Always deny these paths even if in allow lists
    #[serde(default)]
    pub deny: Vec<PathBuf>,

    /// Follow symlinks (dangerous, default false)
    #[serde(default)]
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent serialized capabilities preserve the public policy schema."
)]
pub struct NetworkPolicy {
    /// Allow network access at all (default false)
    #[serde(default)]
    pub allow: bool,

    /// Allow outbound connections (egress). If false and allow is true, only inbound allowed
    #[serde(default)]
    pub allow_outbound: bool,

    /// Allow inbound connections (ingress)
    #[serde(default)]
    pub allow_inbound: bool,

    /// Allow localhost connections
    #[serde(default)]
    pub allow_localhost: bool,

    /// Specific hosts/IPs allowed for outbound (CIDR notation not fully supported by seatbelt, use IPs)
    #[serde(default)]
    pub allow_hosts: Vec<String>,

    /// Specific ports allowed for outbound
    #[serde(default)]
    pub allow_ports: Vec<u16>,

    /// Allow DNS lookups (needs network access usually)
    #[serde(default)]
    pub allow_dns: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvPolicy {
    /// Only these env vars are passed to sandboxed process
    #[serde(default)]
    pub allow: HashSet<String>,

    /// Explicitly set these env vars
    #[serde(default)]
    pub set: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// Max CPU time in seconds (None = unlimited)
    pub max_cpu_seconds: Option<u64>,

    /// Max memory in bytes (None = unlimited)
    pub max_memory_bytes: Option<u64>,

    /// Max wall time in seconds
    pub max_wall_seconds: Option<u64>,

    /// Max number of processes
    pub max_processes: Option<u32>,

    /// Max file size in bytes
    pub max_file_size: Option<u64>,
}

impl ResourcePolicy {
    /// True when a caller asks the backend to enforce at least one resource limit.
    #[must_use]
    pub const fn has_requested_limits(&self) -> bool {
        self.max_cpu_seconds.is_some()
            || self.max_memory_bytes.is_some()
            || self.max_wall_seconds.is_some()
            || self.max_processes.is_some()
            || self.max_file_size.is_some()
    }
}

impl Policy {
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allow_path_read(mut self, path: PathBuf) -> Self {
        self.fs.allow_read.push(path);
        self
    }

    #[must_use]
    pub fn allow_path_write(mut self, path: PathBuf) -> Self {
        self.fs.allow_write.push(path);
        self
    }

    #[must_use]
    pub const fn allow_network(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = false;
        self.network.allow_localhost = true;
        self
    }

    #[must_use]
    pub const fn allow_network_full(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = true;
        self.network.allow_localhost = true;
        self.network.allow_dns = true;
        self
    }

    #[must_use]
    pub const fn allow_network_egress(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = false;
        self.network.allow_dns = true;
        self
    }

    #[must_use]
    pub fn allow_env(mut self, key: impl Into<String>) -> Self {
        self.env.allow.insert(key.into());
        self
    }
}
