use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub fs: FsPolicy,
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
    pub resources: ResourcePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPolicy {
    /// Only these env vars are passed to sandboxed process
    #[serde(default)]
    pub allow: HashSet<String>,
    
    /// Explicitly set these env vars
    #[serde(default)]
    pub set: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for Policy {
    fn default() -> Self {
        Self {
            fs: FsPolicy::default(),
            network: NetworkPolicy::default(),
            env: EnvPolicy::default(),
            resources: ResourcePolicy::default(),
        }
    }
}

impl Default for FsPolicy {
    fn default() -> Self {
        Self {
            allow_read: vec![],
            allow_write: vec![],
            deny: vec![],
            follow_symlinks: false,
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow: false,
            allow_outbound: false,
            allow_inbound: false,
            allow_localhost: false,
            allow_hosts: vec![],
            allow_ports: vec![],
            allow_dns: false,
        }
    }
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            allow: HashSet::new(),
            set: std::collections::HashMap::new(),
        }
    }
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            max_cpu_seconds: Some(3600),
            max_memory_bytes: Some(2 * 1024 * 1024 * 1024), // 2GB
            max_wall_seconds: Some(7200),
            max_processes: Some(256),
            max_file_size: Some(1024 * 1024 * 1024), // 1GB
        }
    }
}

impl Policy {
    pub fn deny_all() -> Self {
        Self::default()
    }
    
    pub fn allow_path_read(mut self, path: PathBuf) -> Self {
        self.fs.allow_read.push(path);
        self
    }
    
    pub fn allow_path_write(mut self, path: PathBuf) -> Self {
        self.fs.allow_read.push(path.clone());
        self.fs.allow_write.push(path);
        self
    }
    
    pub fn allow_network(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = false;
        self.network.allow_localhost = true;
        self
    }
    
    pub fn allow_network_full(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = true;
        self.network.allow_localhost = true;
        self.network.allow_dns = true;
        self
    }
    
    pub fn allow_network_egress(mut self) -> Self {
        self.network.allow = true;
        self.network.allow_outbound = true;
        self.network.allow_inbound = false;
        self.network.allow_dns = true;
        self
    }
    
    pub fn allow_env(mut self, key: impl Into<String>) -> Self {
        self.env.allow.insert(key.into());
        self
    }
}
