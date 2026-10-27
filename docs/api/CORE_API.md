# Core API Documentation

## vak-sandbox-core

### Traits

#### `SandboxBackend`
```rust
pub trait SandboxBackend: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn platforms(&self) -> &[&str];
    fn available(&self) -> bool;
    fn capabilities(&self) -> BackendCaps;
    fn create_process(&self, plan: &ProcessPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>>;
    fn create_realm(&self, plan: &RealmPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>>;
}
```

#### `SandboxEnv`
```rust
pub trait SandboxEnv: Send + Sync {
    fn id(&self) -> &str;
    fn mode(&self) -> SandboxMode;
    fn exec(&self, cmd: &str, args: &[String], env: &HashMap<String, String>) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>>;
    fn destroy(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}
```

### Policy

```rust
pub struct Policy {
    pub fs: FsPolicy,
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
    pub resources: ResourcePolicy,
}
```

Builder methods:
- `Policy::deny_all()` - Create deny-by-default policy
- `.allow_path_read(path)` - Allow reading
- `.allow_path_write(path)` - Allow reading and writing
- `.allow_network()` - Allow localhost network
- `.allow_network_full()` - Allow full network access
- `.allow_network_egress()` - Allow outbound only
- `.allow_env(key)` - Allow environment variable

### Path Confinement

```rust
pub fn confined(root: &Path, relative: &str) -> Result<PathBuf>;
pub fn is_contained(root: &Path, path: &Path) -> Result<bool>;
pub fn safe_canonicalize(root: &Path, path: &Path) -> Result<PathBuf>;
```

All functions reject path traversal, absolute paths, and symlink escapes.

### Errors

```rust
pub enum Error {
    PathEscape(String),
    PathNotAllowed(String),
    SymlinkEscape(String),
    MissingFile(PathBuf),
    CandidateChanged(String),
    Conflict(String),
    BackendNotAvailable(String),
    Backend(String),
    Journal(String),
    Promotion(String),
    InvalidPolicy(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}
```
