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

### Journal (Promotion)

```rust
pub struct PromotionJournal { ... }
pub struct JournalEntry { id, timestamp, operation, status, workspace_root }
pub enum JournalOp { Begin, Backup, Change, Apply, Rollback, Commit, Abort }
pub enum ChangeAction { Create, Modify, Delete }
pub enum JournalStatus { Pending, Applied, Committed, RolledBack, Failed }

// Methods
PromotionJournal::new(journal_dir) -> Result<Self>
.begin(realm_id, base_path) -> Result<String>
.backup(file, backup_path) -> Result<()>
.change(file, action) -> Result<()>
.commit() -> Result<()>
.abort() -> Result<()>
.load_journal(id) -> Result<Vec<JournalEntry>>
.list_incomplete() -> Result<Vec<String>>
```

### Runtime

```rust
pub struct SandboxManager { ... }
pub struct CreateRealmRequest { env_sha256, env_id, base_path, policy_overrides }
pub struct RealmHandle { realm_id, realm_root, writable_layer, status, created_at }
pub enum RealmStatus { Creating, Ready, Running, Stopped, Promoted, Destroyed, Error }

// Methods
SandboxManager::new(store) -> Self
.create_realm(req) -> Result<RealmHandle>
.get_realm(id) -> Option<RealmHandle>
.list_realms() -> Vec<RealmHandle>
.destroy_realm(id) -> Result<()>
.ping(id)
.heartbeat_monitor() -> Arc<HeartbeatMonitor>

pub struct Promoter { ... }
pub struct PromotionPlan { realm_root, base_path, changes }
pub struct PromotionReceipt { journal_id, promoted_files, backed_up }

Promoter::new(state_dir) -> Result<Self>
.promote(plan) -> Result<PromotionReceipt>
.rollback(journal_id) -> Result<()>

pub struct HeartbeatMonitor { ... }
.heartbeat.ping(hb)
.is_alive(realm_id) -> bool
.get_all() -> Vec<Heartbeat>
.check_stale() -> Vec<String>

pub enum ControlMessage { Ping, Exec, Snapshot, Promote, Destroy, Status }
pub enum ControlResponse { Pong, ExecResult, Snapshot, Promoted, Destroyed, Status, Error }
```
