//! vak-sandbox-core: Runtime-agnostic execution sandbox
//! 
//! Two modes:
//! - ProcessSandbox: Jail a single process with OS-level restrictions
//! - RealmSandbox: Isolated workspace for agent work with reviewable promotion

pub mod error;
pub mod policy;
pub mod path;
pub mod backend;

pub use error::{Error, Result};
pub use policy::{Policy, NetworkPolicy, FsPolicy, EnvPolicy, ResourcePolicy};
pub use path::confined;
pub use backend::{SandboxBackend, SandboxEnv, BackendCaps, SandboxMode, ProcessPlan, RealmPlan, ExecHandle};
