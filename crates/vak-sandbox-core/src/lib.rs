//! vak-sandbox-core: Runtime-agnostic execution sandbox
//!
//! Two modes:
//! - ProcessSandbox: Jail a single process with OS-level restrictions
//! - RealmSandbox: Isolated workspace for agent work with reviewable promotion

pub mod backend;
pub mod error;
pub mod path;
pub mod policy;

pub use backend::{
    BackendCaps, ExecHandle, ProcessPlan, RealmPlan, SandboxBackend, SandboxEnv, SandboxMode,
};
pub use error::{Error, Result};
pub use path::confined;
pub use policy::{EnvPolicy, FsPolicy, NetworkPolicy, Policy, ResourcePolicy};
