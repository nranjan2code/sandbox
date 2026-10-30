#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! vak-sandbox-core: Runtime-agnostic execution sandbox
//!
//! Two modes:
//! - `ProcessSandbox`: Jail a single process with OS-level restrictions
//! - `RealmSandbox`: Isolated workspace for agent work with reviewable promotion

pub mod backend;
pub mod error;
pub mod journal;
pub mod path;
pub mod policy;

pub use backend::{
    AsyncReadWrite, BackendCaps, ExecHandle, ProcessPlan, RealmPlan, SandboxBackend, SandboxEnv,
    SandboxMode,
};
pub use error::{Error, Result};
pub use journal::{ChangeAction, JournalEntry, JournalOp, JournalStatus, PromotionJournal};
pub use path::{confined, is_contained, safe_canonicalize};
pub use policy::{EnvPolicy, FsPolicy, NetworkPolicy, Policy, ResourcePolicy};
