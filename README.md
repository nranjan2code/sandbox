# vak-sandbox

**Production-grade, runtime-agnostic sandboxing for safe agent code execution with reviewable promotion.**

[![Rust 2024](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-green.svg)](#testing)

## Table of Contents

- [Overview](#overview)
- [Philosophy](#philosophy)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Modes](#modes)
- [Security Model](#security-model)
- [Platform Support](#platform-support)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Environment Management](#environment-management)
- [Management, Heartbeat & Control Protocol](#management-heartbeat--control-protocol)
- [CLI Usage (vaksb)](#cli-usage-vaksb)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

`vak-sandbox` provides two complementary isolation strategies in one cohesive system:

1. **Process containment** - OS-level capability restriction (macOS Seatbelt, Linux Landlock/seccomp/bubblewrap) to jail individual processes with deny-by-default policies
2. **Realm isolation with reviewable promotion** - Create isolated, disposable workspace copies for agents to work in freely (install deps, run builds/tests, make arbitrary changes), inspect diffs, then promote reviewed changes atomically with crash-safe journaling and rollback

Built for Vakyartha's agent execution needs, `vak-sandbox` is backend-agnostic, observable, and designed to be safe by construction.

## Philosophy

- **Containment and promotion are separate concerns** - `ProcessSandbox` and `RealmSandbox` are distinct modes sharing common primitives
- **Deny by default** - Nothing is allowed unless explicitly permitted. Network is disabled by default
- **Defense in depth** - OS-level sandboxes plus application-level checks (path confinement, env filtering, symlink protection)
- **Crash safety** - All mutations to real workspaces go through write-ahead journals with backups and rollback capability
- **Zero trust of paths** - All paths pass through `confined()` validation. Absolute paths, `..` traversal, and symlink escapes are rejected
- **Minimal attack surface** - Lean dependencies, `unsafe_code = "deny"`, strict Clippy lints (`unwrap`/`expect`/`panic` denied in libraries)
- **Observable** - Complete audit trail of creates, execs, snapshots, promotes, and undos

## Key Features

- **Backend-agnostic trait system** - Pluggable `SandboxBackend` implementations with capability discovery
- **Fine-grained policies** - Control filesystem (read/write/deny), network (egress/ingress/localhost/DNS/hosts/ports), environment variables, and resources
- **Path confinement** - Canonicalization with symlink traversal protection (ported from Vak/code)
- **Prebuilt, distributable environments** - Content-addressed environment store with CoW materialization (macOS `clonefile`/`cp -c`, Linux reflinks/hardlinks)
- **Hash verification** - All artifacts verified by SHA256 before use
- **Management & orchestration** - `SandboxManager` for lifecycle management of realms and processes
- **Heartbeat & liveness monitoring** - Track realm health with configurable timeouts, stale detection, and ping protocol
- **Control protocol** - Structured message-based protocol for coordination (`Ping`, `Exec`, `Snapshot`, `Promote`, `Destroy`, `Status`)
- **Environment checking** - Validate environments with required binaries and post-checks
- **Crash-safe promotion** (in progress) - Write-ahead journals, backups, atomic operations, rollback
- **Cross-platform** - macOS (Seatbelt) production-ready foundation, Linux (Landlock + seccomp-bpf + bubblewrap) stubs in place

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           vak-sandbox                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  CLI (vaksb)        │  Runtime Manager  │  Control Protocol            │
│  - env mgmt         │  - lifecycle      │  - heartbeat/ping           │
│  - realm ops        │  - orchestration  │  - status/exec/snapshot     │
│  - status/monitor   │  - health checks  │  - promote/destroy          │
├─────────────────────────────────────────────────────────────────────────┤
│                        Core (backend-agnostic)                           │
│  - Traits: SandboxBackend, SandboxEnv                                    │
│  - Policy: FS/Network/Env/Resource (deny-by-default)                    │
│  - Path confinement: safe traversal, symlink protection                 │
│  - Types: ProcessPlan, RealmPlan, ExecHandle, BackendCaps               │
├─────────────────────────────────────────────────────────────────────────┤
│  Backends            │  Environments      │  Security                    │
│  - Seatbelt (macOS)  │  - EnvStore        │  - Path validation           │
│  - Landlock (Linux)  │  - Content-addressed│ - Profile injection protect │
│  - Bubblewrap (Linux)│  - CoW materialize │  - Env allowlisting         │
│  - (extensible)      │  - Hash verify     │  - Audit logging            │
└─────────────────────────────────────────────────────────────────────────┘
```

### Crate Structure

| Crate | Purpose | Status |
| --- | --- | --- |
| `vak-sandbox-core` | Runtime-agnostic traits, policies, path confinement, errors | Core complete |
| `vak-sandbox-seatbelt` | macOS Seatbelt backend with safe profile generation | Process jail implemented, realm support in progress |
| `vak-sandbox-env` | Environment store, specs, hashing, CoW materialization, validation | Complete with tests |
| `vak-sandbox-runtime` | Sandbox manager, heartbeat monitor, control protocol, orchestration | Complete with tests |
| `vak-sandbox-ctl` | CLI (`vaksb`) for management and operations | Skeleton, expanding |

## Modes

### ProcessSandbox (Single-process containment)

Jail a single process with OS-level restrictions. Ideal for running untrusted commands, MCP servers, or one-off tool executions.

```rust
use vak_sandbox_core::{Policy, ProcessPlan};
use vak_sandbox_seatbelt::SeatbeltBackend;
use vak_sandbox_core::SandboxBackend;

let policy = Policy::deny_all()
    .allow_path_read("/usr/bin".into())
    .allow_path_read("/bin".into())
    .allow_path_write("/tmp/workspace".into())
    .allow_env("PATH")
    .allow_env("HOME");

let plan = ProcessPlan {
    command: "npm".into(),
    args: vec!["test".into()],
    cwd: Some("/tmp/workspace".into()),
    env: std::collections::HashMap::new(),
    policy,
};

let backend = SeatbeltBackend;
let env = backend.create_process(&plan).await?;
```

### RealmSandbox (Isolated workspace with reviewable promotion)

Create an isolated copy of a workspace where agents can work freely. All changes stay in the realm until explicitly promoted with review.

```rust
use vak_sandbox_runtime::{SandboxManager, CreateRealmRequest};
use vak_sandbox_env::{EnvStore};
use std::sync::Arc;

let store = Arc::new(EnvStore::new(EnvStore::default_root())?);
let manager = SandboxManager::new(store);

let req = CreateRealmRequest {
    env_sha256: Some("...".into()), // Use prebuilt env
    env_id: None,
    base_path: Some("/path/to/workspace".into()),
    policy_overrides: None,
};

let realm = manager.create_realm(req).await?;
// Agent works in realm.realm_root
// Review changes, then promote (journaled, rollbackable)
```

## Security Model

### Deny-by-Default

- **Filesystem**: No read/write access unless explicitly in allowlists. System paths only added as needed
- **Network**: Completely disabled by default. Must explicitly opt-in with granular controls
- **Environment**: Empty allowlist by default - only explicitly allowed vars passed through
- **Processes**: Fork/exec controlled by OS sandbox

### Path Confinement

All user-provided paths are validated through `vak_sandbox_core::path::confined()`:

- Rejects absolute paths
- Rejects `..` (parent directory) components
- Detects and rejects symlink escapes
- Canonicalizes roots to prevent TOCTOU issues
- Never interpolates untrusted paths into Seatbelt profiles

```rust
use vak_sandbox_core::path::confined;
let safe = confined(&root, "src/app.rs")?; // OK
confined(&root, "../etc/passwd")?; // Err(PathEscape)
confined(&root, "/etc/passwd")?;  // Err(PathEscape)
```

### Seatbelt Safety

- Profile generation uses safe quoting (`sbpl_quote`) to prevent injection
- Paths are canonicalized before insertion
- Special characters in paths are rejected
- Network rules are explicit and minimal
- Default profile denies everything, explicitly allows only required operations

### Environment Isolation

- Only variables in `EnvPolicy.allow` are passed (plus explicitly set vars)
- Never leaks `process.env` wholesale
- Artifacts verified by SHA256 before materialization
- Environments stored content-addressed in `~/.cache/vak-sandbox/`

### Resource Limits

Default resource limits (configurable):
- CPU: 3600s
- Memory: 2GB
- Wall time: 7200s
- Processes: 256
- File size: 1GB

## Platform Support

| Feature | macOS (Seatbelt) | Linux (Landlock/seccomp/bwrap) |
| --- | --- | --- |
| Process jail | ✅ Implemented | 🚧 Stubs in place |
| Realm isolation | 🚧 In progress | 🚧 Planned |
| Network control | ✅ Fine-grained | 🚧 Planned |
| Path confinement | ✅ App-level | ✅ App-level |
| CoW materialization | ✅ `cp -c` / clonefile | 🚧 reflinks/hardlinks |
| Resource limits | ⚠️ Limited by OS | 🚧 rlimits/cgroups |
| Status | **Usable for process jail** | **Development** |

## Installation

### Prerequisites

- **Rust** 1.90+ with Rust 2024 edition
- **macOS**: `sandbox-exec` available (built-in)
- **Linux**: `bubblewrap` (optional), kernel with Landlock support (5.13+)

### Build from source

```bash
git clone https://github.com/nranjan2code/sandbox.git
cd sandbox
cargo build --workspace --release
```

The CLI binary `vaksb` will be at `target/release/vaksb`.

### Using in your project

Add to your `Cargo.toml`:

```toml
[dependencies]
vak-sandbox-core = { git = "https://github.com/nranjan2code/sandbox" }
vak-sandbox-runtime = { git = "https://github.com/nranjan2code/sandbox" }
vak-sandbox-env = { git = "https://github.com/nranjan2code/sandbox" }
```

## Quick Start

### Create a minimal realm

```rust
use vak_sandbox_runtime::{SandboxManager, CreateRealmRequest};
use vak_sandbox_env::EnvStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = Arc::new(EnvStore::new(EnvStore::default_root())?);
    let mgr = SandboxManager::new(store);
    
    let realm = mgr.create_realm(CreateRealmRequest {
        env_sha256: None,
        env_id: None,
        base_path: None,
        policy_overrides: None,
    }).await?;
    
    println!("Created realm: {}", realm.realm_id);
    println!("Root: {}", realm.realm_root.display());
    Ok(())
}
```

### Monitor heartbeats

```rust
mgr.ping(&realm.realm_id).await;
if mgr.heartbeat_monitor().is_alive(&realm.realm_id) {
    println!("Realm is alive");
}
```

## Environment Management

Environments are prebuilt, content-addressed, and stored in `~/.cache/vak-sandbox/` by default.

### Environment Store Layout

```text
~/.cache/vak-sandbox/
├── artifacts/    # Downloaded/verified artifacts (keyed by sha256)
├── envs/         # Materialized base environments (keyed by sha256)
├── realms/       # Active realm instances
└── state/        # Runtime state, journals, locks
```

### Environment Spec (TOML)

```toml
[env]
id = "node20"
version = "1.0.0"
description = "Node.js 20 LTS environment"
platforms = ["macos", "linux"]
arch = ["x86_64", "aarch64"]

[base]
kind = "prebuilt"
artifact = "node20.tar.zst"
sha256 = "..."
size = 150000000

[tools.node]
version = "20.11.0"
check = ["node --version"]

[checks]
required_bins = ["node", "npm"]
post_check = ["node --version", "npm --version"]

[policy_defaults.network]
egress = false
allow_hosts = []

[[mounts]]
src = "/usr/local/bin"
dst = "/usr/local/bin"
ro = true
```

### Materialization with CoW

On macOS, `materialize()` attempts `cp -cR` for copy-on-write (clonefile). On other platforms, it falls back to copying with hardlinks where possible. The base environment is hardened to read-only, with only a writable layer exposed.

### Environment Validation

```rust
use vak_sandbox_env::{check_env, load_spec};
let spec = load_spec(&spec_path)?;
let report = check_env(&spec, &realm_root)?;
assert!(report.ok);
```

## Management, Heartbeat & Control Protocol

### SandboxManager

The `SandboxManager` orchestrates realm lifecycle:

- `create_realm(req)` - Create a new realm (from env or minimal)
- `get_realm(id)` - Retrieve realm handle
- `list_realms()` - List all realms
- `ping(id)` - Send heartbeat ping
- `heartbeat_monitor()` - Access liveness monitor

### HeartbeatMonitor

Tracks realm health with configurable timeouts:

```rust
let monitor = mgr.heartbeat_monitor();
mgr.ping(&realm_id).await;
monitor.is_alive(&realm_id); // true if seen within timeout
monitor.check_stale();       // returns stale realm IDs
monitor.get_all();           // all heartbeats
```

Default timeout: 30 seconds. Heartbeats include timestamp, PID, load, memory usage.

### Control Protocol

Message-based protocol for inter-component communication:

```rust
use vak_sandbox_runtime::{ControlMessage, ControlResponse};

// Messages
ControlMessage::Ping { realm_id }
ControlMessage::Exec { realm_id, cmd, args }
ControlMessage::Snapshot { realm_id }
ControlMessage::Promote { realm_id }
ControlMessage::Destroy { realm_id }
ControlMessage::Status { realm_id }

// Responses
ControlResponse::Pong { realm_id, alive }
ControlResponse::ExecResult { realm_id, exit_code, stdout, stderr }
ControlResponse::Snapshot { realm_id, manifest }
ControlResponse::Promoted { realm_id, receipt }
ControlResponse::Destroyed { realm_id }
ControlResponse::Status { realm_id, status, info }
ControlResponse::Error { message }
```

## CLI Usage (vaksb)

```bash
# Show help
vaksb --help

# Environment management (planned)
vaksb env list
vaksb env check <spec.toml>
vaksb env materialize <sha256> <realm-id>

# Realm operations (planned)
vaksb realm create [--env <sha256>]
vaksb realm list
vaksb realm exec <realm-id> -- <cmd> [args...]
vaksb realm snapshot <realm-id>
vaksb realm promote <realm-id>
vaksb realm destroy <realm-id>

# Status & monitoring (planned)
vaksb status [realm-id]
vaksb ping <realm-id>
vaksb health
```

## API Documentation

Generate and view API docs:

```bash
cargo doc --workspace --no-deps --open
```

Key types:
- `vak_sandbox_core::{Policy, SandboxBackend, SandboxEnv, ProcessPlan, RealmPlan}`
- `vak_sandbox_core::path::{confined, is_contained, safe_canonicalize}`
- `vak_sandbox_env::{EnvStore, EnvSpec, materialize, check_env}`
- `vak_sandbox_runtime::{SandboxManager, HeartbeatMonitor, ControlMessage}`
- `vak_sandbox_seatbelt::SeatbeltBackend`

## Development

### Setup

```bash
git clone https://github.com/nranjan2code/sandbox.git
cd sandbox
cargo build --workspace
```

### Code Style

- **Edition**: Rust 2024
- **Lints**: Strict Clippy (`all`, `pedantic`, `nursery` as warnings). `unwrap`/`expect`/`panic` denied in library code
- **Safety**: `unsafe_code = "deny"`
- **Errors**: Use `thiserror` for error types
- **Comments**: Explain *why* (especially security rationale), not *what*
- **Paths**: Always go through `confined()` before use
- **Tests**: Unit tests in modules, integration tests as needed

### Adding a new backend

1. Implement `SandboxBackend` trait from `vak-sandbox-core`
2. Implement `SandboxEnv` trait for the backend's environment handles
3. Add crate in `crates/` and add to workspace
4. Register backend in runtime/CLI

### Security Guidelines

- Never interpolate untrusted paths into shell commands or config profiles
- Always quote strings properly (use `shell_quote`/`sbpl_quote` helpers)
- Canonicalize and validate paths before use
- Filter environment variables strictly
- Keep promotion journal outside the workspace being promoted
- Use file locks for cross-process promotion operations

## Testing

### Run all tests

```bash
# Local (macOS)
cargo test --workspace

# Linux (Docker)
docker run --rm -v $(pwd):/sandbox -w /sandbox vaksb-rust:1.90 cargo test --workspace
```

### Test coverage

Current tests:
- `vak-sandbox-core`: Path confinement (traversal, absolute paths, normal paths)
- `vak-sandbox-env`: Hashing, store layout, file hashing
- `vak-sandbox-runtime`: Realm creation, heartbeat/ping

Run with output:
```bash
cargo test --workspace -- --nocapture
```

### Docker test images

```bash
# Build test images
docker build -t vaksb-rust:1.90 -f Dockerfile.rust .
docker build -t vaksb-test:alpine -f Dockerfile.test .
```

## Roadmap

### Phase 1: Foundation (Complete)
- [x] Core traits and policy system
- [x] Path confinement with symlink protection
- [x] macOS Seatbelt process jail backend
- [x] Environment store with CoW materialization
- [x] Hash verification
- [x] Runtime manager and heartbeat monitor
- [x] Control protocol types
- [x] Linux stubs (Landlock/Bubblewrap)
- [x] Basic tests on macOS and Linux

### Phase 2: Realm & Promotion (In Progress)
- [ ] Complete Seatbelt realm creation with full isolation
- [ ] Promotion journal (write-ahead log)
- [ ] Crash-safe promotion with backups
- [ ] Rollback/undo mechanism
- [ ] Diff generation and review workflow
- [ ] File locking for concurrent promotion safety

### Phase 3: Linux Backends (Planned)
- [ ] Landlock LSM integration
- [ ] seccomp-bpf syscall filtering
- [ ] Bubblewrap (bwrap) backend
- [ ] Resource limits via rlimits/cgroups
- [ ] Cross-platform backend auto-detection

### Phase 4: CLI & Management (Planned)
- [ ] Full `vaksb` CLI implementation
- [ ] Environment download/fetch integration points
- [ ] Realm exec/snapshot/promote/destroy commands
- [ ] Status dashboard and health monitoring
- [ ] JSON output mode for programmatic use
- [ ] Configuration file support

### Phase 5: Production Hardening (Planned)
- [ ] Comprehensive integration tests
- [ ] Audit logging system
- [ ] Performance benchmarks
- [ ] Security audit
- [ ] Documentation expansion
- [ ] Example environments and recipes

## Contributing

Contributions are welcome! Please follow the guidelines in [AGENTS.md](AGENTS.md):

1. Read the philosophy and rules carefully
2. Security is paramount - never cut corners
3. All paths must be confined
4. Tests required for new functionality
5. Follow Rust style and lints
6. Explain security rationale in comments

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [vak/code](https://github.com/nranjan2code/code)'s transactional sandbox model
- Inspired by [Anthropic's sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Built for the [Vakyartha](https://github.com/nranjan2code/vakyartha) ecosystem
