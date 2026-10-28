# Architecture Overview

## Design Principles

vak-sandbox is built around these core principles:

Current implementation includes macOS process containment and durable retained Realms with bounded execution, paged review, fingerprint-bound promotion, backups, conflict checks, explicit recovery, latest-promotion rollback and destruction. The durable owner is `RealmStore`; OS containment uses the process backend. Snapshots are review manifests, not restorable checkpoints. Linux and stronger resource quotas remain unsupported. This document also contains target architecture; the [runbook](../operations/RUNBOOK.md) and [README](../../README.md#current-implementation-status) define the supported path.

### 1. Separation of Concerns
- **ProcessSandbox**: OS-level process containment only
- **RealmSandbox**: Workspace isolation + reviewable promotion (separate from process jailing)
- Both share common primitives (policies, paths, backends)

### 2. Deny by Default
Everything is blocked unless explicitly allowed. This applies to:
- Filesystem access (read/write)
- Network access (egress/ingress/DNS)
- Environment variables
- System calls (where possible via OS sandboxes)

### 3. Defense in Depth
Multiple layers of protection:
1. **Application layer**: Path confinement, env filtering, validation
2. **OS layer**: Seatbelt (macOS), Landlock/seccomp (Linux)
3. **Audit layer**: All operations logged

### 4. Crash Safety
All mutations that affect the real workspace go through:
- Write-ahead journals
- Backups before changes
- Atomic operations where possible
- Rollback/undo capability

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (vaksb)                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                    Runtime Manager                           │
│  - Realm lifecycle    - Heartbeat monitoring                 │
│  - Process orchestration - Control protocol                  │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                      Core Traits                             │
│  SandboxBackend ◄─► SandboxEnv                              │
│  ProcessPlan / RealmPlan                                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    ┌─────────┐   ┌─────────────┐   ┌──────────┐
    │ Seatbelt │   │   Landlock   │   │ Bubblewrap│
    │ (macOS)  │   │   (Linux)    │   │  (Linux)  │
    └─────────┘   └─────────────┘   └──────────┘
```

## Data Flow

### Process Execution
1. Create ProcessPlan with command, args, env, policy
2. Backend generates OS-specific sandbox profile/config
3. Spawn process under sandbox
4. Stream stdout/stderr via channels
5. Monitor resources and enforce limits
6. Cleanup on destroy

### Realm Workflow
1. Create realm from base env (CoW materialized) or empty
2. Agent works in isolated realm_root
3. Track changes (snapshot/diff)
4. Review changes
5. Promote via journaled transaction (backup → apply → verify)
6. On error: rollback from journal/backups
7. Cleanup realm

## State Management

- **EnvStore** (`~/.cache/vak-sandbox/`): Persistent store for environments
- **Realm state**: Tracked in memory by SandboxManager, persisted in `state/`
- **Promotion journals**: Stored outside workspace (in control dir) for safety
- **Heartbeats**: In-memory with timeout-based liveness

## Concurrency & Safety

- **Async/await** throughout with Tokio
- **Send + Sync** bounds on all traits
- **File locking** for promotion operations (prevents concurrent promotes)
- **No unsafe code** (`unsafe_code = "deny"`)
- **Thread-safe** managers with Arc/RwLock/Mutex as appropriate
