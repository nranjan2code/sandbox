# AGENTS.md: working on vak-sandbox

Rules for building this sandbox. Read README.md for intent, then follow these rules strictly.

## Core Philosophy

1. **Process containment + change promotion are different concerns** - Don't merge them. `ProcessSandbox` (jail a process) and `RealmSandbox` (isolate workspace + review+promote) are separate modes sharing common primitives.
2. **Deny by default** - Everything blocked unless explicitly allowed. Network off by default. Paths explicitly allowlisted.
3. **Paranoia about paths** - Port Vak/code's `confined()` logic. Reject `..`, absolute paths, symlink escapes. Never trust user input.
4. **Crash safety** - Any mutation to real workspace must go through write-ahead journal with backups. Must be recoverable/rollback-able.
5. **Own it, don't vendor blindly** - Learn from sandbox-runtime and Vak/code, write our own. No external process-sandbox dependencies that could become restricted.

## Non-negotiable Rules

1. **No shortcuts** - If security boundary is involved, do it correctly. No "TODO: make secure later".
2. **Defense in depth** - Even if OS sandbox exists, apply application-level checks (path confinement, env filtering).
3. **Minimal env** - Only pass declared environment variables. Never leak full process.env.
4. **Log everything** - Audit trail for creates, execs, snapshots, promotes, undos.
5. **Platform first** - macOS (Seatbelt) first. Linux backends later. Don't block on cross-platform until macOS works correctly.

## Code Style

- Rust 2021 edition, strict clippy
- TypeScript only for bindings/client if needed (keep Rust as core)
- Comments explain *why* (security rationale), not *what*
- All paths must go through `confined()` before use
- Use `thiserror` for errors, no `unwrap`/`expect` in library code (only tests)

## Architecture Decisions

- **Backend trait** - Everything pluggable. Built-ins in-process, custom backends via JSON-RPC
- **Journal outside workspace** - Promotion journal stored in sandbox control dir, not in promoted workspace
- **Hashes everywhere** - Content hashes for files, candidate digests
- **Cross-process safety** - File locks for promotion operations
- **Realm is disposable** - Can create/destroy freely. Promotion is the only way to affect real workspace.
