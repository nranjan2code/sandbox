# AGENTS.md: working on vak-sandbox

Read [README.md](README.md), [architecture](docs/architecture/OVERVIEW.md), [security model](docs/security/THREAT_MODEL.md), [runbook](docs/operations/RUNBOOK.md) and [upgrade notes](docs/operations/UPGRADING.md) before changing a boundary. The maintained hardening rationale and evidence live in [HARDENING-2026-10-28.md](docs/security/HARDENING-2026-10-28.md).

## Ownership and scope

1. Containment and promotion are separate. The Seatbelt backend owns supervised processes; `RealmStore` owns durable copies, reviews and host-project transactions. Never restore a parallel Realm shell/promoter path.
2. Changes in this repository do not authorize editing, staging, building or restarting a client application's repository or installed data. Keep client work separate unless explicitly requested. A push does not update an installed helper.
3. Deny by default. Network is off, data paths explicit, environment declared. A command argument is data and must never add a read/write grant or inferred package root.
4. No shortcuts at a security boundary. Reject an unsupported policy or runtime before effects; do not silently drop a restriction, run on the host, relax the profile, enlarge limits or replay interrupted commands to obtain a pass.
5. Reuse existing dependencies and system APIs. The native supervisor is first-party source compiled with the macOS system toolchain; do not add a third-party sandbox engine or vendor unreviewed code.

## Process lifetime and control code

- The supported macOS contract uses a trusted supervisor, a trusted process-group anchor, owner lifelines and kernel gates for session/group changes, indirect syscall dispatch and all `posix_spawn`. Fork/exec remains supported. Do not remove one half of this contract: spawn attributes can change group/session inside the kernel.
- Keep trusted code outside target TMPDIR and all target write grants. Reject loader-affecting environment variables before starting trusted code. Do not inherit ambient environment.
- Target stdin is `/dev/null`. No target inherits lifetime/result/completion-control descriptors or the execution lease. No general host command socket/service is exposed.
- Completion proof and target exit status are separate. A command exiting 126 is an ordinary command failure, not proof of supervisor failure. Only a validated host-private completion receipt can establish cleanup.
- The runtime retains an exclusive record lock and shares a separate execution gate with the supervisor. New operations need both exclusively. Preserve the handshake ordering: acquire the shared gate, check owner liveness, then start work. Never unlink lock files to bypass a busy state.
- Persist unverified completion before `running`. Missing/corrupt/unverified completion quarantines the Realm as `cleanup_failed`; ordinary recovery must not clear uncertainty. Owner death does not authorize command replay.
- C code is part of the trusted computing base. Use checked system calls, close-on-exec descriptors, explicit ownership and bounded failure handling. Keep `-Wall -Wextra -Werror`; verify Darwin syscall numbers against platform headers. Rust unsafe code stays denied.

## Files, policy and integrity

- Route relative host paths through `confined()`. Reject absolute/traversing paths, symlinks and special files for Realm operations. Checked path strings are not race-proof opened handles; keep untrusted writers stopped and avoid concurrent external mutation.
- Quote every policy datum. Explicit filesystem denies override allows. Failed canonicalization/unsupported policy fields must not silently disappear.
- Current network support is explicit localhost ports only, not exact remote-IP/DNS filtering. Loopback selectors compile to `localhost` across address families. Reject unrepresentable constraints and document them.
- Validate digest/UUID identifiers before joining cache/materialization paths. Rehash existing artifacts, source trees and copied environments; existence is not integrity. Never reuse a materialization destination.
- Specs/supporting files are data. `check_env` is static; executable post-checks need an explicitly authorized sandbox process plan. Never execute environment/spec code as an implicit host validation step.

## Durable mutation and recovery

- All mutations to an original project go through `RealmStore` staging, backups and write-ahead state outside the jailed workspace. Synchronize directory entries as well as files before host changes. Promotion is recoverable across files, not globally atomic.
- A review contains every unique sorted changed path and its version. Preserve explicit deduplication; blindly removing a set collection can apply a modified file twice. Current fingerprint and complete exact paths are required for promotion.
- Persist exact active transaction identity before mutation. Recurring A→B→A content is normal work, not transaction order. Never choose recovery by scanning for a matching old baseline or directory enumeration order.
- Directory permissions are journaled: temporary owner access permits descendant updates; final reviewed/restored modes apply after descendants. Recognize only journal-derived transient states during recovery.
- Refuse conflicting later edits and damaged backups. Rollback requires readiness and the latest committed receipt. Empty/environment Realms have no original-project promotion target and must not require a nonexistent project lock for verified command recovery.
- Snapshot means a review manifest, not a restorable filesystem checkpoint. Destroy does not undo promotion or erase receipts/backups. Audit creates, execs, snapshots, promotes, undo, recovery and destruction without logging undeclared environment values.

## Code and verification

Rust 2024, minimum Rust 1.90, strict Clippy. Comments explain invariants/security rationale. No unwrap/expect/panic in library code; tests may assert known fixtures. Preserve existing public signatures unless a boundary requires an explicit documented migration.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --locked --workspace
cargo test --workspace
cargo test --workspace --doc
```

The root is a virtual Cargo workspace: root `tests/` files are not discovered. Put integration/security tests under the owning crate's `tests/`. macOS native tests must prove actual allowed/denied behavior, closed-stream deadline, detachment/spawn gates, fork/exec, no delayed writes after receipt/owner death, shared-gate exclusion and quarantine. Use temporary synthetic canaries/local listeners, no actual secrets or internet dependency. Linux tests do not prove Linux containment; its backends remain stubs.

Freeze original expected bytes, paths, versions, permissions, interaction results and receipts before evaluating a fix. Keep failures as evidence; do not weaken assertions after a failure. Unit tests, safe rejection, lint success, a commit or an installed build do not replace the original intended outcome. Be explicit about unsupported toolchains, quotas, storage power-loss testing and platform coverage.

## Documentation and delivery

Keep README, API error contracts, architecture/security guides, runbook, upgrade notes, testing evidence and CHANGELOG consistent with final code. Record breaking restrictions and remaining limits; do not claim universal/production-grade containment from passing tests alone. Do not publish a release or change a client pin unless requested.

Before a public commit/push, inspect the full staged diff, scan for credential patterns without printing matched secret values, verify only your intended repository/files are staged, and preserve unrelated work. Never commit local secrets, caches, generated executables or private Realm data.
