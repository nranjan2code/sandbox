# Sandbox handover — 2026-10-29

The hardening is implemented in this repository only. Read the [current contract](../README.md), [agent rules](../AGENTS.md), [changelog](../CHANGELOG.md), [repair evidence](security/HARDENING-2026-10-28.md) and [upgrade notes](operations/UPGRADING.md) before further changes.

## Current state

- Supervised macOS process execution: explicit argument/data boundary, overriding denies, filtered environment, owner/anchor lifelines, immutable process group and actual cleanup verification.
- Normal fork/exec works. Detachment, indirect dispatch and `posix_spawn` are blocked. Some runtime launchers are incompatible; do not quietly weaken isolation.
- Durable Realm record/execution locks prevent early recovery after owner death. Initial unverified completion precedes running; verified completion is separate from target exit codes. Failed/missing proof quarantines work permanently from normal recovery.
- Promotion/rollback use explicit active transaction identity, unique sorted path reviews, synced staging and directory-aware permission ordering. Repeated content states and empty/environment recovery are covered.
- Verified environment copies cannot promote into the environment cache. Environment checking is static; no spec-owned host commands run.
- All 18 former orphan tests are owned by Cargo packages. Final local workspace suite: 57 passing tests; strict Clippy, format and locked build passed on macOS 27.0 arm64 / Rust 1.98.1.
- Linux runtime compiles on Rust 1.99.1 and explicitly refuses command execution before launch or writing an unverified Realm receipt. Capability output reports platform enforcement flags accurately; Landlock and Bubblewrap stubs report unavailable even if `bwrap` is installed. Docker ARM64 workspace suite passes 51/51 and strict Clippy passes. This is compile/fail-closed evidence only; Linux containment is still unavailable.

## Preserved limits and next work

Linux isolation, CPU/memory/process-count/disk-growth quotas, remote/DNS network brokerage, unmodified spawn-based toolchains and globally atomic multi-file promotion are not implemented. Power-loss behavior was not physically fault-tested. Receipt/backups/temp-code retention remains manual. External host editors and separate stores do not participate in project locks.

Legacy ambiguous interrupted stores require explicit inspection; do not reconstruct identity from content equality or remove lock files. A pushed sandbox commit is not an installed-helper/client migration. No client repository is part of this delivery; coordinate that work separately.
