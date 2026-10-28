# Changelog

All notable changes to vak-sandbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Durable Realm workflow (2026-10-28)
- Replace the in-memory-only Realm manager with a private durable store shared by independent CLI invocations.
- Implement create/list/status, bounded Seatbelt execution, paged review manifests and file reads, fingerprint/path-bound promotion, latest-promotion rollback, interrupted-work recovery and destruction.
- Stage immutable candidates/backups before host writes, journal transaction state, atomically replace individual files and refuse stale reviews, original-file conflicts and unsupported paths/types. Preserve receipts/history after workspace destruction.
- Add OS locks, private control state and audit records outside jailed workspaces. Keep resource/platform limits and manifest-snapshot semantics explicit; remove the legacy unreviewed path-copy Promoter API.
- Correct bounded-run option parsing, compilation and command exit-code handling. Exercise partial apply and commit/rollback metadata recovery in tests; Vakyartha verifies real tool and WebKit lifecycle journeys.

### Added
- Core traits and policy system (deny-by-default)
- Path confinement with symlink/traversal protection
- macOS Seatbelt backend for process isolation
- Environment store with content-addressed artifacts
- CoW materialization (macOS clonefile, fallback copy)
- Environment validation and checking
- SandboxManager with realm lifecycle
- HeartbeatMonitor with ping/liveness/stale detection
- Control protocol (Ping/Exec/Snapshot/Promote/Destroy/Status)
- Linux stubs for Landlock and Bubblewrap
- Full CLI (vaksb) with env/realm/status/ping/health commands
- Comprehensive test suite (unit, integration, security)
- World-class documentation
- CI workflow for macOS and Linux
- Security threat model
- Contributing guidelines
- MIT License

### Fixed
- Materialization now copies contents correctly
- CLI dependency management

### Security
- `unsafe_code = "deny"`
- Clippy lints deny unwrap/expect/panic in libraries
- Path injection protection in Seatbelt profiles
- Environment variable allowlisting
- Network deny-by-default
