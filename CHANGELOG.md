# Changelog

All notable changes to vak-sandbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security and correctness hardening (2026-10-28)

#### Security
- Remove implicit read authority from command arguments and inferred package ancestors; compile explicit overriding filesystem denies with validated/quoted paths.
- Add an in-repo native macOS supervisor and trusted group anchor, private owner lifelines, verified descendant cleanup and a retained Realm execution gate. Reject detachment, indirect syscall dispatch and `posix_spawn` to keep descendants in the reserved group.
- Keep trusted supervisor binaries outside target-controlled TMPDIR/write grants and reject loader-affecting environment variables before launching trusted code.
- Reject unsupported direct legacy Seatbelt Realm execution rather than inheriting host environment or launching untracked children; advertise only implemented backend capabilities.
- Replace malformed/unsafe network rules with supported explicit localhost-port policy and fail closed for unsupported remote/DNS/broad requests.
- Validate environment digest/Realm IDs, confine cache/materialization paths, verify existing cached artifacts, verify tree/copy digests and refuse destination reuse.
- Stop environment specifications from executing host post-check commands; use static checks and trusted absolute copy helpers with cleared environment.

#### Fixed
- Enforce deadlines/cancellation after stdout and stderr close; await supervisor cleanup before completion/readiness.
- Separate trusted cleanup completion from target exit status (including 126); persist unverified completion before running and quarantine missing/corrupt/failed cleanup proof so normal recovery cannot clear it.
- Persist exact active transaction identity instead of reconstructing history from recurring content; A→B→A workflows retain the latest receipt and readiness.
- Recover interrupted empty/environment Realms without requiring an original-project lock; keep environment caches out of promotion targets.
- Synchronize newly created transaction directories before host writes, prepare directory access for descendant operations and finalize/restore reviewed directory modes last.
- Harden legacy journal ID/ownership validation, writer locking, unique naming, durable append and corruption handling.

#### Tests and documentation
- Wire all 18 previously undiscovered root integration/security tests into owning Cargo crates; add real macOS containment/policy/lifetime regressions and integrity/recovery tests.
- Correct stale heartbeat and ineffective artifact assertions; use isolated fixtures rather than fixed shared temporary filenames.
- Restore strict lint/format checks with correct lint priorities, public API error contracts and explicit library/test assertion boundaries.
- Rewrite supported-contract documentation, architecture, threat model, runbook, backend/environment/API/testing guides; add upgrade notes and the finding-to-evidence hardening record.

#### Compatibility
- Containment capability contract is now `2`; installed helpers/apps are not updated by a repository push.
- `fork`/`exec` remains supported; spawn-based launchers/process libraries may fail because `posix_spawn` is intentionally blocked.
- Networking is localhost/explicit-port only. Direct legacy backend Realm creation, arbitrary path-like environment IDs and implicit host post-check execution now fail closed.
- CPU/memory/process-count/disk-growth quotas, Linux isolation and globally atomic multi-file promotion remain unavailable. See `docs/operations/UPGRADING.md` before reusing older interrupted stores.


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
