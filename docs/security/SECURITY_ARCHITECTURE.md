# Security architecture

## Boundary placement

Untrusted commands receive a copy/workspace policy. The host runtime owns original-project paths, durable baselines, reviews, transaction state and consent. Commands cannot select promotion by modifying workspace files. The CLI's raw process mode does not itself copy a workspace; applications requesting disposable behavior must stage it before granting access.

## Profile construction

The profile starts deny-by-default, adds the minimum process/bootstrap operations and explicit file grants, then emits overriding denies. Policy paths are validated and safely quoted. Failed canonicalization is an error, not a silently missing restriction. Command argument strings never contribute paths or grants.

System read roots belong to the caller's explicit runtime policy. Global file metadata/root bootstrap access is not a claim that every host filename is hidden. Standard null/random devices are available. The backend's symlink capability flag stays false; the runtime separately rejects all Realm symlinks and special files.

Enabled network policy is deliberately narrow: explicitly named localhost ports. Unsupported remote, DNS, broad or contradictory policies fail before launch. There is no implied network broker.

## Trusted process supervision

The supervisor is compiled from `crates/vak-sandbox-seatbelt/native/supervisor.c`, embedded at build time, and materialized under a fresh private `/private/tmp/vaksb-supervisor-*` directory. Caller-controlled target `TMPDIR` is not used for that code. Grants overlapping supervisor storage or an execution-lock path are refused. Rust uses no unsafe blocks; native code uses the macOS system API directly and is part of the trusted computing base.

Two lifelines separate Rust ownership from the trusted group anchor. The anchor reserves group identity until the supervisor has stopped/killed and inspected the target group. Target code never inherits control descriptors, receives `/dev/null` stdin and cannot signal the unsandboxed supervisors through its same-sandbox signal permission. Session/group changes and spawn attributes are blocked in the kernel. A normal background fork cannot keep working after completion merely by closing stdout/stderr.

The direct target's exit status reaches the outer supervisor through a private pipe. After verified cleanup the supervisor writes a separate host-private JSON receipt with `cleanup_verified: true` and the actual `exit_code`, then exits successfully. Rust validates this bounded regular-file receipt independently of the supervisor's process status. A target exiting 126 remains an ordinary command failure with verified cleanup, not an interrupted Realm. Missing/corrupt/unverified completion is a distinct protocol failure. The supervisor is not a general host command server and opens no socket.

Before persisting `running`, the runtime durably initializes `state/executions/<realm-id>.json` with unverified completion. The native supervisor updates it only after cleanup, while retaining the execution gate. This also covers CLI death before it can save final Realm state. Recovery requires that proof; missing/corrupt/false completion persists `cleanup_failed` quarantine. Ordinary recovery never clears quarantine or infers termination merely from an unlocked gate. Explicit inspection/discard or a separately designed verified reconciliation is required; there is no automatic resume/replay.

## Lock handoff

A Realm operation takes an exclusive record lock and execution gate. Execution shares only the gate with the supervisor while retaining the exclusive record lock. After CLI death, exclusive acquisition by recovery or another command fails while the supervisor still holds its gate. The new helper's shared acquisition is nonblocking and owner liveness is checked before launching target code. This closes both cleanup/readiness races and stale-owner restart races.

## Environment and artifacts

Ambient environment is cleared before starting trusted launch code. Only the approved plan values are retained, and loader-affecting keys are rejected. Environment specs and static checks never create execution authority.

Artifact insertion verifies incoming bytes and any existing cache entry; writes use exclusive temporary files, sync and no-clobber persistence. Environment identifiers must be lowercase SHA-256 values, Realm materialization IDs valid UUIDs. Tree hashes cover sorted relative paths, file/directory type, size, normal permission bits and file hashes. Copy integrity is checked before hardening. Symlinks/special files are refused. Trusted `/bin/cp` is launched with a cleared environment; no archive download/extraction or install hook runs implicitly.

## Promotion durability and recovery

Before host mutation, the runtime creates/synchronizes transaction directories, durable backups/candidates, journal state and the explicit active transaction identity. Per-file writes are atomic replacements. Directory creation entries are synchronized, temporary owner permissions allow descendant updates, and final modes are applied last. Recovery recognizes only journal-derived transient directory modes in addition to before/after versions.

Recovery validates ownership and refuses subsequent conflicting edits. It follows one active identity instead of treating content equality as transaction order. Empty and verified-environment Realms can reconcile interrupted command state without an original-project lock. Rollback is a separate authorized operation on the latest committed receipt and cannot overlap unreconciled work.

## Audit and failure handling

Runtime creation, exec, snapshot, promotion, rollback, recovery and destruction append to the serialized private audit trail. Inspection failures must not be represented as successful execution. If journal/audit persistence fails after filesystem effects, inspect status and receipts before retrying; never replay a command automatically. One-shot process output is a receipt, not a persistent audit service.

Backups/receipts, old snapshots, incomplete pre-journal staging and temporary supervisor executables have no automatic retention policy. Manual cleanup must preserve pending transactions and active supervisors. Follow the [runbook](../operations/RUNBOOK.md) and [upgrade notes](../operations/UPGRADING.md).

## Verification limits

Source review and regression tests establish the observed contracts on the tested macOS build. They do not certify absence of kernel/service vulnerabilities, independently hostile same-UID processes, storage power-loss failure modes, resource exhaustion or every interpreter/toolchain. Do not replace these limits with production-grade/universal claims.
