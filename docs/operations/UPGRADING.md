# Upgrading to containment contract 2

This hardening changes behavior intentionally. Rebuild the sandbox helper and test a disposable fixture before relying on it. Updating source or pushing a commit does not replace an installed app/helper or restart running commands. No Vakyartha source or installed data is part of this sandbox-only change.

## Client contract

`vaksb capabilities` returns JSON with `contract: 2`, `execution_available`, `supervised_processes`, `detachment_denied` and `posix_spawn_denied`. These enforcement flags are true only in a macOS build with the Seatbelt supervisor. Unsupported platforms report false and refuse command execution before launch. Check the contract and actual platform rather than version/help strings alone. The existing executable/argument, `run`, Realm CLI and receipt shapes remain, with one additional Realm control-record field: `active_transaction`.

No argument-derived read grants remain. Callers that previously depended on a script/package argument outside the workspace must stage their approved code in the workspace or provide an explicit trusted read policy through the library. Do not infer package roots from argument paths. System runtime roots remain explicit read grants, not private-project data guarantees.

## Execution restrictions

The supervisor preserves ordinary fork/exec but denies direct session/group changes, indirect dispatch and all `posix_spawn`. Some language launchers/process libraries fail instead of falling back to fork/exec. This is a declared compatibility limit; do not silently disable containment. Target loader-affecting environment variables are rejected before the trusted supervisor starts.

Supervisor code lives outside target-controlled TMPDIR under a fresh private `/private/tmp` directory. A write policy spanning that trusted storage is invalid. Choose a project subdirectory instead of all `/tmp`, `/private/tmp` or `/`. Do not use the former broad default as a workspace.

Direct `SeatbeltBackend::create_realm` is rejected. Its previous shell inherited host environment and launched untracked commands. Use the runtime's `RealmStore`/`SandboxManager` and leased executor. Backend capability flags no longer claim runtime-owned promotion/rollback or universal symlink protection.

## Networking

Unsupported network requests now fail before process creation. The current implementation supports explicit localhost ports, with inbound permissions limited to those ports. It does not support arbitrary remote IP/domain allowlists, DNS control or unrestricted network builders. Loopback address inputs compile to a `localhost` endpoint and do not promise separate IPv4/IPv6 filtering. A future network broker requires its own design and tests.

## Saved Realm state

Back up the control store before upgrade. Ready records without `active_transaction` deserialize with no active transaction. New promotions/rollbacks persist an exact active identity before host mutation and clear it after metadata reconciliation.

Older interrupted transactions in prepared/applying/rolling_back phases are discoverable for explicit recovery. An old committed transaction whose metadata write was lost has no persisted active identity; the upgraded runtime deliberately will not guess by content equality. Inspect and reconcile such legacy ambiguous history manually, preferably by retaining the old store as evidence and creating a fresh Realm. Do not edit JSON to invent an active identity unless independently establishing ownership and exact transaction state.

New executions initialize a durable unverified completion record before `running`; the native supervisor writes verified cleanup plus the actual exit code before releasing the execution gate. Running/interrupted records without valid completion proof quarantine as `cleanup_failed`. Ordinary recovery cannot clear quarantine. This is an intentional safety change for legacy interrupted executions as well as damaged new receipts. A target that exits 126 retains its normal failure receipt when cleanup was verified.

Use the same canonical store between operations. The added execution gate protects recovery after owner death; never delete stable lock files to bypass a busy result. External editors and different stores are still outside the locking protocol.

## Environments and checks

Stored environment names must be valid SHA-256 tree digests. Existing arbitrary directory names/path-like environment IDs are rejected. Re-provision trusted trees under their verified digest; do not rename unverified content merely to bypass validation. Existing artifact cache entries are rehashed and corrupt entries refused. Materialization requires a fresh UUID destination.

`check_env` is static. Host PATH no longer satisfies environment binary declarations and post-check commands are reported unexecuted. Explicitly authorize sandboxed post-checks through the process API. `env check` remains a TOML parser; it does not execute a specification.

## Verification and deployment

Run formatting, strict Clippy, workspace tests and actual macOS CLI tests, then verify the intended interpreter/build workflow under the documented restrictions. Review complete changed paths and receipts for a disposable promotion/rollback cycle. Publishing a repository commit is not an installed-build acceptance test or release publication.
