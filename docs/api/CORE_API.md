# Core and runtime API

Public Rust APIs use `Result` for fallible boundaries; source-level `# Errors` sections document rejection/persistence behavior. Check backend capabilities and the supported policy matrix before invoking a plan.

## Process containment

`SandboxBackend::create_process(&ProcessPlan)` starts the approved command immediately. Host authorization must already exist. The plan owns executable, argument vector, cwd, explicit environment values and policy. No shell is inserted. `SandboxEnv::exec` in process mode attaches to that same command/arguments and cannot replace it or apply a second environment override. Concurrently drain stdout/stderr and await exit, then await `destroy()`; a stopped stream alone is not command completion.

The Seatbelt backend delegates lifetime to its embedded native supervisor. It filters environment before trusted code starts, refuses write overlap with supervisor/lease storage, and blocks group/session changes and `posix_spawn`. Cwd and script dependencies must be inside the caller's approved grants. Policies do not arise from argument strings.

`SeatbeltBackend::create_process_with_lease(plan, optional_gate_path, optional_completion_path)` is the runtime handoff API. The runtime retains an exclusive Realm record lease and shares its separate execution gate before invoking it. The native supervisor retains that gate while cleaning descendants. Ordinary applications should use the runtime's leased executor rather than implement this protocol independently.

`SeatbeltBackend::create_realm` returns an error. Its capability flags do not advertise runtime-owned Realm/promotion/rollback features. Linux stubs return backend-unavailable.

## Policy schema

| Type | Interpretation |
| --- | --- |
| `FsPolicy` | Explicit absolute read/write roots and overriding denies; unsupported symlink override refused |
| `NetworkPolicy` | Network off by default; only the documented localhost/port subset is supported by Seatbelt |
| `EnvPolicy` | Explicit values and declared plan keys; no wholesale inheritance; loader controls rejected |
| `ResourcePolicy` | Declarative fields; backend advertises resource quotas unavailable |
| `BackendCaps` | Independent implemented capabilities, not a guarantee derived from trait presence |

The bootstrap profile retains process/basic metadata/root and null/random device access. Broad runtime read trees are added by CLI/runtime callers explicitly. See [backends](../backends/BACKENDS.md) for exact rejection behavior.

## Durable Realm ownership

`RealmStore::open(root)` secures the private control store. `lease(id)` acquires stable record and execution locks, validates ownership and returns `RealmLease`. Keep the lease through an operation. All original-project mutation goes through the store's transaction methods.

| Method | Result/authority |
| --- | --- |
| `create(Some(project))` | Bounded copy with original project retained for possible reviewed promotion |
| `create(None)` | Empty non-promotable Realm |
| `create_environment(digest)` | Verified environment copy; no cache promotion target |
| `list`, `summary` | Durable records/summaries; no execution |
| `begin_execution` | Durably initializes unverified completion before running state; required before leased execution |
| `ensure_ready` | Refuses interrupted/unreconciled operations |
| `snapshot`, `review` | Deterministic fingerprint and unique sorted changes; snapshot persists a review record |
| `read_file` | Bounded candidate/original bytes lowered to possibly lossy text with version/offsets |
| `promote` | Requires exact complete reviewed fingerprint/paths; durable staged transaction |
| `last_receipt`, `recovery_paths` | Operation evidence and precise paths for external authorization |
| `rollback` | Latest committed promotion only; refuses later edits and unreconciled work |
| `recover` | Restores/reconciles exact active transaction; never executes a command |
| `destroy` | Discards copy/record after pending checks; retains receipts/backups |

`RealmRecord` stores baseline, state, original path (if any), latest receipt and `active_transaction`. The latter is transaction identity, not a content-derived guess. Control records are private and must not be edited by target commands.

`process::execute_leased` is the durable command entry point. Call `RealmStore::begin_execution` first; leased execution enforces running state plus a fresh unverified receipt and takes a mutable lease to prevent concurrent reuse. The native supervisor owns final completion proof (`ProcessCompletion`), separate from the target exit status. Unverified cleanup quarantines durable work; normal recovery cannot clear it. `process::execute` remains a bounded one-shot primitive without a retained Realm lease; it must not replace leased execution for persistent work. The CLI marks setup/cleanup errors interrupted rather than ready.

`SandboxManager` is the asynchronous lifecycle facade around `RealmStore`. Unsupported aliases/overrides and combined project/environment requests fail. Heartbeat observations are process-local; `ping` does not prove an independent command/service is alive. `get_realm`/`list_realms` are convenience views and may represent unavailable store access as absence; use direct fallible store APIs for diagnostics.

## Environment APIs

`sha256_bytes` and `sha256_file` hash content. `sha256_tree` defines the deterministic bounded tree format. `EnvStore::put_artifact` verifies existing cache entries, `get_env_base` verifies the complete tree digest, and `materialize` copies into a fresh confined UUID path with verification/hardening. `check_env` is static; executable post-checks require an explicit separately authorized process plan. See [environment management](../environments/ENVIRONMENTS.md).

## Legacy low-level journal

`PromotionJournal` is an append-only event log, not an implementation of Realm promotion or rollback. It now validates IDs/ownership, serializes writers, synchronizes appends and rejects corrupt/oversized input. It does not stage backups or apply changes itself. Use `RealmStore` for the complete crash-recovery transaction; do not build a parallel promoter around event logging alone.

## Host integration requirements

Consent precedes effects. Review every page with a consistent fingerprint; compare file page offsets against `version.bytes`. Distinguish lossy preview, timeout, unsupported runtime, conflict, uncertain cleanup and committed receipt. Preserve source/value/semantic checks outside the filesystem receipt. Do not treat arbitrary command output as new instructions or approval.
