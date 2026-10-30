# vak-sandbox

Runtime-independent process containment and durable project copies with reviewed promotion.

**Current scope:** macOS Seatbelt and Linux Landlock/seccomp supervised commands, retained Realms, fingerprint-bound promotion, recovery and latest-promotion rollback. Linux execution is enabled only when Landlock ABI 5+ and seccomp are available; otherwise commands are refused before launch. This is a constrained execution boundary, not a VM or a guarantee that arbitrary build systems will run unchanged.

## Supported behavior

| Capability | Current contract |
| --- | --- |
| Command authority | Explicit executable and arguments; argument paths never grant reads |
| Filesystem | Explicit policy grants and overriding denies; CLI adds documented system runtime reads |
| Network | Denied by default; library policies support explicit localhost ports; unsupported remote/DNS policies fail before launch |
| Linux network | All socket creation and network syscalls are denied; Linux network allowances fail before launch |
| Environment | Clear inherited environment; pass declared values only; reject loader-affecting variables |
| Lifetime | Trusted native supervisor and group anchor; deny group/session changes and `posix_spawn`; verify cleanup before completion |
| Persistent work | Runtime-owned private Realm store, separate workspace and control state |
| Review | Deterministic unique sorted paths, exact candidate fingerprint, paged file contents |
| Apply | Staged immutable candidates/backups, version checks, journal, per-file atomic replacement |
| Recovery | Explicit active transaction identity and verified command cleanup; unverified cleanup quarantined, no command replay |
| Rollback | Latest committed promotion for that Realm, exact paths, original-project version checks |
| Resources | CLI wall/output caps and copy/manifest/count bounds; no CPU, memory, process-count or disk-growth quota. Explicit backend resource requests fail before launch. |

`fork` followed by `exec` is supported on both backends. macOS blocks `setsid`, `setpgid`, indirect syscall dispatch and `posix_spawn`. Linux drops the target's inherited capabilities and blocks session/group changes, mount and namespace operations, network syscalls, and attempts to signal processes outside the contained process group or its trusted supervisor. Some process libraries and build tools remain incompatible. Do not disable the gates or run failed work on the host as an automatic fallback. See [backend compatibility](docs/backends/BACKENDS.md).

Ordinary target stdin stays `/dev/null`. The explicit `create_interactive_process` API gives a persistent, invocation-scoped worker a full-duplex private descriptor 3; it does not reuse the supervisor's lifetime pipe. This channel does not grant filesystem or network access and must be paired with a narrowly scoped process policy.

The `vaksb worker` CLI exposes that boundary for a host that supervises a persistent sidecar. It requires an existing working directory inside an explicit read/write grant, an explicit executable, and repeated `--env KEY=VALUE` entries. Worker protocol bytes travel on descriptor 3 (the wrapper's stdin/stdout); target stdout and stderr are forwarded to wrapper stderr for diagnostics. Worker startup skips the durable Realm store. This command is a containment primitive: the host still owns task admission, user approval, workspace scoping, lifecycle policy, and receipts.

```sh
vaksb worker --cwd ./workspace --read ./workspace --write ./workspace \
  --env PATH=/usr/bin:/bin --command /path/to/sidecar -- --stdio-protocol
```

## Build and verify

The current verification stack is Rust 1.99.1. Native execution builds the small in-repo supervisor using the system C compiler. macOS requires command-line developer tools and `/usr/bin/sandbox-exec`; Linux requires x86_64 or aarch64, a C compiler, Landlock ABI 5+, and seccomp filtering. The embedded supervisor uses no separately installed daemon or network listener.

```sh
cargo build --locked --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The CLI is `target/debug/vaksb`. Read [testing](docs/automation/TESTING.md) for the actual test targets, fixture behavior and limits of the evidence. A passing unit suite alone does not prove OS containment or power-loss durability.

## One-shot process containment

Supply a specific existing project directory, separated from trusted supervisor storage. The raw CLI does not copy that directory; it grants writes there. An application requiring disposable execution must create and own its copy first.

```sh
vaksb capabilities
vaksb run --workspace /path/to/disposable-copy --cwd /path/to/disposable-copy \
  --timeout-seconds 30 --max-output-bytes 32768 -- /bin/sh -c 'printf ready'
```

`capabilities` returns containment contract `2`, with supervised-process and detachment-gate declarations. It is a capability declaration, not proof that a particular command succeeded. On Linux, execution requires Landlock ABI 5+ and seccomp; the runner denies all network access. Executing `run` always uses the supervisor; there is no unsupervised fallback.

macOS system runtime reads include `/usr`, `/bin`, `/etc`, `/System`, `/Library`, `/opt` and `/dev`. Linux reads `/usr`, `/bin`, `/lib`, `/lib64`, the dynamic-loader cache when present, and explicitly discovered toolchain directories; it does not grant the `/etc` tree. Both platform lists are broader than the selected project's files. The backend itself does not silently add system trees. Minimal bootstrap metadata and standard null/random devices remain accessible. On macOS, `run` grants an explicitly selected executable outside the system trees as a single file; its argument files and package ancestors do not. Linux command executables must resolve within its granted runtime roots or discovered toolchain paths. Linux device ioctl operations are denied by Landlock.

## Durable project work

Use one private store consistently between invocations, outside the original project and every jailed copy.

```sh
vaksb --store /path/to/private/control realm create --project /path/to/project
vaksb --store /path/to/private/control realm list
vaksb --store /path/to/private/control realm exec REALM_ID --cwd . -- /bin/pwd
vaksb --store /path/to/private/control realm snapshot REALM_ID --offset 0
vaksb --store /path/to/private/control realm read REALM_ID src/file.rs --offset 0
```

Review every page under the same fingerprint and inspect relevant complete file contents. A snapshot is a review manifest, not a restorable filesystem checkpoint. Authorize promotion with the exact fingerprint and all paths in review order. Committed receipts name the transaction needed for rollback. See the [runbook](docs/operations/RUNBOOK.md) for apply, rollback, cancellation and recovery.

Creation without a project produces an empty non-promotable Realm. Creation with `--env DIGEST` copies a verified environment without granting promotion into its cache. Only project-backed Realms can promote to an original project. Environment aliases and policy overrides are rejected.

## Bounds and exclusions

- Realm command: 30 seconds and 32 KiB combined returned output.
- Initial/retained copy scan: 512 MiB, 50,000 entries and 8 MiB manifest.
- Retained Realms: 32; changes per promotion: 200.
- Review page: 20 changes; file read: 16 KiB by byte offset.
- Supported filesystem objects: regular files/directories; Realm symlinks, special files and file/directory replacement are refused.
- Common credential filenames, `.env*`, `.git` and `.vak` are omitted from initial copies and protected from promotion. Exclusions do not inspect secret content.

Multi-file promotion is recoverable, not globally atomic to readers. Advisory locks coordinate this canonical store, not external editors or separate stores. Avoid concurrent host-project edits. Receipts/backups survive destruction and need separate retention management. Resource quotas remain incomplete. `ResourcePolicy::default()` requests no unsupported quota; explicit CPU, memory, wall-time, process-count or file-size limits are refused by the current OS backends rather than silently ignored. The CLI/runtime's separate wall/output bounds remain in effect on their own paths.

## Public ownership boundaries

| Crate | Responsibility |
| --- | --- |
| `vak-sandbox-core` | Policy/trait schemas, checked paths, legacy low-level event journal |
| `vak-sandbox-seatbelt` | Policy compilation, supervised process jail; direct legacy Realm creation is rejected |
| `vak-sandbox-env` | Artifact/tree digests, bounded environment copies, static checks |
| `vak-sandbox-runtime` | Durable Realm lifecycle, execution gate, review, transaction/recovery/rollback and audit |
| `vak-sandbox-ctl` | Bounded CLI, signal handling and machine-readable receipts |

Containment and promotion remain separate. `SeatbeltBackend::create_realm` does not implement the runtime's persistence or promotion; it now returns an error rather than launching a second, incomplete execution path. Use `RealmStore`/`SandboxManager`.

## Documentation

Start with the [documentation index](docs/README.md), [security model](docs/security/THREAT_MODEL.md), [architecture](docs/architecture/OVERVIEW.md), [API guide](docs/api/CORE_API.md), [environment format](docs/environments/ENVIRONMENTS.md), and [upgrade notes](docs/operations/UPGRADING.md). The [hardening record](docs/security/HARDENING-2026-10-28.md) maps review findings to repairs and evidence. [CHANGELOG.md](CHANGELOG.md) records the changes.

MIT licensed. See [AGENTS.md](AGENTS.md) before modifying the implementation.
