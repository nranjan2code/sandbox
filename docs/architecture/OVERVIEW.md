# Architecture overview

Containment and change promotion are separate capabilities. The runtime composes them without giving command code authority over the original project.

```text
Host application / CLI (owns authorization)
  ├─ RealmStore: private records, locks, reviews, transaction candidates/backups
  ├─ Process plan: executable + arguments + explicit policy
  └─ supervised process executor
       └─ trusted supervisor S (outside target's Seatbelt profile)
            └─ trusted group anchor A (reserves group identity)
                 └─ sandbox-exec → command → fork/exec descendants
```

The supervisor is small in-repo C compiled using macOS system headers; Rust retains `unsafe_code = "deny"`. The trusted executables are materialized in a private directory outside target-writable scopes, independently of caller-controlled `TMPDIR`. Loader injection variables are rejected before those processes start. The worker CLI can apply nested deny paths on macOS; Linux Landlock currently refuses nested denies before target launch because additive parent grants cannot enforce that carve-out.

## Process lifetime

Rust retains a private stdin lifetime pipe to S. S retains a separate lifetime pipe to A. Target code inherits neither control descriptor: stdin remains `/dev/null`, stdout/stderr are bounded host-reader pipes, and internal descriptors are close-on-exec or explicitly closed. An explicitly requested interactive worker gets one invocation-scoped full-duplex Unix socket on descriptor 3. Rust accepts the supervisor's connection, closes the listener, then sends a one-byte readiness signal; the supervisor will not launch the target before that handshake. The target receives the connected descriptor, never the supervisor lifetime pipe or listener. Ordinary one-shot commands receive no descriptor 3.

S establishes A’s process group while A waits on the private lifeline. S then sends a one-byte group-admission handoff; A verifies its own group identity before it can create the target and reserves that identity until cleanup. Owner EOF before this handoff starts no target and cannot invoke group teardown against an inherited host group. The profile rejects direct session/group changes, indirect syscall dispatch, and all `posix_spawn`, including its in-kernel session/group attributes. Fork/exec descendants therefore stay in the reserved group. Target signal permission is limited to its own sandbox and cannot terminate the trusted unsandboxed supervisors.

On direct command exit, cancellation or Rust-owner EOF, S stops/kills the group and checks process status before writing a private completion receipt, distinct from the target exit code. A watches S's lifetime pipe and kills the group if S disappears. There is no network service or reusable host command interpreter behind this mechanism.

## Durable execution handoff

Each Realm lease holds an exclusive record lock and a separate exclusive execution gate. Before spawning, the runtime changes only its execution gate to shared while keeping the record lock exclusive. S acquires that gate shared and retains it until cleanup. New operations must acquire both locks exclusively.

Consequently, killing the CLI releases its record lock but does not admit recovery, promotion, destruction or a second command while S still owns the execution gate. The helper refuses a busy gate and checks for a dead owner before starting target work. The distinct gate avoids relying on an atomic downgrade of the record lock.

## Store ownership

```text
control/
  realms/<realm-id>/workspace/        target-writable project copy
  state/records/<realm-id>.json       baseline, state, active/latest transaction IDs
  state/locks/                       stable record/execution/project/audit locks
  state/executions/<realm-id>.json    latest host-private cleanup/exit receipt
  state/snapshots/                   durable review manifests
  state/promotions/<transaction>/    journal, immutable before/after bytes
  state/audit.jsonl                  serialized lifecycle events
```

The original project is outside this tree. Target policy grants its workspace, not control records or the original project. Promotion is the only runtime operation that changes the original. Project locks coordinate different Realms sharing that original within this store; external editors and independent stores do not participate.

## Public boundaries

`SandboxManager` chooses project, empty or verified-environment creation and delegates persistence to `RealmStore`. The backend owns process containment only. Its direct legacy Realm API is rejected and its capability flags do not claim promotion/rollback. Environment provisioning/copying owns no execution authority: `check_env` is static and refuses executable post-checks. Host applications still own consent, user-visible review and receipt interpretation.

## Interactive host receipt handoff

The CLI may create an exclusive owner-only completion record in an existing private directory outside all target grants. It synchronizes unverified state before backend launch, then synchronizes the exact invocation identity and verified target exit code only after the backend’s private cleanup proof and environment teardown. The target protocol descriptor and diagnostic streams never carry this authority. EOF on the host’s input closes the worker channel and asks the backend to stop and verify the whole process tree. A bounded input bridge avoids retaining runtime shutdown on an uncancellable async stdin read. Missing/unverified output remains uncertainty; file persistence is not a physical power-loss proof.
