# Operations runbook

## Build and choose storage

Build with `cargo build --locked --workspace`. The system C compiler builds the embedded platform supervisor. Check `vaksb capabilities`: contract 2 advertises supervised process lifetime and detachment gates only when the platform backend is available. Linux requires Landlock ABI 5+ and seccomp and refuses all network access. A declaration is not a command test. Use a specific workspace; grants covering trusted supervisor storage are rejected. The raw `run` command does not create a disposable copy.

Use one private canonical `--store` outside the original project and every jailed copy. Do not place control state in a directory writable by the command. Do not use separate stores to coordinate edits to the same project.

```sh
vaksb run --workspace /path/to/copy --cwd /path/to/copy \
  --timeout-seconds 30 --max-output-bytes 32768 -- /bin/pwd
vaksb --store /path/to/control realm create --project /path/to/project
vaksb --store /path/to/control realm list
vaksb --store /path/to/control realm status REALM_ID
vaksb --store /path/to/control realm exec REALM_ID --cwd . -- /bin/sh -c 'printf ready > proof.txt'
```

Commands receive a minimal PATH/HOME/TMPDIR policy, network denial and explicit system read grants. There is no implicit shell. A command's first argument never grants reads. Fork/exec works; group/session detachment, Linux namespace operations and macOS `posix_spawn` are blocked. Some interpreter wrappers or build tools will fail. Explain that restriction; do not run on the host or disable the gates automatically. Neither OS backend currently enforces the serialized CPU, memory, wall-time, process-count or file-size `ResourcePolicy`; default policies request no such limits, and explicit requests are rejected before target launch. The CLI's own wall/output ceilings are separate controls, not aggregate CPU or memory quotas.

## Review every changed path

```sh
vaksb --store /path/to/control realm snapshot REALM_ID --offset 0
vaksb --store /path/to/control realm read REALM_ID proof.txt --offset 0
vaksb --store /path/to/control realm read REALM_ID existing.txt --original --offset 0
```

Snapshot returns a fingerprint, total, offset, next_offset and up to 20 unique sorted changes. Read all pages with the same fingerprint; restart the review if it changes. Inspect complete relevant file contents and modes, not only names or a first page. `can_promote` must be true. Conflicts/protected paths/type replacements must be resolved, not bypassed.

File pages return up to 16 KiB by byte offset, a version with full-file byte count/hash, `next_offset`, text and a lossy flag. Compare offsets with `version.bytes` to determine completeness; there is no independent `truncated` boolean. Lossy text is not exact binary content. A snapshot is a review manifest, not a restorable filesystem checkpoint.

## Apply and undo

Only the host application's existing consent policy authorizes these operations. Supply all affected paths in the order returned by the complete review.

```sh
vaksb --store /path/to/control realm promote REALM_ID \
  --fingerprint EXACT_REVIEW_SHA --paths=first.txt --paths=folder/second.txt
vaksb --store /path/to/control realm rollback REALM_ID TRANSACTION_ID \
  --paths=first.txt --paths=folder/second.txt
```

A committed receipt includes the Realm, transaction ID, phase and paths. Keep it. Rollback supports only that Realm's latest committed promotion and refuses later conflicting original-project edits. Destroy does not undo promotion. Do not describe isolated edits as saved to the original project before a committed receipt exists.

Promotion stages/synchronizes immutable candidates/backups before host writes. Directory owner access may be temporarily enabled for the journaled operation; final reviewed modes are applied after descendants. Files are atomically replaced individually, not as one globally atomic multi-file change. Avoid concurrent target edits by external editors; they do not honor the store's locks.

## Interruption and recovery

1. Inspect `realm status`. Do not replay a command automatically.
2. If the Realm is busy, wait for the trusted supervisor to finish cleanup; do not delete/replace lock files. Record and execution locks are stable and must not be unlinked.
3. Use exactly the status response's `recovery_paths` in order. Omit `--paths` when the array is empty.
4. Recover only after inspecting the interrupted state and authorizing affected paths.

```sh
vaksb --store /path/to/control realm recover REALM_ID --paths=first.txt --paths=folder/second.txt
vaksb --store /path/to/control realm status REALM_ID
```

Recovery first requires a valid host-private cleanup receipt for interrupted execution, then restores incomplete transactions or reconciles the explicit active transaction receipt. It does not infer history from recurring content and never re-executes commands. Empty/environment Realms require no project lock for command-state recovery. A `creating` Realm should be discarded and recreated. A `cleanup_failed` Realm is quarantined: ordinary recovery will not mark it ready. Preserve/inspect it, establish that old processes are gone before manual maintenance, and explicitly discard/recreate if appropriate. Missing completion proof in a legacy interrupted Realm also quarantines it rather than guessing. A conflict/damaged backup stops recovery and requires manual reconciliation; preserve the whole control store and original project while investigating.

```sh
vaksb --store /path/to/control realm destroy REALM_ID
```

Destroy removes the isolated copy/record after pending checks. Receipts/backups remain. Back up the entire control store before separate history management. Do not remove active transaction directories or active supervisor temporary executables. Hard crashes can leave inactive private supervisor files and pre-journal staging; there is no automatic janitor.

## Exit and failure interpretation

| Result | Interpretation |
| --- | --- |
| 0 | Command observed success; inspect output and intended effects separately |
| nonzero target exit | Command failed; retained copy may still contain partial changes |
| 124 | CLI deadline exceeded; cleanup precedes return |
| 125 | CLI output cap exceeded; cleanup precedes return |
| 126 | May be the target's ordinary failure; a supervisor/protocol failure is reported separately and quarantines durable execution |
| 143 / cancellation | Owner interruption/cancellation; inspect state before continuing |
| invalid policy | Unsupported authority request; no automatic weakening/retry |
| conflict / stale review | Re-review current state; do not reuse old authorization arguments |

The runtime distinguishes an ordinary target exit 126 from unverified cleanup using the private completion receipt. The raw CLI also uses 126 for supervisor failure, so callers must not infer verified success from a nonzero raw exit alone. The CLI/runtime keep deadlines active even with closed streams. Owner death transfers cleanup responsibility to the native supervisors; a shared execution gate blocks new Realm operations until cleanup releases it. No CPU, memory, process-count or disk-growth quotas exist. If a caller requests any currently unsupported `ResourcePolicy` limit, the backend refuses before launching the command.

## Limits

Realm command 30 s / 32 KiB output; copy 512 MiB / 50,000 entries / 8 MiB manifest; 32 retained Realms; 200 changes per promotion; 20 changes and 16 KiB file text per page. Regular files/directories only. Common credential filenames are excluded, not secret contents. Linux requires Landlock ABI 5+ and seccomp; it does not enforce CPU, memory, process-count or disk-growth quotas. Heartbeats are process-local observations, not an independent persistent service health monitor.

## Interactive worker completion

For a worker with a durable host run, supply paired `--completion-record` and `--invocation-id` options. Use an owner-only control directory outside every target grant and a fresh filename; an existing path is never overwritten at admission. Keep the exact identity/path in the host’s durable run record. Host stdin EOF requests cancellation even when the worker ignores its channel. After helper termination, validate the complete bounded JSON record and exact invocation identity. `cleanup_verified:true` proves backend cleanup, while `exit_code` reports target outcome; 126 can be an ordinary target failure. Missing/false/corrupt proof cannot release uncertain charges or authorize replay. A successful task outcome still needs independent evidence.
