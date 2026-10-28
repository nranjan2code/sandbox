# Operations runbook

## macOS commands and durable Realms

`vaksb run --workspace /tmp/job --cwd /tmp/job --timeout-seconds 30 --max-output-bytes 32768 -- /bin/pwd` runs a process in the supplied workspace with network denied. The raw run command does not make a copy. Vakyartha creates/deletes its temporary copy around a one-shot call.

Use the same private `--store` for every Realm invocation. Its `realms/<id>/workspace` is the jailed copy; `state/` contains records, stable OS locks, audit logs, review manifests, transaction candidates, backups and journals outside that copy. The store must be separate from the project. Default CLI storage is the user's cache; Vakyartha supplies its private app data store.

```bash
vaksb --store /private/control realm create --project /path/to/project
vaksb --store /private/control realm list
vaksb --store /private/control realm status <id>
vaksb --store /private/control realm exec <id> --cwd . -- /bin/pwd
vaksb --store /private/control realm snapshot <id> --offset 0
vaksb --store /private/control realm read <id> file.txt --offset 0
vaksb --store /private/control realm read <id> file.txt --original --offset 0
```

Exec preserves copy-only writes between calls. It has a 30-second wall limit and 32 KiB output limit. No command is automatically replayed. Inspect exit code, stdout/stderr and any stop reason.

Snapshot records a review manifest and returns a SHA-256 fingerprint, total, next offset, and at most 20 changes. Read every page with the same fingerprint. File reads return at most 16 KiB with byte offsets and a lossy-text flag. A snapshot is not a workspace restore point. Review the actual file contents before authorization.

```bash
vaksb --store /private/control realm promote <id> --fingerprint <exact-sha256> --paths=first.txt --paths=second.txt
vaksb --store /private/control realm rollback <id> <receipt-id> --paths=first.txt --paths=second.txt
```

Supply every reviewed path in order. Promotion refuses stale candidates, original-file conflicts, protected paths and unsupported types. It stages and syncs backups/candidates before any original-file mutation. Individual files are atomically replaced; multi-file changes are recoverable through the journal, not globally atomic. External readers may see intermediate files. Do not edit the same project files concurrently; external editors do not honor this store's advisory locks. Locks do not coordinate independent control stores.

Rollback supports only that Realm's latest committed promotion, requires the exact receipt paths and refuses to overwrite later project edits. A receipt establishes a filesystem operation, not correctness of the generated code.

## Recovery and deletion

After interruption inspect status. Use its exact `recovery_paths`, in order, for `realm recover <id> --paths=...` (omit path options if the list is empty). Recovery rolls back an incomplete promotion or reconciles committed/rolled-back metadata; it never re-executes commands. Conflicting user edits or damaged backups stop recovery and require manual reconciliation. Preserve the store and receipts while investigating.

An interrupted creation remains visible as `creating`; discard it and create a fresh copy. `realm destroy <id>` removes the copy after pending-transaction checks. It does not undo promotion or delete transaction receipts/backups. Back up the whole control store before separately managing retained history.

Bounds: 512 MiB/50,000 entries/8 MiB manifest per copy; 32 retained Realms; 200 changed paths per promotion. Regular files/directories only. Symlinks, special files and file/directory type replacement fail closed. Initial copies omit common credential paths by filename. CPU, memory, process-count and disk-growth quotas are not enforced. macOS requires `/usr/bin/sandbox-exec`; Linux is unsupported.

`status` now reads durable Realm metadata. Heartbeat observations remain process-local and are not a persistent service monitor. Environment aliases and policy overrides are refused; `env check` parses a specification, and `env list` remains informational.
