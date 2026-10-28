# System design and state transitions

This describes implemented ordering, not a roadmap. See the [overview](OVERVIEW.md) for process topology and the [runbook](../operations/RUNBOOK.md) for commands.

## Execution invariants

1. Validate command/policy, cwd and workspace before launch. Arguments are data, never permission declarations.
2. Materialize trusted supervisor code outside every target write grant. Clear ambient environment and reject loader-affecting values.
3. Keep a stable trusted group anchor and kernel gates against group/session changes, indirect dispatch and spawn attributes.
4. Hold Realm record exclusion during execution. Hand a distinct shared execution gate to the supervisor so owner death does not admit recovery early.
5. Drain output and wait for command completion together. Deadlines and signals stay active even after both output streams close.
6. Initialize an unverified completion record before persisting `running`; require the supervisor's verified private completion receipt before readiness. Keep target exit status separate from cleanup proof.
7. Missing/corrupt/unverified cleanup quarantines the Realm as `cleanup_failed`, including after owner death. Ordinary recovery cannot clear quarantine. Never replay an interrupted command.

`create_process` starts the approved process immediately; `exec` attaches to that exact plan. It is not a later authorization point. Host consent must precede creation.

## Realm creation

Creation uses a store-level retention lock, scans a bounded source and records `creating` before copying. The copy is rechecked against its manifest. Only then is `ready` persisted. Interrupted creation is visible and disposable. Project roots and control state cannot overlap. Verified-environment creation deliberately has no original project; its cache cannot be a promotion target.

## Review identity

A review hashes Realm identity, baseline, current manifest and the complete change list. Paths are explicitly sorted and deduplicated: a modified path present in both manifests appears once. Every path/version participates, including directory mode changes. Conflicts compare current original-project versions with the recorded baseline. Protected names and file/directory replacement prevent promotion.

Pages must share one fingerprint. File pages carry byte offsets and the observed version. Neither an incomplete preview nor a lossy string is proof of exact binary content.

## Promotion ordering

1. Require a ready Realm, no unreconciled transaction, project lock, matching current fingerprint and exact complete path list.
2. Create private transaction directories and synchronize their entries in their parents.
3. Stage and sync original backups and immutable candidate file bytes; verify their hashes.
4. Persist the `prepared` transaction and the Realm's exact `active_transaction` identity before host mutation.
5. Persist `applying`; verify original versions before the operation and immediately before file writes/deletions.
6. Prepare touched directories with temporary owner access. Install descendant files before final directory modes, including read-only modes. The journal's before/after versions define the permitted transient directory modes.
7. Delete paths in reverse order, finalize directory modes from leaves upward, then persist `committed`.
8. Update baseline/latest receipt, clear active identity, persist metadata and append the audit result.

Individual file replacement is atomic. The collection of files is not one globally atomic filesystem transaction. New directory entries, staged files, transaction JSON and containing directories are synchronized; physical power-loss behavior still depends on the filesystem/storage stack and has not been established by power-cut testing.

## Recovery identity

Normal content can recur: A→B→A is not evidence of an unfinished old commit. Recovery therefore follows `active_transaction`, not matches against every historical baseline or directory enumeration order.

A pending prepared/applying/rolling-back transaction is restored from its own journal. An active committed transaction reconciles to its new baseline/receipt. An active rolled-back transaction reconciles to its previous baseline and clears the corresponding latest receipt. Ownership and original versions are validated. An empty or environment Realm can recover command state with verified cleanup without a nonexistent project lock. Running/interrupted records with missing, invalid or false completion become quarantined; an unlocked execution gate alone is insufficient proof.

Before restoration, each affected path must match the recorded before, after or explicitly derived temporary directory state. Conflicting later edits stop recovery. Unchanged original files are not needlessly rewritten. Recovery never re-executes commands.

## Rollback and retention

Rollback requires readiness, the latest committed receipt for this Realm, exact ordered paths and the promoted original versions. It persists active transaction identity before restoration. Directory modes are restored after descendant contents. The baseline and receipt metadata are reconciled durably.

Destroy refuses pending transactions and removes the isolated copy/record. It does not undo committed project writes or erase receipts/backups. Audit/history and orphaned pre-journal staging directories have no automatic retention policy. A crash can leave private supervisor executable files in the OS temporary directory; remove only confirmed inactive files during maintenance.
