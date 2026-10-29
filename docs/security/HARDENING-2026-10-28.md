# Hardening review and repair record — 2026-10-28

## Scope

Repository-only sandbox repair following the review of commit `89f4d429068f8f571c619b342bb91473cdc10802`. Process containment, environment integrity, durable transactions, test discovery and operator/API documentation were examined. No framework dependency files, installed application data or client application files belong to this change. Publishing a commit does not upgrade an installed helper.

## Review finding disposition

| Finding | Repair | Required evidence |
| --- | --- | --- |
| First argument silently grants external reads | Remove argument/package-derived grants; retain only approved executable and explicit policy grants | Outside-file/directory canaries denied; inside file readable |
| Detached/background descendants survive completion | Trusted native supervisor/anchor, group/session/spawn/indirect gates, verified teardown, private lifelines | Detachment denied; fork/exec succeeds; delayed marker absent after receipt and owner death |
| Closed output bypasses deadline | One exit/stream/deadline/signal state machine | Closed-stream command times out with 124 |
| Filesystem deny ignored | Validate/quote paths and emit overriding denies after grants | Parent allow with denied current/future child cannot read/write |
| Direct legacy Realm inherits environment/untracked children | Reject that backend API, use one supervised runtime executor, correct capability flags | Legacy API rejected before target start; environment synthetic key absent |
| Same-content history confuses recovery | Persist and reconcile an exact active transaction identity | Repeated A→B→A remains ready and retains latest receipt; interrupted metadata reconciles |
| Empty Realm cannot recover | Project lock only when an original exists | Interrupted empty Realm becomes ready without replay |
| Host-restricted network rules malformed/fields ignored | Emit supported localhost/port rules; reject unsupported remote/DNS/broad requests | Allowed local port connects, second port denied; malformed/unsupported policies fail before start |
| Environment/materialization IDs escape roots or trust stale bytes | Validate digests/UUIDs, confine paths, rehash cached/tree/copied content, fresh destination | Traversal/absolute IDs and poisoned cache fail; verified copy succeeds |
| Top-level integration/security tests undiscovered | Move all 18 tests into owning Cargo packages; correct stale assertion and ineffective equality check | Cargo enumerates/runs those targets with native containment tests |

## Independent follow-up review

Astra reviewed the native descriptor/lock/reaping paths without modifying files. It identified target exit-126 ambiguity and recovery clearing unverified cleanup. Both were repaired with separate completion proof, durable initial unverified state and quarantine. Follow-up source review confirmed these repairs and the owner/gate ordering, with no additional blocker found in the reviewed paths. This is source review, not a formal security certification.

## Additional repairs

- Persist new transaction directory entries before host mutation; finalize read-only directory modes after descendants and restore exact modes during undo.
- Separate target exit status from cleanup proof; preserve a target exit 126 as an ordinary failure. Persist initial unverified completion before running and quarantine missing/corrupt/false proof, including after owner death.
- Keep a separate shared execution gate in the native supervisor so CLI death does not admit recovery/promotion before cleanup. Retain the exclusive record lock during handoff.
- Reject loader-affecting environment controls and target write overlap with trusted supervisor/control paths. Materialize trusted code outside target TMPDIR.
- Make environment checks static, refuse implicit host post-check execution and use absolute trusted copy helpers with cleared environment.
- Harden the legacy low-level journal with ID/ownership validation, writer exclusion, unique transaction naming, sync and corruption refusal. It still is not a replacement promoter.
- Fix lint-group priority, distinguish permitted test assertions from library panic/unwrap restrictions, add public error contracts, and keep strict Clippy as a completion gate.

## Explicit unsupported resource limits — 2026-10-30

`ResourcePolicy::default()` previously supplied numeric CPU, memory, wall-time, process-count and file-size values even though neither OS backend enforced them. Defaults now represent no requested backend quota. macOS and Linux refuse any explicit `ResourcePolicy` request before target execution until each requested limit has real enforcement semantics. The CLI/runtime wall and output ceilings are separate controls and are not reported as aggregate CPU/memory guarantees. macOS policy tests and Linux Rust 1.99.1 Docker tests include a pre-effect refusal canary. Linux Docker has a read-only cgroup v2 mount, so it cannot support or verify a future cgroup quota backend in this gate. One parallel macOS policy-suite run also had the existing localhost networking test fail with an unverified supervisor completion; its isolated rerun passed. Keep that failure in the evidence; the cause is unknown.

## Retained failure evidence and interpretation

The baseline had 19 discovered passing tests, 18 undiscovered tests, no Seatbelt tests and a failing strict Clippy gate. Synthetic probes demonstrated outside reads, a one-second deadline returning success after a longer closed-stream command, a late detached writer after a ready receipt, and normal repeated-state recovery failure.

During repair, tests caught a wrong automatic Clippy suggestion that removed path deduplication. The implementation now builds/extends an explicit ordered set before traversal and asserts one change per modified path. No review/transaction expectation was weakened. A first network implementation was rejected by the actual Seatbelt compiler: only `localhost`/wildcard address syntax was supported there, so unsupported remote-IP policy now fails closed instead of being advertised as implemented.

## Compatibility and limits

Fork/exec remains available; `posix_spawn` and detachment are deliberately unavailable. Some interpreter wrappers/build systems are incompatible. Arbitrary remote-host/DNS networking, Linux isolation and CPU/memory/process-count/disk-growth quotas remain unimplemented. Direct legacy Realm creation and implicit host post-check execution are removed behaviors. Existing ready records deserialize the new optional active identity; ambiguous old committed-with-lost-metadata history must be inspected, not guessed.

Multi-file promotion remains recoverable rather than globally atomic. Directory syncing improves persistence ordering but no physical power-loss campaign was run. Host editors/independent stores remain outside lock coordination. Private temp executables/history can need manual maintenance after hard interruption. These remain explicit limits, not closed user-outcome claims.

## Completion evidence

See [testing](../automation/TESTING.md) for commands/targets and the final committed test receipts. The acceptance gate is the original concrete behavior: denied outside authority, enforced lifetime/deadline, exact reviewed promotion, non-destructive conflict handling, repeated-state recovery and retained receipt identity. Documentation and lint success alone do not close those checks.


### Final local acceptance receipt

On 2026-10-28, macOS 27.0 arm64 with Rust/Cargo 1.98.1:

- `cargo test --workspace`: **57 passed, 0 failed** (including all 18 formerly orphaned tests); doc-test targets completed with no failures.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo build --locked --workspace`: passed.
- Local Markdown file links and `git diff --check`: passed.
- No third-party package/version was added; existing locked `tempfile` is reused by the supervisor and CLI fixtures. No generated executable or private control state is committed.

Linux containment, physical power-loss experiments and installed-client acceptance were not run or claimed. The repository commit and push do not update an installed helper or client.
