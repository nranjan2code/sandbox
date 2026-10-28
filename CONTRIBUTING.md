# Contributing to vak-sandbox

Read [AGENTS.md](AGENTS.md) and the [current contract](README.md) first. Containment, durable change promotion and client authorization are different responsibilities; preserve those boundaries.

## Setup and required checks

Use Rust 1.90+ / edition 2024. Native macOS execution also needs the system command-line developer tools and Seatbelt helper. The in-repo C supervisor is compiled with warnings as errors; no external sandbox service is installed.

```sh
cargo build --locked --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

Integration tests belong in the owning crate. The root is a virtual workspace, so root-level test files are not automatically discovered. Run real macOS lifetime/policy tests; portable tests on Linux do not establish process containment there.

## Changing a boundary

- Start with a failing user-observable contract and freeze expected paths, bytes, permissions, receipts and side effects.
- Use synthetic canaries, temporary fixtures and locally owned listeners. Do not probe actual secrets, live projects or external services to demonstrate a defect.
- Inspect native control-descriptor ownership, group identity, owner-death behavior, lock handoff and verified completion independently of target exit codes.
- Test both allowed work and denied authority. A fail-closed rejection is useful evidence, but does not prove a supported workflow succeeds.
- Preserve uncertainty: invalid completion quarantines execution; later conflicts stop rollback; missing transaction identity is not guessed from equal content.
- Reject unsupported policy/runtime combinations and explain compatibility changes. Do not relax checks, reinstall packages or substitute host execution to make tests pass.
- Review automatic lint fixes. Sorting/deduplicating paths is semantic, even when a lint suggests removing a collection.

Keep Rust unsafe code denied; no unwrap/expect/panic in libraries. Test assertions may use them. Native code is part of the trusted computing base: checked system calls, validated data, close-on-exec controls and explicit cleanup are required. Public fallible APIs document their errors.

## Documentation and delivery

Update the supported contract, API docs, architecture/security invariants, runbook, upgrade notes, test evidence and changelog for behavior changes. Distinguish implemented behavior from future work. A repository push is not a release, installed-helper update or client acceptance test.

Review the staged diff and scan for credential patterns without printing any matches. Commit only the intended work and preserve unrelated edits. Never commit local credentials, caches, binaries, copied workspaces or private control state. Report security concerns through an appropriate private maintainer channel, not a public issue containing exploit details.
