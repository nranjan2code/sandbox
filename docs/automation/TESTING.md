# Testing and verification

## Required local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --locked --workspace
cargo test --workspace
cargo test --workspace --doc
```

CI runs macOS native tests and Linux compilation/portable tests. Native supervision requires system command-line developer tools. The C build uses `-Wall -Wextra -Werror`; platform headers must agree with the Darwin syscall gates. Rust unsafe code remains denied. Test assertions may use unwrap/expect; library code may not.

## Discovered targets

The workspace root is virtual. A root-level `tests/` directory is not automatically a Cargo test package. The former 18 orphan test functions now live under owning crates:

| Target | Coverage |
| --- | --- |
| core unit / `tests/path_security.rs` | Relative confinement, absolute/traversal/symlink refusal, canonical containment |
| core `tests/policy_tests.rs` | Policy schema/default/builders |
| core journal unit tests | Durable append, active state, validation and history |
| env unit / `tests/env_integration.rs` | Byte/tree hashing, cache corruption refusal, ID confinement, verified fresh materialization, static-only post-checks |
| runtime unit / `tests/runtime_integration.rs` | Retained state, unique path review, conflicts, protected paths, apply/undo, interrupted state, repeated A→B→A content, directory modes, empty Realm recovery |
| CLI unit / `tests/containment.rs` | Actual macOS executable/argument boundary, closed-stream timeout, group lifetime, owner death, explicit shell semantics, environment filtering |
| Seatbelt `tests/policy.rs` | Actual deny-over-allow/future denies, quoted paths, permitted/denied localhost ports, unsupported policies and legacy API rejection, trusted storage/loader safeguards |

macOS-only tests use platform cfg guards; a zero-test target on Linux is not a macOS containment pass. Linux supervisor tests require Landlock ABI 5+ and seccomp and exercise actual kernel rules; on unsupported kernels they verify refusal before effects. Record kernel and architecture with the result. Run `cargo test --workspace -- --list` to inspect discovery rather than relying on a badge.

## Real process fixtures

`crates/vak-sandbox-ctl/tests/fixtures/probe.c` is first-party test code compiled with the system C compiler into a disposable directory. It checks denied group/session/spawn and indirect-dispatch operations, successful fork/exec, closed streams, and delayed synthetic marker writes. Its one deprecated raw syscall call is narrowly annotated because the test deliberately checks that legacy entry point; production code does not use it.

The tests never read actual secrets or require an internet endpoint. Network checks use locally owned loopback listeners. Filesystem probes use fresh temporary directories and synthetic canaries. A passing descendant test means its delayed write is absent after completion; owner-death tests wait for a fixture readiness marker before killing the CLI, then check the child cannot write later.

## Recovery tests

Freeze expected before/after bytes, paths, receipt identity and permission modes before evaluation. Simulate partial apply and commit/rollback metadata interruption; recover from retained candidates/backups without replay. Include repeated identical content states so history cannot be inferred from hashes. A conflict refusal is separate evidence from a successful intended apply/rollback.

Target exit 126 is tested through the actual Realm CLI and must retain an ordinary failure receipt plus ready status. Missing/false completion must remain quarantined after repeated recovery attempts. A leased command without `begin_execution` must be rejected before launch.

Native execution-gate tests must demonstrate that another operation cannot acquire an exclusive lease while a supervisor still holds the shared execution gate after owner loss. Do not delete lock files as a test cleanup shortcut.

## Evidence boundaries

The hardening run was exercised on macOS 27.0 arm64 and Linux 7.0.14 ARM64 in Docker. These runs are not evidence for every macOS/Linux kernel or architecture, arbitrary syscall-dependent runtimes, power-cut durability, kernel/service escape resistance or resource exhaustion. OS/architecture upgrades should rerun native policy and lifetime tests.

Semantic correctness of generated code or model outputs is outside these receipts. A successful command, safe rejection, committed patch or pushed repository does not substitute for the original user outcome. Preserve failed evidence while repairing tests/implementation and do not relax assertions to make a failed gate pass.
