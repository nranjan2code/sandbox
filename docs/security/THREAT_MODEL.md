# Threat model

## Assets and actors

Protect host project files until reviewed promotion, control records/receipts/backups, undeclared environment values, non-granted file content and network endpoints, and the ordering of command completion versus review/recovery.

The host caller, sandbox implementation, native supervisors, macOS kernel and system binaries/compiler are trusted. Target executables, their descendants, tool output and copied project files are untrusted. A separate hostile host process with the same user account, an administrator, a compromised compiler/kernel, and deliberate tampering with private control state are outside this containment model. Private directory permissions are not isolation from an already hostile same-UID host process.

The host application owns authorization. No model text, script, tool response or review fingerprint authorizes a host write by itself.

## Threats and enforcement

| Threat | Enforcement | Residual limitation |
| --- | --- | --- |
| Argument names a secret or whole external tree | Arguments never add read grants | Explicit executable and system runtime grants still apply |
| Path traversal/symlink escape in host operations | Relative confinement, component checks, canonical roots, regular-object scans | Checked path strings are not race-proof opened handles; avoid concurrent external mutation |
| Parent allow root overrides credential deny | Explicit denies emitted after allows | Filename exclusions do not scan secret contents |
| Child detaches and writes after receipt | Kernel group/session/spawn gates plus trusted anchored group, cleanup verification | Unmodified spawn-based tools may be unsupported |
| Owner is killed during execution | Native owner/anchor lifelines plus retained Realm execution gate | Crashes can leave private temporary executables for maintenance |
| Output closes before command exits | Deadline/signal/exit/stream state stays active until completion | No CPU/memory/process-count quota |
| Environment injects into trusted launcher | Clear ambient env; declared values only; reject loader controls | Explicitly permitted target credentials are intentionally visible to the target |
| Network exfiltration | No network by default; supported localhost ports only | Configured system/runtime reads may reveal their granted content |
| Stale or partially reviewed apply | Current complete fingerprint, exact ordered paths and original version checks | Review still needs semantic inspection by the caller |
| Recovery picks old same-content history | Persisted active transaction identity | Old-format interrupted metadata needs upgrade inspection |
| Crash during apply/undo | Durable candidates/backups and phases, conflict refusal, directory-aware restore | Multi-file visibility is not globally atomic; power-loss testing not performed |
| Poisoned environment/artifact cache | Validate identifiers, confine paths, verify existing bytes/tree digest and copied tree | Root metadata/ownership/ACLs are not a full image digest |
| Spec-owned post-check executes on host | Static `check_env`; executable checks are reported unexecuted | Caller must separately authorize a sandboxed test |

## Non-guarantees

No VM boundary, CPU/memory/process-count/disk-growth quota, arbitrary remote-host/DNS firewall, automatic secret-content scanner, arbitrary unmodified build-tool support, globally atomic multi-file commit or semantic code verification is provided. Linux process isolation is unavailable. Runtime locks coordinate one canonical store, not external editors or separate stores.

Do not weaken the boundary when a command fails. Keep unsupported execution, policy rejection, timeout, cancelled work, conflicting recovery and successful completion distinguishable. Neither safe rejection nor a valid receipt establishes correctness of a user's result.

## Evidence

See [hardening evidence](HARDENING-2026-10-28.md), [test targets](../automation/TESTING.md) and [operating constraints](../operations/RUNBOOK.md). Actual macOS fixture tests are required; profile strings and passing non-OS tests are insufficient.
