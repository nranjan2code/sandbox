# Documentation

These documents describe the implemented contract. Planned backends or policies must not be inferred from trait fields or older examples.

| Document | Owns |
| --- | --- |
| [Handover](HANDOVER.md) | Final implementation state, evidence and remaining work |
| [Project README](../README.md) | Current scope, setup and capability/limit summary |
| [Runbook](operations/RUNBOOK.md) | Operator commands, review/apply/undo, interruption and troubleshooting |
| [Upgrade notes](operations/UPGRADING.md) | Breaking behavior, client migrations and saved-state cautions |
| [Architecture overview](architecture/OVERVIEW.md) | Ownership and process/store topology |
| [System design](architecture/SYSTEM_DESIGN.md) | Ordered execution, promotion and recovery invariants |
| [Threat model](security/THREAT_MODEL.md) | Trusted/untrusted actors, protected assets and exclusions |
| [Security architecture](security/SECURITY_ARCHITECTURE.md) | Concrete enforcement and remaining limitations |
| [Hardening record](security/HARDENING-2026-10-28.md) | Review finding disposition and measured evidence |
| [Backends](backends/BACKENDS.md) | Seatbelt policy support and compatibility restrictions |
| [Environment management](environments/ENVIRONMENTS.md) | Digests, cache layout, copying and static checking |
| [Core and runtime API](api/CORE_API.md) | Public ownership, launch semantics and fallible boundaries |
| [Testing](automation/TESTING.md) | Discovered targets, real OS checks, CI and evidence limits |
| [Changelog](../CHANGELOG.md) | Historical changes and compatibility notes |

A manifest snapshot is a review record. It is not a filesystem restore point. A receipt proves an operation's observed result, not the correctness of the code or data involved. macOS containment tests must run on macOS. Linux enforcement tests exercise Landlock and seccomp in the reported Docker kernel; they do not prove containment on every kernel, architecture or host configuration.
