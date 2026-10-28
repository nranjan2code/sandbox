# Threat Model

## Assets to Protect
- Host filesystem (especially outside workspace)
- Host network
- Host processes and system resources
- Secrets/environment variables
- User data

## Threats

### Path Traversal
- **Attack**: `../../../etc/passwd`, absolute paths
- **Mitigation**: `confined()` rejects `..` and absolute paths, canonicalization

### Symlink Attacks
- **Attack**: Symlink to sensitive files outside sandbox
- **Mitigation**: Walk components checking for symlinks, reject symlink escapes

### Profile Injection (Seatbelt)
- **Attack**: Malicious paths containing quotes/backslashes
- **Mitigation**: `sbpl_quote()` escaping, character validation, path canonicalization

### Environment Leakage
- **Attack**: Exposing secrets via env vars
- **Mitigation**: Deny-by-default env allowlist, never pass `process.env` wholesale

### Network Exfiltration
- **Attack**: Making unauthorized network connections
- **Mitigation**: Network disabled by default, explicit allowlists per host/port

### Resource Exhaustion
- **Attack**: Fork bombs, memory bombs, disk exhaustion
- **Mitigation**: Vakyartha bounds snapshot size, wall time and output; the current backend does not enforce CPU, memory, process-count or per-file-size quotas.

### TOCTOU (Time of Check/Time of Use)
- **Attack**: File changed between check and use
- **Mitigation**: Canonicalize paths, use file locks, validate at use time

### Promotion Attacks
- **Attack**: Malicious changes promoted to workspace
- **Mitigation**: Review required, journaled promotion, backups, rollback capability

## Security Controls

| Control | Status | Notes |
|---------|--------|-------|
| Path confinement | ✅ | Core implementation |
| Symlink protection | ✅ | Component-wise checking |
| Deny-by-default policies | ✅ | All policies default deny |
| Seatbelt profile injection protection | ✅ | Safe quoting |
| Env allowlisting | ✅ | Strict filtering |
| Network deny-by-default | ✅ | Explicit opt-in |
| Resource limits | ⚠️ | CLI has optional wall/output caps; memory, CPU, process-count and per-file quotas are not enforced |
| SHA256 verification | ✅ | For artifacts/envs |
| Recoverable promotion | ✅ bounded workflow | Reviewed candidate fingerprint and exact paths, original-file checks, durable backups/candidates, per-file atomic replacement and explicit recovery |
| Audit logging | 🚧 | Planned |
| seccomp-bpf | 🚧 | Linux planned |

## Security Testing
See `tests/path_security.rs` for security test coverage.


## Durable Realm limits (2026-10-28)

Control state lives outside every jailed copy. Commands cannot authorize promotion. The caller must supply the reviewed fingerprint and exact affected paths; the host application owns consent. OS locks coordinate managed operations sharing one control store. External editors or separate stores do not honor those locks, so callers must avoid concurrent target edits. Versions are rechecked before apply and rollback; multi-file visibility is not globally atomic. Later user edits stop rollback/recovery instead of being overwritten.

Symlinks, special files, protected credential paths and file/directory type replacement are refused. Initial copy exclusions are filename rules, not secret-content scanning. Time/output/copy/manifest/count limits do not enforce memory, CPU, process-count or disk-growth quotas. Hard interruption requires explicit inspection/recovery; no command is automatically replayed. Snapshots are review manifests, not restore points. Destroy retains promotion receipts/backups, which require separate disk/history management.
