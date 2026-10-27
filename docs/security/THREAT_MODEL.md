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
- **Mitigation**: Resource limits (CPU, memory, processes, file size, wall time)

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
| Resource limits | ✅ | Defined in policy |
| SHA256 verification | ✅ | For artifacts/envs |
| Crash-safe promotion | 🚧 | Journal design in place |
| Audit logging | 🚧 | Planned |
| seccomp-bpf | 🚧 | Linux planned |

## Security Testing
See `tests/path_security.rs` for security test coverage.
