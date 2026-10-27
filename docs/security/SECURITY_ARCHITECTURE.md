# Security Architecture

## Security Philosophy

vak-sandbox operates on the principle of **defense in depth** with **fail-safe defaults**. Every security boundary is enforced at multiple layers, and access is denied unless explicitly permitted.

## Trust Model

```
┌─────────────────────────────────────────────────────────┐
│                        TRUST BOUNDARIES                  │
├─────────────────────────────────────────────────────────┤
│ Host OS (Trusted)                                        │
│  ├── Sandbox Runtime (Trusted)                           │
│  ├── Control Plane (Trusted)                             │
│  └── Promotion Journal (Trusted, outside workspace)      │
├─────────────────────────────────────────────────────────┤
│ Sandbox Boundary (Untrusted Agent Code)                  │
│  ├── ProcessSandbox                                      │
│  └── RealmSandbox                                         │
└─────────────────────────────────────────────────────────┘
```

**Trusted**: Core runtime, policy engine, path validator, journal
**Untrusted**: Code executed in sandbox, MCP servers, agent tools

## Attack Surface Analysis

### 1. Path Traversal Attacks
**Vector**: `../../../etc/passwd`, symlink chains
**Impact**: Read/write outside sandbox
**Mitigations**:
- Reject absolute paths
- Reject `..` components
- Component-wise symlink detection
- Canonicalization of roots
- `confined()` validates all paths

### 2. Seatbelt Profile Injection
**Vector**: Malicious paths with quotes, backslashes, newlines
**Impact**: Profile syntax escape, privilege escalation
**Mitigations**:
- `sbpl_quote()` escapes all special characters
- Character validation rejects `"` and `\` in paths
- Canonicalization normalizes paths
- Never interpolate raw strings

### 3. Environment Variable Leakage
**Vector**: Inheriting `process.env` containing secrets
**Impact**: Credential exfiltration
**Mitigations**:
- Empty allowlist by default
- Explicit `EnvPolicy.allow` required
- Only `set` and `allow` vars passed
- No automatic inheritance

### 4. Network Exfiltration
**Vector**: Unauthorized connections
**Impact**: Data exfiltration, C2
**Mitigations**:
- `NetworkPolicy.allow = false` by default
- Granular host/port controls
- DNS control
- OS-level enforcement

### 5. Resource Exhaustion
**Vector**: Fork bombs, memory exhaustion, disk filling
**Impact**: DoS of host
**Mitigations**:
- `ResourcePolicy` limits defined
- Process limits
- Memory limits
- File size limits
- Wall time limits

### 6. Symlink Attacks
**Vector**: Create symlink pointing outside, traverse through it
**Impact**: Escape sandbox
**Mitigations**:
- Check each component with `symlink_metadata()`
- Reject if component is symlink
- `follow_symlinks = false` default

### 7. Promotion Attacks
**Vector**: Malicious files promoted to workspace
**Impact**: Code execution on host
**Mitigations**:
- Review required (manual/automated)
- Journaled with hashes
- Backups before apply
- Rollback capability
- Path re-validation at promotion time

## Security Controls Matrix

| Control | Layer | Enforcement | Status |
|---------|-------|-------------|--------|
| Deny-by-default policy | Application | Policy engine | ✅ |
| Path confinement | Application | `confined()` | ✅ |
| Symlink protection | Application | Metadata check | ✅ |
| Env allowlisting | Application | Filter | ✅ |
| Profile injection protection | Application | Quoting | ✅ |
| Seatbelt sandbox | OS | sandbox-exec | ✅ |
| Process isolation | OS | fork/spawn under sandbox | ✅ |
| Filesystem restrictions | OS | Seatbelt rules | ✅ |
| Network restrictions | OS | Seatbelt rules | ✅ |
| Resource limits | OS/App | ResourcePolicy | ⚠️ Partial |
| Audit logging | App | (planned) | 🚧 |
| Journal integrity | App | (planned) | 🚧 |

## Secure Coding Practices

### Path Handling
```rust
// WRONG - never do this
let path = format!("{}/{}", root, user_input);

// RIGHT - always confine
use vak_sandbox_core::path::confined;
let safe = confined(&root, user_input)?;
```

### Environment Handling
```rust
// WRONG - leaks everything
cmd.envs(std::env::vars());

// RIGHT - filtered
for (k,v) in &plan.policy.env.set {
    cmd.env(k, v);
}
for (k,v) in &plan.env {
    if plan.policy.env.allow.contains(k) { cmd.env(k,v); }
}
```

### Seatbelt Profile
```rust
// WRONG - injection vulnerable
p.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", user_path));

// RIGHT - safe quoting + validation
if let Ok(canonical) = path.canonicalize() {
    if !contains_bad_chars(&s) {
        p.push_str(&format!("(allow file-read* (subpath {}))\n", sbpl_quote(&s)));
    }
}
```

## Incident Response

### Sandbox Escape Detected
1. Kill sandboxed process immediately
2. Log incident with full context
3. Review audit trail
4. Check for modifications to host
5. Rollback if changes promoted

### Policy Violation
1. Deny operation
2. Log violation
3. Alert (if configured)

## Security Testing

See [THREAT_MODEL.md](THREAT_MODEL.md) for test coverage. Additional tests in `tests/path_security.rs`.

## Compliance Considerations

- **Least privilege**: Minimal permissions granted
- **Auditability**: All operations traceable (planned)
- **Fail secure**: Errors deny access
- **Defense in depth**: Multiple layers
