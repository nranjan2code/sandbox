# Automated Testing Guide

## Test Philosophy
We aim for best-in-class automated testing covering:
- **Unit tests**: Core logic, policies, path confinement
- **Integration tests**: Cross-component workflows
- **Security tests**: Path traversal, symlink escapes, injection attempts
- **Platform tests**: macOS and Linux compatibility
- **Stress tests**: Resource limits, concurrency (planned)

## Running Tests

### All tests
```bash
cargo test --workspace
```

### Specific crate
```bash
cargo test -p vak-sandbox-core
cargo test -p vak-sandbox-env
cargo test -p vak-sandbox-runtime
```

### With output
```bash
cargo test --workspace -- --nocapture
```

### Release mode
```bash
cargo test --workspace --release
```

## Test Organization

```
tests/                        # Integration tests
├── path_security.rs         # Security-focused path tests
├── env_integration.rs       # Environment management tests
├── runtime_integration.rs   # Manager/heartbeat tests
└── policy_tests.rs          # Policy construction tests

crates/*/src/tests.rs       # Unit tests in modules
```

## Security Test Coverage

### Path Security
- ✅ Parent directory traversal (`..`)
- ✅ Absolute paths
- ✅ Nested traversal attempts
- ✅ Symlink escape detection
- ✅ Path containment validation
- ✅ Safe canonicalization

### Environment Security
- ✅ Hash verification
- ✅ Artifact integrity
- ✅ Bad hash rejection

### Runtime Security
- ✅ Realm isolation
- ✅ Heartbeat monitoring
- ✅ Lifecycle management

## CI/CD (Planned)

GitHub Actions workflow for:
- **Lint**: `cargo clippy --workspace -- -D warnings`
- **Format**: `cargo fmt --all -- --check`
- **Test (macOS)**: `cargo test --workspace`
- **Test (Linux)**: `cargo test --workspace` in container
- **Security audit**: `cargo audit`
- **MSRV check**: Rust 1.90
- **Doc tests**: `cargo test --doc`

## Writing Good Tests

1. Test security boundaries explicitly
2. Use `tempfile` for filesystem tests
3. Clean up resources
4. Test both success and failure cases
5. Add descriptive test names
6. Document complex security scenarios

## Coverage Goals
- Core: >90%
- Security-critical (path, policy): 100%
- Integration paths: Comprehensive
