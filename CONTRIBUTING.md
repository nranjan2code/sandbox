# Contributing to vak-sandbox

Thank you for your interest in contributing! This project prioritizes security, correctness, and clarity.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/sandbox.git`
3. Read [AGENTS.md](AGENTS.md) and [README.md](README.md)
4. Build: `cargo build --workspace`
5. Test: `cargo test --workspace`

## Development Guidelines

### Security First
- Never cut corners on security boundaries
- All paths must go through `confined()` 
- Use deny-by-default for all policies
- Never interpolate untrusted input into shell/Seatbelt profiles
- Add security tests for new attack vectors

### Code Quality
- Rust 2024 edition
- Follow existing style and patterns
- Add comments explaining *why*, especially for security rationale
- No `unwrap()`/`expect()`/`panic!()` in library code (tests are fine)
- Run `cargo clippy --workspace` and fix warnings
- Format with `cargo fmt`

### Testing
- Add unit tests for new functionality
- Add integration tests for cross-component features
- Add security tests for security-sensitive code
- All tests must pass on macOS and Linux
- Test with both debug and release builds when relevant

### Commits
- Use clear, descriptive commit messages
- Reference issues when applicable
- Keep commits focused

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Add/update tests
4. Run tests: `cargo test --workspace`
5. Run clippy: `cargo clippy --workspace`
6. Run fmt: `cargo fmt --all --check`
7. Commit and push
8. Open a Pull Request with clear description

## Reporting Security Issues

**Do not** open public issues for security vulnerabilities. Email security concerns privately.

## Areas to Contribute

- **Linux backends**: Landlock, seccomp-bpf, bubblewrap implementations
- **Promotion system**: Journal, rollback, diff generation
- **CLI**: Full vaksb implementation
- **Tests**: Security tests, integration tests, stress tests
- **Documentation**: Examples, tutorials, API docs
- **Performance**: Optimization while maintaining security
