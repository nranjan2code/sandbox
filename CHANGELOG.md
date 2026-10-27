# Changelog

All notable changes to vak-sandbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core traits and policy system (deny-by-default)
- Path confinement with symlink/traversal protection
- macOS Seatbelt backend for process isolation
- Environment store with content-addressed artifacts
- CoW materialization (macOS clonefile, fallback copy)
- Environment validation and checking
- SandboxManager with realm lifecycle
- HeartbeatMonitor with ping/liveness/stale detection
- Control protocol (Ping/Exec/Snapshot/Promote/Destroy/Status)
- Linux stubs for Landlock and Bubblewrap
- Full CLI (vaksb) with env/realm/status/ping/health commands
- Comprehensive test suite (unit, integration, security)
- World-class documentation
- CI workflow for macOS and Linux
- Security threat model
- Contributing guidelines
- MIT License

### Fixed
- Materialization now copies contents correctly
- CLI dependency management

### Security
- `unsafe_code = "deny"`
- Clippy lints deny unwrap/expect/panic in libraries
- Path injection protection in Seatbelt profiles
- Environment variable allowlisting
- Network deny-by-default
