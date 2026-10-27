# Backend Implementations

## Overview
vak-sandbox uses a backend-agnostic trait system. Each backend implements OS-specific sandboxing.

## Seatbelt (macOS) - Implemented

### Capabilities
- Process jail: ✅
- Realm isolation: 🚧 (in progress)
- Promotion: 🚧
- Network control: ✅ (fine-grained)
- Resource limits: ⚠️ (limited)
- Symlink protection: ✅ (app-level)

### Profile Generation
Deny-by-default with explicit allows:
```scheme
(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow file-read* (subpath "/usr"))
(allow file-write* (subpath "/tmp/workspace"))
```

### Security Features
- Safe quoting prevents injection
- Paths canonicalized before insertion
- Character validation
- Network rules explicit
- Minimal permissions

### Usage
```rust
use vak_sandbox_seatbelt::SeatbeltBackend;
use vak_sandbox_core::SandboxBackend;

let backend = SeatbeltBackend;
if backend.available() {
    let env = backend.create_process(&plan).await?;
}
```

## Landlock (Linux) - Stub

Planned for Linux kernel 5.13+ with Landlock LSM support.
- Filesystem restrictions
- Network restrictions (where supported)
- Syscall filtering

## Bubblewrap (Linux) - Stub

Uses `bwrap` for namespace-based isolation:
- Mount namespaces
- PID namespaces
- Network namespaces
- User namespaces
- Seccomp filtering

## Adding a Custom Backend

1. Implement `SandboxBackend` trait
2. Implement `SandboxEnv` trait
3. Add to workspace
4. Register with runtime

Example:
```rust
pub struct MyBackend;
impl SandboxBackend for MyBackend {
    fn id(&self) -> &str { "mybackend" }
    fn name(&self) -> &str { "My Backend" }
    fn platforms(&self) -> &[&str] { &["linux"] }
    fn available(&self) -> bool { true }
    fn capabilities(&self) -> BackendCaps { ... }
    fn create_process(&self, plan: &ProcessPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
        Box::pin(async move { ... })
    }
    fn create_realm(&self, plan: &RealmPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
        Box::pin(async move { ... })
    }
}
```
