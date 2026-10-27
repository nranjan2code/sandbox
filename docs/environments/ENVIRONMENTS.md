# Environment Management

## Overview
Environments are prebuilt, content-addressed, distributable sandboxes with all dependencies ready. They are stored in `~/.cache/vak-sandbox/` and materialized using copy-on-write for efficiency.

## Directory Structure

```
~/.cache/vak-sandbox/
├── artifacts/    # Downloaded artifacts keyed by sha256
├── envs/         # Base environments keyed by sha256  
├── realms/       # Active realm instances by realm_id
└── state/        # Runtime state and journals
```

## Environment Spec Format

```toml
[env]
id = "node20"
version = "1.0.0"
description = "Node.js 20 LTS with npm/yarn"
platforms = ["macos", "linux"]
arch = ["x86_64", "aarch64"]

[base]
kind = "prebuilt"
artifact = "node20-v1.0.0.tar.zst"
sha256 = "abc123..."
size = 150000000

[tools.node]
version = "20.11.0"
check = ["node --version"]

[tools.npm]
version = "10.2.4"
check = ["npm --version"]

[checks]
required_bins = ["node", "npm", "git"]
post_check = ["node -e 'console.log(1)'"]

[policy_defaults.network]
egress = false
allow_hosts = []

[[mounts]]
src = "/usr/local/share/certs"
dst = "/etc/ssl/certs"
ro = true
```

## API Usage

### Creating a store
```rust
use vak_sandbox_env::EnvStore;
let store = EnvStore::new(EnvStore::default_root())?;
```

### Materializing an environment
```rust
use vak_sandbox_env::materialize;
let mat = materialize(&store, &sha256, &realm_id)?;
println!("Realm: {}", mat.realm_root.display());
println!("Writable: {}", mat.writable_layer.display());
```

### Checking an environment
```rust
use vak_sandbox_env::{load_spec, check_env};
let spec = load_spec(&Path::new("env.toml"))?;
let report = check_env(&spec, &realm_root)?;
if report.ok {
    println!("Environment OK");
}
```

### Hashing
```rust
use vak_sandbox_env::{sha256_bytes, sha256_file};
let h = sha256_file(&path)?;
```

## CoW Materialization

### macOS
Uses `cp -cR` for clonefile (copy-on-write) when available, falls back to regular copy.

### Linux
Uses regular copy with hardlink attempts where possible.

Base environment is hardened to read-only, writable layer at `.vak-sandbox-writable/` remains writable.
