# Operations Runbook

## Quick Reference

| Command | Purpose |
|---------|---------|
| `vaksb realm create` | Create new realm |
| `vaksb realm list` | List all realms |
| `vaksb ping <id>` | Check realm health |
| `vaksb health` | System health overview |
| `vaksb env list` | List environments |

## Setup

### Prerequisites
- Rust 1.90+
- macOS 11+ or Linux kernel 5.13+
- For Linux: bubblewrap optional, Landlock supported

### Installation
```bash
git clone https://github.com/nranjan2code/sandbox.git
cd sandbox
cargo build --workspace --release
sudo cp target/release/vaksb /usr/local/bin/
```

### First Run
```bash
vaksb health
# Should show: Realms: 0, Alive: 0
```

## Realm Operations

### Create Realm (minimal)
```bash
vaksb realm create
```

### Create Realm from Environment
```bash
vaksb realm create --env <sha256>
```

### Check Realm Status
```bash
vaksb realm status <realm-id>
```

### Monitor Health
```bash
vaksb ping <realm-id>
vaksb health
```

### Destroy Realm
```bash
vaksb realm destroy <realm-id>
```

## Environment Operations

### List Environments
```bash
vaksb env list
```

### Check Environment Spec
```bash
vaksb env check /path/to/env.toml
```

## Troubleshooting

### "Realm not found"
- Check `vaksb realm list`
- Realm may have been destroyed

### Heartbeat timeouts
- Default timeout 30s
- Stale realms can be cleaned up

## Maintenance

### Clean up old realms
```bash
rm -rf ~/.cache/vak-sandbox/realms/<old-realm-id>
```

### Check disk usage
```bash
du -sh ~/.cache/vak-sandbox/
```

### Logs
```bash
RUST_LOG=debug vaksb <command>
```
