# Environment management

Environment management supplies verified file trees. It does not execute installation hooks, fetch artifacts, grant process permissions or authorize promotion.

## Layout and identifiers

```text
store/
  artifacts/<sha256>        immutable artifact bytes
  envs/<tree-sha256>/       pre-provisioned environment tree
  realms/<uuid>/           materialized copies / runtime Realm directories
  state/                   runtime-owned control state
```

SHA identifiers are exactly 64 lowercase hexadecimal characters. Materialization IDs must parse as UUIDs. Absolute paths, traversal and symlink-derived cache entries are refused; an arbitrary existing directory is not a valid environment ID.

The runtime's durable workspace format (`realms/<id>/workspace`) and the older `materialize` result (`realms/<id>` plus a writable layer) are distinct APIs. Do not point both at the same ID or reuse an existing materialization destination.

## Artifact integrity

`put_artifact(bytes, expected_sha)` verifies the input and any already-cached object at that path. Corrupt cache entries are rejected rather than reused. New bytes are written/synced through a private temporary file and persisted without clobbering a competing writer. The directory is synchronized afterward. This is byte verification, not a trust decision about executable content.

## Environment tree digest

`sha256_tree(root)` hashes deterministic JSON for a sorted mapping:

```text
relative UTF-8 path → [is_directory, bytes, mode & 0777, sha256(file bytes) or ""]
```

Regular files and directories only; symlinks/special files fail. Limits: 512 MiB total file bytes, 50,000 entries, 512 UTF-8 bytes per relative path and 8 MiB encoded manifest. Root permissions, timestamps, ownership, ACLs and extended attributes are not part of this digest. A tree digest is not a complete filesystem-image signature.

Provision a trusted tree separately, compute its digest and place it under `envs/<digest>`. `get_env_base` validates the ID, confines the directory and recomputes the tree digest before returning it. Environment aliases and implicit fetching are not implemented.

`materialize` requires a fresh UUID destination, copies via macOS clone-capable `/bin/cp` with a regular-copy fallback, rechecks copied content and then removes ordinary write permission bits outside `.vak-sandbox-writable`. The helper is invoked directly with a cleared environment. Source trees may not contain that reserved writable-layer name. Filesystem permissions are defense in depth; the caller still needs the OS process policy. There is no hardlink-based shared writable layer.

## Durable environment Realms

`RealmStore::create_environment(digest)` and `realm create --env DIGEST` use a verified stored source and the bounded Realm copier. Their `base_path` is absent. They retain a copy across commands, but cannot promote into the immutable cache. The same recovery flow supports their interrupted commands without requiring an original project.

Project-backed creation remains separate and refuses overlap with the control store. No environment request may reinterpret a digest as an unrestricted host path.

## Specs and static checks

`load_spec` parses TOML metadata. `vaksb env check SPEC` parses that specification; it is not an executable health check. `[tools]`, mounts and policy defaults are descriptive fields, not an implemented installer or automatic policy override.

`check_env` looks for explicitly declared binary names in `bin/` and `usr/bin/` inside the given root. Host PATH is not a substitute for a missing environment binary. It never executes spec-owned `post_check` commands: those checks are returned unsuccessful with an explanation. To run them, a trusted caller must build an explicit approved sandbox process plan and inspect its execution receipt.

This changes older behavior that could execute checks on the host. Do not restore host command execution as a compatibility fallback.
