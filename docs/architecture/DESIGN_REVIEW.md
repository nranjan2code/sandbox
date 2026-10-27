# Design Review & Improvements

## Issues Identified & Fixed

### 1. Materialization Bug
- **Issue**: Was copying the base directory as `realm_root/base_dir_name` instead of copying contents
- **Fix**: Copy contents with `cp -R src/. dst/` to materialize properly
- **Impact**: Realms now work correctly with prebuilt environments

### 2. CLI Dependencies
- **Issue**: anyhow dependency management in workspace
- **Fix**: Properly configured
- **Status**: Resolved

## Remaining Design Considerations

### Seatbelt Backend
- `create_realm` not fully implemented - needs to integrate with EnvStore/materialization
- `exec` in SeatbeltEnv is stubbed (returns 0 immediately)
- Need proper process management with stdout/stderr streaming

### Promotion System
- Not yet implemented (critical for realm workflow)
- Needs: journal, backups, diff, atomic apply, rollback
- Should follow Vak/code patterns

### Linux Backends
- Landlock and Bubblewrap are stubs
- Need full implementation for cross-platform support

### Resource Limits
- Defined in policy but not enforced by backends yet
- Seatbelt has limited resource control

## Recommendations

1. **Complete Seatbelt realm integration** - Wire up materialization
2. **Implement promotion journal** - Write-ahead log, crash safety
3. **Add exec streaming** - Properly pipe stdout/stderr
4. **Linux backends** - Implement Landlock/seccomp/bwrap
5. **Add more tests** - End-to-end scenarios, stress tests

All core architecture is solid. The design is sound for the stated goals.
