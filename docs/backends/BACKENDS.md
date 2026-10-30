# Backend and policy support

## macOS Seatbelt

`SeatbeltBackend` supplies supervised process containment. Direct backend Realm creation is unavailable; use the runtime's durable Realm implementation. Backend flags consequently advertise process containment and bounded network policy support, not Realm isolation, promotion, rollback, resource quotas or universal symlink rejection.

### Filesystem

Read/write roots must be absolute and non-traversing. They are canonicalized, quoted as data and never silently omitted on failure. Explicit deny roots are emitted after allow rules and override parent grants. Future deny paths resolve through an existing ancestor. Quotes/backslashes are escaped; invalid control characters and non-UTF-8 policy paths are refused.

The backend adds only bootstrap metadata/root access and standard null/random device rules. The CLI/runtime explicitly add their system runtime read roots. Policy data permissions are distinct from the ability to fork/exec. The OS resolves permitted file targets; the backend does not guarantee rejection of every symlink hop. Realm scanners reject all symlinks separately. `follow_symlinks=true` is an unsupported override.

### Network

The default has no network rules. Enabled policies require `allow_outbound`, `allow_localhost`, a nonempty loopback-IP list and nonzero explicit ports. Each allowed endpoint compiles to `localhost:PORT`. Seatbelt's address syntax does not accept arbitrary literal remote IPs here; requests for non-loopback endpoints, domain names, direct DNS policy, unrestricted networking or incomplete contradictory settings return an invalid-policy error before process creation.

Inbound support is limited to the same explicitly permitted localhost ports. Specifying IPv4/IPv6 loopback does not select one loopback address family: the emitted `localhost` rule is the boundary. There is no hostname resolution proxy, remote-host firewall or automatic DNS permission.

The convenience broad-network builders remain public schema helpers; they do not make unsupported Seatbelt configurations valid. Check the actual backend contract instead of inferring support from a field name.

### Environment and execution

Only declared plan environment values and explicit policy values are passed; ambient environment is cleared. Invalid/NUL-containing keys/values and loader-affecting variables (`DYLD_*`, `__XPC_DYLD_*`, `MALLOC_*`, `LD_PRELOAD`, `LD_LIBRARY_PATH`) are rejected before trusted supervisor launch.

Executable/arguments are passed directly, with no implicit shell. Use an explicitly approved shell for shell syntax. Process-mode `exec` must match the command/arguments already started by its plan and supplies no second environment override. The direct legacy Realm shell path is rejected.

### Lifetime compatibility

The trusted supervisor and anchor require an immutable process group. Darwin syscall gates reject `setpgid` (82), `setsid` (147), `posix_spawn` (244) and indirect dispatch (0). The native build checks these numbers against platform headers. `posix_spawn` can change group/session inside the kernel, bypassing separate syscall gates; it is denied in full, not patched by a user-space wrapper.

Fork/exec descendants and explicit shell commands remain supported. Launchers and libraries that require `posix_spawn` may fail, including some interpreter entry points. Use a supported executable/runtime selected by the caller; never automatically relax isolation or switch to host execution. Arbitrary unmodified toolchain compatibility is not claimed.

Supervisor binaries live in a fresh private directory under `/private/tmp`, independently of target `TMPDIR`. A write grant overlapping that storage (for example all of `/private/tmp`) is rejected. Choose a narrower project directory. CPU/memory/process-count/file-growth quotas remain unenforced.

## Linux Landlock and seccomp

`LandlockBackend` runs only on x86_64/aarch64 kernels that expose Landlock ABI 5+ and seccomp filtering. Its first-party C supervisor is built into the crate. The runtime probes both mechanisms before advertising process containment; if either is missing or the policy cannot be applied, creation fails before the target command starts. Bubblewrap is not used and its mere presence never enables execution.

Landlock handles filesystem read, execute, write, create/remove, cross-directory rename/link, truncate and device-ioctl rights. Explicit canonical read/write roots are the only project grants; the runtime adds `/usr`, `/bin`, `/lib`, `/lib64`, the dynamic-loader cache when present and discovered toolchain directories. It does not grant the whole `/etc` tree. Standard null/random devices are separately granted. The backend removes all effective, permitted, inheritable and ambient Linux capabilities from the target before execution. It rejects policy denies, symlink-follow overrides, and any network allowance because it does not implement those semantics. Seccomp denies socket creation/use, session/group changes, namespace and mount operations, handle-based filesystem access, `clone3`, `io_uring`, ptrace, process-control routes and capability/keyring/BPF operations. A second filter limits `kill(2)` to the contained process group and denies thread-directed and pidfd signal routes. The target receives `/dev/null` as stdin, may use fork/exec, and cannot alter the trusted supervisor's process group. Descendants are reaped before a verified completion receipt releases the Realm execution gate.

Linux grants are established before target execution and inherited by its descendants. This is not a VM, cgroup, or hostile same-user isolation boundary. CPU, memory, process-count and disk-growth quotas are not enforced; the user can still exhaust those host resources. Commands relying on blocked syscalls may fail. No host execution fallback is permitted. Windows process containment is not implemented.

## Extension rule

Reject unsupported policies and advertise only implemented capabilities. A new backend must prove execution lifetime, environment filtering, path rules and denied/allowed endpoints with actual OS tests. Containment must not implicitly gain promotion authority.

### Linux private descriptor inspection

Interactive workers may call only `getsockopt(3, SOL_SOCKET, SO_TYPE)` to let runtime stream wrappers recognize the existing Unix stream. The same call on another descriptor, another option on descriptor 3, and every such call in ordinary execution is refused. Socket creation/pairs, connect/bind/listen/accept, option mutation, sendmsg/recvmsg descriptor passing and network dispatch remain denied. Read/write on the already connected private channel remain the only worker protocol path. ARM64 Docker verifies the exact allowed/denied calls and an actual Node 26 stream wrapper; this does not prove x86_64 or a packaged Linux desktop app.
