#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::future::Future;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::pin::Pin;
    use std::process::Stdio;
    use tokio::process::{Child, Command};
    use tokio::sync::{Mutex, mpsc, oneshot};
    use vak_sandbox_core::{
        BackendCaps, Error, ExecHandle, Policy, ProcessPlan, RealmPlan, Result, SandboxBackend,
        SandboxEnv, SandboxMode,
    };

    fn validate_resource_policy(policy: &vak_sandbox_core::ResourcePolicy) -> Result<()> {
        if policy.has_requested_limits() {
            return Err(Error::InvalidPolicy(
                "macOS resource limits are not enforced by this backend; no command was run".into(),
            ));
        }
        Ok(())
    }

    fn sbpl_quote(value: &str) -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn rule_path(path: &Path) -> Result<String> {
        use std::path::Component;
        if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(Error::InvalidPolicy(
                "Policy paths must be absolute without parent traversal".into(),
            ));
        }
        // Future deny paths still need a rule; resolve their nearest existing ancestor.
        let mut ancestor = path;
        while !ancestor.exists() {
            ancestor = ancestor
                .parent()
                .ok_or_else(|| Error::InvalidPolicy("Unavailable policy root".into()))?;
        }
        let canonical = ancestor.canonicalize()?.join(
            path.strip_prefix(ancestor)
                .map_err(|e| Error::InvalidPolicy(e.to_string()))?,
        );
        let value = canonical
            .to_str()
            .ok_or_else(|| Error::InvalidPolicy("Policy paths must be UTF-8".into()))?;
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidPolicy(
                "Control character in policy path".into(),
            ));
        }
        Ok(sbpl_quote(value))
    }

    #[allow(
        clippy::format_push_string,
        reason = "Keep each safely quoted policy expression visible; profiles are built once per command."
    )]
    fn profile(policy: &Policy) -> Result<String> {
        if policy.fs.follow_symlinks {
            return Err(Error::InvalidPolicy(
                "Symlink following is not a supported policy override".into(),
            ));
        }
        let mut p = String::from(
            "(version 1)\n(deny default)\n(allow process-exec)\n(allow process-fork)\n(allow signal (target same-sandbox))\n(allow sysctl-read)\n(allow file-read-metadata)\n(allow file-read* (literal \"/\"))\n",
        );
        // Deny indirect syscalls (0), setpgid (82) and setsid (147) so processes cannot
        // detach or leave their supervised process group. posix_spawn (244) remains
        // allowed so runtimes (Python, Node, compilers) can spawn processes while
        // remaining in the supervised group.
        p.push_str("(allow syscall-unix)\n(deny syscall-unix (syscall-number 0) (syscall-number 82) (syscall-number 147))\n");
        for path in &policy.fs.allow_read {
            p.push_str(&format!(
                "(allow file-read* (subpath {}))\n",
                rule_path(path)?
            ));
        }
        for path in &policy.fs.allow_write {
            p.push_str(&format!(
                "(allow file-write* (subpath {}))\n",
                rule_path(path)?
            ));
        }
        for device in ["/dev/null", "/dev/random", "/dev/urandom"] {
            p.push_str(&format!(
                "(allow file-read* file-write* (literal {}))\n",
                sbpl_quote(device)
            ));
        }
        for path in &policy.fs.deny {
            p.push_str(&format!(
                "(deny file-read* file-write* (subpath {}))\n",
                rule_path(path)?
            ));
        }
        let net = &policy.network;
        if net.allow_dns {
            return Err(Error::InvalidPolicy(
                "Direct DNS control is unsupported; use explicit IP endpoints".into(),
            ));
        }
        if !net.allow {
            if net.allow_outbound
                || net.allow_inbound
                || net.allow_localhost
                || !net.allow_hosts.is_empty()
                || !net.allow_ports.is_empty()
            {
                return Err(Error::InvalidPolicy(
                    "Network permissions require network.allow".into(),
                ));
            }
            return Ok(p);
        }
        if !net.allow_outbound
            || net.allow_hosts.is_empty()
            || net.allow_ports.is_empty()
            || net.allow_ports.contains(&0)
        {
            return Err(Error::InvalidPolicy(
                "Networking requires explicit outbound IPs and nonzero ports".into(),
            ));
        }
        for host in &net.allow_hosts {
            let ip: std::net::IpAddr = host.parse().map_err(|_| {
                Error::InvalidPolicy("Only literal IP endpoints are supported".into())
            })?;
            if ip.is_loopback() && !net.allow_localhost {
                return Err(Error::InvalidPolicy(
                    "Loopback endpoint requires allow_localhost".into(),
                ));
            }
            if !ip.is_loopback() {
                return Err(Error::InvalidPolicy("Seatbelt supports localhost endpoint filtering only; remote IP policies require a separate network broker".into()));
            }
            for port in &net.allow_ports {
                let endpoint = format!("localhost:{port}");
                let endpoint = sbpl_quote(&endpoint);
                p.push_str(&format!(
                    "(allow network-outbound (remote ip {endpoint}))\n"
                ));
                if net.allow_inbound {
                    p.push_str(&format!(
                        "(allow network-bind network-inbound (local ip {endpoint}))\n"
                    ));
                }
            }
        }
        Ok(p)
    }

    #[derive(Clone)]
    pub struct SeatbeltBackend;
    impl SandboxBackend for SeatbeltBackend {
        fn id(&self) -> &'static str {
            "seatbelt"
        }
        fn name(&self) -> &'static str {
            "macOS Seatbelt"
        }
        fn platforms(&self) -> &[&str] {
            &["macos"]
        }
        fn available(&self) -> bool {
            Path::new("/usr/bin/sandbox-exec").exists()
        }
        fn capabilities(&self) -> BackendCaps {
            BackendCaps {
                process_jail: true,
                realm_isolation: false,
                promotion: false,
                rollback: false,
                network_control: true,
                resource_limits: false,
                symlink_protection: false,
            }
        }
        fn create_process(
            &self,
            plan: &ProcessPlan,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            self.create_process_with_lease(plan, None, None)
        }
        fn create_interactive_process(
            &self,
            plan: &ProcessPlan,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            Self::create_process_mode(plan.clone(), None, None, true)
        }

        fn create_realm(
            &self,
            _plan: &RealmPlan,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            Box::pin(async {
                Err(Error::Backend("Use runtime::RealmStore for durable Realms and its supervised process executor".into()))
            })
        }
    }

    impl SeatbeltBackend {
        /// Start a process while retaining a runtime-owned shared execution lock.
        /// The runtime must share its execution gate while retaining its exclusive record lease.
        ///
        /// # Errors
        /// Rejects invalid policy, overlapping trusted paths, invalid environment and launch errors.
        pub fn create_process_with_lease(
            &self,
            plan: &ProcessPlan,
            lease: Option<&Path>,
            completion: Option<&Path>,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            Self::create_process_mode(
                plan.clone(),
                lease.map(Path::to_path_buf),
                completion.map(Path::to_path_buf),
                false,
            )
        }

        #[allow(
            clippy::too_many_lines,
            reason = "Keep the macOS fail-closed policy admission and supervised process setup together."
        )]
        fn create_process_mode(
            plan: ProcessPlan,
            lease: Option<std::path::PathBuf>,
            completion: Option<std::path::PathBuf>,
            interactive: bool,
        ) -> vak_sandbox_core::backend::SandboxFuture<'static, Box<dyn SandboxEnv>> {
            Box::pin(async move {
                validate_resource_policy(&plan.policy.resources)?;
                let profile = profile(&plan.policy)?;
                for (key, value) in plan.policy.env.set.iter().chain(
                    plan.env
                        .iter()
                        .filter(|(key, _)| plan.policy.env.allow.contains(*key)),
                ) {
                    if key.is_empty()
                        || key.contains('=')
                        || key.contains('\0')
                        || value.contains('\0')
                        || key.starts_with("DYLD_")
                        || key.starts_with("__XPC_DYLD_")
                        || key.starts_with("MALLOC_")
                        || key == "LD_PRELOAD"
                        || key == "LD_LIBRARY_PATH"
                    {
                        return Err(Error::InvalidPolicy(
                            "Invalid or loader-affecting environment variable".into(),
                        ));
                    }
                }
                if plan.command.is_empty() || plan.command.contains('\0') {
                    return Err(Error::InvalidPolicy("Invalid executable".into()));
                }
                // The host owns this private executable; target code cannot replace it.
                // Caller-supplied TMPDIR is usually the writable workspace. The
                // trusted supervisor must never be materialized there.
                let control = tempfile::Builder::new()
                    .prefix("vaksb-supervisor-")
                    .tempdir_in("/private/tmp")?;
                let worker_listener = if interactive {
                    let socket = control.path().join("worker-input.sock");
                    let listener = UnixListener::bind(&socket)?;
                    listener.set_nonblocking(true)?;
                    Some((socket, listener))
                } else {
                    None
                };
                let mut supervisor = tempfile::NamedTempFile::new_in(control.path())?;
                let completion_path = if let Some(path) = completion {
                    path
                } else {
                    let path = control.path().join("completion.json");
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    path
                };
                for root in &plan.policy.fs.allow_write {
                    let canonical = root.canonicalize()?;
                    if completion_path.starts_with(&canonical)
                        || supervisor.path().starts_with(&canonical)
                        || lease
                            .as_ref()
                            .is_some_and(|path| path.starts_with(&canonical))
                    {
                        return Err(Error::InvalidPolicy("Writable scope overlaps trusted supervisor storage; choose a narrower workspace".into()));
                    }
                }
                supervisor.write_all(include_bytes!(concat!(
                    env!("OUT_DIR"),
                    "/vaksb-supervisor"
                )))?;
                supervisor
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o500))?;
                supervisor.as_file().sync_all()?;
                let supervisor = supervisor.into_temp_path();
                let mut cmd = Command::new(&supervisor);
                if let Some(lease) = lease {
                    cmd.arg("--lease-lock").arg(lease);
                }
                cmd.arg("--receipt").arg(&completion_path);
                if let Some((socket, _)) = &worker_listener {
                    cmd.arg("--worker-input-socket").arg(socket);
                }
                cmd.arg("-p")
                    .arg(profile)
                    .arg("--")
                    .arg(&plan.command)
                    .args(&plan.args);
                if let Some(cwd) = &plan.cwd {
                    cmd.current_dir(cwd);
                }
                cmd.env_clear().envs(&plan.policy.env.set);
                for (key, value) in &plan.env {
                    if plan.policy.env.allow.contains(key) {
                        cmd.env(key, value);
                    }
                }
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let child = cmd.spawn().map_err(|e| Error::Backend(e.to_string()))?;
                Ok(Box::new(SeatbeltEnv {
                    id: uuid::Uuid::new_v4().to_string(),
                    child: Mutex::new(Some(child)),
                    kill: Mutex::new(None),
                    done: Mutex::new(None),
                    process_spec: (plan.command, plan.args),
                    completion_path,
                    worker_listener: Mutex::new(worker_listener.map(|(_, listener)| listener)),
                    _supervisor: supervisor,
                    _control: control,
                }) as Box<dyn SandboxEnv>)
            })
        }
    }

    struct SeatbeltEnv {
        id: String,
        child: Mutex<Option<Child>>,
        kill: Mutex<Option<oneshot::Sender<()>>>,
        done: Mutex<Option<oneshot::Receiver<Result<()>>>>,
        process_spec: (String, Vec<String>),
        completion_path: std::path::PathBuf,
        worker_listener: Mutex<Option<UnixListener>>,
        _supervisor: tempfile::TempPath,
        _control: tempfile::TempDir,
    }
    fn completion(path: &Path, status: std::io::Result<std::process::ExitStatus>) -> Result<i32> {
        if !status.is_ok_and(|status| status.success()) {
            return Err(Error::Backend(
                "Trusted supervisor did not complete successfully".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 256 {
            return Err(Error::Backend(
                "Invalid supervisor completion receipt".into(),
            ));
        }
        let receipt: vak_sandbox_core::backend::ProcessCompletion =
            serde_json::from_slice(&std::fs::read(path)?)?;
        if !receipt.verified() {
            return Err(Error::Backend("Descendant cleanup was not verified".into()));
        }
        Ok(receipt.exit_code)
    }
    async fn forward<R: tokio::io::AsyncRead + Unpin>(mut reader: R, tx: mpsc::Sender<String>) {
        use tokio::io::AsyncReadExt;
        let mut buffer = [0u8; 8192];
        while let Ok(count) = reader.read(&mut buffer).await {
            if count == 0
                || tx
                    .send(String::from_utf8_lossy(&buffer[..count]).into_owned())
                    .await
                    .is_err()
            {
                break;
            }
        }
    }
    impl SeatbeltEnv {
        async fn start_exec(
            &self,
            command: &str,
            args: &[String],
            env: &HashMap<String, String>,
            interactive: bool,
        ) -> Result<ExecHandle> {
            use tokio::io::AsyncWriteExt;

            let matches =
                command == self.process_spec.0 && args == self.process_spec.1 && env.is_empty();
            let listener = self.worker_listener.lock().await.take();
            if !matches || listener.is_some() != interactive {
                self.destroy().await?;
                return Err(Error::Backend(
                    "exec mode must match its approved macOS process plan".into(),
                ));
            }
            let mut child = self
                .child
                .lock()
                .await
                .take()
                .ok_or_else(|| Error::Backend("process was already started".into()))?;
            let worker_io: Option<Box<dyn vak_sandbox_core::AsyncReadWrite + Send + Unpin>> =
                if let Some(listener) = listener {
                    let listener = tokio::net::UnixListener::from_std(listener)
                        .map_err(|error| Error::Backend(error.to_string()))?;
                    match tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                    {
                        Ok(Ok((mut stream, _))) => {
                            drop(listener);
                            if let Err(error) = stream.write_all(b"R").await {
                                let _ = child.kill().await;
                                let status = child.wait().await;
                                let _ = completion(&self.completion_path, status);
                                return Err(Error::Backend(format!(
                                    "private worker input handshake failed: {error}"
                                )));
                            }
                            Some(Box::new(stream))
                        }
                        Ok(Err(error)) => {
                            let _ = child.kill().await;
                            let status = child.wait().await;
                            let _ = completion(&self.completion_path, status);
                            return Err(Error::Backend(format!(
                                "private worker input connection failed: {error}"
                            )));
                        }
                        Err(_) => {
                            let _ = child.kill().await;
                            let status = child.wait().await;
                            let _ = completion(&self.completion_path, status);
                            return Err(Error::Backend(
                                "private worker input connection timed out".into(),
                            ));
                        }
                    }
                } else {
                    None
                };
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| Error::Backend("Missing stdout".into()))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| Error::Backend("Missing stderr".into()))?;
            let (out_tx, stdout_rx) = mpsc::channel(8);
            let (err_tx, stderr_rx) = mpsc::channel(8);
            let (exit_tx, exit_rx) = oneshot::channel();
            let (kill_tx, mut kill_rx) = oneshot::channel();
            let (done_tx, done_rx) = oneshot::channel();
            *self.kill.lock().await = Some(kill_tx);
            *self.done.lock().await = Some(done_rx);
            tokio::spawn(forward(stdout, out_tx));
            tokio::spawn(forward(stderr, err_tx));
            let mut lifetime = child.stdin.take();
            let completion_path = self.completion_path.clone();
            tokio::spawn(async move {
                let status = tokio::select! {
                    status = child.wait() => status,
                    _ = &mut kill_rx => { drop(lifetime.take()); child.wait().await }
                };
                drop(lifetime);
                let result = completion(&completion_path, status);
                let code = result.as_ref().copied().unwrap_or(-1);
                let _ = exit_tx.send(code);
                let _ = done_tx.send(result.map(|_| ()));
            });
            Ok(ExecHandle {
                worker_io,
                stdout: stdout_rx,
                stderr: stderr_rx,
                exit_code: exit_rx,
            })
        }
    }
    impl SandboxEnv for SeatbeltEnv {
        fn id(&self) -> &str {
            &self.id
        }
        fn mode(&self) -> SandboxMode {
            SandboxMode::Process
        }
        fn exec(
            &self,
            command: &str,
            args: &[String],
            env: &HashMap<String, String>,
        ) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>> {
            let command = command.to_owned();
            let args = args.to_vec();
            let env = env.clone();
            Box::pin(async move { self.start_exec(&command, &args, &env, false).await })
        }
        fn exec_interactive(
            &self,
            command: &str,
            args: &[String],
            env: &HashMap<String, String>,
        ) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>> {
            let command = command.to_owned();
            let args = args.to_vec();
            let env = env.clone();
            Box::pin(async move { self.start_exec(&command, &args, &env, true).await })
        }
        fn destroy(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                let kill = self.kill.lock().await.take();
                if let Some(kill) = kill {
                    let _ = kill.send(());
                }
                let child = self.child.lock().await.take();
                if let Some(mut child) = child {
                    drop(child.stdin.take());
                    let status = child.wait().await;
                    completion(&self.completion_path, status)?;
                }
                let done = self.done.lock().await.take();
                if let Some(done) = done {
                    done.await.map_err(|e| {
                        Error::Backend(format!("Supervisor cleanup did not finish: {e}"))
                    })??;
                }
                Ok(())
            })
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod stub {
    use vak_sandbox_core::{
        BackendCaps, Error, ProcessPlan, RealmPlan, Result, SandboxBackend, SandboxEnv,
    };

    #[derive(Clone)]
    pub struct SeatbeltBackend;

    impl SeatbeltBackend {
        /// # Errors
        /// Always returns backend-unavailable on non-macOS platforms.
        pub fn create_process_with_lease(
            &self,
            plan: &ProcessPlan,
            _lease: Option<&std::path::Path>,
            _completion: Option<&std::path::Path>,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            self.create_process(plan)
        }
    }
    impl SandboxBackend for SeatbeltBackend {
        fn id(&self) -> &str {
            "seatbelt"
        }
        fn name(&self) -> &str {
            "macOS Seatbelt"
        }
        fn platforms(&self) -> &[&str] {
            &["macos"]
        }
        fn available(&self) -> bool {
            false
        }
        fn capabilities(&self) -> BackendCaps {
            BackendCaps {
                process_jail: false,
                realm_isolation: false,
                promotion: false,
                rollback: false,
                network_control: false,
                resource_limits: false,
                symlink_protection: false,
            }
        }
        fn create_process(
            &self,
            _plan: &ProcessPlan,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            Box::pin(async move {
                Err(Error::BackendNotAvailable(
                    "Seatbelt only available on macOS".into(),
                ))
            })
        }
        fn create_realm(
            &self,
            _plan: &RealmPlan,
        ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
            Box::pin(async move {
                Err(Error::BackendNotAvailable(
                    "Seatbelt only available on macOS".into(),
                ))
            })
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::SeatbeltBackend;

#[cfg(not(target_os = "macos"))]
pub use stub::SeatbeltBackend;
