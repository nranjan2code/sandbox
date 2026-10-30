//! Linux process isolation using Landlock filesystem rules and seccomp network
//! and process-group restrictions. The trusted supervisor is first-party C.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::OnceLock;
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};
use vak_sandbox_core::{
    BackendCaps, Error, ExecHandle, ProcessPlan, RealmPlan, Result, SandboxBackend, SandboxEnv,
    SandboxMode,
};

static AVAILABLE: OnceLock<bool> = OnceLock::new();
const MAX_POLICY_ROOTS: usize = 256;
const MAX_COMMAND_BYTES: usize = 256;
const MAX_ARGUMENT_COUNT: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_TOTAL_ARGUMENT_BYTES: usize = 16_384;

const fn supervisor_bytes() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/vaksb-linux-supervisor"))
}

fn private_control_dir() -> Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("vaksb-linux-")
        .tempdir_in("/tmp")
        .map_err(Error::Io)
}

fn materialize_supervisor(directory: &Path) -> Result<tempfile::TempPath> {
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(supervisor_bytes())?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    file.as_file().sync_all()?;
    Ok(file.into_temp_path())
}

fn supported_kernel() -> bool {
    *AVAILABLE.get_or_init(|| {
        private_control_dir().is_ok_and(|directory| {
            materialize_supervisor(directory.path()).is_ok_and(|helper| {
                std::process::Command::new(&helper)
                    .arg("--probe")
                    .status()
                    .is_ok_and(|status| status.success())
            })
        })
    })
}

fn canonical_policy_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if paths.len() > 256 {
        return Err(Error::InvalidPolicy(
            "Too many filesystem policy roots".into(),
        ));
    }
    let mut canonical_paths = paths
        .iter()
        .map(|path| {
            let canonical = path.canonicalize().map_err(|_| {
                Error::InvalidPolicy("Every Linux filesystem grant must exist".into())
            })?;
            if !canonical.is_absolute() {
                return Err(Error::InvalidPolicy(
                    "Filesystem grants must be absolute paths".into(),
                ));
            }
            Ok(canonical)
        })
        .collect::<Result<Vec<_>>>()?;
    canonical_paths.sort();
    canonical_paths.dedup();
    Ok(canonical_paths)
}

fn validate_environment(plan: &ProcessPlan) -> Result<HashMap<String, String>> {
    let mut environment = plan.policy.env.set.clone();
    for (key, value) in &plan.env {
        if plan.policy.env.allow.contains(key) {
            environment.insert(key.clone(), value.clone());
        }
    }
    if environment.iter().any(|(key, value)| {
        key.is_empty()
            || key.contains(['=', '\0'])
            || value.contains('\0')
            || key.starts_with("LD_")
            || key == "GCONV_PATH"
            || key == "LOCPATH"
    }) {
        return Err(Error::InvalidPolicy(
            "Invalid or loader-affecting environment variable".into(),
        ));
    }
    Ok(environment)
}

fn validate_resource_policy(policy: &vak_sandbox_core::ResourcePolicy) -> Result<()> {
    if policy.has_requested_limits() {
        return Err(Error::InvalidPolicy(
            "Linux resource limits are not enforced by this backend; no command was run".into(),
        ));
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn completion(path: &Path, status: std::io::Result<std::process::ExitStatus>) -> Result<i32> {
    if !status.is_ok_and(|status| status.success()) {
        return Err(Error::Backend(
            "Trusted Linux supervisor did not complete successfully".into(),
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 256 {
        return Err(Error::Backend(
            "Invalid Linux supervisor completion receipt".into(),
        ));
    }
    let receipt: vak_sandbox_core::backend::ProcessCompletion =
        serde_json::from_slice(&std::fs::read(path)?)?;
    if !receipt.verified() {
        return Err(Error::Backend(
            "Linux descendant cleanup was not verified".into(),
        ));
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

#[derive(Clone)]
pub struct LandlockBackend;

impl LandlockBackend {
    /// Start a restricted command and retain the optional Realm execution gate.
    ///
    /// # Errors
    /// Refuses unsupported kernel policies and any authority the Linux backend cannot enforce.
    #[allow(
        clippy::too_many_lines,
        reason = "Keep the Linux fail-closed policy admission and process setup together."
    )]
    pub fn create_process_with_lease(
        &self,
        plan: &ProcessPlan,
        lease: Option<&Path>,
        completion_path: Option<&Path>,
    ) -> vak_sandbox_core::backend::SandboxFuture<'_, Box<dyn SandboxEnv>> {
        Self::create_process_mode(
            plan.clone(),
            lease.map(Path::to_path_buf),
            completion_path.map(Path::to_path_buf),
            false,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep the Linux fail-closed policy admission and supervised process setup together."
    )]
    fn create_process_mode(
        plan: ProcessPlan,
        lease: Option<PathBuf>,
        completion_path: Option<PathBuf>,
        interactive: bool,
    ) -> vak_sandbox_core::backend::SandboxFuture<'static, Box<dyn SandboxEnv>> {
        Box::pin(async move {
            if !supported_kernel() {
                return Err(Error::Backend(
                    "Linux execution requires Landlock ABI 5+ and seccomp; no command was run"
                        .into(),
                ));
            }
            validate_resource_policy(&plan.policy.resources)?;
            if plan.command.is_empty()
                || plan.command.len() > MAX_COMMAND_BYTES
                || plan.command.contains('\0')
                || plan.args.len() > MAX_ARGUMENT_COUNT
                || plan
                    .args
                    .iter()
                    .any(|argument| argument.len() > MAX_ARGUMENT_BYTES || argument.contains('\0'))
                || plan.args.iter().map(String::len).sum::<usize>() > MAX_TOTAL_ARGUMENT_BYTES
                || plan.policy.fs.follow_symlinks
                || !plan.policy.fs.deny.is_empty()
                || plan.policy.network.allow
                || plan.policy.network.allow_dns
                || plan.policy.network.allow_inbound
                || plan.policy.network.allow_outbound
                || plan.policy.network.allow_localhost
                || !plan.policy.network.allow_hosts.is_empty()
                || !plan.policy.network.allow_ports.is_empty()
            {
                return Err(Error::InvalidPolicy(
                    "Linux requires an explicit filesystem allowlist and denies network; this policy needs unsupported enforcement".into(),
                ));
            }
            let environment = validate_environment(&plan)?;
            let reads = canonical_policy_paths(&plan.policy.fs.allow_read)?;
            let writes = canonical_policy_paths(&plan.policy.fs.allow_write)?;
            if reads.len() + writes.len() + 3 > MAX_POLICY_ROOTS {
                return Err(Error::InvalidPolicy(
                    "Too many combined Linux filesystem policy roots".into(),
                ));
            }
            let cwd = plan
                .cwd
                .as_ref()
                .ok_or_else(|| Error::InvalidPolicy("A working directory is required".into()))?
                .canonicalize()?;
            if !reads
                .iter()
                .chain(writes.iter())
                .any(|root| cwd.starts_with(root))
            {
                return Err(Error::InvalidPolicy(
                    "Working directory is outside all filesystem grants".into(),
                ));
            }
            let directory = private_control_dir()?;
            let helper = materialize_supervisor(directory.path())?;
            if writes.iter().any(|root| overlaps(root, directory.path())) {
                return Err(Error::InvalidPolicy(
                    "Writable scope overlaps trusted Linux supervisor storage".into(),
                ));
            }
            let (receipt, receipt_temp) = if let Some(path) = completion_path {
                (path, None)
            } else {
                let file = tempfile::NamedTempFile::new_in(directory.path())?;
                let path = file.into_temp_path();
                (path.to_path_buf(), Some(path))
            };
            if writes.iter().any(|root| overlaps(root, &receipt))
                || lease
                    .as_ref()
                    .is_some_and(|path| writes.iter().any(|root| overlaps(root, path)))
            {
                return Err(Error::InvalidPolicy(
                    "Writable scope overlaps trusted control storage".into(),
                ));
            }
            let mut command = Command::new(&helper);
            command
                .arg("--cwd")
                .arg(&cwd)
                .arg("--receipt")
                .arg(&receipt);
            if let Some(lease) = &lease {
                command.arg("--lease-lock").arg(lease);
            }
            let worker_listener = if interactive {
                let socket = directory.path().join("worker-input.sock");
                let listener = UnixListener::bind(&socket)?;
                listener.set_nonblocking(true)?;
                command.arg("--worker-input-socket").arg(&socket);
                Some(listener)
            } else {
                None
            };
            for path in &reads {
                command.arg("--read").arg(path);
            }
            for path in &writes {
                command.arg("--write").arg(path);
            }
            command.arg("--").arg(&plan.command).args(&plan.args);
            command
                .current_dir("/")
                .env_clear()
                .envs(environment)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command.as_std_mut().process_group(0);
            Ok(Box::new(LandlockEnv {
                id: uuid::Uuid::new_v4().to_string(),
                process_spec: (plan.command, plan.args),
                command: Mutex::new(Some(command)),
                kill: Mutex::new(None),
                done: Mutex::new(None),
                completion_path: receipt,
                worker_listener: Mutex::new(worker_listener),
                _receipt: receipt_temp,
                _helper: helper,
                _control: directory,
            }) as Box<dyn SandboxEnv>)
        })
    }
}

impl SandboxBackend for LandlockBackend {
    fn id(&self) -> &'static str {
        "landlock-seccomp"
    }
    fn name(&self) -> &'static str {
        "Linux Landlock and seccomp"
    }
    fn platforms(&self) -> &[&str] {
        &["linux"]
    }
    fn available(&self) -> bool {
        supported_kernel()
    }
    fn capabilities(&self) -> BackendCaps {
        BackendCaps {
            process_jail: self.available(),
            realm_isolation: false,
            promotion: false,
            rollback: false,
            network_control: self.available(),
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
            Err(Error::Backend(
                "Use runtime::RealmStore for durable Realms and its supervised process executor"
                    .into(),
            ))
        })
    }
}

struct LandlockEnv {
    id: String,
    process_spec: (String, Vec<String>),
    command: Mutex<Option<Command>>,
    kill: Mutex<Option<oneshot::Sender<()>>>,
    done: Mutex<Option<oneshot::Receiver<Result<()>>>>,
    completion_path: PathBuf,
    worker_listener: Mutex<Option<UnixListener>>,
    _receipt: Option<tempfile::TempPath>,
    _helper: tempfile::TempPath,
    _control: tempfile::TempDir,
}

impl LandlockEnv {
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
                "exec mode must match its approved Linux process plan".into(),
            ));
        }
        let mut command = self
            .command
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::Backend("process was already started".into()))?;
        let mut child = command
            .spawn()
            .map_err(|error| Error::Backend(error.to_string()))?;
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
                            let _ = child.wait().await;
                            return Err(Error::Backend(format!(
                                "private worker input handshake failed: {error}"
                            )));
                        }
                        Some(Box::new(stream))
                    }
                    Ok(Err(error)) => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        return Err(Error::Backend(format!(
                            "private worker input connection failed: {error}"
                        )));
                    }
                    Err(_) => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
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
        let mut control = child.stdin.take();
        let receipt = self.completion_path.clone();
        tokio::spawn(async move {
            let status = tokio::select! {
                status = child.wait() => status,
                _ = &mut kill_rx => { drop(control.take()); child.wait().await }
            };
            drop(control);
            let result = completion(&receipt, status);
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

impl SandboxEnv for LandlockEnv {
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
            self.command.lock().await.take();
            let done = self.done.lock().await.take();
            if let Some(done) = done {
                done.await
                    .map_err(|error| Error::Backend(error.to_string()))??;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use vak_sandbox_core::Policy;

    fn policy(workspace: &Path) -> Policy {
        let mut policy = Policy::deny_all()
            .allow_path_read(workspace.to_path_buf())
            .allow_path_write(workspace.to_path_buf());
        for root in ["/usr", "/bin", "/lib", "/lib64"] {
            if Path::new(root).exists() {
                policy = policy.allow_path_read(root.into());
            }
        }
        if Path::new("/etc/ld.so.cache").is_file() {
            policy = policy.allow_path_read("/etc/ld.so.cache".into());
        }
        policy
    }

    async fn run(
        workspace: &Path,
        command: &str,
        args: &[String],
        policy: Policy,
    ) -> (i32, String, String) {
        let plan = ProcessPlan {
            command: command.into(),
            args: args.to_vec(),
            cwd: Some(workspace.into()),
            env: HashMap::new(),
            policy,
        };
        let backend = LandlockBackend;
        let environment = backend.create_process(&plan).await.unwrap();
        let handle = environment
            .exec(command, args, &HashMap::new())
            .await
            .unwrap();
        let (stdout, stderr) = tokio::join!(
            async move {
                let mut value = String::new();
                let mut stream = handle.stdout;
                while let Some(chunk) = stream.recv().await {
                    value.push_str(&chunk);
                }
                value
            },
            async move {
                let mut value = String::new();
                let mut stream = handle.stderr;
                while let Some(chunk) = stream.recv().await {
                    value.push_str(&chunk);
                }
                value
            }
        );
        let code = handle.exit_code.await.unwrap();
        environment.destroy().await.unwrap();
        (code, stdout, stderr)
    }

    #[tokio::test]
    async fn filesystem_and_network_access_fail_closed() {
        let backend = LandlockBackend;
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("canary");
        std::fs::write(&secret, "outside-secret").unwrap();

        if !backend.available() {
            let plan = ProcessPlan {
                command: "/bin/true".into(),
                args: Vec::new(),
                cwd: Some(workspace.path().into()),
                env: HashMap::new(),
                policy: policy(workspace.path()),
            };
            assert!(backend.create_process(&plan).await.is_err());
            return;
        }

        let marker = workspace.path().join("allowed-write");
        let existing = workspace.path().join("existing-write");
        std::fs::write(&existing, "old").unwrap();
        let (code, stdout, _) = run(
            workspace.path(),
            "/bin/sh",
            &[
                "-c".into(),
                "cat \"$1\"; printf safe > \"$2\"; printf changed > \"$3\"".into(),
                "sandbox-test".into(),
                secret.display().to_string(),
                marker.display().to_string(),
                existing.display().to_string(),
            ],
            policy(workspace.path()),
        )
        .await;
        assert_eq!(code, 0);
        assert_eq!(stdout, "");
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "safe");
        assert_eq!(std::fs::read_to_string(existing).unwrap(), "changed");
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "outside-secret");

        let (code, stdout, stderr) = run(
            workspace.path(),
            "/bin/sh",
            &["-c".into(), "cat /etc/passwd >/dev/null".into()],
            policy(workspace.path()),
        )
        .await;
        assert_ne!(code, 0);
        assert_eq!(stdout, "");
        assert!(stderr.contains("Permission denied"), "{stderr}");

        let (code, stdout, _) = run(
            workspace.path(),
            "/usr/bin/grep",
            &["CapEff:".into(), "/proc/self/status".into()],
            policy(workspace.path()).allow_path_read("/proc".into()),
        )
        .await;
        assert_eq!(code, 0);
        assert_eq!(stdout.split_whitespace().last(), Some("0000000000000000"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (code, _, stderr) = run(
            workspace.path(),
            "/bin/bash",
            &[
                "-c".into(),
                "echo test > /dev/tcp/$1/$2".into(),
                "sandbox-test".into(),
                address.ip().to_string(),
                address.port().to_string(),
            ],
            policy(workspace.path()),
        )
        .await;
        assert_ne!(code, 0);
        assert!(stderr.contains("Operation not permitted"), "{stderr}");
        assert!(listener.set_nonblocking(true).is_ok());
        assert!(listener.accept().is_err());
    }

    #[tokio::test]
    async fn unsupported_network_policy_refuses_before_execution() {
        let workspace = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("should-not-exist");
        let mut policy = policy(workspace.path());
        policy.network = vak_sandbox_core::NetworkPolicy {
            allow: true,
            allow_dns: false,
            allow_inbound: false,
            allow_outbound: true,
            allow_localhost: true,
            allow_hosts: vec!["127.0.0.1".into()],
            allow_ports: vec![8000],
        };
        let plan = ProcessPlan {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), format!("touch {}", marker.display())],
            cwd: Some(workspace.path().into()),
            env: HashMap::new(),
            policy,
        };
        assert!(LandlockBackend.create_process(&plan).await.is_err());
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn requested_resource_limits_refuse_before_execution() {
        let workspace = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("should-not-exist");
        let mut policy = policy(workspace.path());
        policy.resources.max_memory_bytes = Some(64 * 1024 * 1024);
        let plan = ProcessPlan {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), format!("touch {}", marker.display())],
            cwd: Some(workspace.path().into()),
            env: HashMap::new(),
            policy,
        };
        let result = LandlockBackend.create_process(&plan).await;
        if !LandlockBackend.available() {
            assert!(result.is_err());
            assert!(!marker.exists());
            return;
        }
        assert!(
            matches!(result, Err(Error::InvalidPolicy(message)) if message.contains("resource limits are not enforced"))
        );
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn oversized_command_arguments_refuse_before_execution() {
        let workspace = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("should-not-exist");
        let plan = ProcessPlan {
            command: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!("touch {}", marker.display()),
                "x".repeat(MAX_ARGUMENT_BYTES + 1),
            ],
            cwd: Some(workspace.path().into()),
            env: HashMap::new(),
            policy: policy(workspace.path()),
        };
        assert!(LandlockBackend.create_process(&plan).await.is_err());
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn detached_descendants_are_cleaned_before_receipt() {
        let workspace = tempfile::tempdir().unwrap();
        if !LandlockBackend.available() {
            return;
        }
        let marker = workspace.path().join("late-marker");
        let (code, _, _) = run(
            workspace.path(),
            "/bin/sh",
            &[
                "-c".into(),
                "(sleep 1; printf late > \"$1\") & exit 0".into(),
                "sandbox-test".into(),
                marker.display().to_string(),
            ],
            policy(workspace.path()),
        )
        .await;
        assert_eq!(code, 0);
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn closing_supervisor_input_cancels_the_restricted_group() {
        let workspace = tempfile::tempdir().unwrap();
        if !LandlockBackend.available() {
            return;
        }
        let marker = workspace.path().join("cancelled-marker");
        let plan = ProcessPlan {
            command: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "sleep 2; printf late > \"$1\"".into(),
                "sandbox-test".into(),
                marker.display().to_string(),
            ],
            cwd: Some(workspace.path().into()),
            env: HashMap::new(),
            policy: policy(workspace.path()),
        };
        let environment = LandlockBackend.create_process(&plan).await.unwrap();
        let handle = environment
            .exec(&plan.command, &plan.args, &HashMap::new())
            .await
            .unwrap();
        environment.destroy().await.unwrap();
        assert_eq!(handle.exit_code.await.unwrap(), 143);
        tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn interactive_worker_fd_is_separate_and_target_stdin_stays_null() {
        use tokio::io::AsyncWriteExt;

        let backend = LandlockBackend;
        if !backend.available() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let plan = ProcessPlan {
            command: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "if read -r line <&0; then exit 77; fi; cat <&3".into(),
            ],
            cwd: Some(workspace.path().into()),
            env: HashMap::new(),
            policy: policy(workspace.path()),
        };
        let environment = backend.create_interactive_process(&plan).await.unwrap();
        let mut handle = environment
            .exec_interactive("/bin/sh", &plan.args, &HashMap::new())
            .await
            .unwrap();
        let mut input = handle.worker_io.take().expect("private worker I/O");
        input.write_all(b"private-worker-input\n").await.unwrap();
        drop(input);
        let output_task = tokio::spawn(async move {
            let mut output = String::new();
            while let Some(chunk) = handle.stdout.recv().await {
                output.push_str(&chunk);
            }
            output
        });
        let code = handle.exit_code.await.unwrap();
        assert_eq!(code, 0);
        assert_eq!(output_task.await.unwrap(), "private-worker-input\n");
        environment.destroy().await.unwrap();
    }

    #[tokio::test]
    async fn restricted_command_cannot_signal_its_trusted_supervisor() {
        let workspace = tempfile::tempdir().unwrap();
        if !LandlockBackend.available() {
            return;
        }
        let (code, stdout, _) = run(
            workspace.path(),
            "/bin/sh",
            &[
                "-c".into(),
                "kill -KILL \"$PPID\" 2>/dev/null || true; printf alive".into(),
                "sandbox-test".into(),
            ],
            policy(workspace.path()),
        )
        .await;
        assert_eq!(code, 0);
        assert_eq!(stdout, "alive");
    }
}
