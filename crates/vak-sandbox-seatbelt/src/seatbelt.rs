#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::process::Stdio;
    use tokio::process::Command;
    use tokio::sync::{mpsc, oneshot, Mutex};
    use vak_sandbox_core::{BackendCaps, Error, ExecHandle, Policy, ProcessPlan, RealmPlan, Result, SandboxBackend, SandboxEnv, SandboxMode};

    fn shell_quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('\'');
        for c in s.chars() {
            if c == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        out
    }

    fn sbpl_quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                _ => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[derive(Clone)]
    struct SeatbeltProfile {
        _workspace: std::path::PathBuf,
        mode: SandboxMode,
        policy: Policy,
    }

    impl SeatbeltProfile {
        fn generate(&self) -> String {
            let mut p = String::from("(version 1)\n(deny default)\n");
            p.push_str("(allow process-exec)\n");
            p.push_str("(allow process-fork)\n");
            p.push_str("(allow signal (target same-sandbox))\n");
            p.push_str("(allow sysctl-read)\n");
            p.push_str("(allow mach-lookup)\n");
            p.push_str("(allow iokit-get-properties)\n");
            p.push_str("(allow file-read-metadata)\n");
            p.push_str("(allow file-read* (literal \"/\"))\n");

            for path in ["/System", "/usr", "/bin", "/sbin", "/Library", "/Applications", "/opt", "/private/etc", "/private/var/db", "/dev"] {
                p.push_str(&format!("(allow file-read* (subpath {}))\n", sbpl_quote(path)));
            }

            for path in &self.policy.fs.allow_read {
                if let Ok(canonical) = path.canonicalize() {
                    let s = canonical.display().to_string();
                    if !s.contains('"') && !s.contains('\\') {
                        p.push_str(&format!("(allow file-read* (subpath {}))\n", sbpl_quote(&s)));
                    }
                }
            }

            if self.mode == SandboxMode::Realm || !self.policy.fs.allow_write.is_empty() {
                for path in &self.policy.fs.allow_write {
                    if let Ok(canonical) = path.canonicalize() {
                        let s = canonical.display().to_string();
                        if !s.contains('"') && !s.contains('\\') {
                            p.push_str(&format!("(allow file-write* (subpath {}))\n", sbpl_quote(&s)));
                        }
                    }
                }
                for dev in ["/dev/null", "/dev/urandom", "/dev/random", "/dev/stdin", "/dev/stdout", "/dev/stderr"] {
                    p.push_str(&format!("(allow file-write* (subpath {}))\n", sbpl_quote(dev)));
                }
            }

            if self.policy.network.allow {
                if self.policy.network.allow_localhost {
                    if self.policy.network.allow_inbound || self.mode == SandboxMode::Realm {
                        p.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
                        p.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
                    }
                    if self.policy.network.allow_outbound {
                        p.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
                    }
                }
                if self.policy.network.allow_outbound {
                if self.policy.network.allow_hosts.is_empty() {
                    p.push_str("(allow network-outbound)\n");
                } else {
                    for host in &self.policy.network.allow_hosts {
                        if host.contains(':') || host.chars().all(|c| c.is_ascii_digit() || c == '.') {
                            p.push_str(&format!("(allow network-outbound (remote ip \"{}:*\")\n", host));
                        }
                    }
                }
                }
            }
            p
        }
    }

    #[derive(Clone)]
    pub struct SeatbeltBackend;

    impl SandboxBackend for SeatbeltBackend {
        fn id(&self) -> &str { "seatbelt" }
        fn name(&self) -> &str { "macOS Seatbelt" }
        fn platforms(&self) -> &[&str] { &["macos"] }
        fn available(&self) -> bool {
            std::path::Path::new("/usr/bin/sandbox-exec").exists()
        }
        fn capabilities(&self) -> BackendCaps {
            BackendCaps {
                process_jail: true,
                realm_isolation: true,
                promotion: true,
                rollback: true,
                network_control: true,
                resource_limits: false,
                symlink_protection: true,
            }
        }

        fn create_process(&self, plan: &ProcessPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            let plan = plan.clone();
            Box::pin(async move {
                let profile = SeatbeltProfile {
                    _workspace: plan.cwd.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_default()),
                    mode: SandboxMode::Process,
                    policy: plan.policy.clone(),
                };
                let profile_str = profile.generate();
                let mut cmd = Command::new("sandbox-exec");
                cmd.arg("-p").arg(&profile_str);
                cmd.arg("--");
                let full_cmd = format!("{} {}", shell_quote(&plan.command), plan.args.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "));
                cmd.arg("sh").arg("-c").arg(&full_cmd);
                if let Some(cwd) = &plan.cwd {
                    cmd.current_dir(cwd);
                }
                for (k, v) in &plan.policy.env.set {
                    cmd.env(k, v);
                }
                for (k, v) in &plan.env {
                    if plan.policy.env.allow.is_empty() || plan.policy.env.allow.contains(k) {
                        cmd.env(k, v);
                    }
                }
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                let child = cmd.spawn().map_err(|e| Error::Backend(e.to_string()))?;
                Ok(Box::new(SeatbeltEnv {
                    id: uuid::Uuid::new_v4().to_string(),
                    mode: SandboxMode::Process,
                    policy: plan.policy.clone(),
                    child: Mutex::new(child),
                }) as Box<dyn SandboxEnv>)
            })
        }

        fn create_realm(&self, plan: &RealmPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            let plan = plan.clone();
            Box::pin(async move {
                let profile = SeatbeltProfile {
                    _workspace: plan.realm_root.clone(),
                    mode: SandboxMode::Realm,
                    policy: plan.policy.clone(),
                };
                let profile_str = profile.generate();
                // Create a shell in the realm for interactive/work execution
                let mut cmd = Command::new("sandbox-exec");
                cmd.arg("-p").arg(&profile_str);
                cmd.arg("--");
                cmd.arg("sh");
                cmd.current_dir(&plan.realm_root);
                cmd.env("HOME", &plan.realm_root);
                cmd.env("TMPDIR", plan.realm_root.join(".vak-sandbox-writable"));
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                cmd.stdin(Stdio::piped());
                let child = cmd.spawn().map_err(|e| Error::Backend(e.to_string()))?;
                Ok(Box::new(SeatbeltEnv {
                    id: plan.id,
                    mode: SandboxMode::Realm,
                    policy: plan.policy.clone(),
                    child: Mutex::new(child),
                }) as Box<dyn SandboxEnv>)
            })
        }
    }

    struct SeatbeltEnv {
        id: String,
        mode: SandboxMode,
        policy: Policy,
        #[allow(dead_code)]
        child: Mutex<tokio::process::Child>,
    }

    impl SandboxEnv for SeatbeltEnv {
        fn id(&self) -> &str { &self.id }
        fn mode(&self) -> SandboxMode { self.mode }

        fn exec(&self, cmd: &str, args: &[String], _env: &HashMap<String, String>) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>> {
            let cmd = cmd.to_string();
            let args: Vec<String> = args.to_vec();
            let policy = self.policy.clone();
            Box::pin(async move {
                let (tx_out, rx_out) = mpsc::channel(256);
                let (tx_err, rx_err) = mpsc::channel(256);
                let (tx_exit, rx_exit) = oneshot::channel();

                let profile = SeatbeltProfile {
                    _workspace: std::path::PathBuf::from("/tmp"),
                    mode: SandboxMode::Process,
                    policy: policy.clone(),
                };
                let profile_str = profile.generate();

                let full_cmd = if args.is_empty() { cmd.clone() } else {
                    format!("{} {}", shell_quote(&cmd), args.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "))
                };

                tokio::spawn(async move {
                    let child = Command::new("sandbox-exec")
                        .arg("-p")
                        .arg(&profile_str)
                        .arg("--")
                        .arg("sh")
                        .arg("-c")
                        .arg(&full_cmd)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn();

                    match child {
                        Ok(mut c) => {
                            if let Some(stdout) = c.stdout.take() {
                                use tokio::io::{AsyncBufReadExt, BufReader};
                                let mut reader = BufReader::new(stdout).lines();
                                let tx = tx_out.clone();
                                tokio::spawn(async move {
                                    while let Ok(Some(line)) = reader.next_line().await {
                                        let _ = tx.send(line).await;
                                    }
                                });
                            }
                            if let Some(stderr) = c.stderr.take() {
                                use tokio::io::{AsyncBufReadExt, BufReader};
                                let mut reader = BufReader::new(stderr).lines();
                                tokio::spawn(async move {
                                    while let Ok(Some(line)) = reader.next_line().await {
                                        let _ = tx_err.send(line).await;
                                    }
                                });
                            }
                            let status = c.wait().await;
                            let code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
                            let _ = tx_exit.send(code);
                        }
                        Err(_) => {
                            let _ = tx_exit.send(-1);
                        }
                    }
                });

                Ok(ExecHandle {
                    stdout: rx_out,
                    stderr: rx_err,
                    exit_code: rx_exit,
                })
            })
        }

        fn destroy(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move {
                Ok(())
            })
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod stub {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use vak_sandbox_core::{BackendCaps, Error, ExecHandle, ProcessPlan, RealmPlan, Result, SandboxBackend, SandboxEnv};

    #[derive(Clone)]
    pub struct SeatbeltBackend;

    impl SandboxBackend for SeatbeltBackend {
        fn id(&self) -> &str { "seatbelt" }
        fn name(&self) -> &str { "macOS Seatbelt" }
        fn platforms(&self) -> &[&str] { &["macos"] }
        fn available(&self) -> bool { false }
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
        fn create_process(&self, _plan: &ProcessPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            Box::pin(async move { Err(Error::BackendNotAvailable("Seatbelt only available on macOS".into())) })
        }
        fn create_realm(&self, _plan: &RealmPlan) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            Box::pin(async move { Err(Error::BackendNotAvailable("Seatbelt only available on macOS".into())) })
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::SeatbeltBackend;

#[cfg(not(target_os = "macos"))]
pub use stub::SeatbeltBackend;
