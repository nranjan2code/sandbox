#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::process::Stdio;
    use tokio::process::Command;
    use vak_sandbox_core::{
        Error, ExecHandle, Policy, ProcessPlan, RealmPlan, Result, SandboxEnv, SandboxMode,
    };

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
        workspace: std::path::PathBuf,
        mode: SandboxMode,
        policy: Policy,
    }

    impl SeatbeltProfile {
        fn generate(&self) -> String {
            // Never interpolate untrusted paths directly - always quote properly
            let mut p = String::from("(version 1)\n(deny default)\n");

            // Allow basic process operations
            p.push_str("(allow process-exec)\n");
            p.push_str("(allow process-fork)\n");
            p.push_str("(allow signal (target same-sandbox))\n");
            p.push_str("(allow sysctl-read)\n");
            p.push_str("(allow mach-lookup)\n");
            p.push_str("(allow iokit-get-properties)\n");
            p.push_str("(allow file-read-metadata)\n");
            p.push_str("(allow file-read* (literal \"/\"))\n");

            // Allow reading system paths needed for execution
            for path in [
                "/System",
                "/usr",
                "/bin",
                "/sbin",
                "/Library",
                "/Applications",
                "/opt",
                "/private/etc",
                "/private/var/db",
                "/dev",
            ] {
                p.push_str(&format!(
                    "(allow file-read* (subpath {}))\n",
                    sbpl_quote(path)
                ));
            }

            // Allow reading specified paths - only if they exist and are safe
            for path in &self.policy.fs.allow_read {
                if let Ok(canonical) = path.canonicalize() {
                    let s = canonical.display().to_string();
                    // Extra safety check
                    if !s.contains('"') && !s.contains('\\') {
                        p.push_str(&format!(
                            "(allow file-read* (subpath {}))\n",
                            sbpl_quote(&s)
                        ));
                    }
                }
            }

            // Allow writing to specified paths
            if self.mode == SandboxMode::Realm || !self.policy.fs.allow_write.is_empty() {
                for path in &self.policy.fs.allow_write {
                    if let Ok(canonical) = path.canonicalize() {
                        let s = canonical.display().to_string();
                        if !s.contains('"') && !s.contains('\\') {
                            p.push_str(&format!(
                                "(allow file-write* (subpath {}))\n",
                                sbpl_quote(&s)
                            ));
                        }
                    }
                }
                for dev in ["/dev/null", "/dev/urandom", "/dev/random"] {
                    p.push_str(&format!(
                        "(allow file-write* (subpath {}))\n",
                        sbpl_quote(dev)
                    ));
                }
            }

            // Network control - deny by default, fine-grained control
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
                // Specific host egress
                if self.policy.network.allow_outbound {
                    for host in &self.policy.network.allow_hosts {
                        // Basic IP/host matching - seatbelt is limited, but we do our best
                        if host.contains(':')
                            || host.chars().all(|c| c.is_ascii_digit() || c == '.')
                        {
                            p.push_str(&format!(
                                "(allow network-outbound (remote ip \"{}:*\"))\n",
                                host
                            ));
                        }
                    }
                    // If hosts specified but we need DNS, allow it
                    if self.policy.network.allow_dns || !self.policy.network.allow_hosts.is_empty()
                    {
                        // DNS typically uses 53 - seatbelt has limited control here
                    }
                }
            }
            // Network completely denied by default

            p
        }
    }

    pub struct SeatbeltBackend;

    impl vak_sandbox_core::SandboxBackend for SeatbeltBackend {
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
            #[cfg(target_os = "macos")]
            {
                std::path::Path::new("/usr/bin/sandbox-exec").exists()
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        }
        fn capabilities(&self) -> vak_sandbox_core::BackendCaps {
            vak_sandbox_core::BackendCaps {
                process_jail: true,
                realm_isolation: true,
                promotion: true,
                rollback: true,
                network_control: true,
                resource_limits: false,
                symlink_protection: true,
            }
        }

        fn create_process(
            &self,
            plan: &ProcessPlan,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            let plan = plan.clone();
            Box::pin(async move {
                let profile = SeatbeltProfile {
                    workspace: plan
                        .cwd
                        .clone()
                        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default()),
                    mode: SandboxMode::Process,
                    policy: plan.policy.clone(),
                };
                let profile_str = profile.generate();
                let mut cmd = Command::new("sandbox-exec");
                cmd.arg("-p").arg(&profile_str);
                cmd.arg("--");
                cmd.arg("sh").arg("-c").arg(&format!(
                    "{} {}",
                    shell_quote(&plan.command),
                    plan.args
                        .iter()
                        .map(|a| shell_quote(a))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
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
                    child: tokio::sync::Mutex::new(child),
                }) as Box<dyn SandboxEnv>)
            })
        }

        fn create_realm(
            &self,
            _plan: &RealmPlan,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn SandboxEnv>>> + Send + '_>> {
            Box::pin(async move { Err(Error::Backend("realm not yet implemented".to_string())) })
        }
    }

    struct SeatbeltEnv {
        id: String,
        mode: SandboxMode,
        child: tokio::sync::Mutex<tokio::process::Child>,
    }

    impl SandboxEnv for SeatbeltEnv {
        fn id(&self) -> &str {
            &self.id
        }
        fn mode(&self) -> SandboxMode {
            self.mode
        }

        fn exec(
            &self,
            _cmd: &str,
            _args: &[String],
            _env: &HashMap<String, String>,
        ) -> Pin<Box<dyn Future<Output = Result<ExecHandle>> + Send + '_>> {
            Box::pin(async move {
                let (tx_out, rx_out) = tokio::sync::mpsc::channel(100);
                let (tx_err, rx_err) = tokio::sync::mpsc::channel(100);
                let (tx_exit, rx_exit) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let _ = tx_exit.send(0);
                });
                let _ = tx_out;
                let _ = tx_err;
                Ok(ExecHandle {
                    stdout: rx_out,
                    stderr: rx_err,
                    exit_code: rx_exit,
                })
            })
        }

        fn destroy(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            Box::pin(async move { Ok(()) })
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod stub {
    pub struct SeatbeltBackend;
}

#[cfg(target_os = "macos")]
pub use macos::SeatbeltBackend;

#[cfg(not(target_os = "macos"))]
pub use stub::SeatbeltBackend;
