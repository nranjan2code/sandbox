#[cfg(target_os = "linux")]
pub struct BubblewrapBackend;

#[cfg(target_os = "linux")]
impl BubblewrapBackend {
    pub fn new() -> Self {
        Self
    }
    pub fn available() -> bool {
        std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
