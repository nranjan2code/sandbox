#[cfg(target_os = "linux")]
pub struct BubblewrapBackend;

#[cfg(target_os = "linux")]
impl BubblewrapBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    /// Binary presence is not proof that this crate can enforce a policy.
    #[must_use]
    pub const fn available() -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
impl Default for BubblewrapBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::BubblewrapBackend;

    #[test]
    fn stub_does_not_advertise_containment() {
        assert!(!BubblewrapBackend::available());
    }
}
