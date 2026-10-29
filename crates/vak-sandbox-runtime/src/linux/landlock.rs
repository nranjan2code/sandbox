#[cfg(target_os = "linux")]
pub struct LandlockBackend;

#[cfg(target_os = "linux")]
impl LandlockBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
    /// This type is a reserved integration point, not an implementation.
    /// Capability discovery must never advertise containment until a backend
    /// can apply and verify a complete policy for the current process.
    #[must_use]
    pub const fn available() -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
impl Default for LandlockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::LandlockBackend;

    #[test]
    fn stub_does_not_advertise_containment() {
        assert!(!LandlockBackend::available());
    }
}
