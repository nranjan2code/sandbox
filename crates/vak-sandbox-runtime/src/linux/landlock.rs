#[cfg(target_os = "linux")]
pub struct LandlockBackend;

#[cfg(target_os = "linux")]
impl LandlockBackend {
    pub fn new() -> Self { Self }
    pub fn available() -> bool { true } // best effort
}
