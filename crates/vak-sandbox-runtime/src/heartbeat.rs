use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub realm_id: String,
    pub timestamp: u64,
    pub pid: Option<u32>,
    pub load: f32,
    pub mem_mb: u64,
    pub alive: bool,
}

#[derive(Debug)]
pub struct HeartbeatMonitor {
    heartbeats: Arc<Mutex<HashMap<String, HeartbeatEntry>>>,
    timeout: Duration,
}

#[derive(Debug)]
struct HeartbeatEntry {
    last: Heartbeat,
    last_seen: Instant,
}

impl HeartbeatMonitor {
    #[must_use]
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            heartbeats: Arc::new(Mutex::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn ping(&self, hb: Heartbeat) {
        if let Ok(mut map) = self.heartbeats.lock() {
            map.insert(
                hb.realm_id.clone(),
                HeartbeatEntry {
                    last: hb,
                    last_seen: Instant::now(),
                },
            );
        }
    }

    #[must_use]
    pub fn is_alive(&self, realm_id: &str) -> bool {
        if let Ok(map) = self.heartbeats.lock()
            && let Some(entry) = map.get(realm_id)
        {
            return entry.last_seen.elapsed() < self.timeout && entry.last.alive;
        }
        false
    }

    #[must_use]
    pub fn get_all(&self) -> Vec<Heartbeat> {
        self.heartbeats.lock().map_or_else(
            |_| vec![],
            |map| map.values().map(|e| e.last.clone()).collect(),
        )
    }

    #[must_use]
    pub fn check_stale(&self) -> Vec<String> {
        self.heartbeats.lock().map_or_else(
            |_| vec![],
            |map| {
                map.iter()
                    .filter(|(_, e)| e.last_seen.elapsed() >= self.timeout)
                    .map(|(key, _)| key.clone())
                    .collect()
            },
        )
    }
}
