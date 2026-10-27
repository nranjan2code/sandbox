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
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            heartbeats: Arc::new(Mutex::new(HashMap::new())),
            timeout: Duration::from_secs(timeout_secs),
        }
    }
    
    pub fn ping(&self, hb: Heartbeat) {
        if let Ok(mut map) = self.heartbeats.lock() {
            map.insert(hb.realm_id.clone(), HeartbeatEntry {
                last: hb,
                last_seen: Instant::now(),
            });
        }
    }
    
    pub fn is_alive(&self, realm_id: &str) -> bool {
        if let Ok(map) = self.heartbeats.lock() {
            if let Some(entry) = map.get(realm_id) {
                return entry.last_seen.elapsed() < self.timeout && entry.last.alive;
            }
        }
        false
    }
    
    pub fn get_all(&self) -> Vec<Heartbeat> {
        if let Ok(map) = self.heartbeats.lock() {
            map.values().map(|e| e.last.clone()).collect()
        } else {
            vec![]
        }
    }
    
    pub fn check_stale(&self) -> Vec<String> {
        if let Ok(map) = self.heartbeats.lock() {
            map.iter()
                .filter(|(_, e)| e.last_seen.elapsed() >= self.timeout)
                .map(|(k, _)| k.clone())
                .collect()
        } else {
            vec![]
        }
    }
}
