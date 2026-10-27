use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    Ping {
        realm_id: String,
    },
    Exec {
        realm_id: String,
        cmd: String,
        args: Vec<String>,
    },
    Snapshot {
        realm_id: String,
    },
    Promote {
        realm_id: String,
    },
    Destroy {
        realm_id: String,
    },
    Status {
        realm_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlResponse {
    Pong {
        realm_id: String,
        alive: bool,
    },
    ExecResult {
        realm_id: String,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    Snapshot {
        realm_id: String,
        manifest: serde_json::Value,
    },
    Promoted {
        realm_id: String,
        receipt: serde_json::Value,
    },
    Destroyed {
        realm_id: String,
    },
    Status {
        realm_id: String,
        status: String,
        info: serde_json::Value,
    },
    Error {
        message: String,
    },
}
