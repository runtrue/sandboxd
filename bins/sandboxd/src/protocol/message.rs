use runtrue_sandbox_core::SnapshotMode;
use runtrue_sandbox_oci::TopologyLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) schema_version: u32,
    pub(crate) request_id: String,
    pub(crate) operation: Operation,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum Operation {
    Ping,
    Stats,
    Admit {
        topology: TopologyLock,
    },
    Run {
        topology: TopologyLock,
        project: String,
        wait_for: String,
        timeout_ms: u64,
    },
    Create {
        topology: TopologyLock,
        sandbox: String,
        timeout_ms: u64,
    },
    Restore {
        topology: TopologyLock,
        sandbox: String,
        snapshot: String,
        timeout_ms: u64,
    },
    Inspect {
        sandbox: String,
    },
    Pause {
        sandbox: String,
    },
    Resume {
        sandbox: String,
    },
    Stop {
        sandbox: String,
    },
    Logs {
        sandbox: String,
        container: String,
    },
    Snapshot {
        sandbox: String,
        snapshot: String,
        mode: SnapshotMode,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    pub(crate) schema_version: u32,
    pub(crate) request_id: String,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_outer_fields() {
        let encoded =
            r#"{"schema_version":1,"request_id":"a","operation":{"kind":"ping"},"surprise":true}"#;
        assert!(serde_json::from_str::<Request>(encoded).is_err());
    }

    #[test]
    fn rejects_unknown_operation_fields() {
        let encoded =
            r#"{"schema_version":1,"request_id":"a","operation":{"kind":"ping","surprise":true}}"#;
        assert!(serde_json::from_str::<Request>(encoded).is_err());
    }

    #[test]
    fn request_identifier_is_bounded() {
        assert!(valid_request_id("request_1"));
        assert!(!valid_request_id(""));
        assert!(!valid_request_id(&"x".repeat(65)));
        assert!(!valid_request_id("contains a space"));
    }
}
