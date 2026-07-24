use runtrue_sandbox_core::{
    SignedWorkOrder, SnapshotMode, SubjectId, TenantId, WorkOrderOperation, WorkspaceId,
};
use runtrue_sandbox_oci::TopologyLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

pub(crate) const PROTOCOL_VERSION: u32 = 2;
pub(crate) const LEGACY_OPERATOR_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) schema_version: u32,
    pub(crate) request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorization: Option<RequestAuthorization>,
    pub(crate) operation: Operation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RequestAuthorization {
    Operator {
        tenant_id: TenantId,
        workspace_id: WorkspaceId,
        subject_id: SubjectId,
    },
    WorkOrder {
        work_order: Box<SignedWorkOrder>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[derive(Clone)]
pub(crate) enum Operation {
    Ping,
    Ready,
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
    PublishArtifact {
        source: PathBuf,
        digest: String,
    },
    GarbageCollectArtifacts {
        minimum_age_seconds: u64,
    },
    Shutdown,
}

impl Operation {
    pub(crate) fn work_order_operation(&self) -> Option<WorkOrderOperation> {
        Some(match self {
            Self::Ping => WorkOrderOperation::Ping,
            Self::Ready => return None,
            Self::Stats => WorkOrderOperation::Stats,
            Self::Admit { .. } => WorkOrderOperation::Admit,
            Self::Run { .. } => WorkOrderOperation::Run,
            Self::Create { .. } => WorkOrderOperation::Create,
            Self::Restore { .. } => WorkOrderOperation::Restore,
            Self::Inspect { .. } => WorkOrderOperation::Inspect,
            Self::Pause { .. } => WorkOrderOperation::Pause,
            Self::Resume { .. } => WorkOrderOperation::Resume,
            Self::Stop { .. } => WorkOrderOperation::Stop,
            Self::Logs { .. } => WorkOrderOperation::Logs,
            Self::Snapshot { .. } => WorkOrderOperation::Snapshot,
            Self::PublishArtifact { .. }
            | Self::GarbageCollectArtifacts { .. }
            | Self::Shutdown => return None,
        })
    }

    pub(crate) fn sandbox(&self) -> Option<&str> {
        match self {
            Self::Run { project, .. } => Some(project),
            Self::Create { sandbox, .. }
            | Self::Restore { sandbox, .. }
            | Self::Inspect { sandbox }
            | Self::Pause { sandbox }
            | Self::Resume { sandbox }
            | Self::Stop { sandbox }
            | Self::Logs { sandbox, .. }
            | Self::Snapshot { sandbox, .. } => Some(sandbox),
            Self::Ping
            | Self::Ready
            | Self::Stats
            | Self::Admit { .. }
            | Self::PublishArtifact { .. }
            | Self::GarbageCollectArtifacts { .. }
            | Self::Shutdown => None,
        }
    }

    pub(crate) fn digest(&self) -> Result<String, String> {
        serde_json::to_vec(self)
            .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
            .map_err(|error| format!("encode operation digest: {error}"))
    }

    pub(crate) fn timeout_ms(&self) -> Option<u64> {
        match self {
            Self::Run { timeout_ms, .. }
            | Self::Create { timeout_ms, .. }
            | Self::Restore { timeout_ms, .. } => Some(*timeout_ms),
            _ => None,
        }
    }

    pub(crate) fn topology(&self) -> Option<&TopologyLock> {
        match self {
            Self::Admit { topology }
            | Self::Run { topology, .. }
            | Self::Create { topology, .. }
            | Self::Restore { topology, .. } => Some(topology),
            Self::Ping
            | Self::Ready
            | Self::Stats
            | Self::Inspect { .. }
            | Self::Pause { .. }
            | Self::Resume { .. }
            | Self::Stop { .. }
            | Self::Logs { .. }
            | Self::Snapshot { .. }
            | Self::PublishArtifact { .. }
            | Self::GarbageCollectArtifacts { .. }
            | Self::Shutdown => None,
        }
    }
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

    #[test]
    fn legacy_operator_request_decodes_without_authorization() {
        let encoded = r#"{"schema_version":1,"request_id":"a","operation":{"kind":"ping"}}"#;
        let request = serde_json::from_str::<Request>(encoded).expect("legacy request");
        assert!(request.authorization.is_none());
        assert_eq!(
            request.operation.work_order_operation(),
            Some(WorkOrderOperation::Ping)
        );
    }

    #[test]
    fn operation_digest_changes_with_parameters() {
        let first = Operation::Inspect {
            sandbox: "sandbox-a".to_owned(),
        };
        let second = Operation::Inspect {
            sandbox: "sandbox-b".to_owned(),
        };
        assert_ne!(
            first.digest().expect("digest"),
            second.digest().expect("digest")
        );
    }

    #[test]
    fn artifact_maintenance_is_operator_only_and_has_no_tenant_topology() {
        let publication = Operation::PublishArtifact {
            source: PathBuf::from("/operator/staging/dataset"),
            digest: format!("sha256:{}", "a".repeat(64)),
        };
        let collection = Operation::GarbageCollectArtifacts {
            minimum_age_seconds: 86_400,
        };
        for operation in [&publication, &collection] {
            assert!(operation.work_order_operation().is_none());
            assert!(operation.topology().is_none());
            assert!(operation.sandbox().is_none());
        }
        let encoded = serde_json::to_value(&publication).expect("encode publication");
        assert_eq!(encoded["kind"], "publish_artifact");
    }
}
