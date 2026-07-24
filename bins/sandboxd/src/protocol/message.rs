use runtrue_sandbox_core::{SignedWorkOrder, SubjectId, TenantId, WorkspaceId};
pub(crate) use runtrue_sandbox_protocol::{
    valid_request_id, Operation, WorkloadResponse as Response, LEGACY_OPERATOR_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::WorkOrderOperation;
    use std::path::PathBuf;

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
