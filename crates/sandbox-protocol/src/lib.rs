use runtrue_sandbox_core::{
    ResourceCeilings, SignedWorkOrder, SnapshotMode, WorkOrderOperation, WorkerId,
    WORK_ORDER_VERSION,
};
use runtrue_sandbox_oci::TopologyLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{net::SocketAddr, path::PathBuf};

pub const PROTOCOL_VERSION: u32 = 2;
pub const LEGACY_OPERATOR_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAdvertisement {
    pub worker_id: WorkerId,
    pub pool_name: String,
    pub topology: String,
    pub resource_shape: String,
    pub compatibility_cohort: String,
    pub broker_address: SocketAddr,
    pub resource_ceilings: ResourceCeilings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub authorization: WorkloadAuthorization,
    pub operation: Operation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadAuthorization {
    WorkOrder { work_order: Box<SignedWorkOrder> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadResponse {
    pub schema_version: u32,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WorkloadResponse {
    pub fn validate_for(&self, request_id: &str) -> Result<(), &'static str> {
        if self.schema_version != PROTOCOL_VERSION
            || self.request_id != request_id
            || !valid_request_id(&self.request_id)
        {
            return Err("response identity does not match the request");
        }
        if (self.ok && self.error.is_some())
            || (!self.ok
                && (self.result.is_some() || self.error.as_deref().is_none_or(str::is_empty)))
            || self
                .error
                .as_ref()
                .is_some_and(|error| error.len() > 4 * 1024)
        {
            return Err("response result and error fields are inconsistent");
        }
        Ok(())
    }
}

impl WorkloadRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != PROTOCOL_VERSION || !valid_request_id(&self.request_id) {
            return Err("invalid protocol version or request ID");
        }
        let WorkloadAuthorization::WorkOrder { work_order } = &self.authorization;
        work_order
            .claims
            .validate()
            .map_err(|_| "invalid work-order claims")?;
        if work_order.claims.schema_version != WORK_ORDER_VERSION
            || work_order.claims.request_id != self.request_id
            || work_order.signature.len() != 64
            || !lowercase_hex(&work_order.signature)
        {
            return Err("work order does not match the request");
        }
        let operation = self
            .operation
            .work_order_operation()
            .ok_or("operator operation is not brokerable")?;
        if work_order.claims.operation != operation {
            return Err("operation does not match the work order");
        }
        if work_order.claims.sandbox_id.as_ref().map(|id| id.as_str()) != self.operation.sandbox() {
            return Err("sandbox identity does not match the work order");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "parameters",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Operation {
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fenced_source_epoch: Option<u64>,
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
    #[must_use]
    pub fn work_order_operation(&self) -> Option<WorkOrderOperation> {
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

    #[must_use]
    pub fn sandbox(&self) -> Option<&str> {
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

    pub fn digest(&self) -> Result<String, String> {
        serde_json::to_vec(self)
            .map(|bytes| format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
            .map_err(|error| format!("encode operation digest: {error}"))
    }

    #[must_use]
    pub fn timeout_ms(&self) -> Option<u64> {
        match self {
            Self::Run { timeout_ms, .. }
            | Self::Create { timeout_ms, .. }
            | Self::Restore { timeout_ms, .. } => Some(*timeout_ms),
            _ => None,
        }
    }

    #[must_use]
    pub fn topology(&self) -> Option<&TopologyLock> {
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

#[must_use]
pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{
        AssignmentEpoch, GuestProfile, ResourceCeilings, SandboxId, SubjectId, TenantId,
        WorkOrderClaims, WorkspaceId,
    };

    fn request() -> WorkloadRequest {
        WorkloadRequest {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-a".to_owned(),
            authorization: WorkloadAuthorization::WorkOrder {
                work_order: Box::new(SignedWorkOrder {
                    claims: WorkOrderClaims {
                        schema_version: WORK_ORDER_VERSION,
                        tenant_id: TenantId::parse("tenant-a").expect("tenant"),
                        workspace_id: WorkspaceId::parse("workspace-a").expect("workspace"),
                        subject_id: SubjectId::parse("gateway-a").expect("subject"),
                        request_id: "request-a".to_owned(),
                        operation: WorkOrderOperation::Inspect,
                        sandbox_id: Some(SandboxId::parse("sandbox-a").expect("sandbox")),
                        assignment_epoch: AssignmentEpoch::new(1).expect("epoch"),
                        issued_unix_millis: 1,
                        expires_unix_millis: 2,
                        nonce: "nonce-a".to_owned(),
                        operation_digest: format!("sha256:{}", "a".repeat(64)),
                        resource_ceilings: ResourceCeilings {
                            allowed_guest_profiles: vec![GuestProfile::strict().identity],
                            maximum_services: 1,
                            maximum_timeout_ms: 1_000,
                            memory_bytes_per_service: 1024,
                            cpu_per_service_millis: 100,
                            pids_per_service: 16,
                            tmpfs_bytes: 1024,
                            writable_root_bytes_per_service: 1024,
                            maximum_volumes: 1,
                            maximum_volume_bytes: 1024,
                            maximum_output_bytes: 1024,
                        },
                    },
                    signature: "a".repeat(64),
                }),
            },
            operation: Operation::Inspect {
                sandbox: "sandbox-a".to_owned(),
            },
        }
    }

    #[test]
    fn only_matching_workload_operations_validate() {
        request().validate().expect("inspect");
        let mut operator = request();
        operator.operation = Operation::Shutdown;
        assert!(operator.validate().is_err());
        let mut mismatch = request();
        mismatch.operation = Operation::Inspect {
            sandbox: "sandbox-b".to_owned(),
        };
        assert!(mismatch.validate().is_err());
    }

    #[test]
    fn unknown_and_operator_authorization_shapes_are_rejected() {
        let mut encoded = serde_json::to_value(request()).expect("request");
        encoded["operator"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<WorkloadRequest>(encoded).is_err());
        let operator = serde_json::json!({
            "schema_version": 2,
            "request_id": "request-a",
            "authorization": {"kind": "operator"},
            "operation": {"kind": "shutdown"}
        });
        assert!(serde_json::from_value::<WorkloadRequest>(operator).is_err());
    }

    #[test]
    fn digest_uses_the_typed_canonical_field_order() {
        let topology: TopologyLock =
            serde_json::from_str(include_str!("../../../deploy/k3s/fixed-runtime.lock.json"))
                .expect("checked-in topology lock");
        let operation = Operation::Restore {
            topology,
            sandbox: "sandbox-a".to_owned(),
            snapshot: "snapshot-a".to_owned(),
            timeout_ms: 1,
            fenced_source_epoch: None,
        };
        let encoded = serde_json::to_string(&operation).expect("operation");
        assert!(encoded.starts_with(r#"{"kind":"restore","parameters":{"topology":"#));
        assert!(
            encoded.ends_with(r#","sandbox":"sandbox-a","snapshot":"snapshot-a","timeout_ms":1}}"#)
        );
    }
}
