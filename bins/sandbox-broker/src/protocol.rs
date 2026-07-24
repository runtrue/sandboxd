use runtrue_sandbox_core::{SignedWorkOrder, WorkOrderOperation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerRequest {
    pub(crate) schema_version: u32,
    pub(crate) request_id: String,
    pub(crate) authorization: BrokerAuthorization,
    pub(crate) operation: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BrokerAuthorization {
    WorkOrder { work_order: Box<SignedWorkOrder> },
}

impl BrokerRequest {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != PROTOCOL_VERSION || !valid_token(&self.request_id, 64) {
            return Err("invalid protocol version or request ID");
        }
        let work_order = match &self.authorization {
            BrokerAuthorization::WorkOrder { work_order } => work_order,
        };
        work_order
            .claims
            .validate()
            .map_err(|_| "invalid work-order claims")?;
        if work_order.claims.request_id != self.request_id
            || work_order.signature.len() != 64
            || !work_order
                .signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("work order does not match the request");
        }
        let object = self
            .operation
            .as_object()
            .ok_or("operation must be an object")?;
        if object
            .keys()
            .any(|key| key != "kind" && key != "parameters")
        {
            return Err("operation contains an unknown field");
        }
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("operation kind is missing")?;
        let expected = operation_kind(kind).ok_or("operator operation is not brokerable")?;
        if work_order.claims.operation != expected {
            return Err("operation does not match the work order");
        }
        let sandbox = sandbox_parameter(expected, object.get("parameters"))?;
        if work_order.claims.sandbox_id.as_ref().map(|id| id.as_str()) != sandbox {
            return Err("sandbox identity does not match the work order");
        }
        Ok(())
    }
}

fn operation_kind(kind: &str) -> Option<WorkOrderOperation> {
    Some(match kind {
        "ping" => WorkOrderOperation::Ping,
        "stats" => WorkOrderOperation::Stats,
        "admit" => WorkOrderOperation::Admit,
        "run" => WorkOrderOperation::Run,
        "create" => WorkOrderOperation::Create,
        "restore" => WorkOrderOperation::Restore,
        "inspect" => WorkOrderOperation::Inspect,
        "pause" => WorkOrderOperation::Pause,
        "resume" => WorkOrderOperation::Resume,
        "stop" => WorkOrderOperation::Stop,
        "logs" => WorkOrderOperation::Logs,
        "snapshot" => WorkOrderOperation::Snapshot,
        _ => return None,
    })
}

fn sandbox_parameter(
    operation: WorkOrderOperation,
    parameters: Option<&Value>,
) -> Result<Option<&str>, &'static str> {
    if !operation.requires_sandbox() {
        return Ok(None);
    }
    let parameters = parameters
        .and_then(Value::as_object)
        .ok_or("sandbox operation parameters are missing")?;
    let field = if operation == WorkOrderOperation::Run {
        "project"
    } else {
        "sandbox"
    };
    parameters
        .get(field)
        .and_then(Value::as_str)
        .map(Some)
        .ok_or("sandbox operation identity is missing")
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{
        AssignmentEpoch, GuestProfile, ResourceCeilings, SandboxId, SubjectId, TenantId,
        WorkspaceId, WORK_ORDER_VERSION,
    };

    fn request(kind: &str) -> BrokerRequest {
        let operation = serde_json::json!({
            "kind": kind,
            "parameters": {"sandbox": "sandbox-a"}
        });
        BrokerRequest {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-a".to_owned(),
            authorization: BrokerAuthorization::WorkOrder {
                work_order: Box::new(SignedWorkOrder {
                    claims: runtrue_sandbox_core::WorkOrderClaims {
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
            operation,
        }
    }

    #[test]
    fn accepts_only_matching_workload_operations() {
        request("inspect").validate().expect("inspect");
        assert!(request("shutdown").validate().is_err());
        assert!(request("publish_artifact").validate().is_err());
        let mut mismatch = request("stop");
        assert!(mismatch.validate().is_err());
        mismatch.operation = serde_json::json!({
            "kind": "inspect",
            "parameters": {"sandbox": "sandbox-b"}
        });
        assert!(mismatch.validate().is_err());
    }

    #[test]
    fn outer_and_authorization_objects_reject_unknown_or_operator_fields() {
        let extra = serde_json::json!({
            "schema_version": 2,
            "request_id": "request-a",
            "authorization": {
                "kind": "work_order",
                "work_order": match request("inspect").authorization {
                    BrokerAuthorization::WorkOrder { work_order } => work_order
                }
            },
            "operation": {"kind": "inspect", "parameters": {"sandbox": "sandbox-a"}},
            "operator": true
        });
        assert!(serde_json::from_value::<BrokerRequest>(extra).is_err());
        let operator = serde_json::json!({
            "schema_version": 2,
            "request_id": "request-a",
            "authorization": {
                "kind": "operator",
                "tenant_id": "tenant-a",
                "workspace_id": "workspace-a",
                "subject_id": "operator-a"
            },
            "operation": {"kind": "shutdown"}
        });
        assert!(serde_json::from_value::<BrokerRequest>(operator).is_err());
    }
}
