use crate::{
    specification::validate_digest, AssignmentEpoch, CoreError, GuestProfileIdentity, SandboxId,
    SubjectId, TenantId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

pub const WORK_ORDER_VERSION: u32 = 4;
pub const MAXIMUM_WORK_ORDER_LIFETIME_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderOperation {
    Ping,
    Stats,
    Admit,
    Run,
    Create,
    Restore,
    Inspect,
    Pause,
    Resume,
    Stop,
    Logs,
    Snapshot,
}

impl WorkOrderOperation {
    #[must_use]
    pub const fn requires_sandbox(self) -> bool {
        !matches!(self, Self::Ping | Self::Stats | Self::Admit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCeilings {
    pub allowed_guest_profiles: Vec<GuestProfileIdentity>,
    pub maximum_services: u16,
    pub maximum_timeout_ms: u64,
    pub memory_bytes_per_service: u64,
    pub cpu_per_service_millis: u32,
    pub pids_per_service: u32,
    pub tmpfs_bytes: u64,
    pub writable_root_bytes_per_service: u64,
    pub maximum_volumes: u16,
    pub maximum_volume_bytes: u64,
    pub maximum_output_bytes: u64,
}

impl ResourceCeilings {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.allowed_guest_profiles.is_empty()
            || self.allowed_guest_profiles.len() > 16
            || self
                .allowed_guest_profiles
                .iter()
                .enumerate()
                .any(|(index, profile)| {
                    self.allowed_guest_profiles[..index].contains(profile)
                        || GuestProfileIdentity::parse(&profile.canonical()).as_ref() != Ok(profile)
                })
            || self.maximum_services == 0
            || self.maximum_services > 64
            || self.maximum_timeout_ms == 0
            || self.maximum_timeout_ms > 300_000
            || self.memory_bytes_per_service == 0
            || self.cpu_per_service_millis == 0
            || self.pids_per_service == 0
            || self.tmpfs_bytes == 0
            || self.writable_root_bytes_per_service == 0
            || self.maximum_volumes > 128
            || self.maximum_volume_bytes == 0
            || self.maximum_output_bytes == 0
        {
            return Err(CoreError::InvalidWorkOrder(
                "resource ceilings are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderClaims {
    pub schema_version: u32,
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub subject_id: SubjectId,
    pub request_id: String,
    pub operation: WorkOrderOperation,
    pub sandbox_id: Option<SandboxId>,
    pub assignment_epoch: AssignmentEpoch,
    pub issued_unix_millis: u64,
    pub expires_unix_millis: u64,
    pub nonce: String,
    pub operation_digest: String,
    pub resource_ceilings: ResourceCeilings,
}

impl WorkOrderClaims {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != WORK_ORDER_VERSION {
            return Err(CoreError::InvalidWorkOrder(
                "unsupported schema version".to_owned(),
            ));
        }
        if !bounded_token(&self.request_id, 64) || !bounded_token(&self.nonce, 96) {
            return Err(CoreError::InvalidWorkOrder(
                "request ID or nonce is invalid".to_owned(),
            ));
        }
        if self.operation.requires_sandbox() != self.sandbox_id.is_some() {
            return Err(CoreError::InvalidWorkOrder(
                "sandbox identity does not match the operation".to_owned(),
            ));
        }
        if self.issued_unix_millis == 0
            || self.expires_unix_millis <= self.issued_unix_millis
            || self
                .expires_unix_millis
                .saturating_sub(self.issued_unix_millis)
                > MAXIMUM_WORK_ORDER_LIFETIME_MILLIS
        {
            return Err(CoreError::InvalidWorkOrder(
                "work-order lifetime is invalid".to_owned(),
            ));
        }
        validate_digest("operation", &self.operation_digest)
            .map_err(|error| CoreError::InvalidWorkOrder(error.to_string()))?;
        self.resource_ceilings.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWorkOrder {
    pub claims: WorkOrderClaims,
    pub signature: String,
}

fn bounded_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> WorkOrderClaims {
        WorkOrderClaims {
            schema_version: WORK_ORDER_VERSION,
            tenant_id: TenantId::parse("tenant-a").expect("tenant"),
            workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            subject_id: SubjectId::parse("broker-a").expect("subject"),
            request_id: "request-1".to_owned(),
            operation: WorkOrderOperation::Create,
            sandbox_id: Some(SandboxId::parse("sandbox-a").expect("sandbox")),
            assignment_epoch: AssignmentEpoch::new(1).expect("epoch"),
            issued_unix_millis: 1,
            expires_unix_millis: 2,
            nonce: "nonce-1".to_owned(),
            operation_digest: format!("sha256:{}", "a".repeat(64)),
            resource_ceilings: ResourceCeilings {
                allowed_guest_profiles: vec![crate::GuestProfile::strict().identity],
                maximum_services: 4,
                maximum_timeout_ms: 10_000,
                memory_bytes_per_service: 1024,
                cpu_per_service_millis: 100,
                pids_per_service: 16,
                tmpfs_bytes: 1024,
                writable_root_bytes_per_service: 1024,
                maximum_volumes: 4,
                maximum_volume_bytes: 4096,
                maximum_output_bytes: 1024,
            },
        }
    }

    #[test]
    fn validates_bounded_claims() {
        claims().validate().expect("valid claims");
        let mut invalid = claims();
        invalid.sandbox_id = None;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_long_lived_grants() {
        let mut invalid = claims();
        invalid.expires_unix_millis =
            invalid.issued_unix_millis + MAXIMUM_WORK_ORDER_LIFETIME_MILLIS + 1;
        assert!(invalid.validate().is_err());
    }
}
