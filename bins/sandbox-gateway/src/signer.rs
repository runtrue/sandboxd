use crate::config::read_owner_config;
use hmac::{Hmac, Mac as _};
use runtrue_sandbox_core::{
    SignedWorkOrder, WorkOrderClaims, MAXIMUM_WORK_ORDER_LIFETIME_MILLIS, WORK_ORDER_VERSION,
};
use runtrue_sandbox_placement::Assignment;
use runtrue_sandbox_protocol::{WorkloadAuthorization, WorkloadRequest, PROTOCOL_VERSION};
use sha2::{Digest as _, Sha256};
use std::{path::Path, time::Duration};
use zeroize::Zeroize as _;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct WorkOrderSigner {
    key: [u8; 32],
    lifetime: Duration,
}

impl WorkOrderSigner {
    pub(crate) fn load(path: &Path, lifetime: Duration) -> Result<Self, String> {
        let encoded = read_owner_config(path)?;
        let encoded = encoded.strip_suffix(b"\n").unwrap_or(&encoded);
        if encoded.len() != 64
            || !encoded
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(
                "work-order key must contain exactly 64 lowercase hex characters".to_owned(),
            );
        }
        let key: [u8; 32] = hex::decode(encoded)
            .map_err(|_| "work-order key is not valid hexadecimal".to_owned())?
            .try_into()
            .map_err(|_| "work-order key has an invalid length".to_owned())?;
        Self::new(key, lifetime)
    }

    fn new(key: [u8; 32], lifetime: Duration) -> Result<Self, String> {
        if lifetime.is_zero()
            || lifetime.as_millis() > u128::from(MAXIMUM_WORK_ORDER_LIFETIME_MILLIS)
        {
            return Err("work-order lifetime is invalid".to_owned());
        }
        Ok(Self { key, lifetime })
    }

    #[cfg(test)]
    pub(crate) fn for_test(key: [u8; 32], lifetime: Duration) -> Self {
        Self::new(key, lifetime).expect("test signer")
    }

    pub(crate) fn sign(
        &self,
        assignment: &Assignment,
        now_unix_ms: u64,
    ) -> Result<WorkloadRequest, String> {
        self.sign_operation(assignment, &assignment.operation, now_unix_ms)
    }

    pub(crate) fn sign_operation(
        &self,
        assignment: &Assignment,
        requested_operation: &runtrue_sandbox_protocol::Operation,
        now_unix_ms: u64,
    ) -> Result<WorkloadRequest, String> {
        if requested_operation.sandbox() != Some(assignment.identity.sandbox_id.as_str()) {
            return Err("requested operation does not match the assignment sandbox".to_owned());
        }
        let operation = requested_operation
            .work_order_operation()
            .ok_or_else(|| "assignment operation is not workload-authorized".to_owned())?;
        let maximum_expiry = now_unix_ms
            .checked_add(
                u64::try_from(self.lifetime.as_millis())
                    .map_err(|_| "work-order lifetime overflows".to_owned())?,
            )
            .ok_or_else(|| "work-order expiration overflows".to_owned())?;
        let expires_unix_millis = assignment.lease_expires_unix_ms.min(maximum_expiry);
        if expires_unix_millis <= now_unix_ms {
            return Err("assignment lease has expired".to_owned());
        }
        let claims = WorkOrderClaims {
            schema_version: WORK_ORDER_VERSION,
            tenant_id: assignment.identity.tenant_id.clone(),
            workspace_id: assignment.identity.workspace_id.clone(),
            subject_id: assignment.subject_id.clone(),
            request_id: assignment.request_id.clone(),
            operation,
            sandbox_id: Some(assignment.identity.sandbox_id.clone()),
            assignment_epoch: assignment.epoch,
            issued_unix_millis: now_unix_ms,
            expires_unix_millis,
            nonce: nonce(assignment, now_unix_ms),
            operation_digest: requested_operation.digest()?,
            resource_ceilings: assignment.resource_ceilings.clone(),
        };
        claims.validate().map_err(|error| error.to_string())?;
        let encoded = serde_json::to_vec(&claims)
            .map_err(|error| format!("encode work-order claims: {error}"))?;
        let mut signer = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| "initialize work-order signer".to_owned())?;
        signer.update(&encoded);
        let request = WorkloadRequest {
            schema_version: PROTOCOL_VERSION,
            request_id: assignment.request_id.clone(),
            authorization: WorkloadAuthorization::WorkOrder {
                work_order: Box::new(SignedWorkOrder {
                    claims,
                    signature: hex::encode(signer.finalize().into_bytes()),
                }),
            },
            operation: requested_operation.clone(),
        };
        request.validate().map_err(str::to_owned)?;
        Ok(request)
    }
}

impl Drop for WorkOrderSigner {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn nonce(assignment: &Assignment, now_unix_ms: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(assignment.request_id.as_bytes());
    digest.update([0]);
    digest.update(assignment.epoch.get().to_be_bytes());
    digest.update(now_unix_ms.to_be_bytes());
    digest.update(assignment.worker_id.as_str().as_bytes());
    hex::encode(digest.finalize())
}
