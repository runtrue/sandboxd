use crate::config::read_owner_config;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use runtrue_sandbox_core::{SubjectId, TenantId, WorkspaceId};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use subtle::ConstantTimeEq as _;

const AUTH_POLICY_VERSION: u32 = 1;
const DUMMY_DIGEST: [u8; 32] = [0x5a; 32];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthPolicy {
    schema_version: u32,
    credentials: BTreeMap<String, CredentialPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialPolicy {
    token_sha256: String,
    tenant_id: TenantId,
    subject_id: SubjectId,
    workspaces: BTreeSet<WorkspaceId>,
    maximum_deadline_ms: u64,
    topologies: BTreeSet<String>,
    resource_shapes: BTreeSet<String>,
    compatibility_cohorts: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Principal {
    pub(crate) tenant_id: TenantId,
    pub(crate) subject_id: SubjectId,
    policy: CredentialPolicy,
}

impl AuthPolicy {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let policy: Self = serde_json::from_slice(&read_owner_config(path)?)
            .map_err(|error| format!("decode auth policy: {error}"))?;
        policy.validate()?;
        Ok(policy)
    }

    #[cfg(test)]
    pub(crate) fn for_test(secret: &str) -> Self {
        Self {
            schema_version: AUTH_POLICY_VERSION,
            credentials: BTreeMap::from([(
                "key-a".to_owned(),
                CredentialPolicy {
                    token_sha256: hex::encode(Sha256::digest(secret.as_bytes())),
                    tenant_id: TenantId::parse("tenant-gateway").expect("tenant"),
                    subject_id: SubjectId::parse("subject-gateway").expect("subject"),
                    workspaces: BTreeSet::from([
                        WorkspaceId::parse("workspace-a").expect("workspace")
                    ]),
                    maximum_deadline_ms: 60_000,
                    topologies: BTreeSet::from(["topology-v1".to_owned()]),
                    resource_shapes: BTreeSet::from(["standard-v1".to_owned()]),
                    compatibility_cohorts: BTreeSet::from(["runsc-v1".to_owned()]),
                },
            )]),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != AUTH_POLICY_VERSION
            || self.credentials.is_empty()
            || self.credentials.len() > 10_000
        {
            return Err("auth policy version or credential count is invalid".to_owned());
        }
        for (key_id, credential) in &self.credentials {
            if !bounded_token(key_id, 64)
                || decode_digest(&credential.token_sha256).is_none()
                || credential.workspaces.is_empty()
                || credential.workspaces.len() > 1_000
                || credential.maximum_deadline_ms == 0
                || credential.maximum_deadline_ms > 24 * 60 * 60 * 1_000
                || !valid_allowlist(&credential.topologies)
                || !valid_allowlist(&credential.resource_shapes)
                || !valid_allowlist(&credential.compatibility_cohorts)
            {
                return Err("auth policy contains an invalid credential".to_owned());
            }
        }
        Ok(())
    }

    pub(crate) fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, ()> {
        let value = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(())?;
        let (key_id, secret) = value.split_once('.').ok_or(())?;
        if !bounded_token(key_id, 64)
            || !bounded_token(secret, 128)
            || secret.len() < 32
            || value.len() > 196
        {
            return Err(());
        }
        let observed: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        let credential = self.credentials.get(key_id);
        let expected = credential
            .and_then(|policy| decode_digest(&policy.token_sha256))
            .unwrap_or(DUMMY_DIGEST);
        if !bool::from(observed.ct_eq(&expected)) {
            return Err(());
        }
        let credential = credential.ok_or(())?.clone();
        Ok(Principal {
            tenant_id: credential.tenant_id.clone(),
            subject_id: credential.subject_id.clone(),
            policy: credential,
        })
    }
}

impl Principal {
    pub(crate) fn authorize(
        &self,
        workspace_id: &WorkspaceId,
        deadline_from_now_ms: u64,
        topology: &str,
        resource_shape: &str,
        compatibility_cohort: &str,
    ) -> Result<(), ()> {
        if !self.policy.workspaces.contains(workspace_id)
            || deadline_from_now_ms == 0
            || deadline_from_now_ms > self.policy.maximum_deadline_ms
            || !self.policy.topologies.contains(topology)
            || !self.policy.resource_shapes.contains(resource_shape)
            || !self
                .policy
                .compatibility_cohorts
                .contains(compatibility_cohort)
        {
            return Err(());
        }
        Ok(())
    }
}

fn valid_allowlist(values: &BTreeSet<String>) -> bool {
    !values.is_empty()
        && values.len() <= 1_000
        && values.iter().all(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
                })
        })
}

fn bounded_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn policy(secret: &str) -> AuthPolicy {
        AuthPolicy::for_test(secret)
    }

    #[test]
    fn bearer_identity_is_policy_derived_and_exact() {
        let secret = "a-secure-random-token-with-32-bytes";
        let policy = policy(secret);
        policy.validate().expect("policy");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer key-a.{secret}")).expect("header"),
        );
        let principal = policy.authenticate(&headers).expect("principal");
        assert_eq!(principal.tenant_id.as_str(), "tenant-gateway");
        assert_eq!(principal.subject_id.as_str(), "subject-gateway");
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer key-a.wrong-wrong-wrong-wrong-wrong-wrong"),
        );
        assert!(policy.authenticate(&headers).is_err());
    }
}
