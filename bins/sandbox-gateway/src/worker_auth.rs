use crate::config::read_owner_config;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use runtrue_sandbox_core::WorkerId;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path};
use subtle::ConstantTimeEq as _;

const POLICY_VERSION: u32 = 1;
const DUMMY_DIGEST: [u8; 32] = [0xa5; 32];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerAuthPolicy {
    schema_version: u32,
    credentials: BTreeMap<String, WorkerCredential>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCredential {
    token_sha256: String,
    worker_id: WorkerId,
    topology: String,
    resource_shape: String,
    compatibility_cohort: String,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerPrincipal(WorkerCredential);

impl WorkerAuthPolicy {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let policy: Self = serde_json::from_slice(&read_owner_config(path)?)
            .map_err(|error| format!("decode worker auth policy: {error}"))?;
        policy.validate()?;
        Ok(policy)
    }

    #[cfg(test)]
    pub(crate) fn for_test(secret: &str, worker_id: &str) -> Self {
        Self {
            schema_version: POLICY_VERSION,
            credentials: BTreeMap::from([(
                "worker-key-a".to_owned(),
                WorkerCredential {
                    token_sha256: hex::encode(Sha256::digest(secret.as_bytes())),
                    worker_id: WorkerId::parse(worker_id).expect("worker"),
                    topology: "topology-v1".to_owned(),
                    resource_shape: "standard-v1".to_owned(),
                    compatibility_cohort: "runsc-v1".to_owned(),
                },
            )]),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != POLICY_VERSION
            || self.credentials.is_empty()
            || self.credentials.len() > 10_000
        {
            return Err("worker auth policy version or credential count is invalid".to_owned());
        }
        for (key_id, credential) in &self.credentials {
            if !bounded_token(key_id, 64)
                || decode_digest(&credential.token_sha256).is_none()
                || !bounded_label(&credential.topology)
                || !bounded_label(&credential.resource_shape)
                || !bounded_label(&credential.compatibility_cohort)
            {
                return Err("worker auth policy contains an invalid credential".to_owned());
            }
        }
        Ok(())
    }

    pub(crate) fn authenticate(&self, headers: &HeaderMap) -> Result<WorkerPrincipal, ()> {
        let value = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Worker "))
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
        Ok(WorkerPrincipal(credential.ok_or(())?.clone()))
    }
}

impl WorkerPrincipal {
    pub(crate) fn authorize(
        &self,
        worker_id: &WorkerId,
        topology: &str,
        resource_shape: &str,
        compatibility_cohort: &str,
    ) -> Result<(), ()> {
        if self.0.worker_id != *worker_id
            || self.0.topology != topology
            || self.0.resource_shape != resource_shape
            || self.0.compatibility_cohort != compatibility_cohort
        {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn authorize_worker(&self, worker_id: &WorkerId) -> Result<(), ()> {
        (self.0.worker_id == *worker_id).then_some(()).ok_or(())
    }
}

fn bounded_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn bounded_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
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

    #[test]
    fn credential_is_bound_to_one_exact_worker_advertisement() {
        let secret = "a-secure-worker-token-with-32-bytes";
        let policy = WorkerAuthPolicy::for_test(secret, "worker-a");
        policy.validate().expect("policy");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Worker worker-key-a.{secret}")).expect("header"),
        );
        let principal = policy.authenticate(&headers).expect("principal");
        let worker = WorkerId::parse("worker-a").expect("worker");
        principal
            .authorize(&worker, "topology-v1", "standard-v1", "runsc-v1")
            .expect("advertisement");
        assert!(principal
            .authorize(
                &WorkerId::parse("worker-b").expect("worker"),
                "topology-v1",
                "standard-v1",
                "runsc-v1"
            )
            .is_err());
        assert!(principal
            .authorize(&worker, "other-topology", "standard-v1", "runsc-v1")
            .is_err());
    }
}
