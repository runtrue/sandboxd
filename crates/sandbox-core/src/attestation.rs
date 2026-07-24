use crate::CoreError;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const IMAGE_ATTESTATION_VERSION: u32 = 1;
const SIGNING_DOMAIN: &[u8] = b"runtrue-sandboxd/image-attestation/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedDescriptor {
    pub role: String,
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePreparationAttestation {
    pub schema_version: u32,
    pub exact_reference: String,
    pub image_id: String,
    pub platform: String,
    pub descriptors: Vec<AttestedDescriptor>,
    pub expanded_root_digest: String,
    pub expanded_root_entries: u64,
    pub expanded_root_bytes: u64,
    pub preparation_policy: String,
    pub toolchain_digest: String,
    pub worker_artifact_digest: String,
    pub prepared_unix_ms: u64,
}

impl ImagePreparationAttestation {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != IMAGE_ATTESTATION_VERSION
            || self.exact_reference.len() > 512
            || !valid_exact_reference(&self.exact_reference)
            || !valid_digest(&self.image_id)
            || !valid_platform(&self.platform)
            || self.descriptors.is_empty()
            || self.descriptors.len() > 1_024
            || !valid_digest(&self.expanded_root_digest)
            || self.expanded_root_entries == 0
            || self.expanded_root_bytes == 0
            || !bounded_name(&self.preparation_policy, 128)
            || !valid_digest(&self.toolchain_digest)
            || !valid_digest(&self.worker_artifact_digest)
            || self.prepared_unix_ms == 0
        {
            return Err(CoreError::InvalidSpecification(
                "image preparation attestation is invalid".to_owned(),
            ));
        }
        let mut roles = BTreeSet::new();
        let mut previous: Option<&AttestedDescriptor> = None;
        for descriptor in &self.descriptors {
            if !bounded_name(&descriptor.role, 64)
                || descriptor.media_type.is_empty()
                || descriptor.media_type.len() > 256
                || !descriptor.media_type.is_ascii()
                || !valid_digest(&descriptor.digest)
                || descriptor.size == 0
                || !roles.insert(descriptor.role.as_str())
                || previous.is_some_and(|prior| prior >= descriptor)
            {
                return Err(CoreError::InvalidSpecification(
                    "attested descriptor graph is invalid or noncanonical".to_owned(),
                ));
            }
            previous = Some(descriptor);
        }
        if !roles.contains("index")
            || !roles.contains("manifest")
            || !roles.contains("config")
            || !roles.iter().any(|role| role.starts_with("layer-"))
        {
            return Err(CoreError::InvalidSpecification(
                "attested descriptor graph is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedImageAttestation {
    pub key_id: String,
    pub attestation: ImagePreparationAttestation,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationTrustPolicy {
    pub trusted_public_keys: BTreeMap<String, String>,
    pub allowed_preparation_policies: BTreeSet<String>,
    pub allowed_toolchain_digests: BTreeSet<String>,
    pub revoked_worker_artifact_digests: BTreeSet<String>,
    pub revoked_expanded_root_digests: BTreeSet<String>,
    pub maximum_attestation_age_ms: u64,
}

impl AttestationTrustPolicy {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.trusted_public_keys.is_empty()
            || self.trusted_public_keys.len() > 64
            || self.allowed_preparation_policies.is_empty()
            || self.allowed_preparation_policies.len() > 64
            || self.allowed_toolchain_digests.is_empty()
            || self.allowed_toolchain_digests.len() > 256
            || self.revoked_worker_artifact_digests.len() > 65_536
            || self.revoked_expanded_root_digests.len() > 65_536
            || self.maximum_attestation_age_ms == 0
            || self.maximum_attestation_age_ms > 366 * 24 * 60 * 60 * 1_000
            || self.trusted_public_keys.iter().any(|(key_id, key)| {
                validate_key_id(key_id).is_err() || decode_public_key(key).is_err()
            })
            || self
                .allowed_preparation_policies
                .iter()
                .any(|policy| !bounded_name(policy, 128))
            || self
                .allowed_toolchain_digests
                .iter()
                .any(|digest| !valid_digest(digest))
            || self
                .revoked_worker_artifact_digests
                .iter()
                .chain(self.revoked_expanded_root_digests.iter())
                .any(|digest| !valid_digest(digest))
        {
            return Err(CoreError::InvalidSpecification(
                "image attestation trust policy is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn sign_image_attestation(
    key_id: &str,
    private_key: &[u8; 32],
    attestation: ImagePreparationAttestation,
) -> Result<SignedImageAttestation, CoreError> {
    attestation.validate()?;
    validate_key_id(key_id)?;
    let payload = signing_payload(key_id, &attestation)?;
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(&payload);
    Ok(SignedImageAttestation {
        key_id: key_id.to_owned(),
        attestation,
        signature: STANDARD_NO_PAD.encode(signature.to_bytes()),
    })
}

pub fn verify_image_attestation(
    public_key: &[u8; 32],
    signed: &SignedImageAttestation,
) -> Result<(), CoreError> {
    signed.attestation.validate()?;
    validate_key_id(&signed.key_id)?;
    let signature_bytes = STANDARD_NO_PAD.decode(&signed.signature).map_err(|_| {
        CoreError::InvalidSpecification("image attestation signature is invalid".to_owned())
    })?;
    let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        CoreError::InvalidSpecification("image attestation signature is invalid".to_owned())
    })?;
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| {
        CoreError::InvalidSpecification("image attestation public key is invalid".to_owned())
    })?;
    let payload = signing_payload(&signed.key_id, &signed.attestation)?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| {
            CoreError::InvalidSpecification("image attestation signature is invalid".to_owned())
        })
}

pub fn verify_trusted_image_attestation(
    policy: &AttestationTrustPolicy,
    signed: &SignedImageAttestation,
    now_unix_ms: u64,
) -> Result<(), CoreError> {
    policy.validate()?;
    let encoded_key = policy
        .trusted_public_keys
        .get(&signed.key_id)
        .ok_or_else(|| {
            CoreError::InvalidSpecification("image attestation key is not trusted".to_owned())
        })?;
    let public_key = decode_public_key(encoded_key)?;
    verify_image_attestation(&public_key, signed)?;
    let attestation = &signed.attestation;
    if attestation.prepared_unix_ms > now_unix_ms
        || now_unix_ms.saturating_sub(attestation.prepared_unix_ms)
            > policy.maximum_attestation_age_ms
        || !policy
            .allowed_preparation_policies
            .contains(&attestation.preparation_policy)
        || !policy
            .allowed_toolchain_digests
            .contains(&attestation.toolchain_digest)
        || policy
            .revoked_worker_artifact_digests
            .contains(&attestation.worker_artifact_digest)
        || policy
            .revoked_expanded_root_digests
            .contains(&attestation.expanded_root_digest)
    {
        return Err(CoreError::InvalidSpecification(
            "image attestation is expired, revoked, or outside operator policy".to_owned(),
        ));
    }
    Ok(())
}

fn signing_payload(
    key_id: &str,
    attestation: &ImagePreparationAttestation,
) -> Result<Vec<u8>, CoreError> {
    let encoded = serde_json::to_vec(attestation).map_err(|error| {
        CoreError::InvalidSpecification(format!("encode image attestation: {error}"))
    })?;
    let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + key_id.len() + encoded.len() + 1);
    payload.extend_from_slice(SIGNING_DOMAIN);
    payload.extend_from_slice(key_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn validate_key_id(value: &str) -> Result<(), CoreError> {
    if bounded_name(value, 64) {
        Ok(())
    } else {
        Err(CoreError::InvalidSpecification(
            "image attestation key ID is invalid".to_owned(),
        ))
    }
}

fn decode_public_key(value: &str) -> Result<[u8; 32], CoreError> {
    STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| {
            CoreError::InvalidSpecification("image attestation public key is invalid".to_owned())
        })?
        .try_into()
        .map_err(|_| {
            CoreError::InvalidSpecification("image attestation public key is invalid".to_owned())
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_exact_reference(value: &str) -> bool {
    value.rsplit_once('@').is_some_and(|(name, digest)| {
        !name.is_empty() && !name.contains('@') && valid_digest(digest)
    })
}

fn valid_platform(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("linux"), Some("amd64" | "arm64"), None, None)
            | (Some("linux"), Some("arm"), Some("v7"), None)
    )
}

fn bounded_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn attestation() -> ImagePreparationAttestation {
        ImagePreparationAttestation {
            schema_version: IMAGE_ATTESTATION_VERSION,
            exact_reference: format!("registry.example/app@{}", digest('a')),
            image_id: digest('b'),
            platform: "linux/amd64".to_owned(),
            descriptors: vec![
                AttestedDescriptor {
                    role: "config".to_owned(),
                    media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                    digest: digest('c'),
                    size: 100,
                },
                AttestedDescriptor {
                    role: "index".to_owned(),
                    media_type: "application/vnd.oci.image.index.v1+json".to_owned(),
                    digest: digest('d'),
                    size: 200,
                },
                AttestedDescriptor {
                    role: "layer-0000".to_owned(),
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                    digest: digest('e'),
                    size: 300,
                },
                AttestedDescriptor {
                    role: "manifest".to_owned(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
                    digest: digest('f'),
                    size: 400,
                },
            ],
            expanded_root_digest: digest('1'),
            expanded_root_entries: 500,
            expanded_root_bytes: 1_000,
            preparation_policy: "strict-v1".to_owned(),
            toolchain_digest: digest('2'),
            worker_artifact_digest: digest('3'),
            prepared_unix_ms: 1,
        }
    }

    #[test]
    fn signature_binds_every_preparation_identity() {
        let private_key = [7_u8; 32];
        let public_key = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        let signed = sign_image_attestation("preparer-2026", &private_key, attestation())
            .expect("signed attestation");
        verify_image_attestation(&public_key, &signed).expect("verified");

        let mut tampered = signed.clone();
        tampered.attestation.expanded_root_digest = digest('4');
        assert!(verify_image_attestation(&public_key, &tampered).is_err());
        let mut tampered = signed.clone();
        tampered.attestation.descriptors[0].digest = digest('5');
        assert!(verify_image_attestation(&public_key, &tampered).is_err());
        let mut tampered = signed.clone();
        tampered.attestation.preparation_policy = "strict-v2".to_owned();
        assert!(verify_image_attestation(&public_key, &tampered).is_err());
        let mut tampered = signed.clone();
        tampered.attestation.worker_artifact_digest = digest('6');
        assert!(verify_image_attestation(&public_key, &tampered).is_err());
        let mut tampered = signed;
        tampered.key_id = "preparer-2027".to_owned();
        assert!(verify_image_attestation(&public_key, &tampered).is_err());
    }

    #[test]
    fn descriptor_graph_must_be_complete_unique_and_canonical() {
        attestation().validate().expect("attestation");
        let mut duplicate = attestation();
        duplicate.descriptors[2].role = "index".to_owned();
        assert!(duplicate.validate().is_err());
        let mut reordered = attestation();
        reordered.descriptors.swap(0, 1);
        assert!(reordered.validate().is_err());
        let mut mutable = attestation();
        mutable.exact_reference = "registry.example/app:latest".to_owned();
        assert!(mutable.validate().is_err());
    }

    #[test]
    fn trust_policy_enforces_age_cohort_and_revocation() {
        let private_key = [7_u8; 32];
        let public_key = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        let signed = sign_image_attestation("preparer-2026", &private_key, attestation())
            .expect("signed attestation");
        let mut policy = AttestationTrustPolicy {
            trusted_public_keys: BTreeMap::from([(
                "preparer-2026".to_owned(),
                STANDARD_NO_PAD.encode(public_key),
            )]),
            allowed_preparation_policies: BTreeSet::from(["strict-v1".to_owned()]),
            allowed_toolchain_digests: BTreeSet::from([digest('2')]),
            revoked_worker_artifact_digests: BTreeSet::new(),
            revoked_expanded_root_digests: BTreeSet::new(),
            maximum_attestation_age_ms: 100,
        };
        verify_trusted_image_attestation(&policy, &signed, 101).expect("trusted");
        assert!(verify_trusted_image_attestation(&policy, &signed, 102).is_err());
        policy.maximum_attestation_age_ms = 1_000;
        policy.revoked_worker_artifact_digests.insert(digest('3'));
        assert!(verify_trusted_image_attestation(&policy, &signed, 101).is_err());
    }
}
