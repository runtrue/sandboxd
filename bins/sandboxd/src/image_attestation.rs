use runtrue_sandbox_core::{
    verify_bound_image_attestation, AttestationTrustPolicy, AttestedDescriptor,
    ImageAttestationExpectation, SignedImageAttestation,
};
use runtrue_sandbox_oci::{io_error, provider::FixedRootfsConfig, SandboxError, TopologyLock};
use std::{
    fs::OpenOptions,
    io::Read as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const MAXIMUM_POLICY_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) fn verify_configured(
    signed_path: Option<&Path>,
    policy_path: Option<&Path>,
    worker_artifact_digest: Option<&str>,
    fixed: Option<&FixedRootfsConfig>,
) -> Result<(), SandboxError> {
    let (Some(signed_path), Some(policy_path), Some(worker_artifact_digest), Some(fixed)) =
        (signed_path, policy_path, worker_artifact_digest, fixed)
    else {
        return Ok(());
    };
    let measurement = fixed.measurement.as_ref().ok_or_else(|| {
        SandboxError::Runtime(
            "attested fixed rootfs requires an expanded-root measurement".to_owned(),
        )
    })?;
    let signed: SignedImageAttestation = read_json(signed_path)?;
    let policy: AttestationTrustPolicy = read_json(policy_path)?;
    let topology: TopologyLock = read_json(&fixed.topology_lock)?;
    let mut images = topology.services.values().map(|service| &service.image);
    let image = images
        .next()
        .ok_or_else(|| SandboxError::Runtime("attested topology has no locked image".to_owned()))?;
    if images.any(|candidate| candidate != image) {
        return Err(SandboxError::Runtime(
            "one attested fixed rootfs cannot represent multiple locked images".to_owned(),
        ));
    }
    let mut descriptors = Vec::with_capacity(image.layers.len() + 3);
    if let Some(index) = &image.index {
        descriptors.push(descriptor("index", index));
    }
    descriptors.push(descriptor("manifest", &image.manifest));
    descriptors.push(descriptor("config", &image.config));
    descriptors.extend(
        image
            .layers
            .iter()
            .enumerate()
            .map(|(index, layer)| descriptor(&format!("layer-{index:04}"), layer)),
    );
    descriptors.sort();
    let platform = image.variant.as_ref().map_or_else(
        || format!("{}/{}", image.operating_system, image.architecture),
        |variant| {
            format!(
                "{}/{}/{}",
                image.operating_system, image.architecture, variant
            )
        },
    );
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SandboxError::Runtime("system time precedes Unix epoch".to_owned()))?
            .as_millis(),
    )
    .map_err(|_| SandboxError::Runtime("system time exceeds attestation range".to_owned()))?;
    verify_bound_image_attestation(
        &policy,
        &signed,
        ImageAttestationExpectation {
            exact_reference: &image.exact_reference,
            image_id: &image.image_id,
            platform: &platform,
            descriptors: &descriptors,
            expanded_root_digest: &measurement.digest,
            expanded_root_entries: u64::try_from(measurement.entries).map_err(|_| {
                SandboxError::Runtime(
                    "expanded-root entry count exceeds attestation range".to_owned(),
                )
            })?,
            expanded_root_bytes: measurement.bytes,
            worker_artifact_digest,
        },
        now,
    )
    .map_err(|error| SandboxError::Runtime(error.to_string()))
}

fn descriptor(
    role: &str,
    descriptor: &runtrue_sandbox_oci::LockedDescriptor,
) -> AttestedDescriptor {
    AttestedDescriptor {
        role: role.to_owned(),
        media_type: descriptor.media_type.clone(),
        digest: descriptor.digest.clone(),
        size: descriptor.size,
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SandboxError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAXIMUM_POLICY_BYTES
    {
        return Err(SandboxError::Runtime(format!(
            "attestation input `{}` is not a bounded regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        SandboxError::Runtime(format!(
            "decode attestation input `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    use runtrue_sandbox_core::{
        sign_image_attestation, ImagePreparationAttestation, IMAGE_ATTESTATION_VERSION,
    };
    use runtrue_sandbox_oci::provider::FixedRootfsMeasurement;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
    };

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    #[test]
    fn worker_becomes_eligible_only_for_the_exact_signed_artifact() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let topology_path = directory.path().join("topology.json");
        fs::write(
            &topology_path,
            include_bytes!("../../../deploy/k3s/fixed-runtime.lock.json"),
        )
        .expect("topology");
        let topology: TopologyLock =
            serde_json::from_slice(&fs::read(&topology_path).expect("topology bytes"))
                .expect("topology lock");
        let image = &topology.services.values().next().expect("service").image;
        let mut descriptors = vec![
            descriptor("index", image.index.as_ref().expect("index")),
            descriptor("manifest", &image.manifest),
            descriptor("config", &image.config),
        ];
        descriptors.extend(
            image
                .layers
                .iter()
                .enumerate()
                .map(|(index, layer)| descriptor(&format!("layer-{index:04}"), layer)),
        );
        descriptors.sort();
        let prepared_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_millis(),
        )
        .expect("clock range");
        let private_key = [7_u8; 32];
        let signed = sign_image_attestation(
            "preparer-2026",
            &private_key,
            ImagePreparationAttestation {
                schema_version: IMAGE_ATTESTATION_VERSION,
                exact_reference: image.exact_reference.clone(),
                image_id: image.image_id.clone(),
                platform: "linux/amd64".to_owned(),
                descriptors,
                expanded_root_digest:
                    "sha256:c73e49867e5b68681c2222e1e7b60aca9218d5a83ded507226f89438cea40db1"
                        .to_owned(),
                expanded_root_entries: 5_621,
                expanded_root_bytes: 118_293_769,
                preparation_policy: "strict-v1".to_owned(),
                toolchain_digest: digest('a'),
                worker_artifact_digest: digest('b'),
                prepared_unix_ms,
            },
        )
        .expect("signed attestation");
        let policy = AttestationTrustPolicy {
            trusted_public_keys: BTreeMap::from([(
                "preparer-2026".to_owned(),
                STANDARD_NO_PAD.encode(
                    SigningKey::from_bytes(&private_key)
                        .verifying_key()
                        .to_bytes(),
                ),
            )]),
            allowed_preparation_policies: BTreeSet::from(["strict-v1".to_owned()]),
            allowed_toolchain_digests: BTreeSet::from([digest('a')]),
            revoked_worker_artifact_digests: BTreeSet::new(),
            revoked_expanded_root_digests: BTreeSet::new(),
            maximum_attestation_age_ms: 60_000,
        };
        let signed_path = directory.path().join("attestation.json");
        let policy_path = directory.path().join("policy.json");
        fs::write(
            &signed_path,
            serde_json::to_vec(&signed).expect("attestation JSON"),
        )
        .expect("attestation file");
        fs::write(
            &policy_path,
            serde_json::to_vec(&policy).expect("policy JSON"),
        )
        .expect("policy file");
        let fixed = FixedRootfsConfig {
            rootfs: directory.path().to_owned(),
            topology_lock: topology_path,
            measurement: Some(FixedRootfsMeasurement {
                digest: "sha256:c73e49867e5b68681c2222e1e7b60aca9218d5a83ded507226f89438cea40db1"
                    .to_owned(),
                entries: 5_621,
                bytes: 118_293_769,
            }),
        };

        verify_configured(
            Some(&signed_path),
            Some(&policy_path),
            Some(&digest('b')),
            Some(&fixed),
        )
        .expect("exact worker binding");
        assert!(verify_configured(
            Some(&signed_path),
            Some(&policy_path),
            Some(&digest('c')),
            Some(&fixed),
        )
        .is_err());
    }
}
