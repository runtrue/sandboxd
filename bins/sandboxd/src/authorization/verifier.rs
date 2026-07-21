use super::{replay::ReplayCache, TenantScope, VerifiedTenant};
use crate::protocol::{Operation, Request};
use hmac::{Hmac, Mac as _};
use runtrue_sandbox_core::{SignedWorkOrder, WorkOrderClaims};
use runtrue_sandbox_oci::SandboxError;
use sha2::Sha256;
use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const CLOCK_SKEW_MILLIS: u64 = 30_000;
const KEY_BYTES: usize = 32;

pub(crate) struct WorkOrderVerifier {
    key: [u8; KEY_BYTES],
    replay: ReplayCache,
}

impl WorkOrderVerifier {
    pub(crate) fn from_key_file(path: &Path, control_root: &Path) -> Result<Self, SandboxError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| {
            SandboxError::Runtime(format!("read work-order key metadata: {source}"))
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o007 != 0
        {
            return Err(SandboxError::Runtime(
                "work-order key must be a root-owned regular file without group write or world access"
                    .to_owned(),
            ));
        }
        let encoded = fs::read_to_string(path)
            .map_err(|source| SandboxError::Runtime(format!("read work-order key: {source}")))?;
        let encoded = encoded
            .strip_suffix("\r\n")
            .or_else(|| encoded.strip_suffix('\n'))
            .unwrap_or(&encoded);
        if encoded.trim() != encoded {
            return Err(SandboxError::Runtime(
                "work-order key contains surrounding whitespace".to_owned(),
            ));
        }
        let decoded = hex::decode(encoded)
            .map_err(|_| SandboxError::Runtime("work-order key is not hexadecimal".to_owned()))?;
        let key: [u8; KEY_BYTES] = decoded.try_into().map_err(|_| {
            SandboxError::Runtime("work-order key must contain exactly 32 bytes".to_owned())
        })?;
        Ok(Self {
            key,
            replay: ReplayCache::open(control_root)?,
        })
    }

    #[cfg(test)]
    pub(super) fn for_test(key: [u8; KEY_BYTES]) -> Self {
        Self {
            key,
            replay: ReplayCache::default(),
        }
    }

    pub(crate) fn verify(
        &self,
        request: &Request,
        work_order: &SignedWorkOrder,
    ) -> Result<VerifiedTenant, SandboxError> {
        let now = unix_millis()?;
        self.verify_at(request, work_order, now)
    }

    fn verify_at(
        &self,
        request: &Request,
        work_order: &SignedWorkOrder,
        now_unix_millis: u64,
    ) -> Result<VerifiedTenant, SandboxError> {
        work_order
            .claims
            .validate()
            .map_err(|error| SandboxError::Runtime(error.to_string()))?;
        verify_signature(&self.key, work_order)?;
        let claims = &work_order.claims;
        if claims.issued_unix_millis > now_unix_millis.saturating_add(CLOCK_SKEW_MILLIS)
            || claims.expires_unix_millis <= now_unix_millis
        {
            return Err(SandboxError::Runtime(
                "work order is expired or not yet valid".to_owned(),
            ));
        }
        if claims.request_id != request.request_id
            || Some(claims.operation) != request.operation.work_order_operation()
            || claims.sandbox_id.as_ref().map(|id| id.as_str()) != request.operation.sandbox()
            || claims.operation_digest
                != request.operation.digest().map_err(SandboxError::Runtime)?
        {
            return Err(SandboxError::Runtime(
                "work order does not authorize this request".to_owned(),
            ));
        }
        enforce_resource_ceilings(&request.operation, claims)?;
        let scope = TenantScope {
            tenant_id: claims.tenant_id.clone(),
            workspace_id: claims.workspace_id.clone(),
        };
        self.replay.consume(
            &scope,
            &claims.nonce,
            claims.expires_unix_millis,
            now_unix_millis,
        )?;
        Ok(VerifiedTenant {
            scope,
            subject_id: claims.subject_id.clone(),
            assignment_epoch: claims.assignment_epoch,
        })
    }
}

fn enforce_resource_ceilings(
    operation: &Operation,
    claims: &WorkOrderClaims,
) -> Result<(), SandboxError> {
    let ceilings = &claims.resource_ceilings;
    if operation
        .timeout_ms()
        .is_some_and(|timeout| timeout > ceilings.maximum_timeout_ms)
    {
        return Err(SandboxError::Runtime(
            "request exceeds the authorized timeout".to_owned(),
        ));
    }
    if let Some(topology) = operation.topology() {
        let output_bytes = u64::try_from(topology.policy.maximum_output_bytes).map_err(|_| {
            SandboxError::Runtime("topology output limit cannot be represented".to_owned())
        })?;
        let volume_bytes = topology.volumes.values().try_fold(0_u64, |total, volume| {
            total
                .checked_add(volume.quota_bytes)
                .ok_or_else(|| SandboxError::Runtime("topology volume quota overflow".to_owned()))
        })?;
        if topology.services.len() > usize::from(ceilings.maximum_services)
            || topology.volumes.len() > usize::from(ceilings.maximum_volumes)
            || volume_bytes > ceilings.maximum_volume_bytes
            || topology.policy.memory_bytes_per_service > ceilings.memory_bytes_per_service
            || topology.policy.cpu_per_service_millis > ceilings.cpu_per_service_millis
            || topology.policy.pids_per_service > ceilings.pids_per_service
            || topology.policy.tmpfs_bytes > ceilings.tmpfs_bytes
            || topology.policy.writable_root_bytes_per_service
                > ceilings.writable_root_bytes_per_service
            || output_bytes > ceilings.maximum_output_bytes
        {
            return Err(SandboxError::Runtime(
                "topology exceeds authorized resource ceilings".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_signature(
    key: &[u8; KEY_BYTES],
    work_order: &SignedWorkOrder,
) -> Result<(), SandboxError> {
    if work_order.signature.len() != 64
        || !work_order
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SandboxError::Runtime(
            "work-order signature is invalid".to_owned(),
        ));
    }
    let signature = hex::decode(&work_order.signature)
        .map_err(|_| SandboxError::Runtime("work-order signature is invalid".to_owned()))?;
    let payload = serde_json::to_vec(&work_order.claims)
        .map_err(|error| SandboxError::Runtime(format!("encode work-order claims: {error}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| SandboxError::Runtime("initialize work-order verifier".to_owned()))?;
    mac.update(&payload);
    mac.verify_slice(&signature)
        .map_err(|_| SandboxError::Runtime("work-order signature is invalid".to_owned()))
}

fn unix_millis() -> Result<u64, SandboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SandboxError::Runtime("system clock predates the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| SandboxError::Runtime("system time overflow".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{RequestAuthorization, PROTOCOL_VERSION};
    use runtrue_sandbox_core::{
        AssignmentEpoch, ResourceCeilings, SandboxId, SubjectId, TenantId, WorkspaceId,
        WORK_ORDER_VERSION,
    };

    fn request() -> Request {
        Request {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            authorization: Some(RequestAuthorization::WorkOrder {
                work_order: Box::new(signed_order(&Operation::Inspect {
                    sandbox: "sandbox-a".to_owned(),
                })),
            }),
            operation: Operation::Inspect {
                sandbox: "sandbox-a".to_owned(),
            },
        }
    }

    fn signed_order(operation: &Operation) -> SignedWorkOrder {
        let claims = WorkOrderClaims {
            schema_version: WORK_ORDER_VERSION,
            tenant_id: TenantId::parse("tenant-a").expect("tenant"),
            workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            subject_id: SubjectId::parse("broker-a").expect("subject"),
            request_id: "request-1".to_owned(),
            operation: operation
                .work_order_operation()
                .expect("workload operation"),
            sandbox_id: operation
                .sandbox()
                .map(|sandbox| SandboxId::parse(sandbox).expect("sandbox")),
            assignment_epoch: AssignmentEpoch::new(7).expect("epoch"),
            issued_unix_millis: 1_000,
            expires_unix_millis: 2_000,
            nonce: "nonce-1".to_owned(),
            operation_digest: operation.digest().expect("digest"),
            resource_ceilings: ResourceCeilings {
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
        };
        let payload = serde_json::to_vec(&claims).expect("claims");
        let mut mac = Hmac::<Sha256>::new_from_slice(&[7_u8; KEY_BYTES]).expect("HMAC");
        mac.update(&payload);
        SignedWorkOrder {
            claims,
            signature: hex::encode(mac.finalize().into_bytes()),
        }
    }

    #[test]
    fn verifies_bound_request_and_rejects_replay() {
        let verifier = WorkOrderVerifier::for_test([7_u8; KEY_BYTES]);
        let request = request();
        let work_order = match request.authorization.as_ref().expect("authorization") {
            RequestAuthorization::WorkOrder { work_order } => work_order,
            RequestAuthorization::Operator { .. } => panic!("unexpected operator request"),
        };
        let verified = verifier
            .verify_at(&request, work_order, 1_500)
            .expect("verified request");
        assert_eq!(verified.scope.tenant_id.as_str(), "tenant-a");
        assert!(verifier.verify_at(&request, work_order, 1_500).is_err());
    }

    #[test]
    fn signing_contract_has_a_stable_cross_language_vector() {
        let operation = Operation::Inspect {
            sandbox: "sandbox-a".to_owned(),
        };
        assert_eq!(
            operation.digest().expect("operation digest"),
            "sha256:e27468322e56a5d5d7eba7c8af325c35b72168f83ebf7b345ce079a48d389a27"
        );
        assert_eq!(
            signed_order(&operation).signature,
            "88c7166ec9f359c662e5de1121854e7ef298296dbe60bfe4a73e3326c348f036"
        );
    }

    #[test]
    fn rejects_tampering_and_expiration() {
        let verifier = WorkOrderVerifier::for_test([7_u8; KEY_BYTES]);
        let mut changed_request = request();
        let work_order = match changed_request.authorization.take().expect("authorization") {
            RequestAuthorization::WorkOrder { work_order } => work_order,
            RequestAuthorization::Operator { .. } => panic!("unexpected operator request"),
        };
        changed_request.operation = Operation::Inspect {
            sandbox: "sandbox-b".to_owned(),
        };
        assert!(verifier
            .verify_at(&changed_request, &work_order, 1_500)
            .is_err());
        let original = request();
        let work_order = match original.authorization.as_ref().expect("authorization") {
            RequestAuthorization::WorkOrder { work_order } => work_order,
            RequestAuthorization::Operator { .. } => panic!("unexpected operator request"),
        };
        assert!(verifier.verify_at(&original, work_order, 2_000).is_err());
    }

    #[test]
    fn rejects_topology_above_signed_resource_ceiling() {
        use runtrue_sandbox_oci::model::{
            LockedNetwork, LockedService, LockedVolume, RootFilesystemMode, SandboxPolicy,
            TopologyLock,
        };
        use std::collections::BTreeMap;

        let topology = TopologyLock {
            schema_version: 4,
            topology_digest: format!("sha256:{}", "a".repeat(64)),
            name: "example".to_owned(),
            services: BTreeMap::from([(
                "app".to_owned(),
                LockedService {
                    image: runtrue_sandbox_oci::LockedImage {
                        source: "example".to_owned(),
                        exact_reference: format!("example@sha256:{}", "b".repeat(64)),
                        image_id: format!("sha256:{}", "c".repeat(64)),
                        index: None,
                        manifest: runtrue_sandbox_oci::LockedDescriptor {
                            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
                            digest: format!("sha256:{}", "b".repeat(64)),
                            size: 1_024,
                        },
                        config: runtrue_sandbox_oci::LockedDescriptor {
                            media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                            digest: format!("sha256:{}", "c".repeat(64)),
                            size: 512,
                        },
                        layers: vec![runtrue_sandbox_oci::LockedDescriptor {
                            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                            digest: format!("sha256:{}", "d".repeat(64)),
                            size: 4_096,
                        }],
                        operating_system: "linux".to_owned(),
                        architecture: "amd64".to_owned(),
                        variant: None,
                    },
                    command: Vec::new(),
                    entrypoint: vec!["/bin/true".to_owned()],
                    environment: BTreeMap::new(),
                    depends_on: BTreeMap::new(),
                    healthcheck: None,
                    networks: vec!["default".to_owned()],
                    user: "65534:65534".to_owned(),
                    working_dir: "/work".to_owned(),
                    root_filesystem: RootFilesystemMode::ReadOnly,
                    volumes: Vec::new(),
                },
            )]),
            networks: BTreeMap::from([(
                "default".to_owned(),
                LockedNetwork {
                    internal: true,
                    driver: "bridge".to_owned(),
                },
            )]),
            volumes: BTreeMap::from([(
                "oversized".to_owned(),
                LockedVolume {
                    persistence_class: runtrue_sandbox_core::VolumePersistenceClass::Persistent,
                    snapshot_policy: runtrue_sandbox_core::VolumeSnapshotPolicy::Required,
                    quota_bytes: 4097,
                    content_digest: None,
                },
            )]),
            startup_order: vec!["app".to_owned()],
            policy: SandboxPolicy {
                runtime: "runsc".to_owned(),
                memory_bytes_per_service: 1024,
                cpu_per_service_millis: 100,
                pids_per_service: 16,
                tmpfs_bytes: 1024,
                writable_root_bytes_per_service: 1024,
                maximum_output_bytes: 1024,
            },
        };
        let operation = Operation::Create {
            topology,
            sandbox: "sandbox-a".to_owned(),
            timeout_ms: 1_000,
        };
        let work_order = signed_order(&operation);
        let request = Request {
            schema_version: PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            authorization: Some(RequestAuthorization::WorkOrder {
                work_order: Box::new(work_order.clone()),
            }),
            operation,
        };
        assert!(WorkOrderVerifier::for_test([7_u8; KEY_BYTES])
            .verify_at(&request, &work_order, 1_500)
            .is_err());
    }
}
