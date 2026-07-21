use crate::{
    backend::{BlobBackend, PutStatus},
    crypto::{describe, maximum_envelope_bytes, open, seal, EnvelopeKey},
    error::io_error,
    ArtifactError, ArtifactScope, SnapshotTransferClaim, SnapshotTransferGrant,
};
use runtrue_sandbox_core::{
    ArtifactDescriptor, AssignmentEpoch, RestoreTarget, SnapshotId, SnapshotManifest, SnapshotMode,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    time::Instant,
};

const TRANSFER_VERSION: u32 = 1;
const TRANSFER_GRANT_MEDIA_TYPE: &str = "application/vnd.runtrue.snapshot.transfer-grant.v1+json";
const TRANSFER_CLAIM_MEDIA_TYPE: &str = "application/vnd.runtrue.snapshot.transfer-claim.v1+json";
const MAXIMUM_TRANSFER_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferPointer {
    schema_version: u32,
    snapshot_id: SnapshotId,
    grant: ArtifactDescriptor,
}

pub(crate) fn publish_grant(
    backend: &dyn BlobBackend,
    envelope_key: &EnvelopeKey,
    scope: &ArtifactScope,
    manifest: &SnapshotManifest,
    temporary: &Path,
    deadline: Instant,
) -> Result<SnapshotTransferGrant, ArtifactError> {
    if backend.exists(
        &transfer_pointer_key(scope, &manifest.snapshot_id),
        deadline,
    )? {
        return read_grant(backend, envelope_key, scope, manifest, temporary, deadline);
    }
    if manifest.mode != SnapshotMode::StopAndMove {
        return Err(ArtifactError::Invalid(
            "only a stop-and-move snapshot can receive a transfer grant".to_owned(),
        ));
    }
    let grant = SnapshotTransferGrant {
        schema_version: TRANSFER_VERSION,
        tenant_id: manifest.tenant_id.clone(),
        workspace_id: manifest.workspace_id.clone(),
        sandbox_id: manifest.sandbox_id.clone(),
        snapshot_id: manifest.snapshot_id.clone(),
        source_worker: manifest.source_worker.clone(),
        source_assignment_epoch: AssignmentEpoch::new(manifest.source_assignment_epoch)
            .map_err(|error| ArtifactError::Integrity(error.to_string()))?,
        created_unix_millis: manifest.created_unix_millis,
    };
    let plaintext = temporary.join("transfer-grant.json");
    write_json(&plaintext, &grant)?;
    let mut descriptor = describe(&plaintext, MAXIMUM_TRANSFER_BYTES)?;
    descriptor.media_type = TRANSFER_GRANT_MEDIA_TYPE.to_owned();
    let envelope = temporary.join("transfer-grant.envelope");
    seal(
        &plaintext,
        &envelope,
        scope,
        &descriptor,
        envelope_key,
        deadline,
    )?;
    backend.put_if_absent(
        &transfer_grant_key(scope, &manifest.snapshot_id),
        &envelope,
        deadline,
    )?;
    let pointer = TransferPointer {
        schema_version: TRANSFER_VERSION,
        snapshot_id: manifest.snapshot_id.clone(),
        grant: descriptor,
    };
    let pointer_path = temporary.join("transfer-pointer.json");
    write_json(&pointer_path, &pointer)?;
    if fs::metadata(&pointer_path)
        .map_err(|error| io_error(&pointer_path, error))?
        .len()
        > MAXIMUM_TRANSFER_BYTES
    {
        return Err(ArtifactError::Invalid(
            "snapshot transfer pointer exceeds its byte limit".to_owned(),
        ));
    }
    if backend.put_if_absent(
        &transfer_pointer_key(scope, &manifest.snapshot_id),
        &pointer_path,
        deadline,
    )? == PutStatus::Reused
    {
        let existing = read_grant(backend, envelope_key, scope, manifest, temporary, deadline)?;
        if existing != grant {
            return Err(ArtifactError::Integrity(
                "snapshot transfer grant conflicts with its manifest".to_owned(),
            ));
        }
    }
    Ok(grant)
}

pub(crate) fn claim(
    backend: &dyn BlobBackend,
    envelope_key: &EnvelopeKey,
    scope: &ArtifactScope,
    manifest: &SnapshotManifest,
    target: &RestoreTarget,
    temporary: &Path,
    deadline: Instant,
) -> Result<SnapshotTransferClaim, ArtifactError> {
    let grant = read_grant(backend, envelope_key, scope, manifest, temporary, deadline)?;
    if grant.tenant_id != target.tenant_id
        || grant.workspace_id != target.workspace_id
        || grant.sandbox_id != target.sandbox_id
        || grant.source_worker == target.worker_id
        || target.assignment_epoch <= grant.source_assignment_epoch
    {
        return Err(ArtifactError::AccessDenied(
            "snapshot transfer target does not match its fenced grant".to_owned(),
        ));
    }
    let claim = SnapshotTransferClaim {
        schema_version: TRANSFER_VERSION,
        tenant_id: grant.tenant_id,
        workspace_id: grant.workspace_id,
        sandbox_id: grant.sandbox_id,
        snapshot_id: grant.snapshot_id,
        source_worker: grant.source_worker,
        source_assignment_epoch: grant.source_assignment_epoch,
        destination_worker: target.worker_id.clone(),
        destination_assignment_epoch: target.assignment_epoch,
    };
    let plaintext = temporary.join("transfer-claim.json");
    write_json(&plaintext, &claim)?;
    let mut descriptor = describe(&plaintext, MAXIMUM_TRANSFER_BYTES)?;
    descriptor.media_type = TRANSFER_CLAIM_MEDIA_TYPE.to_owned();
    let envelope = temporary.join("transfer-claim.envelope");
    seal(
        &plaintext,
        &envelope,
        scope,
        &descriptor,
        envelope_key,
        deadline,
    )?;
    if backend.put_if_absent(
        &transfer_claim_key(scope, &manifest.snapshot_id),
        &envelope,
        deadline,
    )? == PutStatus::Reused
    {
        verify_existing_claim(
            backend,
            envelope_key,
            scope,
            &manifest.snapshot_id,
            &claim,
            &descriptor,
            temporary,
            deadline,
        )?;
    }
    Ok(claim)
}

fn read_grant(
    backend: &dyn BlobBackend,
    envelope_key: &EnvelopeKey,
    scope: &ArtifactScope,
    manifest: &SnapshotManifest,
    temporary: &Path,
    deadline: Instant,
) -> Result<SnapshotTransferGrant, ArtifactError> {
    let pointer_path = temporary.join("existing-transfer-pointer.json");
    remove_if_present(&pointer_path)?;
    let pointer_bytes = backend.get(
        &transfer_pointer_key(scope, &manifest.snapshot_id),
        &pointer_path,
        MAXIMUM_TRANSFER_BYTES,
        deadline,
    )?;
    if pointer_bytes > MAXIMUM_TRANSFER_BYTES {
        return Err(ArtifactError::Integrity(
            "snapshot transfer pointer exceeds its byte limit".to_owned(),
        ));
    }
    let pointer: TransferPointer = read_json(&pointer_path, "snapshot transfer pointer")?;
    if pointer.schema_version != TRANSFER_VERSION
        || pointer.snapshot_id != manifest.snapshot_id
        || pointer.grant.media_type != TRANSFER_GRANT_MEDIA_TYPE
        || pointer.grant.size_bytes > MAXIMUM_TRANSFER_BYTES
    {
        return Err(ArtifactError::Integrity(
            "snapshot transfer pointer is invalid".to_owned(),
        ));
    }
    let envelope = temporary.join("existing-transfer-grant.envelope");
    remove_if_present(&envelope)?;
    backend.get(
        &transfer_grant_key(scope, &manifest.snapshot_id),
        &envelope,
        maximum_envelope_bytes(pointer.grant.size_bytes)?,
        deadline,
    )?;
    let plaintext = temporary.join("existing-transfer-grant.json");
    remove_if_present(&plaintext)?;
    open(
        &envelope,
        &plaintext,
        scope,
        &pointer.grant,
        envelope_key,
        deadline,
    )?;
    let grant: SnapshotTransferGrant = read_json(&plaintext, "snapshot transfer grant")?;
    if grant.schema_version != TRANSFER_VERSION
        || grant.snapshot_id != manifest.snapshot_id
        || grant.tenant_id != *scope.tenant_id()
        || grant.workspace_id != *scope.workspace_id()
        || manifest.mode != SnapshotMode::StopAndMove
        || grant.sandbox_id != manifest.sandbox_id
        || grant.source_worker != manifest.source_worker
        || grant.source_assignment_epoch.get() != manifest.source_assignment_epoch
        || grant.created_unix_millis != manifest.created_unix_millis
    {
        return Err(ArtifactError::Integrity(
            "snapshot transfer grant does not match its manifest".to_owned(),
        ));
    }
    Ok(grant)
}

#[allow(clippy::too_many_arguments)]
fn verify_existing_claim(
    backend: &dyn BlobBackend,
    envelope_key: &EnvelopeKey,
    scope: &ArtifactScope,
    snapshot_id: &SnapshotId,
    claim: &SnapshotTransferClaim,
    descriptor: &ArtifactDescriptor,
    temporary: &Path,
    deadline: Instant,
) -> Result<(), ArtifactError> {
    let existing = temporary.join("existing-transfer-claim.envelope");
    backend.get(
        &transfer_claim_key(scope, snapshot_id),
        &existing,
        maximum_envelope_bytes(descriptor.size_bytes)?,
        deadline,
    )?;
    let decoded = temporary.join("existing-transfer-claim.json");
    if open(
        &existing,
        &decoded,
        scope,
        descriptor,
        envelope_key,
        deadline,
    )
    .is_err()
    {
        return Err(already_claimed());
    }
    let existing_claim: SnapshotTransferClaim = read_json(&decoded, "snapshot transfer claim")?;
    if &existing_claim != claim {
        return Err(already_claimed());
    }
    Ok(())
}

fn already_claimed() -> ArtifactError {
    ArtifactError::AlreadyExists("snapshot transfer was claimed by another destination".to_owned())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ArtifactError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ArtifactError::Storage(format!("encode transfer metadata: {error}")))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(&bytes)
        .map_err(|error| io_error(path, error))?;
    file.sync_all().map_err(|error| io_error(path, error))
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    description: &str,
) -> Result<T, ArtifactError> {
    serde_json::from_slice(&fs::read(path).map_err(|error| io_error(path, error))?)
        .map_err(|error| ArtifactError::Integrity(format!("decode {description}: {error}")))
}

fn remove_if_present(path: &Path) -> Result<(), ArtifactError> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| io_error(path, error))?;
    }
    Ok(())
}

fn transfer_pointer_key(scope: &ArtifactScope, snapshot_id: &SnapshotId) -> String {
    format!(
        "{}/transfers/{}/grant.json",
        scope.storage_prefix(),
        snapshot_id.as_str()
    )
}

fn transfer_grant_key(scope: &ArtifactScope, snapshot_id: &SnapshotId) -> String {
    format!(
        "{}/transfers/{}/grant.envelope",
        scope.storage_prefix(),
        snapshot_id.as_str()
    )
}

fn transfer_claim_key(scope: &ArtifactScope, snapshot_id: &SnapshotId) -> String {
    format!(
        "{}/transfers/{}/claim.envelope",
        scope.storage_prefix(),
        snapshot_id.as_str()
    )
}
