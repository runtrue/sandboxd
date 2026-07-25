#[cfg(test)]
use crate::publication::file_digest;
use crate::publication::{
    read_retained_bounded, retained_file_digest, validate_cache_limits, PublicationLock,
    MAXIMUM_EVIDENCE_BYTES,
};
use runtrue_sandbox_core::{
    verify_trusted_image_attestation, AttestationTrustPolicy, PreparedRootCatalog,
    SignedImageAttestation, WorkerPoolCatalog,
};
use runtrue_sandbox_oci::{
    io_error,
    provider::{measure_expanded_rootfs, ImageLimits},
    SandboxError,
};
use serde::Serialize;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAXIMUM_CONTROL_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_ATTESTATION_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
struct CacheEntry {
    digest: String,
    directory: PathBuf,
    logical_bytes: u64,
    modified_unix_ms: u64,
    scan_error: Option<String>,
}

#[derive(Debug, Clone)]
struct InternalEntry {
    name: String,
    path: PathBuf,
    artifact_key: Option<String>,
    logical_bytes: u64,
    modified_unix_ms: u64,
}

struct CacheScan {
    entries: Vec<CacheEntry>,
    invalid_entries: Vec<String>,
    internal_entries: Vec<InternalEntry>,
}

#[derive(Debug, Serialize)]
struct PoolImpact {
    name: String,
    kubernetes_stateful_set: String,
    cohort: String,
}

#[derive(Debug, Serialize)]
struct AuditArtifact {
    worker_artifact_digest: String,
    expanded_root_digest: Option<String>,
    cohort: Option<String>,
    status: &'static str,
    reason: Option<String>,
    logical_bytes: u64,
    affected_pools: Vec<PoolImpact>,
}

#[derive(Debug, Serialize)]
struct CachePressure {
    artifacts: usize,
    logical_bytes: u64,
    maximum_artifacts: usize,
    maximum_bytes: u64,
    over_artifact_limit: bool,
    over_byte_limit: bool,
}

#[derive(Debug, Serialize)]
struct AuditReport {
    schema_version: u32,
    healthy: bool,
    pressure: CachePressure,
    artifacts: Vec<AuditArtifact>,
    invalid_entries: Vec<String>,
    internal_entries: Vec<String>,
    affected_pools: Vec<PoolImpact>,
}

#[derive(Debug, Serialize)]
struct GarbageCollectionArtifact {
    worker_artifact_digest: String,
    logical_bytes: u64,
    modified_unix_ms: u64,
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct GarbageCollectionReport {
    schema_version: u32,
    mode: &'static str,
    before: CachePressure,
    after: CachePressure,
    protected_artifacts: usize,
    candidates: Vec<GarbageCollectionArtifact>,
    internal_candidates: Vec<GarbageCollectionArtifact>,
    limit_satisfied: bool,
}

pub(crate) fn audit(
    cache: &Path,
    trust_policy_path: &Path,
    prepared_root_catalog_path: &Path,
    worker_pool_catalog_path: &Path,
    maximum_cache_artifacts: usize,
    maximum_cache_bytes: u64,
    require_healthy: bool,
) -> Result<(), SandboxError> {
    validate_cache_limits(maximum_cache_artifacts, maximum_cache_bytes)?;
    let trust_policy: AttestationTrustPolicy = read_json(trust_policy_path)?;
    trust_policy
        .validate()
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    let prepared_roots: PreparedRootCatalog = read_json(prepared_root_catalog_path)?;
    prepared_roots
        .validate()
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    let worker_pools: WorkerPoolCatalog = read_json(worker_pool_catalog_path)?;
    worker_pools
        .validate()
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    validate_pool_cohorts(&prepared_roots, &worker_pools)?;

    let CacheScan {
        entries,
        invalid_entries,
        internal_entries,
    } = scan_cache(cache)?;
    let internal_bytes = internal_entries
        .iter()
        .map(|entry| entry.logical_bytes)
        .sum::<u64>();
    let pressure = pressure(
        entries.len(),
        entries
            .iter()
            .map(|entry| entry.logical_bytes)
            .sum::<u64>()
            .saturating_add(internal_bytes),
        maximum_cache_artifacts,
        maximum_cache_bytes,
    );
    let now = now_unix_ms()?;
    let mut artifacts = Vec::with_capacity(entries.len());
    let mut all_affected = BTreeMap::new();
    let retained = entries
        .iter()
        .map(|entry| entry.digest.clone())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        let report = audit_entry(&entry, &trust_policy, &prepared_roots, &worker_pools, now);
        for pool in &report.affected_pools {
            all_affected.insert(
                (pool.name.clone(), pool.kubernetes_stateful_set.clone()),
                PoolImpact {
                    name: pool.name.clone(),
                    kubernetes_stateful_set: pool.kubernetes_stateful_set.clone(),
                    cohort: pool.cohort.clone(),
                },
            );
        }
        artifacts.push(report);
    }
    for cohort in &prepared_roots.cohorts {
        for artifact in &cohort.artifacts {
            if retained.contains(artifact.worker_artifact_digest.as_str()) {
                continue;
            }
            let affected_pools = pools_for_cohort(&worker_pools, &cohort.name);
            for pool in &affected_pools {
                all_affected.insert(
                    (pool.name.clone(), pool.kubernetes_stateful_set.clone()),
                    PoolImpact {
                        name: pool.name.clone(),
                        kubernetes_stateful_set: pool.kubernetes_stateful_set.clone(),
                        cohort: pool.cohort.clone(),
                    },
                );
            }
            artifacts.push(AuditArtifact {
                worker_artifact_digest: artifact.worker_artifact_digest.clone(),
                expanded_root_digest: Some(artifact.expanded_root_digest.clone()),
                cohort: Some(cohort.name.clone()),
                status: "missing",
                reason: Some("reviewed artifact is absent from the cache".to_owned()),
                logical_bytes: 0,
                affected_pools,
            });
        }
    }
    artifacts.sort_by(|left, right| {
        left.worker_artifact_digest
            .cmp(&right.worker_artifact_digest)
    });
    let healthy = invalid_entries.is_empty()
        && internal_entries.is_empty()
        && !pressure.over_artifact_limit
        && !pressure.over_byte_limit
        && artifacts
            .iter()
            .all(|artifact| artifact.status == "trusted" || artifact.status == "orphaned");
    let output = serde_json::to_string(&AuditReport {
        schema_version: 1,
        healthy,
        pressure,
        artifacts,
        invalid_entries,
        internal_entries: internal_entries
            .into_iter()
            .map(|entry| entry.name)
            .collect(),
        affected_pools: all_affected.into_values().collect(),
    })
    .map_err(|error| SandboxError::Lock(format!("encode cache audit: {error}")))?;
    println!("{output}");
    if require_healthy && !healthy {
        return Err(SandboxError::Lock(
            "attested cache audit found unhealthy reviewed roots".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn garbage_collect(
    cache: &Path,
    prepared_root_catalog_path: &Path,
    maximum_cache_artifacts: usize,
    maximum_cache_bytes: u64,
    minimum_age_seconds: u64,
    delete: bool,
) -> Result<(), SandboxError> {
    validate_cache_limits(maximum_cache_artifacts, maximum_cache_bytes)?;
    if minimum_age_seconds > 366 * 24 * 60 * 60 {
        return Err(SandboxError::Lock(
            "garbage-collection minimum age exceeds one year".to_owned(),
        ));
    }
    let prepared_roots: PreparedRootCatalog = read_json(prepared_root_catalog_path)?;
    prepared_roots
        .validate()
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    let cache = canonical_cache(cache)?;
    let CacheScan {
        entries,
        invalid_entries,
        internal_entries,
    } = scan_cache(&cache)?;
    let corrupt_entries = entries
        .iter()
        .filter_map(|entry| entry.scan_error.as_ref().map(|_| entry.digest.as_str()))
        .collect::<Vec<_>>();
    if !invalid_entries.is_empty() || !corrupt_entries.is_empty() {
        return Err(SandboxError::Lock(format!(
            "cache contains invalid entries; audit and quarantine them first: {}",
            invalid_entries
                .iter()
                .map(String::as_str)
                .chain(corrupt_entries)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let before_bytes = entries
        .iter()
        .map(|entry| entry.logical_bytes)
        .sum::<u64>()
        .saturating_add(
            internal_entries
                .iter()
                .map(|entry| entry.logical_bytes)
                .sum(),
        );
    let before = pressure(
        entries.len(),
        before_bytes,
        maximum_cache_artifacts,
        maximum_cache_bytes,
    );
    let now = now_unix_ms()?;
    let minimum_age_ms = minimum_age_seconds.saturating_mul(1_000);
    let protected = entries
        .iter()
        .filter(|entry| prepared_roots.artifact(&entry.digest).is_some())
        .count();
    let mut candidates = entries
        .iter()
        .filter(|entry| {
            prepared_roots.artifact(&entry.digest).is_none()
                && now.saturating_sub(entry.modified_unix_ms) >= minimum_age_ms
        })
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by_key(|entry| (entry.modified_unix_ms, Reverse(entry.logical_bytes)));

    let mut planned_count = entries.len();
    let mut planned_bytes = before_bytes;
    let mut report = Vec::new();
    let mut internal_report = Vec::new();
    for entry in internal_entries
        .into_iter()
        .filter(|entry| now.saturating_sub(entry.modified_unix_ms) >= minimum_age_ms)
    {
        let result = if delete {
            delete_internal_entry(&cache, &entry)?
        } else {
            "planned"
        };
        if result != "busy" {
            planned_bytes = planned_bytes.saturating_sub(entry.logical_bytes);
        }
        internal_report.push(GarbageCollectionArtifact {
            worker_artifact_digest: entry
                .artifact_key
                .as_deref()
                .map_or_else(|| "unknown".to_owned(), |key| format!("sha256:{key}")),
            logical_bytes: entry.logical_bytes,
            modified_unix_ms: entry.modified_unix_ms,
            result,
        });
    }
    for entry in candidates {
        if planned_count <= maximum_cache_artifacts && planned_bytes <= maximum_cache_bytes {
            break;
        }
        let result = if delete {
            delete_entry(&cache, &entry)?
        } else {
            "planned"
        };
        if result != "busy" {
            planned_count = planned_count.saturating_sub(1);
            planned_bytes = planned_bytes.saturating_sub(entry.logical_bytes);
        }
        report.push(GarbageCollectionArtifact {
            worker_artifact_digest: entry.digest,
            logical_bytes: entry.logical_bytes,
            modified_unix_ms: entry.modified_unix_ms,
            result,
        });
    }
    let after = pressure(
        planned_count,
        planned_bytes,
        maximum_cache_artifacts,
        maximum_cache_bytes,
    );
    let limit_satisfied = !after.over_artifact_limit && !after.over_byte_limit;
    println!(
        "{}",
        serde_json::to_string(&GarbageCollectionReport {
            schema_version: 1,
            mode: if delete { "delete" } else { "dry_run" },
            before,
            after,
            protected_artifacts: protected,
            candidates: report,
            internal_candidates: internal_report,
            limit_satisfied,
        })
        .map_err(|error| SandboxError::Lock(format!("encode garbage collection: {error}")))?
    );
    Ok(())
}

pub(crate) fn enforce_publication_capacity(
    cache: &Path,
    maximum_cache_artifacts: usize,
    maximum_cache_bytes: u64,
    additional_bytes: u64,
) -> Result<(), SandboxError> {
    validate_cache_limits(maximum_cache_artifacts, maximum_cache_bytes)?;
    let CacheScan {
        entries,
        invalid_entries,
        internal_entries,
    } = scan_cache(cache)?;
    if !invalid_entries.is_empty()
        || !internal_entries.is_empty()
        || entries.iter().any(|entry| entry.scan_error.is_some())
    {
        return Err(SandboxError::Lock(
            "cache contains invalid entries; publication is disabled until audit".to_owned(),
        ));
    }
    let bytes = entries.iter().map(|entry| entry.logical_bytes).sum::<u64>();
    if entries.len() >= maximum_cache_artifacts
        || bytes.saturating_add(additional_bytes) > maximum_cache_bytes
    {
        return Err(SandboxError::Lock(
            "attested cache capacity exhausted; run reviewed garbage collection".to_owned(),
        ));
    }
    Ok(())
}

fn audit_entry(
    entry: &CacheEntry,
    trust_policy: &AttestationTrustPolicy,
    prepared_roots: &PreparedRootCatalog,
    worker_pools: &WorkerPoolCatalog,
    now_unix_ms: u64,
) -> AuditArtifact {
    let referenced = prepared_roots.artifact(&entry.digest);
    let cohort = referenced.map(|(cohort, _)| cohort.name.clone());
    let mut report = AuditArtifact {
        worker_artifact_digest: entry.digest.clone(),
        expanded_root_digest: None,
        cohort: cohort.clone(),
        status: if referenced.is_some() {
            "rejected"
        } else {
            "orphaned"
        },
        reason: None,
        logical_bytes: entry.logical_bytes,
        affected_pools: Vec::new(),
    };
    let result = (|| {
        if let Some(error) = &entry.scan_error {
            return Err(SandboxError::Lock(error.clone()));
        }
        let signed: SignedImageAttestation =
            read_retained_json(&entry.directory.join("attestation.json"))?;
        report.expanded_root_digest = Some(signed.attestation.expanded_root_digest.clone());
        if signed.attestation.worker_artifact_digest != entry.digest {
            return Err(SandboxError::Lock(
                "directory identity does not match signed worker artifact".to_owned(),
            ));
        }
        let revoked = trust_policy
            .revoked_worker_artifact_digests
            .contains(&entry.digest)
            || trust_policy
                .revoked_expanded_root_digests
                .contains(&signed.attestation.expanded_root_digest);
        let mut signature_policy = trust_policy.clone();
        signature_policy.revoked_worker_artifact_digests.clear();
        signature_policy.revoked_expanded_root_digests.clear();
        verify_trusted_image_attestation(&signature_policy, &signed, now_unix_ms)
            .map_err(|error| SandboxError::Lock(error.to_string()))?;
        let measured =
            measure_expanded_rootfs(&entry.directory.join("rootfs"), &ImageLimits::default())?;
        if measured.digest != signed.attestation.expanded_root_digest
            || u64::try_from(measured.entries).ok()
                != Some(signed.attestation.expanded_root_entries)
            || measured.bytes != signed.attestation.expanded_root_bytes
            || retained_file_digest(&entry.directory.join("sbom.json"), MAXIMUM_EVIDENCE_BYTES)?
                != signed.attestation.sbom_digest
            || retained_file_digest(
                &entry.directory.join("provenance.json"),
                MAXIMUM_EVIDENCE_BYTES,
            )? != signed.attestation.provenance_digest
        {
            return Err(SandboxError::Lock(
                "retained root or evidence does not match its attestation".to_owned(),
            ));
        }
        if let Some((_, catalog_artifact)) = referenced {
            if catalog_artifact.expanded_root_digest != measured.digest {
                return Err(SandboxError::Lock(
                    "reviewed cohort maps the worker artifact to a different root".to_owned(),
                ));
            }
        }
        report.status = if revoked {
            "revoked"
        } else if referenced.is_some() {
            "trusted"
        } else {
            "orphaned"
        };
        Ok(())
    })();
    if let Err(error) = result {
        report.status = if referenced.is_some() {
            "rejected"
        } else {
            "corrupt"
        };
        report.reason = Some(error.to_string());
    }
    if referenced.is_some() && report.status != "trusted" {
        report.affected_pools =
            pools_for_cohort(worker_pools, cohort.as_deref().unwrap_or_default());
    }
    report
}

fn pools_for_cohort(catalog: &WorkerPoolCatalog, cohort: &str) -> Vec<PoolImpact> {
    catalog
        .pools
        .iter()
        .filter(|pool| pool.key.attested_root_cohort == cohort)
        .map(|pool| PoolImpact {
            name: pool.name.clone(),
            kubernetes_stateful_set: pool.kubernetes_stateful_set.clone(),
            cohort: cohort.to_owned(),
        })
        .collect()
}

fn validate_pool_cohorts(
    prepared_roots: &PreparedRootCatalog,
    worker_pools: &WorkerPoolCatalog,
) -> Result<(), SandboxError> {
    let missing = worker_pools
        .pools
        .iter()
        .map(|pool| pool.key.attested_root_cohort.as_str())
        .filter(|cohort| prepared_roots.cohort(cohort).is_none())
        .collect::<BTreeSet<_>>();
    if !missing.is_empty() {
        return Err(SandboxError::Lock(format!(
            "worker pools reference missing prepared-root cohorts: {}",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    Ok(())
}

fn scan_cache(cache: &Path) -> Result<CacheScan, SandboxError> {
    let cache = canonical_cache(cache)?;
    let mut entries = Vec::new();
    let mut invalid = Vec::new();
    let mut internal = Vec::new();
    for candidate in fs::read_dir(&cache)
        .map_err(|error| io_error(&cache, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&cache, error))?
    {
        let name = candidate.file_name().to_string_lossy().into_owned();
        if name == "latest-result.json" {
            continue;
        }
        let metadata = fs::symlink_metadata(candidate.path())
            .map_err(|error| io_error(candidate.path(), error))?;
        if (valid_lock_name(&name) || name == ".capacity.lock") && metadata.is_file() {
            continue;
        }
        if let Some(artifact_key) = internal_artifact_key(&name) {
            if !metadata.is_dir() {
                invalid.push(name);
                continue;
            }
            internal.push(InternalEntry {
                name,
                path: candidate.path(),
                artifact_key,
                logical_bytes: directory_logical_bytes(&candidate.path()).unwrap_or_default(),
                modified_unix_ms: system_time_ms(metadata.modified().unwrap_or(UNIX_EPOCH))?,
            });
            continue;
        }
        if !valid_cache_key(&name) || !metadata.is_dir() {
            invalid.push(name);
            continue;
        }
        let directory = candidate.path();
        let (logical_bytes, scan_error) = match artifact_logical_bytes(&directory) {
            Ok(bytes) => (bytes, None),
            Err(error) => (
                directory_logical_bytes(&directory).unwrap_or_default(),
                Some(error.to_string()),
            ),
        };
        let modified_unix_ms = system_time_ms(metadata.modified().unwrap_or(UNIX_EPOCH))?;
        entries.push(CacheEntry {
            digest: format!("sha256:{name}"),
            directory,
            logical_bytes,
            modified_unix_ms,
            scan_error,
        });
    }
    entries.sort_by(|left, right| left.digest.cmp(&right.digest));
    invalid.sort();
    internal.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(CacheScan {
        entries,
        invalid_entries: invalid,
        internal_entries: internal,
    })
}

fn directory_logical_bytes(directory: &Path) -> Result<u64, SandboxError> {
    let mut pending = vec![directory.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current)
            .map_err(|error| io_error(&current, error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io_error(&current, error))?
        {
            entries = entries.saturating_add(1);
            if entries > ImageLimits::default().maximum_entries {
                return Err(SandboxError::Lock(
                    "cache artifact exceeds the bounded entry count".to_owned(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| io_error(entry.path(), error))?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            } else if !metadata.file_type().is_symlink() {
                return Err(SandboxError::Lock(
                    "cache artifact contains an unsupported entry".to_owned(),
                ));
            }
        }
    }
    Ok(bytes)
}

fn artifact_logical_bytes(directory: &Path) -> Result<u64, SandboxError> {
    let signed: SignedImageAttestation = read_retained_json(&directory.join("attestation.json"))?;
    let sbom = fs::symlink_metadata(directory.join("sbom.json"))
        .map_err(|error| io_error(directory.join("sbom.json"), error))?;
    let provenance = fs::symlink_metadata(directory.join("provenance.json"))
        .map_err(|error| io_error(directory.join("provenance.json"), error))?;
    if !sbom.is_file()
        || !provenance.is_file()
        || sbom.len() == 0
        || provenance.len() == 0
        || sbom.len() > MAXIMUM_EVIDENCE_BYTES
        || provenance.len() > MAXIMUM_EVIDENCE_BYTES
    {
        return Err(SandboxError::Lock(format!(
            "artifact `{}` has invalid retained evidence",
            directory.display()
        )));
    }
    Ok(signed
        .attestation
        .expanded_root_bytes
        .saturating_add(sbom.len())
        .saturating_add(provenance.len()))
}

fn read_retained_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SandboxError> {
    let bytes = read_retained_bounded(path, MAXIMUM_ATTESTATION_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode `{}`: {error}", path.display())))
}

fn delete_entry(cache: &Path, entry: &CacheEntry) -> Result<&'static str, SandboxError> {
    let key = entry
        .digest
        .strip_prefix("sha256:")
        .expect("validated cache digest");
    let lock_path = cache.join(format!(".{key}.lock"));
    let Some(lock) = PublicationLock::acquire(&lock_path)? else {
        return Ok("busy");
    };
    match fs::symlink_metadata(&entry.directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(SandboxError::Lock(
                "garbage-collection target changed type".to_owned(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("already_absent");
        }
        Err(error) => return Err(io_error(&entry.directory, error)),
    }
    let tombstone = cache.join(format!(
        ".gc-{key}-{}-{}",
        std::process::id(),
        now_unix_ms()?
    ));
    fs::rename(&entry.directory, &tombstone).map_err(|error| io_error(&entry.directory, error))?;
    File::open(cache)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(cache, error))?;
    fs::remove_dir_all(&tombstone).map_err(|error| io_error(&tombstone, error))?;
    File::open(cache)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(cache, error))?;
    drop(lock);
    Ok("deleted")
}

fn delete_internal_entry(
    cache: &Path,
    entry: &InternalEntry,
) -> Result<&'static str, SandboxError> {
    let lock = if let Some(key) = &entry.artifact_key {
        let lock_path = cache.join(format!(".{key}.lock"));
        let Some(lock) = PublicationLock::acquire(&lock_path)? else {
            return Ok("busy");
        };
        Some(lock)
    } else {
        None
    };
    match fs::symlink_metadata(&entry.path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(SandboxError::Lock(
                "internal cache entry changed type".to_owned(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("already_absent");
        }
        Err(error) => return Err(io_error(&entry.path, error)),
    }
    fs::remove_dir_all(&entry.path).map_err(|error| io_error(&entry.path, error))?;
    File::open(cache)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(cache, error))?;
    drop(lock);
    Ok("deleted")
}

fn pressure(
    artifacts: usize,
    logical_bytes: u64,
    maximum_artifacts: usize,
    maximum_bytes: u64,
) -> CachePressure {
    CachePressure {
        artifacts,
        logical_bytes,
        maximum_artifacts,
        maximum_bytes,
        over_artifact_limit: artifacts > maximum_artifacts,
        over_byte_limit: logical_bytes > maximum_bytes,
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SandboxError> {
    let mut file = File::open(path).map_err(|error| io_error(path, error))?;
    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    let maximum = if path
        .file_name()
        .is_some_and(|name| name == "attestation.json")
    {
        MAXIMUM_ATTESTATION_BYTES
    } else {
        MAXIMUM_CONTROL_BYTES
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(SandboxError::Lock(format!(
            "JSON control file `{}` is not bounded",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode `{}`: {error}", path.display())))
}

fn canonical_cache(cache: &Path) -> Result<PathBuf, SandboxError> {
    let cache = fs::canonicalize(cache).map_err(|error| io_error(cache, error))?;
    let metadata = fs::metadata(&cache).map_err(|error| io_error(&cache, error))?;
    if !metadata.is_dir() {
        return Err(SandboxError::Lock(
            "attested cache is not a directory".to_owned(),
        ));
    }
    Ok(cache)
}

fn valid_cache_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_lock_name(value: &str) -> bool {
    value
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".lock"))
        .is_some_and(valid_cache_key)
}

fn internal_artifact_key(value: &str) -> Option<Option<String>> {
    let suffix = value
        .strip_prefix(".publication-")
        .or_else(|| value.strip_prefix(".gc-"))?;
    if suffix.is_empty()
        || suffix.len() > 160
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    let key = suffix.get(..64).filter(|key| {
        valid_cache_key(key) && suffix.as_bytes().get(64).is_some_and(|byte| *byte == b'-')
    });
    Some(key.map(str::to_owned))
}

fn now_unix_ms() -> Result<u64, SandboxError> {
    system_time_ms(SystemTime::now())
}

fn system_time_ms(value: SystemTime) -> Result<u64, SandboxError> {
    u64::try_from(
        value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SandboxError::Lock("system time precedes Unix epoch".to_owned()))?
            .as_millis(),
    )
    .map_err(|_| SandboxError::Lock("system time exceeds u64".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use runtrue_sandbox_core::{
        sign_image_attestation, AttestedDescriptor, ImagePreparationAttestation,
        PreparedRootArtifact, PreparedRootCohort, IMAGE_ATTESTATION_VERSION,
        PREPARED_ROOT_CATALOG_VERSION,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    struct Fixture {
        directory: tempfile::TempDir,
        cache: PathBuf,
        trust: AttestationTrustPolicy,
        catalog: PreparedRootCatalog,
        pools: WorkerPoolCatalog,
        artifact_digest: String,
        root_digest: String,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = directory.path().join("cache");
        fs::create_dir(&cache).expect("cache");
        let artifact_digest = digest('a');
        let root_digest = write_artifact(&cache, &artifact_digest, &[7_u8; 32]);
        let public_key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
            .verifying_key()
            .to_bytes();
        let trust = AttestationTrustPolicy {
            trusted_public_keys: BTreeMap::from([(
                "cache-test".to_owned(),
                STANDARD_NO_PAD.encode(public_key),
            )]),
            allowed_preparation_policies: BTreeSet::from(["strict-v1".to_owned()]),
            allowed_toolchain_digests: BTreeSet::from([digest('f')]),
            allowed_vulnerability_policies: BTreeSet::from(["release-v1".to_owned()]),
            revoked_worker_artifact_digests: BTreeSet::new(),
            revoked_expanded_root_digests: BTreeSet::new(),
            maximum_attestation_age_ms: 60_000,
        };
        let catalog = PreparedRootCatalog {
            schema_version: PREPARED_ROOT_CATALOG_VERSION,
            cohorts: vec![PreparedRootCohort {
                name: "fixed-rootset-20260724".to_owned(),
                artifacts: vec![PreparedRootArtifact {
                    worker_artifact_digest: artifact_digest.clone(),
                    expanded_root_digest: root_digest.clone(),
                }],
            }],
        };
        let pools: WorkerPoolCatalog =
            serde_json::from_str(include_str!("../../../deploy/k3s/worker-pools.json"))
                .expect("worker pools");
        Fixture {
            directory,
            cache,
            trust,
            catalog,
            pools,
            artifact_digest,
            root_digest,
        }
    }

    fn write_artifact(cache: &Path, artifact_digest: &str, private_key: &[u8; 32]) -> String {
        let key = artifact_digest.strip_prefix("sha256:").expect("digest");
        let artifact = cache.join(key);
        let rootfs = artifact.join("rootfs");
        fs::create_dir_all(&rootfs).expect("rootfs");
        fs::write(rootfs.join("application"), b"prepared").expect("root file");
        fs::write(artifact.join("sbom.json"), b"{\"packages\":[]}").expect("SBOM");
        fs::write(
            artifact.join("provenance.json"),
            b"{\"builder\":\"isolated\"}",
        )
        .expect("provenance");
        let measured =
            measure_expanded_rootfs(&rootfs, &ImageLimits::default()).expect("measurement");
        let attestation = ImagePreparationAttestation {
            schema_version: IMAGE_ATTESTATION_VERSION,
            exact_reference: format!("registry.example/app@{}", digest('1')),
            image_id: digest('2'),
            platform: "linux/amd64".to_owned(),
            descriptors: vec![
                AttestedDescriptor {
                    role: "config".to_owned(),
                    media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                    digest: digest('2'),
                    size: 10,
                },
                AttestedDescriptor {
                    role: "layer-0000".to_owned(),
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                    digest: digest('3'),
                    size: 20,
                },
                AttestedDescriptor {
                    role: "manifest".to_owned(),
                    media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
                    digest: digest('1'),
                    size: 30,
                },
            ],
            expanded_root_digest: measured.digest.clone(),
            expanded_root_entries: u64::try_from(measured.entries).expect("entries"),
            expanded_root_bytes: measured.bytes,
            preparation_policy: "strict-v1".to_owned(),
            toolchain_digest: digest('f'),
            sbom_digest: file_digest(&artifact.join("sbom.json"), MAXIMUM_EVIDENCE_BYTES)
                .expect("SBOM digest"),
            provenance_digest: file_digest(
                &artifact.join("provenance.json"),
                MAXIMUM_EVIDENCE_BYTES,
            )
            .expect("provenance digest"),
            vulnerability_policy: "release-v1".to_owned(),
            worker_artifact_digest: artifact_digest.to_owned(),
            prepared_unix_ms: now_unix_ms().expect("time"),
        };
        let signed =
            sign_image_attestation("cache-test", private_key, attestation).expect("attestation");
        fs::write(
            artifact.join("attestation.json"),
            serde_json::to_vec(&signed).expect("encode"),
        )
        .expect("write attestation");
        measured.digest
    }

    #[test]
    fn audit_remeasures_roots_and_maps_revocation_to_every_pool() {
        let mut fixture = fixture();
        let entry = scan_cache(&fixture.cache).expect("scan").entries.remove(0);
        let trusted = audit_entry(
            &entry,
            &fixture.trust,
            &fixture.catalog,
            &fixture.pools,
            now_unix_ms().expect("time"),
        );
        assert_eq!(trusted.status, "trusted");
        assert!(trusted.affected_pools.is_empty());

        fixture
            .trust
            .revoked_expanded_root_digests
            .insert(fixture.root_digest);
        let revoked = audit_entry(
            &entry,
            &fixture.trust,
            &fixture.catalog,
            &fixture.pools,
            now_unix_ms().expect("time"),
        );
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.affected_pools.len(), 3);

        fs::write(entry.directory.join("rootfs/application"), b"tampered").expect("tamper");
        let rejected = audit_entry(
            &entry,
            &fixture.trust,
            &fixture.catalog,
            &fixture.pools,
            now_unix_ms().expect("time"),
        );
        assert_eq!(rejected.status, "rejected");
        assert!(rejected
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("does not match")));
        assert_eq!(rejected.affected_pools.len(), 3);
    }

    #[test]
    fn garbage_collection_deletes_only_unreferenced_roots() {
        let fixture = fixture();
        let orphan_digest = digest('b');
        write_artifact(&fixture.cache, &orphan_digest, &[7_u8; 32]);
        let interrupted = fixture.cache.join(format!(
            ".publication-{}-interrupted",
            orphan_digest.strip_prefix("sha256:").expect("digest")
        ));
        fs::create_dir(&interrupted).expect("interrupted staging");
        fs::write(interrupted.join("partial"), b"untrusted").expect("partial staging");
        let catalog_path = fixture.directory.path().join("prepared-roots.json");
        fs::write(
            &catalog_path,
            serde_json::to_vec(&fixture.catalog).expect("catalog"),
        )
        .expect("write catalog");

        garbage_collect(&fixture.cache, &catalog_path, 1, 1024 * 1024, 0, true)
            .expect("garbage collection");
        assert!(fixture
            .cache
            .join(
                fixture
                    .artifact_digest
                    .strip_prefix("sha256:")
                    .expect("digest")
            )
            .is_dir());
        assert!(!fixture
            .cache
            .join(orphan_digest.strip_prefix("sha256:").expect("digest"))
            .exists());
        assert!(!interrupted.exists());
    }

    #[test]
    fn publication_capacity_fails_closed_on_corrupt_cache_state() {
        let fixture = fixture();
        fs::remove_file(
            fixture
                .cache
                .join(
                    fixture
                        .artifact_digest
                        .strip_prefix("sha256:")
                        .expect("digest"),
                )
                .join("attestation.json"),
        )
        .expect("remove attestation");
        assert!(enforce_publication_capacity(&fixture.cache, 16, 1024 * 1024, 1).is_err());
    }

    #[test]
    fn required_audit_rejects_a_missing_reviewed_root() {
        let fixture = fixture();
        fs::remove_dir_all(
            fixture.cache.join(
                fixture
                    .artifact_digest
                    .strip_prefix("sha256:")
                    .expect("digest"),
            ),
        )
        .expect("remove reviewed root");
        let trust = fixture.directory.path().join("trust.json");
        let catalog = fixture.directory.path().join("catalog.json");
        let pools = fixture.directory.path().join("pools.json");
        fs::write(&trust, serde_json::to_vec(&fixture.trust).expect("trust")).expect("write trust");
        fs::write(
            &catalog,
            serde_json::to_vec(&fixture.catalog).expect("catalog"),
        )
        .expect("write catalog");
        fs::write(&pools, serde_json::to_vec(&fixture.pools).expect("pools")).expect("write pools");
        assert!(audit(
            &fixture.cache,
            &trust,
            &catalog,
            &pools,
            16,
            1024 * 1024,
            true,
        )
        .is_err());
    }
}
