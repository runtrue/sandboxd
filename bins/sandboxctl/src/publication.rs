use runtrue_sandbox_core::{
    sign_image_attestation, verify_image_attestation, AttestedDescriptor,
    ImagePreparationAttestation, SignedImageAttestation, IMAGE_ATTESTATION_VERSION,
};
use runtrue_sandbox_oci::{
    io_error,
    provider::{measure_expanded_rootfs, ImageLimits, ImageProvider, RegistryCredential},
    LockedDescriptor, LockedImage, SandboxError,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{symlink, DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::Builder;

const MAXIMUM_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_CREDENTIAL_BYTES: u64 = 128 * 1024;
const PUBLICATION_WAIT: Duration = Duration::from_secs(15 * 60);

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RegistryCredentialInput {
    Basic {
        tenant: String,
        registry: String,
        username: String,
        password: String,
    },
    Bearer {
        tenant: String,
        registry: String,
        token: String,
    },
}

pub(crate) fn read_registry_credential(path: &Path) -> Result<RegistryCredential, SandboxError> {
    let input: RegistryCredentialInput =
        serde_json::from_slice(&read_bounded(path, MAXIMUM_CREDENTIAL_BYTES)?).map_err(
            |error| SandboxError::ImageProvider(format!("decode registry credential: {error}")),
        )?;
    match input {
        RegistryCredentialInput::Basic {
            tenant,
            registry,
            username,
            password,
        } => RegistryCredential::basic(tenant, registry, username, password),
        RegistryCredentialInput::Bearer {
            tenant,
            registry,
            token,
        } => RegistryCredential::bearer(tenant, registry, token),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn publish(
    provider: &dyn ImageProvider,
    reference: &str,
    credential: Option<&RegistryCredential>,
    cache: &Path,
    private_key: &[u8; 32],
    key_id: &str,
    preparation_policy: &str,
    toolchain_digest: &str,
    sbom: &Path,
    provenance: &Path,
    vulnerability_policy: &str,
) -> Result<(), SandboxError> {
    let started = Instant::now();
    let image = provider.resolve(reference, credential)?;
    let exact_reference = image.exact_reference.clone();
    let (preparation_status, rootfs) = provider.prepare(&image, credential)?;
    let sbom_digest = file_digest(sbom, MAXIMUM_EVIDENCE_BYTES)?;
    let provenance_digest = file_digest(provenance, MAXIMUM_EVIDENCE_BYTES)?;
    let artifact_digest = root_artifact_digest(
        &image,
        rootfs.rootfs_digest(),
        rootfs.rootfs_entries(),
        rootfs.rootfs_bytes(),
        key_id,
        &ed25519_dalek::SigningKey::from_bytes(private_key)
            .verifying_key()
            .to_bytes(),
        preparation_policy,
        toolchain_digest,
        &sbom_digest,
        &provenance_digest,
        vulnerability_policy,
    );
    let publication = publish_inner(
        &image,
        rootfs.rootfs(),
        rootfs.rootfs_digest(),
        rootfs.rootfs_entries(),
        rootfs.rootfs_bytes(),
        cache,
        private_key,
        key_id,
        preparation_policy,
        toolchain_digest,
        sbom,
        &sbom_digest,
        provenance,
        &provenance_digest,
        vulnerability_policy,
        &artifact_digest,
    );
    let release = provider.release(&rootfs);
    let report = publication?;
    release?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "status": report.status,
            "provider_status": format!("{preparation_status:?}").to_lowercase(),
            "exact_reference": exact_reference,
            "worker_artifact_digest": artifact_digest,
            "artifact_directory": report.directory,
            "rootfs_bytes": report.rootfs_bytes,
            "rootfs_entries": report.rootfs_entries,
            "preparation_ms": started.elapsed().as_millis(),
        })
    );
    Ok(())
}

struct PublicationReport {
    status: &'static str,
    directory: PathBuf,
    rootfs_entries: usize,
    rootfs_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn publish_inner(
    image: &LockedImage,
    source_rootfs: &Path,
    rootfs_digest: &str,
    rootfs_entries: usize,
    rootfs_bytes: u64,
    cache: &Path,
    private_key: &[u8; 32],
    key_id: &str,
    preparation_policy: &str,
    toolchain_digest: &str,
    sbom: &Path,
    sbom_digest: &str,
    provenance: &Path,
    provenance_digest: &str,
    vulnerability_policy: &str,
    artifact_digest: &str,
) -> Result<PublicationReport, SandboxError> {
    fs::create_dir_all(cache).map_err(|source| io_error(cache, source))?;
    let cache = fs::canonicalize(cache).map_err(|source| io_error(cache, source))?;
    let key = artifact_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| SandboxError::Lock("artifact digest is not sha256".to_owned()))?;
    let destination = cache.join(key);
    if destination.exists() {
        verify_cached(
            &destination,
            image,
            rootfs_digest,
            rootfs_entries,
            rootfs_bytes,
            artifact_digest,
            private_key,
            key_id,
            preparation_policy,
            toolchain_digest,
            sbom_digest,
            provenance_digest,
            vulnerability_policy,
        )?;
        return Ok(PublicationReport {
            status: "cache_hit",
            directory: destination,
            rootfs_entries,
            rootfs_bytes,
        });
    }
    let lock_path = cache.join(format!(".{key}.lock"));
    let lock = match wait_for_publication_lock(&lock_path, &destination)? {
        Some(lock) => lock,
        None => {
            verify_cached(
                &destination,
                image,
                rootfs_digest,
                rootfs_entries,
                rootfs_bytes,
                artifact_digest,
                private_key,
                key_id,
                preparation_policy,
                toolchain_digest,
                sbom_digest,
                provenance_digest,
                vulnerability_policy,
            )?;
            return Ok(PublicationReport {
                status: "cache_hit",
                directory: destination,
                rootfs_entries,
                rootfs_bytes,
            });
        }
    };
    let staging = Builder::new()
        .prefix(".publication-")
        .tempdir_in(&cache)
        .map_err(|source| io_error(&cache, source))?;
    let staged_rootfs = staging.path().join("rootfs");
    copy_tree(source_rootfs, &staged_rootfs)?;
    copy_evidence(sbom, &staging.path().join("sbom.json"))?;
    copy_evidence(provenance, &staging.path().join("provenance.json"))?;
    let attestation = ImagePreparationAttestation {
        schema_version: IMAGE_ATTESTATION_VERSION,
        exact_reference: image.exact_reference.clone(),
        image_id: image.image_id.clone(),
        platform: platform(image),
        descriptors: descriptors(image),
        expanded_root_digest: rootfs_digest.to_owned(),
        expanded_root_entries: u64::try_from(rootfs_entries)
            .map_err(|_| SandboxError::Lock("root entry count exceeds u64".to_owned()))?,
        expanded_root_bytes: rootfs_bytes,
        preparation_policy: preparation_policy.to_owned(),
        toolchain_digest: toolchain_digest.to_owned(),
        sbom_digest: sbom_digest.to_owned(),
        provenance_digest: provenance_digest.to_owned(),
        vulnerability_policy: vulnerability_policy.to_owned(),
        worker_artifact_digest: artifact_digest.to_owned(),
        prepared_unix_ms: now_unix_ms()?,
    };
    let signed = sign_image_attestation(key_id, private_key, attestation)
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    write_new_json(&staging.path().join("attestation.json"), &signed)?;
    let staging_path = staging.keep();
    fs::rename(&staging_path, &destination).map_err(|source| io_error(&destination, source))?;
    File::open(&cache)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(&cache, source))?;
    drop(lock);
    Ok(PublicationReport {
        status: "published",
        directory: destination,
        rootfs_entries,
        rootfs_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_cached(
    directory: &Path,
    image: &LockedImage,
    rootfs_digest: &str,
    rootfs_entries: usize,
    rootfs_bytes: u64,
    artifact_digest: &str,
    private_key: &[u8; 32],
    key_id: &str,
    preparation_policy: &str,
    toolchain_digest: &str,
    sbom_digest: &str,
    provenance_digest: &str,
    vulnerability_policy: &str,
) -> Result<(), SandboxError> {
    let signed: SignedImageAttestation = serde_json::from_slice(
        &fs::read(directory.join("attestation.json"))
            .map_err(|source| io_error(directory.join("attestation.json"), source))?,
    )
    .map_err(|error| SandboxError::Lock(format!("decode cached attestation: {error}")))?;
    let public_key = ed25519_dalek::SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes();
    verify_image_attestation(&public_key, &signed)
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    let measured = measure_expanded_rootfs(&directory.join("rootfs"), &ImageLimits::default())?;
    let rootfs_entries = u64::try_from(rootfs_entries)
        .map_err(|_| SandboxError::Lock("root entry count exceeds u64".to_owned()))?;
    if signed.key_id != key_id
        || signed.attestation.exact_reference != image.exact_reference
        || signed.attestation.image_id != image.image_id
        || signed.attestation.descriptors != descriptors(image)
        || signed.attestation.expanded_root_digest != rootfs_digest
        || signed.attestation.expanded_root_entries != rootfs_entries
        || signed.attestation.expanded_root_bytes != rootfs_bytes
        || measured.digest != rootfs_digest
        || u64::try_from(measured.entries).ok() != Some(rootfs_entries)
        || measured.bytes != rootfs_bytes
        || signed.attestation.preparation_policy != preparation_policy
        || signed.attestation.toolchain_digest != toolchain_digest
        || signed.attestation.sbom_digest != sbom_digest
        || signed.attestation.provenance_digest != provenance_digest
        || signed.attestation.vulnerability_policy != vulnerability_policy
        || signed.attestation.worker_artifact_digest != artifact_digest
        || file_digest(&directory.join("sbom.json"), MAXIMUM_EVIDENCE_BYTES)? != sbom_digest
        || file_digest(&directory.join("provenance.json"), MAXIMUM_EVIDENCE_BYTES)?
            != provenance_digest
    {
        return Err(SandboxError::Lock(
            "cached root artifact does not match the prepared image".to_owned(),
        ));
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), SandboxError> {
    let source_metadata = fs::symlink_metadata(source).map_err(|error| io_error(source, error))?;
    if !source_metadata.is_dir() {
        return Err(SandboxError::Lock(
            "prepared root source is not a directory".to_owned(),
        ));
    }
    DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .map_err(|error| io_error(destination, error))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| io_error(source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(source, error))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&source_path).map_err(|error| io_error(&source_path, error))?;
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            let mut source_file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&source_path)
                .map_err(|error| io_error(&source_path, error))?;
            let mut destination_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination_path)
                .map_err(|error| io_error(&destination_path, error))?;
            std::io::copy(&mut source_file, &mut destination_file)
                .map_err(|error| io_error(&destination_path, error))?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o7777),
            )
            .and_then(|()| destination_file.sync_all())
            .map_err(|error| io_error(&destination_path, error))?;
        } else if metadata.file_type().is_symlink() {
            let target =
                fs::read_link(&source_path).map_err(|error| io_error(&source_path, error))?;
            symlink(target, &destination_path)
                .map_err(|error| io_error(&destination_path, error))?;
        } else {
            return Err(SandboxError::Lock(format!(
                "prepared root contains unsupported entry `{}`",
                source_path.display()
            )));
        }
    }
    fs::set_permissions(
        destination,
        fs::Permissions::from_mode(source_metadata.permissions().mode() & 0o7777),
    )
    .map_err(|error| io_error(destination, error))?;
    File::open(destination)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(destination, error))
}

fn copy_evidence(source: &Path, destination: &Path) -> Result<(), SandboxError> {
    let bytes = read_bounded(source, MAXIMUM_EVIDENCE_BYTES)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(destination)
        .map_err(|error| io_error(destination, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(destination, error))
}

fn file_digest(path: &Path, maximum: u64) -> Result<String, SandboxError> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(read_bounded(path, maximum)?))
    ))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, SandboxError> {
    // Kubernetes projected volumes use an atomic, read-only symlink layout.
    // Resolve it once and keep O_NOFOLLOW on the resulting regular file.
    let resolved = fs::canonicalize(path).map_err(|error| io_error(path, error))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&resolved)
        .map_err(|error| io_error(&resolved, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(&resolved, error))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(SandboxError::Lock(format!(
            "evidence `{}` is not a bounded regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn root_artifact_digest(
    image: &LockedImage,
    rootfs_digest: &str,
    entries: usize,
    bytes: u64,
    key_id: &str,
    public_key: &[u8; 32],
    preparation_policy: &str,
    toolchain_digest: &str,
    sbom_digest: &str,
    provenance_digest: &str,
    vulnerability_policy: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"runtrue-sandboxd/root-artifact/v2\0");
    update_digest_field(&mut digest, image.exact_reference.as_bytes());
    update_digest_field(&mut digest, image.image_id.as_bytes());
    update_digest_field(&mut digest, rootfs_digest.as_bytes());
    digest.update(entries.to_be_bytes());
    digest.update(bytes.to_be_bytes());
    update_digest_field(&mut digest, key_id.as_bytes());
    update_digest_field(&mut digest, public_key);
    update_digest_field(&mut digest, preparation_policy.as_bytes());
    update_digest_field(&mut digest, toolchain_digest.as_bytes());
    update_digest_field(&mut digest, sbom_digest.as_bytes());
    update_digest_field(&mut digest, provenance_digest.as_bytes());
    update_digest_field(&mut digest, vulnerability_policy.as_bytes());
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(
        u64::try_from(value.len())
            .expect("attestation field length fits u64")
            .to_be_bytes(),
    );
    digest.update(value);
}

fn descriptors(image: &LockedImage) -> Vec<AttestedDescriptor> {
    let mut descriptors = Vec::with_capacity(image.layers.len() + 3);
    if let Some(index) = &image.index {
        descriptors.push(attested("index", index));
    }
    descriptors.push(attested("manifest", &image.manifest));
    descriptors.push(attested("config", &image.config));
    descriptors.extend(
        image
            .layers
            .iter()
            .enumerate()
            .map(|(index, layer)| attested(&format!("layer-{index:04}"), layer)),
    );
    descriptors.sort();
    descriptors
}

fn attested(role: &str, descriptor: &LockedDescriptor) -> AttestedDescriptor {
    AttestedDescriptor {
        role: role.to_owned(),
        media_type: descriptor.media_type.clone(),
        digest: descriptor.digest.clone(),
        size: descriptor.size,
    }
}

fn platform(image: &LockedImage) -> String {
    image.variant.as_ref().map_or_else(
        || format!("{}/{}", image.operating_system, image.architecture),
        |variant| {
            format!(
                "{}/{}/{}",
                image.operating_system, image.architecture, variant
            )
        },
    )
}

fn write_new_json(path: &Path, value: &impl serde::Serialize) -> Result<(), SandboxError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| SandboxError::Lock(format!("encode publication: {error}")))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn wait_for_publication_lock(
    lock_path: &Path,
    destination: &Path,
) -> Result<Option<PublicationLock>, SandboxError> {
    let deadline = Instant::now() + PUBLICATION_WAIT;
    while Instant::now() < deadline {
        if destination.is_dir() {
            return Ok(None);
        }
        if let Some(lock) = PublicationLock::acquire(lock_path)? {
            return Ok(Some(lock));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(SandboxError::Timeout(
        "wait for concurrent image publication".to_owned(),
    ))
}

fn now_unix_ms() -> Result<u64, SandboxError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SandboxError::Lock("system time precedes Unix epoch".to_owned()))?
            .as_millis(),
    )
    .map_err(|_| SandboxError::Lock("system time exceeds u64".to_owned()))
}

struct PublicationLock {
    _file: nix::fcntl::Flock<File>,
}

impl PublicationLock {
    fn acquire(path: &Path) -> Result<Option<Self>, SandboxError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|error| io_error(path, error))?;
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(mut file) => {
                file.set_len(0).map_err(|error| io_error(path, error))?;
                writeln!(file, "{}", std::process::id())
                    .and_then(|()| file.sync_all())
                    .map_err(|error| io_error(path, error))?;
                Ok(Some(Self { _file: file }))
            }
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
            Err((_, error)) => Err(SandboxError::Lock(format!(
                "lock image publication `{}`: {error}",
                path.display()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_oci::LockedDescriptor;
    use std::{
        collections::BTreeSet,
        os::unix::net::UnixListener,
        sync::{Arc, Barrier},
    };

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn descriptor(value: char, media_type: &str, size: u64) -> LockedDescriptor {
        LockedDescriptor {
            media_type: media_type.to_owned(),
            digest: digest(value),
            size,
        }
    }

    fn image() -> LockedImage {
        LockedImage {
            source: "registry.example/app:stable".to_owned(),
            exact_reference: format!("registry.example/app@{}", digest('a')),
            image_id: digest('b'),
            index: Some(descriptor(
                'c',
                "application/vnd.oci.image.index.v1+json",
                100,
            )),
            manifest: descriptor('a', "application/vnd.oci.image.manifest.v1+json", 200),
            config: descriptor('b', "application/vnd.oci.image.config.v1+json", 300),
            layers: vec![descriptor(
                'd',
                "application/vnd.oci.image.layer.v1.tar+gzip",
                400,
            )],
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        rootfs: PathBuf,
        cache: PathBuf,
        sbom: PathBuf,
        provenance: PathBuf,
        rootfs_digest: String,
        rootfs_entries: usize,
        rootfs_bytes: u64,
        artifact_digest: String,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().expect("temporary directory");
        let rootfs = directory.path().join("source-root");
        fs::create_dir(&rootfs).expect("rootfs");
        fs::write(rootfs.join("application"), b"prepared").expect("root file");
        fs::create_dir(rootfs.join("tmp")).expect("temporary directory");
        fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777))
            .expect("sticky mode");
        let cache = directory.path().join("cache");
        let sbom = directory.path().join("sbom.json");
        let provenance = directory.path().join("provenance.json");
        fs::write(&sbom, b"{\"packages\":[]}").expect("SBOM");
        fs::write(&provenance, b"{\"builder\":\"isolated\"}").expect("provenance");
        let sbom_digest = file_digest(&sbom, MAXIMUM_EVIDENCE_BYTES).expect("SBOM digest");
        let provenance_digest =
            file_digest(&provenance, MAXIMUM_EVIDENCE_BYTES).expect("provenance digest");
        let measured =
            measure_expanded_rootfs(&rootfs, &ImageLimits::default()).expect("root measurement");
        let artifact_digest = root_artifact_digest(
            &image(),
            &measured.digest,
            measured.entries,
            measured.bytes,
            "preparer-2026",
            &ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                .verifying_key()
                .to_bytes(),
            "strict-v1",
            &digest('f'),
            &sbom_digest,
            &provenance_digest,
            "release-v1",
        );
        Fixture {
            directory,
            rootfs,
            cache,
            sbom,
            provenance,
            rootfs_digest: measured.digest,
            rootfs_entries: measured.entries,
            rootfs_bytes: measured.bytes,
            artifact_digest,
        }
    }

    fn publish_fixture(fixture: &Fixture) -> Result<PublicationReport, SandboxError> {
        let sbom_digest = file_digest(&fixture.sbom, MAXIMUM_EVIDENCE_BYTES).expect("SBOM digest");
        let provenance_digest =
            file_digest(&fixture.provenance, MAXIMUM_EVIDENCE_BYTES).expect("provenance digest");
        publish_inner(
            &image(),
            &fixture.rootfs,
            &fixture.rootfs_digest,
            fixture.rootfs_entries,
            fixture.rootfs_bytes,
            &fixture.cache,
            &[7_u8; 32],
            "preparer-2026",
            "strict-v1",
            &digest('f'),
            &fixture.sbom,
            &sbom_digest,
            &fixture.provenance,
            &provenance_digest,
            "release-v1",
            &fixture.artifact_digest,
        )
    }

    #[test]
    fn publication_is_atomic_reusable_and_evidence_bound() {
        let fixture = fixture();
        assert_eq!(
            publish_fixture(&fixture).expect("publish").status,
            "published"
        );
        assert_eq!(
            publish_fixture(&fixture).expect("cache hit").status,
            "cache_hit"
        );
        let destination = fixture.cache.join(
            fixture
                .artifact_digest
                .strip_prefix("sha256:")
                .expect("digest"),
        );
        assert_eq!(
            fs::read(destination.join("rootfs/application")).expect("root file"),
            b"prepared"
        );
        assert_eq!(
            fs::symlink_metadata(destination.join("rootfs/tmp"))
                .expect("temporary directory")
                .permissions()
                .mode()
                & 0o7777,
            0o1777
        );
        let signed: SignedImageAttestation = serde_json::from_slice(
            &fs::read(destination.join("attestation.json")).expect("attestation"),
        )
        .expect("signed attestation");
        assert_eq!(
            signed.attestation.sbom_digest,
            file_digest(&fixture.sbom, MAXIMUM_EVIDENCE_BYTES).expect("SBOM digest")
        );
        fs::write(destination.join("rootfs/application"), b"tampered").expect("tamper root");
        assert!(publish_fixture(&fixture).is_err());
    }

    #[test]
    fn publication_identity_separates_policy_and_signer_cohorts() {
        let fixture = fixture();
        let sbom_digest = file_digest(&fixture.sbom, MAXIMUM_EVIDENCE_BYTES).expect("SBOM digest");
        let provenance_digest =
            file_digest(&fixture.provenance, MAXIMUM_EVIDENCE_BYTES).expect("provenance digest");
        let changed_policy = root_artifact_digest(
            &image(),
            &fixture.rootfs_digest,
            fixture.rootfs_entries,
            fixture.rootfs_bytes,
            "preparer-2026",
            &ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
                .verifying_key()
                .to_bytes(),
            "strict-v2",
            &digest('f'),
            &sbom_digest,
            &provenance_digest,
            "release-v1",
        );
        let changed_signer = root_artifact_digest(
            &image(),
            &fixture.rootfs_digest,
            fixture.rootfs_entries,
            fixture.rootfs_bytes,
            "preparer-2027",
            &ed25519_dalek::SigningKey::from_bytes(&[8_u8; 32])
                .verifying_key()
                .to_bytes(),
            "strict-v1",
            &digest('f'),
            &sbom_digest,
            &provenance_digest,
            "release-v1",
        );
        assert_ne!(fixture.artifact_digest, changed_policy);
        assert_ne!(fixture.artifact_digest, changed_signer);
        assert_ne!(changed_policy, changed_signer);
    }

    #[test]
    fn cache_rejects_retained_evidence_tampering() {
        let fixture = fixture();
        publish_fixture(&fixture).expect("publish");
        let destination = fixture.cache.join(
            fixture
                .artifact_digest
                .strip_prefix("sha256:")
                .expect("digest"),
        );
        let cached_sbom = destination.join("sbom.json");
        fs::set_permissions(&cached_sbom, fs::Permissions::from_mode(0o644))
            .expect("simulate cache-writer authority");
        fs::write(cached_sbom, b"{\"tampered\":true}").expect("tamper retained evidence");
        assert!(publish_fixture(&fixture).is_err());
    }

    #[test]
    fn concurrent_duplicate_publication_has_one_writer() {
        let fixture = Arc::new(fixture());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                publish_fixture(&fixture).expect("publication").status
            }));
        }
        barrier.wait();
        let statuses = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<BTreeSet<_>>();
        assert_eq!(statuses, BTreeSet::from(["cache_hit", "published"]));
    }

    #[test]
    fn failed_copy_publishes_no_trusted_partial() {
        let fixture = fixture();
        let socket_path = fixture.rootfs.join("socket");
        let socket = UnixListener::bind(&socket_path).expect("socket");
        assert!(publish_fixture(&fixture).is_err());
        assert!(!fixture
            .cache
            .join(
                fixture
                    .artifact_digest
                    .strip_prefix("sha256:")
                    .expect("digest")
            )
            .exists());
        let directories = fs::read_dir(&fixture.cache)
            .expect("cache")
            .filter_map(|entry| {
                let entry = entry.expect("entry");
                entry
                    .file_type()
                    .expect("file type")
                    .is_dir()
                    .then_some(entry)
            })
            .collect::<Vec<_>>();
        assert!(directories.is_empty(), "{directories:?}");
        drop(socket);
        fs::remove_file(socket_path).expect("remove socket");
        assert_eq!(
            publish_fixture(&fixture)
                .expect("retry after interrupted writer")
                .status,
            "published"
        );
        assert!(fixture.directory.path().is_dir());
    }
}
