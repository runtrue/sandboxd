use crate::cli::{Cli, Command};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use runtrue_sandbox_core::{
    sign_image_attestation, verify_image_attestation, ImagePreparationAttestation,
    SignedImageAttestation,
};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{
    compiler, io_error, prepared,
    provider::{
        ContainerdImageProvider, ContainerdProviderConfig, ImageLimits, ImagePlatform,
        ImageProvider, WritableRootfsConfig, MINIMUM_WRITABLE_ROOT_BYTES,
    },
    Docker, SandboxError, TopologyLock,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(crate) fn execute(cli: Cli) -> Result<(), SandboxError> {
    let provider_options = ProviderOptions {
        ctr: cli.ctr,
        address: cli.containerd_address,
        namespace: cli.containerd_namespace,
        snapshotter: cli.snapshotter,
        platform: cli.image_platform,
    };
    match cli.command {
        Command::GenerateImageAttestationKey {
            private_key,
            public_key,
        } => generate_attestation_key(private_key, public_key),
        Command::Lock {
            compose,
            output,
            image_store,
        } => {
            let provider = provider(&provider_options, image_store)?;
            lock(provider.as_ref(), compose, output)
        }
        Command::PrepareImage {
            reference,
            image_store,
        } => {
            let provider = provider(&provider_options, image_store)?;
            prepare_image(provider.as_ref(), reference)
        }
        Command::PublishAttestedRoot {
            reference,
            image_store,
            cache,
            private_key,
            key_id,
            preparation_policy,
            toolchain_digest,
            sbom,
            provenance,
            vulnerability_policy,
            registry_credential,
            maximum_cache_artifacts,
            maximum_cache_bytes,
        } => {
            let provider = provider(&provider_options, image_store)?;
            let private_key = read_exact_key(&private_key, true)?;
            let registry_credential = registry_credential
                .as_deref()
                .map(crate::publication::read_registry_credential)
                .transpose()?;
            crate::publication::publish(
                provider.as_ref(),
                &reference,
                registry_credential.as_ref(),
                &cache,
                &private_key,
                &key_id,
                &preparation_policy,
                &toolchain_digest,
                &sbom,
                &provenance,
                &vulnerability_policy,
                maximum_cache_artifacts,
                maximum_cache_bytes,
            )
        }
        Command::AuditAttestedCache {
            cache,
            trust_policy,
            prepared_root_catalog,
            worker_pool_catalog,
            maximum_cache_artifacts,
            maximum_cache_bytes,
            require_healthy,
        } => crate::cache::audit(
            &cache,
            &trust_policy,
            &prepared_root_catalog,
            &worker_pool_catalog,
            maximum_cache_artifacts,
            maximum_cache_bytes,
            require_healthy,
        ),
        Command::GarbageCollectAttestedCache {
            cache,
            prepared_root_catalog,
            maximum_cache_artifacts,
            maximum_cache_bytes,
            minimum_age_seconds,
            delete,
        } => crate::cache::garbage_collect(
            &cache,
            &prepared_root_catalog,
            maximum_cache_artifacts,
            maximum_cache_bytes,
            minimum_age_seconds,
            delete,
        ),
        Command::PrepareDockerImage {
            docker,
            reference,
            image_store,
            tar,
        } => prepare_docker_image(docker, reference, image_store, tar),
        Command::SignImageAttestation {
            attestation,
            private_key,
            key_id,
            output,
        } => sign_attestation(attestation, private_key, key_id, output),
        Command::VerifyImageAttestation {
            attestation,
            public_key,
        } => verify_attestation(attestation, public_key),
        Command::Run {
            lock,
            project,
            wait_for,
            timeout_seconds,
            state_root,
            image_store,
            runsc,
            ip,
            nft,
        } => {
            let provider = provider(&provider_options, image_store)?;
            run(
                provider,
                lock,
                project,
                wait_for,
                timeout_seconds,
                state_root,
                runsc,
                ip,
                nft,
            )
        }
    }
}

fn generate_attestation_key(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(), SandboxError> {
    let mut seed = [0_u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut seed))
        .map_err(|source| io_error("/dev/urandom", source))?;
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut private = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&private_key_path)
        .map_err(|source| io_error(&private_key_path, source))?;
    let public = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&public_key_path);
    let mut public = match public {
        Ok(public) => public,
        Err(source) => {
            drop(private);
            let _ = fs::remove_file(&private_key_path);
            return Err(io_error(&public_key_path, source));
        }
    };
    let write_result = private
        .write_all(&seed)
        .and_then(|()| private.sync_all())
        .and_then(|()| public.write_all(&public_key))
        .and_then(|()| public.sync_all());
    if let Err(source) = write_result {
        drop(private);
        drop(public);
        let _ = fs::remove_file(&private_key_path);
        let _ = fs::remove_file(&public_key_path);
        return Err(io_error("image attestation keypair", source));
    }
    println!(
        "{}",
        serde_json::json!({
            "private_key": private_key_path,
            "public_key": public_key_path,
            "public_key_base64": STANDARD_NO_PAD.encode(public_key),
        })
    );
    Ok(())
}

fn sign_attestation(
    attestation_path: PathBuf,
    private_key_path: PathBuf,
    key_id: String,
    output: PathBuf,
) -> Result<(), SandboxError> {
    let attestation: ImagePreparationAttestation = decode_json(&attestation_path)?;
    let private_key = read_exact_key(&private_key_path, true)?;
    let signed = sign_image_attestation(&key_id, &private_key, attestation)
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    write_new_json(&output, &signed)?;
    println!(
        "{}",
        serde_json::json!({"output": output, "key_id": key_id})
    );
    Ok(())
}

fn verify_attestation(
    attestation_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(), SandboxError> {
    let signed: SignedImageAttestation = decode_json(&attestation_path)?;
    let public_key = read_exact_key(&public_key_path, false)?;
    verify_image_attestation(&public_key, &signed)
        .map_err(|error| SandboxError::Lock(error.to_string()))?;
    println!(
        "{}",
        serde_json::json!({
            "verified": true,
            "key_id": signed.key_id,
            "worker_artifact_digest": signed.attestation.worker_artifact_digest,
            "expanded_root_digest": signed.attestation.expanded_root_digest,
        })
    );
    Ok(())
}

fn decode_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SandboxError> {
    let bytes = fs::read(path).map_err(|source| io_error(path, source))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode `{}`: {error}", path.display())))
}

fn read_exact_key(path: &Path, private: bool) -> Result<[u8; 32], SandboxError> {
    // Kubernetes Secret and ConfigMap volumes expose keys through the atomic
    // writer's read-only symlink layout. Resolve that indirection once, then
    // retain O_NOFOLLOW on the file we actually open.
    let resolved = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(&resolved)
        .map_err(|source| io_error(&resolved, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(&resolved, source))?;
    if !metadata.file_type().is_file()
        || (private
            && (metadata.mode() & 0o077 != 0 || metadata.uid() != nix::unistd::geteuid().as_raw()))
    {
        return Err(SandboxError::Lock(format!(
            "{} key must be a regular {} file",
            if private { "private" } else { "public" },
            if private {
                "owner-only file owned by the invoking identity"
            } else {
                "file"
            }
        )));
    }
    let mut bytes = Vec::with_capacity(33);
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    bytes.try_into().map_err(|_| {
        SandboxError::Lock(format!(
            "key `{}` must contain exactly 32 bytes",
            path.display()
        ))
    })
}

fn write_new_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| SandboxError::Lock(format!("encode `{}`: {error}", path.display())))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|source| io_error(path, source))?;
    file.sync_all().map_err(|source| io_error(path, source))
}

struct ProviderOptions {
    ctr: PathBuf,
    address: PathBuf,
    namespace: String,
    snapshotter: String,
    platform: String,
}

fn provider(
    options: &ProviderOptions,
    mount_root: PathBuf,
) -> Result<Arc<ContainerdImageProvider>, SandboxError> {
    let writable_root = mount_root.join("writable-roots");
    ContainerdImageProvider::new(ContainerdProviderConfig {
        ctr_program: options.ctr.clone(),
        address: options.address.clone(),
        namespace: options.namespace.clone(),
        snapshotter: options.snapshotter.clone(),
        mount_root,
        writable_rootfs: WritableRootfsConfig {
            root: writable_root,
            minimum_bytes: MINIMUM_WRITABLE_ROOT_BYTES,
            maximum_bytes: 16 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(60),
        },
        platform: ImagePlatform::parse(&options.platform)?,
        limits: ImageLimits::default(),
        fixed_rootfs: None,
    })
    .map(Arc::new)
}

fn lock(
    provider: &dyn ImageProvider,
    compose: PathBuf,
    output: PathBuf,
) -> Result<(), SandboxError> {
    let lock = compiler::lock_compose(&compose, provider, None)?;
    let bytes = serde_json::to_vec_pretty(&lock)
        .map_err(|error| SandboxError::Lock(format!("encode topology lock: {error}")))?;
    fs::write(&output, bytes).map_err(|source| io_error(&output, source))?;
    println!(
        "{}",
        serde_json::json!({
            "output": output,
            "topology_digest": lock.topology_digest,
            "services": lock.services.len(),
            "networks": lock.networks.len(),
            "startup_order": lock.startup_order,
        })
    );
    Ok(())
}

fn prepare_image(provider: &dyn ImageProvider, reference: String) -> Result<(), SandboxError> {
    let image = provider.resolve(&reference, None)?;
    let (status, rootfs) = provider.prepare(&image, None)?;
    let output = serde_json::json!({
        "status": format!("{status:?}").to_lowercase(),
        "activation": "validated_and_released",
        "rootfs_digest": rootfs.rootfs_digest(),
        "rootfs_entries": rootfs.rootfs_entries(),
        "rootfs_bytes": rootfs.rootfs_bytes(),
        "image": image,
    });
    provider.release(&rootfs)?;
    println!("{}", output);
    Ok(())
}

fn prepare_docker_image(
    docker_path: PathBuf,
    reference: String,
    image_store: PathBuf,
    tar: PathBuf,
) -> Result<(), SandboxError> {
    let docker = Docker::new(docker_path)?;
    let (directory, metadata) = prepared::prepare_image(&docker, &tar, &reference, &image_store)?;
    println!(
        "{}",
        serde_json::json!({"directory": directory, "image": metadata})
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run(
    provider: Arc<dyn ImageProvider>,
    lock: PathBuf,
    project: String,
    wait_for: String,
    timeout_seconds: u64,
    state_root: std::path::PathBuf,
    runsc: PathBuf,
    ip: PathBuf,
    nft: PathBuf,
) -> Result<(), SandboxError> {
    if timeout_seconds == 0 || timeout_seconds > 300 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300 seconds".to_owned(),
        ));
    }
    let bytes = fs::read(&lock).map_err(|source| io_error(&lock, source))?;
    let topology: TopologyLock = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode topology lock: {error}")))?;
    let mut admitted = BTreeMap::new();
    for service in topology.services.values() {
        if !admitted.contains_key(&service.image.image_id) {
            admitted.insert(
                service.image.image_id.clone(),
                provider.admit(&service.image)?,
            );
        }
    }
    let execution = executor::run_admitted(
        &topology,
        &project,
        &wait_for,
        Duration::from_secs(timeout_seconds),
        &state_root,
        &runsc,
        &ip,
        &nft,
        &admitted,
        Arc::clone(&provider),
        &runtrue_sandbox_volume::VolumeScope::new(
            runtrue_sandbox_core::TenantId::parse("local").expect("local tenant"),
            runtrue_sandbox_core::WorkspaceId::parse("local").expect("local workspace"),
        ),
        {
            let auxiliary = Arc::new(
                runtrue_sandbox_volume::LocalVolumeProvider::open(
                    runtrue_sandbox_volume::LocalVolumeConfig::new(
                        state_root.join(".auxiliary-volumes"),
                    ),
                )
                .map_err(|error| {
                    SandboxError::Runtime(format!("open auxiliary volume provider: {error}"))
                })?,
            );
            Arc::new(
                runtrue_sandbox_volume::DirectoryVolumeProvider::open(
                    runtrue_sandbox_volume::DirectoryVolumeConfig::new(
                        state_root.join(".directory-volumes"),
                    ),
                    auxiliary,
                )
                .map_err(|error| {
                    SandboxError::Runtime(format!("open directory volume provider: {error}"))
                })?,
            )
        },
        executor::ExecutorConfiguration::default(),
    );
    let mut release_error = None;
    for rootfs in admitted.values() {
        if let Err(error) = provider.release(rootfs) {
            release_error.get_or_insert(error);
        }
    }
    let result = match (execution, release_error) {
        (Ok(result), None) => result,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(error),
        (Err(error), Some(release)) => {
            return Err(SandboxError::ImageProvider(format!(
                "execution failed: {error}; image release failed: {release}"
            )));
        }
    };
    println!(
        "{}",
        serde_json::to_string(&result)
            .map_err(|error| SandboxError::Lock(format!("encode run result: {error}")))?
    );
    Ok(())
}
