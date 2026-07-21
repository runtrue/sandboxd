use crate::cli::{Cli, Command};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{
    compiler, io_error, prepared,
    provider::{
        ContainerdImageProvider, ContainerdProviderConfig, ImageLimits, ImagePlatform,
        ImageProvider, WritableRootfsConfig, MINIMUM_WRITABLE_ROOT_BYTES,
    },
    Docker, SandboxError, TopologyLock,
};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc, time::Duration};

pub(crate) fn execute(cli: Cli) -> Result<(), SandboxError> {
    let provider_options = ProviderOptions {
        ctr: cli.ctr,
        mkfs_ext4: cli.mkfs_ext4,
        losetup: cli.losetup,
        address: cli.containerd_address,
        namespace: cli.containerd_namespace,
        snapshotter: cli.snapshotter,
        platform: cli.image_platform,
    };
    match cli.command {
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
        Command::PrepareDockerImage {
            docker,
            reference,
            image_store,
            tar,
        } => prepare_docker_image(docker, reference, image_store, tar),
        Command::Run {
            lock,
            project,
            wait_for,
            timeout_seconds,
            state_root,
            image_store,
            runsc,
            ip,
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
            )
        }
    }
}

struct ProviderOptions {
    ctr: PathBuf,
    mkfs_ext4: PathBuf,
    losetup: PathBuf,
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
            mkfs_ext4_program: options.mkfs_ext4.clone(),
            losetup_program: options.losetup.clone(),
            minimum_bytes: MINIMUM_WRITABLE_ROOT_BYTES,
            maximum_bytes: 16 * 1024 * 1024 * 1024,
            operation_timeout: Duration::from_secs(60),
        },
        platform: ImagePlatform::parse(&options.platform)?,
        limits: ImageLimits::default(),
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
        &admitted,
        Arc::clone(&provider),
        &runtrue_sandbox_volume::VolumeScope::new(
            runtrue_sandbox_core::TenantId::parse("local").expect("local tenant"),
            runtrue_sandbox_core::WorkspaceId::parse("local").expect("local workspace"),
        ),
        Arc::new(
            runtrue_sandbox_volume::LocalVolumeProvider::open(
                runtrue_sandbox_volume::LocalVolumeConfig::new(state_root.join(".volumes")),
            )
            .map_err(|error| {
                SandboxError::Runtime(format!("open local volume provider: {error}"))
            })?,
        ),
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
