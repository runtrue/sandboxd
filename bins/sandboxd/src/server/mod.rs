mod config;
mod connection;
mod limit;
mod socket;

pub(crate) use config::ServerConfig;

use crate::{
    assignment::AssignmentLedger,
    audit::AuditLog,
    authorization::{ConnectionEndpoint, WorkOrderVerifier},
    state::{Counters, DaemonState},
    worker::WorkerSlot,
};
use limit::ConnectionLimiter;
use nix::{
    errno::Errno,
    poll::{poll, PollFd, PollFlags},
};
use runtrue_sandbox_artifact::{ArtifactLimits, ArtifactStore, LocalArtifactStore};
#[cfg(feature = "s3-artifacts")]
use runtrue_sandbox_artifact::{S3ArtifactConfig, S3ArtifactStore};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{
    compiler, io_error,
    provider::{
        ContainerdImageProvider, ContainerdProviderConfig, FixedRootfsConfig, ImageLimits,
        ImagePlatform, ImmutableRootfs, WritableRootfsConfig,
    },
    SandboxError, TopologyLock,
};
use runtrue_sandbox_volume::{
    ArtifactVolumeStore, DirectoryVolumeConfig, DirectoryVolumeProvider, LocalSecretResolver,
    LocalVolumeConfig, LocalVolumeProvider, VolumeProvider,
};

pub(crate) const MAXIMUM_WRITABLE_ROOT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::{fd::AsFd as _, unix::fs::PermissionsExt as _, unix::net::UnixListener},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{atomic::Ordering, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

struct BoundEndpoint {
    listener: UnixListener,
    path: PathBuf,
    endpoint: ConnectionEndpoint,
}

impl Drop for BoundEndpoint {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServeOutcome {
    Shutdown,
    Recycle,
}

pub(crate) fn serve(config: ServerConfig) -> Result<ServeOutcome, SandboxError> {
    socket::require_root()?;
    config.validate()?;
    socket::validate_paths(
        &config.operator_socket,
        config.workload_socket.as_deref(),
        &config.state_root,
        &config.image_store,
    )?;

    let sandbox_root = config.state_root.join("sandboxes");
    let artifact_root = config.state_root.join("artifacts");
    let snapshot_staging_root = config.state_root.join("snapshot-staging");
    let control_root = config.state_root.join("control");
    let runsc = validate_runsc(&config.runsc)?;
    let recovery = executor::recover(&sandbox_root, &runsc, &config.ip, &config.nft)?;
    let assignments = AssignmentLedger::open(&control_root)?;
    assignments.reconcile_after_recovery()?;
    let Some(worker) = WorkerSlot::open(
        &control_root,
        config.resource_shape.clone(),
        config.minimum_clean_age,
    )?
    else {
        return Ok(ServeOutcome::Recycle);
    };
    let audit = AuditLog::open(&control_root)?;
    let artifact_store: Arc<dyn ArtifactStore> = if let Some(bucket) = &config.artifact_s3_bucket {
        #[cfg(not(feature = "s3-artifacts"))]
        {
            let _ = (
                bucket,
                &config.artifact_s3_region,
                &config.artifact_s3_prefix,
            );
            return Err(SandboxError::Runtime(
                "this sandboxd build does not include S3 artifact support".to_owned(),
            ));
        }
        #[cfg(feature = "s3-artifacts")]
        {
            let key_path = config
                .artifact_master_key
                .as_deref()
                .expect("S3 artifact master key is validated");
            Arc::new(
                S3ArtifactStore::open(
                    S3ArtifactConfig {
                        bucket: bucket.clone(),
                        region: config.artifact_s3_region.clone(),
                        endpoint: config.artifact_s3_endpoint.clone(),
                        key_prefix: config.artifact_s3_prefix.clone(),
                        virtual_hosted: config.artifact_s3_virtual_hosted,
                        allow_http_for_local_testing: config
                            .artifact_s3_allow_http_for_local_testing,
                        credentials_file: config.artifact_s3_credentials_file.clone(),
                    },
                    key_path,
                    ArtifactLimits::default(),
                )
                .map_err(|error| {
                    SandboxError::Runtime(format!("open S3 artifact store: {error}"))
                })?,
            )
        }
    } else {
        let key_path = config
            .artifact_master_key
            .clone()
            .unwrap_or_else(|| control_root.join("artifact-master.key"));
        Arc::new(
            LocalArtifactStore::open(artifact_root, &key_path, ArtifactLimits::default()).map_err(
                |error| SandboxError::Runtime(format!("open local artifact store: {error}")),
            )?,
        )
    };
    let work_orders = config
        .work_order_key
        .as_deref()
        .map(|path| WorkOrderVerifier::from_key_file(path, &control_root))
        .transpose()?;
    let fixed_rootfs = config.fixed_rootfs.clone();
    crate::image_attestation::verify_configured(
        config.image_attestation.as_deref(),
        config.image_attestation_trust_policy.as_deref(),
        config.worker_artifact_digest.as_deref(),
        fixed_rootfs.as_ref(),
    )?;
    let image_provider: Arc<dyn runtrue_sandbox_oci::provider::ImageProvider> =
        Arc::new(ContainerdImageProvider::new(ContainerdProviderConfig {
            ctr_program: config.ctr,
            address: config.containerd_address,
            namespace: config.containerd_namespace,
            snapshotter: config.snapshotter,
            mount_root: config.image_store,
            writable_rootfs: WritableRootfsConfig {
                root: config.state_root.join("writable-roots"),
                minimum_bytes: runtrue_sandbox_oci::provider::MINIMUM_WRITABLE_ROOT_BYTES,
                maximum_bytes: MAXIMUM_WRITABLE_ROOT_BYTES,
                operation_timeout: Duration::from_secs(60),
            },
            platform: ImagePlatform::parse(&config.image_platform)?,
            limits: ImageLimits::default(),
            fixed_rootfs: config.fixed_rootfs,
        })?);
    let preloaded_images = preload_fixed_images(fixed_rootfs.as_ref(), &image_provider)?;
    let mut volume_config = LocalVolumeConfig::new(config.state_root.join("volumes"));
    volume_config.mkfs_ext4_program = config.mkfs_ext4.clone();
    volume_config.losetup_program = config.losetup.clone();
    volume_config.operation_timeout = Duration::from_secs(60);
    let secret_resolver = Arc::new(
        LocalSecretResolver::open(config.state_root.join("secret-source"), 16 * 1024 * 1024)
            .map_err(|error| {
                SandboxError::Runtime(format!("open local secret resolver: {error}"))
            })?,
    );
    let local_volume_provider = Arc::new(
        LocalVolumeProvider::open_with_secret_resolver(volume_config, Some(secret_resolver))
            .map_err(|error| {
                SandboxError::Runtime(format!("open local volume provider: {error}"))
            })?,
    );
    let volume_provider: Arc<dyn VolumeProvider> = Arc::new(
        DirectoryVolumeProvider::open(
            DirectoryVolumeConfig::new(config.state_root.join("directory-volumes")),
            Arc::clone(&local_volume_provider),
        )
        .map_err(|error| {
            SandboxError::Runtime(format!("open directory volume provider: {error}"))
        })?,
    );
    let artifact_volume_store: Arc<dyn ArtifactVolumeStore> = local_volume_provider;

    let mut endpoints = vec![BoundEndpoint {
        listener: socket::bind_operator(&config.operator_socket)?,
        path: config.operator_socket.clone(),
        endpoint: ConnectionEndpoint::Operator,
    }];
    if let (Some(path), Some(broker_uid)) = (&config.workload_socket, config.broker_uid) {
        endpoints.push(BoundEndpoint {
            listener: socket::bind_workload(path, broker_uid, config.broker_gid)?,
            path: path.clone(),
            endpoint: ConnectionEndpoint::Workload { broker_uid },
        });
    }

    let daemon = Arc::new(DaemonState {
        state_root: sandbox_root,
        snapshot_staging_root,
        artifact_store,
        worker_id: config.worker_id,
        guest_profiles: config.guest_profiles,
        image_provider,
        volume_provider,
        artifact_volume_store,
        runsc: config.runsc,
        ip: config.ip,
        nft: config.nft,
        executor: config.executor,
        assignments,
        worker,
        audit,
        work_orders,
        cache: Mutex::new(preloaded_images),
        active: Mutex::new(BTreeSet::new()),
        sandboxes: Mutex::new(BTreeMap::new()),
        counters: Mutex::new(Counters {
            recovered_projects: recovery.recovered_projects,
            ..Counters::default()
        }),
        tenant_counters: Mutex::new(BTreeMap::new()),
        shutdown: std::sync::atomic::AtomicBool::new(false),
    });
    daemon.worker.mark_clean()?;
    print_ready(&endpoints, &daemon);
    let limiter = ConnectionLimiter::new(config.maximum_connections);
    accept_connections(&endpoints, &daemon, &limiter, config.io_timeout)?;
    wait_for_connections(&limiter, config.io_timeout)?;
    if daemon.worker.recycle_required() {
        let sandboxes = std::mem::take(&mut *daemon.sandboxes.lock().expect("sandbox lock"));
        drop(sandboxes);
        release_image_cache(&daemon)?;
        return Ok(ServeOutcome::Recycle);
    }
    if !daemon.active.lock().expect("active lock").is_empty() {
        return Err(SandboxError::Runtime(
            "shutdown raced with active sandboxes".to_owned(),
        ));
    }
    release_image_cache(&daemon)?;
    Ok(ServeOutcome::Shutdown)
}

fn validate_runsc(path: &std::path::Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::Runtime(
            "runsc executable must be an absolute path".to_owned(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::metadata(&canonical).map_err(|source| io_error(&canonical, source))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(SandboxError::Runtime(
            "runsc must be an executable regular file".to_owned(),
        ));
    }
    let mut child = Command::new(&canonical)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| io_error(&canonical, source))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| SandboxError::Runtime(format!("wait for runsc version: {source}")))?
        {
            if status.success() {
                return Ok(canonical);
            }
            return Err(SandboxError::Runtime(format!(
                "runsc version check failed with status {status}"
            )));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::Timeout(
                "validate runsc executable".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn preload_fixed_images(
    fixed: Option<&FixedRootfsConfig>,
    provider: &Arc<dyn runtrue_sandbox_oci::provider::ImageProvider>,
) -> Result<BTreeMap<String, Arc<ImmutableRootfs>>, SandboxError> {
    let Some(fixed) = fixed else {
        return Ok(BTreeMap::new());
    };
    let bytes =
        fs::read(&fixed.topology_lock).map_err(|source| io_error(&fixed.topology_lock, source))?;
    let topology: TopologyLock = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode fixed topology lock: {error}")))?;
    compiler::verify_lock(&topology)?;
    let mut images = BTreeMap::new();
    for service in topology.services.values() {
        if images.contains_key(&service.image.image_id) {
            continue;
        }
        images.insert(
            service.image.image_id.clone(),
            Arc::new(provider.admit(&service.image)?),
        );
    }
    if images.is_empty() {
        return Err(SandboxError::Runtime(
            "fixed worker did not preload an attested root set".to_owned(),
        ));
    }
    Ok(images)
}

fn release_image_cache(daemon: &DaemonState) -> Result<(), SandboxError> {
    let images = std::mem::take(&mut *daemon.cache.lock().expect("cache lock"));
    let mut first_error = None;
    for (_, image) in images {
        match Arc::try_unwrap(image) {
            Ok(image) => {
                if let Err(error) = daemon.image_provider.release(&image) {
                    first_error.get_or_insert(error);
                }
            }
            Err(_) => {
                first_error.get_or_insert_with(|| {
                    SandboxError::Runtime(
                        "image admission handle remained borrowed during shutdown".to_owned(),
                    )
                });
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn accept_connections(
    endpoints: &[BoundEndpoint],
    daemon: &Arc<DaemonState>,
    limiter: &Arc<ConnectionLimiter>,
    io_timeout: Duration,
) -> Result<(), SandboxError> {
    while !daemon.shutdown.load(Ordering::Acquire) {
        let mut descriptors = endpoints
            .iter()
            .map(|bound| PollFd::new(bound.listener.as_fd(), PollFlags::POLLIN))
            .collect::<Vec<_>>();
        match poll(&mut descriptors, 100_u16) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => {
                return Err(SandboxError::Runtime(format!(
                    "poll control sockets: {error}"
                )))
            }
        }
        let readiness = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or(PollFlags::POLLNVAL))
            .collect::<Vec<_>>();
        drop(descriptors);
        for (bound, events) in endpoints.iter().zip(readiness) {
            if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                return Err(SandboxError::Runtime(format!(
                    "control socket `{}` reported poll error {events:?}",
                    bound.path.display()
                )));
            }
            if events.contains(PollFlags::POLLIN) {
                drain_connections(bound, daemon, limiter, io_timeout)?;
            }
        }
    }
    Ok(())
}

fn drain_connections(
    bound: &BoundEndpoint,
    daemon: &Arc<DaemonState>,
    limiter: &Arc<ConnectionLimiter>,
    io_timeout: Duration,
) -> Result<(), SandboxError> {
    loop {
        let stream = match bound.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(source) => return Err(io_error(&bound.path, source)),
        };
        let Some(permit) = limiter.try_acquire() else {
            daemon
                .counters
                .lock()
                .expect("counter lock")
                .rejected_connections += 1;
            continue;
        };
        let daemon = Arc::clone(daemon);
        let endpoint = bound.endpoint;
        thread::spawn(move || {
            let _permit = permit;
            if let Err(error) = connection::serve(stream, &daemon, endpoint, io_timeout) {
                eprintln!("runtrue-sandboxd connection: {error}");
            }
        });
    }
}

fn wait_for_connections(
    limiter: &ConnectionLimiter,
    timeout: Duration,
) -> Result<(), SandboxError> {
    let deadline = Instant::now() + timeout;
    while !limiter.is_idle() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if limiter.is_idle() {
        Ok(())
    } else {
        Err(SandboxError::Runtime(
            "connections remained active after shutdown deadline".to_owned(),
        ))
    }
}

fn print_ready(endpoints: &[BoundEndpoint], daemon: &DaemonState) {
    println!(
        "{}",
        serde_json::json!({
            "ready": true,
            "operator_socket": endpoints[0].path,
            "workload_socket": endpoints.get(1).map(|endpoint| &endpoint.path),
            "recovered_projects": daemon.counters.lock().expect("counter lock").recovered_projects,
            "worker": daemon.worker.status(),
        })
    );
}
