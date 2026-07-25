use crate::{
    cli::{Cli, Command, ServeArgs},
    client,
    protocol::Operation,
    server,
};
use runtrue_sandbox_oci::{io_error, SandboxError};

pub(crate) fn execute(cli: Cli) -> Result<(), SandboxError> {
    match cli.command {
        Command::Serve(options) => {
            let ServeArgs {
                socket,
                workload_socket,
                broker_uid,
                broker_gid,
                work_order_key,
                maximum_connections,
                io_timeout_seconds,
                worker_id,
                worker_pod_uid_env,
                resource_shape,
                sandbox_cpu_millis,
                sandbox_memory_bytes,
                sandbox_pids,
                sandbox_ephemeral_storage_bytes,
                maximum_services,
                guest_profiles,
                artifact_master_key,
                artifact_s3_bucket,
                artifact_s3_region,
                artifact_s3_endpoint,
                artifact_s3_prefix,
                artifact_s3_virtual_hosted,
                artifact_s3_allow_http_for_local_testing,
                artifact_s3_credentials_file,
                state_root,
                image_store,
                ctr,
                mkfs_ext4,
                losetup,
                containerd_address,
                containerd_namespace,
                snapshotter,
                image_platform,
                fixed_rootfs,
                fixed_topology_lock,
                fixed_rootfs_digest,
                fixed_rootfs_entries,
                fixed_rootfs_bytes,
                image_attestation,
                image_attestation_trust_policy,
                worker_artifact_digest,
                network_mode,
                cgroup_mode,
                runsc,
                ip,
                nft,
            } = *options;
            let mut installed_guest_profiles = vec![runtrue_sandbox_core::GuestProfile::strict()];
            for name in guest_profiles {
                let profile = runtrue_sandbox_core::GuestProfile::reviewed_named(&name)
                    .map_err(|error| SandboxError::Runtime(error.to_string()))?;
                if installed_guest_profiles
                    .iter()
                    .any(|installed| installed.identity == profile.identity)
                {
                    return Err(SandboxError::Runtime(format!(
                        "guest profile `{name}` was installed more than once"
                    )));
                }
                installed_guest_profiles.push(profile);
            }
            let fixed_rootfs =
                fixed_rootfs
                    .zip(fixed_topology_lock)
                    .map(|(rootfs, topology_lock)| {
                        runtrue_sandbox_oci::provider::FixedRootfsConfig {
                            rootfs,
                            topology_lock,
                            measurement: fixed_rootfs_digest
                                .zip(fixed_rootfs_entries)
                                .zip(fixed_rootfs_bytes)
                                .map(|((digest, entries), bytes)| {
                                    runtrue_sandbox_oci::provider::FixedRootfsMeasurement {
                                        digest,
                                        entries,
                                        bytes,
                                    }
                                }),
                        }
                    });
            let executor = runtrue_sandbox_gvisor::executor::ExecutorConfiguration {
                network_mode: match network_mode {
                    crate::cli::NetworkMode::Private => {
                        runtrue_sandbox_gvisor::executor::NetworkMode::Private
                    }
                    crate::cli::NetworkMode::Loopback => {
                        runtrue_sandbox_gvisor::executor::NetworkMode::Loopback
                    }
                    crate::cli::NetworkMode::Userspace => {
                        runtrue_sandbox_gvisor::executor::NetworkMode::Userspace
                    }
                },
                cgroup_mode: match cgroup_mode {
                    crate::cli::CgroupMode::Managed => {
                        runtrue_sandbox_gvisor::executor::CgroupMode::Managed
                    }
                    crate::cli::CgroupMode::External => {
                        runtrue_sandbox_gvisor::executor::CgroupMode::External
                    }
                },
            };
            let worker_id = worker_pod_uid_env
                .as_deref()
                .map(worker_id_from_pod_uid_environment)
                .transpose()?
                .unwrap_or(worker_id);
            match server::serve(server::ServerConfig {
                operator_socket: socket,
                workload_socket,
                broker_uid,
                broker_gid,
                work_order_key,
                worker_id: runtrue_sandbox_core::WorkerId::parse(worker_id)
                    .map_err(|error| SandboxError::Runtime(error.to_string()))?,
                resource_shape: runtrue_sandbox_core::WorkerResourceShape {
                    schema_version: runtrue_sandbox_core::WORKER_RESOURCE_SHAPE_VERSION,
                    name: resource_shape,
                    sandbox_cpu_millis,
                    sandbox_memory_bytes,
                    sandbox_pids,
                    sandbox_ephemeral_storage_bytes,
                    maximum_services,
                },
                guest_profiles: installed_guest_profiles,
                artifact_master_key,
                artifact_s3_bucket,
                artifact_s3_region,
                artifact_s3_endpoint,
                artifact_s3_prefix,
                artifact_s3_virtual_hosted,
                artifact_s3_allow_http_for_local_testing,
                artifact_s3_credentials_file,
                state_root,
                image_store,
                ctr,
                mkfs_ext4,
                losetup,
                containerd_address,
                containerd_namespace,
                snapshotter,
                image_platform,
                fixed_rootfs,
                image_attestation,
                image_attestation_trust_policy,
                worker_artifact_digest,
                executor,
                runsc,
                ip,
                nft,
                maximum_connections,
                io_timeout: std::time::Duration::from_secs(io_timeout_seconds),
            })? {
                server::ServeOutcome::Shutdown => Ok(()),
                server::ServeOutcome::Recycle => std::process::exit(75),
            }
        }
        Command::Ping { socket } => client::send(&socket, Operation::Ping),
        Command::Ready { socket } => client::send(&socket, Operation::Ready),
        Command::Stats { socket } => client::send(&socket, Operation::Stats),
        Command::Admit { socket, lock } => client::send(
            &socket,
            Operation::Admit {
                topology: client::read_topology(&lock)?,
            },
        ),
        Command::Run {
            socket,
            lock,
            project,
            wait_for,
            timeout_seconds,
        } => {
            if timeout_seconds == 0 || timeout_seconds > 300 {
                return Err(SandboxError::Lock(
                    "timeout must be between 1 and 300 seconds".to_owned(),
                ));
            }
            client::send(
                &socket,
                Operation::Run {
                    topology: client::read_topology(&lock)?,
                    project,
                    wait_for,
                    timeout_ms: timeout_seconds * 1_000,
                },
            )
        }
        Command::Create {
            socket,
            lock,
            sandbox,
            timeout_seconds,
        } => {
            validate_timeout(timeout_seconds)?;
            client::send(
                &socket,
                Operation::Create {
                    topology: client::read_topology(&lock)?,
                    sandbox,
                    timeout_ms: timeout_seconds * 1_000,
                },
            )
        }
        Command::Restore {
            socket,
            lock,
            sandbox,
            snapshot,
            timeout_seconds,
        } => {
            validate_timeout(timeout_seconds)?;
            client::send(
                &socket,
                Operation::Restore {
                    topology: client::read_topology(&lock)?,
                    sandbox,
                    snapshot,
                    timeout_ms: timeout_seconds * 1_000,
                    fenced_source_epoch: None,
                },
            )
        }
        Command::Inspect { socket, sandbox } => {
            client::send(&socket, Operation::Inspect { sandbox })
        }
        Command::Pause { socket, sandbox } => client::send(&socket, Operation::Pause { sandbox }),
        Command::Resume { socket, sandbox } => client::send(&socket, Operation::Resume { sandbox }),
        Command::Stop { socket, sandbox } => client::send(&socket, Operation::Stop { sandbox }),
        Command::Logs {
            socket,
            sandbox,
            container,
        } => client::send(&socket, Operation::Logs { sandbox, container }),
        Command::Snapshot {
            socket,
            sandbox,
            snapshot,
            stop_after,
        } => client::send(
            &socket,
            Operation::Snapshot {
                sandbox,
                snapshot,
                mode: if stop_after {
                    runtrue_sandbox_core::SnapshotMode::StopAndMove
                } else {
                    runtrue_sandbox_core::SnapshotMode::Live
                },
            },
        ),
        Command::PublishArtifact {
            socket,
            source,
            digest,
        } => {
            let source =
                std::fs::canonicalize(&source).map_err(|error| io_error(&source, error))?;
            client::send(&socket, Operation::PublishArtifact { source, digest })
        }
        Command::GarbageCollectArtifacts {
            socket,
            minimum_age_seconds,
        } => client::send(
            &socket,
            Operation::GarbageCollectArtifacts {
                minimum_age_seconds,
            },
        ),
        Command::Shutdown { socket } => client::send(&socket, Operation::Shutdown),
    }
}

fn worker_id_from_pod_uid_environment(name: &str) -> Result<String, SandboxError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(SandboxError::Runtime(
            "Pod UID environment variable name is invalid".to_owned(),
        ));
    }
    let uid = std::env::var(name)
        .map_err(|_| SandboxError::Runtime("Pod UID environment variable is unset".to_owned()))?;
    if uid.is_empty()
        || uid.len() > 48
        || !uid
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(SandboxError::Runtime(
            "Pod UID environment variable is invalid".to_owned(),
        ));
    }
    Ok(format!("worker-{uid}"))
}

fn validate_timeout(timeout_seconds: u64) -> Result<(), SandboxError> {
    if timeout_seconds == 0 || timeout_seconds > 300 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300 seconds".to_owned(),
        ));
    }
    Ok(())
}
