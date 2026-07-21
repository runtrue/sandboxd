use crate::{
    cli::{Cli, Command, ServeArgs},
    client,
    protocol::Operation,
    server,
};
use runtrue_sandbox_oci::SandboxError;

pub(crate) fn execute(cli: Cli) -> Result<(), SandboxError> {
    match cli.command {
        Command::Serve(options) => {
            let ServeArgs {
                socket,
                workload_socket,
                broker_uid,
                work_order_key,
                maximum_connections,
                io_timeout_seconds,
                worker_id,
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
                runsc,
                ip,
            } = *options;
            server::serve(server::ServerConfig {
                operator_socket: socket,
                workload_socket,
                broker_uid,
                work_order_key,
                worker_id: runtrue_sandbox_core::WorkerId::parse(worker_id)
                    .map_err(|error| SandboxError::Runtime(error.to_string()))?,
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
                runsc,
                ip,
                maximum_connections,
                io_timeout: std::time::Duration::from_secs(io_timeout_seconds),
            })
        }
        Command::Ping { socket } => client::send(&socket, Operation::Ping),
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
        Command::Shutdown { socket } => client::send(&socket, Operation::Shutdown),
    }
}

fn validate_timeout(timeout_seconds: u64) -> Result<(), SandboxError> {
    if timeout_seconds == 0 || timeout_seconds > 300 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300 seconds".to_owned(),
        ));
    }
    Ok(())
}
