use crate::cli::{Cli, Command};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{compiler, io_error, prepared, Docker, SandboxError, TopologyLock};
use std::{fs, time::Duration};

pub(crate) fn execute(cli: Cli) -> Result<(), SandboxError> {
    match cli.command {
        Command::Lock { compose, output } => lock(cli.docker, compose, output),
        Command::PrepareImage {
            reference,
            image_store,
            tar,
        } => prepare_image(cli.docker, reference, image_store, tar),
        Command::Run {
            lock,
            project,
            wait_for,
            timeout_seconds,
            state_root,
            image_store,
            runsc,
            ip,
        } => run(
            lock,
            project,
            wait_for,
            timeout_seconds,
            state_root,
            image_store,
            runsc,
            ip,
        ),
    }
}

fn lock(
    docker_path: std::path::PathBuf,
    compose: std::path::PathBuf,
    output: std::path::PathBuf,
) -> Result<(), SandboxError> {
    let docker = Docker::new(docker_path)?;
    let lock = compiler::lock_compose(&compose, &docker)?;
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

fn prepare_image(
    docker_path: std::path::PathBuf,
    reference: String,
    image_store: std::path::PathBuf,
    tar: std::path::PathBuf,
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
    lock: std::path::PathBuf,
    project: String,
    wait_for: String,
    timeout_seconds: u64,
    state_root: std::path::PathBuf,
    image_store: std::path::PathBuf,
    runsc: std::path::PathBuf,
    ip: std::path::PathBuf,
) -> Result<(), SandboxError> {
    if timeout_seconds == 0 || timeout_seconds > 300 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300 seconds".to_owned(),
        ));
    }
    let bytes = fs::read(&lock).map_err(|source| io_error(&lock, source))?;
    let topology: TopologyLock = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode topology lock: {error}")))?;
    let result = executor::run(
        &topology,
        &project,
        &wait_for,
        Duration::from_secs(timeout_seconds),
        &state_root,
        &image_store,
        &runsc,
        &ip,
    )?;
    println!(
        "{}",
        serde_json::to_string(&result)
            .map_err(|error| SandboxError::Lock(format!("encode run result: {error}")))?
    );
    Ok(())
}
