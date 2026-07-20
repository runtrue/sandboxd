use super::{admission::admit_topology, metrics, reservation::ProjectReservation};
use crate::{
    protocol::{valid_request_id, Operation, Request, PROTOCOL_VERSION},
    state::DaemonState,
};
use runtrue_sandbox_core::{BackendCapabilities, BackendKind};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{SandboxError, TopologyLock};
use serde_json::Value;
use std::{sync::atomic::Ordering, time::Duration};

pub(crate) fn handle(request: Request, daemon: &DaemonState) -> Result<Value, SandboxError> {
    if request.schema_version != PROTOCOL_VERSION || !valid_request_id(&request.request_id) {
        return Err(SandboxError::Runtime(
            "invalid protocol version or request identifier".to_owned(),
        ));
    }
    daemon.counters.lock().expect("counter lock").requests += 1;
    match request.operation {
        Operation::Ping => Ok(capabilities()),
        Operation::Stats => metrics::collect(daemon),
        Operation::Admit { topology } => admit(daemon, &topology),
        Operation::Run {
            topology,
            project,
            wait_for,
            timeout_ms,
        } => run(daemon, topology, project, wait_for, timeout_ms),
        Operation::Create {
            topology,
            sandbox,
            timeout_ms,
        } => create(daemon, topology, sandbox, timeout_ms),
        Operation::Restore {
            topology,
            sandbox,
            snapshot,
            timeout_ms,
        } => restore(daemon, topology, sandbox, &snapshot, timeout_ms),
        Operation::Inspect { sandbox } => inspect(daemon, &sandbox),
        Operation::Pause { sandbox } => pause(daemon, &sandbox),
        Operation::Resume { sandbox } => resume(daemon, &sandbox),
        Operation::Stop { sandbox } => stop(daemon, &sandbox),
        Operation::Logs { sandbox, container } => logs(daemon, &sandbox, &container),
        Operation::Snapshot {
            sandbox,
            snapshot: snapshot_id,
            mode,
        } => snapshot(daemon, &sandbox, &snapshot_id, mode),
        Operation::Shutdown => shutdown(daemon),
    }
}

fn capabilities() -> Value {
    serde_json::json!({
        "status": "ready",
        "backends": [
            {
                "kind": BackendKind::Gvisor,
                "status": "available",
                "capabilities": BackendCapabilities::gvisor_local_snapshot(64),
            }
        ]
    })
}

fn admit(daemon: &DaemonState, topology: &TopologyLock) -> Result<Value, SandboxError> {
    let images = admit_topology(daemon, topology)?;
    Ok(serde_json::json!({
        "admitted_images": images.values().map(|image| serde_json::json!({
            "image_id": image.image_id,
            "exact_reference": image.exact_reference,
            "rootfs_digest": image.rootfs_digest,
        })).collect::<Vec<_>>()
    }))
}

fn run(
    daemon: &DaemonState,
    topology: TopologyLock,
    project: String,
    wait_for: String,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    if timeout_ms == 0 || timeout_ms > 300_000 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300000 milliseconds".to_owned(),
        ));
    }
    let _reservation = ProjectReservation::acquire(daemon, &project)?;
    let admitted = admit_topology(daemon, &topology)?;
    let result = executor::run_admitted(
        &topology,
        &project,
        &wait_for,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    );
    let mut counters = daemon.counters.lock().expect("counter lock");
    match result {
        Ok(result) => {
            counters.completed_runs += 1;
            serde_json::to_value(result).map_err(|error| {
                SandboxError::Runtime(format!("encode direct run result: {error}"))
            })
        }
        Err(error) => {
            counters.failed_runs += 1;
            Err(error)
        }
    }
}

fn create(
    daemon: &DaemonState,
    topology: TopologyLock,
    sandbox: String,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    validate_timeout(timeout_ms)?;
    if daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .contains_key(&sandbox)
    {
        return Err(SandboxError::Runtime(format!(
            "sandbox `{sandbox}` already exists"
        )));
    }
    let _reservation = ProjectReservation::acquire(daemon, &sandbox)?;
    let admitted = admit_topology(daemon, &topology)?;
    let instance = executor::start_admitted(
        &topology,
        &sandbox,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    )?;
    let status = instance.status()?;
    daemon.sandboxes.lock().expect("sandbox lock").insert(
        sandbox,
        std::sync::Arc::new(std::sync::Mutex::new(instance)),
    );
    serde_json::to_value(status)
        .map_err(|error| SandboxError::Runtime(format!("encode sandbox status: {error}")))
}

fn inspect(daemon: &DaemonState, sandbox: &str) -> Result<Value, SandboxError> {
    with_sandbox(daemon, sandbox, |instance| instance.status())
}

fn restore(
    daemon: &DaemonState,
    topology: TopologyLock,
    sandbox: String,
    snapshot: &str,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    validate_timeout(timeout_ms)?;
    let snapshot_id = runtrue_sandbox_core::SnapshotId::parse(snapshot)
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    if daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .contains_key(&sandbox)
    {
        return Err(SandboxError::Runtime(format!(
            "sandbox `{sandbox}` already exists"
        )));
    }
    let _reservation = ProjectReservation::acquire(daemon, &sandbox)?;
    let admitted = admit_topology(daemon, &topology)?;
    let instance = executor::restore_admitted(
        &topology,
        &sandbox,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.snapshot_root,
        &snapshot_id,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    )?;
    let status = instance.status()?;
    daemon.sandboxes.lock().expect("sandbox lock").insert(
        sandbox,
        std::sync::Arc::new(std::sync::Mutex::new(instance)),
    );
    serde_json::to_value(status)
        .map_err(|error| SandboxError::Runtime(format!("encode sandbox status: {error}")))
}

fn pause(daemon: &DaemonState, sandbox: &str) -> Result<Value, SandboxError> {
    with_sandbox(
        daemon,
        sandbox,
        runtrue_sandbox_gvisor::executor::GvisorSandbox::pause,
    )
}

fn resume(daemon: &DaemonState, sandbox: &str) -> Result<Value, SandboxError> {
    with_sandbox(
        daemon,
        sandbox,
        runtrue_sandbox_gvisor::executor::GvisorSandbox::resume,
    )
}

fn stop(daemon: &DaemonState, sandbox: &str) -> Result<Value, SandboxError> {
    let value = with_sandbox(
        daemon,
        sandbox,
        runtrue_sandbox_gvisor::executor::GvisorSandbox::stop,
    )?;
    daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .remove(sandbox);
    Ok(value)
}

fn logs(daemon: &DaemonState, sandbox: &str, container: &str) -> Result<Value, SandboxError> {
    with_sandbox(daemon, sandbox, |instance| {
        instance.completed_output(container)
    })
}

fn snapshot(
    daemon: &DaemonState,
    sandbox: &str,
    snapshot: &str,
    mode: runtrue_sandbox_core::SnapshotMode,
) -> Result<Value, SandboxError> {
    let snapshot_id = runtrue_sandbox_core::SnapshotId::parse(snapshot)
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    let instance = daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .get(sandbox)
        .cloned()
        .ok_or_else(|| SandboxError::Runtime(format!("sandbox `{sandbox}` does not exist")))?;
    let summary = instance.lock().expect("sandbox instance lock").snapshot(
        snapshot_id,
        &daemon.snapshot_root,
        mode,
    )?;
    if mode == runtrue_sandbox_core::SnapshotMode::StopAndMove {
        daemon
            .sandboxes
            .lock()
            .expect("sandbox lock")
            .remove(sandbox);
    }
    serde_json::to_value(summary)
        .map_err(|error| SandboxError::Runtime(format!("encode snapshot result: {error}")))
}

fn with_sandbox<F, T>(
    daemon: &DaemonState,
    sandbox: &str,
    operation: F,
) -> Result<Value, SandboxError>
where
    F: FnOnce(&mut runtrue_sandbox_gvisor::executor::GvisorSandbox) -> Result<T, SandboxError>,
    T: serde::Serialize,
{
    let instance = daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .get(sandbox)
        .cloned()
        .ok_or_else(|| SandboxError::Runtime(format!("sandbox `{sandbox}` does not exist")))?;
    let mut instance = instance.lock().expect("sandbox instance lock");
    let result = operation(&mut instance)?;
    serde_json::to_value(result)
        .map_err(|error| SandboxError::Runtime(format!("encode sandbox status: {error}")))
}

fn validate_timeout(timeout_ms: u64) -> Result<(), SandboxError> {
    if timeout_ms == 0 || timeout_ms > 300_000 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300000 milliseconds".to_owned(),
        ));
    }
    Ok(())
}

fn shutdown(daemon: &DaemonState) -> Result<Value, SandboxError> {
    let active = daemon.active.lock().expect("active lock");
    if !active.is_empty() || !daemon.sandboxes.lock().expect("sandbox lock").is_empty() {
        return Err(SandboxError::Runtime(
            "refusing graceful shutdown with active sandboxes".to_owned(),
        ));
    }
    daemon.shutdown.store(true, Ordering::Release);
    Ok(serde_json::json!({"shutdown": true}))
}
