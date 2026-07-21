use super::{admission::admit_topology, metrics, reservation::ProjectReservation};
use crate::{
    assignment::AssignmentState,
    authorization::{AccessContext, SandboxKey},
    protocol::Operation,
    state::DaemonState,
};
use runtrue_sandbox_core::{BackendCapabilities, BackendKind, SandboxId};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{SandboxError, TopologyLock};
use serde::Serialize;
use serde_json::Value;
use std::{sync::atomic::Ordering, time::Duration};

pub(crate) fn handle(
    operation: Operation,
    context: &AccessContext,
    daemon: &DaemonState,
) -> Result<Value, SandboxError> {
    daemon.counters.lock().expect("counter lock").requests += 1;
    if !context.is_operator() {
        daemon
            .tenant_counters
            .lock()
            .expect("tenant counter lock")
            .entry(context.scope().clone())
            .or_default()
            .requests += 1;
    }
    match operation {
        Operation::Ping => Ok(capabilities()),
        Operation::Stats => metrics::collect(daemon, context),
        Operation::Admit { topology } => admit(daemon, &topology),
        Operation::Run {
            topology,
            project,
            wait_for,
            timeout_ms,
        } => run(daemon, context, topology, &project, &wait_for, timeout_ms),
        Operation::Create {
            topology,
            sandbox,
            timeout_ms,
        } => create(daemon, context, topology, &sandbox, timeout_ms),
        Operation::Restore {
            topology,
            sandbox,
            snapshot,
            timeout_ms,
        } => restore(daemon, context, topology, &sandbox, &snapshot, timeout_ms),
        Operation::Inspect { sandbox } => inspect(daemon, context, &sandbox),
        Operation::Pause { sandbox } => pause(daemon, context, &sandbox),
        Operation::Resume { sandbox } => resume(daemon, context, &sandbox),
        Operation::Stop { sandbox } => stop(daemon, context, &sandbox),
        Operation::Logs { sandbox, container } => logs(daemon, context, &sandbox, &container),
        Operation::Snapshot {
            sandbox,
            snapshot: snapshot_id,
            mode,
        } => snapshot(daemon, context, &sandbox, &snapshot_id, mode),
        Operation::Shutdown => shutdown(daemon, context),
    }
}

fn capabilities() -> Value {
    serde_json::json!({
        "status": "ready",
        "protocol_versions": [1, 2],
        "workload_protocol_version": 2,
        "backends": [
            {
                "kind": BackendKind::Gvisor,
                "status": "available",
                "capabilities": BackendCapabilities::gvisor_portable_snapshot(64),
            }
        ]
    })
}

fn admit(daemon: &DaemonState, topology: &TopologyLock) -> Result<Value, SandboxError> {
    let images = admit_topology(daemon, topology)?;
    Ok(serde_json::json!({
        "admitted_images": images.values().map(|image| serde_json::json!({
            "image_id": image.image().image_id,
            "exact_reference": image.image().exact_reference,
            "rootfs_digest": image.rootfs_digest(),
        })).collect::<Vec<_>>()
    }))
}

fn run(
    daemon: &DaemonState,
    context: &AccessContext,
    topology: TopologyLock,
    sandbox: &str,
    wait_for: &str,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    validate_timeout(timeout_ms)?;
    let key = sandbox_key(context, sandbox)?;
    let _reservation = ProjectReservation::acquire(daemon, &key)?;
    let epoch = daemon.assignments.begin(&key, context.assignment_epoch())?;
    let runtime_project = key.runtime_project(epoch);
    let admitted = match admit_topology(daemon, &topology) {
        Ok(admitted) => admitted,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let result = executor::run_admitted(
        &topology,
        &runtime_project,
        wait_for,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    );
    match result {
        Ok(result) => {
            daemon
                .assignments
                .mark(&key, epoch, AssignmentState::Stopped)?;
            record_run(daemon, context, true);
            scoped_value(result, &key, context.is_operator())
        }
        Err(error) => {
            record_run(daemon, context, false);
            Err(mark_failed(daemon, &key, epoch, error))
        }
    }
}

fn create(
    daemon: &DaemonState,
    context: &AccessContext,
    topology: TopologyLock,
    sandbox: &str,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    validate_timeout(timeout_ms)?;
    let key = sandbox_key(context, sandbox)?;
    if daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .contains_key(&key)
    {
        return Err(SandboxError::Runtime(format!(
            "sandbox `{sandbox}` already exists"
        )));
    }
    let _reservation = ProjectReservation::acquire(daemon, &key)?;
    let epoch = daemon.assignments.begin(&key, context.assignment_epoch())?;
    let admitted = match admit_topology(daemon, &topology) {
        Ok(admitted) => admitted,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let runtime_project = key.runtime_project(epoch);
    let instance = match executor::start_admitted(
        &topology,
        &runtime_project,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    ) {
        Ok(instance) => instance,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let status = match instance.status() {
        Ok(status) => status,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    if let Err(error) = daemon
        .assignments
        .mark(&key, epoch, AssignmentState::Active)
    {
        drop(instance);
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    daemon.sandboxes.lock().expect("sandbox lock").insert(
        key.clone(),
        std::sync::Arc::new(std::sync::Mutex::new(instance)),
    );
    scoped_value(status, &key, context.is_operator())
}

fn restore(
    daemon: &DaemonState,
    context: &AccessContext,
    topology: TopologyLock,
    sandbox: &str,
    snapshot: &str,
    timeout_ms: u64,
) -> Result<Value, SandboxError> {
    validate_timeout(timeout_ms)?;
    let snapshot_id = runtrue_sandbox_core::SnapshotId::parse(snapshot)
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    let key = sandbox_key(context, sandbox)?;
    if daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .contains_key(&key)
    {
        return Err(SandboxError::Runtime(format!(
            "sandbox `{sandbox}` already exists"
        )));
    }
    let _reservation = ProjectReservation::acquire(daemon, &key)?;
    let epoch = daemon.assignments.begin(&key, context.assignment_epoch())?;
    let admitted = match admit_topology(daemon, &topology) {
        Ok(admitted) => admitted,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let runtime_project = key.runtime_project(epoch);
    let instance = match executor::restore_admitted(
        &topology,
        &runtime_project,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.snapshot_staging_root,
        daemon.artifact_store.as_ref(),
        &context.scope().artifact_scope(),
        &snapshot_id,
        &daemon.runsc,
        &daemon.ip,
        &admitted,
    ) {
        Ok(instance) => instance,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let status = match instance.status() {
        Ok(status) => status,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    if let Err(error) = daemon
        .assignments
        .mark(&key, epoch, AssignmentState::Active)
    {
        drop(instance);
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    daemon.sandboxes.lock().expect("sandbox lock").insert(
        key.clone(),
        std::sync::Arc::new(std::sync::Mutex::new(instance)),
    );
    scoped_value(status, &key, context.is_operator())
}

fn inspect(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
) -> Result<Value, SandboxError> {
    with_sandbox(daemon, context, sandbox, |instance| instance.status())
}

fn pause(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
) -> Result<Value, SandboxError> {
    with_sandbox(daemon, context, sandbox, |instance| instance.pause())
}

fn resume(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
) -> Result<Value, SandboxError> {
    with_sandbox(daemon, context, sandbox, |instance| instance.resume())
}

fn stop(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
) -> Result<Value, SandboxError> {
    let key = sandbox_key(context, sandbox)?;
    let epoch = daemon
        .assignments
        .require_current(&key, context.assignment_epoch())?;
    let value = with_key(daemon, &key, context.is_operator(), |instance| {
        instance.stop()
    })?;
    let assignment_result = daemon
        .assignments
        .mark(&key, epoch, AssignmentState::Stopped);
    daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
    assignment_result?;
    Ok(value)
}

fn logs(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
    container: &str,
) -> Result<Value, SandboxError> {
    with_sandbox(daemon, context, sandbox, |instance| {
        instance.completed_output(container)
    })
}

fn snapshot(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
    snapshot: &str,
    mode: runtrue_sandbox_core::SnapshotMode,
) -> Result<Value, SandboxError> {
    let snapshot_id = runtrue_sandbox_core::SnapshotId::parse(snapshot)
        .map_err(|error| SandboxError::Runtime(error.to_string()))?;
    let key = sandbox_key(context, sandbox)?;
    let epoch = daemon
        .assignments
        .require_current(&key, context.assignment_epoch())?;
    let instance = daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .get(&key)
        .cloned()
        .ok_or_else(|| SandboxError::Runtime(format!("sandbox `{sandbox}` does not exist")))?;
    let summary = instance.lock().expect("sandbox instance lock").snapshot(
        snapshot_id,
        &daemon.snapshot_staging_root,
        mode,
        daemon.artifact_store.as_ref(),
        &runtrue_sandbox_gvisor::snapshot::SnapshotProvenance {
            tenant_id: key.scope.tenant_id.clone(),
            workspace_id: key.scope.workspace_id.clone(),
            sandbox_id: key.sandbox_id.clone(),
            source_worker: daemon.worker_id.clone(),
            source_assignment_epoch: epoch,
        },
    )?;
    if mode == runtrue_sandbox_core::SnapshotMode::StopAndMove {
        let assignment_result = daemon
            .assignments
            .mark(&key, epoch, AssignmentState::Stopped);
        daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
        assignment_result?;
    }
    let mut value = serde_json::to_value(summary)
        .map_err(|error| SandboxError::Runtime(format!("encode snapshot result: {error}")))?;
    value["source_sandbox"] = Value::String(key.sandbox_id.as_str().to_owned());
    Ok(value)
}

fn with_sandbox<F, T>(
    daemon: &DaemonState,
    context: &AccessContext,
    sandbox: &str,
    operation: F,
) -> Result<Value, SandboxError>
where
    F: FnOnce(&mut runtrue_sandbox_gvisor::executor::GvisorSandbox) -> Result<T, SandboxError>,
    T: Serialize,
{
    let key = sandbox_key(context, sandbox)?;
    daemon
        .assignments
        .require_current(&key, context.assignment_epoch())?;
    with_key(daemon, &key, context.is_operator(), operation)
}

fn with_key<F, T>(
    daemon: &DaemonState,
    key: &SandboxKey,
    operator: bool,
    operation: F,
) -> Result<Value, SandboxError>
where
    F: FnOnce(&mut runtrue_sandbox_gvisor::executor::GvisorSandbox) -> Result<T, SandboxError>,
    T: Serialize,
{
    let instance = daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .get(key)
        .cloned()
        .ok_or_else(|| {
            SandboxError::Runtime(format!("sandbox `{}` does not exist", key.sandbox_id))
        })?;
    let mut instance = instance.lock().expect("sandbox instance lock");
    let result = operation(&mut instance)?;
    scoped_value(result, key, operator)
}

fn sandbox_key(context: &AccessContext, sandbox: &str) -> Result<SandboxKey, SandboxError> {
    let sandbox_id =
        SandboxId::parse(sandbox).map_err(|error| SandboxError::Runtime(error.to_string()))?;
    Ok(context.sandbox_key(sandbox_id))
}

fn scoped_value<T: Serialize>(
    value: T,
    key: &SandboxKey,
    operator: bool,
) -> Result<Value, SandboxError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| SandboxError::Runtime(format!("encode sandbox result: {error}")))?;
    if let Some(runtime_project) = value
        .get("project")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        value["project"] = Value::String(key.sandbox_id.as_str().to_owned());
        if operator {
            value["runtime_project"] = Value::String(runtime_project);
        }
    }
    Ok(value)
}

fn mark_failed(
    daemon: &DaemonState,
    key: &SandboxKey,
    epoch: runtrue_sandbox_core::AssignmentEpoch,
    error: SandboxError,
) -> SandboxError {
    match daemon.assignments.mark(key, epoch, AssignmentState::Failed) {
        Ok(()) => error,
        Err(journal_error) => SandboxError::Runtime(format!(
            "sandbox operation failed: {error}; assignment journal failed: {journal_error}"
        )),
    }
}

fn record_run(daemon: &DaemonState, context: &AccessContext, succeeded: bool) {
    let mut counters = daemon.counters.lock().expect("counter lock");
    if succeeded {
        counters.completed_runs += 1;
    } else {
        counters.failed_runs += 1;
    }
    drop(counters);
    if !context.is_operator() {
        let mut tenant_counters = daemon.tenant_counters.lock().expect("tenant counter lock");
        let counters = tenant_counters.entry(context.scope().clone()).or_default();
        if succeeded {
            counters.completed_runs += 1;
        } else {
            counters.failed_runs += 1;
        }
    }
}

fn validate_timeout(timeout_ms: u64) -> Result<(), SandboxError> {
    if timeout_ms == 0 || timeout_ms > 300_000 {
        return Err(SandboxError::Lock(
            "timeout must be between 1 and 300000 milliseconds".to_owned(),
        ));
    }
    Ok(())
}

fn shutdown(daemon: &DaemonState, context: &AccessContext) -> Result<Value, SandboxError> {
    if !context.is_operator() {
        return Err(SandboxError::Runtime(
            "shutdown is restricted to the operator endpoint".to_owned(),
        ));
    }
    let active = daemon.active.lock().expect("active lock");
    if !active.is_empty() || !daemon.sandboxes.lock().expect("sandbox lock").is_empty() {
        return Err(SandboxError::Runtime(
            "refusing graceful shutdown with active sandboxes".to_owned(),
        ));
    }
    daemon.shutdown.store(true, Ordering::Release);
    Ok(serde_json::json!({"shutdown": true}))
}
