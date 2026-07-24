use super::{admission::admit_topology, metrics, reservation::ProjectReservation};
use crate::{
    assignment::AssignmentState,
    authorization::{AccessContext, SandboxKey},
    protocol::Operation,
    state::DaemonState,
};
use runtrue_sandbox_core::{BackendCapabilities, BackendKind, RestoreTarget, SandboxId};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{SandboxError, TopologyLock};
use serde::Serialize;
use serde_json::Value;
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

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
        Operation::Ping => Ok(capabilities(daemon)),
        Operation::Ready => readiness(daemon, context),
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
        Operation::PublishArtifact { source, digest } => {
            publish_artifact(daemon, context, &source, &digest)
        }
        Operation::GarbageCollectArtifacts {
            minimum_age_seconds,
        } => garbage_collect_artifacts(daemon, context, minimum_age_seconds),
        Operation::Shutdown => shutdown(daemon, context),
    }
}

fn readiness(daemon: &DaemonState, context: &AccessContext) -> Result<Value, SandboxError> {
    if !context.is_operator() {
        return Err(SandboxError::Runtime(
            "worker readiness is restricted to the operator endpoint".to_owned(),
        ));
    }
    let status = daemon.worker.status();
    if !status.ready() {
        return Err(SandboxError::Runtime(format!(
            "worker is not ready: state is {:?}",
            status.state()
        )));
    }
    serde_json::to_value(status)
        .map_err(|error| SandboxError::Runtime(format!("encode worker readiness: {error}")))
}

fn capabilities(daemon: &DaemonState) -> Value {
    serde_json::json!({
        "status": "ready",
        "worker": daemon.worker.status(),
        "protocol_versions": [1, 2],
        "workload_protocol_version": 2,
        "backends": [
            {
                "kind": BackendKind::Gvisor,
                "status": "available",
                "capabilities": BackendCapabilities::gvisor_snapshot(
                    64,
                    crate::server::MAXIMUM_WRITABLE_ROOT_BYTES,
                    daemon.artifact_store.snapshot_portability(),
                    daemon.guest_profiles.clone(),
                ),
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
            "rootfs_entries": image.rootfs_entries(),
            "rootfs_bytes": image.rootfs_bytes(),
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
    daemon.worker.lease(&key)?;
    let epoch = match daemon.assignments.begin(&key, context.assignment_epoch()) {
        Ok(epoch) => epoch,
        Err(error) => return Err(quarantine_after_failure(daemon, &key, error)),
    };
    let runtime_project = key.runtime_project(epoch);
    let admitted = match admit_topology(daemon, &topology) {
        Ok(admitted) => admitted,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    if let Err(error) = daemon.worker.mark_running(&key) {
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    let result = executor::run_admitted(
        &topology,
        &runtime_project,
        wait_for,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.runsc,
        &daemon.ip,
        &daemon.nft,
        &admitted,
        std::sync::Arc::clone(&daemon.image_provider),
        &key.scope.volume_scope(),
        std::sync::Arc::clone(&daemon.volume_provider),
        daemon.executor,
    );
    match result {
        Ok(result) => {
            if let Err(error) = finish_terminal_assignment(daemon, &key, epoch) {
                return Err(quarantine_after_failure(daemon, &key, error));
            }
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
    daemon.worker.lease(&key)?;
    let epoch = match daemon.assignments.begin(&key, context.assignment_epoch()) {
        Ok(epoch) => epoch,
        Err(error) => return Err(quarantine_after_failure(daemon, &key, error)),
    };
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
        &daemon.nft,
        &admitted,
        std::sync::Arc::clone(&daemon.image_provider),
        &key.scope.volume_scope(),
        std::sync::Arc::clone(&daemon.volume_provider),
        daemon.executor,
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
    if let Err(error) = instance.activate_ingress() {
        drop(instance);
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    if let Err(error) = daemon.worker.mark_running(&key) {
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
    daemon.worker.lease(&key)?;
    let epoch =
        match daemon
            .assignments
            .begin_restore(&key, context.assignment_epoch(), &snapshot_id)
        {
            Ok(epoch) => epoch,
            Err(error) => return Err(quarantine_after_failure(daemon, &key, error)),
        };
    let admitted = match admit_topology(daemon, &topology) {
        Ok(admitted) => admitted,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    let runtime_project = key.runtime_project(epoch);
    let restore_target = RestoreTarget {
        tenant_id: key.scope.tenant_id.clone(),
        workspace_id: key.scope.workspace_id.clone(),
        sandbox_id: key.sandbox_id.clone(),
        worker_id: daemon.worker_id.clone(),
        assignment_epoch: epoch,
        artifact_portability: daemon.artifact_store.snapshot_portability(),
        guest_profile: topology.policy.guest_profile.clone(),
    };
    let instance = match executor::restore_admitted(
        &topology,
        &runtime_project,
        Duration::from_millis(timeout_ms),
        &daemon.state_root,
        &daemon.snapshot_staging_root,
        daemon.artifact_store.as_ref(),
        &context.scope().artifact_scope(),
        &snapshot_id,
        &restore_target,
        &daemon.runsc,
        &daemon.ip,
        &daemon.nft,
        &admitted,
        std::sync::Arc::clone(&daemon.image_provider),
        &key.scope.volume_scope(),
        std::sync::Arc::clone(&daemon.volume_provider),
        daemon.executor,
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
    if let Err(error) = instance.activate_ingress() {
        drop(instance);
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    if let Err(error) = daemon.worker.mark_running(&key) {
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
    let instance = daemon
        .sandboxes
        .lock()
        .expect("sandbox lock")
        .get(&key)
        .cloned()
        .ok_or_else(|| SandboxError::Runtime(format!("sandbox `{sandbox}` does not exist")))?;
    let mut instance = instance.lock().expect("sandbox instance lock");
    daemon.assignments.require_current(&key, Some(epoch))?;
    daemon.worker.begin_draining(&key)?;
    let status = match instance.stop() {
        Ok(status) => status,
        Err(error) => return Err(mark_failed(daemon, &key, epoch, error)),
    };
    if let Err(error) = daemon
        .assignments
        .mark(&key, epoch, AssignmentState::Stopped)
    {
        return Err(mark_failed(daemon, &key, epoch, error));
    }
    drop(instance);
    daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
    if let Err(error) = complete_worker_cleanup(daemon, &key) {
        return Err(quarantine_after_failure(daemon, &key, error));
    }
    scoped_value(status, &key, context.is_operator())
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
    let stop_and_move = mode == runtrue_sandbox_core::SnapshotMode::StopAndMove;
    let mut instance = instance.lock().expect("sandbox instance lock");
    daemon.assignments.require_current(&key, Some(epoch))?;
    let mut source_fence_millis = 0;
    if stop_and_move {
        let fence_started = Instant::now();
        daemon.worker.begin_draining(&key)?;
        if let Err(error) = instance.fence_ingress() {
            daemon.worker.cancel_draining(&key)?;
            return Err(error);
        }
        if let Err(error) = daemon.assignments.begin_fencing(&key, epoch, &snapshot_id) {
            instance.activate_ingress()?;
            daemon.worker.cancel_draining(&key)?;
            return Err(error);
        }
        source_fence_millis = fence_started.elapsed().as_millis();
    }
    let result = instance.snapshot(
        snapshot_id.clone(),
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
    );
    let summary = match result {
        Ok(summary) => summary,
        Err(error) if stop_and_move && instance.is_executable() => {
            daemon
                .assignments
                .mark(&key, epoch, AssignmentState::Active)?;
            instance.activate_ingress()?;
            daemon.worker.cancel_draining(&key)?;
            return Err(error);
        }
        Err(error) if stop_and_move => {
            drop(instance);
            daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
            return Err(mark_failed(daemon, &key, epoch, error));
        }
        Err(error) => return Err(error),
    };
    drop(instance);
    let mut transfer_grant_millis = 0;
    if stop_and_move {
        let grant_started = Instant::now();
        if let Err(error) = daemon
            .artifact_store
            .publish_transfer_grant(&key.scope.artifact_scope(), &snapshot_id)
        {
            daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
            return Err(mark_failed(
                daemon,
                &key,
                epoch,
                SandboxError::Runtime(format!("publish snapshot transfer grant: {error}")),
            ));
        }
        transfer_grant_millis = grant_started.elapsed().as_millis();
        let assignment_result = daemon
            .assignments
            .mark_transferable(&key, epoch, &snapshot_id);
        daemon.sandboxes.lock().expect("sandbox lock").remove(&key);
        if let Err(error) = assignment_result {
            return Err(mark_failed(daemon, &key, epoch, error));
        }
        if let Err(error) = complete_worker_cleanup(daemon, &key) {
            return Err(quarantine_after_failure(daemon, &key, error));
        }
    }
    let mut value = serde_json::to_value(summary)
        .map_err(|error| SandboxError::Runtime(format!("encode snapshot result: {error}")))?;
    value["source_sandbox"] = Value::String(key.sandbox_id.as_str().to_owned());
    if stop_and_move {
        value["source_fence_millis"] = serde_json::to_value(source_fence_millis)
            .map_err(|error| SandboxError::Runtime(format!("encode fence metrics: {error}")))?;
        value["transfer_grant_millis"] = serde_json::to_value(transfer_grant_millis)
            .map_err(|error| SandboxError::Runtime(format!("encode grant metrics: {error}")))?;
    }
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
    let epoch = daemon
        .assignments
        .require_current(&key, context.assignment_epoch())?;
    with_key(daemon, &key, epoch, context.is_operator(), operation)
}

fn with_key<F, T>(
    daemon: &DaemonState,
    key: &SandboxKey,
    expected_epoch: runtrue_sandbox_core::AssignmentEpoch,
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
    daemon
        .assignments
        .require_current(key, Some(expected_epoch))?;
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

fn finish_terminal_assignment(
    daemon: &DaemonState,
    key: &SandboxKey,
    epoch: runtrue_sandbox_core::AssignmentEpoch,
) -> Result<(), SandboxError> {
    daemon.worker.begin_draining(key)?;
    daemon
        .assignments
        .mark(key, epoch, AssignmentState::Stopped)?;
    complete_worker_cleanup(daemon, key)
}

fn complete_worker_cleanup(daemon: &DaemonState, key: &SandboxKey) -> Result<(), SandboxError> {
    daemon.worker.begin_cleaning(key)?;
    daemon.worker.recycle_clean(key)?;
    daemon.shutdown.store(true, Ordering::Release);
    Ok(())
}

fn quarantine_after_failure(
    daemon: &DaemonState,
    key: &SandboxKey,
    error: SandboxError,
) -> SandboxError {
    daemon.shutdown.store(true, Ordering::Release);
    match daemon
        .worker
        .quarantine(Some(key), "sandbox-operation-failed")
    {
        Ok(()) => error,
        Err(quarantine_error) => SandboxError::Runtime(format!(
            "sandbox operation failed: {error}; worker quarantine failed: {quarantine_error}"
        )),
    }
}

fn mark_failed(
    daemon: &DaemonState,
    key: &SandboxKey,
    epoch: runtrue_sandbox_core::AssignmentEpoch,
    error: SandboxError,
) -> SandboxError {
    let error = match daemon.assignments.mark(key, epoch, AssignmentState::Failed) {
        Ok(()) => error,
        Err(journal_error) => SandboxError::Runtime(format!(
            "sandbox operation failed: {error}; assignment journal failed: {journal_error}"
        )),
    };
    quarantine_after_failure(daemon, key, error)
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

fn publish_artifact(
    daemon: &DaemonState,
    context: &AccessContext,
    source: &std::path::Path,
    digest: &str,
) -> Result<Value, SandboxError> {
    if !context.is_operator() {
        return Err(SandboxError::Runtime(
            "artifact publication is restricted to the operator endpoint".to_owned(),
        ));
    }
    let publication = daemon
        .artifact_volume_store
        .publish_artifact(source, digest)
        .map_err(|error| SandboxError::Runtime(format!("publish artifact volume: {error}")))?;
    serde_json::to_value(publication)
        .map_err(|error| SandboxError::Runtime(format!("encode artifact publication: {error}")))
}

fn garbage_collect_artifacts(
    daemon: &DaemonState,
    context: &AccessContext,
    minimum_age_seconds: u64,
) -> Result<Value, SandboxError> {
    if !context.is_operator() {
        return Err(SandboxError::Runtime(
            "artifact garbage collection is restricted to the operator endpoint".to_owned(),
        ));
    }
    if minimum_age_seconds > 31_536_000 {
        return Err(SandboxError::Runtime(
            "artifact garbage-collection grace cannot exceed one year".to_owned(),
        ));
    }
    let report = daemon
        .artifact_volume_store
        .garbage_collect_artifacts(Duration::from_secs(minimum_age_seconds))
        .map_err(|error| {
            SandboxError::Runtime(format!("garbage collect artifact volumes: {error}"))
        })?;
    serde_json::to_value(report).map_err(|error| {
        SandboxError::Runtime(format!(
            "encode artifact garbage-collection report: {error}"
        ))
    })
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
