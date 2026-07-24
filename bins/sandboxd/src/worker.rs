use crate::authorization::SandboxKey;
use runtrue_sandbox_core::{WorkerResourceShape, WorkerState};
use runtrue_sandbox_oci::{io_error, SandboxError};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

const TERMINAL_MARKER: &str = "worker-terminal.json";
const TERMINAL_MARKER_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WorkerStatus {
    state: WorkerState,
    generation: u64,
    ready: bool,
    recycle_required: bool,
    resource_shape: WorkerResourceShape,
}

impl WorkerStatus {
    pub(crate) const fn state(&self) -> WorkerState {
        self.state
    }

    pub(crate) const fn ready(&self) -> bool {
        self.ready
    }
}

#[derive(Debug)]
struct SlotState {
    state: WorkerState,
    generation: u64,
    assignment: Option<SandboxKey>,
    recycle_required: bool,
}

pub(crate) struct WorkerSlot {
    marker: PathBuf,
    shape: WorkerResourceShape,
    state: Mutex<SlotState>,
}

#[derive(Serialize)]
struct TerminalMarker<'a> {
    schema_version: u32,
    state: WorkerState,
    reason: &'a str,
}

impl WorkerSlot {
    pub(crate) fn open(
        control_root: &Path,
        shape: WorkerResourceShape,
    ) -> Result<Option<Self>, SandboxError> {
        shape
            .validate()
            .map_err(|error| SandboxError::Runtime(error.to_string()))?;
        let marker = control_root.join(TERMINAL_MARKER);
        match fs::symlink_metadata(&marker) {
            Ok(_) => return Ok(None),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&marker, source)),
        }
        Ok(Some(Self {
            marker,
            shape,
            state: Mutex::new(SlotState {
                state: WorkerState::Starting,
                generation: 0,
                assignment: None,
                recycle_required: false,
            }),
        }))
    }

    pub(crate) fn mark_clean(&self) -> Result<(), SandboxError> {
        self.transition(None, WorkerState::Starting, WorkerState::Clean)
    }

    pub(crate) fn lease(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        let mut state = self.state.lock().expect("worker slot lock");
        if state.state != WorkerState::Clean || state.assignment.is_some() {
            return Err(SandboxError::Runtime(format!(
                "worker slot is not available: state is {:?}",
                state.state
            )));
        }
        state.assignment = Some(key.clone());
        set_state(&mut state, WorkerState::Leased)?;
        Ok(())
    }

    pub(crate) fn mark_running(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        self.transition(Some(key), WorkerState::Leased, WorkerState::Running)
    }

    pub(crate) fn begin_draining(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        self.transition(Some(key), WorkerState::Running, WorkerState::Draining)
    }

    pub(crate) fn begin_cleaning(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        self.transition(Some(key), WorkerState::Draining, WorkerState::Cleaning)
    }

    pub(crate) fn cancel_draining(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        self.transition(Some(key), WorkerState::Draining, WorkerState::Running)
    }

    pub(crate) fn recycle_clean(&self, key: &SandboxKey) -> Result<(), SandboxError> {
        let mut state = self.state.lock().expect("worker slot lock");
        require_assignment(&state, key)?;
        if state.state != WorkerState::Cleaning {
            return Err(invalid_transition(state.state, WorkerState::Cleaning));
        }
        self.persist_terminal(WorkerState::Cleaning, "single-use-assignment-complete")?;
        state.recycle_required = true;
        Ok(())
    }

    pub(crate) fn quarantine(
        &self,
        key: Option<&SandboxKey>,
        reason: &'static str,
    ) -> Result<(), SandboxError> {
        let mut state = self.state.lock().expect("worker slot lock");
        if let Some(key) = key {
            require_assignment(&state, key)?;
        }
        if state.state == WorkerState::Quarantined {
            state.recycle_required = true;
            return Ok(());
        }
        set_state(&mut state, WorkerState::Quarantined)?;
        self.persist_terminal(WorkerState::Quarantined, reason)?;
        state.recycle_required = true;
        Ok(())
    }

    pub(crate) fn status(&self) -> WorkerStatus {
        let state = self.state.lock().expect("worker slot lock");
        WorkerStatus {
            state: state.state,
            generation: state.generation,
            ready: state.state.is_ready(),
            recycle_required: state.recycle_required,
            resource_shape: self.shape.clone(),
        }
    }

    pub(crate) fn resource_shape(&self) -> &WorkerResourceShape {
        &self.shape
    }

    pub(crate) fn recycle_required(&self) -> bool {
        self.state
            .lock()
            .expect("worker slot lock")
            .recycle_required
    }

    fn transition(
        &self,
        key: Option<&SandboxKey>,
        expected: WorkerState,
        next: WorkerState,
    ) -> Result<(), SandboxError> {
        let mut state = self.state.lock().expect("worker slot lock");
        if let Some(key) = key {
            require_assignment(&state, key)?;
        }
        if state.state != expected {
            return Err(invalid_transition(state.state, next));
        }
        set_state(&mut state, next)
    }

    fn persist_terminal(
        &self,
        state: WorkerState,
        reason: &'static str,
    ) -> Result<(), SandboxError> {
        match fs::symlink_metadata(&self.marker) {
            Ok(_) => return Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&self.marker, source)),
        }
        let parent = self.marker.parent().ok_or_else(|| {
            SandboxError::Runtime("worker marker has no parent directory".to_owned())
        })?;
        let temporary = parent.join(format!(".worker-terminal-{}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|source| io_error(&temporary, source))?;
            let mut bytes = serde_json::to_vec(&TerminalMarker {
                schema_version: TERMINAL_MARKER_SCHEMA_VERSION,
                state,
                reason,
            })
            .map_err(|error| {
                SandboxError::Runtime(format!("encode worker terminal marker: {error}"))
            })?;
            bytes.push(b'\n');
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| io_error(&temporary, source))?;
            fs::rename(&temporary, &self.marker)
                .map_err(|source| io_error(&self.marker, source))?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error(parent, source))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn require_assignment(state: &SlotState, key: &SandboxKey) -> Result<(), SandboxError> {
    if state.assignment.as_ref() == Some(key) {
        Ok(())
    } else {
        Err(SandboxError::Runtime(
            "worker slot assignment does not match the request".to_owned(),
        ))
    }
}

fn set_state(state: &mut SlotState, next: WorkerState) -> Result<(), SandboxError> {
    state.generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| SandboxError::Runtime("worker state generation overflow".to_owned()))?;
    state.state = next;
    Ok(())
}

fn invalid_transition(from: WorkerState, to: WorkerState) -> SandboxError {
    SandboxError::Runtime(format!("invalid worker transition from {from:?} to {to:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::TenantScope;
    use runtrue_sandbox_core::{SandboxId, TenantId, WorkspaceId, WORKER_RESOURCE_SHAPE_VERSION};

    fn shape() -> WorkerResourceShape {
        WorkerResourceShape {
            schema_version: WORKER_RESOURCE_SHAPE_VERSION,
            name: "standard-v1".to_owned(),
            sandbox_cpu_millis: 1_000,
            sandbox_memory_bytes: 1024 * 1024 * 1024,
            sandbox_pids: 256,
            sandbox_ephemeral_storage_bytes: 2 * 1024 * 1024 * 1024,
            maximum_services: 8,
        }
    }

    fn key(tenant: &str) -> SandboxKey {
        SandboxKey {
            scope: TenantScope {
                tenant_id: TenantId::parse(tenant).expect("tenant"),
                workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            },
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox"),
        }
    }

    #[test]
    fn one_assignment_reaches_terminal_recycle_and_cannot_be_reopened() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let worker = WorkerSlot::open(directory.path(), shape())
            .expect("worker")
            .expect("clean pod");
        worker.mark_clean().expect("clean");
        worker.lease(&key("tenant-a")).expect("lease");
        assert!(worker.lease(&key("tenant-b")).is_err());
        worker.mark_running(&key("tenant-a")).expect("running");
        worker.begin_draining(&key("tenant-a")).expect("draining");
        worker.begin_cleaning(&key("tenant-a")).expect("cleaning");
        worker
            .recycle_clean(&key("tenant-a"))
            .expect("terminal marker");
        assert!(worker.recycle_required());
        assert!(WorkerSlot::open(directory.path(), shape())
            .expect("marker check")
            .is_none());
    }

    #[test]
    fn failure_quarantines_and_persists_fail_closed_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let worker = WorkerSlot::open(directory.path(), shape())
            .expect("worker")
            .expect("clean pod");
        worker.mark_clean().expect("clean");
        worker.lease(&key("tenant-a")).expect("lease");
        worker
            .quarantine(Some(&key("tenant-a")), "injected-failure")
            .expect("quarantine");
        let status = worker.status();
        assert_eq!(status.state, WorkerState::Quarantined);
        assert!(status.recycle_required);
        assert!(WorkerSlot::open(directory.path(), shape())
            .expect("marker check")
            .is_none());
    }
}
