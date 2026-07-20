use crate::state::DaemonState;
use runtrue_sandbox_oci::SandboxError;
use std::sync::atomic::Ordering;

pub(super) struct ProjectReservation<'a> {
    daemon: &'a DaemonState,
    project: String,
}

impl<'a> ProjectReservation<'a> {
    pub(super) fn acquire(daemon: &'a DaemonState, project: &str) -> Result<Self, SandboxError> {
        let mut active = daemon.active.lock().expect("active lock");
        if daemon.shutdown.load(Ordering::Acquire) {
            return Err(SandboxError::Runtime(
                "sandboxd is shutting down".to_owned(),
            ));
        }
        if !active.insert(project.to_owned()) {
            return Err(SandboxError::Runtime(format!(
                "project `{project}` already has an active sandbox"
            )));
        }
        Ok(Self {
            daemon,
            project: project.to_owned(),
        })
    }
}

impl Drop for ProjectReservation<'_> {
    fn drop(&mut self) {
        self.daemon
            .active
            .lock()
            .expect("active lock")
            .remove(&self.project);
    }
}
