use crate::{authorization::SandboxKey, state::DaemonState};
use runtrue_sandbox_oci::SandboxError;
use std::sync::atomic::Ordering;

pub(super) struct ProjectReservation<'a> {
    daemon: &'a DaemonState,
    key: SandboxKey,
}

impl<'a> ProjectReservation<'a> {
    pub(super) fn acquire(daemon: &'a DaemonState, key: &SandboxKey) -> Result<Self, SandboxError> {
        let mut active = daemon.active.lock().expect("active lock");
        if daemon.shutdown.load(Ordering::Acquire) {
            return Err(SandboxError::Runtime(
                "sandboxd is shutting down".to_owned(),
            ));
        }
        if !active.insert(key.clone()) {
            return Err(SandboxError::Runtime(format!(
                "sandbox `{}` already has an active operation",
                key.sandbox_id
            )));
        }
        Ok(Self {
            daemon,
            key: key.clone(),
        })
    }
}

impl Drop for ProjectReservation<'_> {
    fn drop(&mut self) {
        self.daemon
            .active
            .lock()
            .expect("active lock")
            .remove(&self.key);
    }
}
