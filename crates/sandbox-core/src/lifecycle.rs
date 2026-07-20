use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Pending,
    Provisioning,
    Restoring,
    Running,
    Pausing,
    Paused,
    Resuming,
    Snapshotting,
    Stopping,
    Stopped,
    Failed,
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", format!("{self:?}").to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    state: LifecycleState,
    generation: u64,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Pending,
            generation: 0,
        }
    }
}

impl Lifecycle {
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn transition(&mut self, next: LifecycleState) -> Result<(), CoreError> {
        if !allowed(self.state, next) {
            return Err(CoreError::InvalidLifecycleTransition {
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }
        self.state = next;
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            CoreError::InvalidSpecification("lifecycle generation overflow".to_owned())
        })?;
        Ok(())
    }
}

const fn allowed(from: LifecycleState, to: LifecycleState) -> bool {
    use LifecycleState::{
        Failed, Paused, Pausing, Pending, Provisioning, Restoring, Resuming, Running, Snapshotting,
        Stopped, Stopping,
    };
    matches!(
        (from, to),
        (Pending, Provisioning | Restoring | Stopping | Failed)
            | (
                Provisioning | Restoring | Resuming,
                Running | Stopping | Failed
            )
            | (Running, Pausing | Snapshotting | Stopping | Failed)
            | (Pausing, Paused | Running | Stopping | Failed)
            | (Paused, Resuming | Snapshotting | Stopping | Failed)
            | (Snapshotting, Running | Paused | Stopping | Failed)
            | (Stopping | Failed, Stopped)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_create_pause_resume_snapshot_and_stop() {
        let mut lifecycle = Lifecycle::default();
        for state in [
            LifecycleState::Provisioning,
            LifecycleState::Running,
            LifecycleState::Pausing,
            LifecycleState::Paused,
            LifecycleState::Snapshotting,
            LifecycleState::Paused,
            LifecycleState::Resuming,
            LifecycleState::Running,
            LifecycleState::Stopping,
            LifecycleState::Stopped,
        ] {
            lifecycle.transition(state).expect("transition is valid");
        }
        assert_eq!(lifecycle.state(), LifecycleState::Stopped);
        assert_eq!(lifecycle.generation(), 10);
    }

    #[test]
    fn rejects_resume_without_pause_and_reuse_after_stop() {
        let mut lifecycle = Lifecycle::default();
        assert!(lifecycle.transition(LifecycleState::Resuming).is_err());
        lifecycle
            .transition(LifecycleState::Stopping)
            .expect("pending sandbox can be cancelled");
        lifecycle
            .transition(LifecycleState::Stopped)
            .expect("stopping completes");
        assert!(lifecycle.transition(LifecycleState::Provisioning).is_err());
    }
}
