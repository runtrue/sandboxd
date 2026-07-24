use crate::CoreError;
use serde::{Deserialize, Serialize};

pub const WORKER_RESOURCE_SHAPE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Starting,
    Clean,
    Leased,
    Running,
    Draining,
    Cleaning,
    Quarantined,
}

impl WorkerState {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Clean)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResourceShape {
    pub schema_version: u32,
    pub name: String,
    pub sandbox_cpu_millis: u32,
    pub sandbox_memory_bytes: u64,
    pub sandbox_pids: u32,
    pub sandbox_ephemeral_storage_bytes: u64,
    pub maximum_services: u16,
}

impl WorkerResourceShape {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != WORKER_RESOURCE_SHAPE_VERSION
            || !valid_name(&self.name)
            || self.sandbox_cpu_millis == 0
            || self.sandbox_cpu_millis > 64_000
            || self.sandbox_memory_bytes < 64 * 1024 * 1024
            || self.sandbox_memory_bytes > 1024 * 1024 * 1024 * 1024
            || self.sandbox_pids == 0
            || self.sandbox_pids > 1_048_576
            || self.sandbox_ephemeral_storage_bytes < 64 * 1024 * 1024
            || self.sandbox_ephemeral_storage_bytes > 16 * 1024 * 1024 * 1024 * 1024
            || self.maximum_services == 0
            || self.maximum_services > 64
        {
            return Err(CoreError::InvalidSpecification(
                "worker resource shape is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn require_capacity(&self, demand: &SandboxResourceDemand) -> Result<(), CoreError> {
        self.validate()?;
        demand.validate()?;
        if demand.services > self.maximum_services
            || demand.cpu_millis > u64::from(self.sandbox_cpu_millis)
            || demand.memory_bytes > self.sandbox_memory_bytes
            || demand.pids > u64::from(self.sandbox_pids)
            || demand.ephemeral_storage_bytes > self.sandbox_ephemeral_storage_bytes
        {
            return Err(CoreError::InvalidSpecification(format!(
                "sandbox demand exceeds worker resource shape `{}`",
                self.name
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxResourceDemand {
    pub services: u16,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub ephemeral_storage_bytes: u64,
}

impl SandboxResourceDemand {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.services == 0 || self.cpu_millis == 0 || self.memory_bytes == 0 || self.pids == 0 {
            return Err(CoreError::InvalidSpecification(
                "sandbox resource demand is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn validates_reviewed_shape_and_exact_capacity_boundary() {
        let shape = shape();
        shape.validate().expect("valid shape");
        shape
            .require_capacity(&SandboxResourceDemand {
                services: 8,
                cpu_millis: 1_000,
                memory_bytes: 1024 * 1024 * 1024,
                pids: 256,
                ephemeral_storage_bytes: 2 * 1024 * 1024 * 1024,
            })
            .expect("exact boundary");
    }

    #[test]
    fn rejects_invalid_names_and_each_exceeded_dimension() {
        let mut invalid = shape();
        invalid.name = "Tenant_Selected".to_owned();
        assert!(invalid.validate().is_err());

        let shape = shape();
        for demand in [
            SandboxResourceDemand {
                services: 9,
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                ephemeral_storage_bytes: 0,
            },
            SandboxResourceDemand {
                services: 1,
                cpu_millis: 1_001,
                memory_bytes: 1,
                pids: 1,
                ephemeral_storage_bytes: 0,
            },
            SandboxResourceDemand {
                services: 1,
                cpu_millis: 1,
                memory_bytes: 1024 * 1024 * 1024 + 1,
                pids: 1,
                ephemeral_storage_bytes: 0,
            },
            SandboxResourceDemand {
                services: 1,
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 257,
                ephemeral_storage_bytes: 0,
            },
            SandboxResourceDemand {
                services: 1,
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
                ephemeral_storage_bytes: 2 * 1024 * 1024 * 1024 + 1,
            },
        ] {
            assert!(shape.require_capacity(&demand).is_err());
        }
    }
}
