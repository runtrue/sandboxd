use crate::SandboxError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableRootfsIdentity {
    project: String,
    service: String,
}

impl WritableRootfsIdentity {
    pub fn new(
        project: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, SandboxError> {
        let identity = Self {
            project: project.into(),
            service: service.into(),
        };
        validate_component("project", &identity.project, 32)?;
        validate_component("service", &identity.service, 32)?;
        Ok(identity)
    }

    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

fn validate_component(kind: &str, value: &str, maximum: usize) -> Result<(), SandboxError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
        || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err(SandboxError::ImageProvider(format!(
            "writable rootfs {kind} identity is invalid"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_bounded_and_path_safe() {
        assert!(WritableRootfsIdentity::new("s0123", "api_worker").is_ok());
        assert!(WritableRootfsIdentity::new("../tenant", "api").is_err());
        assert!(WritableRootfsIdentity::new("tenant", "api/worker").is_err());
    }
}
