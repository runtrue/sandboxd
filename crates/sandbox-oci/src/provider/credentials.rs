use crate::SandboxError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fmt;

#[derive(Clone)]
enum RegistrySecret {
    Basic { username: String, password: String },
    Bearer(String),
}

#[derive(Clone)]
pub struct RegistryCredential {
    tenant: String,
    registry: String,
    secret: RegistrySecret,
}

impl fmt::Debug for RegistryCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCredential")
            .field("tenant", &self.tenant)
            .field("registry", &self.registry)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl RegistryCredential {
    pub fn basic(
        tenant: impl Into<String>,
        registry: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, SandboxError> {
        let credential = Self {
            tenant: tenant.into(),
            registry: registry.into(),
            secret: RegistrySecret::Basic {
                username: username.into(),
                password: password.into(),
            },
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn bearer(
        tenant: impl Into<String>,
        registry: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, SandboxError> {
        let credential = Self {
            tenant: tenant.into(),
            registry: registry.into(),
            secret: RegistrySecret::Bearer(token.into()),
        };
        credential.validate()?;
        Ok(credential)
    }

    fn validate(&self) -> Result<(), SandboxError> {
        if self.tenant.is_empty()
            || self.tenant.len() > 128
            || self.registry.is_empty()
            || self.registry.len() > 255
            || !self.registry.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'_')
            })
        {
            return Err(SandboxError::ImageProvider(
                "registry credential scope is invalid".to_owned(),
            ));
        }
        let valid = match &self.secret {
            RegistrySecret::Basic { username, password } => {
                !username.is_empty()
                    && username.len() <= 1_024
                    && !password.is_empty()
                    && password.len() <= 16 * 1_024
            }
            RegistrySecret::Bearer(token) => !token.is_empty() && token.len() <= 64 * 1_024,
        };
        if !valid {
            return Err(SandboxError::ImageProvider(
                "registry credential secret is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_registry(&self, registry: &str) -> Result<(), SandboxError> {
        if self.registry != registry
            && !(self.registry == "docker.io" && registry == "index.docker.io")
        {
            return Err(SandboxError::ImageProvider(
                "registry credential does not match the image registry".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn authorization_header(&self) -> String {
        match &self.secret {
            RegistrySecret::Basic { username, password } => {
                let encoded = STANDARD.encode(format!("{username}:{password}"));
                format!("Basic {encoded}")
            }
            RegistrySecret::Bearer(token) => format!("Bearer {token}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_contains_the_secret() {
        let credential = RegistryCredential::basic(
            "tenant-a",
            "ghcr.io",
            "user",
            "credential-value-must-not-leak",
        )
        .expect("valid credential");
        let debug = format!("{credential:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("credential-value-must-not-leak"));
    }

    #[test]
    fn credentials_are_registry_scoped() {
        let credential =
            RegistryCredential::bearer("tenant-a", "ghcr.io", "secret").expect("valid credential");
        assert!(credential.ensure_registry("ghcr.io").is_ok());
        assert!(credential.ensure_registry("registry.example").is_err());
    }
}
