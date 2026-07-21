use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! identifier {
    ($name:ident, $kind:literal, $maximum:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, CoreError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > $maximum
                    || !value.as_bytes()[0].is_ascii_lowercase()
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'-' | b'_')
                    })
                {
                    return Err(CoreError::InvalidIdentifier { kind: $kind, value });
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CoreError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier!(SandboxId, "sandbox", 64);
identifier!(ContainerId, "container", 64);
identifier!(NetworkId, "network", 64);
identifier!(SnapshotId, "snapshot", 64);
identifier!(VolumeId, "volume", 64);
identifier!(WorkerId, "worker", 64);
identifier!(TenantId, "tenant", 64);
identifier!(WorkspaceId, "workspace", 64);
identifier!(SubjectId, "subject", 128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_bounded_and_path_safe() {
        assert!(SandboxId::parse("tenant-a_1").is_ok());
        assert!(SandboxId::parse("../tenant").is_err());
        assert!(SandboxId::parse("Tenant").is_err());
        assert!(SandboxId::parse("x".repeat(65)).is_err());
        assert!(TenantId::parse("tenant-a").is_ok());
        assert!(WorkspaceId::parse("team-b").is_ok());
        assert!(VolumeId::parse("cache_1").is_ok());
        assert!(VolumeId::parse("../cache").is_err());
        assert!(SubjectId::parse("service-account_1").is_ok());
    }
}
