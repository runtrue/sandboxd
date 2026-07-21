use crate::CoreError;
use serde::{Deserialize, Serialize};

pub const STRICT_GUEST_PROFILE: &str = "strict-v1";
pub const ROOT_GUEST_PROFILE: &str = "root-in-sandbox-v1";
pub const OCI_COMPAT_GUEST_PROFILE: &str = "oci-compat-v1";

const ISOLATED_NAMESPACES: &[&str] = &["pid", "network", "ipc", "uts", "mount"];
const MASKED_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/sys/firmware",
];
const READONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];
const OCI_COMPAT_CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_SETGID",
    "CAP_SETUID",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestProfileIdentity {
    pub name: String,
    pub version: u32,
}

impl GuestProfileIdentity {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        let (name, version) = value.rsplit_once("-v").ok_or_else(|| {
            CoreError::InvalidSpecification(
                "guest profile identity must end in `-v<version>`".to_owned(),
            )
        })?;
        if name.is_empty()
            || name.len() > 48
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !name.as_bytes()[0].is_ascii_lowercase()
        {
            return Err(CoreError::InvalidSpecification(
                "guest profile name is invalid".to_owned(),
            ));
        }
        let version_text = version;
        let version = version_text.parse::<u32>().map_err(|_| {
            CoreError::InvalidSpecification("guest profile version is invalid".to_owned())
        })?;
        if version == 0 || version.to_string() != version_text {
            return Err(CoreError::InvalidSpecification(
                "guest profile version must be positive and canonical".to_owned(),
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }

    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}-v{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestProfileRestrictions {
    pub uid: u32,
    pub gid: u32,
    pub bounding_capabilities: Vec<String>,
    pub effective_capabilities: Vec<String>,
    pub inheritable_capabilities: Vec<String>,
    pub permitted_capabilities: Vec<String>,
    pub ambient_capabilities: Vec<String>,
    pub no_new_privileges: bool,
    pub isolated_namespaces: Vec<String>,
    pub masked_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub directfs_enabled: bool,
    pub host_unix_sockets: bool,
    pub host_fifos: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestProfile {
    pub identity: GuestProfileIdentity,
    pub restrictions: GuestProfileRestrictions,
}

impl GuestProfile {
    pub fn reviewed(identity: &GuestProfileIdentity) -> Option<Self> {
        let canonical = identity.canonical();
        let (uid, gid, capabilities) = match canonical.as_str() {
            STRICT_GUEST_PROFILE => (65_534, 65_534, &[][..]),
            ROOT_GUEST_PROFILE => (0, 0, &[][..]),
            OCI_COMPAT_GUEST_PROFILE => (0, 0, OCI_COMPAT_CAPABILITIES),
            _ => return None,
        };
        Some(Self {
            identity: identity.clone(),
            restrictions: GuestProfileRestrictions {
                uid,
                gid,
                bounding_capabilities: strings(capabilities),
                effective_capabilities: strings(capabilities),
                inheritable_capabilities: Vec::new(),
                permitted_capabilities: strings(capabilities),
                ambient_capabilities: Vec::new(),
                no_new_privileges: true,
                isolated_namespaces: strings(ISOLATED_NAMESPACES),
                masked_paths: strings(MASKED_PATHS),
                readonly_paths: strings(READONLY_PATHS),
                directfs_enabled: false,
                host_unix_sockets: false,
                host_fifos: false,
            },
        })
    }

    pub fn reviewed_named(value: &str) -> Result<Self, CoreError> {
        let identity = GuestProfileIdentity::parse(value)?;
        Self::reviewed(&identity).ok_or_else(|| {
            CoreError::InvalidSpecification(format!(
                "guest profile `{value}` is not a reviewed profile"
            ))
        })
    }

    pub fn strict() -> Self {
        Self::reviewed_named(STRICT_GUEST_PROFILE).expect("strict profile is reviewed")
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_profiles_keep_host_boundaries_closed() {
        for name in [
            STRICT_GUEST_PROFILE,
            ROOT_GUEST_PROFILE,
            OCI_COMPAT_GUEST_PROFILE,
        ] {
            let profile = GuestProfile::reviewed_named(name).expect("reviewed profile");
            assert!(profile.restrictions.no_new_privileges);
            assert!(profile.restrictions.ambient_capabilities.is_empty());
            assert!(profile.restrictions.inheritable_capabilities.is_empty());
            assert_eq!(
                profile.restrictions.bounding_capabilities,
                profile.restrictions.effective_capabilities
            );
            assert_eq!(
                profile.restrictions.permitted_capabilities,
                profile.restrictions.effective_capabilities
            );
            assert!(!profile.restrictions.directfs_enabled);
            assert!(!profile.restrictions.host_unix_sockets);
            assert!(!profile.restrictions.host_fifos);
            for forbidden in [
                "CAP_SYS_ADMIN",
                "CAP_NET_ADMIN",
                "CAP_NET_RAW",
                "CAP_SYS_MODULE",
                "CAP_SYS_PTRACE",
            ] {
                assert!(!profile
                    .restrictions
                    .effective_capabilities
                    .iter()
                    .any(|cap| cap == forbidden));
            }
        }
    }
}
