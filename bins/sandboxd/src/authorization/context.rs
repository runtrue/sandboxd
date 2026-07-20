use runtrue_sandbox_core::{AssignmentEpoch, SandboxId, SubjectId, TenantId, WorkspaceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantScope {
    pub(crate) tenant_id: TenantId,
    pub(crate) workspace_id: WorkspaceId,
}

impl TenantScope {
    pub(crate) fn snapshot_root(&self, base: &Path) -> PathBuf {
        base.join(self.tenant_id.as_str())
            .join(self.workspace_id.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SandboxKey {
    pub(crate) scope: TenantScope,
    pub(crate) sandbox_id: SandboxId,
}

impl SandboxKey {
    pub(crate) fn runtime_project(&self, epoch: AssignmentEpoch) -> String {
        let mut digest = Sha256::new();
        digest.update(self.scope.tenant_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.scope.workspace_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(self.sandbox_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(epoch.get().to_le_bytes());
        format!("s{}", &hex::encode(digest.finalize())[..23])
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedTenant {
    pub(crate) scope: TenantScope,
    pub(crate) subject_id: SubjectId,
    pub(crate) assignment_epoch: AssignmentEpoch,
}

#[derive(Debug, Clone)]
pub(crate) enum AccessContext {
    Operator {
        scope: TenantScope,
        subject_id: SubjectId,
    },
    Tenant(VerifiedTenant),
}

impl AccessContext {
    pub(crate) fn scope(&self) -> &TenantScope {
        match self {
            Self::Operator { scope, .. } => scope,
            Self::Tenant(tenant) => &tenant.scope,
        }
    }

    pub(crate) fn subject_id(&self) -> &SubjectId {
        match self {
            Self::Operator { subject_id, .. } => subject_id,
            Self::Tenant(tenant) => &tenant.subject_id,
        }
    }

    pub(crate) const fn assignment_epoch(&self) -> Option<AssignmentEpoch> {
        match self {
            Self::Operator { .. } => None,
            Self::Tenant(tenant) => Some(tenant.assignment_epoch),
        }
    }

    pub(crate) const fn is_operator(&self) -> bool {
        matches!(self, Self::Operator { .. })
    }

    pub(crate) fn sandbox_key(&self, sandbox_id: SandboxId) -> SandboxKey {
        SandboxKey {
            scope: self.scope().clone(),
            sandbox_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn runtime_identity_is_tenant_and_epoch_scoped() {
        let epoch = AssignmentEpoch::new(1).expect("epoch");
        assert_ne!(
            key("tenant-a").runtime_project(epoch),
            key("tenant-b").runtime_project(epoch)
        );
        assert_ne!(
            key("tenant-a").runtime_project(epoch),
            key("tenant-a").runtime_project(AssignmentEpoch::new(2).expect("epoch"))
        );
    }

    #[test]
    fn snapshot_paths_are_tenant_and_workspace_scoped() {
        let base = Path::new("/var/lib/runtrue-sandboxd/state/snapshots");
        assert_eq!(
            key("tenant-a").scope.snapshot_root(base),
            base.join("tenant-a").join("team-a")
        );
        assert_ne!(
            key("tenant-a").scope.snapshot_root(base),
            key("tenant-b").scope.snapshot_root(base)
        );
    }
}
