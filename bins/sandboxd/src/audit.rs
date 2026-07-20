use crate::{
    authorization::{AccessContext, ConnectionEndpoint},
    journal::DurableJournal,
};
use runtrue_sandbox_core::WorkOrderOperation;
use runtrue_sandbox_oci::{io_error, SandboxError};
use serde::Serialize;
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditOutcome {
    Rejected,
    Succeeded,
    Failed,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    timestamp_unix_millis: u64,
    request_id: &'a str,
    endpoint: &'static str,
    peer_uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<WorkOrderOperation>,
    outcome: AuditOutcome,
}

pub(crate) struct AuditLog {
    journal: DurableJournal,
}

impl AuditLog {
    pub(crate) fn open(control_root: &Path) -> Result<Self, SandboxError> {
        fs::create_dir_all(control_root).map_err(|source| io_error(control_root, source))?;
        fs::set_permissions(control_root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(control_root, source))?;
        let path = control_root.join("audit.jsonl");
        Ok(Self {
            journal: DurableJournal::open(&path)?,
        })
    }

    pub(crate) fn record(
        &self,
        request_id: &str,
        endpoint: ConnectionEndpoint,
        peer_uid: u32,
        context: Option<&AccessContext>,
        operation: Option<WorkOrderOperation>,
        outcome: AuditOutcome,
    ) -> Result<(), SandboxError> {
        let timestamp_unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SandboxError::Runtime("system clock predates the Unix epoch".to_owned()))?
            .as_millis()
            .try_into()
            .map_err(|_| SandboxError::Runtime("system time overflow".to_owned()))?;
        let record = AuditRecord {
            timestamp_unix_millis,
            request_id,
            endpoint: match endpoint {
                ConnectionEndpoint::Operator => "operator",
                ConnectionEndpoint::Workload { .. } => "workload",
            },
            peer_uid,
            tenant_id: context.map(|context| context.scope().tenant_id.as_str()),
            workspace_id: context.map(|context| context.scope().workspace_id.as_str()),
            subject_id: context.map(|context| context.subject_id().as_str()),
            operation,
            outcome,
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|error| SandboxError::Runtime(format!("encode audit record: {error}")))?;
        bytes.push(b'\n');
        self.journal.enqueue_append(bytes)?.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_records_are_bounded_structured_events() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = AuditLog::open(directory.path()).expect("audit log");
        audit
            .record(
                "request-1",
                ConnectionEndpoint::Operator,
                0,
                None,
                Some(WorkOrderOperation::Ping),
                AuditOutcome::Succeeded,
            )
            .expect("record");
        let bytes = fs::read(directory.path().join("audit.jsonl")).expect("audit bytes");
        let line: serde_json::Value = serde_json::from_slice(&bytes).expect("audit JSON");
        assert_eq!(line["request_id"], "request-1");
        assert!(line.get("parameters").is_none());
    }
}
