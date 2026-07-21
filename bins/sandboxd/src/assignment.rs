use crate::{
    authorization::SandboxKey,
    journal::{read_records, DurableJournal, JournalReceipt},
};
use runtrue_sandbox_core::{AssignmentEpoch, SnapshotId};
use runtrue_sandbox_oci::{io_error, SandboxError};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::Path,
    sync::Mutex,
};

const ASSIGNMENT_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_ASSIGNMENTS: usize = 100_000;
const COMPACTION_INTERVAL: usize = 10_000;
const MAXIMUM_RECOVERY_RECORDS: usize = MAXIMUM_ASSIGNMENTS + COMPACTION_INTERVAL;
const MAXIMUM_WAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AssignmentState {
    Provisioning,
    Restoring,
    Active,
    Fencing,
    Transferable,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentRecord {
    schema_version: u32,
    key: SandboxKey,
    epoch: AssignmentEpoch,
    state: AssignmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<SnapshotId>,
}

struct AssignmentLedgerState {
    entries: BTreeMap<SandboxKey, AssignmentRecord>,
    appends_since_compaction: usize,
}

pub(crate) struct AssignmentLedger {
    journal: DurableJournal,
    state: Mutex<AssignmentLedgerState>,
}

impl AssignmentLedger {
    pub(crate) fn open(root: &Path) -> Result<Self, SandboxError> {
        if !root.is_absolute() {
            return Err(SandboxError::Runtime(
                "control state root must be absolute".to_owned(),
            ));
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(|source| io_error(root, source))?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(root, source))?;
        let root = fs::canonicalize(root).map_err(|source| io_error(root, source))?;
        let path = root.join("assignments.wal");
        let entries = load(&path)?;
        let ledger = Self {
            journal: DurableJournal::open(&path)?,
            state: Mutex::new(AssignmentLedgerState {
                entries,
                appends_since_compaction: 0,
            }),
        };
        ledger.compact()?;
        Ok(ledger)
    }

    pub(crate) fn begin(
        &self,
        key: &SandboxKey,
        requested_epoch: Option<AssignmentEpoch>,
    ) -> Result<AssignmentEpoch, SandboxError> {
        self.begin_operation(key, requested_epoch, AssignmentState::Provisioning, None)
    }

    pub(crate) fn begin_restore(
        &self,
        key: &SandboxKey,
        requested_epoch: Option<AssignmentEpoch>,
        snapshot_id: &SnapshotId,
    ) -> Result<AssignmentEpoch, SandboxError> {
        self.begin_operation(
            key,
            requested_epoch,
            AssignmentState::Restoring,
            Some(snapshot_id.clone()),
        )
    }

    fn begin_operation(
        &self,
        key: &SandboxKey,
        requested_epoch: Option<AssignmentEpoch>,
        assignment_state: AssignmentState,
        snapshot_id: Option<SnapshotId>,
    ) -> Result<AssignmentEpoch, SandboxError> {
        let (epoch, record, previous, append, replacement) = {
            let mut state = self.state.lock().expect("assignment lock");
            if state.entries.len() >= MAXIMUM_ASSIGNMENTS && !state.entries.contains_key(key) {
                return Err(SandboxError::Runtime(
                    "assignment ledger is full".to_owned(),
                ));
            }
            let current = state.entries.get(key);
            if current.is_some_and(|record| {
                matches!(
                    record.state,
                    AssignmentState::Provisioning
                        | AssignmentState::Restoring
                        | AssignmentState::Active
                        | AssignmentState::Fencing
                )
            }) {
                return Err(SandboxError::Runtime(
                    "sandbox assignment is already active".to_owned(),
                ));
            }
            let epoch = match requested_epoch {
                Some(epoch) => epoch,
                None => AssignmentEpoch::new(
                    current
                        .map(|record| record.epoch.get())
                        .unwrap_or(0)
                        .checked_add(1)
                        .ok_or_else(|| {
                            SandboxError::Runtime("assignment epoch overflow".to_owned())
                        })?,
                )
                .map_err(|error| SandboxError::Runtime(error.to_string()))?,
            };
            if let Some(current) = current {
                if epoch <= current.epoch {
                    return Err(SandboxError::Runtime(
                        "assignment epoch is stale or already consumed".to_owned(),
                    ));
                }
                if current.state == AssignmentState::Transferable
                    && (assignment_state != AssignmentState::Restoring
                        || current.snapshot_id.as_ref() != snapshot_id.as_ref())
                {
                    return Err(SandboxError::Runtime(
                        "transferable assignment must be restored from its fenced snapshot"
                            .to_owned(),
                    ));
                }
            }
            let previous = state.entries.get(key).cloned();
            let record = AssignmentRecord {
                schema_version: ASSIGNMENT_SCHEMA_VERSION,
                key: key.clone(),
                epoch,
                state: assignment_state,
                snapshot_id,
            };
            state.entries.insert(key.clone(), record.clone());
            let append = self.journal.enqueue_append(encode_record(&record)?)?;
            state.appends_since_compaction += 1;
            let replacement = self.maybe_enqueue_compaction(&mut state)?;
            (epoch, record, previous, append, replacement)
        };
        if let Err(error) = append.wait() {
            self.rollback(&record, previous);
            return Err(error);
        }
        if let Some(receipt) = replacement {
            receipt.wait()?;
        }
        Ok(epoch)
    }

    pub(crate) fn begin_fencing(
        &self,
        key: &SandboxKey,
        epoch: AssignmentEpoch,
        snapshot_id: &SnapshotId,
    ) -> Result<(), SandboxError> {
        self.transition(
            key,
            epoch,
            AssignmentState::Fencing,
            Some(snapshot_id.clone()),
        )
    }

    pub(crate) fn mark_transferable(
        &self,
        key: &SandboxKey,
        epoch: AssignmentEpoch,
        snapshot_id: &SnapshotId,
    ) -> Result<(), SandboxError> {
        self.transition(
            key,
            epoch,
            AssignmentState::Transferable,
            Some(snapshot_id.clone()),
        )
    }

    pub(crate) fn require_current(
        &self,
        key: &SandboxKey,
        requested_epoch: Option<AssignmentEpoch>,
    ) -> Result<AssignmentEpoch, SandboxError> {
        let state = self.state.lock().expect("assignment lock");
        let record = state.entries.get(key).ok_or_else(|| {
            SandboxError::Runtime("sandbox does not have an assignment".to_owned())
        })?;
        if requested_epoch.is_some_and(|epoch| epoch != record.epoch) {
            return Err(SandboxError::Runtime(
                "assignment epoch is stale".to_owned(),
            ));
        }
        if !matches!(record.state, AssignmentState::Active) {
            return Err(SandboxError::Runtime(
                "sandbox assignment is not active".to_owned(),
            ));
        }
        Ok(record.epoch)
    }

    pub(crate) fn mark(
        &self,
        key: &SandboxKey,
        epoch: AssignmentEpoch,
        assignment_state: AssignmentState,
    ) -> Result<(), SandboxError> {
        self.transition(key, epoch, assignment_state, None)
    }

    fn transition(
        &self,
        key: &SandboxKey,
        epoch: AssignmentEpoch,
        assignment_state: AssignmentState,
        snapshot_id: Option<SnapshotId>,
    ) -> Result<(), SandboxError> {
        let (record, previous, append, replacement) = {
            let mut state = self.state.lock().expect("assignment lock");
            let previous = state.entries.get(key).cloned().ok_or_else(|| {
                SandboxError::Runtime("sandbox does not have an assignment".to_owned())
            })?;
            if previous.epoch != epoch {
                return Err(SandboxError::Runtime(
                    "assignment epoch changed during operation".to_owned(),
                ));
            }
            if !valid_transition(previous.state, assignment_state) {
                return Err(SandboxError::Runtime(format!(
                    "invalid assignment transition from {:?} to {:?}",
                    previous.state, assignment_state
                )));
            }
            if matches!(
                assignment_state,
                AssignmentState::Fencing | AssignmentState::Transferable
            ) && snapshot_id.is_none()
            {
                return Err(SandboxError::Runtime(
                    "snapshot fencing transition requires a snapshot identity".to_owned(),
                ));
            }
            if previous.state == AssignmentState::Fencing
                && assignment_state == AssignmentState::Transferable
                && previous.snapshot_id != snapshot_id
            {
                return Err(SandboxError::Runtime(
                    "transferable snapshot does not match the fencing record".to_owned(),
                ));
            }
            let mut record = previous.clone();
            record.state = assignment_state;
            if snapshot_id.is_some() {
                record.snapshot_id = snapshot_id;
            } else if matches!(
                assignment_state,
                AssignmentState::Active | AssignmentState::Stopped
            ) {
                record.snapshot_id = None;
            }
            state.entries.insert(key.clone(), record.clone());
            let append = self.journal.enqueue_append(encode_record(&record)?)?;
            state.appends_since_compaction += 1;
            let replacement = self.maybe_enqueue_compaction(&mut state)?;
            (record, Some(previous), append, replacement)
        };
        if let Err(error) = append.wait() {
            self.rollback(&record, previous);
            return Err(error);
        }
        if let Some(receipt) = replacement {
            receipt.wait()?;
        }
        Ok(())
    }

    pub(crate) fn reconcile_after_recovery(&self) -> Result<(), SandboxError> {
        let receipt = {
            let mut state = self.state.lock().expect("assignment lock");
            let mut modified = false;
            for record in state.entries.values_mut() {
                if matches!(
                    record.state,
                    AssignmentState::Provisioning
                        | AssignmentState::Restoring
                        | AssignmentState::Active
                        | AssignmentState::Fencing
                ) {
                    record.state = AssignmentState::Failed;
                    modified = true;
                }
            }
            if !modified {
                return Ok(());
            }
            state.appends_since_compaction = 0;
            self.journal
                .enqueue_replace(encode_entries(&state.entries)?)?
        };
        receipt.wait()
    }

    fn maybe_enqueue_compaction(
        &self,
        state: &mut AssignmentLedgerState,
    ) -> Result<Option<JournalReceipt>, SandboxError> {
        if state.appends_since_compaction < COMPACTION_INTERVAL {
            return Ok(None);
        }
        state.appends_since_compaction = 0;
        self.journal
            .enqueue_replace(encode_entries(&state.entries)?)
            .map(Some)
    }

    fn compact(&self) -> Result<(), SandboxError> {
        let receipt = {
            let mut state = self.state.lock().expect("assignment lock");
            state.appends_since_compaction = 0;
            self.journal
                .enqueue_replace(encode_entries(&state.entries)?)?
        };
        receipt.wait()
    }

    fn rollback(&self, expected: &AssignmentRecord, previous: Option<AssignmentRecord>) {
        let mut state = self.state.lock().expect("assignment lock");
        if state.entries.get(&expected.key) == Some(expected) {
            if let Some(previous) = previous {
                state.entries.insert(expected.key.clone(), previous);
            } else {
                state.entries.remove(&expected.key);
            }
        }
    }
}

const fn valid_transition(from: AssignmentState, to: AssignmentState) -> bool {
    matches!(
        (from, to),
        (AssignmentState::Provisioning, AssignmentState::Active)
            | (AssignmentState::Provisioning, AssignmentState::Stopped)
            | (AssignmentState::Provisioning, AssignmentState::Failed)
            | (AssignmentState::Restoring, AssignmentState::Active)
            | (AssignmentState::Restoring, AssignmentState::Failed)
            | (AssignmentState::Active, AssignmentState::Fencing)
            | (AssignmentState::Active, AssignmentState::Stopped)
            | (AssignmentState::Active, AssignmentState::Failed)
            | (AssignmentState::Fencing, AssignmentState::Active)
            | (AssignmentState::Fencing, AssignmentState::Transferable)
            | (AssignmentState::Fencing, AssignmentState::Failed)
    )
}

fn load(path: &Path) -> Result<BTreeMap<SandboxKey, AssignmentRecord>, SandboxError> {
    let records = read_records(path, MAXIMUM_WAL_BYTES, MAXIMUM_RECOVERY_RECORDS)?;
    let mut entries = BTreeMap::new();
    for bytes in records {
        let record: AssignmentRecord = serde_json::from_slice(&bytes)
            .map_err(|error| SandboxError::Runtime(format!("decode assignment record: {error}")))?;
        if record.schema_version != ASSIGNMENT_SCHEMA_VERSION {
            return Err(SandboxError::Runtime(
                "assignment record schema is invalid".to_owned(),
            ));
        }
        entries.insert(record.key.clone(), record);
        if entries.len() > MAXIMUM_ASSIGNMENTS {
            return Err(SandboxError::Runtime(
                "assignment journal exceeds its entry bound".to_owned(),
            ));
        }
    }
    Ok(entries)
}

fn encode_record(record: &AssignmentRecord) -> Result<Vec<u8>, SandboxError> {
    let mut bytes = serde_json::to_vec(record)
        .map_err(|error| SandboxError::Runtime(format!("encode assignment record: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn encode_entries(
    entries: &BTreeMap<SandboxKey, AssignmentRecord>,
) -> Result<Vec<u8>, SandboxError> {
    let mut bytes = Vec::new();
    for record in entries.values() {
        bytes.extend(encode_record(record)?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::TenantScope;
    use runtrue_sandbox_core::{SandboxId, TenantId, WorkspaceId};
    use std::sync::{Arc, Barrier};

    fn key(tenant: &str) -> SandboxKey {
        SandboxKey {
            scope: TenantScope {
                tenant_id: TenantId::parse(tenant).expect("tenant"),
                workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            },
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox"),
        }
    }

    fn snapshot(value: &str) -> SnapshotId {
        SnapshotId::parse(value).expect("snapshot")
    }

    #[test]
    fn persists_epochs_and_separates_tenants() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let first = ledger.begin(&key("tenant-a"), None).expect("begin");
        ledger
            .mark(&key("tenant-a"), first, AssignmentState::Active)
            .expect("active");
        let other = ledger.begin(&key("tenant-b"), None).expect("other tenant");
        ledger
            .mark(&key("tenant-b"), other, AssignmentState::Active)
            .expect("active");
        drop(ledger);

        let reloaded = AssignmentLedger::open(directory.path()).expect("reloaded ledger");
        assert_eq!(
            reloaded
                .require_current(&key("tenant-a"), Some(first))
                .expect("tenant A"),
            first
        );
        assert_eq!(
            reloaded
                .require_current(&key("tenant-b"), Some(other))
                .expect("tenant B"),
            other
        );
    }

    #[test]
    fn cross_tenant_probe_cannot_resolve_an_existing_sandbox() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let epoch = ledger.begin(&key("tenant-a"), None).expect("begin");
        ledger
            .mark(&key("tenant-a"), epoch, AssignmentState::Active)
            .expect("active");

        let error = ledger
            .require_current(&key("tenant-b"), Some(epoch))
            .expect_err("cross-tenant lookup must fail");
        assert_eq!(
            error.to_string(),
            "sandbox runtime failed: sandbox does not have an assignment"
        );
    }

    #[test]
    fn rejects_stale_consumed_and_overlapping_epochs() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let epoch = AssignmentEpoch::new(4).expect("epoch");
        ledger.begin(&key("tenant-a"), Some(epoch)).expect("begin");
        assert!(ledger
            .begin(
                &key("tenant-a"),
                Some(AssignmentEpoch::new(5).expect("epoch"))
            )
            .is_err());
        ledger
            .mark(&key("tenant-a"), epoch, AssignmentState::Stopped)
            .expect("stopped");
        assert!(ledger.begin(&key("tenant-a"), Some(epoch)).is_err());
        assert!(ledger
            .begin(
                &key("tenant-a"),
                Some(AssignmentEpoch::new(3).expect("epoch"))
            )
            .is_err());
    }

    #[test]
    fn recovery_preserves_owner_and_fences_active_epoch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let epoch = ledger.begin(&key("tenant-a"), None).expect("begin");
        ledger
            .mark(&key("tenant-a"), epoch, AssignmentState::Active)
            .expect("active");
        ledger.reconcile_after_recovery().expect("reconcile");
        assert!(ledger
            .require_current(&key("tenant-a"), Some(epoch))
            .is_err());
        let next = ledger.begin(&key("tenant-a"), None).expect("new epoch");
        assert_eq!(next.get(), epoch.get() + 1);
    }

    #[test]
    fn stop_and_move_fences_source_before_transfer_and_restore() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let key = key("tenant-a");
        let snapshot_id = snapshot("snapshot-transfer");
        let source = ledger.begin(&key, None).expect("source assignment");
        ledger
            .mark(&key, source, AssignmentState::Active)
            .expect("active source");
        ledger
            .begin_fencing(&key, source, &snapshot_id)
            .expect("durable source fence");
        assert!(ledger.require_current(&key, Some(source)).is_err());
        ledger
            .mark_transferable(&key, source, &snapshot_id)
            .expect("transferable snapshot");
        drop(ledger);
        let ledger = AssignmentLedger::open(directory.path()).expect("reloaded ledger");
        ledger
            .reconcile_after_recovery()
            .expect("reconcile transferable assignment");

        let destination = ledger
            .begin_restore(
                &key,
                Some(AssignmentEpoch::new(source.get() + 1).expect("destination epoch")),
                &snapshot_id,
            )
            .expect("destination assignment");
        assert!(ledger.require_current(&key, Some(source)).is_err());
        ledger
            .mark(&key, destination, AssignmentState::Active)
            .expect("active destination");
        assert_eq!(
            ledger
                .require_current(&key, Some(destination))
                .expect("destination owns sandbox"),
            destination
        );
    }

    #[test]
    fn transferable_assignment_rejects_wrong_snapshot_and_reused_epoch() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let key = key("tenant-a");
        let snapshot_id = snapshot("snapshot-transfer");
        let epoch = ledger.begin(&key, None).expect("source assignment");
        ledger
            .mark(&key, epoch, AssignmentState::Active)
            .expect("active source");
        ledger
            .begin_fencing(&key, epoch, &snapshot_id)
            .expect("durable source fence");
        ledger
            .mark_transferable(&key, epoch, &snapshot_id)
            .expect("transferable snapshot");

        assert!(ledger
            .begin_restore(&key, Some(epoch), &snapshot_id)
            .is_err());
        assert!(ledger
            .begin_restore(
                &key,
                Some(AssignmentEpoch::new(epoch.get() + 1).expect("epoch")),
                &snapshot("different-snapshot"),
            )
            .is_err());
        assert!(ledger
            .begin(
                &key,
                Some(AssignmentEpoch::new(epoch.get() + 1).expect("epoch")),
            )
            .is_err());
    }

    #[test]
    fn compaction_retains_only_latest_assignment_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = AssignmentLedger::open(directory.path()).expect("ledger");
        let epoch = ledger.begin(&key("tenant-a"), None).expect("begin");
        {
            let mut state = ledger.state.lock().expect("assignment lock");
            state.appends_since_compaction = COMPACTION_INTERVAL - 1;
        }
        ledger
            .mark(&key("tenant-a"), epoch, AssignmentState::Active)
            .expect("active");
        assert_eq!(
            read_records(
                &directory.path().join("assignments.wal"),
                MAXIMUM_WAL_BYTES,
                MAXIMUM_RECOVERY_RECORDS,
            )
            .expect("records")
            .len(),
            1
        );
    }

    #[test]
    fn concurrent_assignment_transitions_survive_restart() {
        const ASSIGNMENTS: usize = 32;
        let directory = tempfile::tempdir().expect("temporary directory");
        let ledger = Arc::new(AssignmentLedger::open(directory.path()).expect("ledger"));
        let barrier = Arc::new(Barrier::new(ASSIGNMENTS));
        let transitions = (0..ASSIGNMENTS)
            .map(|index| {
                let ledger = Arc::clone(&ledger);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let key = key(&format!("tenant-{index}"));
                    barrier.wait();
                    let epoch = ledger.begin(&key, None).expect("begin");
                    ledger
                        .mark(&key, epoch, AssignmentState::Active)
                        .expect("active");
                    (key, epoch)
                })
            })
            .collect::<Vec<_>>();
        let assignments = transitions
            .into_iter()
            .map(|transition| transition.join().expect("transition thread"))
            .collect::<Vec<_>>();
        drop(ledger);

        let reloaded = AssignmentLedger::open(directory.path()).expect("reloaded ledger");
        for (key, epoch) in assignments {
            assert_eq!(
                reloaded
                    .require_current(&key, Some(epoch))
                    .expect("current assignment"),
                epoch
            );
        }
    }
}
