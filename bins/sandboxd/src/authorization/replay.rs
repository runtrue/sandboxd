use crate::{
    authorization::TenantScope,
    journal::{read_records, DurableJournal, JournalReceipt},
};
use runtrue_sandbox_oci::{io_error, SandboxError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const REPLAY_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_LIVE_NONCES: usize = 100_000;
const COMPACTION_INTERVAL: usize = 10_000;
const MAXIMUM_RECOVERY_RECORDS: usize = MAXIMUM_LIVE_NONCES + COMPACTION_INTERVAL;
const MAXIMUM_WAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayKey {
    scope: TenantScope,
    nonce_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecord {
    schema_version: u32,
    key: ReplayKey,
    expires_unix_millis: u64,
}

#[derive(Debug, Default)]
struct ReplayState {
    entries: BTreeMap<ReplayKey, u64>,
    appends_since_compaction: usize,
}

#[derive(Debug)]
pub(super) struct ReplayCache {
    journal: Option<DurableJournal>,
    state: Mutex<ReplayState>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            journal: None,
            state: Mutex::new(ReplayState::default()),
        }
    }
}

impl ReplayCache {
    pub(super) fn open(root: &Path) -> Result<Self, SandboxError> {
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
        let path = root.join("replay.wal");
        let now_unix_millis = unix_millis()?;
        let entries = load(&path, now_unix_millis)?;
        let cache = Self {
            journal: Some(DurableJournal::open(&path)?),
            state: Mutex::new(ReplayState {
                entries,
                appends_since_compaction: 0,
            }),
        };
        cache.compact(now_unix_millis)?;
        Ok(cache)
    }

    pub(super) fn consume(
        &self,
        scope: &TenantScope,
        nonce: &str,
        expires_unix_millis: u64,
        now_unix_millis: u64,
    ) -> Result<(), SandboxError> {
        let key = ReplayKey {
            scope: scope.clone(),
            nonce_digest: hex::encode(Sha256::digest(nonce.as_bytes())),
        };
        let (append, replacement) = {
            let mut state = self.state.lock().expect("replay lock");
            state.entries.retain(|_, expiry| *expiry > now_unix_millis);
            if state.entries.contains_key(&key) {
                return Err(SandboxError::Runtime(
                    "work order has already been consumed".to_owned(),
                ));
            }
            if state.entries.len() >= MAXIMUM_LIVE_NONCES {
                return Err(SandboxError::Runtime(
                    "work-order replay cache is full".to_owned(),
                ));
            }
            state.entries.insert(key.clone(), expires_unix_millis);
            let append = self.enqueue_record(&ReplayRecord {
                schema_version: REPLAY_SCHEMA_VERSION,
                key: key.clone(),
                expires_unix_millis,
            })?;
            state.appends_since_compaction += 1;
            let replacement = if state.appends_since_compaction >= COMPACTION_INTERVAL {
                state.appends_since_compaction = 0;
                self.enqueue_compaction(&state.entries)?
            } else {
                None
            };
            (append, replacement)
        };
        if let Some(receipt) = append {
            if let Err(error) = receipt.wait() {
                let mut state = self.state.lock().expect("replay lock");
                if state.entries.get(&key) == Some(&expires_unix_millis) {
                    state.entries.remove(&key);
                }
                return Err(error);
            }
        }
        if let Some(receipt) = replacement {
            receipt.wait()?;
        }
        Ok(())
    }

    fn compact(&self, now_unix_millis: u64) -> Result<(), SandboxError> {
        let receipt = {
            let mut state = self.state.lock().expect("replay lock");
            state.entries.retain(|_, expiry| *expiry > now_unix_millis);
            state.appends_since_compaction = 0;
            self.enqueue_compaction(&state.entries)?
        };
        if let Some(receipt) = receipt {
            receipt.wait()?;
        }
        Ok(())
    }

    fn enqueue_record(
        &self,
        record: &ReplayRecord,
    ) -> Result<Option<JournalReceipt>, SandboxError> {
        self.journal
            .as_ref()
            .map(|journal| journal.enqueue_append(encode_record(record)?))
            .transpose()
    }

    fn enqueue_compaction(
        &self,
        entries: &BTreeMap<ReplayKey, u64>,
    ) -> Result<Option<JournalReceipt>, SandboxError> {
        self.journal
            .as_ref()
            .map(|journal| journal.enqueue_replace(encode_entries(entries)?))
            .transpose()
    }
}

fn load(path: &Path, now_unix_millis: u64) -> Result<BTreeMap<ReplayKey, u64>, SandboxError> {
    let records = read_records(path, MAXIMUM_WAL_BYTES, MAXIMUM_RECOVERY_RECORDS)?;
    let mut entries = BTreeMap::new();
    for bytes in records {
        let record: ReplayRecord = serde_json::from_slice(&bytes)
            .map_err(|error| SandboxError::Runtime(format!("decode replay record: {error}")))?;
        if record.schema_version != REPLAY_SCHEMA_VERSION || record.expires_unix_millis == 0 {
            return Err(SandboxError::Runtime(
                "replay record schema or expiry is invalid".to_owned(),
            ));
        }
        if record.expires_unix_millis <= now_unix_millis {
            continue;
        }
        if entries
            .insert(record.key, record.expires_unix_millis)
            .is_some()
        {
            return Err(SandboxError::Runtime(
                "replay journal contains a duplicate live nonce".to_owned(),
            ));
        }
    }
    if entries.len() > MAXIMUM_LIVE_NONCES {
        return Err(SandboxError::Runtime(
            "replay journal exceeds the live nonce bound".to_owned(),
        ));
    }
    Ok(entries)
}

fn encode_record(record: &ReplayRecord) -> Result<Vec<u8>, SandboxError> {
    let mut bytes = serde_json::to_vec(record)
        .map_err(|error| SandboxError::Runtime(format!("encode replay record: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn encode_entries(entries: &BTreeMap<ReplayKey, u64>) -> Result<Vec<u8>, SandboxError> {
    let mut bytes = Vec::new();
    for (key, expires_unix_millis) in entries {
        bytes.extend(encode_record(&ReplayRecord {
            schema_version: REPLAY_SCHEMA_VERSION,
            key: key.clone(),
            expires_unix_millis: *expires_unix_millis,
        })?);
    }
    Ok(bytes)
}

fn unix_millis() -> Result<u64, SandboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SandboxError::Runtime("system clock predates the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| SandboxError::Runtime("system time overflow".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_core::{TenantId, WorkspaceId};
    use std::sync::{Arc, Barrier};

    fn scope() -> TenantScope {
        TenantScope {
            tenant_id: TenantId::parse("tenant-a").expect("tenant"),
            workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
        }
    }

    #[test]
    fn rejects_replay_and_expires_old_nonces() {
        let cache = ReplayCache::default();
        cache
            .consume(&scope(), "nonce-a", 20, 10)
            .expect("first use");
        assert!(cache.consume(&scope(), "nonce-a", 20, 10).is_err());
        cache
            .consume(&scope(), "nonce-a", 40, 21)
            .expect("expired nonce");
    }

    #[test]
    fn rejects_replay_after_restart() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = ReplayCache::open(directory.path()).expect("replay journal");
        let now = unix_millis().expect("current time");
        cache
            .consume(&scope(), "nonce-a", now + 10_000, now)
            .expect("first use");
        drop(cache);

        let reloaded = ReplayCache::open(directory.path()).expect("reloaded journal");
        assert!(reloaded
            .consume(&scope(), "nonce-a", now + 10_000, now)
            .is_err());
        assert!(
            !std::fs::read_to_string(directory.path().join("replay.wal"))
                .expect("replay data")
                .contains("nonce-a")
        );
    }

    #[test]
    fn compaction_preserves_live_entries_and_bounds_records() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = ReplayCache::open(directory.path()).expect("replay journal");
        let now = unix_millis().expect("current time");
        cache
            .consume(&scope(), "expired", now + 1, now)
            .expect("expired entry");
        {
            let mut state = cache.state.lock().expect("replay lock");
            state.appends_since_compaction = COMPACTION_INTERVAL - 1;
        }
        cache
            .consume(&scope(), "live", now + 10_000, now + 2)
            .expect("live entry");
        let records = read_records(
            &directory.path().join("replay.wal"),
            MAXIMUM_WAL_BYTES,
            MAXIMUM_RECOVERY_RECORDS,
        )
        .expect("records");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn concurrent_consumption_survives_restart() {
        const CONSUMERS: usize = 32;
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = Arc::new(ReplayCache::open(directory.path()).expect("replay journal"));
        let barrier = Arc::new(Barrier::new(CONSUMERS));
        let now = unix_millis().expect("current time");
        let consumers = (0..CONSUMERS)
            .map(|index| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .consume(&scope(), &format!("nonce-{index}"), now + 10_000, now)
                        .expect("consume nonce");
                })
            })
            .collect::<Vec<_>>();
        for consumer in consumers {
            consumer.join().expect("consumer thread");
        }
        drop(cache);

        let reloaded = ReplayCache::open(directory.path()).expect("reloaded journal");
        for index in 0..CONSUMERS {
            assert!(reloaded
                .consume(&scope(), &format!("nonce-{index}"), now + 10_000, now,)
                .is_err());
        }
    }
}
