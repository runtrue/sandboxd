use crate::{io_error, SandboxError};
use runtrue_sandbox_core::{SnapshotId, SnapshotMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const LOCAL_SNAPSHOT_VERSION: u32 = 2;
const MANIFEST_NAME: &str = "snapshot.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSnapshotManifest {
    pub schema_version: u32,
    pub snapshot_id: SnapshotId,
    pub source_sandbox: String,
    pub topology_digest: String,
    pub mode: SnapshotMode,
    pub created_unix_millis: u64,
    pub architecture: String,
    pub operating_system: String,
    pub runsc_version: String,
    pub runtime_configuration_digest: String,
    pub cpu_features_digest: String,
    pub root_service: String,
    pub services: Vec<String>,
    pub service_states: BTreeMap<String, String>,
    pub files: Vec<SnapshotFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFile {
    pub name: String,
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotSummary {
    pub snapshot_id: SnapshotId,
    pub source_sandbox: String,
    pub topology_digest: String,
    pub mode: SnapshotMode,
    pub files: usize,
    pub size_bytes: u64,
    pub runtime_configuration_digest: String,
}

pub(super) struct SnapshotStaging {
    snapshot_id: SnapshotId,
    root: PathBuf,
    staging: PathBuf,
    final_path: PathBuf,
}

impl SnapshotStaging {
    pub(super) fn create(root: &Path, snapshot_id: SnapshotId) -> Result<Self, SandboxError> {
        if !root.is_absolute() {
            return Err(SandboxError::Runtime(
                "snapshot root must be absolute".to_owned(),
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
        let final_path = root.join(snapshot_id.as_str());
        if final_path.exists() {
            return Err(SandboxError::Runtime(format!(
                "snapshot `{snapshot_id}` already exists"
            )));
        }
        let staging = root.join(format!(
            ".staging-{}-{}",
            snapshot_id.as_str(),
            std::process::id()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .map_err(|source| io_error(&staging, source))?;
        Ok(Self {
            snapshot_id,
            root,
            staging,
            final_path,
        })
    }

    pub(super) fn image_path(&self) -> Result<PathBuf, SandboxError> {
        let path = self.staging.join("runtime");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|source| io_error(&path, source))?;
        Ok(path)
    }

    pub(super) fn publish(
        self,
        mut manifest: LocalSnapshotManifest,
    ) -> Result<SnapshotSummary, SandboxError> {
        manifest.files = describe_files(&self.staging.join("runtime"))?;
        if manifest.files.is_empty() {
            return Err(SandboxError::Runtime(
                "runsc checkpoint produced no files".to_owned(),
            ));
        }
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| SandboxError::Runtime(format!("encode snapshot manifest: {error}")))?;
        let manifest_path = self.staging.join(MANIFEST_NAME);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&manifest_path)
            .map_err(|source| io_error(&manifest_path, source))?;
        file.write_all(&bytes)
            .map_err(|source| io_error(&manifest_path, source))?;
        file.sync_all()
            .map_err(|source| io_error(&manifest_path, source))?;
        make_read_only(&self.staging.join("runtime"))?;
        fs::set_permissions(&self.staging, fs::Permissions::from_mode(0o500))
            .map_err(|source| io_error(&self.staging, source))?;
        fs::File::open(&self.staging)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(&self.staging, source))?;
        fs::rename(&self.staging, &self.final_path)
            .map_err(|source| io_error(&self.final_path, source))?;
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(&self.root, source))?;
        let size_bytes = manifest.files.iter().map(|file| file.size_bytes).sum();
        Ok(SnapshotSummary {
            snapshot_id: self.snapshot_id.clone(),
            source_sandbox: manifest.source_sandbox,
            topology_digest: manifest.topology_digest,
            mode: manifest.mode,
            files: manifest.files.len(),
            size_bytes,
            runtime_configuration_digest: manifest.runtime_configuration_digest,
        })
    }
}

impl Drop for SnapshotStaging {
    fn drop(&mut self) {
        if self.staging.exists() {
            let _ = make_writable(&self.staging);
            let _ = fs::remove_dir_all(&self.staging);
        }
    }
}

pub(super) fn load(
    root: &Path,
    snapshot_id: &SnapshotId,
) -> Result<(LocalSnapshotManifest, PathBuf), SandboxError> {
    let root = fs::canonicalize(root).map_err(|source| io_error(root, source))?;
    let directory = root.join(snapshot_id.as_str());
    let canonical = fs::canonicalize(&directory).map_err(|source| io_error(&directory, source))?;
    if canonical.parent() != Some(root.as_path()) {
        return Err(SandboxError::Runtime(
            "snapshot path escaped its store".to_owned(),
        ));
    }
    let manifest_path = canonical.join(MANIFEST_NAME);
    let bytes = fs::read(&manifest_path).map_err(|source| io_error(&manifest_path, source))?;
    let manifest: LocalSnapshotManifest = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Runtime(format!("decode snapshot manifest: {error}")))?;
    if manifest.schema_version != LOCAL_SNAPSHOT_VERSION || &manifest.snapshot_id != snapshot_id {
        return Err(SandboxError::Runtime(
            "snapshot manifest identity is invalid".to_owned(),
        ));
    }
    verify_files(&canonical.join("runtime"), &manifest.files)?;
    Ok((manifest, canonical.join("runtime")))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn manifest(
    snapshot_id: SnapshotId,
    source_sandbox: String,
    topology_digest: String,
    mode: SnapshotMode,
    runsc_version: String,
    runtime_configuration_digest: String,
    cpu_features_digest: String,
    root_service: String,
    services: Vec<String>,
    service_states: BTreeMap<String, String>,
) -> Result<LocalSnapshotManifest, SandboxError> {
    let created_unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SandboxError::Runtime("system clock predates the Unix epoch".to_owned()))?
        .as_millis()
        .try_into()
        .map_err(|_| SandboxError::Runtime("snapshot timestamp overflow".to_owned()))?;
    Ok(LocalSnapshotManifest {
        schema_version: LOCAL_SNAPSHOT_VERSION,
        snapshot_id,
        source_sandbox,
        topology_digest,
        mode,
        created_unix_millis,
        architecture: std::env::consts::ARCH.to_owned(),
        operating_system: std::env::consts::OS.to_owned(),
        runsc_version,
        runtime_configuration_digest,
        cpu_features_digest,
        root_service,
        services,
        service_states,
        files: Vec::new(),
    })
}

fn describe_files(directory: &Path) -> Result<Vec<SnapshotFile>, SandboxError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| io_error(directory, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(directory, source))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut files = Vec::new();
    for entry in entries {
        if !entry
            .file_type()
            .map_err(|source| io_error(entry.path(), source))?
            .is_file()
        {
            return Err(SandboxError::Runtime(
                "checkpoint contains a non-file entry".to_owned(),
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SandboxError::Runtime("checkpoint filename is not UTF-8".to_owned()))?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(SandboxError::Runtime(
                "checkpoint filename is unsafe".to_owned(),
            ));
        }
        let path = entry.path();
        let (digest, size_bytes) = digest_file(&path)?;
        files.push(SnapshotFile {
            name,
            digest,
            size_bytes,
            media_type: "application/vnd.runtrue.gvisor.checkpoint".to_owned(),
        });
    }
    Ok(files)
}

fn verify_files(directory: &Path, expected: &[SnapshotFile]) -> Result<(), SandboxError> {
    let actual = describe_files(directory)?;
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.name != expected.name
                || actual.digest != expected.digest
                || actual.size_bytes != expected.size_bytes
                || actual.media_type != expected.media_type
        })
    {
        return Err(SandboxError::Runtime(
            "snapshot artifact integrity check failed".to_owned(),
        ));
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<(String, u64), SandboxError> {
    let mut file = fs::File::open(path).map_err(|source| io_error(path, source))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| SandboxError::Runtime("snapshot size overflow".to_owned()))?;
    }
    Ok((format!("sha256:{:x}", digest.finalize()), size))
}

fn make_read_only(directory: &Path) -> Result<(), SandboxError> {
    for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
        let path = entry.map_err(|source| io_error(directory, source))?.path();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|source| io_error(&path, source))?;
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
        .map_err(|source| io_error(directory, source))
}

fn make_writable(directory: &Path) -> Result<(), SandboxError> {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(directory, source))?;
    for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
        let path = entry.map_err(|source| io_error(directory, source))?.path();
        if path.is_dir() {
            make_writable(&path)?;
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|source| io_error(&path, source))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_manifest(snapshot_id: SnapshotId) -> LocalSnapshotManifest {
        manifest(
            snapshot_id,
            "source-a".to_owned(),
            format!("sha256:{}", "a".repeat(64)),
            SnapshotMode::StopAndMove,
            "runsc test".to_owned(),
            format!("sha256:{}", "b".repeat(64)),
            format!("sha256:{}", "c".repeat(64)),
            "server".to_owned(),
            vec!["server".to_owned(), "client".to_owned()],
            BTreeMap::from([
                ("client".to_owned(), "running".to_owned()),
                ("server".to_owned(), "running".to_owned()),
            ]),
        )
        .expect("manifest")
    }

    #[test]
    fn publishes_and_verifies_immutable_snapshot() {
        let root = tempfile::tempdir().expect("temporary directory");
        let id = SnapshotId::parse("snapshot-a").expect("snapshot ID");
        let staging = SnapshotStaging::create(root.path(), id.clone()).expect("staging");
        let image = staging.image_path().expect("image path");
        fs::write(image.join("checkpoint.img"), b"checkpoint").expect("checkpoint file");
        let summary = staging.publish(test_manifest(id.clone())).expect("publish");
        assert_eq!(summary.files, 1);
        let (loaded, _) = load(root.path(), &id).expect("load snapshot");
        assert_eq!(loaded.service_states["client"], "running");
        make_writable(root.path()).expect("allow temporary directory cleanup");
    }

    #[test]
    fn rejects_modified_snapshot_artifact() {
        let root = tempfile::tempdir().expect("temporary directory");
        let id = SnapshotId::parse("snapshot-b").expect("snapshot ID");
        let staging = SnapshotStaging::create(root.path(), id.clone()).expect("staging");
        let image = staging.image_path().expect("image path");
        fs::write(image.join("pages.img"), b"original").expect("pages file");
        staging.publish(test_manifest(id.clone())).expect("publish");
        let snapshot = root.path().join(id.as_str());
        make_writable(&snapshot).expect("make snapshot writable for tamper probe");
        fs::write(snapshot.join("runtime/pages.img"), b"tampered").expect("tamper artifact");
        assert!(load(root.path(), &id).is_err());
    }
}
