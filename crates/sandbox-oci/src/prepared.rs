use crate::{error::io_error, Docker, SandboxError};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::Builder;

const PREPARED_SCHEMA_VERSION: u32 = 1;
const MAX_TREE_ENTRIES: usize = 500_000;
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedImage {
    pub schema_version: u32,
    pub exact_reference: String,
    pub image_id: String,
    pub export_digest: String,
    pub rootfs_digest: String,
    pub rootfs_entries: usize,
    pub rootfs_bytes: u64,
}

pub fn prepare_image(
    docker: &Docker,
    tar_program: &Path,
    reference: &str,
    image_store: &Path,
) -> Result<(PathBuf, PreparedImage), SandboxError> {
    let tar_program = validate_program(tar_program, "tar")?;
    if !reference.contains("@sha256:") {
        return Err(SandboxError::Unsupported(
            "direct image preparation requires an exact sha256 repository reference".to_owned(),
        ));
    }
    let inspected = docker.image_inspect(reference)?;
    let exact_reference = reference.to_owned();
    let exact = docker.image_inspect(&exact_reference)?;
    if exact.id != inspected.id {
        return Err(SandboxError::Docker(format!(
            "image `{reference}` changed during preparation"
        )));
    }
    let image_key = image_key(&exact.id)?;
    fs::create_dir_all(image_store).map_err(|source| io_error(image_store, source))?;
    let canonical_store =
        fs::canonicalize(image_store).map_err(|source| io_error(image_store, source))?;
    let destination = canonical_store.join(&image_key);
    if destination.exists() {
        return Err(SandboxError::Docker(format!(
            "prepared image `{}` already exists",
            destination.display()
        )));
    }
    let staging = Builder::new()
        .prefix(".prepare-")
        .tempdir_in(&canonical_store)
        .map_err(|source| io_error(&canonical_store, source))?;
    let archive = staging.path().join("rootfs.tar");
    let rootfs = staging.path().join("rootfs");
    fs::create_dir(&rootfs).map_err(|source| io_error(&rootfs, source))?;
    let container = docker.checked(&["create", &exact_reference])?;
    let container_id = String::from_utf8_lossy(&container.stdout).trim().to_owned();
    if container_id.is_empty() {
        return Err(SandboxError::Docker(
            "docker create did not return a container ID".to_owned(),
        ));
    }
    let export_result = docker.checked_owned(&[
        "export".to_owned(),
        "--output".to_owned(),
        archive.display().to_string(),
        container_id.clone(),
    ]);
    let remove_result = docker.checked(&["rm", &container_id]);
    export_result?;
    remove_result?;
    let export_digest = file_digest(&archive)?;
    let output = Command::new(&tar_program)
        .args([
            OsStr::new("--extract"),
            OsStr::new("--file"),
            archive.as_os_str(),
            OsStr::new("--directory"),
            rootfs.as_os_str(),
            OsStr::new("--no-same-owner"),
            OsStr::new("--numeric-owner"),
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .map_err(|source| io_error(&tar_program, source))?;
    if !output.status.success() {
        return Err(SandboxError::Docker(format!(
            "rootfs extraction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    fs::set_permissions(&rootfs, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .map_err(|source| io_error(&rootfs, source))?;
    fs::remove_file(&archive).map_err(|source| io_error(&archive, source))?;
    let tree = tree_digest(&rootfs)?;
    let metadata = PreparedImage {
        schema_version: PREPARED_SCHEMA_VERSION,
        exact_reference,
        image_id: exact.id,
        export_digest,
        rootfs_digest: tree.digest,
        rootfs_entries: tree.entries,
        rootfs_bytes: tree.bytes,
    };
    let metadata_path = staging.path().join("prepared-image.json");
    let metadata_bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| SandboxError::Lock(format!("encode prepared image: {error}")))?;
    fs::write(&metadata_path, metadata_bytes).map_err(|source| io_error(&metadata_path, source))?;
    let staging_path = staging.into_path();
    fs::rename(&staging_path, &destination).map_err(|source| io_error(&destination, source))?;
    Ok((destination, metadata))
}

pub fn load_prepared(
    image_store: &Path,
    image_id: &str,
    exact_reference: &str,
) -> Result<(PathBuf, PreparedImage), SandboxError> {
    let canonical_store =
        fs::canonicalize(image_store).map_err(|source| io_error(image_store, source))?;
    let directory = canonical_store.join(image_key(image_id)?);
    let metadata_path = directory.join("prepared-image.json");
    let bytes = fs::read(&metadata_path).map_err(|source| io_error(&metadata_path, source))?;
    let metadata: PreparedImage = serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Lock(format!("decode prepared image: {error}")))?;
    if metadata.schema_version != PREPARED_SCHEMA_VERSION
        || metadata.image_id != image_id
        || metadata.exact_reference != exact_reference
    {
        return Err(SandboxError::Lock(
            "prepared image identity does not match the topology lock".to_owned(),
        ));
    }
    let rootfs = fs::canonicalize(directory.join("rootfs"))
        .map_err(|source| io_error(directory.join("rootfs"), source))?;
    if !rootfs.starts_with(&canonical_store) || !rootfs.is_dir() {
        return Err(SandboxError::Lock(
            "prepared rootfs escaped the image store".to_owned(),
        ));
    }
    let observed = tree_digest(&rootfs)?;
    if observed.digest != metadata.rootfs_digest
        || observed.entries != metadata.rootfs_entries
        || observed.bytes != metadata.rootfs_bytes
    {
        return Err(SandboxError::Lock(
            "prepared rootfs integrity check failed".to_owned(),
        ));
    }
    Ok((rootfs, metadata))
}

fn image_key(image_id: &str) -> Result<String, SandboxError> {
    let hex = image_id
        .strip_prefix("sha256:")
        .ok_or_else(|| SandboxError::Lock("prepared image ID is not sha256".to_owned()))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SandboxError::Lock(
            "prepared image ID has invalid sha256 syntax".to_owned(),
        ));
    }
    Ok(hex.to_owned())
}

struct TreeDigest {
    digest: String,
    entries: usize,
    bytes: u64,
}

fn tree_digest(root: &Path) -> Result<TreeDigest, SandboxError> {
    let mut paths = Vec::new();
    collect_paths(root, root, &mut paths)?;
    paths.sort();
    if paths.len() > MAX_TREE_ENTRIES {
        return Err(SandboxError::Lock(
            "prepared rootfs has too many entries".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    for relative in &paths {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        let file_type = metadata.file_type();
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(metadata.mode().to_le_bytes());
        if file_type.is_dir() {
            hasher.update(b"dir");
        } else if file_type.is_symlink() {
            hasher.update(b"symlink");
            let target = fs::read_link(&path).map_err(|source| io_error(&path, source))?;
            hasher.update(target.as_os_str().as_encoded_bytes());
        } else if file_type.is_file() {
            hasher.update(b"file");
            hasher.update(metadata.len().to_le_bytes());
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| SandboxError::Lock("prepared rootfs size overflow".to_owned()))?;
            if total_bytes > MAX_TREE_BYTES {
                return Err(SandboxError::Lock(
                    "prepared rootfs exceeds the byte bound".to_owned(),
                ));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .map_err(|source| io_error(&path, source))?;
            let mut buffer = [0_u8; 1024 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|source| io_error(&path, source))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            return Err(SandboxError::Lock(format!(
                "prepared rootfs contains a special file `{}`",
                relative.display()
            )));
        }
        hasher.update([0xff]);
    }
    Ok(TreeDigest {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
        entries: paths.len(),
        bytes: total_bytes,
    })
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), SandboxError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|source| io_error(directory, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| io_error(directory, source))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| SandboxError::Lock("rootfs traversal escaped".to_owned()))?
            .to_owned();
        paths.push(relative);
        if entry
            .file_type()
            .map_err(|source| io_error(&path, source))?
            .is_dir()
        {
            collect_paths(root, &path, paths)?;
        }
    }
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, SandboxError> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_program(path: &Path, expected_name: &str) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() || path.file_name().and_then(OsStr::to_str) != Some(expected_name) {
        return Err(SandboxError::Lock(format!(
            "{expected_name} program must be an absolute `{expected_name}` path"
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    if !canonical.is_file() {
        return Err(SandboxError::Lock(format!(
            "{expected_name} program is not a regular file"
        )));
    }
    Ok(canonical)
}
