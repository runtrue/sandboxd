use super::{WritableRootfs, WritableRootfsExport};
use crate::{io_error, provider::layer::validate_writable_diff, SandboxError};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tar::{Builder, EntryType, Header};

const MAXIMUM_DIFF_ENTRIES: usize = 100_000;
const MAXIMUM_PATH_BYTES: usize = 4_096;
const OVERLAY_OPAQUE_XATTR: &str = "trusted.overlay.opaque";

pub(super) fn export(
    root: &Path,
    rootfs: &WritableRootfs,
    destination: &Path,
) -> Result<WritableRootfsExport, SandboxError> {
    let upper = root.join(&rootfs.key).join("storage/upper");
    if !upper.is_dir() {
        return Err(SandboxError::ImageProvider(
            "writable rootfs upper layer is unavailable".to_owned(),
        ));
    }
    let mut paths = Vec::new();
    collect_paths(&upper, &upper, &mut paths)?;
    paths.sort();
    if paths.len() > MAXIMUM_DIFF_ENTRIES {
        return Err(SandboxError::ImageProvider(
            "writable rootfs diff has too many entries".to_owned(),
        ));
    }
    let maximum_archive_bytes = rootfs.quota_bytes.saturating_mul(2);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|source| io_error(destination, source))?;
    let writer = BoundedWriter::new(file, maximum_archive_bytes);
    let mut archive = Builder::new(writer);
    archive.follow_symlinks(false);
    let mut logical_bytes = 0_u64;
    for relative in &paths {
        let path = upper.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        validate_xattrs(&path, &metadata)?;
        let file_type = metadata.file_type();
        if file_type.is_char_device() {
            if metadata.rdev() != 0 {
                return Err(SandboxError::ImageProvider(
                    "writable rootfs contains a non-whiteout character device".to_owned(),
                ));
            }
            append_whiteout(&mut archive, relative, &metadata)?;
        } else if file_type.is_dir() {
            append_directory(&mut archive, relative, &metadata)?;
            if is_opaque(&path)? {
                append_opaque_whiteout(&mut archive, relative, &metadata)?;
            }
        } else if file_type.is_symlink() {
            append_symlink(&mut archive, relative, &path, &metadata)?;
        } else if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err(SandboxError::ImageProvider(
                    "writable rootfs hard links are not yet portable".to_owned(),
                ));
            }
            logical_bytes = logical_bytes.checked_add(metadata.len()).ok_or_else(|| {
                SandboxError::ImageProvider("writable rootfs logical size overflow".to_owned())
            })?;
            if logical_bytes > rootfs.quota_bytes {
                return Err(SandboxError::ImageProvider(
                    "writable rootfs sparse content exceeds its quota".to_owned(),
                ));
            }
            append_file(&mut archive, relative, &path, &metadata)?;
        } else {
            return Err(SandboxError::ImageProvider(format!(
                "writable rootfs contains unsupported entry `{}`",
                relative.display()
            )));
        }
    }
    archive
        .finish()
        .map_err(|error| archive_error("finish writable rootfs diff", error))?;
    let writer = archive
        .into_inner()
        .map_err(|error| archive_error("finish writable rootfs diff", error))?;
    let archive_bytes = writer.bytes;
    writer
        .inner
        .sync_all()
        .map_err(|source| io_error(destination, source))?;
    Ok(WritableRootfsExport {
        entries: paths.len(),
        logical_bytes,
        archive_bytes,
    })
}

pub(super) fn import(
    root: &Path,
    rootfs: &WritableRootfs,
    source: &Path,
    timeout: Duration,
) -> Result<(), SandboxError> {
    let maximum_archive_bytes = rootfs.quota_bytes.saturating_mul(2);
    validate_writable_diff(
        source,
        maximum_archive_bytes,
        MAXIMUM_DIFF_ENTRIES,
        MAXIMUM_PATH_BYTES,
        timeout,
    )?;
    validate_whiteout_conflicts(source)?;
    let upper = root.join(&rootfs.key).join("storage/upper");
    if fs::read_dir(&upper)
        .map_err(|source| io_error(&upper, source))?
        .next()
        .is_some()
    {
        return Err(SandboxError::ImageProvider(
            "writable rootfs restore target is not empty".to_owned(),
        ));
    }
    let file = File::open(source).map_err(|error| io_error(source, error))?;
    let mut archive = tar::Archive::new(file);
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.set_preserve_mtime(true);
    archive
        .unpack(&upper)
        .map_err(|error| archive_error("unpack writable rootfs diff", error))?;
    convert_whiteouts(&upper)?;
    File::open(&upper)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(&upper, source))
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
            .map_err(|_| SandboxError::ImageProvider("writable rootfs path escaped".to_owned()))?
            .to_owned();
        if relative.as_os_str().as_bytes().len() > MAXIMUM_PATH_BYTES {
            return Err(SandboxError::ImageProvider(
                "writable rootfs path exceeds its limit".to_owned(),
            ));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        paths.push(relative);
        if paths.len() > MAXIMUM_DIFF_ENTRIES {
            return Err(SandboxError::ImageProvider(
                "writable rootfs diff has too many entries".to_owned(),
            ));
        }
        if metadata.file_type().is_dir() {
            collect_paths(root, &path, paths)?;
        }
    }
    Ok(())
}

fn header(
    metadata: &fs::Metadata,
    entry_type: EntryType,
    size: u64,
) -> Result<Header, SandboxError> {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(metadata.mode() & 0o7777);
    header.set_uid(u64::from(metadata.uid()));
    header.set_gid(u64::from(metadata.gid()));
    header.set_size(size);
    let mtime = u64::try_from(metadata.mtime()).map_err(|_| {
        SandboxError::ImageProvider("writable rootfs mtime predates the Unix epoch".to_owned())
    })?;
    header.set_mtime(mtime);
    header.set_cksum();
    Ok(header)
}

fn append_directory<W: Write>(
    archive: &mut Builder<W>,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SandboxError> {
    archive
        .append_data(
            &mut header(metadata, EntryType::Directory, 0)?,
            relative,
            io::empty(),
        )
        .map_err(|error| archive_error("append writable rootfs directory", error))
}

fn append_file<W: Write>(
    archive: &mut Builder<W>,
    relative: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SandboxError> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    archive
        .append_data(
            &mut header(metadata, EntryType::Regular, metadata.len())?,
            relative,
            &mut file,
        )
        .map_err(|error| archive_error("append writable rootfs file", error))
}

fn append_symlink<W: Write>(
    archive: &mut Builder<W>,
    relative: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SandboxError> {
    let target = fs::read_link(path).map_err(|source| io_error(path, source))?;
    if target.as_os_str().as_bytes().is_empty()
        || target.as_os_str().as_bytes().len() > MAXIMUM_PATH_BYTES
    {
        return Err(SandboxError::ImageProvider(
            "writable rootfs symlink target is invalid".to_owned(),
        ));
    }
    archive
        .append_link(
            &mut header(metadata, EntryType::Symlink, 0)?,
            relative,
            target,
        )
        .map_err(|error| archive_error("append writable rootfs symlink", error))
}

fn append_whiteout<W: Write>(
    archive: &mut Builder<W>,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SandboxError> {
    let name = relative.file_name().ok_or_else(|| {
        SandboxError::ImageProvider("writable rootfs whiteout has no name".to_owned())
    })?;
    let mut marker = OsString::from(".wh.");
    marker.push(name);
    let path = relative
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(marker);
    archive
        .append_data(
            &mut header(metadata, EntryType::Regular, 0)?,
            path,
            io::empty(),
        )
        .map_err(|error| archive_error("append writable rootfs whiteout", error))
}

fn append_opaque_whiteout<W: Write>(
    archive: &mut Builder<W>,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SandboxError> {
    archive
        .append_data(
            &mut header(metadata, EntryType::Regular, 0)?,
            relative.join(".wh..wh..opq"),
            io::empty(),
        )
        .map_err(|error| archive_error("append writable rootfs opaque marker", error))
}

fn validate_xattrs(path: &Path, metadata: &fs::Metadata) -> Result<(), SandboxError> {
    for name in xattr::list(path).map_err(|source| io_error(path, source))? {
        if metadata.file_type().is_dir() && name == OsStr::new(OVERLAY_OPAQUE_XATTR) {
            continue;
        }
        if name.as_bytes().starts_with(b"trusted.overlay.") {
            continue;
        }
        return Err(SandboxError::ImageProvider(format!(
            "writable rootfs xattr `{}` is not portable",
            name.to_string_lossy()
        )));
    }
    Ok(())
}

fn is_opaque(path: &Path) -> Result<bool, SandboxError> {
    Ok(xattr::get(path, OVERLAY_OPAQUE_XATTR)
        .map_err(|source| io_error(path, source))?
        .is_some_and(|value| value == b"y"))
}

fn validate_whiteout_conflicts(source: &Path) -> Result<(), SandboxError> {
    let file = File::open(source).map_err(|error| io_error(source, error))?;
    let mut archive = tar::Archive::new(file);
    let mut ordinary = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    for entry in archive
        .entries()
        .map_err(|error| archive_error("read writable rootfs diff", error))?
    {
        let entry = entry.map_err(|error| archive_error("read writable rootfs diff", error))?;
        let path = entry
            .path()
            .map_err(|error| archive_error("read writable rootfs path", error))?
            .into_owned();
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if let Some(target_name) = name.strip_prefix(".wh.") {
            if target_name != ".wh..opq" {
                let target = path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(target_name);
                if ordinary.contains(&target) || !deleted.insert(target) {
                    return Err(SandboxError::ImageProvider(
                        "writable rootfs diff contains conflicting whiteouts".to_owned(),
                    ));
                }
            }
        } else if deleted.contains(&path) || !ordinary.insert(path) {
            return Err(SandboxError::ImageProvider(
                "writable rootfs diff contains conflicting entries".to_owned(),
            ));
        }
    }
    Ok(())
}

fn convert_whiteouts(root: &Path) -> Result<(), SandboxError> {
    let mut paths = Vec::new();
    collect_paths(root, root, &mut paths)?;
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for relative in paths {
        let name = relative.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name == ".wh..wh..opq" {
            let marker = root.join(&relative);
            fs::remove_file(&marker).map_err(|source| io_error(&marker, source))?;
            let parent = marker.parent().expect("opaque marker has a parent");
            xattr::set(parent, OVERLAY_OPAQUE_XATTR, b"y")
                .map_err(|source| io_error(parent, source))?;
        } else if let Some(target_name) = name.strip_prefix(".wh.") {
            let marker = root.join(&relative);
            fs::remove_file(&marker).map_err(|source| io_error(&marker, source))?;
            let target = marker
                .parent()
                .expect("whiteout marker has a parent")
                .join(OsString::from_vec(target_name.as_bytes().to_vec()));
            mknod(&target, SFlag::S_IFCHR, Mode::empty(), makedev(0, 0)).map_err(|error| {
                SandboxError::ImageProvider(format!("create OCI whiteout: {error}"))
            })?;
        }
    }
    Ok(())
}

fn archive_error(operation: &str, error: io::Error) -> SandboxError {
    SandboxError::ImageProvider(format!("{operation}: {error}"))
}

struct BoundedWriter<W> {
    inner: W,
    bytes: u64,
    maximum: u64,
}

impl<W> BoundedWriter<W> {
    const fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            bytes: 0,
            maximum,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::other("writable diff size overflow"))?;
        if next > self.maximum {
            return Err(io::Error::other("writable diff exceeded its archive limit"));
        }
        let written = self.inner.write(buffer)?;
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LockedDescriptor, LockedImage};
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    fn image() -> LockedImage {
        let descriptor = |digit: char, media_type: &str| LockedDescriptor {
            media_type: media_type.to_owned(),
            digest: format!("sha256:{}", digit.to_string().repeat(64)),
            size: 1,
        };
        LockedImage {
            source: "example.test/image:latest".to_owned(),
            exact_reference: format!("example.test/image@sha256:{}", "a".repeat(64)),
            image_id: format!("sha256:{}", "b".repeat(64)),
            index: None,
            manifest: descriptor('a', "application/vnd.oci.image.manifest.v1+json"),
            config: descriptor('b', "application/vnd.oci.image.config.v1+json"),
            layers: vec![descriptor(
                'c',
                "application/vnd.oci.image.layer.v1.tar+gzip",
            )],
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    fn handle(root: &Path, key: &str) -> WritableRootfs {
        let upper = root.join(key).join("storage/upper");
        fs::create_dir_all(&upper).unwrap();
        WritableRootfs {
            provider: "test".to_owned(),
            key: key.to_owned(),
            identity: super::super::WritableRootfsIdentity::new("sandbox", "api").unwrap(),
            image: image(),
            rootfs: root.join(key).join("rootfs"),
            quota_bytes: 16 * 1024 * 1024,
        }
    }

    #[test]
    fn bounded_writer_stops_archive_growth() {
        let mut writer = BoundedWriter::new(Vec::new(), 4);
        assert_eq!(writer.write(b"test").unwrap(), 4);
        assert!(writer.write(b"x").is_err());
    }

    #[test]
    fn portable_diff_round_trip_preserves_basic_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        let source = handle(temporary.path(), "source");
        let source_upper = temporary.path().join("source/storage/upper");
        fs::create_dir(source_upper.join("directory")).unwrap();
        fs::write(source_upper.join("directory/value"), b"retained").unwrap();
        fs::set_permissions(
            source_upper.join("directory/value"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        symlink("directory/value", source_upper.join("link")).unwrap();
        let archive = temporary.path().join("rootfs.tar");

        let exported = export(temporary.path(), &source, &archive).unwrap();
        assert_eq!(exported.logical_bytes, 8);

        let restored = handle(temporary.path(), "restored");
        import(
            temporary.path(),
            &restored,
            &archive,
            Duration::from_secs(5),
        )
        .unwrap();
        let restored_upper = temporary.path().join("restored/storage/upper");
        assert_eq!(
            fs::read(restored_upper.join("directory/value")).unwrap(),
            b"retained"
        );
        assert_eq!(
            fs::symlink_metadata(restored_upper.join("directory/value"))
                .unwrap()
                .mode()
                & 0o777,
            0o640
        );
        let source_metadata = fs::symlink_metadata(source_upper.join("directory/value")).unwrap();
        let restored_metadata =
            fs::symlink_metadata(restored_upper.join("directory/value")).unwrap();
        assert_eq!(restored_metadata.uid(), source_metadata.uid());
        assert_eq!(restored_metadata.gid(), source_metadata.gid());
        assert_eq!(restored_metadata.mtime(), source_metadata.mtime());
        assert_eq!(
            fs::read_link(restored_upper.join("link")).unwrap(),
            Path::new("directory/value")
        );
    }

    #[test]
    fn export_rejects_hard_links_until_inode_identity_is_portable() {
        let temporary = tempfile::tempdir().unwrap();
        let rootfs = handle(temporary.path(), "source");
        let upper = temporary.path().join("source/storage/upper");
        fs::write(upper.join("first"), b"value").unwrap();
        fs::hard_link(upper.join("first"), upper.join("second")).unwrap();
        assert!(export(
            temporary.path(),
            &rootfs,
            &temporary.path().join("diff.tar")
        )
        .is_err());
    }

    #[test]
    fn import_rejects_corrupt_content_without_populating_the_upper_layer() {
        let temporary = tempfile::tempdir().unwrap();
        let restored = handle(temporary.path(), "restored");
        let archive = temporary.path().join("corrupt.tar");
        fs::write(&archive, b"not a tar archive").unwrap();

        assert!(import(
            temporary.path(),
            &restored,
            &archive,
            Duration::from_secs(5),
        )
        .is_err());
        assert!(
            fs::read_dir(temporary.path().join("restored/storage/upper"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}
