use super::ImageLimits;
use crate::{LockedDescriptor, SandboxError};
use flate2::read::MultiGzDecoder;
use std::{
    collections::BTreeSet,
    io::{self, Read},
    os::unix::ffi::OsStrExt as _,
    time::Instant,
};

const TAR_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const GZIP_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];
const ZSTD_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

#[derive(Debug, Default)]
pub(crate) struct LayerBudget {
    entries: usize,
    logical_bytes: u64,
    decoded_bytes: u64,
}

pub(crate) fn validate_layer(
    compressed: &mut dyn Read,
    descriptor: &LockedDescriptor,
    limits: &ImageLimits,
    budget: &mut LayerBudget,
    deadline: Instant,
) -> Result<(), SandboxError> {
    let decoder: Box<dyn Read + '_> = if descriptor.media_type == TAR_MEDIA_TYPE
        || descriptor.media_type == "application/vnd.docker.image.rootfs.diff.tar"
    {
        Box::new(compressed)
    } else if GZIP_MEDIA_TYPES.contains(&descriptor.media_type.as_str()) {
        Box::new(MultiGzDecoder::new(compressed))
    } else if descriptor.media_type == ZSTD_MEDIA_TYPE {
        Box::new(
            zstd::stream::read::Decoder::new(compressed).map_err(|error| {
                SandboxError::ImageProvider(format!("initialize zstd OCI layer decoder: {error}"))
            })?,
        )
    } else {
        return Err(SandboxError::ImageProvider(
            "OCI layer compression is unsupported".to_owned(),
        ));
    };
    let maximum_decoded = limits
        .maximum_expanded_bytes
        .checked_sub(budget.decoded_bytes)
        .ok_or_else(|| {
            SandboxError::ImageProvider("image exceeds the decoded byte limit".to_owned())
        })?;
    let limited = DeadlineReader {
        inner: decoder,
        bytes: 0,
        maximum: maximum_decoded,
        deadline,
    };
    let mut archive = tar::Archive::new(limited);
    let mut paths = BTreeSet::new();
    for entry in archive.entries().map_err(layer_error)? {
        check_deadline(deadline)?;
        let mut entry = entry.map_err(layer_error)?;
        let path = normalized_path(&entry.path_bytes(), limits.maximum_path_bytes, "path")?;
        if !paths.insert(path.clone()) {
            return Err(SandboxError::ImageProvider(format!(
                "OCI layer repeats path `{}`",
                String::from_utf8_lossy(&path)
            )));
        }
        budget.entries = budget
            .entries
            .checked_add(1)
            .ok_or_else(|| SandboxError::ImageProvider("layer entry count overflow".to_owned()))?;
        if budget.entries > limits.maximum_entries {
            return Err(SandboxError::ImageProvider(
                "image exceeds the layer entry limit".to_owned(),
            ));
        }
        reject_pax_extensions(&mut entry)?;
        let kind = entry.header().entry_type();
        let size = entry.header().size().map_err(layer_error)?;
        if path == b"." && !kind.is_dir() {
            return Err(SandboxError::ImageProvider(
                "OCI root entry is not a directory".to_owned(),
            ));
        }
        let whiteout = is_whiteout(&path);
        if whiteout && (!kind.is_file() || size != 0) {
            return Err(SandboxError::ImageProvider(
                "OCI whiteout is not an empty regular file".to_owned(),
            ));
        }
        if kind.is_symlink() || kind.is_hard_link() {
            let target = entry.link_name().map_err(layer_error)?.ok_or_else(|| {
                SandboxError::ImageProvider("OCI link omits its target".to_owned())
            })?;
            let target = target.as_os_str().as_bytes();
            if kind.is_hard_link() {
                normalized_path(target, limits.maximum_path_bytes, "hard-link target")?;
            } else if target.is_empty() || target.len() > limits.maximum_path_bytes {
                return Err(SandboxError::ImageProvider(
                    "OCI symbolic-link target is invalid".to_owned(),
                ));
            }
        } else if !(kind.is_file() || kind.is_dir()) {
            return Err(SandboxError::ImageProvider(format!(
                "OCI layer contains unsupported entry `{}`",
                String::from_utf8_lossy(&path)
            )));
        }
        if kind.is_file() && !whiteout {
            budget.logical_bytes = budget.logical_bytes.checked_add(size).ok_or_else(|| {
                SandboxError::ImageProvider("expanded layer size overflow".to_owned())
            })?;
            if budget.logical_bytes > limits.maximum_expanded_bytes {
                return Err(SandboxError::ImageProvider(
                    "image exceeds the expanded byte limit".to_owned(),
                ));
            }
        }
        io::copy(&mut entry, &mut io::sink()).map_err(layer_error)?;
    }
    let mut limited = archive.into_inner();
    io::copy(&mut limited, &mut io::sink()).map_err(layer_error)?;
    budget.decoded_bytes = budget
        .decoded_bytes
        .checked_add(limited.bytes)
        .ok_or_else(|| SandboxError::ImageProvider("decoded layer size overflow".to_owned()))?;
    Ok(())
}

fn normalized_path(bytes: &[u8], maximum: usize, kind: &str) -> Result<Vec<u8>, SandboxError> {
    let bytes = bytes.strip_suffix(b"/").unwrap_or(bytes);
    if bytes == b"." {
        return Ok(bytes.to_vec());
    }
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.starts_with(b"/")
        || bytes
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(SandboxError::ImageProvider(format!(
            "OCI layer {kind} `{}` is not relative and normalized",
            String::from_utf8_lossy(bytes)
        )));
    }
    Ok(bytes.to_vec())
}

fn is_whiteout(path: &[u8]) -> bool {
    path.rsplit(|byte| *byte == b'/')
        .next()
        .is_some_and(|name| name.starts_with(b".wh.") && name.len() > 4)
}

fn reject_pax_extensions<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<(), SandboxError> {
    let Some(extensions) = entry.pax_extensions().map_err(layer_error)? else {
        return Ok(());
    };
    for extension in extensions {
        let extension = extension.map_err(layer_error)?;
        let key = extension.key_bytes();
        if key.starts_with(b"SCHILY.xattr.")
            || key.starts_with(b"LIBARCHIVE.xattr.")
            || key.starts_with(b"GNU.sparse.")
        {
            return Err(SandboxError::ImageProvider(
                "OCI layer contains extended attributes or sparse metadata".to_owned(),
            ));
        }
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<(), SandboxError> {
    if Instant::now() >= deadline {
        return Err(SandboxError::Timeout(
            "validate OCI layer archive".to_owned(),
        ));
    }
    Ok(())
}

fn layer_error(error: io::Error) -> SandboxError {
    SandboxError::ImageProvider(format!("validate OCI layer archive: {error}"))
}

struct DeadlineReader<R> {
    inner: R,
    bytes: u64,
    maximum: u64,
    deadline: Instant,
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OCI layer validation deadline exceeded",
            ));
        }
        let read = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("decoded OCI layer size overflow"))?;
        if self.bytes > self.maximum {
            return Err(io::Error::other(
                "decoded OCI layer exceeds the expanded byte limit",
            ));
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::{io::Cursor, time::Duration};
    use tar::{Builder, EntryType, Header};

    fn descriptor(media_type: &str, size: usize) -> LockedDescriptor {
        LockedDescriptor {
            media_type: media_type.to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size: size as u64,
        }
    }

    fn regular(builder: &mut Builder<Vec<u8>>, path: &str, contents: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_entry_type(EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(contents))
            .unwrap();
    }

    fn finish(builder: Builder<Vec<u8>>) -> Vec<u8> {
        builder.into_inner().unwrap()
    }

    fn validate(bytes: &[u8], limits: &ImageLimits) -> Result<(), SandboxError> {
        let mut reader = Cursor::new(bytes);
        validate_layer(
            &mut reader,
            &descriptor(TAR_MEDIA_TYPE, bytes.len()),
            limits,
            &mut LayerBudget::default(),
            Instant::now() + Duration::from_secs(5),
        )
    }

    #[test]
    fn corpus_rejects_traversal_absolute_and_hardlink_escapes() {
        assert!(normalized_path(b"../host", 4_096, "path").is_err());
        assert!(normalized_path(b"/etc/passwd", 4_096, "path").is_err());

        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Link);
        header.set_size(0);
        builder
            .append_link(&mut header, "inside", "../outside")
            .unwrap();
        assert!(validate(&finish(builder), &ImageLimits::default()).is_err());
    }

    #[test]
    fn corpus_bounds_symlinks_and_accepts_valid_whiteouts() {
        let mut builder = Builder::new(Vec::new());
        let mut link = Header::new_gnu();
        link.set_entry_type(EntryType::Symlink);
        link.set_size(0);
        builder.append_link(&mut link, "var/run", "/run").unwrap();
        regular(&mut builder, "etc/.wh.removed", b"");
        assert!(validate(&finish(builder), &ImageLimits::default()).is_ok());
    }

    #[test]
    fn accepts_gzip_and_zstd_layers() {
        let mut builder = Builder::new(Vec::new());
        regular(&mut builder, "payload", b"safe");
        let archive = finish(builder);

        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        io::copy(&mut Cursor::new(&archive), &mut gzip).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut gzip_reader = Cursor::new(&gzip);
        assert!(validate_layer(
            &mut gzip_reader,
            &descriptor(GZIP_MEDIA_TYPES[0], gzip.len()),
            &ImageLimits::default(),
            &mut LayerBudget::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .is_ok());

        let zstd = zstd::stream::encode_all(Cursor::new(&archive), 1).unwrap();
        let mut zstd_reader = Cursor::new(&zstd);
        assert!(validate_layer(
            &mut zstd_reader,
            &descriptor(ZSTD_MEDIA_TYPE, zstd.len()),
            &ImageLimits::default(),
            &mut LayerBudget::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .is_ok());
    }

    #[test]
    fn corpus_rejects_duplicate_special_xattr_and_sparse_entries() {
        let mut duplicate = Builder::new(Vec::new());
        regular(&mut duplicate, "same", b"first");
        regular(&mut duplicate, "same", b"second");
        assert!(validate(&finish(duplicate), &ImageLimits::default()).is_err());

        let mut special = Builder::new(Vec::new());
        let mut fifo = Header::new_gnu();
        fifo.set_entry_type(EntryType::Fifo);
        fifo.set_size(0);
        fifo.set_cksum();
        special.append_data(&mut fifo, "fifo", io::empty()).unwrap();
        assert!(validate(&finish(special), &ImageLimits::default()).is_err());

        let mut attributed = Builder::new(Vec::new());
        attributed
            .append_pax_extensions([("SCHILY.xattr.user.bad", b"value".as_slice())])
            .unwrap();
        regular(&mut attributed, "attributed", b"content");
        assert!(validate(&finish(attributed), &ImageLimits::default()).is_err());

        let mut sparse = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::GNUSparse);
        header.set_size(0);
        header.set_cksum();
        sparse
            .append_data(&mut header, "sparse", io::empty())
            .unwrap();
        assert!(validate(&finish(sparse), &ImageLimits::default()).is_err());
    }

    #[test]
    fn corpus_rejects_sparse_expansion_and_compression_bombs() {
        let mut builder = Builder::new(Vec::new());
        regular(&mut builder, "expanded", &vec![0_u8; 64 * 1024]);
        let archive = finish(builder);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        io::copy(&mut Cursor::new(archive), &mut encoder).unwrap();
        let compressed = encoder.finish().unwrap();
        let limits = ImageLimits {
            maximum_expanded_bytes: 4 * 1024,
            ..ImageLimits::default()
        };
        let mut reader = Cursor::new(&compressed);
        assert!(validate_layer(
            &mut reader,
            &descriptor(GZIP_MEDIA_TYPES[0], compressed.len()),
            &limits,
            &mut LayerBudget::default(),
            Instant::now() + Duration::from_secs(5),
        )
        .is_err());
    }
}
