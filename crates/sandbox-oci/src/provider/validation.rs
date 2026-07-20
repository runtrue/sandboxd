use super::{ImageLimits, ImagePlatform};
use crate::{io_error, LockedDescriptor, LockedImage, SandboxError};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

const ALLOWED_MANIFEST_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];
const ALLOWED_INDEX_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const ALLOWED_CONFIG_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
];
const ALLOWED_LAYER_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

pub(crate) struct RootfsMeasurement {
    pub(crate) digest: String,
    pub(crate) entries: usize,
    pub(crate) bytes: u64,
}

pub(crate) fn validate_locked_image(
    image: &LockedImage,
    limits: &ImageLimits,
) -> Result<(), SandboxError> {
    if image.operating_system != "linux"
        || !matches!(image.architecture.as_str(), "amd64" | "arm64")
        || image.image_id != image.config.digest
        || image.exact_reference != exact_reference(image)?
        || image.layers.is_empty()
        || image.layers.len() > limits.maximum_layers
    {
        return Err(SandboxError::ImageProvider(
            "locked image identity or platform is invalid".to_owned(),
        ));
    }
    validate_descriptor(
        "manifest",
        &image.manifest,
        limits.maximum_manifest_bytes,
        ALLOWED_MANIFEST_MEDIA_TYPES,
    )?;
    validate_descriptor(
        "config",
        &image.config,
        limits.maximum_config_bytes,
        ALLOWED_CONFIG_MEDIA_TYPES,
    )?;
    if let Some(index) = &image.index {
        validate_descriptor(
            "index",
            index,
            limits.maximum_manifest_bytes,
            ALLOWED_INDEX_MEDIA_TYPES,
        )?;
    }
    let mut compressed = 0_u64;
    let mut digests = BTreeSet::new();
    for layer in &image.layers {
        validate_descriptor(
            "layer",
            layer,
            limits.maximum_compressed_bytes,
            ALLOWED_LAYER_MEDIA_TYPES,
        )?;
        if !digests.insert(&layer.digest) {
            return Err(SandboxError::ImageProvider(
                "image repeats a layer descriptor".to_owned(),
            ));
        }
        compressed = compressed
            .checked_add(layer.size)
            .ok_or_else(|| SandboxError::ImageProvider("layer size overflow".to_owned()))?;
    }
    if compressed > limits.maximum_compressed_bytes {
        return Err(SandboxError::ImageProvider(
            "image exceeds the compressed byte limit".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_platform(
    image: &LockedImage,
    platform: &ImagePlatform,
) -> Result<(), SandboxError> {
    if image.operating_system != platform.operating_system
        || image.architecture != platform.architecture
        || image.variant != platform.variant
    {
        return Err(SandboxError::ImageProvider(format!(
            "locked image platform {}/{}{} does not match provider platform {}",
            image.operating_system,
            image.architecture,
            image
                .variant
                .as_ref()
                .map_or_else(String::new, |variant| format!("/{variant}")),
            platform.as_containerd_platform()
        )));
    }
    Ok(())
}

fn validate_descriptor(
    kind: &str,
    descriptor: &LockedDescriptor,
    maximum_bytes: u64,
    allowed_media_types: &[&str],
) -> Result<(), SandboxError> {
    if !valid_digest(&descriptor.digest)
        || descriptor.size == 0
        || descriptor.size > maximum_bytes
        || !allowed_media_types.contains(&descriptor.media_type.as_str())
    {
        return Err(SandboxError::ImageProvider(format!(
            "{kind} descriptor is invalid or exceeds policy"
        )));
    }
    Ok(())
}

fn exact_reference(image: &LockedImage) -> Result<String, SandboxError> {
    let (repository, _) = image
        .exact_reference
        .rsplit_once('@')
        .ok_or_else(|| SandboxError::ImageProvider("image reference is not pinned".to_owned()))?;
    if repository.is_empty() || repository.starts_with('-') {
        return Err(SandboxError::ImageProvider(
            "image repository is invalid".to_owned(),
        ));
    }
    Ok(format!("{repository}@{}", image.manifest.digest))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn measure_rootfs(
    root: &Path,
    limits: &ImageLimits,
) -> Result<RootfsMeasurement, SandboxError> {
    let mut paths = Vec::new();
    collect_paths(root, root, limits, &mut paths)?;
    paths.sort();
    if paths.len() > limits.maximum_entries {
        return Err(SandboxError::ImageProvider(
            "rootfs exceeds the entry limit".to_owned(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    for relative in &paths {
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if xattr::list(&path)
            .map_err(|source| io_error(&path, source))?
            .next()
            .is_some()
        {
            return Err(SandboxError::ImageProvider(format!(
                "rootfs entry `{}` contains extended attributes",
                relative.display()
            )));
        }
        let file_type = metadata.file_type();
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(metadata.mode().to_le_bytes());
        if file_type.is_dir() {
            hasher.update(b"dir");
        } else if file_type.is_symlink() {
            hasher.update(b"symlink");
            let target = fs::read_link(&path).map_err(|source| io_error(&path, source))?;
            if target.as_os_str().as_encoded_bytes().len() > limits.maximum_path_bytes {
                return Err(SandboxError::ImageProvider(
                    "rootfs symlink target exceeds the path limit".to_owned(),
                ));
            }
            hasher.update(target.as_os_str().as_encoded_bytes());
        } else if file_type.is_file() {
            hasher.update(b"file");
            hasher.update(metadata.len().to_le_bytes());
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| SandboxError::ImageProvider("rootfs size overflow".to_owned()))?;
            if total_bytes > limits.maximum_expanded_bytes {
                return Err(SandboxError::ImageProvider(
                    "rootfs exceeds the expanded byte limit".to_owned(),
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
            return Err(SandboxError::ImageProvider(format!(
                "rootfs contains special file `{}`",
                relative.display()
            )));
        }
    }
    Ok(RootfsMeasurement {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
        entries: paths.len(),
        bytes: total_bytes,
    })
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    limits: &ImageLimits,
    paths: &mut Vec<PathBuf>,
) -> Result<(), SandboxError> {
    for entry in fs::read_dir(directory).map_err(|source| io_error(directory, source))? {
        let entry = entry.map_err(|source| io_error(directory, source))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| SandboxError::ImageProvider("rootfs traversal escaped".to_owned()))?
            .to_owned();
        if relative.as_os_str().as_encoded_bytes().len() > limits.maximum_path_bytes {
            return Err(SandboxError::ImageProvider(
                "rootfs path exceeds the path limit".to_owned(),
            ));
        }
        paths.push(relative);
        if paths.len() > limits.maximum_entries {
            return Err(SandboxError::ImageProvider(
                "rootfs exceeds the entry limit".to_owned(),
            ));
        }
        if entry
            .file_type()
            .map_err(|source| io_error(&path, source))?
            .is_dir()
        {
            collect_paths(root, &path, limits, paths)?;
        }
    }
    Ok(())
}

pub(crate) fn mount_state(target: &Path) -> Result<Option<bool>, SandboxError> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|source| io_error("/proc/self/mountinfo", source))?;
    let target = target.as_os_str().as_encoded_bytes();
    for line in mountinfo.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            continue;
        }
        let mountpoint = decode_mount_path(fields[4])?;
        if mountpoint == target {
            return Ok(Some(fields[5].split(',').any(|option| option == "ro")));
        }
    }
    Ok(None)
}

pub(crate) fn mount_is_read_only(target: &Path) -> Result<bool, SandboxError> {
    Ok(mount_state(target)? == Some(true))
}

fn decode_mount_path(value: &str) -> Result<Vec<u8>, SandboxError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..=index + 3].iter().all(u8::is_ascii_digit)
            {
                return Err(SandboxError::ImageProvider(
                    "mountinfo contains an invalid escaped path".to_owned(),
                ));
            }
            let octal = std::str::from_utf8(&bytes[index + 1..=index + 3])
                .map_err(|_| SandboxError::ImageProvider("invalid mountinfo path".to_owned()))?;
            decoded.push(u8::from_str_radix(octal, 8).map_err(|_| {
                SandboxError::ImageProvider("invalid mountinfo path escape".to_owned())
            })?);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn descriptor(media_type: &str, digit: char, size: u64) -> LockedDescriptor {
        LockedDescriptor {
            media_type: media_type.to_owned(),
            digest: format!("sha256:{}", digit.to_string().repeat(64)),
            size,
        }
    }

    fn image() -> LockedImage {
        let manifest = descriptor(ALLOWED_MANIFEST_MEDIA_TYPES[0], '1', 100);
        let config = descriptor(ALLOWED_CONFIG_MEDIA_TYPES[0], '2', 100);
        LockedImage {
            source: "example.test/app:latest".to_owned(),
            exact_reference: format!("example.test/app@{}", manifest.digest),
            image_id: config.digest.clone(),
            index: None,
            manifest,
            config,
            layers: vec![descriptor(ALLOWED_LAYER_MEDIA_TYPES[1], '3', 100)],
            operating_system: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            variant: None,
        }
    }

    #[test]
    fn rejects_duplicate_layers_and_oversized_images() {
        let limits = ImageLimits::default();
        let mut locked = image();
        assert!(validate_locked_image(&locked, &limits).is_ok());
        locked.layers.push(locked.layers[0].clone());
        assert!(validate_locked_image(&locked, &limits).is_err());

        let mut locked = image();
        locked.layers[0].size = limits.maximum_compressed_bytes + 1;
        assert!(validate_locked_image(&locked, &limits).is_err());
    }

    #[test]
    fn rejects_platform_and_digest_identity_mismatches() {
        let limits = ImageLimits::default();
        let mut wrong_platform = image();
        wrong_platform.architecture = "arm64".to_owned();
        wrong_platform.variant = Some("../../host".to_owned());
        assert!(validate_platform(&wrong_platform, &ImagePlatform::linux_amd64()).is_err());

        let mut wrong_manifest = image();
        wrong_manifest.manifest.digest = format!("sha256:{}", "9".repeat(64));
        assert!(validate_locked_image(&wrong_manifest, &limits).is_err());

        let mut wrong_config = image();
        wrong_config.config.digest = format!("sha256:{}", "8".repeat(64));
        assert!(validate_locked_image(&wrong_config, &limits).is_err());
    }

    #[test]
    fn rootfs_scan_rejects_special_files_and_bounds_paths() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("file"), b"content").unwrap();
        symlink("file", temporary.path().join("link")).unwrap();
        let measured = measure_rootfs(temporary.path(), &ImageLimits::default()).unwrap();
        assert_eq!(measured.entries, 2);
        assert_eq!(measured.bytes, 7);

        let limits = ImageLimits {
            maximum_path_bytes: 2,
            ..ImageLimits::default()
        };
        assert!(measure_rootfs(temporary.path(), &limits).is_err());
    }

    #[test]
    fn rootfs_corpus_rejects_special_files_xattrs_and_sparse_expansion() {
        let special = tempfile::tempdir().unwrap();
        nix::unistd::mkfifo(
            &special.path().join("guest-fifo"),
            nix::sys::stat::Mode::S_IRUSR,
        )
        .unwrap();
        assert!(measure_rootfs(special.path(), &ImageLimits::default()).is_err());

        let attributed = tempfile::tempdir().unwrap();
        let attributed_file = attributed.path().join("capability");
        fs::write(&attributed_file, b"content").unwrap();
        xattr::set(&attributed_file, "user.runtrue-test", b"untrusted").unwrap();
        assert!(measure_rootfs(attributed.path(), &ImageLimits::default()).is_err());

        let sparse = tempfile::tempdir().unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(sparse.path().join("sparse"))
            .unwrap()
            .set_len(1_024 * 1_024)
            .unwrap();
        let limits = ImageLimits {
            maximum_expanded_bytes: 1_024,
            ..ImageLimits::default()
        };
        assert!(measure_rootfs(sparse.path(), &limits).is_err());
    }

    #[test]
    fn rootfs_corpus_hashes_symlinks_without_following_them() {
        let temporary = tempfile::tempdir().unwrap();
        symlink("../../../../etc/passwd", temporary.path().join("escape")).unwrap();
        let measured = measure_rootfs(temporary.path(), &ImageLimits::default()).unwrap();
        assert_eq!(measured.entries, 1);
        assert_eq!(measured.bytes, 0);
    }

    #[test]
    fn mountinfo_octal_paths_decode() {
        assert_eq!(decode_mount_path("/tmp/a\\040b").unwrap(), b"/tmp/a b");
        assert!(decode_mount_path("/tmp/invalid\\xx").is_err());
    }
}
