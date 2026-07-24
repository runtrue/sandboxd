use std::{
    fs::OpenOptions,
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

const MAXIMUM_CONFIG_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_owner_config(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open `{}`: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect `{}`: {error}", path.display()))?;
    let process_owned =
        metadata.uid() == nix::unistd::geteuid().as_raw() && metadata.mode() & 0o077 == 0;
    let root_group_mounted = metadata.uid() == 0
        && metadata.gid() == nix::unistd::getegid().as_raw()
        && metadata.mode() & 0o037 == 0
        && metadata.mode() & 0o040 != 0;
    if !metadata.is_file() || (!process_owned && !root_group_mounted) {
        return Err(format!(
            "`{}` must be a regular non-symlink owned by the process with mode 0600, or root-owned and process-group-readable with mode 0640 or stricter",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAXIMUM_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read `{}`: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_CONFIG_BYTES {
        return Err(format!(
            "`{}` is empty or exceeds its size limit",
            path.display()
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_database_url(path: &Path) -> Result<String, String> {
    let bytes = read_owner_config(path)?;
    let value =
        String::from_utf8(bytes).map_err(|_| format!("`{}` is not UTF-8", path.display()))?;
    if value.trim() != value || value.contains(['\r', '\n', '\0']) {
        return Err(format!(
            "`{}` contains surrounding whitespace or control characters",
            path.display()
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn database_url_file_is_owner_only_and_exact() {
        let temporary = tempfile::tempdir().expect("temporary");
        let path = temporary.path().join("database-url");
        fs::write(&path, "postgres://localhost/test").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            read_database_url(&path).expect("URL"),
            "postgres://localhost/test"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(read_database_url(&path).is_err());
    }
}
