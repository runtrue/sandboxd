use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::Path,
};

pub(super) fn validate_paths(
    operator_socket: &Path,
    workload_socket: Option<&Path>,
    state_root: &Path,
    image_store: &Path,
) -> Result<(), SandboxError> {
    if !operator_socket.is_absolute()
        || workload_socket.is_some_and(|path| !path.is_absolute())
        || !state_root.is_absolute()
        || !image_store.is_absolute()
    {
        return Err(SandboxError::Runtime(
            "socket, state root, and image store paths must be absolute".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn bind_operator(socket: &Path) -> Result<UnixListener, SandboxError> {
    bind(socket, 0o700, 0o600, None)
}

pub(super) fn bind_workload(
    socket: &Path,
    broker_uid: u32,
    broker_gid: Option<u32>,
) -> Result<UnixListener, SandboxError> {
    match broker_gid {
        Some(gid) => bind_shared_group(socket, gid),
        None => bind(socket, 0o711, 0o600, Some(broker_uid)),
    }
}

fn bind_shared_group(socket: &Path, broker_gid: u32) -> Result<UnixListener, SandboxError> {
    let parent = socket
        .parent()
        .ok_or_else(|| SandboxError::Runtime("socket has no parent directory".to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let parent_metadata = fs::metadata(parent).map_err(|source| io_error(parent, source))?;
    if parent_metadata.gid() != broker_gid {
        return Err(SandboxError::Runtime(format!(
            "workload socket directory GID {} does not match configured broker GID {broker_gid}",
            parent_metadata.gid()
        )));
    }

    // The setgid directory makes the socket inherit the pre-provisioned shared
    // group, so sandboxd does not need CAP_CHOWN.
    fs::set_permissions(parent, fs::Permissions::from_mode(0o2770))
        .map_err(|source| io_error(parent, source))?;
    let listener = bind(socket, 0o2770, 0o660, None)?;
    let socket_metadata = fs::metadata(socket).map_err(|source| io_error(socket, source))?;
    if socket_metadata.gid() != broker_gid {
        return Err(SandboxError::Runtime(format!(
            "workload socket GID {} does not match configured broker GID {broker_gid}",
            socket_metadata.gid()
        )));
    }
    Ok(listener)
}

fn bind(
    socket: &Path,
    parent_mode: u32,
    socket_mode: u32,
    owner_uid: Option<u32>,
) -> Result<UnixListener, SandboxError> {
    let parent = socket
        .parent()
        .ok_or_else(|| SandboxError::Runtime("socket has no parent directory".to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(parent_mode))
        .map_err(|source| io_error(parent, source))?;
    if socket.exists() {
        let metadata = fs::symlink_metadata(socket).map_err(|source| io_error(socket, source))?;
        if !metadata.file_type().is_socket() {
            return Err(SandboxError::Runtime(format!(
                "refusing to replace non-socket `{}`",
                socket.display()
            )));
        }
        if UnixStream::connect(socket).is_ok() {
            return Err(SandboxError::Runtime(
                "sandboxd socket is already active".to_owned(),
            ));
        }
        fs::remove_file(socket).map_err(|source| io_error(socket, source))?;
    }
    let listener = UnixListener::bind(socket).map_err(|source| io_error(socket, source))?;
    if let Some(uid) = owner_uid {
        nix::unistd::chown(
            socket,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(0)),
        )
        .map_err(|error| SandboxError::Runtime(format!("set workload socket owner: {error}")))?;
    }
    fs::set_permissions(socket, fs::Permissions::from_mode(socket_mode))
        .map_err(|source| io_error(socket, source))?;
    listener
        .set_nonblocking(true)
        .map_err(|source| io_error(socket, source))?;
    Ok(listener)
}

pub(super) fn require_root() -> Result<(), SandboxError> {
    if effective_user_id() != 0 {
        return Err(SandboxError::Runtime(
            "sandboxd requires root for cgroups and network namespaces".to_owned(),
        ));
    }
    Ok(())
}

fn effective_user_id() -> u32 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|uid| uid.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_group_socket_inherits_preprovisioned_group_without_chown() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let gid = fs::metadata(directory.path()).expect("metadata").gid();
        let socket = directory.path().join("workload.sock");

        let _listener = bind_workload(&socket, 65_533, Some(gid)).expect("shared-group socket");
        let directory_metadata = fs::metadata(directory.path()).expect("directory metadata");
        let socket_metadata = fs::metadata(&socket).expect("socket metadata");
        assert_eq!(directory_metadata.mode() & 0o7777, 0o2770);
        assert_eq!(socket_metadata.mode() & 0o777, 0o660);
        assert_eq!(socket_metadata.gid(), gid);
    }

    #[test]
    fn shared_group_socket_rejects_an_unprovisioned_group() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let gid = fs::metadata(directory.path())
            .expect("metadata")
            .gid()
            .saturating_add(1);
        let socket = directory.path().join("workload.sock");

        assert!(bind_workload(&socket, 65_533, Some(gid)).is_err());
        assert!(!socket.exists());
    }
}
