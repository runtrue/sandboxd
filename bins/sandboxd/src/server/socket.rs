use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{
    fs,
    os::unix::{fs::FileTypeExt as _, fs::PermissionsExt as _, net::UnixStream},
    path::Path,
};

pub(super) fn validate_paths(
    socket: &Path,
    state_root: &Path,
    image_store: &Path,
) -> Result<(), SandboxError> {
    if !socket.is_absolute() || !state_root.is_absolute() || !image_store.is_absolute() {
        return Err(SandboxError::Runtime(
            "socket, state root, and image store must be absolute".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn prepare(socket: &Path) -> Result<(), SandboxError> {
    let parent = socket
        .parent()
        .ok_or_else(|| SandboxError::Runtime("socket has no parent directory".to_owned()))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
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
    Ok(())
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
