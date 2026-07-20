mod connection;
mod socket;

use crate::{state::Counters, state::DaemonState};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::{fs::PermissionsExt as _, net::UnixListener},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc, Mutex},
    thread,
    time::Duration,
};

pub(crate) fn serve(
    socket_path: &Path,
    state_root: PathBuf,
    image_store: PathBuf,
    runsc: PathBuf,
    ip: PathBuf,
) -> Result<(), SandboxError> {
    socket::require_root()?;
    socket::validate_paths(socket_path, &state_root, &image_store)?;
    let sandbox_root = state_root.join("sandboxes");
    let snapshot_root = state_root.join("snapshots");
    let recovery = executor::recover(&sandbox_root, &runsc, &ip)?;
    socket::prepare(socket_path)?;
    let listener =
        UnixListener::bind(socket_path).map_err(|source| io_error(socket_path, source))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(socket_path, source))?;
    listener
        .set_nonblocking(true)
        .map_err(|source| io_error(socket_path, source))?;
    let daemon = Arc::new(DaemonState {
        state_root: sandbox_root,
        snapshot_root,
        image_store,
        runsc,
        ip,
        cache: Mutex::new(BTreeMap::new()),
        active: Mutex::new(BTreeSet::new()),
        sandboxes: Mutex::new(BTreeMap::new()),
        counters: Mutex::new(Counters {
            recovered_projects: recovery.recovered_projects,
            ..Counters::default()
        }),
        shutdown: std::sync::atomic::AtomicBool::new(false),
    });
    print_ready(socket_path, &daemon);
    accept_connections(&listener, socket_path, &daemon)?;
    if !daemon.active.lock().expect("active lock").is_empty() {
        return Err(SandboxError::Runtime(
            "shutdown raced with active sandboxes".to_owned(),
        ));
    }
    fs::remove_file(socket_path).map_err(|source| io_error(socket_path, source))
}

fn accept_connections(
    listener: &UnixListener,
    socket_path: &Path,
    daemon: &Arc<DaemonState>,
) -> Result<(), SandboxError> {
    while !daemon.shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let daemon = Arc::clone(daemon);
                thread::spawn(move || {
                    if let Err(error) = connection::serve(stream, &daemon) {
                        eprintln!("runtrue-sandboxd connection: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(source) => return Err(io_error(socket_path, source)),
        }
    }
    Ok(())
}

fn print_ready(socket: &Path, daemon: &DaemonState) {
    println!(
        "{}",
        serde_json::json!({
            "ready": true,
            "socket": socket,
            "recovered_projects": daemon.counters.lock().expect("counter lock").recovered_projects,
        })
    );
}
