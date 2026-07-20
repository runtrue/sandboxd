mod config;
mod connection;
mod limit;
mod socket;

pub(crate) use config::ServerConfig;

use crate::{
    assignment::AssignmentLedger,
    audit::AuditLog,
    authorization::{ConnectionEndpoint, WorkOrderVerifier},
    state::{Counters, DaemonState},
};
use limit::ConnectionLimiter;
use nix::{
    errno::Errno,
    poll::{poll, PollFd, PollFlags},
};
use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::{fd::AsFd as _, unix::net::UnixListener},
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

struct BoundEndpoint {
    listener: UnixListener,
    path: PathBuf,
    endpoint: ConnectionEndpoint,
}

impl Drop for BoundEndpoint {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn serve(config: ServerConfig) -> Result<(), SandboxError> {
    socket::require_root()?;
    config.validate()?;
    socket::validate_paths(
        &config.operator_socket,
        config.workload_socket.as_deref(),
        &config.state_root,
        &config.image_store,
    )?;

    let sandbox_root = config.state_root.join("sandboxes");
    let snapshot_root = config.state_root.join("snapshots");
    let control_root = config.state_root.join("control");
    let recovery = executor::recover(&sandbox_root, &config.runsc, &config.ip)?;
    let assignments = AssignmentLedger::open(&control_root)?;
    assignments.reconcile_after_recovery()?;
    let audit = AuditLog::open(&control_root)?;
    let work_orders = config
        .work_order_key
        .as_deref()
        .map(|path| WorkOrderVerifier::from_key_file(path, &control_root))
        .transpose()?;

    let mut endpoints = vec![BoundEndpoint {
        listener: socket::bind_operator(&config.operator_socket)?,
        path: config.operator_socket.clone(),
        endpoint: ConnectionEndpoint::Operator,
    }];
    if let (Some(path), Some(broker_uid)) = (&config.workload_socket, config.broker_uid) {
        endpoints.push(BoundEndpoint {
            listener: socket::bind_workload(path, broker_uid)?,
            path: path.clone(),
            endpoint: ConnectionEndpoint::Workload { broker_uid },
        });
    }

    let daemon = Arc::new(DaemonState {
        state_root: sandbox_root,
        snapshot_root,
        image_store: config.image_store,
        runsc: config.runsc,
        ip: config.ip,
        assignments,
        audit,
        work_orders,
        cache: Mutex::new(BTreeMap::new()),
        active: Mutex::new(BTreeSet::new()),
        sandboxes: Mutex::new(BTreeMap::new()),
        counters: Mutex::new(Counters {
            recovered_projects: recovery.recovered_projects,
            ..Counters::default()
        }),
        tenant_counters: Mutex::new(BTreeMap::new()),
        shutdown: std::sync::atomic::AtomicBool::new(false),
    });
    print_ready(&endpoints, &daemon);
    let limiter = ConnectionLimiter::new(config.maximum_connections);
    accept_connections(&endpoints, &daemon, &limiter, config.io_timeout)?;
    wait_for_connections(&limiter, config.io_timeout)?;
    if !daemon.active.lock().expect("active lock").is_empty() {
        return Err(SandboxError::Runtime(
            "shutdown raced with active sandboxes".to_owned(),
        ));
    }
    Ok(())
}

fn accept_connections(
    endpoints: &[BoundEndpoint],
    daemon: &Arc<DaemonState>,
    limiter: &Arc<ConnectionLimiter>,
    io_timeout: Duration,
) -> Result<(), SandboxError> {
    while !daemon.shutdown.load(Ordering::Acquire) {
        let mut descriptors = endpoints
            .iter()
            .map(|bound| PollFd::new(bound.listener.as_fd(), PollFlags::POLLIN))
            .collect::<Vec<_>>();
        match poll(&mut descriptors, 100_u16) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => {
                return Err(SandboxError::Runtime(format!(
                    "poll control sockets: {error}"
                )))
            }
        }
        let readiness = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or(PollFlags::POLLNVAL))
            .collect::<Vec<_>>();
        drop(descriptors);
        for (bound, events) in endpoints.iter().zip(readiness) {
            if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                return Err(SandboxError::Runtime(format!(
                    "control socket `{}` reported poll error {events:?}",
                    bound.path.display()
                )));
            }
            if events.contains(PollFlags::POLLIN) {
                drain_connections(bound, daemon, limiter, io_timeout)?;
            }
        }
    }
    Ok(())
}

fn drain_connections(
    bound: &BoundEndpoint,
    daemon: &Arc<DaemonState>,
    limiter: &Arc<ConnectionLimiter>,
    io_timeout: Duration,
) -> Result<(), SandboxError> {
    loop {
        let stream = match bound.listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(source) => return Err(io_error(&bound.path, source)),
        };
        let Some(permit) = limiter.try_acquire() else {
            daemon
                .counters
                .lock()
                .expect("counter lock")
                .rejected_connections += 1;
            continue;
        };
        let daemon = Arc::clone(daemon);
        let endpoint = bound.endpoint;
        thread::spawn(move || {
            let _permit = permit;
            if let Err(error) = connection::serve(stream, &daemon, endpoint, io_timeout) {
                eprintln!("runtrue-sandboxd connection: {error}");
            }
        });
    }
}

fn wait_for_connections(
    limiter: &ConnectionLimiter,
    timeout: Duration,
) -> Result<(), SandboxError> {
    let deadline = Instant::now() + timeout;
    while !limiter.is_idle() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if limiter.is_idle() {
        Ok(())
    } else {
        Err(SandboxError::Runtime(
            "connections remained active after shutdown deadline".to_owned(),
        ))
    }
}

fn print_ready(endpoints: &[BoundEndpoint], daemon: &DaemonState) {
    println!(
        "{}",
        serde_json::json!({
            "ready": true,
            "operator_socket": endpoints[0].path,
            "workload_socket": endpoints.get(1).map(|endpoint| &endpoint.path),
            "recovered_projects": daemon.counters.lock().expect("counter lock").recovered_projects,
        })
    );
}
