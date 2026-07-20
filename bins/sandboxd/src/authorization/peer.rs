use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use runtrue_sandbox_oci::SandboxError;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionEndpoint {
    Operator,
    Workload { broker_uid: u32 },
}

pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, SandboxError> {
    getsockopt(stream, PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(|error| SandboxError::Runtime(format!("read peer credentials: {error}")))
}

pub(crate) fn authorize_peer(
    peer_uid: u32,
    endpoint: ConnectionEndpoint,
) -> Result<(), SandboxError> {
    let expected_uid = match endpoint {
        ConnectionEndpoint::Operator => 0,
        ConnectionEndpoint::Workload { broker_uid } => broker_uid,
    };
    if peer_uid != expected_uid {
        return Err(SandboxError::Runtime(
            "control peer is not authorized for this endpoint".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_match_the_connected_process() {
        let (left, _right) = UnixStream::pair().expect("socket pair");
        let uid = nix::unistd::getuid().as_raw();
        assert_eq!(peer_uid(&left).expect("peer UID"), uid);
        authorize_peer(uid, ConnectionEndpoint::Workload { broker_uid: uid })
            .expect("authorized peer");
        assert!(authorize_peer(
            uid,
            ConnectionEndpoint::Workload {
                broker_uid: uid.saturating_add(1)
            }
        )
        .is_err());
    }
}
