use clap::Parser;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const MAXIMUM_HEADER_BYTES: usize = 16 * 1024;
const MAXIMUM_ROUTES: usize = 16;

#[derive(Debug, Parser)]
#[command(version, about = "Capability-free sandbox userspace network agent")]
struct Cli {
    #[arg(long, default_value = "/run/lock/ingress.json")]
    ingress_configuration: PathBuf,
    #[arg(long)]
    ingress_service: Vec<String>,
    #[arg(long, default_value = "/run/lock/egress.sock")]
    egress_socket: PathBuf,
    #[arg(long, default_value = "127.0.0.1:3128")]
    egress_listen: SocketAddr,
    #[arg(long, default_value_t = 32)]
    maximum_egress_connections: u32,
    #[arg(long, default_value_t = 30_000)]
    idle_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressConfiguration {
    schema_version: u32,
    sandbox: String,
    routes: Vec<IngressRoute>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressRoute {
    service: String,
    container_port: u16,
    socket: PathBuf,
    credential: String,
}

#[derive(Clone)]
struct RouteIdentity {
    service: String,
    container_port: u16,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("runtrue-sandbox-net-agent: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    validate_cli(&cli)?;
    let configuration = read_configuration(&cli.ingress_configuration)?;
    let selected = cli.ingress_service.iter().cloned().collect::<BTreeSet<_>>();
    if selected.len() != cli.ingress_service.len() {
        return Err("an ingress service was selected more than once".to_owned());
    }
    let mut installed = BTreeSet::new();
    for route in configuration.routes {
        if !selected.contains(&route.service) {
            continue;
        }
        installed.insert(route.service.clone());
        let identity = RouteIdentity {
            service: route.service,
            container_port: route.container_port,
        };
        let configuration_path = cli.ingress_configuration.clone();
        let timeout = Duration::from_millis(cli.idle_timeout_ms);
        thread::Builder::new()
            .name(format!("runtrue-ingress-{}", identity.service))
            .spawn(move || serve_ingress(identity, configuration_path, timeout))
            .map_err(|error| format!("start ingress route: {error}"))?;
    }
    if !selected.is_subset(&installed) {
        return Err("an ingress service selection is not declared by the policy".to_owned());
    }
    serve_egress(
        cli.egress_listen,
        cli.egress_socket,
        cli.maximum_egress_connections,
        Duration::from_millis(cli.idle_timeout_ms),
    )
}

fn validate_cli(cli: &Cli) -> Result<(), String> {
    if !cli.egress_listen.ip().is_loopback() || cli.egress_listen.port() == 0 {
        return Err("the egress proxy must listen on a nonzero loopback port".to_owned());
    }
    if cli.maximum_egress_connections == 0 || cli.maximum_egress_connections > 4_096 {
        return Err("maximum egress connections must be between 1 and 4096".to_owned());
    }
    if !(100..=300_000).contains(&cli.idle_timeout_ms) {
        return Err("idle timeout must be between 100 and 300000 milliseconds".to_owned());
    }
    validate_transport_path(&cli.egress_socket, "egress.sock")
}

fn read_configuration(path: &Path) -> Result<IngressConfiguration, String> {
    if path != Path::new("/run/lock/ingress.json") {
        return Err("ingress configuration must be /run/lock/ingress.json".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| format!("read ingress configuration: {error}"))?;
    if bytes.len() > 64 * 1024 {
        return Err("ingress configuration exceeds 64 KiB".to_owned());
    }
    let configuration: IngressConfiguration = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode ingress configuration: {error}"))?;
    validate_configuration(&configuration)?;
    Ok(configuration)
}

fn validate_configuration(configuration: &IngressConfiguration) -> Result<(), String> {
    if configuration.schema_version != 1
        || configuration.sandbox.is_empty()
        || configuration.sandbox.len() > 128
        || !configuration
            .sandbox
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || configuration.routes.len() > MAXIMUM_ROUTES
    {
        return Err("ingress configuration identity or size is invalid".to_owned());
    }
    let mut identities = BTreeSet::new();
    for (index, route) in configuration.routes.iter().enumerate() {
        if route.service.is_empty()
            || route.service.len() > 63
            || !route
                .service
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || route.container_port == 0
            || route.credential.len() != 64
            || !route
                .credential
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !identities.insert((route.service.as_str(), route.container_port))
        {
            return Err("an ingress route is invalid or duplicated".to_owned());
        }
        validate_transport_path(&route.socket, &format!("ingress-{index}.sock"))?;
    }
    Ok(())
}

fn validate_transport_path(path: &Path, expected_name: &str) -> Result<(), String> {
    if path.parent() != Some(Path::new("/run/lock"))
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        return Err(format!(
            "userspace transport must be /run/lock/{expected_name}"
        ));
    }
    Ok(())
}

fn serve_egress(
    address: SocketAddr,
    transport: PathBuf,
    maximum_connections: u32,
    timeout: Duration,
) -> Result<(), String> {
    let listener =
        TcpListener::bind(address).map_err(|error| format!("bind egress proxy: {error}"))?;
    let active = Arc::new(AtomicU32::new(0));
    for accepted in listener.incoming() {
        let mut client = match accepted {
            Ok(client) => client,
            Err(error) => return Err(format!("accept egress client: {error}")),
        };
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < maximum_connections).then_some(current + 1)
            })
            .is_err()
        {
            let _ =
                client.write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n");
            continue;
        }
        let connection_active = Arc::clone(&active);
        let connection_transport = transport.clone();
        if thread::Builder::new()
            .name("runtrue-egress".to_owned())
            .spawn(move || {
                let _guard = ConnectionGuard(connection_active);
                let _ = handle_egress(&mut client, &connection_transport, timeout);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

struct ConnectionGuard(Arc<AtomicU32>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_egress(client: &mut TcpStream, transport: &Path, timeout: Duration) -> io::Result<()> {
    let mut policy = UnixStream::connect(transport)?;
    client.set_read_timeout(Some(timeout))?;
    client.set_write_timeout(Some(timeout))?;
    policy.set_read_timeout(Some(timeout))?;
    policy.set_write_timeout(Some(timeout))?;
    relay(client, &mut policy)
}

fn serve_ingress(identity: RouteIdentity, configuration_path: PathBuf, timeout: Duration) {
    loop {
        if let Ok(configuration) = read_configuration(&configuration_path) {
            if let Some(route) = route_for_identity(&configuration, &identity) {
                let _ = run_ingress_once(route, timeout);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn route_for_identity<'a>(
    configuration: &'a IngressConfiguration,
    identity: &RouteIdentity,
) -> Option<&'a IngressRoute> {
    configuration.routes.iter().find(|route| {
        route.service == identity.service && route.container_port == identity.container_port
    })
}

fn run_ingress_once(route: &IngressRoute, timeout: Duration) -> io::Result<()> {
    let mut tunnel = UnixStream::connect(&route.socket)?;
    tunnel.set_read_timeout(Some(timeout))?;
    tunnel.set_write_timeout(Some(timeout))?;
    tunnel.write_all(format!("RUNTRUE-TUNNEL/1 {}\r\n\r\n", route.credential).as_bytes())?;
    let response = read_header(&mut tunnel)?;
    if response != b"RUNTRUE-TUNNEL/1 200 READY\r\n\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reverse tunnel registration was rejected",
        ));
    }
    tunnel.set_read_timeout(None)?;
    tunnel.set_write_timeout(None)?;
    let mut service = TcpStream::connect_timeout(
        &SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            route.container_port,
        ),
        timeout,
    )?;
    service.set_read_timeout(None)?;
    service.set_write_timeout(None)?;
    relay(&mut service, &mut tunnel)
}

fn read_header(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut byte = [0_u8; 1];
    while result.len() < MAXIMUM_HEADER_BYTES {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        result.push(byte[0]);
        if result.ends_with(b"\r\n\r\n") {
            return Ok(result);
        }
    }
    Err(io::Error::other(
        "network-agent header is incomplete or oversized",
    ))
}

fn relay(left: &mut TcpStream, right: &mut UnixStream) -> io::Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    thread::scope(|scope| {
        let outgoing = scope.spawn(|| {
            let result = copy(&mut left_reader, &mut right_writer);
            let _ = right_writer.shutdown(Shutdown::Write);
            result
        });
        let incoming = copy(right, left);
        let _ = left.shutdown(Shutdown::Write);
        let outgoing = outgoing
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("network-agent relay panicked")));
        let _ = left.shutdown(Shutdown::Both);
        let _ = right.shutdown(Shutdown::Both);
        outgoing.and(incoming).map(|_| ())
    })
}

fn copy(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<u64> {
    let mut total = 0;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rejects_undeclared_paths_and_duplicate_routes() {
        let mut configuration = IngressConfiguration {
            schema_version: 1,
            sandbox: "sandbox-epoch-1".to_owned(),
            routes: vec![IngressRoute {
                service: "server".to_owned(),
                container_port: 8080,
                socket: "/run/lock/ingress-0.sock".into(),
                credential: "a".repeat(64),
            }],
        };
        validate_configuration(&configuration).expect("configuration");
        configuration.routes.push(configuration.routes[0].clone());
        assert!(validate_configuration(&configuration).is_err());
        configuration.routes.pop();
        configuration.routes[0].socket = "/tmp/ingress.sock".into();
        assert!(validate_configuration(&configuration).is_err());
    }

    #[test]
    fn reconnect_selects_the_current_epoch_credential() {
        let identity = RouteIdentity {
            service: "server".to_owned(),
            container_port: 8080,
        };
        let mut configuration = IngressConfiguration {
            schema_version: 1,
            sandbox: "sandbox-epoch-1".to_owned(),
            routes: vec![IngressRoute {
                service: identity.service.clone(),
                container_port: identity.container_port,
                socket: "/run/lock/ingress-0.sock".into(),
                credential: "a".repeat(64),
            }],
        };
        assert_eq!(
            route_for_identity(&configuration, &identity)
                .expect("first epoch")
                .credential,
            "a".repeat(64)
        );
        configuration.sandbox = "sandbox-epoch-2".to_owned();
        configuration.routes[0].credential = "b".repeat(64);
        assert_eq!(
            route_for_identity(&configuration, &identity)
                .expect("second epoch")
                .credential,
            "b".repeat(64)
        );
    }

    #[test]
    fn egress_agent_relays_to_the_policy_transport() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let transport = directory.path().join("egress.sock");
        let listener = std::os::unix::net::UnixListener::bind(&transport).expect("transport");
        let tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("TCP listener");
        let address = tcp.local_addr().expect("TCP address");
        let policy = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("policy connection");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("policy request");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").expect("policy response");
        });
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("client");
            stream.write_all(b"ping").expect("client request");
            let mut response = [0_u8; 4];
            stream.read_exact(&mut response).expect("client response");
            assert_eq!(&response, b"pong");
        });
        let (mut accepted, _) = tcp.accept().expect("agent client");
        handle_egress(&mut accepted, &transport, Duration::from_secs(1)).expect("egress relay");
        client.join().expect("client thread");
        policy.join().expect("policy thread");
    }

    #[test]
    fn ingress_agent_authenticates_and_relays_to_the_declared_service() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let transport = directory.path().join("ingress.sock");
        let tunnel_listener =
            std::os::unix::net::UnixListener::bind(&transport).expect("tunnel transport");
        let service_listener =
            TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("service listener");
        let service_port = service_listener
            .local_addr()
            .expect("service address")
            .port();
        let route = IngressRoute {
            service: "server".to_owned(),
            container_port: service_port,
            socket: transport,
            credential: "b".repeat(64),
        };
        let agent_route = route.clone();
        let agent = thread::spawn(move || {
            run_ingress_once(&agent_route, Duration::from_secs(2)).expect("ingress relay")
        });
        let service = thread::spawn(move || {
            let (mut stream, _) = service_listener.accept().expect("service connection");
            let request = read_header(&mut stream).expect("service request");
            assert!(request.starts_with(b"GET /ready HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .expect("service response");
        });

        let (mut tunnel, _) = tunnel_listener.accept().expect("tunnel connection");
        tunnel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("tunnel timeout");
        let registration = read_header(&mut tunnel).expect("registration");
        assert_eq!(
            registration,
            format!("RUNTRUE-TUNNEL/1 {}\r\n\r\n", route.credential).as_bytes()
        );
        tunnel
            .write_all(b"RUNTRUE-TUNNEL/1 200 READY\r\n\r\n")
            .expect("registration response");
        tunnel
            .write_all(b"GET /ready HTTP/1.1\r\nHost: sandbox\r\n\r\n")
            .expect("ingress request");
        tunnel.shutdown(Shutdown::Write).expect("request shutdown");
        let mut response = Vec::new();
        tunnel.read_to_end(&mut response).expect("ingress response");
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

        agent.join().expect("agent thread");
        service.join().expect("service thread");
    }
}
