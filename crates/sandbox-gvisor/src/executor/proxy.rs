use crate::SandboxError;
use runtrue_sandbox_oci::{is_protected_destination, HttpScheme, NetworkPolicy, NetworkProfile};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _, UdpSocket},
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const PROXY_PORT: u16 = 3128;
const DNS_PORT: u16 = 53;
const MAXIMUM_HEADER_BYTES: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct PolicyServices {
    stop: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    endpoints: Vec<IngressEndpoint>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IngressEndpoint {
    pub service: String,
    pub container_port: u16,
    pub host_endpoint: SocketAddr,
    pub bearer_token: String,
}

#[derive(Debug)]
struct Shared {
    policy: NetworkPolicy,
    stop: Arc<AtomicBool>,
    active_connections: AtomicU32,
    transferred_bytes: AtomicU64,
    dns_queries: AtomicU32,
    dns_bytes: AtomicU64,
    bandwidth: Mutex<Bandwidth>,
    connections: Mutex<Vec<JoinHandle<()>>>,
}

#[derive(Debug)]
struct Bandwidth {
    available: Instant,
}

struct ConnectionGuard<'a>(&'a AtomicU32);

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl PolicyServices {
    pub(super) fn start_userspace(
        socket_path: &Path,
        policy: &NetworkPolicy,
    ) -> Result<Self, SandboxError> {
        if policy.profile != NetworkProfile::HttpConnect || !policy.ingress.is_empty() {
            return Err(SandboxError::Unsupported(
                "userspace transport currently supports HTTP egress without ingress".to_owned(),
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicBool::new(false));
        let shared = shared_policy(policy, &stop);
        let listener = UnixListener::bind(socket_path).map_err(|error| {
            SandboxError::Runtime(format!("bind userspace egress transport: {error}"))
        })?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666)).map_err(|error| {
            SandboxError::Runtime(format!(
                "set userspace egress transport permissions: {error}"
            ))
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            SandboxError::Runtime(format!("configure userspace egress transport: {error}"))
        })?;
        let thread_shared = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("sandbox-userspace-http".to_owned())
            .spawn(move || serve_unix_proxy(listener, &thread_shared))
            .map_err(|error| {
                SandboxError::Runtime(format!("start userspace HTTP policy proxy: {error}"))
            })?;
        Ok(Self {
            stop,
            active,
            shared,
            threads: vec![thread],
            endpoints: Vec::new(),
        })
    }

    pub(super) fn start(
        gateway: IpAddr,
        guest: IpAddr,
        policy: &NetworkPolicy,
    ) -> Result<Option<Self>, SandboxError> {
        if policy.profile == NetworkProfile::None && policy.ingress.is_empty() {
            return Ok(None);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicBool::new(false));
        let shared = shared_policy(policy, &stop);
        let dns = if policy.profile == NetworkProfile::None {
            None
        } else {
            let dns = UdpSocket::bind(SocketAddr::new(gateway, DNS_PORT)).map_err(|error| {
                SandboxError::Runtime(format!("bind policy DNS resolver: {error}"))
            })?;
            dns.set_read_timeout(Some(Duration::from_millis(200)))
                .map_err(|error| {
                    SandboxError::Runtime(format!("configure policy DNS resolver: {error}"))
                })?;
            Some(dns)
        };
        let proxy_listener = if policy.profile == NetworkProfile::HttpConnect {
            let listener =
                TcpListener::bind(SocketAddr::new(gateway, PROXY_PORT)).map_err(|error| {
                    SandboxError::Runtime(format!("bind HTTP CONNECT policy proxy: {error}"))
                })?;
            listener.set_nonblocking(true).map_err(|error| {
                SandboxError::Runtime(format!("configure HTTP CONNECT policy proxy: {error}"))
            })?;
            Some(listener)
        } else {
            None
        };
        let mut prepared_ingress = Vec::new();
        for rule in &policy.ingress {
            let listener =
                TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
                    SandboxError::Runtime(format!("allocate ingress endpoint: {error}"))
                })?;
            listener.set_nonblocking(true).map_err(|error| {
                SandboxError::Runtime(format!("configure ingress endpoint: {error}"))
            })?;
            let endpoint = IngressEndpoint {
                service: rule.service.clone(),
                container_port: rule.container_port,
                host_endpoint: listener.local_addr().map_err(|error| {
                    SandboxError::Runtime(format!("read ingress endpoint: {error}"))
                })?,
                bearer_token: random_token()?,
            };
            prepared_ingress.push((listener, endpoint));
        }
        let endpoints = prepared_ingress
            .iter()
            .map(|(_, endpoint)| endpoint.clone())
            .collect();
        let mut services = Self {
            stop,
            active,
            shared: Arc::clone(&shared),
            threads: Vec::new(),
            endpoints,
        };
        if let Some(dns) = dns {
            let dns_shared = Arc::clone(&shared);
            services.threads.push(
                thread::Builder::new()
                    .name("sandbox-policy-dns".to_owned())
                    .spawn(move || serve_dns(dns, &dns_shared))
                    .map_err(|error| {
                        SandboxError::Runtime(format!("start policy DNS resolver: {error}"))
                    })?,
            );
        }
        if let Some(listener) = proxy_listener {
            let proxy_shared = Arc::clone(&shared);
            services.threads.push(
                thread::Builder::new()
                    .name("sandbox-policy-http".to_owned())
                    .spawn(move || serve_proxy(listener, &proxy_shared))
                    .map_err(|error| {
                        SandboxError::Runtime(format!("start HTTP CONNECT policy proxy: {error}"))
                    })?,
            );
        }
        for (listener, endpoint) in prepared_ingress {
            let ingress_shared = Arc::clone(&shared);
            let ingress_active = Arc::clone(&services.active);
            let destination = SocketAddr::new(guest, endpoint.container_port);
            services.threads.push(
                thread::Builder::new()
                    .name("sandbox-policy-ingress".to_owned())
                    .spawn(move || {
                        serve_ingress(
                            listener,
                            destination,
                            &endpoint,
                            &ingress_active,
                            &ingress_shared,
                        );
                    })
                    .map_err(|error| {
                        SandboxError::Runtime(format!("start ingress endpoint: {error}"))
                    })?,
            );
        }
        Ok(Some(services))
    }

    pub(super) fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Release);
    }

    pub(super) fn endpoints(&self) -> &[IngressEndpoint] {
        &self.endpoints
    }
}

fn shared_policy(policy: &NetworkPolicy, stop: &Arc<AtomicBool>) -> Arc<Shared> {
    Arc::new(Shared {
        policy: policy.clone(),
        stop: Arc::clone(stop),
        active_connections: AtomicU32::new(0),
        transferred_bytes: AtomicU64::new(0),
        dns_queries: AtomicU32::new(0),
        dns_bytes: AtomicU64::new(0),
        bandwidth: Mutex::new(Bandwidth {
            available: Instant::now(),
        }),
        connections: Mutex::new(Vec::new()),
    })
}

impl Drop for PolicyServices {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        for connection in self
            .shared
            .connections
            .lock()
            .expect("policy connection lock")
            .drain(..)
        {
            let _ = connection.join();
        }
    }
}

fn serve_unix_proxy(listener: UnixListener, shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if !try_acquire_connection(shared) {
                    let _ = stream
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let connection_shared = Arc::clone(shared);
                match thread::Builder::new()
                    .name("sandbox-userspace-http-connection".to_owned())
                    .spawn(move || {
                        let _ = handle_unix_proxy(stream, &connection_shared);
                    }) {
                    Ok(connection) => track_connection(shared, connection),
                    Err(_) => {
                        shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn serve_proxy(listener: TcpListener, shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if !try_acquire_connection(shared) {
                    let _ = stream
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let connection_shared = Arc::clone(shared);
                match thread::Builder::new()
                    .name("sandbox-policy-http-connection".to_owned())
                    .spawn(move || {
                        let _ = handle_proxy(stream, &connection_shared);
                    }) {
                    Ok(connection) => track_connection(shared, connection),
                    Err(_) => {
                        shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn serve_ingress(
    listener: TcpListener,
    destination: SocketAddr,
    endpoint: &IngressEndpoint,
    active: &Arc<AtomicBool>,
    shared: &Arc<Shared>,
) {
    while !shared.stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut client, _)) => {
                if !active.load(Ordering::Acquire) {
                    let _ = client.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                if !try_acquire_connection(shared) {
                    let _ = client
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let endpoint = endpoint.clone();
                let active = Arc::clone(active);
                let connection_shared = Arc::clone(shared);
                match thread::Builder::new()
                    .name("sandbox-policy-ingress-connection".to_owned())
                    .spawn(move || {
                        let _ = handle_ingress(
                            &mut client,
                            destination,
                            &endpoint,
                            &active,
                            &connection_shared,
                        );
                    }) {
                    Ok(connection) => track_connection(shared, connection),
                    Err(_) => {
                        shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_ingress(
    client: &mut TcpStream,
    destination: SocketAddr,
    endpoint: &IngressEndpoint,
    active: &AtomicBool,
    shared: &Shared,
) -> io::Result<()> {
    let _guard = ConnectionGuard(&shared.active_connections);
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let header = read_header(client)?;
    if !authorized_ingress(&header, &endpoint.bearer_token) {
        client.write_all(
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }
    if !active.load(Ordering::Acquire) {
        client.write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let mut upstream = TcpStream::connect_timeout(&destination, IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(IO_TIMEOUT))?;
    upstream.write_all(&strip_ingress_authorization(&header)?)?;
    relay_ingress(client, &mut upstream, active, &shared.stop)
}

fn authorized_ingress(header: &[u8], token: &str) -> bool {
    std::str::from_utf8(header).ok().is_some_and(|header| {
        header.split("\r\n").skip(1).any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    && value.trim().strip_prefix("Bearer ") == Some(token)
            })
        })
    })
}

fn strip_ingress_authorization(header: &[u8]) -> io::Result<Vec<u8>> {
    let end = header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("incomplete ingress header"))?
        + 4;
    let text = std::str::from_utf8(&header[..end])
        .map_err(|_| io::Error::other("ingress header is not UTF-8"))?;
    let mut result = Vec::new();
    for (index, line) in text.split("\r\n").enumerate() {
        if line.is_empty() {
            break;
        }
        if index != 0
            && line.split_once(':').is_some_and(|(name, _)| {
                name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("connection")
            })
        {
            continue;
        }
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }
    result.extend_from_slice(b"Connection: close\r\n\r\n");
    result.extend_from_slice(&header[end..]);
    Ok(result)
}

fn relay_ingress(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    active: &AtomicBool,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    thread::scope(|scope| {
        let first =
            scope.spawn(|| copy_ingress(&mut client_reader, &mut upstream_writer, active, stop));
        let second = copy_ingress(upstream, client, active, stop);
        let first = first
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("ingress relay panicked")));
        first.and(second).map(|_| ())
    })
}

fn copy_ingress(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    active: &AtomicBool,
    stop: &AtomicBool,
) -> io::Result<u64> {
    let mut total = 0;
    let mut buffer = [0_u8; 16 * 1024];
    while active.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => {
                writer.write_all(&buffer[..read])?;
                total += read as u64;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

fn random_token() -> Result<String, SandboxError> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| SandboxError::Runtime(format!("generate ingress credential: {error}")))?;
    Ok(hex::encode(bytes))
}

fn handle_proxy(mut client: TcpStream, shared: &Shared) -> io::Result<()> {
    let _guard = ConnectionGuard(&shared.active_connections);
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = read_header(&mut client)?;
    let parsed =
        parse_request(&request).ok_or_else(|| io::Error::other("invalid proxy request"))?;
    if !shared
        .policy
        .permits_http(&parsed.domain, parsed.scheme, parsed.port)
    {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let destination = resolve_public(&parsed.domain, parsed.port)?;
    let mut upstream = TcpStream::connect_timeout(&destination, IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(IO_TIMEOUT))?;
    if parsed.connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        reserve_bytes(
            &shared.transferred_bytes,
            shared.policy.limits.maximum_bytes,
            parsed.forward_header.len() as u64,
        )?;
        throttle(
            &shared.bandwidth,
            shared.policy.limits.bandwidth_bytes_per_second,
            parsed.forward_header.len() as u64,
        );
        upstream.write_all(&parsed.forward_header)?;
    }
    relay(client, upstream, shared)
}

fn handle_unix_proxy(mut client: UnixStream, shared: &Shared) -> io::Result<()> {
    let _guard = ConnectionGuard(&shared.active_connections);
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))?;
    let request = read_header(&mut client)?;
    let parsed =
        parse_request(&request).ok_or_else(|| io::Error::other("invalid proxy request"))?;
    if !shared
        .policy
        .permits_http(&parsed.domain, parsed.scheme, parsed.port)
    {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }
    let destination = resolve_public(&parsed.domain, parsed.port)?;
    let mut upstream = TcpStream::connect_timeout(&destination, IO_TIMEOUT)?;
    upstream.set_read_timeout(Some(IO_TIMEOUT))?;
    upstream.set_write_timeout(Some(IO_TIMEOUT))?;
    if parsed.connect {
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    } else {
        reserve_bytes(
            &shared.transferred_bytes,
            shared.policy.limits.maximum_bytes,
            parsed.forward_header.len() as u64,
        )?;
        throttle(
            &shared.bandwidth,
            shared.policy.limits.bandwidth_bytes_per_second,
            parsed.forward_header.len() as u64,
        );
        upstream.write_all(&parsed.forward_header)?;
    }
    relay_unix(client, upstream, shared)
}

fn try_acquire_connection(shared: &Shared) -> bool {
    shared
        .active_connections
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < shared.policy.limits.maximum_connections).then_some(active + 1)
        })
        .is_ok()
}

fn track_connection(shared: &Shared, connection: JoinHandle<()>) {
    let mut connections = shared.connections.lock().expect("policy connection lock");
    connections.retain(|connection| !connection.is_finished());
    connections.push(connection);
}

struct ParsedRequest {
    domain: String,
    port: u16,
    scheme: HttpScheme,
    connect: bool,
    forward_header: Vec<u8>,
}

fn read_header(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = [0_u8; 1024];
    while result.len() < MAXIMUM_HEADER_BYTES {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        result.extend_from_slice(&buffer[..read]);
        if result.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(result);
        }
    }
    Err(io::Error::other("proxy header is incomplete or oversized"))
}

fn parse_request(bytes: &[u8]) -> Option<ParsedRequest> {
    let end = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let header = std::str::from_utf8(&bytes[..end]).ok()?;
    let mut lines = header.split("\r\n");
    let first = lines.next()?;
    let mut fields = first.split_whitespace();
    let method = fields.next()?;
    let target = fields.next()?;
    let version = fields.next()?;
    if fields.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    if method == "CONNECT" {
        let (domain, port) = parse_authority(target, 443)?;
        return Some(ParsedRequest {
            domain,
            port,
            scheme: HttpScheme::Https,
            connect: true,
            forward_header: Vec::new(),
        });
    }
    let (scheme, remainder, default_port) = target
        .strip_prefix("http://")
        .map(|value| (HttpScheme::Http, value, 80))
        .or_else(|| {
            target
                .strip_prefix("https://")
                .map(|value| (HttpScheme::Https, value, 443))
        })?;
    let split = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..split];
    let path = remainder
        .get(split..)
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let (domain, port) = parse_authority(authority, default_port)?;
    let mut forward = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, _) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        forward.extend_from_slice(line.as_bytes());
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"Connection: close\r\n\r\n");
    forward.extend_from_slice(&bytes[end..]);
    Some(ParsedRequest {
        domain,
        port,
        scheme,
        connect: false,
        forward_header: forward,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() || authority.contains(['@', '/', '#', '?', '[', ']']) {
        return None;
    }
    let (domain, port) = authority.rsplit_once(':').map_or_else(
        || Some((authority, default_port)),
        |(domain, port)| Some((domain, port.parse::<u16>().ok()?)),
    )?;
    if domain.is_empty() || port == 0 || domain.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some((domain.to_ascii_lowercase(), port))
}

fn resolve_public(domain: &str, port: u16) -> io::Result<SocketAddr> {
    (domain, port)
        .to_socket_addrs()?
        .find(|address| !is_protected_destination(address.ip()))
        .ok_or_else(|| io::Error::other("destination resolved only to protected addresses"))
}

fn relay(client: TcpStream, upstream: TcpStream, shared: &Shared) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let stop = Arc::clone(&shared.stop);
    let bytes = &shared.transferred_bytes;
    let maximum = shared.policy.limits.maximum_bytes;
    let rate = shared.policy.limits.bandwidth_bytes_per_second;
    thread::scope(|scope| {
        let first = scope.spawn(|| {
            copy_limited(
                &mut client_reader,
                &mut upstream_writer,
                &stop,
                bytes,
                maximum,
                rate,
                &shared.bandwidth,
            )
        });
        let second = copy_limited(
            &mut upstream.try_clone()?,
            &mut client.try_clone()?,
            &shared.stop,
            bytes,
            maximum,
            rate,
            &shared.bandwidth,
        );
        let first = first
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("relay panicked")));
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        first.and(second).map(|_| ())
    })
}

fn relay_unix(client: UnixStream, upstream: TcpStream, shared: &Shared) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let stop = Arc::clone(&shared.stop);
    let bytes = &shared.transferred_bytes;
    let maximum = shared.policy.limits.maximum_bytes;
    let rate = shared.policy.limits.bandwidth_bytes_per_second;
    thread::scope(|scope| {
        let first = scope.spawn(|| {
            copy_limited(
                &mut client_reader,
                &mut upstream_writer,
                &stop,
                bytes,
                maximum,
                rate,
                &shared.bandwidth,
            )
        });
        let second = copy_limited(
            &mut upstream.try_clone()?,
            &mut client.try_clone()?,
            &shared.stop,
            bytes,
            maximum,
            rate,
            &shared.bandwidth,
        );
        let first = first
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("userspace relay panicked")));
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        first.and(second).map(|_| ())
    })
}

#[allow(clippy::too_many_arguments)]
fn copy_limited(
    reader: &mut impl Read,
    writer: &mut impl Write,
    stop: &AtomicBool,
    bytes: &AtomicU64,
    maximum: u64,
    rate: u64,
    bandwidth: &Mutex<Bandwidth>,
) -> io::Result<u64> {
    let mut total = 0;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(total);
        }
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        reserve_bytes(bytes, maximum, read as u64)?;
        throttle(bandwidth, rate, read as u64);
        writer.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

fn reserve_bytes(counter: &AtomicU64, maximum: u64, amount: u64) -> io::Result<()> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
            used.checked_add(amount).filter(|next| *next <= maximum)
        })
        .map(|_| ())
        .map_err(|_| io::Error::other("sandbox egress byte limit exceeded"))
}

fn throttle(bandwidth: &Mutex<Bandwidth>, rate: u64, amount: u64) {
    let duration = Duration::from_secs_f64(amount as f64 / rate as f64);
    let sleep_until = {
        let mut state = bandwidth.lock().expect("bandwidth lock");
        let now = Instant::now();
        if state.available < now {
            state.available = now;
        }
        state.available += duration;
        state.available
    };
    thread::sleep(sleep_until.saturating_duration_since(Instant::now()));
}

fn serve_dns(socket: UdpSocket, shared: &Shared) {
    let maximum = shared.policy.dns.maximum_response_bytes as usize;
    let mut buffer = vec![0_u8; maximum.max(512)];
    while !shared.stop.load(Ordering::Acquire) {
        match socket.recv_from(&mut buffer) {
            Ok((size, peer)) => {
                if let Some(response) = dns_response(&buffer[..size], shared) {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

fn dns_response(request: &[u8], shared: &Shared) -> Option<Vec<u8>> {
    if request.len() < 17
        || request[2] & 0x80 != 0
        || u16::from_be_bytes([request[4], request[5]]) != 1
        || shared
            .dns_queries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queries| {
                (queries < shared.policy.dns.maximum_queries).then_some(queries + 1)
            })
            .is_err()
    {
        return None;
    }
    reserve_bytes(
        &shared.dns_bytes,
        shared.policy.dns.maximum_total_bytes,
        request.len() as u64,
    )
    .ok()?;
    let (name, question_end) = parse_dns_question(request)?;
    let query_type = u16::from_be_bytes([request[question_end - 4], request[question_end - 3]]);
    let query_class = u16::from_be_bytes([request[question_end - 2], request[question_end - 1]]);
    if query_class != 1 || !matches!(query_type, 1 | 28) {
        return Some(dns_error(request, question_end, 4));
    }
    let addresses = (name.as_str(), 0)
        .to_socket_addrs()
        .ok()?
        .map(|address| address.ip())
        .filter(|address| match shared.policy.profile {
            NetworkProfile::HttpConnect => {
                shared.policy.permits_dns_name(&name) && !is_protected_destination(*address)
            }
            NetworkProfile::RestrictedTcp => shared.policy.tcp_rules.iter().any(|rule| {
                rule.ports
                    .iter()
                    .any(|port| shared.policy.permits_tcp(*address, *port))
            }),
            NetworkProfile::None => false,
        })
        .filter(|address| {
            matches!(
                (query_type, address),
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(8)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Some(dns_error(request, question_end, 3));
    }
    let mut response = Vec::with_capacity(question_end + addresses.len() * 28);
    response.extend_from_slice(&request[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..question_end]);
    for address in addresses {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&30_u32.to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
        }
    }
    if response.len() > shared.policy.dns.maximum_response_bytes as usize
        || reserve_bytes(
            &shared.dns_bytes,
            shared.policy.dns.maximum_total_bytes,
            response.len() as u64,
        )
        .is_err()
    {
        None
    } else {
        Some(response)
    }
}

fn parse_dns_question(request: &[u8]) -> Option<(String, usize)> {
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < request.len() {
        let length = usize::from(request[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset.checked_add(length)? > request.len() {
            return None;
        }
        let label = std::str::from_utf8(&request[offset..offset + length]).ok()?;
        if label.is_empty()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }
    let end = offset.checked_add(4)?;
    (end <= request.len() && !labels.is_empty()).then(|| (labels.join("."), end))
}

fn dns_error(request: &[u8], question_end: usize, code: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(question_end);
    response.extend_from_slice(&request[..2]);
    response.extend_from_slice(&(0x8180_u16 | code).to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..question_end]);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_oci::{HttpEgressRule, NetworkPolicy};

    #[test]
    fn parses_connect_and_absolute_form_without_ip_literals() {
        let connect =
            parse_request(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n").expect("CONNECT");
        assert_eq!(connect.domain, "api.example.com");
        assert_eq!(connect.port, 443);
        assert!(connect.connect);
        let http = parse_request(
            b"GET http://api.example.com/v1 HTTP/1.1\r\nHost: api.example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .expect("HTTP");
        assert_eq!(
            http.forward_header,
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"
        );
        assert!(parse_request(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn dns_parser_rejects_compression_in_queries() {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x03api\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(
            parse_dns_question(&query),
            Some(("api.example.com".to_owned(), query.len()))
        );
        query[12] = 0xc0;
        assert!(parse_dns_question(&query).is_none());
    }

    #[test]
    fn policy_check_is_applied_before_resolution() {
        let policy = NetworkPolicy {
            profile: NetworkProfile::HttpConnect,
            http_rules: vec![HttpEgressRule {
                domains: vec!["api.example.com".to_owned()],
                schemes: vec![HttpScheme::Https],
                ports: vec![443],
            }],
            ..NetworkPolicy::default()
        };
        assert!(policy.permits_http("api.example.com", HttpScheme::Https, 443));
        assert!(!policy.permits_http("example.com", HttpScheme::Https, 443));
    }

    #[test]
    fn userspace_transport_denies_before_host_resolution() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket = directory.path().join("egress.sock");
        let policy = NetworkPolicy {
            profile: NetworkProfile::HttpConnect,
            http_rules: vec![HttpEgressRule {
                domains: vec!["api.example.com".to_owned()],
                schemes: vec![HttpScheme::Https],
                ports: vec![443],
            }],
            ..NetworkPolicy::default()
        };
        let services = PolicyServices::start_userspace(&socket, &policy).expect("transport");
        let mut client = UnixStream::connect(&socket).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        client
            .write_all(b"CONNECT denied.invalid:443 HTTP/1.1\r\n\r\n")
            .expect("request");
        let mut response = [0_u8; 128];
        let read = client.read(&mut response).expect("response");
        assert!(response[..read].starts_with(b"HTTP/1.1 403 Forbidden"));
        drop(client);
        drop(services);
    }

    #[test]
    fn ingress_authentication_is_exact_and_not_forwarded() {
        let header = b"GET / HTTP/1.1\r\nHost: service\r\nAuthorization: Bearer secret-token\r\nX-Test: retained\r\n\r\nbody";
        assert!(authorized_ingress(header, "secret-token"));
        assert!(!authorized_ingress(header, "secret"));
        assert_eq!(
            strip_ingress_authorization(header).expect("stripped header"),
            b"GET / HTTP/1.1\r\nHost: service\r\nX-Test: retained\r\nConnection: close\r\n\r\nbody"
        );
    }

    #[test]
    fn aggregate_byte_limit_is_atomic_under_concurrency() {
        let counter = AtomicU64::new(0);
        thread::scope(|scope| {
            let results = (0..64)
                .map(|_| scope.spawn(|| reserve_bytes(&counter, 32, 1).is_ok()))
                .collect::<Vec<_>>();
            assert_eq!(
                results
                    .into_iter()
                    .map(|result| result.join().expect("limit worker"))
                    .filter(|allowed| *allowed)
                    .count(),
                32
            );
        });
        assert_eq!(counter.load(Ordering::Acquire), 32);
    }
}
