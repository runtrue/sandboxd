use runtrue_sandbox_core::{ResourceCeilings, WorkerId};
use runtrue_sandbox_protocol::WorkerAdvertisement;
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read as _,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::{sleep, timeout},
};
use zeroize::{Zeroize as _, Zeroizing};

const CONFIG_VERSION: u32 = 1;
const MAXIMUM_CONFIG_BYTES: u64 = 64 * 1024;
const MAXIMUM_HTTP_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationConfig {
    schema_version: u32,
    key_id: String,
    secret: String,
    worker_id: WorkerId,
    topology: String,
    resource_shape: String,
    compatibility_cohort: String,
    resource_ceilings: ResourceCeilings,
}

pub(crate) struct RegistrationClient {
    gateway_address: String,
    authorization: String,
    advertisement: WorkerAdvertisement,
    heartbeat_interval: Duration,
    request_timeout: Duration,
    ready: Arc<AtomicBool>,
}

impl RegistrationClient {
    pub(crate) fn load(
        path: &Path,
        gateway_address: &str,
        advertise_ip: IpAddr,
        broker_port: u16,
        heartbeat_interval: Duration,
        request_timeout: Duration,
    ) -> Result<Self, String> {
        validate_gateway_address(gateway_address)?;
        if advertise_ip.is_unspecified()
            || advertise_ip.is_multicast()
            || broker_port == 0
            || heartbeat_interval.is_zero()
            || heartbeat_interval > Duration::from_secs(60)
            || request_timeout.is_zero()
            || request_timeout > heartbeat_interval
        {
            return Err("worker registration network configuration is invalid".to_owned());
        }
        let encoded = Zeroizing::new(read_owner_config(path)?);
        let mut config: RegistrationConfig = serde_json::from_slice(&encoded)
            .map_err(|error| format!("decode worker registration config: {error}"))?;
        if config.schema_version != CONFIG_VERSION
            || !bounded_token(&config.key_id, 64)
            || !bounded_token(&config.secret, 128)
            || config.secret.len() < 32
            || !bounded_label(&config.topology)
            || !bounded_label(&config.resource_shape)
            || !bounded_label(&config.compatibility_cohort)
        {
            return Err("worker registration config is invalid".to_owned());
        }
        config
            .resource_ceilings
            .validate()
            .map_err(|error| error.to_string())?;
        let authorization = format!("Worker {}.{}", config.key_id, config.secret);
        config.secret.zeroize();
        Ok(Self {
            gateway_address: gateway_address.to_owned(),
            authorization,
            advertisement: WorkerAdvertisement {
                worker_id: config.worker_id,
                topology: config.topology,
                resource_shape: config.resource_shape,
                compatibility_cohort: config.compatibility_cohort,
                broker_address: SocketAddr::new(advertise_ip, broker_port),
                resource_ceilings: config.resource_ceilings,
            },
            heartbeat_interval,
            request_timeout,
            ready: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn ready(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ready)
    }

    pub(crate) async fn run(self) {
        let mut registered = false;
        loop {
            let result = if registered {
                self.send(
                    &format!(
                        "/internal/v1/workers/{}/heartbeat",
                        self.advertisement.worker_id
                    ),
                    &[],
                )
                .await
            } else {
                match serde_json::to_vec(&self.advertisement) {
                    Ok(body) => self.send("/internal/v1/workers/register", &body).await,
                    Err(error) => Err(format!("encode worker advertisement: {error}")),
                }
            };
            registered = result.is_ok();
            self.ready.store(registered, Ordering::Release);
            if let Err(error) = result {
                eprintln!("worker registration unavailable: {error}");
            }
            sleep(self.heartbeat_interval).await;
        }
    }

    pub(crate) async fn run_after_socket(self, workload_socket: PathBuf) {
        loop {
            if tokio::fs::symlink_metadata(&workload_socket)
                .await
                .is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        self.run().await;
    }

    async fn send(&self, path: &str, body: &[u8]) -> Result<(), String> {
        timeout(self.request_timeout, self.exchange(path, body))
            .await
            .map_err(|_| "gateway request timed out".to_owned())?
    }

    async fn exchange(&self, path: &str, body: &[u8]) -> Result<(), String> {
        let mut stream = TcpStream::connect(&self.gateway_address)
            .await
            .map_err(|error| format!("connect gateway: {error}"))?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.gateway_address,
            self.authorization,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("write gateway request: {error}"))?;
        stream
            .write_all(body)
            .await
            .map_err(|error| format!("write gateway body: {error}"))?;
        let mut response = Vec::new();
        stream
            .take((MAXIMUM_HTTP_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|error| format!("read gateway response: {error}"))?;
        if response.len() > MAXIMUM_HTTP_RESPONSE_BYTES {
            return Err("gateway response exceeds its size limit".to_owned());
        }
        let status = response
            .split(|byte| *byte == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .ok_or_else(|| "gateway response has no status".to_owned())?;
        if !(status.starts_with("HTTP/1.1 204 ") || status.starts_with("HTTP/1.0 204 ")) {
            return Err(format!(
                "gateway rejected worker registration ({})",
                status.trim_end_matches('\r')
            ));
        }
        Ok(())
    }
}

impl Drop for RegistrationClient {
    fn drop(&mut self) {
        self.authorization.zeroize();
    }
}

fn read_owner_config(path: &Path) -> Result<Vec<u8>, String> {
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
        return Err("worker registration config is empty or oversized".to_owned());
    }
    Ok(bytes)
}

fn validate_gateway_address(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 255
        || value.contains(['/', '@', '#', '?', '\r', '\n', '\0'])
        || !value.contains(':')
    {
        return Err("gateway address must be a bounded host:port pair".to_owned());
    }
    Ok(())
}

fn bounded_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn bounded_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt as _};
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn owner_only_credential_registers_an_exact_advertisement() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("registration.json");
        fs::write(
            &path,
            serde_json::json!({
                "schema_version": 1,
                "key_id": "worker-key-a",
                "secret": "a-secure-worker-token-with-32-bytes",
                "worker_id": "worker-a",
                "topology": "topology-v1",
                "resource_shape": "standard-v1",
                "compatibility_cohort": "runsc-v1",
                "resource_ceilings": {
                    "allowed_guest_profiles": [{"name": "strict", "version": 1}],
                    "maximum_services": 4,
                    "maximum_timeout_ms": 30000,
                    "memory_bytes_per_service": 268435456_u64,
                    "cpu_per_service_millis": 1000,
                    "pids_per_service": 64,
                    "tmpfs_bytes": 67108864,
                    "writable_root_bytes_per_service": 67108864,
                    "maximum_volumes": 8,
                    "maximum_volume_bytes": 536870912,
                    "maximum_output_bytes": 1048576
                }
            })
            .to_string(),
        )
        .expect("config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("gateway");
        let gateway = listener.local_addr().expect("gateway address").to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await.expect("request");
                assert_ne!(read, 0, "request closed before its complete body");
                request.extend_from_slice(&chunk[..read]);
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let header_end = header_end + 4;
                    let headers =
                        std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("Content-Length: ")
                                .and_then(|value| value.parse::<usize>().ok())
                        })
                        .expect("content length");
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }
            }
            let encoded = String::from_utf8(request).expect("UTF-8 request");
            assert!(encoded.starts_with("POST /internal/v1/workers/register HTTP/1.1\r\n"));
            assert!(encoded.contains(
                "\r\nAuthorization: Worker worker-key-a.a-secure-worker-token-with-32-bytes\r\n"
            ));
            assert!(encoded.contains(r#""broker_address":"127.0.0.1:8081""#));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                .await
                .expect("response");
            stream.shutdown().await.expect("close");
        });
        let client = RegistrationClient::load(
            &path,
            &gateway,
            "127.0.0.1".parse().expect("IP"),
            8081,
            Duration::from_secs(10),
            Duration::from_secs(2),
        )
        .expect("client");
        let body = serde_json::to_vec(&client.advertisement).expect("advertisement");
        client
            .send("/internal/v1/workers/register", &body)
            .await
            .expect("register");
        server.await.expect("gateway task");
    }
}
