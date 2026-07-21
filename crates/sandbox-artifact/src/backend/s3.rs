use super::{local::read_master_key, BlobBackend, PutStatus, StoredObject};
use crate::{
    repository::ArtifactRepository, ArtifactError, ArtifactLimits, ArtifactStore,
    GarbageCollectionReport, MaterializedSnapshot, PublicationMetrics, SnapshotPublication,
    SnapshotTransferClaim, SnapshotTransferGrant,
};
use runtrue_sandbox_core::{RestoreTarget, SnapshotId, SnapshotPortability};
use s3_wire::{
    AbortMultipartUploadRequest, AddressingStyle, ByteStream, DeleteObjectRequest, Endpoint,
    ErrorCategory, GetObjectRequest, HeadObjectRequest, ListMultipartUploadsRequest,
    ListObjectsV2Request, ManagedMultipartUploadRequest, ObjectKey, PutObjectRequest,
    RetryClassification, S3Client, S3Config, S3Error,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime},
};
use tokio::runtime::Runtime;
use zeroize::Zeroize;

const S3_LIST_PAGE_SIZE: usize = 1_000;
const MULTIPART_LOCK_BODY: &[u8] = b"runtrue-sandboxd multipart publication lock\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ArtifactConfig {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub key_prefix: String,
    pub virtual_hosted: bool,
    pub allow_http_for_local_testing: bool,
    pub credentials_file: Option<PathBuf>,
}

pub struct S3ArtifactStore {
    repository: ArtifactRepository,
    backend: Arc<S3Backend>,
    limits: ArtifactLimits,
}

impl S3ArtifactStore {
    pub fn open(
        config: S3ArtifactConfig,
        key_path: &Path,
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let master_key = read_master_key(key_path)?;
        Self::new(config, master_key, limits)
    }

    pub fn new(
        config: S3ArtifactConfig,
        master_key: [u8; 32],
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let key_prefix = validate_key_prefix(&config.key_prefix)?;
        let endpoint = config
            .endpoint
            .as_deref()
            .map_or_else(|| Endpoint::for_aws_region(&config.region), Endpoint::new);
        let endpoint = endpoint.map_err(map_s3_error)?;
        let mut builder = S3Config::builder()
            .endpoint(endpoint)
            .region(config.region)
            .bucket(config.bucket)
            .addressing_style(if config.virtual_hosted {
                AddressingStyle::VirtualHosted
            } else {
                AddressingStyle::Path
            })
            .operation_timeout(limits.operation_timeout);
        if config.allow_http_for_local_testing {
            builder = builder.allow_http_for_local_testing();
        }
        if let Some(path) = config.credentials_file {
            builder =
                builder.credentials_provider(Arc::new(RotatingFileCredentialsProvider::new(path)?));
        }
        let client = S3Client::new(builder.build().map_err(map_s3_error)?).map_err(map_s3_error)?;
        Self::from_client(client, key_prefix, master_key, limits)
    }

    pub fn from_client(
        client: S3Client,
        key_prefix: String,
        master_key: [u8; 32],
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        let minimum_cleanup_grace = limits
            .operation_timeout
            .checked_mul(2)
            .ok_or_else(|| ArtifactError::Invalid("S3 cleanup grace overflow".to_owned()))?;
        if limits.garbage_collection_grace < minimum_cleanup_grace {
            return Err(ArtifactError::Invalid(
                "S3 garbage-collection grace must be at least twice the operation timeout"
                    .to_owned(),
            ));
        }
        let key_prefix = validate_key_prefix(&key_prefix)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("sandbox-artifact-s3")
            .build()
            .map_err(|error| ArtifactError::Storage(format!("create S3 runtime: {error}")))?;
        let backend = Arc::new(S3Backend {
            client,
            runtime: Arc::new(runtime),
            key_prefix,
        });
        let repository = ArtifactRepository::new(backend.clone(), master_key, limits.clone())?;
        Ok(Self {
            repository,
            backend,
            limits,
        })
    }
}

struct RotatingFileCredentialsProvider {
    path: PathBuf,
}

impl RotatingFileCredentialsProvider {
    fn new(path: PathBuf) -> Result<Self, ArtifactError> {
        read_credentials_file(&path).map_err(map_s3_error)?;
        Ok(Self { path })
    }
}

#[async_trait::async_trait]
impl s3_wire::CredentialsProvider for RotatingFileCredentialsProvider {
    async fn provide_credentials(&self) -> Result<s3_wire::Credentials, S3Error> {
        read_credentials_file(&self.path)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsFile {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

impl Drop for CredentialsFile {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

fn read_credentials_file(path: &Path) -> Result<s3_wire::Credentials, S3Error> {
    if !path.is_absolute() {
        return Err(credentials_error(
            "S3 credentials file path must be absolute",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| credentials_error("open S3 credentials file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| credentials_error("inspect S3 credentials file"))?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > 16 * 1024
    {
        return Err(credentials_error(
            "S3 credentials file must be an owner-only regular file of at most 16 KiB",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| credentials_error("read S3 credentials file"))?;
    let credentials = serde_json::from_slice::<CredentialsFile>(&bytes);
    bytes.zeroize();
    let credentials = credentials.map_err(|_| credentials_error("decode S3 credentials file"))?;
    s3_wire::Credentials::new(
        credentials.access_key_id.clone(),
        credentials.secret_access_key.clone(),
        credentials.session_token.clone(),
    )
}

fn credentials_error(message: &str) -> S3Error {
    S3Error::new(
        ErrorCategory::Authentication,
        message,
        RetryClassification::Never,
    )
}

impl ArtifactStore for S3ArtifactStore {
    fn snapshot_portability(&self) -> SnapshotPortability {
        SnapshotPortability::CrossWorkerSameBackend
    }

    fn publish_transfer_grant(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<SnapshotTransferGrant, ArtifactError> {
        self.repository.publish_transfer_grant(scope, snapshot_id)
    }

    fn claim_transfer(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &SnapshotId,
        target: &RestoreTarget,
    ) -> Result<SnapshotTransferClaim, ArtifactError> {
        self.repository.claim_transfer(scope, snapshot_id, target)
    }

    fn publish(
        &self,
        publication: SnapshotPublication,
    ) -> Result<PublicationMetrics, ArtifactError> {
        self.repository.publish(publication)
    }

    fn materialize(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &SnapshotId,
        destination: &Path,
    ) -> Result<MaterializedSnapshot, ArtifactError> {
        self.repository.materialize(scope, snapshot_id, destination)
    }

    fn exists(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<bool, ArtifactError> {
        self.repository.exists(scope, snapshot_id)
    }

    fn remove_reference(
        &self,
        scope: &crate::ArtifactScope,
        snapshot_id: &SnapshotId,
    ) -> Result<(), ArtifactError> {
        self.repository.remove_reference(scope, snapshot_id)
    }

    fn garbage_collect(
        &self,
        scope: &crate::ArtifactScope,
    ) -> Result<GarbageCollectionReport, ArtifactError> {
        let started = Instant::now();
        let mut report = self.repository.garbage_collect(scope)?;
        let deadline = started
            .checked_add(self.limits.operation_timeout)
            .ok_or_else(|| ArtifactError::Timeout("S3 multipart cleanup deadline".to_owned()))?;
        let aborted = self.backend.abort_stale_multipart(
            scope,
            self.limits.garbage_collection_grace,
            self.limits.maximum_listing_entries,
            deadline,
        )?;
        report.removed_staging_objects = report
            .removed_staging_objects
            .checked_add(aborted)
            .ok_or_else(|| ArtifactError::Integrity("cleanup count overflow".to_owned()))?;
        Ok(report)
    }
}

struct S3Backend {
    client: S3Client,
    runtime: Arc<Runtime>,
    key_prefix: String,
}

impl S3Backend {
    fn object_key(&self, key: &str) -> Result<ObjectKey, ArtifactError> {
        ObjectKey::new(self.remote_key(key)?).map_err(|error| {
            ArtifactError::Invalid(format!("derived S3 artifact key is invalid: {error}"))
        })
    }

    fn remote_key(&self, key: &str) -> Result<String, ArtifactError> {
        let mut parts = key.split('/');
        if parts.next() != Some("tenants") {
            return Err(ArtifactError::Invalid(
                "artifact key has no tenant prefix".to_owned(),
            ));
        }
        let tenant = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| ArtifactError::Invalid("artifact key has no tenant".to_owned()))?;
        if parts.next() != Some("workspaces") {
            return Err(ArtifactError::Invalid(
                "artifact key has no workspace prefix".to_owned(),
            ));
        }
        let workspace = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| ArtifactError::Invalid("artifact key has no workspace".to_owned()))?;
        let remainder = parts.collect::<Vec<_>>().join("/");
        if remainder.is_empty() {
            return Err(ArtifactError::Invalid(
                "artifact key has no scoped object path".to_owned(),
            ));
        }
        Ok(format!(
            "{}/tenants/{}/workspaces/{}/{}",
            self.key_prefix,
            hex::encode(Sha256::digest(tenant.as_bytes())),
            hex::encode(Sha256::digest(workspace.as_bytes())),
            remainder
        ))
    }

    fn run<F, T>(&self, deadline: Instant, operation: &str, future: F) -> Result<T, ArtifactError>
    where
        F: Future<Output = Result<T, S3Error>>,
    {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| ArtifactError::Timeout(operation.to_owned()))?;
        self.runtime
            .block_on(async move { tokio::time::timeout(remaining, future).await })
            .map_err(|_| ArtifactError::Timeout(operation.to_owned()))?
            .map_err(map_s3_error)
    }

    fn put_multipart_if_absent(
        &self,
        key: &str,
        source: &Path,
        deadline: Instant,
    ) -> Result<PutStatus, ArtifactError> {
        if self.exists(key, deadline)? {
            return Ok(PutStatus::Reused);
        }
        let lock_key = self.multipart_lock_key(key)?;
        let mut lock_request = PutObjectRequest::new(
            self.object_key(&lock_key)?,
            ByteStream::from_bytes(MULTIPART_LOCK_BODY),
        );
        lock_request.conditions.if_none_match = Some("*".to_owned());
        match self.run(
            deadline,
            "claim S3 multipart publication",
            self.client.put_object(lock_request),
        ) {
            Ok(_) => {}
            Err(ArtifactError::AlreadyExists(_)) => {
                self.wait_for_object(key, deadline)?;
                return Ok(PutStatus::Reused);
            }
            Err(error) => return Err(error),
        };
        let request = ManagedMultipartUploadRequest::from_path(self.object_key(key)?, source)
            .with_content_type("application/octet-stream");
        match self.run(
            deadline,
            "multipart upload S3 artifact",
            self.client.multipart_upload(request),
        ) {
            Ok(_) => Ok(PutStatus::Created),
            Err(error) => Err(error),
        }
    }

    fn wait_for_object(&self, key: &str, deadline: Instant) -> Result<(), ArtifactError> {
        loop {
            if self.exists(key, deadline)? {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    ArtifactError::Timeout("wait for S3 multipart publication".to_owned())
                })?;
            thread::sleep(remaining.min(Duration::from_millis(50)));
        }
    }

    fn multipart_lock_key(&self, key: &str) -> Result<String, ArtifactError> {
        let parts = key.split('/').collect::<Vec<_>>();
        if parts.len() < 5
            || parts[0] != "tenants"
            || parts[1].is_empty()
            || parts[2] != "workspaces"
            || parts[3].is_empty()
        {
            return Err(ArtifactError::Invalid(
                "artifact key has no tenant scope".to_owned(),
            ));
        }
        Ok(format!(
            "tenants/{}/workspaces/{}/staging/multipart-locks/{}",
            parts[1],
            parts[3],
            hex::encode(Sha256::digest(key.as_bytes()))
        ))
    }

    fn remote_scope_prefix(&self, scope: &crate::ArtifactScope) -> String {
        format!(
            "{}/tenants/{}/workspaces/{}/",
            self.key_prefix,
            hex::encode(Sha256::digest(scope.tenant_id().as_str().as_bytes())),
            hex::encode(Sha256::digest(scope.workspace_id().as_str().as_bytes()))
        )
    }

    fn abort_stale_multipart(
        &self,
        scope: &crate::ArtifactScope,
        grace: Duration,
        maximum_entries: usize,
        deadline: Instant,
    ) -> Result<usize, ArtifactError> {
        let prefix = self.remote_scope_prefix(scope);
        let cutoff = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(grace.as_secs());
        let maximum_pages = maximum_entries
            .checked_div(S3_LIST_PAGE_SIZE)
            .and_then(|pages| pages.checked_add(2))
            .ok_or_else(|| ArtifactError::Invalid("S3 listing limit overflow".to_owned()))?;
        self.run(deadline, "clean up stale S3 multipart uploads", async {
            let mut request = ListMultipartUploadsRequest {
                prefix: Some(prefix),
                ..ListMultipartUploadsRequest::default()
            };
            let mut inspected = 0_usize;
            let mut aborted = 0_usize;
            for _ in 0..maximum_pages {
                let page = self.client.list_multipart_uploads(request.clone()).await?;
                for upload in page.uploads {
                    inspected = inspected
                        .checked_add(1)
                        .ok_or_else(|| S3Error::integrity("multipart upload count overflow"))?;
                    if inspected > maximum_entries {
                        return Err(S3Error::configuration(
                            "multipart upload listing exceeds its entry limit",
                        ));
                    }
                    let is_stale = upload
                        .initiated
                        .and_then(|time| u64::try_from(time.unix_timestamp()).ok())
                        .is_some_and(|initiated| initiated <= cutoff);
                    if is_stale {
                        let upload_id = upload.upload_id().clone();
                        self.client
                            .abort_multipart_upload(AbortMultipartUploadRequest::new(
                                upload.key, upload_id,
                            ))
                            .await?;
                        aborted = aborted.checked_add(1).ok_or_else(|| {
                            S3Error::integrity("aborted multipart count overflow")
                        })?;
                    }
                }
                if !page.is_truncated {
                    return Ok(aborted);
                }
                request.key_marker = page.next_key_marker;
                request.upload_id_marker = page.next_upload_id_marker;
                if request.key_marker.is_none() || request.upload_id_marker.is_none() {
                    return Err(S3Error::invalid_response(
                        "truncated multipart listing omitted a required marker",
                    ));
                }
            }
            Err(S3Error::configuration(
                "multipart upload listing exceeded its page limit",
            ))
        })
    }
}

impl BlobBackend for S3Backend {
    fn put_if_absent(
        &self,
        key: &str,
        source: &Path,
        deadline: Instant,
    ) -> Result<PutStatus, ArtifactError> {
        let size = fs::metadata(source)
            .map_err(|error| crate::error::io_error(source, error))?
            .len();
        if size >= self.client.config().multipart_threshold() {
            return self.put_multipart_if_absent(key, source, deadline);
        }
        let mut request =
            PutObjectRequest::new(self.object_key(key)?, ByteStream::from_path(source));
        request.conditions.if_none_match = Some("*".to_owned());
        match self.run(
            deadline,
            "publish S3 artifact",
            self.client.put_object(request),
        ) {
            Ok(_) => Ok(PutStatus::Created),
            Err(ArtifactError::AlreadyExists(_)) => Ok(PutStatus::Reused),
            Err(error) => Err(error),
        }
    }

    fn get(
        &self,
        key: &str,
        destination: &Path,
        maximum_bytes: u64,
        deadline: Instant,
    ) -> Result<u64, ArtifactError> {
        let output = self.run(
            deadline,
            "download S3 artifact",
            self.client
                .get_object(GetObjectRequest::new(self.object_key(key)?)),
        )?;
        if output.metadata.content_length > maximum_bytes {
            return Err(ArtifactError::Integrity(
                "stored S3 artifact exceeds its byte limit".to_owned(),
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|error| crate::error::io_error(destination, error))?;
        let mut destination_file = tokio::fs::File::from_std(file);
        let result = self.run(deadline, "stream S3 artifact", async move {
            let written = output.body.write_to(&mut destination_file).await?;
            destination_file
                .sync_all()
                .await
                .map_err(S3Error::transport)?;
            Ok(written)
        });
        match result {
            Ok(written) if written <= maximum_bytes => Ok(written),
            Ok(_) => {
                let _ = fs::remove_file(destination);
                Err(ArtifactError::Integrity(
                    "stored S3 artifact exceeds its byte limit".to_owned(),
                ))
            }
            Err(error) => {
                let _ = fs::remove_file(destination);
                Err(error)
            }
        }
    }

    fn exists(&self, key: &str, deadline: Instant) -> Result<bool, ArtifactError> {
        let request = HeadObjectRequest::new(self.object_key(key)?);
        match self.run(
            deadline,
            "inspect S3 artifact",
            self.client.head_object(request),
        ) {
            Ok(_) => Ok(true),
            Err(ArtifactError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn list(
        &self,
        prefix: &str,
        maximum_entries: usize,
        deadline: Instant,
    ) -> Result<Vec<StoredObject>, ArtifactError> {
        if maximum_entries == 0 {
            return Err(ArtifactError::Invalid(
                "S3 artifact listing limit must be positive".to_owned(),
            ));
        }
        let remote_prefix = self.remote_key(prefix)?;
        let maximum_pages = maximum_entries
            .checked_div(S3_LIST_PAGE_SIZE)
            .and_then(|pages| pages.checked_add(2))
            .ok_or_else(|| ArtifactError::Invalid("S3 listing limit overflow".to_owned()))?;
        let pages = self.run(
            deadline,
            "list S3 artifacts",
            self.client.list_objects_v2_all(
                ListObjectsV2Request {
                    prefix: Some(remote_prefix.clone()),
                    ..ListObjectsV2Request::default()
                },
                maximum_pages,
            ),
        )?;
        let mut objects = Vec::new();
        for object in pages.into_iter().flat_map(|page| page.objects) {
            if objects.len() >= maximum_entries {
                return Err(ArtifactError::Invalid(
                    "S3 artifact listing exceeds its entry limit".to_owned(),
                ));
            }
            let suffix = object
                .key
                .as_str()
                .strip_prefix(&remote_prefix)
                .ok_or_else(|| {
                    ArtifactError::Integrity("S3 listing escaped its requested prefix".to_owned())
                })?;
            let modified = object.last_modified.map_or(SystemTime::now(), |value| {
                u64::try_from(value.unix_timestamp()).map_or(SystemTime::now(), |seconds| {
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(seconds))
                        .and_then(|time| {
                            time.checked_add(Duration::from_nanos(u64::from(value.nanosecond())))
                        })
                        .unwrap_or_else(SystemTime::now)
                })
            });
            objects.push(StoredObject {
                key: format!("{prefix}{suffix}"),
                modified,
            });
        }
        objects.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(objects)
    }

    fn delete(&self, key: &str, deadline: Instant) -> Result<(), ArtifactError> {
        let request = DeleteObjectRequest::new(self.object_key(key)?);
        self.run(
            deadline,
            "delete S3 artifact",
            self.client.delete_object(request),
        )?;
        Ok(())
    }
}

fn validate_key_prefix(prefix: &str) -> Result<String, ArtifactError> {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty()
        || prefix.len() > 256
        || prefix.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(ArtifactError::Invalid(
            "S3 artifact key prefix is invalid".to_owned(),
        ));
    }
    Ok(prefix.to_owned())
}

fn map_s3_error(error: S3Error) -> ArtifactError {
    let message = error.message().to_owned();
    match error.category() {
        ErrorCategory::Configuration => ArtifactError::Invalid(message),
        ErrorCategory::Authentication | ErrorCategory::Authorization => {
            ArtifactError::AccessDenied(message)
        }
        ErrorCategory::NotFound => ArtifactError::NotFound(message),
        ErrorCategory::Conflict | ErrorCategory::Precondition => {
            ArtifactError::AlreadyExists(message)
        }
        ErrorCategory::Timeout | ErrorCategory::Cancellation => ArtifactError::Timeout(message),
        ErrorCategory::Integrity
        | ErrorCategory::InvalidResponse
        | ErrorCategory::OversizedResponse => ArtifactError::Integrity(message),
        _ => ArtifactError::Storage(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3_wire::{Credentials, CredentialsProvider, StaticCredentialsProvider};
    use std::{
        io::Write as _,
        net::{SocketAddr, TcpListener, TcpStream},
        thread::JoinHandle,
    };

    const MASTER_KEY: [u8; 32] = [11; 32];
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct Response {
        status: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        declared_length: Option<usize>,
    }

    impl Response {
        fn empty(status: &'static str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: Vec::new(),
                declared_length: None,
            }
        }

        fn xml(status: &'static str, body: String) -> Self {
            Self {
                status,
                headers: vec![("Content-Type", "application/xml".to_owned())],
                body: body.into_bytes(),
                declared_length: None,
            }
        }
    }

    fn scripted_server(responses: Vec<Response>) -> (SocketAddr, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind scripted S3 server");
        let address = listener.local_addr().expect("scripted S3 address");
        let handle = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().expect("accept S3 request");
                    let request = read_request(&mut stream);
                    write_response(&mut stream, response);
                    request
                })
                .collect()
        });
        (address, handle)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(TEST_TIMEOUT))
            .expect("request timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        let header_end = loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert!(read > 0, "request closed before its headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(request.len() <= 128 * 1024, "request headers are bounded");
        };
        let headers = String::from_utf8(request[..header_end].to_vec()).expect("HTTP headers");
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .unwrap_or(0);
        while request.len() - header_end < content_length {
            let read = stream.read(&mut buffer).expect("read request body");
            assert!(read > 0, "request body was truncated");
            request.extend_from_slice(&buffer[..read]);
        }
        headers.lines().next().expect("request line").to_owned()
    }

    fn write_response(stream: &mut TcpStream, response: Response) {
        let declared_length = response.declared_length.unwrap_or(response.body.len());
        write!(
            stream,
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            response.status, declared_length
        )
        .expect("response status");
        for (name, value) in response.headers {
            write!(stream, "{name}: {value}\r\n").expect("response header");
        }
        stream.write_all(b"\r\n").expect("response separator");
        stream.write_all(&response.body).expect("response body");
        stream.flush().expect("flush response");
    }

    fn backend(address: SocketAddr, multipart_threshold: u64) -> S3Backend {
        let credentials =
            Credentials::new("test-access", "test-secret", None).expect("static test credentials");
        let provider: Arc<dyn CredentialsProvider> =
            Arc::new(StaticCredentialsProvider::new(credentials));
        let endpoint = Endpoint::new(format!("http://{address}")).expect("test endpoint");
        let config = S3Config::builder()
            .endpoint(endpoint)
            .allow_http_for_local_testing()
            .region("us-east-1")
            .bucket("sandbox-artifacts")
            .multipart_threshold(multipart_threshold)
            .multipart_part_size(5 * 1024 * 1024)
            .multipart_concurrency(1)
            .max_multipart_in_flight_bytes(5 * 1024 * 1024)
            .credentials_provider(provider)
            .build()
            .expect("test S3 config");
        S3Backend {
            client: S3Client::new(config).expect("test S3 client"),
            runtime: Arc::new(Runtime::new().expect("runtime")),
            key_prefix: "runtrue-sandboxd/v1".to_owned(),
        }
    }

    fn config() -> S3ArtifactConfig {
        S3ArtifactConfig {
            bucket: "sandbox-artifacts".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint: None,
            key_prefix: "runtrue-sandboxd/v1".to_owned(),
            virtual_hosted: false,
            allow_http_for_local_testing: false,
            credentials_file: None,
        }
    }

    #[test]
    fn remote_store_enables_same_backend_cross_worker_restore() {
        let store = S3ArtifactStore::new(config(), MASTER_KEY, ArtifactLimits::default())
            .expect("S3 store");
        assert_eq!(
            store.snapshot_portability(),
            SnapshotPortability::CrossWorkerSameBackend
        );
    }

    #[test]
    fn multipart_cleanup_grace_covers_caller_and_abort_deadlines() {
        let limits = ArtifactLimits {
            operation_timeout: Duration::from_secs(5),
            garbage_collection_grace: Duration::from_secs(5),
            ..ArtifactLimits::default()
        };
        assert!(matches!(
            S3ArtifactStore::new(config(), MASTER_KEY, limits),
            Err(ArtifactError::Invalid(_))
        ));
    }

    #[test]
    fn tenant_and_workspace_names_are_not_exposed_in_remote_keys() {
        let backend = S3Backend {
            client: S3Client::new(
                S3Config::builder()
                    .bucket("sandbox-artifacts")
                    .build()
                    .expect("S3 config"),
            )
            .expect("S3 client"),
            runtime: Arc::new(Runtime::new().expect("runtime")),
            key_prefix: "runtrue-sandboxd/v1".to_owned(),
        };
        let key = backend
            .remote_key("tenants/tenant-secret/workspaces/workspace-secret/objects/sha256/aa")
            .expect("remote key");
        assert!(!key.contains("tenant-secret"));
        assert!(!key.contains("workspace-secret"));
        assert!(key.starts_with("runtrue-sandboxd/v1/tenants/"));
    }

    #[test]
    fn multipart_lock_is_tenant_scoped_and_key_specific() {
        let backend = S3Backend {
            client: S3Client::new(
                S3Config::builder()
                    .bucket("sandbox-artifacts")
                    .build()
                    .expect("S3 config"),
            )
            .expect("S3 client"),
            runtime: Arc::new(Runtime::new().expect("runtime")),
            key_prefix: "runtrue-sandboxd/v1".to_owned(),
        };
        let first = backend
            .multipart_lock_key("tenants/tenant-a/workspaces/team-a/objects/sha256/aa")
            .expect("first lock");
        let second = backend
            .multipart_lock_key("tenants/tenant-a/workspaces/team-a/objects/sha256/bb")
            .expect("second lock");
        assert!(first.starts_with("tenants/tenant-a/workspaces/team-a/staging/"));
        assert_ne!(first, second);
    }

    #[test]
    fn credentials_file_is_owner_only_and_refreshes_between_requests() {
        let directory = tempfile::tempdir().expect("credential directory");
        let path = directory.path().join("credentials.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("credentials file");
        file.write_all(
            br#"{"access_key_id":"first","secret_access_key":"secret","session_token":"token"}"#,
        )
        .expect("first credentials");
        file.sync_all().expect("sync credentials");
        drop(file);
        let provider = RotatingFileCredentialsProvider::new(path.clone()).expect("provider");
        let runtime = Runtime::new().expect("runtime");
        let first = runtime
            .block_on(provider.provide_credentials())
            .expect("first refresh");
        assert_eq!(first.access_key_id(), "first");

        fs::write(
            &path,
            br#"{"access_key_id":"second","secret_access_key":"rotated","session_token":"new-token"}"#,
        )
        .expect("rotated credentials");
        let second = runtime
            .block_on(provider.provide_credentials())
            .expect("second refresh");
        assert_eq!(second.access_key_id(), "second");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken test permissions");
        assert!(RotatingFileCredentialsProvider::new(path).is_err());
    }

    #[test]
    fn s3_backend_conditionally_publishes_and_streams_objects() {
        let logical_key = "tenants/tenant-a/workspaces/team-a/objects/sha256/aa";
        let remote_key = format!(
            "runtrue-sandboxd/v1/tenants/{}/workspaces/{}/objects/sha256/aa",
            hex::encode(Sha256::digest(b"tenant-a")),
            hex::encode(Sha256::digest(b"team-a"))
        );
        let precondition =
            "<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>";
        let listing = format!(
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>{remote_key}</Key><LastModified>2026-07-21T00:00:00Z</LastModified><Size>7</Size></Contents><KeyCount>1</KeyCount></ListBucketResult>"
        );
        let mut head = Response::empty("200 OK");
        head.declared_length = Some(7);
        let (address, server) = scripted_server(vec![
            Response::empty("200 OK"),
            Response::xml("412 Precondition Failed", precondition.to_owned()),
            head,
            Response {
                status: "200 OK",
                headers: Vec::new(),
                body: b"payload".to_vec(),
                declared_length: None,
            },
            Response::xml("200 OK", listing),
            Response::empty("204 No Content"),
        ]);
        let backend = backend(address, 8 * 1024 * 1024);
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("source");
        fs::write(&source, b"payload").expect("source");
        let deadline = Instant::now() + TEST_TIMEOUT;
        assert_eq!(
            backend
                .put_if_absent(logical_key, &source, deadline)
                .expect("first publication"),
            PutStatus::Created
        );
        assert_eq!(
            backend
                .put_if_absent(logical_key, &source, deadline)
                .expect("duplicate publication"),
            PutStatus::Reused
        );
        assert!(backend.exists(logical_key, deadline).expect("HEAD"));
        let destination = temporary.path().join("destination");
        assert_eq!(
            backend
                .get(logical_key, &destination, 7, deadline)
                .expect("download"),
            7
        );
        assert_eq!(fs::read(&destination).expect("destination"), b"payload");
        let listed = backend
            .list("tenants/tenant-a/workspaces/team-a/objects/", 10, deadline)
            .expect("listing");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, logical_key);
        backend.delete(logical_key, deadline).expect("delete");

        let requests = server.join().expect("scripted server");
        assert!(requests[0].starts_with("PUT /sandbox-artifacts/"));
        assert!(requests[1].starts_with("PUT /sandbox-artifacts/"));
        assert!(requests[2].starts_with("HEAD /sandbox-artifacts/"));
        assert!(requests[3].starts_with("GET /sandbox-artifacts/"));
        assert!(requests[4].starts_with("GET /sandbox-artifacts?"));
        assert!(requests[5].starts_with("DELETE /sandbox-artifacts/"));
    }

    #[test]
    fn s3_backend_uses_managed_multipart_behind_a_conditional_lock() {
        let logical_key = "tenants/tenant-a/workspaces/team-a/objects/sha256/large";
        let remote_key = format!(
            "runtrue-sandboxd/v1/tenants/{}/workspaces/{}/objects/sha256/large",
            hex::encode(Sha256::digest(b"tenant-a")),
            hex::encode(Sha256::digest(b"team-a"))
        );
        let not_found = "<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>";
        let created = format!(
            "<InitiateMultipartUploadResult><Bucket>sandbox-artifacts</Bucket><Key>{remote_key}</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>"
        );
        let completed = format!(
            "<CompleteMultipartUploadResult><Bucket>sandbox-artifacts</Bucket><Key>{remote_key}</Key><ETag>&quot;complete&quot;</ETag></CompleteMultipartUploadResult>"
        );
        let mut lock = Response::empty("200 OK");
        lock.headers.push(("ETag", "\"lock\"".to_owned()));
        let mut part = Response::empty("200 OK");
        part.headers.push(("ETag", "\"part-1\"".to_owned()));
        let mut exists = Response::empty("200 OK");
        exists.declared_length = Some(5 * 1024 * 1024);
        let (address, server) = scripted_server(vec![
            Response::xml("404 Not Found", not_found.to_owned()),
            lock,
            Response::xml("200 OK", created),
            part,
            Response::xml("200 OK", completed),
            exists,
        ]);
        let backend = backend(address, 5 * 1024 * 1024);
        let temporary = tempfile::tempdir().expect("temporary directory");
        let source = temporary.path().join("large");
        fs::write(&source, vec![7_u8; 5 * 1024 * 1024]).expect("multipart source");
        let deadline = Instant::now() + TEST_TIMEOUT;
        assert_eq!(
            backend
                .put_if_absent(logical_key, &source, deadline)
                .expect("multipart publication"),
            PutStatus::Created
        );
        assert_eq!(
            backend
                .put_if_absent(logical_key, &source, deadline)
                .expect("reuse completed multipart object"),
            PutStatus::Reused
        );

        let requests = server.join().expect("scripted server");
        assert!(requests[0].starts_with("HEAD /sandbox-artifacts/"));
        assert!(requests[1].starts_with("PUT /sandbox-artifacts/"));
        assert!(requests[2].starts_with("POST /sandbox-artifacts/"));
        assert!(requests[2].contains("uploads"));
        assert!(requests[3].starts_with("PUT /sandbox-artifacts/"));
        assert!(requests[3].contains("partNumber=1"));
        assert!(requests[4].starts_with("POST /sandbox-artifacts/"));
        assert!(requests[4].contains("uploadId="));
        assert!(requests[5].starts_with("HEAD /sandbox-artifacts/"));
    }
}
