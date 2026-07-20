use crate::{io_error, SandboxError};
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) struct CommandResult {
    pub(crate) stdout: Vec<u8>,
}

pub(crate) struct BlobDigest {
    pub(crate) digest: String,
    pub(crate) bytes: u64,
}

pub(crate) struct VerifiedContent {
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct CommandRunner {
    program: PathBuf,
    address: PathBuf,
    namespace: String,
    output_limit: usize,
}

impl CommandRunner {
    pub(crate) fn new(
        program: PathBuf,
        address: PathBuf,
        namespace: String,
        output_limit: usize,
    ) -> Self {
        Self {
            program,
            address,
            namespace,
            output_limit,
        }
    }

    pub(crate) fn run(
        &self,
        arguments: &[String],
        timeout: Duration,
        operation: &str,
    ) -> Result<CommandResult, SandboxError> {
        let mut child = self.spawn(arguments)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stdout is unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stderr is unavailable".to_owned()))?;
        let output_limit = self.output_limit;
        let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
        let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
        let status = wait(&mut child, timeout, &self.program, operation)?;
        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| SandboxError::ImageProvider("ctr stdout reader panicked".to_owned()))?
            .map_err(|source| io_error(&self.program, source))?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| SandboxError::ImageProvider("ctr stderr reader panicked".to_owned()))?
            .map_err(|source| io_error(&self.program, source))?;
        ensure_success(status, operation, &stderr, stderr_truncated)?;
        let _ = stdout_truncated;
        Ok(CommandResult { stdout })
    }

    pub(crate) fn verified_content(
        &self,
        digest: &str,
        expected_bytes: u64,
        maximum_bytes: u64,
        timeout: Duration,
    ) -> Result<VerifiedContent, SandboxError> {
        if expected_bytes > maximum_bytes {
            return Err(SandboxError::ImageProvider(format!(
                "content `{digest}` exceeds its byte limit"
            )));
        }
        let (content, observed) = self.read_content(digest, maximum_bytes, timeout)?;
        if observed.bytes != expected_bytes {
            return Err(SandboxError::ImageProvider(format!(
                "content `{digest}` failed size verification"
            )));
        }
        Ok(content)
    }

    pub(crate) fn read_content(
        &self,
        digest: &str,
        maximum_bytes: u64,
        timeout: Duration,
    ) -> Result<(VerifiedContent, BlobDigest), SandboxError> {
        let mut child = self.spawn(&["content".to_owned(), "get".to_owned(), digest.to_owned()])?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stdout is unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stderr is unavailable".to_owned()))?;
        let content_reader = thread::spawn(move || read_verified(stdout, maximum_bytes));
        let output_limit = self.output_limit;
        let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
        let status = wait(
            &mut child,
            timeout,
            &self.program,
            "read containerd metadata",
        )?;
        let (bytes, observed) = content_reader
            .join()
            .map_err(|_| SandboxError::ImageProvider("content reader panicked".to_owned()))??;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| SandboxError::ImageProvider("ctr stderr reader panicked".to_owned()))?
            .map_err(|source| io_error(&self.program, source))?;
        ensure_success(
            status,
            "read containerd metadata",
            &stderr,
            stderr_truncated,
        )?;
        if observed.digest != digest {
            return Err(SandboxError::ImageProvider(format!(
                "content `{digest}` failed digest verification"
            )));
        }
        Ok((VerifiedContent { bytes }, observed))
    }

    pub(crate) fn inspect_content<F>(
        &self,
        digest: &str,
        expected_bytes: u64,
        maximum_bytes: u64,
        timeout: Duration,
        inspect: F,
    ) -> Result<(), SandboxError>
    where
        F: FnOnce(&mut dyn Read) -> Result<(), SandboxError>,
    {
        if expected_bytes > maximum_bytes {
            return Err(SandboxError::ImageProvider(format!(
                "content `{digest}` exceeds its byte limit"
            )));
        }
        let started = Instant::now();
        let mut child = self.spawn(&["content".to_owned(), "get".to_owned(), digest.to_owned()])?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stdout is unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::ImageProvider("ctr stderr is unavailable".to_owned()))?;
        let output_limit = self.output_limit;
        let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
        let mut reader = DigestingReader {
            inner: stdout,
            hasher: Sha256::new(),
            bytes: 0,
            maximum: maximum_bytes,
        };
        let inspection = inspect(&mut reader).and_then(|()| {
            std::io::copy(&mut reader, &mut std::io::sink())
                .map(|_| ())
                .map_err(|source| io_error("containerd content stream", source))
        });
        if let Err(error) = inspection {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stderr_reader.join();
            return Err(error);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        let status = wait(
            &mut child,
            remaining,
            &self.program,
            "inspect containerd content",
        )?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| SandboxError::ImageProvider("ctr stderr reader panicked".to_owned()))?
            .map_err(|source| io_error(&self.program, source))?;
        ensure_success(
            status,
            "inspect containerd content",
            &stderr,
            stderr_truncated,
        )?;
        let observed = reader.finish();
        if observed.bytes != expected_bytes || observed.digest != digest {
            return Err(SandboxError::ImageProvider(format!(
                "content `{digest}` failed digest or size verification"
            )));
        }
        Ok(())
    }

    fn spawn(&self, arguments: &[String]) -> Result<Child, SandboxError> {
        Command::new(&self.program)
            .arg("--address")
            .arg(&self.address)
            .arg("--namespace")
            .arg(&self.namespace)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| io_error(&self.program, source))
    }
}

fn wait(
    child: &mut Child,
    timeout: Duration,
    program: &Path,
    operation: &str,
) -> Result<ExitStatus, SandboxError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| io_error(program, source))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|source| io_error(program, source))?;
            let _ = child.wait();
            return Err(SandboxError::Timeout(operation.to_owned()));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn ensure_success(
    status: ExitStatus,
    operation: &str,
    stderr: &[u8],
    truncated: bool,
) -> Result<(), SandboxError> {
    if status.success() {
        return Ok(());
    }
    let suffix = if truncated { " [truncated]" } else { "" };
    Err(SandboxError::ImageProvider(format!(
        "{operation} exited {:?}: {}{suffix}",
        status.code(),
        String::from_utf8_lossy(stderr).trim()
    )))
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut captured = Vec::with_capacity(maximum.min(64 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.write_all(&buffer[..retained])?;
        truncated |= retained != read;
    }
    Ok((captured, truncated))
}

#[cfg(test)]
fn read_digest(mut reader: impl Read, maximum: u64) -> Result<BlobDigest, SandboxError> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("containerd content stream", source))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| SandboxError::ImageProvider("content size overflow".to_owned()))?;
        if bytes > maximum {
            return Err(SandboxError::ImageProvider(
                "content stream exceeded its byte limit".to_owned(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(BlobDigest {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
        bytes,
    })
}

fn read_verified(
    mut reader: impl Read,
    maximum: u64,
) -> Result<(Vec<u8>, BlobDigest), SandboxError> {
    let capacity = usize::try_from(maximum.min(4 * 1024 * 1024))
        .map_err(|_| SandboxError::ImageProvider("metadata buffer size overflow".to_owned()))?;
    let mut retained = Vec::with_capacity(capacity);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("containerd content stream", source))?;
        if read == 0 {
            break;
        }
        let next = retained
            .len()
            .checked_add(read)
            .ok_or_else(|| SandboxError::ImageProvider("metadata size overflow".to_owned()))?;
        if u64::try_from(next).map_or(true, |bytes| bytes > maximum) {
            return Err(SandboxError::ImageProvider(
                "metadata stream exceeded its byte limit".to_owned(),
            ));
        }
        hasher.update(&buffer[..read]);
        retained.extend_from_slice(&buffer[..read]);
    }
    let bytes = retained.len() as u64;
    Ok((
        retained,
        BlobDigest {
            digest: format!("sha256:{}", hex::encode(hasher.finalize())),
            bytes,
        },
    ))
}

struct DigestingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
    maximum: u64,
}

impl<R> DigestingReader<R> {
    fn finish(self) -> BlobDigest {
        BlobDigest {
            digest: format!("sha256:{}", hex::encode(self.hasher.finalize())),
            bytes: self.bytes,
        }
    }
}

impl<R: Read> Read for DigestingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("content size overflow"))?;
        if self.bytes > self.maximum {
            return Err(std::io::Error::other(
                "content stream exceeded its byte limit",
            ));
        }
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_drains_but_does_not_retain_excess_output() {
        let (captured, truncated) = read_bounded(Cursor::new(vec![b'x'; 1_024]), 32).unwrap();
        assert_eq!(captured, vec![b'x'; 32]);
        assert!(truncated);
    }

    #[test]
    fn digest_reader_enforces_the_stream_limit() {
        let observed = read_digest(Cursor::new(b"verified"), 8).unwrap();
        assert_eq!(observed.bytes, 8);
        assert_eq!(
            observed.digest,
            "sha256:1c34f88707b55e6104c4eb20e71ffa3d33e414b71ef689a15fad0640d0ac58cb"
        );
        assert!(read_digest(Cursor::new(b"oversized"), 8).is_err());
    }

    #[test]
    fn timed_out_child_is_hard_stopped() {
        let mut child = Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .expect("spawn sleep fixture");
        let started = Instant::now();
        let error = wait(
            &mut child,
            Duration::from_millis(25),
            Path::new("/bin/sleep"),
            "test timeout",
        )
        .expect_err("sleep must time out");
        assert!(matches!(error, SandboxError::Timeout(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }
}
