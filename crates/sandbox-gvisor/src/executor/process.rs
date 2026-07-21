use crate::{error::io_error, SandboxError};
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const DELETE_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_TIMEOUT: Duration = Duration::from_millis(250);
const MAXIMUM_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const DIAGNOSTIC_DIRECTORY: &str = "diagnostics";

#[derive(Debug, Clone)]
pub(super) struct Runsc {
    program: PathBuf,
    root: PathBuf,
}

pub(super) struct ServiceProcess {
    pub(super) id: String,
    child: Child,
    stdout: Option<JoinHandle<Result<Vec<u8>, std::io::Error>>>,
    stderr: Option<JoinHandle<Result<Vec<u8>, std::io::Error>>>,
    truncated: Arc<AtomicBool>,
    finished: Option<ExitStatus>,
    captured: Option<CapturedOutput>,
}

#[derive(Debug, Default)]
pub(super) struct CapturedOutput {
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) truncated: bool,
}

impl Runsc {
    pub(super) fn new(program: &Path, root: &Path) -> Result<Self, SandboxError> {
        if !program.is_absolute()
            || program.file_name().and_then(|name| name.to_str()) != Some("runsc")
        {
            return Err(SandboxError::Docker(
                "runsc program must be an absolute `runsc` path".to_owned(),
            ));
        }
        let program = std::fs::canonicalize(program).map_err(|source| io_error(program, source))?;
        if root.exists() {
            if !root.is_dir() {
                return Err(SandboxError::Runtime(
                    "runsc state root is not a directory".to_owned(),
                ));
            }
        } else {
            std::fs::create_dir(root).map_err(|source| io_error(root, source))?;
        }
        let diagnostics = root.join(DIAGNOSTIC_DIRECTORY);
        std::fs::create_dir_all(&diagnostics).map_err(|source| io_error(&diagnostics, source))?;
        Ok(Self {
            program,
            root: root.to_owned(),
        })
    }

    pub(super) fn spawn(
        &self,
        id: String,
        bundle: &Path,
        cgroup: &Path,
        maximum_output: usize,
    ) -> Result<ServiceProcess, SandboxError> {
        self.spawn_operation(
            id,
            cgroup,
            maximum_output,
            [
                "run".to_owned(),
                "--bundle".to_owned(),
                bundle.display().to_string(),
            ],
        )
    }

    pub(super) fn spawn_restore(
        &self,
        id: String,
        bundle: &Path,
        cgroup: &Path,
        maximum_output: usize,
        image_path: &Path,
    ) -> Result<ServiceProcess, SandboxError> {
        self.spawn_operation(
            id,
            cgroup,
            maximum_output,
            [
                "restore".to_owned(),
                "--bundle".to_owned(),
                bundle.display().to_string(),
                "--image-path".to_owned(),
                image_path.display().to_string(),
            ],
        )
    }

    fn spawn_operation<I>(
        &self,
        id: String,
        cgroup: &Path,
        maximum_output: usize,
        operation: I,
    ) -> Result<ServiceProcess, SandboxError>
    where
        I: IntoIterator<Item = String>,
    {
        let current =
            std::env::current_exe().map_err(|source| io_error("<current executable>", source))?;
        let diagnostic_path = self.diagnostic_path(&id);
        let mut command = Command::new(current);
        command
            .arg("__cgroup-exec")
            .arg(cgroup)
            .arg(&self.program)
            .args(self.common_arguments())
            .arg(format!("--log={}", diagnostic_path.display()))
            .arg("--log-format=text")
            .args(operation)
            .arg(&id)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|source| io_error(&self.program, source))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SandboxError::Docker("runsc stdout pipe is absent".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SandboxError::Docker("runsc stderr pipe is absent".to_owned()))?;
        let remaining = Arc::new(AtomicUsize::new(maximum_output));
        let truncated = Arc::new(AtomicBool::new(false));
        Ok(ServiceProcess {
            id,
            child,
            stdout: Some(capture(
                stdout,
                Arc::clone(&remaining),
                Arc::clone(&truncated),
            )),
            stderr: Some(capture(stderr, remaining, Arc::clone(&truncated))),
            truncated,
            finished: None,
            captured: None,
        })
    }

    pub(super) fn checkpoint(
        &self,
        id: &str,
        image_path: &Path,
        leave_running: bool,
        timeout: Duration,
    ) -> Result<(), SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend([
            "checkpoint".to_owned(),
            "--image-path".to_owned(),
            image_path.display().to_string(),
            "--compression=none".to_owned(),
        ]);
        if leave_running {
            arguments.push("--leave-running".to_owned());
        }
        arguments.push(id.to_owned());
        checked_timeout(&self.program, &arguments, timeout)
    }

    pub(super) fn version(&self) -> Result<String, SandboxError> {
        let output = checked(&self.program, &["--version".to_owned()])?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    pub(super) fn configuration_digest(&self) -> String {
        let joined = self
            .common_arguments()
            .into_iter()
            .filter(|argument| !argument.starts_with("--root="))
            .collect::<Vec<_>>()
            .join("\0");
        format!("sha256:{:x}", Sha256::digest(joined.as_bytes()))
    }

    pub(super) fn cpu_features_digest(&self) -> Result<String, SandboxError> {
        let output = checked(&self.program, &["cpu-features".to_owned()])?;
        Ok(format!("sha256:{:x}", Sha256::digest(&output.stdout)))
    }

    pub(super) fn wait_running(
        &self,
        process: &mut ServiceProcess,
        deadline: Instant,
    ) -> Result<(), SandboxError> {
        loop {
            if let Some(status) = process.poll()? {
                let id = process.id.clone();
                let stderr = process.finish_capture()?.stderr.clone();
                return Err(SandboxError::Docker(format!(
                    "runsc service `{}` exited {:?} before running: {}",
                    id,
                    status.code(),
                    String::from_utf8_lossy(&stderr).trim()
                )));
            }
            match self.state(&process.id) {
                Ok(state) if state == "running" => return Ok(()),
                Ok(state) if matches!(state.as_str(), "creating" | "created") => {}
                Ok(state) => {
                    let diagnostic = self.diagnostic(&process.id);
                    return Err(SandboxError::Docker(format!(
                        "runsc service `{}` entered state `{state}`{diagnostic}",
                        process.id,
                    )));
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                let diagnostic = self.diagnostic(&process.id);
                return Err(SandboxError::Timeout(format!(
                    "runsc service `{}` did not start{diagnostic}",
                    process.id,
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn wait_restored(
        &self,
        process: &mut ServiceProcess,
        deadline: Instant,
    ) -> Result<(), SandboxError> {
        loop {
            match self.state(&process.id) {
                Ok(state) if matches!(state.as_str(), "running" | "stopped") => return Ok(()),
                Ok(state) if matches!(state.as_str(), "creating" | "created") => {}
                Ok(state) => {
                    return Err(SandboxError::Runtime(format!(
                        "restored service `{}` entered state `{state}`",
                        process.id
                    )))
                }
                Err(_) => {
                    if let Some(status) = process.poll()? {
                        let id = process.id.clone();
                        let stderr = process.finish_capture()?.stderr.clone();
                        return Err(SandboxError::Runtime(format!(
                            "restore for `{id}` exited {:?}: {}",
                            status.code(),
                            String::from_utf8_lossy(&stderr).trim()
                        )));
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(SandboxError::Timeout(format!(
                    "restored service `{}` did not settle",
                    process.id
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn wait_created(
        &self,
        process: &mut ServiceProcess,
        deadline: Instant,
    ) -> Result<(), SandboxError> {
        loop {
            if self.state(&process.id).is_ok() {
                return Ok(());
            }
            if let Some(status) = process.poll()? {
                let id = process.id.clone();
                let stderr = process.finish_capture()?.stderr.clone();
                return Err(SandboxError::Runtime(format!(
                    "root restore for `{id}` exited {:?}: {}",
                    status.code(),
                    String::from_utf8_lossy(&stderr).trim()
                )));
            }
            if Instant::now() >= deadline {
                return Err(SandboxError::Timeout(format!(
                    "root restore for `{}` did not create its sandbox",
                    process.id
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn health(
        &self,
        id: &str,
        user: &str,
        command: &[String],
        timeout: Duration,
    ) -> Result<bool, SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend(["exec".to_owned(), format!("--user={user}"), id.to_owned()]);
        arguments.extend(command.iter().cloned());
        status_timeout(&self.program, &arguments, timeout)
    }

    pub(super) fn is_empty(&self) -> Result<bool, SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend(["list".to_owned(), "--format=json".to_owned()]);
        let output = checked(&self.program, &arguments)?;
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| SandboxError::Docker(format!("decode runsc list: {error}")))?;
        Ok(value.is_null() || value.as_array().is_some_and(Vec::is_empty))
    }

    pub(super) fn teardown(&self, ids: &[String], sandbox_id: &str) -> Result<(), SandboxError> {
        let children = ids
            .iter()
            .filter(|id| id.as_str() != sandbox_id)
            .cloned()
            .collect::<Vec<_>>();
        for id in &children {
            self.kill(id);
        }
        if ids.iter().any(|id| id == sandbox_id) {
            self.kill(sandbox_id);
            let _ = self.delete_all(&[sandbox_id.to_owned()]);
        }
        let remaining = ids
            .iter()
            .filter(|id| self.state(id).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        self.delete_all(&remaining)?;
        if self.is_empty()? {
            Ok(())
        } else {
            Err(SandboxError::Docker(
                "runsc state is not empty after sandbox teardown".to_owned(),
            ))
        }
    }

    fn kill(&self, id: &str) {
        let mut arguments = self.common_arguments();
        arguments.extend([
            "kill".to_owned(),
            "--all".to_owned(),
            id.to_owned(),
            "KILL".to_owned(),
        ]);
        let _ = checked(&self.program, &arguments);
    }

    pub(super) fn pause(&self, id: &str) -> Result<(), SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend(["pause".to_owned(), id.to_owned()]);
        checked(&self.program, &arguments).map(|_| ())
    }

    pub(super) fn resume(&self, id: &str) -> Result<(), SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend(["resume".to_owned(), id.to_owned()]);
        checked(&self.program, &arguments).map(|_| ())
    }

    pub(super) fn delete_all(&self, ids: &[String]) -> Result<(), SandboxError> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut arguments = self.common_arguments();
        arguments.extend(["delete".to_owned(), "--force".to_owned()]);
        arguments.extend(ids.iter().cloned());
        checked_for(&self.program, &arguments, DELETE_TIMEOUT).map(|_| ())
    }

    pub(super) fn state(&self, id: &str) -> Result<String, SandboxError> {
        let mut arguments = self.common_arguments();
        arguments.extend(["state".to_owned(), id.to_owned()]);
        let output = checked_for(&self.program, &arguments, STATE_TIMEOUT)?;
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| SandboxError::Docker(format!("decode runsc state: {error}")))?;
        value["status"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| SandboxError::Docker("runsc state omitted status".to_owned()))
    }

    fn common_arguments(&self) -> Vec<String> {
        vec![
            format!("--root={}", self.root.display()),
            "--network=sandbox".to_owned(),
            "--ignore-cgroups=true".to_owned(),
            "--platform=systrap".to_owned(),
            "--overlay2=none".to_owned(),
            "--file-access=exclusive".to_owned(),
            "--file-access-mounts=exclusive".to_owned(),
            "--directfs=false".to_owned(),
            "--host-uds=none".to_owned(),
            "--host-fifo=none".to_owned(),
            "--net-raw=false".to_owned(),
        ]
    }

    fn diagnostic_path(&self, id: &str) -> PathBuf {
        self.root
            .join(DIAGNOSTIC_DIRECTORY)
            .join(format!("{id}.log"))
    }

    fn diagnostic(&self, id: &str) -> String {
        let path = self.diagnostic_path(id);
        let Ok(file) = std::fs::File::open(&path) else {
            return String::new();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAXIMUM_DIAGNOSTIC_BYTES)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.is_empty()
        {
            return String::new();
        }
        format!(
            "; runsc diagnostic: {}",
            String::from_utf8_lossy(&bytes).trim()
        )
    }
}

impl ServiceProcess {
    pub(super) fn poll(&mut self) -> Result<Option<ExitStatus>, SandboxError> {
        if let Some(status) = self.finished {
            return Ok(Some(status));
        }
        let status = self
            .child
            .try_wait()
            .map_err(|source| io_error("<runsc child>", source))?;
        if let Some(status) = status {
            self.finished = Some(status);
        }
        Ok(status)
    }

    pub(super) fn wait_until(&mut self, deadline: Instant) -> Result<ExitStatus, SandboxError> {
        loop {
            if let Some(status) = self.poll()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(SandboxError::Timeout(format!(
                    "service `{}` did not finish",
                    self.id
                )));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub(super) fn finish_capture(&mut self) -> Result<&CapturedOutput, SandboxError> {
        if self.captured.is_none() {
            let stdout = join(self.stdout.take(), "stdout")?;
            let stderr = join(self.stderr.take(), "stderr")?;
            self.captured = Some(CapturedOutput {
                stdout,
                stderr,
                truncated: self.truncated.load(Ordering::Relaxed),
            });
        }
        Ok(self.captured.as_ref().expect("capture was inserted"))
    }

    pub(super) fn reap(&mut self) {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        if self.finished.is_none() {
            loop {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.finished = Some(status);
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        let _ = self.child.kill();
                        if let Ok(status) = self.child.wait() {
                            self.finished = Some(status);
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
        }
        let capture_finished = self.stdout.as_ref().is_none_or(JoinHandle::is_finished)
            && self.stderr.as_ref().is_none_or(JoinHandle::is_finished);
        if capture_finished {
            let _ = self.finish_capture();
        } else {
            self.stdout.take();
            self.stderr.take();
        }
    }
}

fn capture<R: Read + Send + 'static>(
    mut reader: R,
    remaining: Arc<AtomicUsize>,
    truncated: Arc<AtomicBool>,
) -> JoinHandle<Result<Vec<u8>, std::io::Error>> {
    thread::spawn(move || {
        let mut retained = Vec::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let reserved = reserve(&remaining, read);
            retained.write_all(&buffer[..reserved])?;
            if reserved < read {
                truncated.store(true, Ordering::Relaxed);
            }
        }
        Ok(retained)
    })
}

fn reserve(remaining: &AtomicUsize, requested: usize) -> usize {
    let mut observed = remaining.load(Ordering::Relaxed);
    loop {
        let reserved = requested.min(observed);
        match remaining.compare_exchange_weak(
            observed,
            observed - reserved,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return reserved,
            Err(actual) => observed = actual,
        }
    }
}

fn join(
    handle: Option<JoinHandle<Result<Vec<u8>, std::io::Error>>>,
    stream: &str,
) -> Result<Vec<u8>, SandboxError> {
    handle
        .ok_or_else(|| SandboxError::Docker(format!("{stream} capture is absent")))?
        .join()
        .map_err(|_| SandboxError::Docker(format!("{stream} capture thread panicked")))?
        .map_err(|source| io_error(format!("<runsc {stream}>"), source))
}

fn checked(program: &Path, arguments: &[String]) -> Result<std::process::Output, SandboxError> {
    checked_for(program, arguments, CONTROL_TIMEOUT)
}

fn checked_timeout(
    program: &Path,
    arguments: &[String],
    timeout: Duration,
) -> Result<(), SandboxError> {
    checked_for(program, arguments, timeout).map(|_| ())
}

fn checked_for(
    program: &Path,
    arguments: &[String],
    timeout: Duration,
) -> Result<std::process::Output, SandboxError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| io_error(program, source))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Runtime("runsc stdout pipe is absent".to_owned()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Runtime("runsc stderr pipe is absent".to_owned()))?;
    let remaining = Arc::new(AtomicUsize::new(64 * 1024));
    let truncated = Arc::new(AtomicBool::new(false));
    let stdout = capture(stdout, Arc::clone(&remaining), Arc::clone(&truncated));
    let stderr = capture(stderr, remaining, truncated);
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| io_error(program, source))?
        {
            let stdout = stdout
                .join()
                .map_err(|_| SandboxError::Runtime("runsc stdout capture panicked".to_owned()))?
                .map_err(|source| io_error("<runsc stdout>", source))?;
            let stderr = stderr
                .join()
                .map_err(|_| SandboxError::Runtime("runsc stderr capture panicked".to_owned()))?
                .map_err(|source| io_error("<runsc stderr>", source))?;
            return if status.success() {
                Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                })
            } else {
                Err(SandboxError::Runtime(format!(
                    "`runsc {}` exited {:?}: {}",
                    arguments.join(" "),
                    status.code(),
                    String::from_utf8_lossy(&stderr).trim()
                )))
            };
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|source| io_error(program, source))?;
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(SandboxError::Timeout(format!(
                "`runsc {}` exceeded {} milliseconds",
                arguments.join(" "),
                timeout.as_millis()
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn status_timeout(
    program: &Path,
    arguments: &[String],
    timeout: Duration,
) -> Result<bool, SandboxError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| io_error(program, source))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| io_error(program, source))?
        {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|source| io_error(program, source))?;
            let _ = child.wait();
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_process_is_hard_stopped_at_deadline() {
        let started = Instant::now();
        let error = checked_for(
            Path::new("/bin/sleep"),
            &["10".to_owned()],
            Duration::from_millis(25),
        )
        .expect_err("sleep must be interrupted");
        assert!(matches!(error, SandboxError::Timeout(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
