use crate::{error::io_error, SandboxError};
use serde::Deserialize;
use std::{
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct Docker {
    program: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageInspect {
    pub id: String,
    pub repo_digests: Vec<String>,
    pub os: String,
    pub architecture: String,
}

impl Docker {
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, SandboxError> {
        let program = program.into();
        if !program.is_absolute() {
            return Err(SandboxError::Docker(
                "Docker program must be an absolute path".to_owned(),
            ));
        }
        let canonical =
            std::fs::canonicalize(&program).map_err(|source| io_error(&program, source))?;
        if !canonical.is_file() {
            return Err(SandboxError::Docker(
                "Docker program is not a file".to_owned(),
            ));
        }
        let docker = Self { program: canonical };
        docker.checked(&["version", "--format", "{{.Server.Version}}"])?;
        Ok(docker)
    }

    pub fn image_inspect(&self, reference: &str) -> Result<ImageInspect, SandboxError> {
        let output = self.checked(&["image", "inspect", reference])?;
        let mut images: Vec<ImageInspect> = serde_json::from_slice(&output.stdout)
            .map_err(|error| SandboxError::Docker(format!("decode image inspection: {error}")))?;
        if images.len() != 1 {
            return Err(SandboxError::Docker(format!(
                "image `{reference}` resolved to {} records",
                images.len()
            )));
        }
        Ok(images.remove(0))
    }

    pub fn checked(&self, arguments: &[&str]) -> Result<Output, SandboxError> {
        let output = Command::new(&self.program)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
            .map_err(|source| io_error(&self.program, source))?;
        if output.status.success() {
            return Ok(output);
        }
        Err(SandboxError::Docker(format!(
            "`docker {}` exited {:?}: {}",
            arguments.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    pub fn checked_owned(&self, arguments: &[String]) -> Result<Output, SandboxError> {
        let refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        self.checked(&refs)
    }

    pub fn status_with_timeout(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<bool, SandboxError> {
        let mut child = Command::new(&self.program)
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| io_error(&self.program, source))?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|source| io_error(&self.program, source))?
            {
                return Ok(status.success());
            }
            if Instant::now() >= deadline {
                child
                    .kill()
                    .map_err(|source| io_error(&self.program, source))?;
                let _ = child.wait();
                return Err(SandboxError::Timeout(format!(
                    "docker {}",
                    arguments.join(" ")
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
