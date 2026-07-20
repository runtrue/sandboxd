use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{ffi::OsStr, fs, os::unix::process::CommandExt as _, path::PathBuf, process::Command};

const LAUNCHER_ARGUMENT: &str = "__cgroup-exec";

pub(crate) fn is_launcher_invocation() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(OsStr::new(LAUNCHER_ARGUMENT))
}

pub(crate) fn execute_or_exit() {
    if let Err(error) = execute() {
        eprintln!("runtrue-sandboxd cgroup launcher: {error}");
        std::process::exit(125);
    }
}

fn execute() -> Result<(), SandboxError> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() < 4 {
        return Err(SandboxError::Runtime(
            "invalid internal cgroup launcher invocation".to_owned(),
        ));
    }
    let cgroup = PathBuf::from(&arguments[2]);
    let runsc_argument = PathBuf::from(&arguments[3]);
    let runsc =
        fs::canonicalize(&runsc_argument).map_err(|source| io_error(&runsc_argument, source))?;
    if runsc.file_name() != Some(OsStr::new("runsc")) {
        return Err(SandboxError::Runtime(
            "internal launcher only permits runsc".to_owned(),
        ));
    }
    executor::enter_cgroup(&cgroup)?;
    let error = Command::new(runsc).args(&arguments[4..]).exec();
    Err(SandboxError::Runtime(format!("exec runsc failed: {error}")))
}
