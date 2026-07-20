use runtrue_sandbox_gvisor::executor;
use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{fs, os::unix::process::CommandExt as _, path::PathBuf};

const LAUNCHER_ARGUMENT: &str = "__cgroup-exec";

pub(crate) fn is_launcher_invocation() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(LAUNCHER_ARGUMENT))
}

pub(crate) fn run_or_exit() {
    if let Err(error) = execute() {
        eprintln!("runtrue-sandboxctl cgroup launcher: {error}");
        std::process::exit(125);
    }
}

fn execute() -> Result<(), SandboxError> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() < 5 {
        return Err(SandboxError::Runtime(
            "invalid internal cgroup launcher arguments".to_owned(),
        ));
    }
    let cgroup = PathBuf::from(&arguments[2]);
    let program = fs::canonicalize(PathBuf::from(&arguments[3]))
        .map_err(|source| io_error(PathBuf::from(&arguments[3]), source))?;
    if program.file_name().and_then(|name| name.to_str()) != Some("runsc") {
        return Err(SandboxError::Runtime(
            "internal cgroup launcher only executes runsc".to_owned(),
        ));
    }
    executor::enter_cgroup(&cgroup)?;
    let error = std::process::Command::new(&program)
        .args(&arguments[4..])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .exec();
    Err(io_error(program, error))
}
