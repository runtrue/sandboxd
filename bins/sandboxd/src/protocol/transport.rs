use runtrue_sandbox_oci::SandboxError;
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    os::unix::net::UnixStream,
};

const MAX_MESSAGE_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn read_message<T: for<'de> Deserialize<'de>>(
    stream: &UnixStream,
) -> Result<T, SandboxError> {
    let mut bytes = Vec::new();
    BufReader::new(stream)
        .take(MAX_MESSAGE_BYTES + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|source| SandboxError::Runtime(format!("read protocol message: {source}")))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MESSAGE_BYTES || bytes.last() != Some(&b'\n') {
        return Err(SandboxError::Runtime(
            "protocol message is empty, oversized, or unterminated".to_owned(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| SandboxError::Runtime(format!("decode protocol message: {error}")))
}

pub(crate) fn write_message<T: Serialize>(
    stream: &mut UnixStream,
    message: &T,
) -> Result<(), SandboxError> {
    let bytes = serde_json::to_vec(message)
        .map_err(|error| SandboxError::Runtime(format!("encode protocol message: {error}")))?;
    if bytes.len() as u64 >= MAX_MESSAGE_BYTES {
        return Err(SandboxError::Runtime(
            "encoded protocol message exceeds limit".to_owned(),
        ));
    }
    stream
        .write_all(&bytes)
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|source| SandboxError::Runtime(format!("write protocol message: {source}")))
}
