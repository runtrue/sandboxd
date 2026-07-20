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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::time::{Duration, Instant};

    #[derive(Deserialize)]
    struct Probe {
        #[allow(dead_code)]
        value: String,
    }

    #[test]
    fn read_timeout_bounds_incomplete_clients() {
        let (reader, _writer) = UnixStream::pair().expect("socket pair");
        reader
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("read timeout");
        let started = Instant::now();
        assert!(read_message::<Probe>(&reader).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn rejects_unterminated_messages() {
        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        writer.write_all(br#"{"value":"x"}"#).expect("write");
        writer
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown");
        assert!(read_message::<Probe>(&reader).is_err());
    }
}
