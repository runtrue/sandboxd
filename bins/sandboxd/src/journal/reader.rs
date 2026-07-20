use runtrue_sandbox_oci::{io_error, SandboxError};
use std::{
    fs::OpenOptions,
    io::{Read as _, Seek as _, SeekFrom},
    path::Path,
};

const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;

pub(crate) fn read_records(
    path: &Path,
    maximum_file_bytes: u64,
    maximum_records: usize,
) -> Result<Vec<Vec<u8>>, SandboxError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    repair_torn_tail(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error(path, source))?
        .len();
    if length > maximum_file_bytes {
        return Err(SandboxError::Runtime(format!(
            "journal `{}` exceeds its recovery bound",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(length.try_into().unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    let records = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .map(|record| record.to_vec())
        .collect::<Vec<_>>();
    if records.len() > maximum_records
        || records
            .iter()
            .any(|record| record.len() > MAXIMUM_RECORD_BYTES || record == b"\n")
    {
        return Err(SandboxError::Runtime(format!(
            "journal `{}` has invalid recovery bounds",
            path.display()
        )));
    }
    Ok(records)
}

pub(super) fn repair_torn_tail(path: &Path) -> Result<(), SandboxError> {
    if !path.exists() {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let length = file
        .metadata()
        .map_err(|source| io_error(path, source))?
        .len();
    if length == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))
        .map_err(|source| io_error(path, source))?;
    let mut last = [0_u8; 1];
    file.read_exact(&mut last)
        .map_err(|source| io_error(path, source))?;
    if last[0] == b'\n' {
        return Ok(());
    }
    let scan_bytes = length.min(MAXIMUM_RECORD_BYTES as u64);
    let scan_start = length - scan_bytes;
    file.seek(SeekFrom::Start(scan_start))
        .map_err(|source| io_error(path, source))?;
    let mut tail = vec![0_u8; scan_bytes as usize];
    file.read_exact(&mut tail)
        .map_err(|source| io_error(path, source))?;
    let recovered_length = match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(position) => scan_start + position as u64 + 1,
        None if scan_start == 0 => 0,
        None => {
            return Err(SandboxError::Runtime(format!(
                "journal `{}` has an oversized torn record",
                path.display()
            )))
        }
    };
    file.set_len(recovered_length)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn discards_only_an_uncommitted_torn_tail() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.wal");
        let mut file = std::fs::File::create(&path).expect("journal");
        file.write_all(b"complete\ntorn").expect("records");
        drop(file);
        assert_eq!(
            read_records(&path, 1024, 10).expect("recovered records"),
            vec![b"complete\n".to_vec()]
        );
        assert_eq!(
            std::fs::read_to_string(path).expect("repaired journal"),
            "complete\n"
        );
    }
}
