use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, RecvTimeoutError, Sender},
    time::{Duration, Instant},
};

const MAXIMUM_BATCH_RECORDS: usize = 64;
const GROUP_COMMIT_WINDOW: Duration = Duration::from_millis(1);
type Completion = Sender<Result<(), String>>;
type PendingAppend = (Vec<u8>, Completion);

pub(super) enum Command {
    Append {
        record: Vec<u8>,
        completion: Completion,
    },
    Replace {
        contents: Vec<u8>,
        completion: Completion,
    },
}

pub(super) fn run(receiver: Receiver<Command>, path: PathBuf, mut file: File) {
    let mut pending = None;
    let mut failure: Option<String> = None;
    loop {
        let command = match pending.take().or_else(|| receiver.recv().ok()) {
            Some(command) => command,
            None => return,
        };
        if let Some(error) = &failure {
            complete(command, Err(error.clone()));
            continue;
        }
        match command {
            Command::Append { record, completion } => {
                let mut batch = vec![(record, completion)];
                let deadline = Instant::now() + GROUP_COMMIT_WINDOW;
                while batch.len() < MAXIMUM_BATCH_RECORDS {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match receiver.recv_timeout(remaining) {
                        Ok(Command::Append { record, completion }) => {
                            batch.push((record, completion));
                        }
                        Ok(replacement @ Command::Replace { .. }) => {
                            pending = Some(replacement);
                            break;
                        }
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                }
                let result = append_batch(&mut file, &batch).map_err(|error| {
                    format!("append and sync journal `{}`: {error}", path.display())
                });
                if let Err(error) = &result {
                    failure = Some(error.clone());
                }
                for (_, completion) in batch {
                    let _ = completion.send(result.clone());
                }
            }
            Command::Replace {
                contents,
                completion,
            } => {
                let result = replace(&path, &contents, &mut file).map_err(|error| {
                    format!("replace and sync journal `{}`: {error}", path.display())
                });
                if let Err(error) = &result {
                    failure = Some(error.clone());
                }
                let _ = completion.send(result);
            }
        }
    }
}

fn append_batch(file: &mut File, batch: &[PendingAppend]) -> std::io::Result<()> {
    for (record, _) in batch {
        file.write_all(record)?;
    }
    file.sync_data()
}

fn replace(path: &Path, contents: &[u8], file: &mut File) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "journal has no parent")
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    *file = OpenOptions::new()
        .append(true)
        .read(true)
        .mode(0o600)
        .open(path)?;
    Ok(())
}

fn complete(command: Command, result: Result<(), String>) {
    let completion = match command {
        Command::Append { completion, .. } | Command::Replace { completion, .. } => completion,
    };
    let _ = completion.send(result);
}
