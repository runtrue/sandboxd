mod reader;
mod writer;

pub(crate) use reader::read_records;
use reader::repair_torn_tail;

use runtrue_sandbox_oci::SandboxError;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use writer::Command;

const MAXIMUM_RECORD_BYTES: usize = 64 * 1024;
const MAXIMUM_REPLACEMENT_BYTES: usize = 64 * 1024 * 1024;
const JOURNAL_QUEUE_DEPTH: usize = 4_096;

#[derive(Debug, Clone)]
pub(crate) struct DurableJournal {
    inner: Arc<JournalInner>,
}

#[derive(Debug)]
struct JournalInner {
    sender: Mutex<Option<SyncSender<Command>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) struct JournalReceipt {
    completion: Receiver<Result<(), String>>,
}

impl DurableJournal {
    pub(crate) fn open(path: &Path) -> Result<Self, SandboxError> {
        if !path.is_absolute() {
            return Err(SandboxError::Runtime(
                "journal path must be absolute".to_owned(),
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| SandboxError::Runtime("journal path has no parent".to_owned()))?;
        fs::create_dir_all(parent).map_err(|error| journal_error(parent, error))?;
        let existed = path.exists();
        repair_torn_tail(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| journal_error(path, error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| journal_error(path, error))?;
        if !existed {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| journal_error(parent, error))?;
        }
        let (sender, receiver) = mpsc::sync_channel(JOURNAL_QUEUE_DEPTH);
        let worker_path = path.to_path_buf();
        let worker = std::thread::Builder::new()
            .name(format!(
                "journal-{}",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("state")
            ))
            .spawn(move || writer::run(receiver, worker_path, file))
            .map_err(|error| SandboxError::Runtime(format!("start journal writer: {error}")))?;
        Ok(Self {
            inner: Arc::new(JournalInner {
                sender: Mutex::new(Some(sender)),
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    pub(crate) fn enqueue_append(&self, record: Vec<u8>) -> Result<JournalReceipt, SandboxError> {
        if record.is_empty() || record.len() > MAXIMUM_RECORD_BYTES || record.last() != Some(&b'\n')
        {
            return Err(SandboxError::Runtime(
                "journal record is empty, oversized, or unterminated".to_owned(),
            ));
        }
        self.enqueue(|completion| Command::Append { record, completion })
    }

    pub(crate) fn enqueue_replace(
        &self,
        contents: Vec<u8>,
    ) -> Result<JournalReceipt, SandboxError> {
        if contents.len() > MAXIMUM_REPLACEMENT_BYTES
            || (!contents.is_empty() && contents.last() != Some(&b'\n'))
        {
            return Err(SandboxError::Runtime(
                "journal replacement is oversized or unterminated".to_owned(),
            ));
        }
        self.enqueue(|completion| Command::Replace {
            contents,
            completion,
        })
    }

    fn enqueue(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<(), String>>) -> Command,
    ) -> Result<JournalReceipt, SandboxError> {
        let (completion, receiver) = mpsc::channel();
        self.inner
            .sender
            .lock()
            .expect("journal sender lock")
            .as_ref()
            .ok_or_else(|| SandboxError::Runtime("journal writer is closed".to_owned()))?
            .send(command(completion))
            .map_err(|_| SandboxError::Runtime("journal writer stopped".to_owned()))?;
        Ok(JournalReceipt {
            completion: receiver,
        })
    }
}

impl JournalReceipt {
    pub(crate) fn wait(self) -> Result<(), SandboxError> {
        self.completion
            .recv()
            .map_err(|_| SandboxError::Runtime("journal writer stopped".to_owned()))?
            .map_err(SandboxError::Runtime)
    }
}

impl Drop for JournalInner {
    fn drop(&mut self) {
        self.sender.get_mut().expect("journal sender lock").take();
        if let Some(worker) = self.worker.get_mut().expect("journal worker lock").take() {
            let _ = worker.join();
        }
    }
}

fn journal_error(path: impl Into<PathBuf>, error: std::io::Error) -> SandboxError {
    SandboxError::Io {
        path: path.into(),
        source: error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_replaces_in_queue_order() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.wal");
        let journal = DurableJournal::open(&path).expect("journal");
        let first = journal
            .enqueue_append(b"first\n".to_vec())
            .expect("first append");
        let replace = journal
            .enqueue_replace(b"replacement\n".to_vec())
            .expect("replacement");
        let last = journal
            .enqueue_append(b"last\n".to_vec())
            .expect("last append");
        first.wait().expect("first durable");
        replace.wait().expect("replacement durable");
        last.wait().expect("last durable");
        assert_eq!(
            fs::read_to_string(path).expect("journal contents"),
            "replacement\nlast\n"
        );
    }

    #[test]
    fn opening_a_journal_repairs_a_torn_final_record() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.wal");
        fs::write(&path, b"complete\ntorn").expect("torn journal");
        let journal = DurableJournal::open(&path).expect("journal");
        journal
            .enqueue_append(b"last\n".to_vec())
            .expect("append")
            .wait()
            .expect("durable");
        assert_eq!(
            fs::read_to_string(path).expect("journal contents"),
            "complete\nlast\n"
        );
    }

    #[test]
    fn concurrent_appends_are_all_durable() {
        use std::{
            collections::BTreeSet,
            sync::{Arc, Barrier},
        };

        const WRITERS: usize = 64;
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("state.wal");
        let journal = Arc::new(DurableJournal::open(&path).expect("journal"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let writers = (0..WRITERS)
            .map(|index| {
                let journal = Arc::clone(&journal);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    journal
                        .enqueue_append(format!("record-{index}\n").into_bytes())
                        .expect("append")
                        .wait()
                        .expect("durable");
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("writer thread");
        }
        drop(journal);

        let records = read_records(&path, 1024 * 1024, WRITERS).expect("records");
        let actual = records
            .into_iter()
            .map(|record| String::from_utf8(record).expect("UTF-8 record"))
            .collect::<BTreeSet<_>>();
        let expected = (0..WRITERS)
            .map(|index| format!("record-{index}\n"))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }
}
