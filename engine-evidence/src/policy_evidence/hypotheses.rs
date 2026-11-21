//! Authenticated append-only hypothesis decisions, flushed outside Replay's state lock.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};
mod publication;
pub(in crate::policy_evidence) use publication::stage;

const JOURNAL_BYTE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Progress {
    durable: u64,
    error: Option<String>,
    bytes: u64,
    sha256: String,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            durable: 0,
            error: None,
            bytes: 0,
            sha256: super::digest(&[]),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalManifest {
    pub path: PathBuf,
    pub enqueued: u64,
    pub durable: u64,
    pub complete: bool,
    pub error: Option<String>,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug)]
struct Message {
    line: Vec<u8>,
    protected_files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
    sender: mpsc::UnboundedSender<Message>,
    progress: watch::Receiver<Progress>,
    sequence: Arc<Mutex<(u64, Option<String>, u64)>>,
    key: Arc<Vec<u8>>,
}

impl Journal {
    pub fn create(path: PathBuf, key: Vec<u8>) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        // A durable file also needs a durable directory entry after creation.
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        // Replay can append a burst while it holds its state lock. Bound the
        // queue by the journal's byte budget so producers can keep ordering
        // their records without waiting for filesystem writes under that lock.
        let (sender, mut receiver) = mpsc::unbounded_channel::<Message>();
        let (progress_sender, progress) = watch::channel(Progress::default());
        let handle =
            tokio::runtime::Handle::try_current().context("hypothesis journal requires Tokio")?;
        // A batch is one blocking filesystem transaction. Tokio's individual
        // async metadata/open/sync calls each schedule a blocking job; keeping
        // the bounded writer together avoids those handoffs without relaxing
        // the acknowledgement's payload, directory or journal durability.
        handle.spawn(async move {
            let mut file = file;
            let mut durable = 0;
            let mut bytes = 0;
            let mut hasher = Sha256::new();
            let mut published_files = BTreeSet::new();
            while let Some(first) = receiver.recv().await {
                let mut batch = vec![first];
                while batch.len() < 64 {
                    match receiver.try_recv() {
                        Ok(next) => batch.push(next),
                        Err(_) => break,
                    }
                }
                let count = batch.len() as u64;
                let mut batch_hasher = hasher.clone();
                let mut batch_bytes = 0;
                for message in &batch {
                    batch_bytes += message.line.len() as u64;
                    batch_hasher.update(&message.line);
                }
                let transaction = tokio::task::spawn_blocking(move || {
                    let result = persist_batch(&mut file, &batch, &mut published_files);
                    (file, published_files, result)
                })
                .await;
                let (returned_file, returned_published_files, result) = match transaction {
                    Ok(transaction) => transaction,
                    Err(_) => {
                        progress_sender.send_replace(Progress {
                            durable,
                            error: Some("hypothesis journal filesystem worker stopped".into()),
                            bytes,
                            sha256: format!("sha256:{:x}", hasher.clone().finalize()),
                        });
                        return;
                    }
                };
                file = returned_file;
                published_files = returned_published_files;
                if let Err(error) = result {
                    progress_sender.send_replace(Progress {
                        durable,
                        error: Some(error.to_string()),
                        bytes,
                        sha256: format!("sha256:{:x}", hasher.clone().finalize()),
                    });
                    return;
                }
                durable += count;
                bytes += batch_bytes;
                hasher = batch_hasher;
                progress_sender.send_replace(Progress {
                    durable,
                    error: None,
                    bytes,
                    sha256: format!("sha256:{:x}", hasher.clone().finalize()),
                });
            }
        });
        Ok(Self {
            path,
            sender,
            progress,
            sequence: Arc::new(Mutex::new((0, None, 0))),
            key: Arc::new(key),
        })
    }

    pub fn append(&self, value: &impl Serialize) -> Result<()> {
        self.append_with_protected_files(value, Vec::new())
    }

    pub fn append_with_protected_files(
        &self,
        value: &impl Serialize,
        protected_files: Vec<PathBuf>,
    ) -> Result<()> {
        let mut sequence = self.sequence.lock().expect("hypothesis journal sequence");
        ensure!(sequence.1.is_none(), "hypothesis journal unavailable");
        let next = sequence
            .0
            .checked_add(1)
            .context("hypothesis journal sequence overflow")?;
        let payload = serde_json::to_value(value)?;
        let signed = serde_json::to_vec(&(next, &payload))?;
        ensure!(
            signed.len() <= 1024 * 1024,
            "hypothesis journal record exceeds 1 MiB"
        );
        let authentication = super::v2::sign(&self.key, "hypothesis", &(next, &payload))?;
        let mut line = serde_json::to_vec(
            &serde_json::json!({"sequence":next,"payload":payload,"sha256":super::digest(&signed),"authentication":authentication}),
        )?;
        line.push(b'\n');
        if sequence.2 + line.len() as u64 > JOURNAL_BYTE_LIMIT {
            sequence.1 = Some("hypothesis journal exceeds 64 MiB".into());
            anyhow::bail!("hypothesis journal metadata budget exhausted");
        }
        let bytes = line.len() as u64;
        if self
            .sender
            .send(Message {
                line,
                protected_files,
            })
            .is_err()
        {
            sequence.1 = Some("hypothesis journal writer stopped".into());
            anyhow::bail!("hypothesis journal writer stopped");
        }
        sequence.0 = next;
        sequence.2 += bytes;
        Ok(())
    }

    pub async fn wait_durable(&self) -> Result<()> {
        let target = {
            let sequence = self.sequence.lock().expect("hypothesis journal sequence");
            ensure!(
                sequence.1.is_none(),
                "hypothesis journal coverage is incomplete"
            );
            sequence.0
        };
        let mut progress = self.progress.clone();
        loop {
            let observed = progress.borrow_and_update().clone();
            ensure!(
                observed.error.is_none(),
                "hypothesis journal persistence failed: {:?}",
                observed.error
            );
            if observed.durable >= target {
                return Ok(());
            }
            progress
                .changed()
                .await
                .context("hypothesis journal writer stopped before durable acknowledgement")?;
        }
    }

    pub fn manifest(&self) -> JournalManifest {
        let (enqueued, queued_error, _) = self
            .sequence
            .lock()
            .expect("hypothesis journal sequence")
            .clone();
        let progress = self.progress.borrow().clone();
        let error = queued_error.or(progress.error);
        JournalManifest {
            path: PathBuf::from(self.path.file_name().expect("hypothesis journal filename")),
            enqueued,
            durable: progress.durable,
            complete: error.is_none() && enqueued == progress.durable,
            error,
            bytes: progress.bytes,
            sha256: progress.sha256,
        }
    }
}

fn persist_batch(
    file: &mut std::fs::File,
    batch: &[Message],
    published_files: &mut BTreeSet<PathBuf>,
) -> std::io::Result<()> {
    let protected = batch
        .iter()
        .flat_map(|message| message.protected_files.iter().cloned())
        .collect::<BTreeSet<_>>();
    let directories = protected
        .iter()
        // Appending an already published segment changes its data, not its
        // directory entry. A newly rotated segment still syncs its directory.
        .filter(|path| !published_files.contains(*path))
        .filter_map(|path| path.parent().map(std::path::Path::to_owned))
        .collect::<BTreeSet<_>>();
    for path in &protected {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "protected hypothesis witness must be a regular file",
            ));
        }
        std::fs::File::open(path)?.sync_all()?;
    }
    for directory in directories {
        std::fs::File::open(directory)?.sync_all()?;
    }
    for message in batch {
        file.write_all(&message.line)?;
    }
    file.sync_data()?;
    published_files.extend(protected);
    Ok(())
}
