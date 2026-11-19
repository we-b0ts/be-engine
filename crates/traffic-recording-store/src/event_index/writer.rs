//! Publish completed trace spans and their sequence-keyed locators during capture.
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use traffic_model::recording::LedgerFileIdentity;

use super::{INDEX, POSTINGS, Span, locator_position};
use crate::writer::{FileDigest, JsonlWriterPool};

const LOCATOR_BATCH: usize = 4096;

pub(crate) struct EventLocations {
    root: PathBuf,
    active: HashMap<u64, ActiveTrace>,
    posting_digest: FileDigest,
    locator: Arc<File>,
    pending: Vec<Locator>,
    posting: Vec<u8>,
}

struct ActiveTrace {
    journal: usize,
    spans: Vec<Span>,
    wire_end: bool,
}

struct Locator {
    position: u64,
    pointer: u64,
}

impl EventLocations {
    pub(crate) async fn initialize(root: &Path) -> Result<Self> {
        crate::storage::write(&root.join(POSTINGS), b"").await?;
        let locator = tokio::fs::File::create(root.join(INDEX))
            .await?
            .into_std()
            .await;
        Ok(Self {
            root: root.to_owned(),
            active: HashMap::new(),
            posting_digest: FileDigest::default(),
            locator: Arc::new(locator),
            pending: Vec::with_capacity(LOCATOR_BATCH),
            posting: Vec::new(),
        })
    }

    pub(crate) fn append(
        &mut self,
        journal: usize,
        dependency: u64,
        offset: u64,
        length: usize,
        wire_end: bool,
    ) -> Result<()> {
        let trace = self
            .active
            .entry(dependency)
            .or_insert_with(|| ActiveTrace {
                journal,
                spans: Vec::new(),
                wire_end: false,
            });
        ensure!(
            trace.journal == journal,
            "dependency trace spans two streams"
        );
        trace.spans.push(Span {
            offset,
            length: u32::try_from(length)?,
        });
        trace.wire_end |= wire_end;
        Ok(())
    }

    pub(crate) fn has_wire_end(&self, dependency: u64) -> bool {
        self.active
            .get(&dependency)
            .is_some_and(|trace| trace.wire_end)
    }

    pub(crate) fn journal(&self, dependency: u64) -> Option<usize> {
        self.active.get(&dependency).map(|trace| trace.journal)
    }

    pub(crate) async fn finish(
        &mut self,
        files: &mut JsonlWriterPool,
        dependency: u64,
    ) -> Result<()> {
        let ActiveTrace { journal, spans, .. } = self
            .active
            .remove(&dependency)
            .context("terminal dependency has no recorded event trace")?;
        let bytes = &mut self.posting;
        bytes.clear();
        bytes.push(journal as u8);
        bytes.extend_from_slice(&u32::try_from(spans.len())?.to_le_bytes());
        for span in spans {
            bytes.extend_from_slice(&span.offset.to_le_bytes());
            bytes.extend_from_slice(&span.length.to_le_bytes());
        }
        let pointer = self
            .posting_digest
            .length()
            .checked_add(1)
            .context("event posting offset overflow")?;
        files.append(&self.root.join(POSTINGS), bytes).await?;
        self.posting_digest.observe(bytes);
        self.pending.push(Locator {
            position: locator_position(dependency)?,
            pointer,
        });
        if self.pending.len() == LOCATOR_BATCH {
            self.flush_locators().await?;
        }
        Ok(())
    }

    async fn flush_locators(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let file = self.locator.clone();
        let mut pending = std::mem::take(&mut self.pending);
        self.pending = tokio::task::spawn_blocking(move || {
            for locator in pending.drain(..) {
                file.write_all_at(&locator.pointer.to_le_bytes(), locator.position)?;
            }
            Ok::<_, std::io::Error>(pending)
        })
        .await??;
        Ok(())
    }

    pub(crate) async fn seal(&mut self) -> Result<[LedgerFileIdentity; 2]> {
        self.flush_locators().await?;
        let locator = self.locator.clone();
        let path = self.root.join(INDEX);
        let index = tokio::task::spawn_blocking(move || {
            locator.sync_all()?;
            let mut file = File::open(path)?;
            let mut buffer = [0; 64 * 1024];
            let mut digest = FileDigest::default();
            loop {
                let length = file.read(&mut buffer)?;
                if length == 0 {
                    return Ok::<_, std::io::Error>(digest.identity(INDEX));
                }
                digest.observe(&buffer[..length]);
            }
        })
        .await??;
        Ok([index, self.posting_digest.identity(POSTINGS)])
    }
}
