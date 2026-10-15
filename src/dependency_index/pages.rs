//! Disk-backed metadata pages; payloads and session consumption are separate owners.
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::store;

const PAGE_RECORDS: usize = 256;
const PAGE_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct Directory {
    path: PathBuf,
    keep: AtomicBool,
}
impl Drop for Directory {
    fn drop(&mut self) {
        if !self.keep.load(Ordering::Relaxed) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Debug)]
pub(crate) struct PageWriter<T> {
    directory: Arc<Directory>,
    records: Vec<T>,
    bytes: usize,
    count: usize,
    lengths: Vec<usize>,
}

impl<T: Serialize + DeserializeOwned> PageWriter<T> {
    pub(crate) fn new(source: &Path) -> Result<Self> {
        let parent = store::cache_directory(source);
        Self::new_in(&parent)
    }
    pub(crate) fn new_in(parent: &Path) -> Result<Self> {
        store::private_directory(parent)?;
        let directory = parent.join(format!("pages-{}", uuid::Uuid::new_v4().simple()));
        store::private_directory(&directory)?;
        Ok(Self {
            directory: Arc::new(Directory {
                path: directory,
                keep: AtomicBool::new(false),
            }),
            records: Vec::new(),
            bytes: 0,
            count: 0,
            lengths: Vec::new(),
        })
    }

    pub(crate) fn push(&mut self, record: T) -> Result<()> {
        self.bytes += serde_json::to_vec(&record)?.len();
        self.records.push(record);
        self.count += 1;
        if self.records.len() >= PAGE_RECORDS || self.bytes >= PAGE_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.records.is_empty() {
            return Ok(());
        }
        store::write_json(
            &self
                .directory
                .path
                .join(format!("{}.json", self.lengths.len())),
            &self.records,
        )?;
        self.lengths.push(self.records.len());
        self.records.clear();
        self.bytes = 0;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Paged<T>> {
        self.flush()?;
        Ok(Paged {
            directory: self.directory,
            count: self.count,
            starts: Arc::new(page_starts(&self.lengths)),
            lengths: Arc::new(self.lengths),
            _record: PhantomData,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Paged<T> {
    directory: Arc<Directory>,
    pub(crate) count: usize,
    lengths: Arc<Vec<usize>>,
    starts: Arc<Vec<usize>>,
    _record: PhantomData<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PageManifest {
    directory: PathBuf,
    pub(crate) count: usize,
    lengths: Vec<usize>,
}

impl PageManifest {
    pub(crate) fn stage_into(&self, source: &Path, destination: &Path) -> Result<()> {
        let resolved = self.clone().resolve(source)?;
        let target = self.clone().resolve(destination)?.directory;
        let inventory = Paged::<serde_json::Value>::restore(resolved)?;
        store::private_directory(&target)?;
        for page in 0..inventory.pages() {
            let from = inventory.directory.path.join(format!("{page}.json"));
            super::FileStamp::read(&from)?;
            std::fs::copy(from, target.join(format!("{page}.json")))?;
        }
        Ok(())
    }
    pub(crate) fn relative_to(mut self, root: &Path) -> Result<Self> {
        self.directory = self.directory.strip_prefix(root)?.to_owned();
        Ok(self)
    }
    pub(crate) fn resolve(mut self, root: &Path) -> Result<Self> {
        ensure!(
            self.directory
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
            "invalid dependency page relative path"
        );
        self.directory = root.join(self.directory);
        Ok(self)
    }
}

impl<T: DeserializeOwned> Paged<T> {
    pub(crate) fn manifest(&self) -> PageManifest {
        PageManifest {
            directory: self.directory.path.clone(),
            count: self.count,
            lengths: self.lengths.as_ref().clone(),
        }
    }
    pub(crate) fn persist(&self) -> PageManifest {
        self.directory.keep.store(true, Ordering::Relaxed);
        self.manifest()
    }
    pub(crate) fn restore(manifest: PageManifest) -> Result<Self> {
        ensure!(
            manifest
                .lengths
                .iter()
                .all(|length| *length > 0 && *length <= PAGE_RECORDS)
                && manifest
                    .lengths
                    .iter()
                    .try_fold(0usize, |sum, length| sum.checked_add(*length))
                    == Some(manifest.count),
            "invalid dependency page manifest counts"
        );
        let metadata = std::fs::symlink_metadata(&manifest.directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "linked dependency page directory"
        );
        Ok(Self {
            directory: Arc::new(Directory {
                path: manifest.directory,
                keep: AtomicBool::new(true),
            }),
            count: manifest.count,
            starts: Arc::new(page_starts(&manifest.lengths)),
            lengths: Arc::new(manifest.lengths),
            _record: PhantomData,
        })
    }
    pub(crate) fn page_start(&self, page: usize) -> usize {
        self.starts[page]
    }
    pub(crate) fn page_for(&self, index: usize) -> Result<usize> {
        ensure!(
            index < self.count,
            "dependency metadata record out of bounds"
        );
        Ok(self.starts.partition_point(|start| *start <= index) - 1)
    }
    pub(crate) fn pages(&self) -> usize {
        self.lengths.len()
    }
    pub(crate) fn read_page(&self, page: usize) -> Result<Vec<T>> {
        ensure!(
            page < self.lengths.len(),
            "dependency metadata page out of bounds"
        );
        let records: Vec<T> = store::read_json(&self.directory.path.join(format!("{page}.json")))?;
        ensure!(
            records.len() == self.lengths[page],
            "dependency metadata page count changed"
        );
        Ok(records)
    }
}

fn page_starts(lengths: &[usize]) -> Vec<usize> {
    let mut offset = 0;
    lengths
        .iter()
        .map(|length| {
            let start = offset;
            offset += length;
            start
        })
        .collect()
}
