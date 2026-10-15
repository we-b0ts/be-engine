//! Shared byte-budgeted access to an original immutable semantic record.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use super::{FileStamp, RecordLocation, RecordReader};

#[derive(Debug)]
pub(crate) struct RecordSource {
    path: PathBuf,
    stamp: FileStamp,
    reader: Arc<Mutex<RecordReader>>,
}

impl RecordSource {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            FileStamp::read(&self.path)? == self.stamp,
            "indexed dependency evidence changed: {}",
            self.path.display()
        );
        Ok(())
    }
    pub(crate) fn new(
        path: &Path,
        stamp: FileStamp,
        reader: Arc<Mutex<RecordReader>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            path: path.to_owned(),
            stamp,
            reader,
        })
    }

    pub(crate) fn reference(self: &Arc<Self>, location: RecordLocation) -> RecordRef {
        RecordRef {
            source: self.clone(),
            location,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RecordRef {
    pub(crate) source: Arc<RecordSource>,
    pub(crate) location: RecordLocation,
}

impl RecordRef {
    pub(crate) fn load<T: DeserializeOwned>(&self) -> Result<T> {
        let raw = self
            .source
            .reader
            .lock()
            .map_err(|_| anyhow::anyhow!("dependency cache lock poisoned"))?
            .read(&self.source.path, &self.source.stamp, &self.location)?;
        serde_json::from_slice(&raw).with_context(|| {
            format!(
                "invalid indexed dependency {} line {}",
                self.source.path.display(),
                self.location.line
            )
        })
    }
}
