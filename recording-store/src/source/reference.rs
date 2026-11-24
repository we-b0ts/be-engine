//! Shared byte-budgeted access to an original immutable semantic record.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

use super::{FileStamp, RecordLocation, RecordReader};

#[derive(Debug)]
pub struct RecordSource {
    path: PathBuf,
    stamp: FileStamp,
    reader: Arc<Mutex<RecordReader>>,
    view: Option<(PathBuf, FileStamp)>,
    resolution_error: Option<String>,
    verify: bool,
}

impl RecordSource {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.resolution_error.is_none(),
            "cannot resolve dependency view: {:?}",
            self.resolution_error
        );
        if !self.verify {
            return Ok(());
        }
        if let Some((path, stamp)) = &self.view {
            anyhow::ensure!(
                FileStamp::read_native(path)? == *stamp,
                "dependency view changed after admission"
            );
        }
        anyhow::ensure!(
            FileStamp::read(&self.path)? == self.stamp,
            "indexed dependency evidence changed: {}",
            self.path.display()
        );
        Ok(())
    }
    pub fn new(path: &Path, stamp: FileStamp, reader: Arc<Mutex<RecordReader>>) -> Arc<Self> {
        let verify = reader.lock().map_or(true, |reader| reader.verifies());
        let source = super::scoped::resolve(path);
        let (path, view, resolution_error) = match source {
            Ok(source) => (source.path, source.view, None),
            Err(error) => (path.to_owned(), None, Some(error.to_string())),
        };
        Arc::new(Self {
            path,
            stamp,
            reader,
            view,
            resolution_error,
            verify,
        })
    }

    pub fn reference(self: &Arc<Self>, location: RecordLocation) -> RecordRef {
        RecordRef {
            source: self.clone(),
            location,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordRef {
    pub source: Arc<RecordSource>,
    pub location: RecordLocation,
}

impl RecordRef {
    /// Load the envelope and protocol extension without restoring payload cells.
    pub fn load_metadata(&self) -> Result<serde_json::Value> {
        self.source.validate()?;
        self.source
            .reader
            .lock()
            .map_err(|_| anyhow::anyhow!("dependency cache lock poisoned"))?
            .read_metadata(&self.source.path, &self.source.stamp, &self.location)
    }

    pub fn load<T: DeserializeOwned>(&self) -> Result<T> {
        self.source.validate()?;
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

    /// Load a semantic value directly from a compact record.
    pub fn load_value(&self) -> Result<serde_json::Value> {
        if !super::compact::is_compact(&self.source.path) {
            return self.load();
        }
        self.source.validate()?;
        self.source
            .reader
            .lock()
            .map_err(|_| anyhow::anyhow!("dependency cache lock poisoned"))?
            .read_value(&self.source.path, &self.source.stamp, &self.location)
            .with_context(|| {
                format!(
                    "invalid indexed dependency {} line {}",
                    self.source.path.display(),
                    self.location.line
                )
            })
    }
}
impl traffic_protocol::evidence::RecordSource for RecordRef {
    fn load<T: serde::de::DeserializeOwned>(&self) -> anyhow::Result<T> {
        RecordRef::load(self)
    }

    fn byte_len(&self) -> Option<u64> {
        Some(self.location.length)
    }
}
