//! Serializable immutable Source locations shared by policy evidence and reports.
use super::{FileStamp, RecordLocation, RecordReader};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub path: PathBuf,
    pub stamp: FileStamp,
    pub location: RecordLocation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<(PathBuf, FileStamp)>,
}

impl SourceRecord {
    pub fn from_source(
        source: &super::scoped::Source,
        stamp: FileStamp,
        location: RecordLocation,
    ) -> Self {
        Self {
            path: source.path.clone(),
            stamp,
            location,
            view: source.view.clone(),
        }
    }

    fn source(&self) -> super::scoped::Source {
        super::scoped::Source {
            path: self.path.clone(),
            locations: None,
            view: self.view.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.source().validate()?;
        ensure!(
            FileStamp::read_native(&self.path)? == self.stamp,
            "referenced Source evidence changed after Replay"
        );
        Ok(())
    }

    pub fn read(&self) -> Result<std::sync::Arc<Vec<u8>>> {
        RecordReader::new(0).read_source(&self.source(), &self.stamp, &self.location)
    }
}
