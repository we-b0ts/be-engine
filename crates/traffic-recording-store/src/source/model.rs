use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    pub size: u64,
    pub device: u64,
    pub inode: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}

impl FileStamp {
    /// Linux filesystems can reuse ctime within a clock tick. Only trust a
    /// stamp as a content seal if it was already old when validation began.
    pub fn stable_before(&self, validation: std::time::SystemTime) -> bool {
        use std::time::{Duration, UNIX_EPOCH};

        let Ok(seconds) = u64::try_from(self.changed.0) else {
            return false;
        };
        let Ok(nanos) = u32::try_from(self.changed.1) else {
            return false;
        };
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .and_then(|changed| validation.duration_since(changed).ok())
            .is_some_and(|age| age >= Duration::from_secs(2))
    }

    pub fn read(path: &std::path::Path) -> anyhow::Result<Self> {
        let source = super::scoped::resolve(path)?;
        Self::read_native(&source.path)
    }
    pub fn read_native(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::ensure;
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && !m.file_type().is_symlink(),
            "dependency evidence must be a regular unlinked file: {}",
            path.display()
        );
        Ok(Self {
            size: m.len(),
            device: m.dev(),
            inode: m.ino(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordLocation {
    pub line: usize,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}
