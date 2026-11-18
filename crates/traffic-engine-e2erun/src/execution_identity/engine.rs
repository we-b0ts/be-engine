//! Reuse an engine digest within this process until the executable file changes.
use std::fs::{self, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result, ensure};

#[derive(PartialEq, Eq)]
struct Identity {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    file: (u64, u64, i64, i64),
}

impl Identity {
    fn new(path: &Path, metadata: &Metadata) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            path: path.into(),
            len: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            file: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        })
    }
}

static CACHE: Mutex<Option<(Identity, String)>> = Mutex::new(None);

pub(super) fn revision(path: &Path) -> Result<String> {
    let key = Identity::new(path, &fs::metadata(path)?)?;
    let mut cache = CACHE
        .lock()
        .map_err(|_| anyhow::anyhow!("engine fingerprint cache is poisoned"))?;
    if let Some((previous, revision)) = cache.as_ref()
        && previous == &key
    {
        return Ok(revision.clone());
    }
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to read traffic-e2e binary {}", path.display()))?;
    let mut hash = super::Fnv1a::default();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("failed to fingerprint traffic-e2e binary")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ensure!(
        key == Identity::new(path, &fs::metadata(path)?)?,
        "traffic-e2e binary changed during fingerprinting; retry status"
    );
    let revision = hash.finish();
    *cache = Some((key, revision.clone()));
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_and_atomically_replaced_binaries_invalidate_cached_revision() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("engine");
        fs::write(&path, b"old").unwrap();
        let before = revision(&path).unwrap();
        assert_eq!(revision(&path).unwrap(), before);
        fs::write(&path, b"changed").unwrap();
        let changed = revision(&path).unwrap();
        assert_ne!(changed, before);
        let replacement = temp.path().join("replacement");
        fs::write(&replacement, b"replace").unwrap();
        fs::rename(replacement, &path).unwrap();
        assert_ne!(revision(&path).unwrap(), changed);
        fs::remove_file(&path).unwrap();
        assert!(revision(&path).is_err());
    }
}
