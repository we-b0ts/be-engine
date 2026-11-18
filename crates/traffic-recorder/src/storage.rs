use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub async fn write(path: &Path, payload: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open recorder artifact {}", path.display()))?;
    file.write_all(payload)
        .await
        .with_context(|| format!("failed to write recorder artifact {}", path.display()))?;
    crate::artifact_file::flush_and_evict(&mut file, 0)
        .await
        .with_context(|| format!("failed to finalize recorder artifact {}", path.display()))?;
    Ok(())
}

pub async fn append(path: &Path, payload: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("failed to open recorder artifact {}", path.display()))?;
    file.write_all(payload)
        .await
        .with_context(|| format!("failed to append recorder artifact {}", path.display()))?;
    crate::artifact_file::flush_and_evict(&mut file, 0)
        .await
        .with_context(|| format!("failed to finalize recorder artifact {}", path.display()))?;
    Ok(())
}

pub async fn flush_and_evict(file: &mut tokio::fs::File, offset: u64) -> Result<u64> {
    crate::artifact_file::flush_and_evict(file, offset).await
}
