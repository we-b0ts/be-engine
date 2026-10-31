use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub(super) async fn write(path: &Path, payload: &[u8]) -> Result<()> {
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

pub(super) async fn append(path: &Path, payload: &[u8]) -> Result<()> {
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

pub(super) async fn flush_and_evict(file: &mut tokio::fs::File, offset: u64) -> Result<u64> {
    crate::artifact_file::flush_and_evict(file, offset).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_and_read_preserve_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact.json");

        write(&path, b"{\"ok\":true}\n").await.unwrap();
        let contents = crate::recorder::test_io::read_to_string(&path)
            .await
            .unwrap();

        assert_eq!(contents, "{\"ok\":true}\n");
    }

    #[tokio::test]
    async fn append_preserves_existing_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("errors.jsonl");

        append(&path, b"first\n").await.unwrap();
        append(&path, b"second\n").await.unwrap();

        assert_eq!(
            crate::recorder::test_io::read_to_string(path)
                .await
                .unwrap(),
            "first\nsecond\n"
        );
    }
}
