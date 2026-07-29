use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    flush_and_evict(&mut file, 0)
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
    flush_and_evict(&mut file, 0)
        .await
        .with_context(|| format!("failed to finalize recorder artifact {}", path.display()))?;
    Ok(())
}

pub(super) async fn read_to_string(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .await
        .with_context(|| format!("failed to open recorder artifact {}", path.display()))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .await
        .with_context(|| format!("failed to read recorder artifact {}", path.display()))?;
    evict_complete_pages(&file, 0, file.metadata().await?.len()).with_context(|| {
        format!(
            "failed to release recorder artifact cache {}",
            path.display()
        )
    })?;
    Ok(contents)
}

pub(super) async fn flush_and_evict(file: &mut File, offset: u64) -> Result<u64> {
    file.sync_data()
        .await
        .context("failed to sync recorder artifact")?;
    let length = file
        .metadata()
        .await
        .context("failed to inspect recorder artifact")?
        .len();
    evict_complete_pages(file, offset, length).context("failed to release recorder artifact cache")
}

fn evict_complete_pages(file: &File, offset: u64, length: u64) -> io::Result<u64> {
    let page_size = page_size()?;
    let offset = offset - (offset % page_size);
    let evict_until = length - (length % page_size);
    if evict_until <= offset {
        return Ok(offset);
    }
    let advise_offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cache offset exceeds off_t"))?;
    let advise_length = libc::off_t::try_from(evict_until - offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cache length exceeds off_t"))?;
    // SAFETY: the descriptor belongs to the open File and both ranges were checked
    // above. POSIX_FADV_DONTNEED is advisory and does not alter file contents.
    let result = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            advise_offset,
            advise_length,
            libc::POSIX_FADV_DONTNEED,
        )
    };
    if result == 0 {
        Ok(evict_until)
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

pub(super) fn page_size() -> io::Result<u64> {
    // SAFETY: sysconf reads the process-wide immutable page-size setting.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| io::Error::other("failed to determine system page size"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_and_read_preserve_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("artifact.json");

        write(&path, b"{\"ok\":true}\n").await.unwrap();
        let contents = read_to_string(&path).await.unwrap();

        assert_eq!(contents, "{\"ok\":true}\n");
    }

    #[tokio::test]
    async fn append_preserves_existing_artifact_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("errors.jsonl");

        append(&path, b"first\n").await.unwrap();
        append(&path, b"second\n").await.unwrap();

        assert_eq!(
            tokio::fs::read_to_string(path).await.unwrap(),
            "first\nsecond\n"
        );
    }

    #[tokio::test]
    async fn flush_cursor_advances_only_through_complete_pages() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("traffic.jsonl");
        let page_size = page_size().unwrap();
        let payload = vec![b'x'; usize::try_from(page_size * 2 + 1).unwrap()];
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .await
            .unwrap();
        file.write_all(&payload).await.unwrap();

        let evicted_until = flush_and_evict(&mut file, 0).await.unwrap();

        assert_eq!(evicted_until, page_size * 2);
    }
}
