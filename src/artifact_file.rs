use std::io;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use tokio::fs::File;

pub(crate) async fn flush_and_evict(file: &mut File, offset: u64) -> Result<u64> {
    file.sync_data()
        .await
        .context("failed to sync artifact file")?;
    evict_after_sync(file, offset).await
}

async fn evict_after_sync(file: &File, offset: u64) -> Result<u64> {
    let length = file
        .metadata()
        .await
        .context("failed to inspect artifact file")?
        .len();
    evict_complete_pages(file, offset, length).context("failed to release artifact file cache")
}

pub(crate) fn evict_complete_pages(file: &File, offset: u64, length: u64) -> io::Result<u64> {
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

pub(crate) fn page_size() -> io::Result<u64> {
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
    async fn flush_cursor_advances_only_through_complete_pages() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("traffic.jsonl");
        let page_size = page_size().unwrap();
        let payload = vec![b'x'; usize::try_from(page_size * 2 + 1).unwrap()];
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, &payload)
            .await
            .unwrap();

        let evicted_until = flush_and_evict(&mut file, 0).await.unwrap();

        assert_eq!(evicted_until, page_size * 2);
    }
}
