use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};

#[derive(Debug, Clone, Copy)]
pub struct JsonlBufferSettings {
    pub capacity: usize,
    pub flush_interval: Duration,
}

pub struct BufferedJsonlWriter {
    writer: BufWriter<File>,
    flush_interval: Duration,
    last_flush: Instant,
    evicted_until: u64,
    dirty: bool,
}

impl BufferedJsonlWriter {
    pub async fn open(path: &Path, settings: JsonlBufferSettings) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create JSONL dir {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("failed to open JSONL file {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::with_capacity(settings.capacity, file),
            flush_interval: settings.flush_interval,
            last_flush: Instant::now(),
            evicted_until: 0,
            dirty: false,
        })
    }

    pub async fn append(&mut self, line: &[u8]) -> Result<()> {
        self.writer
            .write_all(line)
            .await
            .context("failed to append JSONL record")?;
        self.dirty = true;
        if self.last_flush.elapsed() >= self.flush_interval {
            self.flush().await?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            self.last_flush = Instant::now();
            return Ok(());
        }
        self.writer
            .flush()
            .await
            .context("failed to flush JSONL records")?;
        self.evicted_until =
            super::storage::flush_and_evict(self.writer.get_mut(), self.evicted_until).await?;
        self.dirty = false;
        self.last_flush = Instant::now();
        Ok(())
    }
}

pub struct JsonlWriterPool {
    settings: JsonlBufferSettings,
    writers: HashMap<PathBuf, BufferedJsonlWriter>,
}

impl JsonlWriterPool {
    pub fn new(settings: JsonlBufferSettings) -> Self {
        Self {
            settings,
            writers: HashMap::new(),
        }
    }

    pub async fn append(&mut self, path: &Path, line: &[u8]) -> Result<()> {
        if let Some(writer) = self.writers.get_mut(path) {
            return writer.append(line).await;
        }

        let writer = BufferedJsonlWriter::open(path, self.settings).await?;
        self.writers.insert(path.to_path_buf(), writer);
        self.writers
            .get_mut(path)
            .expect("JSONL writer was just inserted")
            .append(line)
            .await
    }

    pub async fn flush_and_remove(&mut self, path: &Path) -> Result<()> {
        if let Some(mut writer) = self.writers.remove(path) {
            writer.flush().await?;
        }
        Ok(())
    }

    pub async fn flush_all(&mut self) -> Result<()> {
        let paths = self.writers.keys().cloned().collect::<Vec<_>>();
        for path in paths {
            self.flush_and_remove(&path).await?;
        }
        Ok(())
    }

    pub async fn flush_open(&mut self) -> Result<()> {
        for writer in self.writers.values_mut() {
            writer.flush().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> JsonlBufferSettings {
        JsonlBufferSettings {
            capacity: 4096,
            flush_interval: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn buffered_writer_flushes_explicitly() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let mut writer = BufferedJsonlWriter::open(&path, settings()).await.unwrap();

        writer.append(b"{\"event\":1}\n").await.unwrap();
        assert!(writer.dirty);
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"");

        writer.flush().await.unwrap();
        assert!(!writer.dirty);
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"{\"event\":1}\n");
    }

    #[tokio::test]
    async fn writer_pool_flushes_only_selected_file() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first/events.jsonl");
        let second = temp.path().join("second/events.jsonl");
        let mut pool = JsonlWriterPool::new(settings());
        pool.append(&first, b"first\n").await.unwrap();
        pool.append(&second, b"second\n").await.unwrap();

        pool.flush_and_remove(&first).await.unwrap();

        assert_eq!(tokio::fs::read(&first).await.unwrap(), b"first\n");
        assert_eq!(tokio::fs::read(&second).await.unwrap(), b"");
        pool.flush_all().await.unwrap();
        assert_eq!(tokio::fs::read(&second).await.unwrap(), b"second\n");
    }
}
