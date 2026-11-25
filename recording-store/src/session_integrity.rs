//! Authenticate timeline chunks against the seal before exposing their bytes.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use traffic_model::recording::{LedgerFileIdentity, RecordingManifest, SESSION_RECORDING_SCHEMA};

use crate::{session, source::recording};

pub const INDEX: &str = "event-checksums.bin";
const CHUNK_BYTES: usize = 256 * 1024;
const HASH_BYTES: usize = 32;
type Hash = [u8; HASH_BYTES];

pub(crate) struct Chunks {
    leaves: Vec<Hash>,
    pending: Sha256,
    bytes: usize,
}

impl Default for Chunks {
    fn default() -> Self {
        Self {
            leaves: Vec::new(),
            pending: leaf_builder(),
            bytes: 0,
        }
    }
}

impl Chunks {
    pub(crate) fn observe(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let len = data.len().min(CHUNK_BYTES - self.bytes);
            self.pending.update(&data[..len]);
            self.bytes += len;
            data = &data[len..];
            if self.bytes == CHUNK_BYTES {
                self.finish_chunk();
            }
        }
    }

    pub(crate) async fn seal(
        &mut self,
        root: &Path,
        index_name: &str,
        identity: &mut LedgerFileIdentity,
    ) -> Result<LedgerFileIdentity> {
        if self.bytes != 0 || self.leaves.is_empty() {
            self.finish_chunk();
        }
        let mut level = std::mem::take(&mut self.leaves);
        let mut index = Vec::new();
        while level.len() > 1 {
            index.extend(level.iter().flatten());
            level = level
                .chunks(2)
                .map(|pair| pair.get(1).map_or(pair[0], |right| parent(&pair[0], right)))
                .collect();
        }
        identity.chunk_root = Some(hex(&level[0]));
        crate::storage::write(&root.join(index_name), &index).await?;
        Ok(LedgerFileIdentity {
            path: index_name.into(),
            length: index.len() as u64,
            sha256: crate::source::digest(&index),
            chunk_root: None,
        })
    }

    fn finish_chunk(&mut self) {
        let hash = std::mem::replace(&mut self.pending, leaf_builder());
        self.leaves.push(hash.finalize().into());
        self.bytes = 0;
    }
}

/// Open the Source timeline. Each chunk is verified before it enters Replay.
/// Historical ledgers authenticate the complete recording before access.
pub fn events(root: &Path, manifest: &RecordingManifest) -> Result<Box<dyn Read + Send>> {
    if manifest.schema == SESSION_RECORDING_SCHEMA {
        return open(root, manifest, session::FILE, INDEX);
    }
    let identity = manifest
        .files
        .iter()
        .find(|identity| identity.path == session::FILE)
        .context("sealed recording has no session event stream")?;
    recording::authenticate(root)?;
    Ok(Box::new(open_file(
        &root.join(session::FILE),
        identity.length,
    )?))
}

pub(crate) fn open(
    root: &Path,
    manifest: &RecordingManifest,
    name: &'static str,
    index: &str,
) -> Result<Box<dyn Read + Send>> {
    let identity = manifest
        .files
        .iter()
        .find(|identity| identity.path == name)
        .with_context(|| format!("recording seal omits {name}"))?;
    let chunk_root = identity
        .chunk_root
        .as_ref()
        .with_context(|| format!("recording seal omits authenticated chunks for {name}"))?;
    let blocks = identity.length.div_ceil(CHUNK_BYTES as u64).max(1);
    let mut nodes = 0_u64;
    let mut width = blocks;
    while width > 1 {
        nodes = nodes
            .checked_add(width)
            .context("event checksum count overflow")?;
        width = width.div_ceil(2);
    }
    let length = nodes
        .checked_mul(HASH_BYTES as u64)
        .context("event checksum size overflow")?;
    ensure!(
        manifest
            .files
            .iter()
            .any(|identity| identity.path == index && identity.length == length),
        "checksum index {index} is missing from the seal or has an invalid length"
    );
    let checksum = open_file(&root.join(index), length)?;
    Ok(Box::new(VerifiedEvents {
        file: open_file(&root.join(name), identity.length)?,
        checksum,
        name,
        root: chunk_root.clone(),
        remaining: identity.length,
        blocks,
        next: 0,
        buffer: Vec::new(),
        consumed: 0,
    }))
}

fn open_file(path: &Path, expected_len: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == expected_len,
        "invalid sealed file {}",
        path.display()
    );
    Ok(file)
}

struct VerifiedEvents {
    file: File,
    checksum: File,
    name: &'static str,
    root: String,
    remaining: u64,
    blocks: u64,
    next: u64,
    buffer: Vec<u8>,
    consumed: usize,
}

impl VerifiedEvents {
    fn load(&mut self) -> io::Result<()> {
        let length = self.remaining.min(CHUNK_BYTES as u64) as usize;
        self.buffer.resize(length, 0);
        self.file
            .read_exact_at(&mut self.buffer, self.next * CHUNK_BYTES as u64)?;
        let mut hash = leaf(&self.buffer);
        let mut width = self.blocks;
        let mut index = self.next;
        let mut previous_nodes = 0;
        while width > 1 {
            let sibling = index ^ 1;
            if sibling < width {
                let mut value = [0; HASH_BYTES];
                self.checksum
                    .read_exact_at(&mut value, (previous_nodes + sibling) * HASH_BYTES as u64)?;
                hash = if index.is_multiple_of(2) {
                    parent(&hash, &value)
                } else {
                    parent(&value, &hash)
                };
            }
            previous_nodes += width;
            width = width.div_ceil(2);
            index /= 2;
        }
        if hex(&hash) != self.root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sealed {} chunk {} has changed", self.name, self.next),
            ));
        }
        self.remaining -= length as u64;
        self.next += 1;
        self.consumed = 0;
        Ok(())
    }
}

impl Read for VerifiedEvents {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.consumed == self.buffer.len() {
            if self.remaining == 0 {
                return Ok(0);
            }
            if let Err(error) = self.load() {
                self.buffer.clear();
                self.consumed = 0;
                return Err(error);
            }
        }
        let length = (&self.buffer[self.consumed..]).read(out)?;
        self.consumed += length;
        Ok(length)
    }
}

fn leaf(bytes: &[u8]) -> Hash {
    let mut hash = leaf_builder();
    hash.update(bytes);
    hash.finalize().into()
}

fn leaf_builder() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update([0]);
    hash
}

fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn hex(bytes: &Hash) -> String {
    format!("{:x}", sha2::digest::Output::<Sha256>::from(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verifies_each_chunk_before_reading_and_detects_late_corruption() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(session::FILE);
        let mut bytes = vec![1; 2 * CHUNK_BYTES];
        bytes.push(3);
        std::fs::write(&path, &bytes)?;
        let mut chunks = Chunks::default();
        for append in bytes.chunks(1201) {
            chunks.observe(append);
        }
        let mut files = vec![LedgerFileIdentity {
            path: session::FILE.into(),
            length: bytes.len() as u64,
            sha256: crate::source::digest(&bytes),
            chunk_root: None,
        }];
        let index = chunks.seal(root.path(), INDEX, &mut files[0]).await?;
        files.push(index);
        let manifest = RecordingManifest {
            schema: SESSION_RECORDING_SCHEMA.into(),
            run_id: "test".into(),
            run_epoch: uuid::Uuid::nil(),
            process_epochs: Vec::new(),
            capture_policy_identity: String::new(),
            source_artifact: traffic_model::recording::SourceArtifactIdentity::Unavailable {
                reason: "fixture".into(),
            },
            sealed: true,
            capture_complete: true,
            coverage: Default::default(),
            records: 0,
            unattributed_records: 0,
            semantic_inventory: Default::default(),
            inputs: Vec::new(),
            files,
        };
        let mut reader = events(root.path(), &manifest)?;
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual)?;
        assert_eq!(actual, bytes);
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .write_all_at(&[9], 2 * CHUNK_BYTES as u64)?;
        let mut reader = events(root.path(), &manifest)?;
        let mut verified = vec![0; 2 * CHUNK_BYTES];
        reader.read_exact(&mut verified)?;
        assert_eq!(verified, bytes[..2 * CHUNK_BYTES]);
        assert_eq!(
            reader.read_exact(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        Ok(())
    }
}
