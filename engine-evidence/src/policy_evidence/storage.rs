//! Bounded traffic chunks in sealed segments. A segment limit rotates storage;
//! it never drops an observation or truncates a value.
use super::v2::{BlobEnvelope, BlobRef};
use super::*;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

pub(super) const CHUNK_BYTES: usize = 1024 * 1024;
const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct Chunk {
    pub artifact: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub plaintext_bytes: usize,
    pub id: String,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct Segment {
    pub artifact: String,
    pub length: u64,
    pub sha256: String,
}
#[derive(Debug)]
pub(super) struct Writer {
    path: PathBuf,
    file: File,
    bytes: u64,
    hash: Sha256,
    sealed: Vec<Segment>,
    limit: u64,
}

fn open(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn file_digest(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 64 * 1024];
    loop {
        let n = input.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}
impl Writer {
    pub(super) fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file,
            bytes: 0,
            hash: Sha256::new(),
            sealed: vec![],
            limit: SEGMENT_BYTES,
        }
    }
    fn name(&self) -> String {
        if self.sealed.is_empty() {
            self.path.file_name().unwrap().to_string_lossy().into()
        } else {
            format!(
                "{}.part-{:04}.jsonl",
                self.path.file_stem().unwrap().to_string_lossy(),
                self.sealed.len()
            )
        }
    }
    fn segment(&self) -> Segment {
        Segment {
            artifact: self.name(),
            length: self.bytes,
            sha256: format!("sha256:{:x}", self.hash.clone().finalize()),
        }
    }
    pub(super) fn segments(&self) -> Vec<Segment> {
        let mut segments = self.sealed.clone();
        segments.push(self.segment());
        segments
    }
    pub(super) fn seal(&mut self) -> Result<()> {
        self.file.sync_all()?;
        for segment in self.segments() {
            let path = self.path.with_file_name(&segment.artifact);
            ensure!(
                file_digest(&path)? == segment.sha256,
                "policy segment changed before sealing"
            );
        }
        Ok(())
    }
    pub(super) fn write(
        &mut self,
        context: &Path,
        payload: &[u8],
        payload_id: &str,
        headers: &[crate::request_headers::evidence::HeaderValueRange],
    ) -> Result<BlobRef> {
        let mut chunks = Vec::new();
        // Empty payloads still have one authenticated physical chunk.
        for (index, chunk) in payload
            .chunks(CHUNK_BYTES)
            .chain(if payload.is_empty() {
                Some(&[][..])
            } else {
                None
            })
            .enumerate()
        {
            let id = if chunk.len() == payload.len() {
                payload_id.to_owned()
            } else {
                digest(chunk)
            };
            let mut bytes = serde_json::to_vec(&BlobEnvelope {
                id: id.clone(),
                payload: StoredPayload::capture(chunk, index * CHUNK_BYTES, headers, context)?,
            })?;
            bytes.push(b'\n');
            if self.bytes + bytes.len() as u64 > self.limit {
                self.file.sync_all()?;
                self.sealed.push(self.segment());
                self.file = open(&self.path.with_file_name(self.name()))?;
                self.bytes = 0;
                self.hash = Sha256::new();
            }
            chunks.push(Chunk {
                artifact: self.name(),
                offset: self.bytes,
                length: bytes.len() as u64,
                sha256: digest(&bytes),
                plaintext_bytes: chunk.len(),
                id,
            });
            self.file.write_all(&bytes)?;
            self.hash.update(&bytes);
            self.bytes += bytes.len() as u64;
        }
        Ok(BlobRef {
            id: payload_id.to_owned(),
            offset: 0,
            length: chunks.iter().map(|c| c.length).sum(),
            sha256: digest(&serde_json::to_vec(&chunks)?),
            plaintext_bytes: payload.len(),
            source: None,
            chunks,
        })
    }
    #[allow(dead_code)]
    #[cfg(test)]
    pub(super) fn fail_writes(&mut self) -> Result<()> {
        self.file = File::open(&self.path)?;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn segment_limit(&mut self, limit: u64) {
        self.limit = limit;
    }
}

pub(super) fn verify(
    report: &Path,
    manifest: &WitnessManifest,
    graph: &ObservationGraph,
) -> Result<()> {
    ensure!(
        !graph.segments.is_empty()
            && graph.segments[0].artifact == manifest.artifact
            && graph.segments[0].sha256 == manifest.sha256,
        "policy segment inventory missing"
    );
    let mut offsets = BTreeMap::new();
    for segment in &graph.segments {
        let path = named_path(report, &segment.artifact)?;
        let meta = std::fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.len() == segment.length
                && meta.len() <= SEGMENT_BYTES
                && offsets.insert(segment.artifact.as_str(), 0u64).is_none(),
            "invalid policy segment"
        );
        ensure!(
            file_digest(&path)? == segment.sha256,
            "policy segment changed after publication"
        );
    }
    let mut ids = std::collections::BTreeSet::new();
    for blob in &graph.blobs {
        ensure!(
            ids.insert((&blob.id, blob.source.is_some())),
            "duplicate policy payload"
        );
        if let Some(source) = &blob.source {
            ensure!(
                blob.chunks.is_empty() && blob.length == 0 && blob.offset == 0,
                "referenced Source evidence changed"
            );
            source.record.validate()?;
            continue;
        }
        ensure!(
            !blob.chunks.is_empty()
                && blob.sha256 == digest(&serde_json::to_vec(&blob.chunks)?)
                && blob.length == blob.chunks.iter().map(|c| c.length).sum::<u64>()
                && blob.plaintext_bytes
                    == blob.chunks.iter().map(|c| c.plaintext_bytes).sum::<usize>(),
            "incomplete policy chunk inventory"
        );
        for chunk in &blob.chunks {
            let offset = offsets
                .get_mut(chunk.artifact.as_str())
                .context("policy chunk segment missing")?;
            ensure!(
                chunk.offset == *offset
                    && chunk.length <= 2 * CHUNK_BYTES as u64
                    && chunk.plaintext_bytes <= CHUNK_BYTES,
                "invalid policy chunk range"
            );
            *offset = offset
                .checked_add(chunk.length)
                .context("policy chunk range overflow")?;
        }
    }
    ensure!(
        graph
            .segments
            .iter()
            .all(|s| offsets[&s.artifact.as_str()] == s.length),
        "policy segment contains unowned data"
    );
    Ok(())
}

pub(super) fn read(path: &Path, session: &str, blob: &BlobRef, context: &Path) -> Result<Vec<u8>> {
    ensure!(
        blob.sha256 == digest(&serde_json::to_vec(&blob.chunks)?),
        "policy chunk inventory changed"
    );
    let mut payload = Vec::new();
    for chunk in &blob.chunks {
        ensure!(
            chunk.length <= 2 * CHUNK_BYTES as u64 && chunk.plaintext_bytes <= CHUNK_BYTES,
            "policy chunk exceeds bound"
        );
        let mut input = File::open(named_path(path, &chunk.artifact)?)?;
        input.seek(SeekFrom::Start(chunk.offset))?;
        let mut bytes = vec![0; usize::try_from(chunk.length)?];
        input.read_exact(&mut bytes)?;
        ensure!(digest(&bytes) == chunk.sha256, "policy chunk changed");
        let envelope: BlobEnvelope = serde_json::from_slice(&bytes)?;
        ensure!(envelope.id == chunk.id, "policy chunk identity changed");
        let bytes = envelope
            .payload
            .read(context, &super::v2::blob_label(session, &chunk.id))?;
        ensure!(
            bytes.len() == chunk.plaintext_bytes && digest(&bytes) == chunk.id,
            "policy chunk plaintext changed"
        );
        payload.extend(bytes);
    }
    ensure!(
        payload.len() == blob.plaintext_bytes && digest(&payload) == blob.id,
        "policy payload coverage changed"
    );
    Ok(payload)
}
pub(super) fn named_path(report: &Path, artifact: &str) -> Result<PathBuf> {
    let manifest = WitnessManifest {
        version: 2,
        artifact: artifact.into(),
        sha256: String::new(),
        observed: 0,
        recorded: 0,
        omitted: 0,
        complete: false,
        sealed: false,
        witnesses: vec![],
        observations: None,
        ..Default::default()
    };
    super::artifact_path(report, &manifest)
}
pub(super) fn stage(source: &Path, destination: &Path, graph: &ObservationGraph) -> Result<()> {
    for segment in &graph.segments {
        let src = named_path(source, &segment.artifact)?;
        let dst = named_path(destination, &segment.artifact)?;
        let metadata = std::fs::symlink_metadata(&src)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == segment.length,
            "policy segment must be a regular file"
        );
        ensure!(
            file_digest(&src)? == segment.sha256,
            "policy segment changed before publication"
        );
        if src != dst {
            if dst.exists() {
                let metadata = std::fs::symlink_metadata(&dst)?;
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "policy destination must be a regular file"
                );
                ensure!(
                    file_digest(&dst)? == segment.sha256,
                    "policy segment publication collision"
                );
            } else {
                std::fs::copy(&src, &dst)?;
            }
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
