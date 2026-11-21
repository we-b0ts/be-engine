use super::{JsonlWriterPool, LedgerFileIdentity, Path, Result, Sha256};
use crate::format::{PayloadRef, SEGMENT_BYTES};
use sha2::Digest;

#[derive(Default)]
pub(super) struct PayloadSegments {
    sealed: Vec<LedgerFileIdentity>,
    length: u64,
    hash: Sha256,
}

impl PayloadSegments {
    pub(super) async fn append(
        &mut self,
        root: &Path,
        files: &mut JsonlWriterPool,
        bytes: &[u8],
    ) -> Result<PayloadRef> {
        if self.length >= SEGMENT_BYTES {
            let identity = self.current_identity();
            files.flush_and_remove(&root.join(&identity.path)).await?;
            self.sealed.push(identity);
            self.length = 0;
            self.hash = Sha256::new();
        }
        let segment = self.sealed.len() as u64;
        let offset = self.length;
        let length = bytes.len() as u64;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("payload segment length overflow"))?;
        files
            .append(&root.join(PayloadRef::path(segment)), bytes)
            .await?;
        self.hash.update(bytes);
        self.length = end;
        Ok(PayloadRef {
            segment,
            offset,
            length,
        })
    }

    pub(super) fn identities(&self) -> Vec<LedgerFileIdentity> {
        let mut identities = self.sealed.clone();
        if self.length != 0 {
            identities.push(self.current_identity());
        }
        identities
    }

    fn current_identity(&self) -> LedgerFileIdentity {
        LedgerFileIdentity {
            path: PayloadRef::path(self.sealed.len() as u64),
            length: self.length,
            sha256: format!("{:x}", self.hash.clone().finalize()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::JsonlBufferSettings;

    #[tokio::test]
    async fn rollover_occurs_after_the_whole_value_crosses_the_target_size() {
        let root = tempfile::tempdir().unwrap();
        let mut files = JsonlWriterPool::new(JsonlBufferSettings {
            capacity: 4096,
            flush_interval: std::time::Duration::from_secs(10),
        });
        let mut segments = PayloadSegments::default();
        const MIB: usize = 1024 * 1024;
        let first = segments
            .append(root.path(), &mut files, &vec![0; 30 * MIB])
            .await
            .unwrap();
        let second = segments
            .append(root.path(), &mut files, &vec![1; 8 * MIB])
            .await
            .unwrap();
        let third = segments
            .append(root.path(), &mut files, b"next")
            .await
            .unwrap();
        files.flush_all().await.unwrap();
        assert_eq!(
            (first.segment, first.offset, first.length),
            (0, 0, 30 * MIB as u64)
        );
        assert_eq!(
            (second.segment, second.offset, second.length),
            (0, 30 * MIB as u64, 8 * MIB as u64)
        );
        assert_eq!((third.segment, third.offset, third.length), (1, 0, 4));
        let sizes: Vec<_> = segments
            .identities()
            .into_iter()
            .map(|entry| entry.length)
            .collect();
        assert_eq!(sizes, vec![38 * MIB as u64, 4]);
    }
}
