//! Canonical ownership identity hashes shared proofs and all finite UUID members.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

#[derive(Serialize)]
struct Snapshot<'a> {
    format: &'static str,
    recording_run_id: &'a str,
    source_revision: Option<&'a str>,
    source_inventory_id: &'a str,
    groups: Vec<&'a DecisionGroup>,
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DecisionSet {
    pub(in crate::rewrite::dependency_review) fn snapshot(
        &self,
        recording_run_id: &str,
        source_revision: Option<&str>,
        source_inventory_id: &str,
        mut eligible: impl FnMut(&DecisionTemplate) -> bool,
    ) -> Result<String> {
        let mut groups = self
            .groups
            .iter()
            .filter(|group| eligible(&group.template))
            .map(Arc::as_ref)
            .collect::<Vec<_>>();
        groups.sort_unstable_by(|left, right| {
            left.template
                .proof_id
                .cmp(&right.template.proof_id)
                .then_with(|| {
                    left.template
                        .proof_revision
                        .cmp(&right.template.proof_revision)
                })
                .then_with(|| left.exchange_ids.cmp(&right.exchange_ids))
        });
        let value = Snapshot {
            format: "dependency-attribution-snapshot/v1",
            recording_run_id,
            source_revision,
            source_inventory_id,
            groups,
        };
        let mut writer = HashWriter(Sha256::new());
        serde_json::to_writer(&mut writer, &value)?;
        Ok(format!("sha256:{:x}", writer.0.finalize()))
    }
}
