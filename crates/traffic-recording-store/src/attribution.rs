//! Canonical identities for frozen, independently proven ownership groups.
use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Snapshot<'a, Group> {
    format: &'static str,
    recording_run_id: &'a str,
    source_revision: Option<&'a str>,
    source_inventory_id: &'a str,
    groups: &'a [Group],
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

/// The decision owner supplies groups in canonical proof/revision/member order.
/// Hashing streams those borrowed groups without expanding proof DTOs per member.
pub fn snapshot_identity<Group: Serialize>(
    recording_run_id: &str,
    source_revision: Option<&str>,
    source_inventory_id: &str,
    groups: &[Group],
) -> Result<String> {
    let snapshot = Snapshot {
        format: "dependency-attribution-snapshot/v1",
        recording_run_id,
        source_revision,
        source_inventory_id,
        groups,
    };
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, &snapshot)?;
    Ok(format!("sha256:{:x}", writer.0.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_preserves_the_existing_serialized_identity() {
        let original = br#"{"format":"dependency-attribution-snapshot/v1","recording_run_id":"run","source_revision":null,"source_inventory_id":"inventory","groups":[]}"#;
        assert_eq!(
            snapshot_identity("run", None, "inventory", &[] as &[()]).unwrap(),
            format!("sha256:{:x}", Sha256::digest(original)),
        );
    }
}
