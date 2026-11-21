//! Durable content-addressed history bodies, published before their state references.
use super::*;
use anyhow::Context;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const SCHEMA: &str = "dependency-decision-history-entry/v1";

#[derive(Serialize)]
pub struct Entry<'a> {
    schema: &'static str,
    workflow_id: &'a str,
    origin: Option<&'a HistoryOrigin>,
    group: &'a DecisionGroup,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredEntry {
    schema: String,
    workflow_id: String,
    origin: Option<HistoryOrigin>,
    group: DecisionGroup,
}

impl DecisionHistory {
    pub fn persist(&mut self, directory: &Path, workflow_id: &str) -> Result<bool> {
        self.validate()?;
        if self.groups.is_empty() {
            return Ok(false);
        }
        ensure!(
            !workflow_id.is_empty(),
            "empty ownership history workflow identity"
        );
        fs::create_dir_all(directory)?;
        // Persist the new directory's link before any state rename can reference
        // its bodies, including a crash before the final state-directory fsync.
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        // Keep the original in-memory history intact until every body is durable.
        let mut refs = self.archives.clone();
        for (index, group) in self.groups.iter().enumerate() {
            let origin = self.origins.get(index).and_then(Option::as_ref);
            let bytes = serde_json::to_vec(&Entry {
                schema: SCHEMA,
                workflow_id,
                origin,
                group,
            })?;
            let sha256 = digest(&bytes);
            publish(directory, &sha256, &bytes)?;
            refs.push(HistoryArchiveRef {
                archived_from_workflow: workflow_id.into(),
                sha256,
                byte_length: bytes.len() as u64,
                occurrences: group.exchange_ids.len() as u64,
                proof_id: group.template.proof_id.clone(),
                proof_revision: group.template.proof_revision,
                template_sha256: template_digest(&group.template)?,
                origin: origin.cloned(),
            });
        }
        let archived = Self {
            archives: refs,
            ..Self::default()
        };
        archived.validate()?;
        *self = archived;
        Ok(true)
    }

    pub fn verify_archives(&self, directory: &Path, workflow_id: &str) -> Result<()> {
        ensure!(
            !workflow_id.is_empty(),
            "empty ownership history workflow identity"
        );
        self.validate()?;
        for reference in &self.archives {
            read(directory, &reference.archived_from_workflow, reference)?;
        }
        Ok(())
    }
}

fn read(directory: &Path, workflow_id: &str, reference: &HistoryArchiveRef) -> Result<StoredEntry> {
    ensure!(
        valid_digest(&reference.sha256),
        "invalid ownership history archive digest"
    );
    let path = directory.join(format!("{}.json", reference.sha256));
    let bytes =
        fs::read(&path).with_context(|| format!("read ownership history {}", path.display()))?;
    ensure!(
        bytes.len() as u64 == reference.byte_length && digest(&bytes) == reference.sha256,
        "ownership history archive content changed: {}",
        path.display()
    );
    let entry: StoredEntry = serde_json::from_slice(&bytes)?;
    ensure!(
        entry.schema == SCHEMA && entry.workflow_id == workflow_id,
        "ownership history archive belongs to another workflow or schema"
    );
    ensure!(
        entry.origin == reference.origin
            && entry.group.exchange_ids.len() as u64 == reference.occurrences
            && entry.group.template.proof_id == reference.proof_id
            && entry.group.template.proof_revision == reference.proof_revision
            && template_digest(&entry.group.template)? == reference.template_sha256,
        "ownership history archive metadata differs from its state reference"
    );
    Ok(entry)
}

fn publish(directory: &Path, sha256: &str, bytes: &[u8]) -> Result<()> {
    let path = directory.join(format!("{sha256}.json"));
    let temporary = directory.join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // A hard link publishes atomically without overwriting an existing body.
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure!(
                    fs::read(&path)? == bytes,
                    "ownership history archive collision or corruption"
                );
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
