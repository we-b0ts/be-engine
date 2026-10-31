//! Purpose entry retires obsolete snapshots without loading their workflow.
use std::{borrow::Cow, os::unix::fs::OpenOptionsExt};

use serde::Deserialize;

use super::*;

#[derive(Deserialize)]
struct SnapshotIdentity {
    version: u32,
    workflow_id: String,
}

pub(in crate::rewrite) enum PreviousWorkflow {
    Current(Box<RewriteState>),
    Obsolete { workflow_id: String, bytes: Vec<u8> },
}

impl PreviousWorkflow {
    pub(in crate::rewrite) fn current(&self) -> Option<&RewriteState> {
        match self {
            Self::Current(state) => Some(state),
            Self::Obsolete { .. } => None,
        }
    }

    pub(in crate::rewrite) fn workflow_id(&self) -> &str {
        match self {
            Self::Current(state) => &state.workflow_id,
            Self::Obsolete { workflow_id, .. } => workflow_id,
        }
    }

    fn archive_bytes(&self) -> Result<Cow<'_, [u8]>> {
        match self {
            Self::Current(state) => {
                let mut payload = serde_json::to_vec_pretty(state)?;
                payload.push(b'\n');
                Ok(Cow::Owned(payload))
            }
            Self::Obsolete { bytes, .. } => Ok(Cow::Borrowed(bytes)),
        }
    }
}

impl RewriteStore {
    /// Only authorized purpose entry may replace a retired schema with a fresh state.
    pub(in crate::rewrite) fn load_for_replacement(
        &self,
        record_new_traffic: bool,
    ) -> Result<Option<PreviousWorkflow>> {
        let Some(bytes) = self.snapshot_bytes()? else {
            return Ok(None);
        };
        let identity: SnapshotIdentity = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid rewrite state {}", self.state_path.display()))?;
        ensure!(
            !identity.workflow_id.trim().is_empty(),
            "empty workflow identity"
        );
        if identity.version == 1 {
            // This is archival, not compatibility: no old assignments, policies,
            // receipts or recording references enter the new execution state.
            return Ok(Some(PreviousWorkflow::Obsolete {
                workflow_id: identity.workflow_id,
                bytes,
            }));
        }
        ensure!(
            identity.version == STATE_VERSION,
            "unsupported rewrite state version {}",
            identity.version
        );
        let state = if record_new_traffic {
            self.load_snapshot()?
        } else {
            self.load()?
        }
        .context("rewrite state disappeared during purpose confirmation")?;
        Ok(Some(PreviousWorkflow::Current(Box::new(state))))
    }

    pub(in crate::rewrite) fn archive(
        &self,
        previous: &PreviousWorkflow,
        next_id: &str,
    ) -> Result<PathBuf> {
        let payload = previous.archive_bytes()?;
        let directory = self.root.join("history");
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{next_id}.json"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(path)
    }

    pub(in crate::rewrite) fn restore_snapshot(
        &self,
        previous: Option<&PreviousWorkflow>,
        feedback: &File,
    ) -> Result<()> {
        match previous {
            Some(PreviousWorkflow::Current(state)) => self.save_snapshot(state, feedback),
            Some(PreviousWorkflow::Obsolete { bytes, .. }) => self.write_snapshot(bytes, 0),
            None => {
                fs::remove_file(&self.state_path)?;
                File::open(&self.root)?.sync_all()?;
                Ok(())
            }
        }
    }
}
