use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};

use super::*;

const MAX_RECORDS: usize = 16_384;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct WitnessStore {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    file: File,
    path: PathBuf,
    observed: usize,
    omitted: usize,
    bytes: u64,
    sealed: bool,
    refs: Vec<WitnessRef>,
    identities: std::collections::BTreeMap<String, WitnessRef>,
}

impl WitnessStore {
    pub(crate) fn new(artifact_dir: &Path) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::create_dir_all(artifact_dir)?;
        let path = artifact_dir.join(format!("policy-witnesses-{}.jsonl", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                file,
                path,
                observed: 0,
                omitted: 0,
                bytes: 0,
                sealed: false,
                refs: Vec::new(),
                identities: Default::default(),
            })),
        })
    }

    /// Record every eligible observation, including the first run without rules.
    /// A bound or persistence failure makes coverage incomplete, never truncated-successful.
    pub(crate) fn record(
        &self,
        metadata: WitnessMetadata,
        key_context: &Path,
        source: &[u8],
        target: Option<&[u8]>,
    ) -> Result<Option<WitnessRef>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        ensure!(
            !state.sealed,
            "policy witness store has already been sealed"
        );
        if let Err(error) = metadata.validate_roles(target.is_some()) {
            state.observed += 1;
            state.omitted += 1;
            return Err(error);
        }
        let identity = digest(&serde_json::to_vec(&(
            &metadata,
            digest(source),
            target.map(digest),
        ))?);
        if let Some(witness) = state.identities.get(&identity) {
            return Ok(Some(witness.clone()));
        }
        state.observed += 1;
        if source.len() > MAX_PAYLOAD
            || target.is_some_and(|b| b.len() > MAX_PAYLOAD)
            || state.refs.len() >= MAX_RECORDS
        {
            state.omitted += 1;
            return Ok(None);
        }
        let result = (|| -> Result<Option<WitnessRef>> {
            let id = uuid::Uuid::new_v4().to_string();
            let payload = serde_json::to_vec(&ProtectedPayload {
                source: STANDARD.encode(source),
                target: target.map(|b| STANDARD.encode(b)),
            })?;
            let encrypted = crate::request_headers::encrypt_evidence(
                key_context,
                &label(&id, &metadata)?,
                &payload,
            )?;
            let mut bytes = serde_json::to_vec(&Envelope {
                id: id.clone(),
                metadata: metadata.clone(),
                encrypted,
            })?;
            bytes.push(b'\n');
            let length = u64::try_from(bytes.len())?;
            if length > 4 * 1024 * 1024
                || state
                    .bytes
                    .checked_add(length)
                    .is_none_or(|n| n > MAX_BYTES)
            {
                return Ok(None);
            }
            let witness = WitnessRef {
                id,
                metadata,
                offset: state.bytes,
                length,
                sha256: digest(&bytes),
                source_sha256: digest(source),
                target_sha256: target.map(digest),
            };
            state.file.write_all(&bytes)?;
            state.file.sync_data()?;
            state.bytes += length;
            state.refs.push(witness.clone());
            state.identities.insert(identity, witness.clone());
            Ok(Some(witness))
        })();
        if !matches!(&result, Ok(Some(_))) {
            state.omitted += 1;
        }
        result.context("failed to retain complete protected policy witness")
    }

    pub(crate) fn manifest(&self) -> Result<WitnessManifest> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        snapshot(&state)
    }

    pub(crate) fn sealed_manifest(&self) -> Result<WitnessManifest> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        state.file.sync_all()?;
        state.sealed = true;
        snapshot(&state)
    }
}

fn snapshot(state: &State) -> Result<WitnessManifest> {
    Ok(WitnessManifest {
        version: 1,
        artifact: state
            .path
            .file_name()
            .context("policy witness filename missing")?
            .to_string_lossy()
            .into_owned(),
        sha256: digest(&std::fs::read(&state.path)?),
        observed: state.observed,
        recorded: state.refs.len(),
        omitted: state.omitted,
        complete: state.omitted == 0 && state.observed == state.refs.len(),
        sealed: state.sealed,
        witnesses: state.refs.clone(),
    })
}
