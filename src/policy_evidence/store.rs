//! Bounded session-local observation inventory and encrypted content storage.
use super::v2::{
    BlobEnvelope, BlobRef, CandidateAssociation, SourceObservation, TargetObservation,
};
use super::*;
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

const MAX_OBSERVATIONS: usize = 16_384;
const MAX_ASSOCIATIONS: usize = 262_144;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationRetention {
    Retained,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssociationOutcome {
    Retained,
    SourceRequired,
    Unavailable,
    Incompatible,
}

#[derive(Debug, Clone)]
pub(crate) struct WitnessStore {
    state: Arc<Mutex<State>>,
}
#[derive(Debug)]
struct State {
    file: File,
    path: PathBuf,
    bytes: u64,
    hasher: Sha256,
    observed: usize,
    omitted: usize,
    sealed: bool,
    graph: ObservationGraph,
    key: Vec<u8>,
    sources: BTreeMap<String, usize>,
    source_records: BTreeMap<String, SourceRecord>,
    unavailable_sources: BTreeSet<String>,
    source_tracking_exhausted: bool,
    targets: BTreeMap<String, usize>,
    associations: BTreeMap<(usize, usize), usize>,
    blobs: BTreeMap<String, usize>,
    sealed_manifest: Option<WitnessManifest>,
    compact: bool,
    segmented: Option<super::storage::Writer>,
}

impl WitnessStore {
    pub(crate) fn register_source_record(
        &self,
        identity: &SourceIdentity,
        protocol: crate::policy::Protocol,
        record: SourceRecord,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        ensure!(
            !state.sealed,
            "policy witness store has already been sealed"
        );
        let key = super::source::identity(identity, protocol)?;
        if let Some(previous) = state.source_records.get(&key) {
            ensure!(
                previous == &record,
                "one immutable Source identity has conflicting record locations"
            );
        } else if state.source_records.len() < MAX_OBSERVATIONS {
            state.source_records.insert(key, record);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn new(artifact_dir: &Path) -> Result<Self> {
        Self::create(artifact_dir)
    }

    pub(crate) fn new_bound(
        artifact_dir: &Path,
        session_id: &str,
        policy_fingerprint: &str,
    ) -> Result<Self> {
        ensure!(
            !session_id.is_empty() && !policy_fingerprint.is_empty(),
            "policy observations require Replay session and policy identities"
        );
        let store = Self::create(artifact_dir)?;
        store.state.lock().expect("new observation store").compact = true;
        {
            let mut state = store.state.lock().expect("new observation store");
            state.segmented = Some(super::storage::Writer::new(
                state.path.clone(),
                state.file.try_clone()?,
            ));
        }
        store
            .state
            .lock()
            .expect("new observation store")
            .graph
            .replay = Some(v2::ReplayBinding {
            session_id: session_id.into(),
            policy_fingerprint: policy_fingerprint.into(),
        });
        Ok(store)
    }

    fn create(artifact_dir: &Path) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::create_dir_all(artifact_dir)?;
        let path = artifact_dir.join(format!("policy-witnesses-{}.jsonl", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let mut key = vec![0; 32];
        getrandom::fill(&mut key).map_err(|error| {
            anyhow::anyhow!("observation session key generation failed: {error}")
        })?;
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                file,
                path,
                bytes: 0,
                hasher: Sha256::new(),
                observed: 0,
                omitted: 0,
                sealed: false,
                graph: ObservationGraph {
                    session_id: uuid::Uuid::new_v4().to_string(),
                    ..Default::default()
                },
                key,
                sources: Default::default(),
                source_records: Default::default(),
                unavailable_sources: Default::default(),
                source_tracking_exhausted: false,
                targets: Default::default(),
                associations: Default::default(),
                blobs: Default::default(),
                sealed_manifest: None,
                compact: false,
                segmented: None,
            })),
        })
    }

    /// A standalone call denotes a new physical Target observation. Matchers
    /// explicitly register a request UUID once and associate candidates separately.
    pub(crate) fn record(
        &self,
        metadata: WitnessMetadata,
        key_context: &Path,
        source: &[u8],
        target: Option<&[u8]>,
    ) -> Result<Option<WitnessRef>> {
        self.record_observation(
            metadata,
            key_context,
            source,
            target,
            target.map(|_| uuid::Uuid::new_v4().to_string()).as_deref(),
        )
    }

    pub(crate) fn record_observation(
        &self,
        metadata: WitnessMetadata,
        key_context: &Path,
        source: &[u8],
        target: Option<&[u8]>,
        target_id: Option<&str>,
    ) -> Result<Option<WitnessRef>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        ensure!(
            !state.sealed,
            "policy witness store has already been sealed"
        );
        let mut source_unavailable = false;
        let result = (|| -> Result<Option<WitnessRef>> {
            metadata.validate_roles(target.is_some())?;
            let Some(source_index) = state.source(&metadata, key_context, source)? else {
                source_unavailable = true;
                return Ok(None);
            };
            if let Some(target) = target {
                let target_id =
                    target_id.context("Target observation requires an explicit identity")?;
                let Some(target_index) = state.target(
                    target_id,
                    TargetMetadata::from_pair(&metadata),
                    key_context,
                    target,
                )?
                else {
                    return Ok(None);
                };
                let Some(index) = state.associate(source_index, target_index)? else {
                    return Ok(None);
                };
                if state.compact {
                    state
                        .graph
                        .pair_group(source_index, &state.graph.groups[index])
                        .map(Some)
                } else {
                    state
                        .graph
                        .pair(source_index, Some(&state.graph.associations[index]))
                        .map(Some)
                }
            } else {
                state.graph.pair(source_index, None).map(Some)
            }
        })();
        if result.is_err() || !source_unavailable && matches!(&result, Ok(None)) {
            state.omitted += 1;
        }
        result.context("failed to retain complete protected policy observations")
    }

    /// Retain the genuine request before scanning Source candidates, including
    /// requests for which no recorded candidate will ever be selected.
    pub(crate) fn record_target(
        &self,
        id: &str,
        metadata: TargetMetadata,
        key_context: &Path,
        payload: &[u8],
    ) -> Result<ObservationRetention> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        ensure!(
            !state.sealed,
            "policy witness store has already been sealed"
        );
        let result = state.target(id, metadata, key_context, payload);
        if !matches!(&result, Ok(Some(_))) {
            state.omitted += 1;
        }
        Ok(if result?.is_some() {
            ObservationRetention::Retained
        } else {
            ObservationRetention::Unavailable
        })
    }

    /// Fast path references immutable Source inventory and an independently
    /// registered Target. A cache miss requests the original Source bytes only.
    pub(crate) fn associate(
        &self,
        metadata: &WitnessMetadata,
        target_id: &str,
        key_context: &Path,
        source: Option<&[u8]>,
    ) -> Result<AssociationOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        ensure!(
            !state.sealed,
            "policy witness store has already been sealed"
        );
        let mut source_unavailable = false;
        let result = (|| -> Result<AssociationOutcome> {
            metadata.validate_roles(true)?;
            let key = target_key(target_id, metadata.surface, metadata.target_role);
            let target_index = *state
                .targets
                .get(&key)
                .context("independent Target observation is missing")?;
            if !v2::compatible(metadata, &state.graph.targets[target_index].metadata) {
                return Ok(AssociationOutcome::Incompatible);
            }
            let source_key = v2::source_key(metadata)?;
            let source_index = source_key
                .as_ref()
                .and_then(|key| state.sources.get(key).copied());
            if source_index.is_none()
                && (state.source_tracking_exhausted
                    || source_key
                        .as_ref()
                        .is_some_and(|key| state.unavailable_sources.contains(key)))
            {
                source_unavailable = true;
                return Ok(AssociationOutcome::Unavailable);
            }
            let source_index = match (source_index, source) {
                (Some(index), None) => index,
                (_, Some(source)) => match state.source(metadata, key_context, source)? {
                    Some(index) => index,
                    None => {
                        source_unavailable = true;
                        return Ok(AssociationOutcome::Unavailable);
                    }
                },
                (None, None) => return Ok(AssociationOutcome::SourceRequired),
            };
            Ok(if state.associate(source_index, target_index)?.is_some() {
                AssociationOutcome::Retained
            } else {
                AssociationOutcome::Unavailable
            })
        })();
        // An ordinary Source lookup miss is not omitted evidence: the caller
        // immediately supplies immutable bytes. All actual persistence errors are.
        if result.is_err()
            || !source_unavailable && matches!(&result, Ok(AssociationOutcome::Unavailable))
        {
            state.omitted += 1;
        }
        result
    }

    pub(crate) fn manifest(&self) -> Result<WitnessManifest> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        Ok(state
            .sealed_manifest
            .clone()
            .unwrap_or_else(|| snapshot(&state)))
    }
    pub(crate) fn sealed_manifest(&self) -> Result<WitnessManifest> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("policy witness lock poisoned"))?;
        if let Some(manifest) = &state.sealed_manifest {
            return Ok(manifest.clone());
        }
        if let Some(writer) = &mut state.segmented {
            writer.seal()?;
        } else {
            state.file.sync_all()?;
            ensure!(
                digest(&std::fs::read(&state.path)?)
                    == format!("sha256:{:x}", state.hasher.clone().finalize()),
                "policy observation artifact changed before sealing"
            );
        }
        for index in 0..state.graph.groups.len() {
            let group = &state.graph.groups[index];
            let signature = v2::sign(
                &state.key,
                "candidate-group",
                &(
                    &state.graph.session_id,
                    &state.graph.targets[group.target].id,
                    state.graph.group_sources(group)?,
                ),
            )?;
            state.graph.groups[index].authentication = signature;
        }
        let mut manifest = snapshot(&state);
        manifest.sealed = true;
        if state.compact {
            manifest.externalize(&state.path, &state.key)?;
        } else if !state.graph.key_envelope.is_empty() {
            manifest.observations.as_mut().unwrap().authentication =
                v2::manifest_signature(&manifest, &state.key)?;
        }
        state.sealed = true;
        state.sealed_manifest = Some(manifest.clone());
        Ok(manifest)
    }
}

impl State {
    fn ensure_key(&mut self, context: &Path) -> Result<()> {
        if self.graph.key_envelope.is_empty() {
            self.graph.key_envelope = crate::request_headers::encrypt_evidence(
                context,
                &v2::key_label(&self.graph.session_id),
                &self.key,
            )?;
        }
        Ok(())
    }
    fn blob(&mut self, context: &Path, payload: &[u8]) -> Result<Option<usize>> {
        if self.segmented.is_some() {
            let id = digest(payload);
            if let Some(index) = self.blobs.get(&id) {
                return Ok(Some(*index));
            }
            self.ensure_key(context)?;
            let blob =
                self.segmented
                    .as_mut()
                    .unwrap()
                    .write(&self.graph.session_id, context, payload)?;
            let index = self.graph.blobs.len();
            self.graph.payload_bytes += payload.len();
            self.graph.blobs.push(blob);
            self.blobs.insert(id, index);
            return Ok(Some(index));
        }
        if payload.len() > MAX_PAYLOAD {
            return Ok(None);
        }
        let id = digest(payload);
        if let Some(index) = self.blobs.get(&id) {
            return Ok(Some(*index));
        }
        self.ensure_key(context)?;
        let encrypted = crate::request_headers::encrypt_evidence(
            context,
            &v2::blob_label(&self.graph.session_id, &id),
            payload,
        )?;
        let mut bytes = serde_json::to_vec(&BlobEnvelope {
            id: id.clone(),
            encrypted,
        })?;
        bytes.push(b'\n');
        let length = u64::try_from(bytes.len())?;
        if self
            .bytes
            .checked_add(length)
            .is_none_or(|bytes| bytes > MAX_BYTES)
        {
            return Ok(None);
        }
        let index = self.graph.blobs.len();
        let reference = BlobRef {
            id: id.clone(),
            offset: self.bytes,
            length,
            sha256: digest(&bytes),
            plaintext_bytes: payload.len(),
            source: None,
            chunks: vec![],
        };
        self.file.write_all(&bytes)?;
        self.hasher.update(&bytes);
        self.bytes += length;
        self.graph.payload_bytes += payload.len();
        self.graph.blobs.push(reference);
        self.blobs.insert(id, index);
        Ok(Some(index))
    }
    fn source(
        &mut self,
        metadata: &WitnessMetadata,
        context: &Path,
        payload: &[u8],
    ) -> Result<Option<usize>> {
        let metadata = v2::source_metadata(metadata);
        let key = v2::source_key(&metadata)?;
        if let Some(index) = key.as_ref().and_then(|key| self.sources.get(key)).copied() {
            ensure!(
                self.graph.blobs[self.graph.sources[index].blob].id == digest(payload),
                "one immutable Source identity has conflicting payloads"
            );
            return Ok(Some(index));
        }
        if self.source_tracking_exhausted
            || key
                .as_ref()
                .is_some_and(|key| self.unavailable_sources.contains(key))
        {
            return Ok(None);
        }
        if self.sources.len() + self.unavailable_sources.len() >= MAX_OBSERVATIONS {
            self.observed += 1;
            self.source_tracking_exhausted = true;
            self.mark_source_unavailable(None);
            return Ok(None);
        }
        self.observed += 1;
        if self.graph.sources.len() + self.graph.targets.len() >= MAX_OBSERVATIONS {
            self.mark_source_unavailable(key);
            return Ok(None);
        }
        let external = metadata
            .resource
            .as_ref()
            .map(|r| -> Result<_> {
                Ok(self
                    .source_records
                    .get(&super::source::identity(&metadata.source, r.protocol)?)
                    .cloned()
                    .map(|record| (record, r.protocol)))
            })
            .transpose()?
            .flatten();
        let blob = if let Some((record, protocol)) = external {
            self.ensure_key(context)?;
            let id = digest(payload);
            let key = format!("source:{id}");
            Some(if let Some(index) = self.blobs.get(&key) {
                *index
            } else {
                let index = self.graph.blobs.len();
                self.graph.blobs.push(BlobRef {
                    id,
                    offset: 0,
                    length: 0,
                    sha256: record.location.sha256.clone(),
                    plaintext_bytes: payload.len(),
                    source: Some(super::source::SourcePayload {
                        record,
                        protocol,
                        surface: metadata.surface,
                    }),
                    chunks: vec![],
                });
                self.graph.payload_bytes += payload.len();
                self.blobs.insert(key, index);
                index
            })
        } else {
            self.blob(context, payload)?
        };
        let Some(blob) = blob else {
            self.mark_source_unavailable(key);
            return Ok(None);
        };
        let id = uuid::Uuid::new_v4().to_string();
        let authentication = v2::sign(
            &self.key,
            "source",
            &(
                &self.graph.session_id,
                &id,
                &metadata,
                &self.graph.blobs[blob],
            ),
        )?;
        let index = self.graph.sources.len();
        self.graph.sources.push(SourceObservation {
            id,
            metadata,
            blob,
            authentication,
        });
        if let Some(key) = key {
            self.sources.insert(key, index);
        }
        Ok(Some(index))
    }

    fn mark_source_unavailable(&mut self, key: Option<String>) {
        self.omitted += 1;
        if let Some(key) = key {
            if self.sources.len() + self.unavailable_sources.len() < MAX_OBSERVATIONS {
                self.unavailable_sources.insert(key);
            } else {
                // Tracking itself is bounded. Once full, unseen identities
                // stay unavailable; retained identities still validate bytes.
                self.source_tracking_exhausted = true;
            }
        }
    }
    fn target(
        &mut self,
        id: &str,
        metadata: TargetMetadata,
        context: &Path,
        payload: &[u8],
    ) -> Result<Option<usize>> {
        metadata.validate()?;
        ensure!(
            !id.is_empty(),
            "Target observation requires a request identity"
        );
        let key = target_key(id, metadata.surface, metadata.role);
        if let Some(index) = self.targets.get(&key).copied() {
            let previous = &self.graph.targets[index];
            ensure!(
                previous.metadata == metadata
                    && self.graph.blobs[previous.blob].id == digest(payload),
                "one genuine Target observation has conflicting metadata or payloads"
            );
            return Ok(Some(index));
        }
        self.observed += 1;
        if self.graph.sources.len() + self.graph.targets.len() >= MAX_OBSERVATIONS {
            return Ok(None);
        }
        let Some(blob) = self.blob(context, payload)? else {
            return Ok(None);
        };
        let id = format!("{id}:{:?}:{:?}", metadata.surface, metadata.role);
        let authentication = v2::sign(
            &self.key,
            "target",
            &(
                &self.graph.session_id,
                &id,
                &metadata,
                &self.graph.blobs[blob],
            ),
        )?;
        let index = self.graph.targets.len();
        self.graph.targets.push(TargetObservation {
            id,
            metadata,
            blob,
            authentication,
        });
        self.targets.insert(key, index);
        Ok(Some(index))
    }
    fn associate(&mut self, source: usize, target: usize) -> Result<Option<usize>> {
        self.graph.association_attempts += 1;
        if let Some(index) = self.associations.get(&(source, target)) {
            return Ok(Some(*index));
        }
        if self.associations.len() >= MAX_ASSOCIATIONS {
            return Ok(None);
        }
        let left = &self.graph.sources[source];
        let right = &self.graph.targets[target];
        ensure!(
            v2::compatible(&left.metadata, &right.metadata),
            "candidate association crosses Case, surface, resource or operation"
        );
        if self.compact {
            if self
                .graph
                .groups
                .last()
                .is_none_or(|group| group.target != target)
            {
                self.graph.groups.push(v2::CandidateGroup {
                    target,
                    sources: vec![],
                    authentication: String::new(),
                });
            }
            let index = self.graph.groups.len() - 1;
            self.graph.groups[index].sources.push(source);
            self.associations.insert((source, target), index);
            return Ok(Some(index));
        }
        let authentication = v2::sign(
            &self.key,
            "association",
            &(&self.graph.session_id, &left.id, &right.id),
        )?;
        let index = self.graph.associations.len();
        self.graph.associations.push(CandidateAssociation {
            source,
            target,
            authentication,
        });
        self.associations.insert((source, target), index);
        Ok(Some(index))
    }
}
pub(crate) fn target_key(id: &str, surface: Surface, role: TargetRole) -> String {
    format!("{id}:{surface:?}:{role:?}")
}
fn snapshot(state: &State) -> WitnessManifest {
    let recorded = state.graph.sources.len() + state.graph.targets.len();
    let mut graph = state.graph.clone();
    for index in 0..graph.groups.len() {
        if graph.groups[index].authentication.is_empty() {
            let group = &graph.groups[index];
            graph.groups[index].authentication = v2::sign(
                &state.key,
                "candidate-group",
                &(
                    &graph.session_id,
                    &graph.targets[group.target].id,
                    graph.group_sources(group).expect("valid Source coverage"),
                ),
            )
            .expect("valid coverage signing key");
        }
    }
    if let Some(writer) = &state.segmented {
        graph.segments = writer.segments();
    }
    WitnessManifest {
        version: if state.compact { 3 } else { 2 },
        artifact: state
            .path
            .file_name()
            .expect("witness filename")
            .to_string_lossy()
            .into_owned(),
        sha256: graph.segments.first().map_or_else(
            || format!("sha256:{:x}", state.hasher.clone().finalize()),
            |s| s.sha256.clone(),
        ),
        observed: state.observed,
        recorded,
        omitted: state.omitted,
        complete: state.omitted == 0 && state.observed == recorded,
        sealed: state.sealed,
        witnesses: Vec::new(),
        observations: Some(graph),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
