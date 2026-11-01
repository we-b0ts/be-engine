//! Immutable Source membership and exact native-reference resolution.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

use super::super::model::RewriteState;
use crate::dependency::observation::{
    CaptureMetadata, LedgerFileIdentity, MANIFEST_FILE, RECORDING_SCHEMA, RecordingManifest,
};

pub(super) struct SourceExchange {
    pub capture: CaptureMetadata,
    pub complete: bool,
    pub selector: Value,
    location: crate::dependency_index::RecordLocation,
}

pub(super) struct SourceSnapshot {
    pub identity: String,
    pub exchanges: BTreeMap<Uuid, SourceExchange>,
    pub native: BTreeMap<(String, String, u64), BTreeSet<Uuid>>,
    pub http: BTreeMap<String, BTreeSet<Uuid>>,
    pub apis: BTreeMap<Uuid, String>,
    pub inputs: BTreeMap<Uuid, PathBuf>,
    pub epochs: BTreeSet<Uuid>,
    pub discovery: crate::dependency_index::reconciliation::Catalog,
    files: BTreeMap<PathBuf, LedgerFileIdentity>,
    central_path: PathBuf,
    central_stamp: crate::dependency_index::FileStamp,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn recording_root(source: &Path) -> Result<PathBuf> {
    source
        .ancestors()
        .find(|path| path.join(MANIFEST_FILE).is_file())
        .map(Path::to_path_buf)
        .context("dependency attribution requires a new-format recording manifest")
}

pub(super) fn inventory_identity(state: &RewriteState) -> Result<String> {
    Ok(inventory(state)?.0)
}

/// Sealed counts select analysis work without loading business payloads or the
/// complete central index on every coordinator status request.
pub(super) fn inventory(state: &RewriteState) -> Result<(String, u64)> {
    inventory_at(
        state
            .case_source
            .as_deref()
            .context("workflow has no Source recording")?,
        &state.recording_run_id,
    )
}

pub(super) fn inventory_at(path: &Path, run_id: &str) -> Result<(String, u64)> {
    let root = recording_root(path)?;
    let bytes = fs::read(root.join(MANIFEST_FILE))?;
    let manifest: RecordingManifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.schema == RECORDING_SCHEMA && manifest.sealed && manifest.run_id == run_id,
        "Source recording inventory is not the current sealed workflow input"
    );
    Ok((
        digest(&bytes),
        manifest.semantic_inventory.unattributed_dependencies,
    ))
}

pub(super) fn load(state: &RewriteState) -> Result<SourceSnapshot> {
    let root = recording_root(
        state
            .case_source
            .as_deref()
            .context("workflow has no Source recording")?,
    )?;
    let bytes = fs::read(root.join(MANIFEST_FILE))?;
    let manifest: RecordingManifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.schema == RECORDING_SCHEMA && manifest.sealed,
        "attribution requires a sealed current-format Source recording"
    );
    ensure!(
        manifest.run_id == state.recording_run_id,
        "attribution Source recording identity changed"
    );
    let path = root.join("dependencies.jsonl");
    let index = crate::dependency_index::load_file(&path)?;
    let mut snapshot = SourceSnapshot {
        identity: digest(&bytes),
        exchanges: BTreeMap::new(),
        native: BTreeMap::new(),
        http: BTreeMap::new(),
        apis: BTreeMap::new(),
        inputs: BTreeMap::new(),
        epochs: manifest.process_epochs.into_iter().collect(),
        discovery: crate::dependency_index::reconciliation::Catalog::from_index(&index)?,
        files: manifest
            .files
            .iter()
            .map(|file| (root.join(&file.path), file.clone()))
            .collect(),
        central_path: path.clone(),
        central_stamp: index.stamp.clone(),
    };
    let identity = manifest
        .files
        .iter()
        .find(|file| file.path == "dependencies.jsonl")
        .context("Source manifest omits the central dependency file")?;
    ensure!(
        identity.length == index.stamp.size
            && identity.sha256.trim_start_matches("sha256:")
                == index.sha256.trim_start_matches("sha256:"),
        "Source central dependency content differs from sealed manifest"
    );
    for record in index
        .proof_records
        .as_ref()
        .context("central Source index has no complete metadata inventory")?
    {
        let event = &record.selector;
        let capture: CaptureMetadata = serde_json::from_value(
            event
                .get("capture")
                .cloned()
                .context("Source dependency has no request-start capture identity")?,
        )?;
        let id = capture.exchange_id;
        let native = serde_json::to_value(&capture.protocol_ref)?;
        if let (Some(protocol), Some(connection), Some(sequence)) = (
            native["protocol"].as_str(),
            native["connection_id"].as_str(),
            native["sequence"].as_u64(),
        ) {
            snapshot
                .native
                .entry((protocol.into(), connection.into(), sequence))
                .or_default()
                .insert(id);
        }
        if let Some(http_id) = native["exchange_id"]
            .as_str()
            .or_else(|| event["id"].as_str())
        {
            snapshot.http.entry(http_id.into()).or_default().insert(id);
        }
        let complete = event["_capture_complete"] == true;
        match snapshot.exchanges.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(SourceExchange {
                    capture,
                    complete,
                    selector: event.clone(),
                    location: record.location.clone(),
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let previous = entry.get_mut();
                ensure!(
                    previous.capture.process_epoch == capture.process_epoch
                        && previous.capture.protocol_ref == capture.protocol_ref
                        && previous.capture.started_at == capture.started_at
                        && previous.capture.attribution == capture.attribution,
                    "one physical Source exchange has contradictory capture identity or ownership"
                );
                previous.complete &= complete;
                if capture.semantic_required && !previous.capture.semantic_required {
                    previous.capture = capture;
                    previous.selector = event.clone();
                    previous.location = record.location.clone();
                }
            }
        }
    }
    for input in manifest.inputs {
        if !input.complete {
            continue;
        }
        let directory = root.join(&input.path);
        let path = if directory.is_file() {
            directory
        } else {
            directory.join("request.json")
        };
        ensure!(
            fs::canonicalize(&path)?.starts_with(fs::canonicalize(&root)?),
            "Source input escapes recording boundary"
        );
        let request: Value = serde_json::from_slice(&snapshot.read_input(&path)?)?;
        let method = request["method"]
            .as_str()
            .context("Source input method absent")?;
        let uri = request["uri"]
            .as_str()
            .context("Source input URI absent")?
            .parse::<hyper::Uri>()?;
        let route = request["api_pattern"].as_str().unwrap_or(uri.path());
        snapshot.apis.insert(
            input.case_id,
            format!("{} {route}", method.to_ascii_uppercase()),
        );
        snapshot
            .inputs
            .insert(input.case_id, root.join(&input.path));
    }
    Ok(snapshot)
}

impl SourceSnapshot {
    pub(super) fn original_selector(
        &self,
        id: &Uuid,
        reader: &mut crate::dependency_index::RecordReader,
    ) -> Result<Value> {
        let event = self
            .exchanges
            .get(id)
            .context("original Source exchange absent")?;
        let bytes = reader.read(&self.central_path, &self.central_stamp, &event.location)?;
        crate::json_value::parse_with_limit(&bytes,crate::dependency::http_limits::MAX_RECORD_BYTES)
            .context("Source occurrence must be complete unique-member JSON within the supported capture bound")
    }
    pub(super) fn read_input(&self, path: &Path) -> Result<Vec<u8>> {
        let identity = self
            .files
            .get(path)
            .context("original Source input is not sealed in the recording manifest")?;
        let bytes = fs::read(path)?;
        ensure!(
            bytes.len() as u64 == identity.length
                && digest(&bytes).trim_start_matches("sha256:")
                    == identity.sha256.trim_start_matches("sha256:"),
            "original Source input content changed after recording seal"
        );
        Ok(bytes)
    }
}

pub(super) fn resolve_unused(
    snapshot: &SourceSnapshot,
    protocol: &str,
    event: &Value,
) -> Result<Uuid> {
    if let Some(id) = event["source_exchange_id"]
        .as_str()
        .or_else(|| event["capture"]["exchange_id"].as_str())
    {
        let id = Uuid::parse_str(id)?;
        ensure!(
            snapshot.exchanges.contains_key(&id),
            "unused occurrence is outside original Source inventory"
        );
        return Ok(id);
    }
    let candidates = if protocol == "http" {
        snapshot.http.get(
            event["source_http_id"]
                .as_str()
                .context("unused HTTP entry lacks exact Source HTTP identity")?,
        )
    } else {
        let connection = event["connection_id"]
            .as_str()
            .context("unused dependency lacks native connection identity")?;
        let sequence = event["query_sequence"]
            .as_u64()
            .or_else(|| event["sequence"].as_u64())
            .context("unused dependency lacks native sequence")?;
        snapshot
            .native
            .get(&(protocol.into(), connection.into(), sequence))
    }
    .context("unused dependency has no original Source occurrence")?;
    ensure!(
        candidates.len() == 1,
        "native Source dependency reference is ambiguous"
    );
    Ok(*candidates.first().expect("one Source identity"))
}

pub(super) fn unused(
    snapshot: &SourceSnapshot,
    report: &Value,
    selected: &BTreeSet<String>,
) -> Result<BTreeSet<Uuid>> {
    let mut ids = BTreeSet::new();
    for (protocol, section, field) in [
        ("mysql", report, "unused_case_exchanges"),
        ("http", report, "unused_case_http_exchanges"),
        ("redis", &report["redis"], "unused_case"),
        ("memcached", &report["memcached"], "unused_case"),
        ("motan", &report["motan"], "unused_case"),
        ("kafka", &report["kafka"], "unused_case"),
        ("network", &report["connect_failures"], "unused_case"),
    ] {
        if let Some(events) = section[field].as_array() {
            for event in events.iter().filter(|event| {
                event["case_id"]
                    .as_str()
                    .is_some_and(|case| selected.contains(case))
            }) {
                ids.insert(resolve_unused(snapshot, protocol, event)?);
            }
        }
    }
    Ok(ids)
}
