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
mod lookup;
pub(super) use lookup::information;
pub(super) mod occurrences;

type NativeReferences = BTreeMap<(String, String, u64), BTreeSet<Uuid>>;
type HttpReferences = BTreeMap<String, BTreeSet<Uuid>>;

#[cfg(test)]
mod tests;

pub(super) struct SourceExchange {
    pub capture: CaptureMetadata,
    pub complete: bool,
    pub selector: Value,
    location: crate::dependency_index::RecordLocation,
}

pub(super) struct SourceSnapshot {
    pub identity: String,
    pub exchanges: BTreeMap<Uuid, SourceExchange>,
    pub native: NativeReferences,
    pub http: HttpReferences,
    pub apis: BTreeMap<Uuid, String>,
    pub inputs: BTreeMap<Uuid, PathBuf>,
    pub epochs: BTreeSet<Uuid>,
    pub discovery: crate::dependency_index::reconciliation::Catalog,
    pub case_defaults: BTreeMap<Uuid, crate::dependency::attribution::DependencyOwner>,
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

fn sealed_manifest(state: &RewriteState) -> Result<(PathBuf, Vec<u8>, RecordingManifest)> {
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
    Ok((root, bytes, manifest))
}

fn sealed_index(
    state: &RewriteState,
) -> Result<(
    PathBuf,
    Vec<u8>,
    RecordingManifest,
    crate::dependency_index::FileIndex,
)> {
    let (root, bytes, manifest) = sealed_manifest(state)?;
    let path = root.join("dependencies.jsonl");
    let index = crate::dependency_index::load_file(&path)?;
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
    Ok((root, bytes, manifest, index))
}

pub(super) fn load(state: &RewriteState) -> Result<SourceSnapshot> {
    let (root, bytes, manifest, index) = sealed_index(state)?;
    let path = root.join("dependencies.jsonl");
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    let mut snapshot = SourceSnapshot {
        identity: digest(&bytes),
        exchanges: BTreeMap::new(),
        native: BTreeMap::new(),
        http: BTreeMap::new(),
        apis: BTreeMap::new(),
        inputs: BTreeMap::new(),
        epochs: manifest.process_epochs.iter().copied().collect(),
        discovery: crate::dependency_index::reconciliation::Catalog::from_index(&index)?,
        case_defaults: super::scope_defaults::load(&root, target)?.owners,
        files: manifest
            .files
            .iter()
            .map(|file| (root.join(&file.path), file.clone()))
            .collect(),
        central_path: path.clone(),
        central_stamp: index.stamp.clone(),
    };
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
        observe_reference(&mut snapshot.native, &mut snapshot.http, &capture, event)?;
        observe_exchange(
            &mut snapshot.exchanges,
            capture,
            &record.selector,
            &record.location,
        )?;
    }
    (snapshot.apis, snapshot.inputs) = input_routes(&root, &manifest, &snapshot.files)?;
    Ok(snapshot)
}

fn input_routes(
    root: &Path,
    manifest: &RecordingManifest,
    files: &BTreeMap<PathBuf, LedgerFileIdentity>,
) -> Result<(BTreeMap<Uuid, String>, BTreeMap<Uuid, PathBuf>)> {
    let mut apis = BTreeMap::new();
    let mut inputs = BTreeMap::new();
    for input in &manifest.inputs {
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
            fs::canonicalize(&path)?.starts_with(fs::canonicalize(root)?),
            "Source input escapes recording boundary"
        );
        let request: Value = serde_json::from_slice(&read_input(files, &path)?)?;
        let method = request["method"]
            .as_str()
            .context("Source input method absent")?;
        let uri = request["uri"]
            .as_str()
            .context("Source input URI absent")?
            .parse::<hyper::Uri>()?;
        let route = request["api_pattern"].as_str().unwrap_or(uri.path());
        apis.insert(
            input.case_id,
            format!("{} {route}", method.to_ascii_uppercase()),
        );
        inputs.insert(input.case_id, root.join(&input.path));
    }
    Ok((apis, inputs))
}

fn observe_reference(
    native: &mut NativeReferences,
    http: &mut HttpReferences,
    capture: &CaptureMetadata,
    event: &Value,
) -> Result<()> {
    let reference = serde_json::to_value(&capture.protocol_ref)?;
    if let (Some(protocol), Some(connection), Some(sequence)) = (
        reference["protocol"].as_str(),
        reference["connection_id"].as_str(),
        reference["sequence"].as_u64(),
    ) {
        native
            .entry((protocol.into(), connection.into(), sequence))
            .or_default()
            .insert(capture.exchange_id);
    }
    if let Some(id) = reference["exchange_id"]
        .as_str()
        .or_else(|| event["id"].as_str())
    {
        http.entry(id.into())
            .or_default()
            .insert(capture.exchange_id);
    }
    Ok(())
}

fn observe_exchange(
    exchanges: &mut BTreeMap<Uuid, SourceExchange>,
    capture: CaptureMetadata,
    selector: &Value,
    location: &crate::dependency_index::RecordLocation,
) -> Result<()> {
    let complete = selector["_capture_complete"] == true;
    match exchanges.entry(capture.exchange_id) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(SourceExchange {
                capture,
                complete,
                selector: selector.clone(),
                location: location.clone(),
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
                previous.selector = selector.clone();
                previous.location = location.clone();
            }
        }
    }
    Ok(())
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
        read_input(&self.files, path)
    }
}

fn read_input(files: &BTreeMap<PathBuf, LedgerFileIdentity>, path: &Path) -> Result<Vec<u8>> {
    let identity = files
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

pub(super) fn resolve_unused(
    snapshot: &SourceSnapshot,
    protocol: &str,
    event: &Value,
) -> Result<Uuid> {
    resolve_unused_reference(
        &snapshot.exchanges,
        &snapshot.native,
        &snapshot.http,
        protocol,
        event,
    )
}

fn resolve_unused_reference(
    exchanges: &BTreeMap<Uuid, SourceExchange>,
    native: &NativeReferences,
    http: &HttpReferences,
    protocol: &str,
    event: &Value,
) -> Result<Uuid> {
    if let Some(id) = event["source_exchange_id"]
        .as_str()
        .or_else(|| event["capture"]["exchange_id"].as_str())
    {
        let id = Uuid::parse_str(id)?;
        let original = exchanges
            .get(&id)
            .context("unused occurrence is outside original Source inventory")?;
        ensure!(
            event["command"] != "PUBSUB_PUSH"
                || original.selector["event_type"] == "redis_pub_sub_push",
            "unused Pub/Sub identity does not name an original notification"
        );
        return Ok(id);
    }
    ensure!(
        event["command"] != "PUBSUB_PUSH",
        "unused Pub/Sub notification lacks its own Source exchange identity; run a fresh Replay to publish notification identities"
    );
    let candidates = if protocol == "http" {
        http.get(
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
        native.get(&(protocol.into(), connection.into(), sequence))
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
    collect_unused(report, selected, |protocol, event| {
        resolve_unused(snapshot, protocol, event)
    })
}

fn collect_unused(
    report: &Value,
    selected: &BTreeSet<String>,
    mut resolve: impl FnMut(&str, &Value) -> Result<Uuid>,
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
                ids.insert(resolve(protocol, event)?);
            }
        }
    }
    Ok(ids)
}
