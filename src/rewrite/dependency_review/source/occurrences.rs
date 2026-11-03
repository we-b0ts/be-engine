//! Read-only unused-occurrence metadata, without ownership or discovery graphs.
use super::*;
use serde_json::json;

pub(in crate::rewrite::dependency_review) struct Occurrences {
    pub identity: String,
    pub exchanges: BTreeMap<Uuid, SourceExchange>,
    pub apis: BTreeMap<Uuid, String>,
    pub case_defaults: BTreeMap<Uuid, crate::dependency::attribution::DependencyOwner>,
    native: NativeReferences,
    http: HttpReferences,
}

impl Occurrences {
    pub fn unused(&self, report: &Value, selected: &BTreeSet<String>) -> Result<BTreeSet<Uuid>> {
        collect_unused(report, selected, |protocol, event| {
            resolve_unused_reference(&self.exchanges, &self.native, &self.http, protocol, event)
        })
    }
}

pub(in crate::rewrite::dependency_review) fn load(state: &RewriteState) -> Result<Occurrences> {
    let (root, bytes, manifest) = sealed_manifest(state)?;
    crate::dependency_index::recording::authenticate(&root)?;
    let files = manifest
        .files
        .iter()
        .map(|file| (root.join(&file.path), file.clone()))
        .collect();
    let (apis, _) = input_routes(&root, &manifest, &files)?;
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    let mut result = Occurrences {
        identity: digest(&bytes),
        exchanges: BTreeMap::new(),
        apis,
        case_defaults: super::super::case_defaults::load(&root, target)?,
        native: BTreeMap::new(),
        http: BTreeMap::new(),
    };
    let mut input = crate::dependency_index::RecordStream::open(&root.join("dependencies.jsonl"))?;
    while let Some((location, raw)) = input.next()? {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value = crate::json_value::parse_with_limit(
            raw,
            crate::dependency::http_limits::MAX_RECORD_BYTES,
        )
        .context("Source occurrence must be complete unique-member JSON within the supported capture bound")?;
        if !crate::dependency_index::proof::is_evidence(&value) {
            continue;
        }
        let capture: CaptureMetadata = serde_json::from_value(
            value
                .get("capture")
                .cloned()
                .context("Source dependency has no request-start capture identity")?,
        )?;
        observe_reference(&mut result.native, &mut result.http, &capture, &value)?;
        let selector = json!({
            "event_type":value["event_type"],
            "_capture_complete":crate::dependency_index::proof::capture_complete(&value)
        });
        observe_exchange(&mut result.exchanges, capture, &selector, &location)?;
    }
    Ok(result)
}
