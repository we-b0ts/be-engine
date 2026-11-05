//! Read-only unused-occurrence metadata, without ownership or discovery graphs.
use super::*;
use serde_json::json;
mod cache;
mod selection;
use selection::Selection;

#[cfg(test)]
thread_local! {
    pub(in crate::rewrite::dependency_review) static ORIGINAL_TRAVERSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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

#[cfg(test)]
pub(in crate::rewrite::dependency_review) fn load(state: &RewriteState) -> Result<Occurrences> {
    load_selected(state, None)
}

pub(in crate::rewrite::dependency_review) fn for_api(
    state: &RewriteState,
    api: &str,
    report: &Value,
) -> Result<Occurrences> {
    load_selected(state, Some((api, report)))
}

fn load_selected(state: &RewriteState, requested: Option<(&str, &Value)>) -> Result<Occurrences> {
    let (root, bytes, manifest) = sealed_manifest(state)?;
    let manifest_stamp =
        crate::dependency_index::FileStamp::read_native(&root.join(MANIFEST_FILE))?;
    ensure!(
        fs::read(root.join(MANIFEST_FILE))? == bytes,
        "Source manifest changed before occurrence lookup"
    );
    crate::dependency_index::recording::authenticate(&root)?;
    let stamp = crate::dependency_index::FileStamp::read_native(&root.join("dependencies.jsonl"))?;
    let identity = digest(&bytes);
    let selected = requested
        .map(|(api, report)| {
            let files = manifest
                .files
                .iter()
                .map(|file| (root.join(&file.path), file.clone()))
                .collect();
            let (apis, _) = input_routes(&root, &manifest, &files)?;
            Selection::new(api, report, apis)
        })
        .transpose()?;
    let scope = selected.as_ref().map(|selected| selected.identity.as_str());
    let mut result = if let Some(cached) = cache::read(&root, &identity, &stamp, scope) {
        cached
    } else {
        let result = collect(&root, &manifest, identity, selected.as_ref())?;
        ensure!(
            crate::dependency_index::FileStamp::read_native(&root.join(MANIFEST_FILE))?
                == manifest_stamp,
            "Source manifest changed during occurrence traversal"
        );
        cache::write(&root, &stamp, scope, &result)?;
        result
    };
    // These defaults depend on current process rules; they must not be frozen
    // into recording-only metadata or reused across policy changes.
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    result.case_defaults = super::super::case_defaults::load(&root, target)?;
    ensure!(
        crate::dependency_index::FileStamp::read_native(&root.join(MANIFEST_FILE))?
            == manifest_stamp
            && crate::dependency_index::FileStamp::read_native(&root.join("dependencies.jsonl"))?
                == stamp,
        "Source recording changed during occurrence lookup"
    );
    Ok(result)
}

fn collect(
    root: &Path,
    manifest: &RecordingManifest,
    identity: String,
    selected: Option<&Selection>,
) -> Result<Occurrences> {
    let apis = if let Some(selected) = selected {
        selected.apis.clone()
    } else {
        let files = manifest
            .files
            .iter()
            .map(|file| (root.join(&file.path), file.clone()))
            .collect();
        input_routes(root, manifest, &files)?.0
    };
    let mut result = Occurrences {
        identity,
        exchanges: BTreeMap::new(),
        apis,
        case_defaults: BTreeMap::new(),
        native: BTreeMap::new(),
        http: BTreeMap::new(),
    };
    if selected.is_some_and(Selection::is_empty) {
        return Ok(result);
    }
    #[cfg(test)]
    ORIGINAL_TRAVERSALS.set(ORIGINAL_TRAVERSALS.get() + 1);
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
        if let Some(selected) = selected
            && !selected.matches(&capture, &value)?
        {
            continue;
        }
        observe_reference(&mut result.native, &mut result.http, &capture, &value)?;
        let selector = json!({
            "event_type":value["event_type"],
            "_capture_complete":crate::dependency_index::proof::capture_complete(&value)
        });
        observe_exchange(&mut result.exchanges, capture, &selector, &location)?;
    }
    Ok(result)
}
