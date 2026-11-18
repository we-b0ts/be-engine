//! Read-only unused-occurrence metadata, without ownership or discovery graphs.
use super::*;
use crate::replay::report::unused_source::{self, SourceOccurrence};
use serde_json::json;
mod cache;
mod selection;
use selection::Selection;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    pub static ORIGINAL_TRAVERSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub struct Occurrences {
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

pub struct DiagnosticOccurrences {
    pub identity: String,
    pub selected: BTreeSet<String>,
    pub unused: BTreeMap<Uuid, SourceOccurrence>,
    pub case_defaults: BTreeMap<Uuid, crate::dependency::attribution::DependencyOwner>,
}

pub fn for_diagnosis(
    state: &RewriteState,
    api: &str,
    report: &Value,
) -> Result<DiagnosticOccurrences> {
    if unused_source::has_published_occurrences(report)
        && let Some(published) = read_published(state, api, report)?
    {
        return Ok(published);
    }
    let source = for_api(state, api, report)?;
    let selected = source.apis.keys().map(Uuid::to_string).collect();
    let unused = source
        .unused(report, &selected)?
        .into_iter()
        .map(|id| {
            let exchange = &source.exchanges[&id];
            (
                id,
                SourceOccurrence {
                    source_exchange_id: id,
                    captured_owner: exchange.capture.attribution.clone(),
                    capture_complete: exchange.complete,
                },
            )
        })
        .collect();
    Ok(DiagnosticOccurrences {
        identity: source.identity,
        selected,
        unused,
        case_defaults: source.case_defaults,
    })
}

fn read_published(
    state: &RewriteState,
    api: &str,
    report: &Value,
) -> Result<Option<DiagnosticOccurrences>> {
    let (root, bytes, manifest) = sealed_manifest(state)?;
    let manifest_path = root.join(MANIFEST_FILE);
    let ledger = root.join("dependencies.jsonl");
    let manifest_stamp = crate::dependency_index::FileStamp::read_native(&manifest_path)?;
    ensure!(
        fs::read(&manifest_path)? == bytes,
        "Source manifest changed before occurrence lookup"
    );
    let stamp = crate::dependency_index::FileStamp::read_native(&ledger)?;
    crate::dependency_index::recording::authenticate(&root)?;
    let identity = digest(&bytes);
    let files = manifest
        .files
        .iter()
        .map(|file| (root.join(&file.path), file.clone()))
        .collect();
    let (apis, _) = input_routes(&root, &manifest, &files)?;
    let selected = apis
        .iter()
        .filter(|(_, method)| method.as_str() == api)
        .map(|(id, _)| id.to_string())
        .collect();
    let providers = crate::protocols::default_providers();
    let Some(unused) =
        unused_source::published_for_cases(report, &identity, &selected, providers.report_codecs())
    else {
        return Ok(None);
    };
    let case_defaults = load_case_defaults(&root)?;
    ensure!(
        crate::dependency_index::FileStamp::read_native(&manifest_path)? == manifest_stamp
            && crate::dependency_index::FileStamp::read_native(&ledger)? == stamp,
        "Source recording changed during occurrence lookup"
    );
    Ok(Some(DiagnosticOccurrences {
        identity,
        selected,
        unused,
        case_defaults,
    }))
}

fn load_case_defaults(
    root: &Path,
) -> Result<BTreeMap<Uuid, crate::dependency::attribution::DependencyOwner>> {
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    super::super::case_defaults::load(root, target)
}

#[cfg(any(test, feature = "test-support"))]
pub fn load(state: &RewriteState) -> Result<Occurrences> {
    load_selected(state, None)
}

pub fn for_api(state: &RewriteState, api: &str, report: &Value) -> Result<Occurrences> {
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
    result.case_defaults = load_case_defaults(&root)?;
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
    #[cfg(any(test, feature = "test-support"))]
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
