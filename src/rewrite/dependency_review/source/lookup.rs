//! One diagnostic occurrence needs no whole-run ownership or discovery graph.
use super::*;
mod scope;

pub(in crate::rewrite::dependency_review) struct SourceInformation {
    pub identity: String,
    pub exchange: SourceExchange,
    pub case_default: Option<crate::dependency::attribution::DependencyOwner>,
}

pub(in crate::rewrite::dependency_review) fn information(
    state: &RewriteState,
    id: Uuid,
) -> Result<SourceInformation> {
    let (root, bytes, manifest) = sealed_manifest(state)?;
    crate::dependency_index::recording::authenticate(&root)?;
    let central = root.join("dependencies.jsonl");
    let stamp = crate::dependency_index::FileStamp::read_native(&central)?;
    let mut locations = Vec::new();
    let mut count = 0_u64;
    for file in &manifest.files {
        let path = Path::new(&file.path);
        if !path.file_name().is_some_and(|name| {
            name == crate::dependency_index::scoped::CASE_SCOPE
                || name.to_string_lossy().ends_with("-scope.json")
        }) {
            continue;
        }
        let selected = scope::read(&root, file, id, stamp.size)?;
        count += selected.count;
        locations.extend(selected.locations);
    }
    // Older or incomplete recordings can lack a complete locator partition.
    // Their existing full metadata path retains its original validation.
    if count != manifest.records {
        return indexed_information(state, id);
    }
    let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
    let mut exchanges = BTreeMap::new();
    for location in locations {
        let raw = reader.read(&central, &stamp, &location)?;
        let value = crate::json_value::parse_with_limit(
            &raw,
            crate::dependency::http_limits::MAX_RECORD_BYTES,
        )
        .context("Source occurrence must be complete unique-member JSON")?;
        let capture: CaptureMetadata = serde_json::from_value(value["capture"].clone())?;
        ensure!(
            capture.exchange_id == id,
            "Source locator names another physical exchange"
        );
        if crate::dependency_index::proof::is_evidence(&value) {
            let selector = crate::dependency_index::proof::selector(&value);
            observe_exchange(&mut exchanges, capture, &selector, &location)?;
        }
    }
    ensure!(
        crate::dependency_index::FileStamp::read_native(&central)? == stamp,
        "Source central dependency changed during diagnostic lookup"
    );
    finish(&root, &bytes, exchanges, id)
}

fn indexed_information(state: &RewriteState, id: Uuid) -> Result<SourceInformation> {
    let (root, bytes, _, index) = sealed_index(state)?;
    let mut exchanges = BTreeMap::new();
    for record in index
        .proof_records
        .as_ref()
        .context("central Source index has no complete metadata inventory")?
        .iter()
        .filter(|record| {
            record.selector["capture"]["exchange_id"]
                .as_str()
                .and_then(|value| value.parse::<Uuid>().ok())
                == Some(id)
        })
    {
        let capture: CaptureMetadata = serde_json::from_value(record.selector["capture"].clone())?;
        observe_exchange(&mut exchanges, capture, &record.selector, &record.location)?;
    }
    finish(&root, &bytes, exchanges, id)
}

fn finish(
    root: &Path,
    bytes: &[u8],
    mut exchanges: BTreeMap<Uuid, SourceExchange>,
    id: Uuid,
) -> Result<SourceInformation> {
    let exchange = exchanges
        .remove(&id)
        .context("Source exchange is outside this immutable recording")?;
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    let case_default = super::super::case_defaults::load(root, target)?.remove(&id);
    Ok(SourceInformation {
        identity: digest(bytes),
        exchange,
        case_default,
    })
}
