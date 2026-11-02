//! One diagnostic occurrence needs no whole-run ownership or discovery graph.
use super::*;

pub(in crate::rewrite::dependency_review) struct SourceInformation {
    pub identity: String,
    pub exchange: SourceExchange,
    pub case_default: Option<crate::dependency::attribution::DependencyOwner>,
}

pub(in crate::rewrite::dependency_review) fn information(
    state: &RewriteState,
    id: Uuid,
) -> Result<SourceInformation> {
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
    let exchange = exchanges
        .remove(&id)
        .context("Source exchange is outside this immutable recording")?;
    let target = root
        .ancestors()
        .find(|path| path.join(".traffic-e2e").is_dir());
    let case_default = super::super::case_defaults::load(&root, target)?.remove(&id);
    Ok(SourceInformation {
        identity: digest(&bytes),
        exchange,
        case_default,
    })
}
