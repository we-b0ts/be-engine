//! One off-path, cached closure check of mandatory facts and original scope views.
use super::*;
use crate::dependency::{attribution::AttributionDecision, observation::*};
use crate::dependency_index::RecordLocation;

#[cfg(test)]
mod tests;

pub(super) fn effective(
    root: &Path,
    manifest: &RecordingManifest,
    decisions: &[AttributionDecision],
) -> Result<SemanticInventory> {
    let key = crate::policy_evidence::digest(&serde_json::to_vec(&(
        "mandatory-scope-coverage/v2",
        manifest,
        decisions,
    ))?);
    let directory = crate::dependency_index::store::cache_directory(root);
    crate::dependency_index::store::private_directory(&directory)?;
    let cache = directory.join(format!(
        "semantic-inventory-v2-{}.json",
        key.trim_start_matches("sha256:")
    ));
    if let Ok(inventory) = crate::dependency_index::store::read_json::<SemanticInventory>(&cache)
        && inventory.total_mandatory == manifest.semantic_inventory.total_mandatory
        && inventory.by_owner_kind.values().sum::<u64>() == inventory.total_mandatory
    {
        return Ok(inventory);
    }

    let locations = original_locations(root, manifest)?;
    // Closure needs one fact at a time, not a second full-ledger FileIndex
    // alongside the protocol-owned paged Global inventories.
    let mut input = crate::dependency_index::RecordStream::open(&root.join("dependencies.jsonl"))?;
    let owners: BTreeMap<_, _> = decisions
        .iter()
        .map(|decision| (decision.exchange_id, &decision.owner))
        .collect();
    let mut inventory = SemanticInventory::default();
    let mut captured = SemanticInventory::default();
    let mut identities = BTreeSet::new();
    let input_ids: BTreeSet<_> = manifest.inputs.iter().map(|input| input.case_id).collect();
    let mut record_count = 0_u64;
    while let Some((record, bytes)) = input.next()? {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        record_count += 1;
        let value: Value = serde_json::from_slice(bytes)?;
        if !crate::dependency_index::proof::is_evidence(&value) {
            continue;
        }
        let selector = crate::dependency_index::proof::selector(&value);
        let raw = selector
            .get("capture")
            .context("current Source fact lacks capture metadata")?;
        let capture: CaptureMetadata = serde_json::from_value(raw.clone())?;
        ensure!(
            !raw_tcp_has_payload(&selector) || capture.semantic_required,
            "unparsed TCP payload cannot be classified as protocol control"
        );
        if !capture.semantic_required {
            continue;
        }
        ensure!(
            identities.insert((capture.exchange_id, capture.effect_index)),
            "mandatory physical effect occurs more than once"
        );
        ensure!(
            manifest.process_epochs.contains(&capture.process_epoch),
            "Source fact has a foreign process epoch"
        );
        capture.attribution.validate()?;
        if let DependencyOwner::Case { origin_case_id, .. } = capture.attribution {
            ensure!(
                input_ids.contains(&origin_case_id),
                "mandatory Source fact has no declared input owner"
            );
        }
        let (scope, location) = locations
            .get(&record.offset)
            .context("mandatory Source fact is absent from its original ownership view")?;
        ensure!(
            scope_matches(scope, &capture.attribution)
                && location.exchange_id == capture.exchange_id
                && location.effect_index == capture.effect_index
                && same_location(location, &record),
            "Source scope does not identify its original physical effect"
        );
        captured.observe_mandatory(&selector, &capture.attribution);
        let owner = owners
            .get(&capture.exchange_id)
            .copied()
            .unwrap_or(&capture.attribution);
        inventory.observe_mandatory(&selector, owner);
    }
    ensure!(
        record_count == manifest.records,
        "central Source record count differs from its seal"
    );
    ensure!(
        captured.total_mandatory == manifest.semantic_inventory.total_mandatory,
        "effective Source inventory does not cover all original business obligations"
    );
    for kind in ["case", "startup", "process", "unattributed"] {
        ensure!(
            captured.by_owner_kind.get(kind).copied().unwrap_or(0)
                == manifest
                    .semantic_inventory
                    .by_owner_kind
                    .get(kind)
                    .copied()
                    .unwrap_or(0),
            "captured Source owner counts differ from the sealed inventory"
        );
    }
    ensure!(
        captured.unattributed_dependencies == manifest.semantic_inventory.unattributed_dependencies,
        "captured unattributed debt differs from its seal"
    );
    // Older manually authored current-schema fixtures cannot hide newly tracked
    // debt; conversely, an existing explicit unsupported marker cannot disappear.
    for (scope, kinds) in &manifest.semantic_inventory.unsupported_by_scope {
        for (kind, count) in kinds {
            ensure!(
                captured
                    .unsupported_by_scope
                    .get(scope)
                    .and_then(|kinds| kinds.get(kind))
                    .copied()
                    .unwrap_or(0)
                    >= *count,
                "original unsupported Source obligation lost its diagnostic marker"
            );
        }
    }
    crate::dependency_index::store::write_json(&cache, &inventory)?;
    Ok(inventory)
}

fn original_locations(
    root: &Path,
    manifest: &RecordingManifest,
) -> Result<BTreeMap<u64, (ScopeKind, ScopeRecordLocation)>> {
    let mut scopes = manifest
        .inputs
        .iter()
        .map(|input| {
            (
                root.join(&input.path).join(scoped::CASE_SCOPE),
                ScopeKind::Case {
                    case_id: input.case_id,
                },
            )
        })
        .collect::<Vec<_>>();
    scopes.extend(
        [
            ("startup", ScopeKind::Startup),
            ("process", ScopeKind::Process),
            ("unattributed", ScopeKind::Unattributed),
        ]
        .map(|(name, scope)| (root.join(format!("indexes/{name}-scope.json")), scope)),
    );
    let sealed: BTreeSet<_> = manifest
        .files
        .iter()
        .map(|identity| identity.path.as_str())
        .collect();
    let mut locations = BTreeMap::new();
    let canonical_root = std::fs::canonicalize(root)?;
    for (path, expected) in scopes {
        let relative = path.strip_prefix(root)?.to_string_lossy();
        ensure!(
            sealed.contains(relative.as_ref()),
            "original scope is absent from the recording seal"
        );
        let scope: ScopeIndex = serde_json::from_slice(&std::fs::read(&path)?)?;
        ensure!(
            scope.schema == SCOPE_SCHEMA && scope_key(&scope.scope) == scope_key(&expected),
            "Source scope identity disagrees with its manifest"
        );
        ensure!(
            std::fs::canonicalize(
                path.parent()
                    .expect("scope directory")
                    .join(&scope.run_relpath)
            )? == canonical_root,
            "Source scope addresses a foreign central ledger"
        );
        for location in scope.locations {
            ensure!(
                locations
                    .insert(location.offset, (scope.scope.clone(), location))
                    .is_none(),
                "Source physical fact occurs in multiple original scope views"
            );
        }
    }
    Ok(locations)
}

fn same_location(scope: &ScopeRecordLocation, record: &RecordLocation) -> bool {
    scope.line == record.line
        && scope.offset == record.offset
        && scope.length == record.length
        && scope.sha256 == record.sha256
}
fn scope_key(scope: &ScopeKind) -> String {
    match scope {
        ScopeKind::Case { case_id } => case_id.to_string(),
        ScopeKind::Startup => "startup".into(),
        ScopeKind::Process => "process".into(),
        ScopeKind::Unattributed => "unattributed".into(),
    }
}
fn scope_matches(scope: &ScopeKind, owner: &DependencyOwner) -> bool {
    match (scope, owner) {
        (ScopeKind::Case { case_id }, DependencyOwner::Case { origin_case_id, .. }) => {
            case_id == origin_case_id
        }
        (ScopeKind::Startup, DependencyOwner::Startup { .. })
        | (ScopeKind::Process, DependencyOwner::Process { .. })
        | (ScopeKind::Unattributed, DependencyOwner::Unattributed { .. }) => true,
        _ => false,
    }
}
