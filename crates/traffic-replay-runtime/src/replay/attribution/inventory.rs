//! One off-path, cached closure check of mandatory facts and original scope views.
use super::*;
use crate::dependency::observation::*;
use crate::dependency_index::RecordLocation;
use crate::dependency_index::scoped;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn effective(
    root: &Path,
    manifest: &RecordingManifest,
    decisions: &BTreeMap<Uuid, DependencyOwner>,
) -> Result<SemanticInventory> {
    effective_with_evidence(
        root,
        manifest,
        decisions,
        crate::protocols::default_providers().evidence(),
        true,
    )
}

pub(super) fn effective_with_evidence(
    root: &Path,
    manifest: &RecordingManifest,
    decisions: &BTreeMap<Uuid, DependencyOwner>,
    evidence: &traffic_protocol::evidence::EvidenceRegistry,
    verify: bool,
) -> Result<SemanticInventory> {
    let key = crate::policy_evidence::digest(&serde_json::to_vec(&(
        "mandatory-scope-coverage/v5",
        evidence.revisions(),
        manifest,
        decisions,
    ))?);
    let directory = crate::dependency_index::store::cache_directory(root);
    crate::dependency_index::store::private_directory(&directory)?;
    let key = key.trim_start_matches("sha256:");
    let cache = directory.join(if verify {
        format!("semantic-inventory-v5-{key}.json")
    } else {
        format!("semantic-inventory-replay-v5-{key}.json")
    });
    if let Ok(inventory) = crate::dependency_index::store::read_json::<SemanticInventory>(&cache)
        && inventory.total_mandatory == manifest.semantic_inventory.total_mandatory
        && inventory.by_owner_kind.values().sum::<u64>() == inventory.total_mandatory
    {
        return Ok(inventory);
    }

    let locations = original_locations(root, manifest)?;
    // Closure needs one fact at a time, not a second full-ledger FileIndex
    // alongside the protocol-owned paged Global inventories.
    let path = root.join("dependencies.jsonl");
    let mut input = if verify {
        crate::dependency_index::RecordStream::open(&path)?
    } else {
        crate::dependency_index::RecordStream::open_for_replay(&path)?
    };
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
        let selector = evidence.proof_selector(&value);
        let raw = selector
            .get("capture")
            .context("current Source fact lacks capture metadata")?;
        let capture: CaptureMetadata = serde_json::from_value(raw.clone())?;
        ensure!(
            !raw_tcp_has_payload(&value) || capture.semantic_required,
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
        if let DependencyOwner::Shutdown {
            process_epoch,
            origin_case_id,
        } = capture.attribution
        {
            ensure!(
                process_epoch == capture.process_epoch
                    && capture.phase == CapturePhase::Shutdown
                    && input_ids.contains(&origin_case_id)
                    && capture.admitted_case.is_none(),
                "shutdown fact lacks its original process, shutdown boundary or associated Case"
            );
        }
        let (scope, location) = locations
            .get(&record.offset)
            .context("mandatory Source fact is absent from its original ownership view")?;
        ensure!(
            scope_matches(scope, &capture.attribution)
                && location.exchange_id == capture.exchange_id
                && location.effect_index == capture.effect_index
                && same_location(location, &record, verify),
            "Source scope does not identify its original physical effect"
        );
        captured.observe_mandatory(
            &selector,
            &capture.attribution,
            crate::protocols::evidence::supports(&value, &capture.attribution, evidence),
        );
        let owner = decisions
            .get(&capture.exchange_id)
            .unwrap_or(&capture.attribution);
        inventory.observe_mandatory(
            &selector,
            owner,
            crate::protocols::evidence::supports(&value, owner, evidence),
        );
    }
    ensure!(
        record_count == manifest.records,
        "central Source record count differs from its seal"
    );
    ensure!(
        captured.total_mandatory == manifest.semantic_inventory.total_mandatory,
        "effective Source inventory does not cover all original business obligations"
    );
    for kind in ["case", "startup", "process", "shutdown", "unattributed"] {
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
    let shutdown = root.join("indexes/shutdown-scope.json");
    let shutdown_physical = scoped::view_path(&shutdown).unwrap_or_else(|| shutdown.clone());
    if sealed.contains(
        shutdown_physical
            .strip_prefix(root)?
            .to_string_lossy()
            .as_ref(),
    ) || manifest
        .semantic_inventory
        .by_owner_kind
        .get("shutdown")
        .copied()
        .unwrap_or(0)
        > 0
    {
        scopes.push((shutdown, ScopeKind::Shutdown));
    }
    let mut locations = BTreeMap::new();
    let canonical_root = std::fs::canonicalize(root)?;
    for (path, expected) in scopes {
        let physical = scoped::view_path(&path).context("missing original dependency scope")?;
        let relative = physical.strip_prefix(root)?.to_string_lossy();
        ensure!(
            sealed.contains(relative.as_ref()),
            "original scope is absent from the recording seal"
        );
        let scope = scoped::read_index_with_epoch(&path, manifest.run_epoch)?;
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

fn same_location(scope: &ScopeRecordLocation, record: &RecordLocation, verify: bool) -> bool {
    scope.line == record.line
        && scope.offset == record.offset
        && scope.length == record.length
        && (!verify || scope.sha256 == record.sha256)
}
fn scope_key(scope: &ScopeKind) -> String {
    match scope {
        ScopeKind::Case { case_id } => case_id.to_string(),
        ScopeKind::Startup => "startup".into(),
        ScopeKind::Process => "process".into(),
        ScopeKind::Shutdown => "shutdown".into(),
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
        | (ScopeKind::Shutdown, DependencyOwner::Shutdown { .. })
        | (ScopeKind::Unattributed, DependencyOwner::Unattributed { .. }) => true,
        _ => false,
    }
}
