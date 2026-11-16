//! Dependency windows skip borrowed metadata before opening private payloads.
use super::*;

pub(super) fn observe(
    drafts: &mut Drafts,
    replay: &Path,
    report: &Value,
    manifest: Option<&WitnessManifest>,
    state: &RewriteState,
    schemas: Option<&CompiledPolicy>,
    cursor: &mut Cursor,
) -> Result<bool> {
    let mut source_events = BTreeMap::new();
    let mut source_bytes = 0_u64;
    if let Some(manifest) = manifest
        && manifest.complete
        && manifest.sealed
    {
        let private = crate::policy_evidence::verify(replay, manifest)?;
        for (index, entry) in manifest
            .witness_entries()?
            .enumerate()
            .skip(cursor.dependency)
        {
            if drafts.observations >= OBSERVATION_LIMIT {
                drafts.limited = true;
                return Ok(false);
            }
            cursor.dependency = index.checked_add(1).context("discovery cursor overflow")?;
            let witness = entry?.expand()?;
            let witness = witness.as_ref();
            drafts.observations += 1;
            let case = report["cases"].as_array().and_then(|items| {
                items
                    .iter()
                    .find(|c| c["case_id"] == witness.metadata.source.case_id)
            });
            let Some(directory) = case.and_then(|c| c["case_dir"].as_str()) else {
                continue;
            };
            crate::policy_evidence::verify_case_clock(witness, report)?;
            let (source, target) =
                crate::policy_evidence::read(&private, witness, Path::new(directory))?;
            let Some(resource) = &witness.metadata.resource else {
                continue;
            };
            if !source_events.contains_key(directory) {
                let path = case
                    .and_then(|case| case["dependencies_path"].as_str())
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| {
                        crate::dependency_index::scoped::case_path(Path::new(directory))
                    });
                let bytes = crate::dependency_index::scoped::read_bytes(&path)?;
                let size = bytes.len() as u64;
                let events = if size <= 16 * 1024 * 1024
                    && source_bytes.saturating_add(size) <= SOURCE_CACHE_LIMIT
                {
                    source_bytes += size;
                    BufReader::new(bytes.as_slice())
                        .lines()
                        .map(|line| -> Result<Option<Value>> {
                            let line = line?;
                            if line.trim().is_empty() {
                                Ok(None)
                            } else {
                                Ok(Some(serde_json::from_str(&line)?))
                            }
                        })
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .flatten()
                        .collect()
                } else {
                    drafts.limit("source_inventory_cache");
                    Vec::new()
                };
                source_events.insert(directory.to_owned(), events);
            }
            let providers = crate::protocols::default_providers();
            let expected_protocol = serde_json::to_value(resource.protocol)?;
            let event = source_events[directory].iter().find(|event| {
                providers
                    .event_provider(event)
                    .is_some_and(|owner| expected_protocol == owner.kind.as_str())
                    && super::super::preflight::dependency::source_identity(
                        &witness.metadata.source.case_id,
                        event,
                    )
                    .as_ref()
                        == Some(&witness.metadata.source)
                    && super::super::preflight::dependency::source_witness(
                        witness.metadata.surface,
                        event,
                        Path::new(directory),
                    )
                    .is_ok_and(|bytes| {
                        crate::policy_evidence::digest(&bytes) == witness.source_sha256
                    })
            });
            let Some(event) = event else {
                continue;
            };
            super::super::preflight::dependency::validate_metadata(witness, event)?;
            let owner = providers
                .event_provider(event)
                .context("native evidence owner is unavailable")?;
            let Some(native) = owner.provider.native_protocol() else {
                drafts.limit("native_evidence_unavailable");
                continue;
            };
            let side = witness.metadata.surface.dependency_side()?;
            let source = native.decode_evidence(event, &source, side)?;
            let source = projection(source, side)?;
            let independent =
                witness.metadata.target_role == TargetRole::IndependentTargetObservation;
            let target = target.as_deref().filter(|_| independent).and_then(|bytes| {
                native
                    .decode_evidence(event, bytes, side)
                    .and_then(|value| projection(value, side))
                    .ok()
            });
            let base = json!({"surface":witness.metadata.surface,"match":{
                "api":state.api,"resource":witness.metadata.resource,
                "operation":witness.metadata.operation},"slot":witness.metadata.slot});
            drafts.native_entry(
                &base,
                &witness.id,
                providers.evidence().discovery_annotations(event, side)?,
            )?;
            for (location, value) in source.values {
                if drafts.observations >= OBSERVATION_LIMIT {
                    drafts.limit("native_values");
                    break;
                }
                drafts.observations += 1;
                let mut base = base.clone();
                base["native_location"] = json!(location);
                drafts.observe(
                    &value.bytes,
                    target
                        .as_ref()
                        .and_then(|target| target.values.get(&location))
                        .map(|value| value.bytes.as_ref()),
                    base,
                    &witness.id,
                    witness.metadata.clocks.comparison(),
                    schemas,
                    None,
                )?;
            }
        }
    }
    Ok(true)
}

fn projection(
    evidence: traffic_protocol::evidence::MessageEvidence,
    side: traffic_protocol::evidence::MessageSide,
) -> Result<traffic_protocol::message::ProjectedMessage> {
    match side {
        traffic_protocol::evidence::MessageSide::Request => evidence.request.project(),
        traffic_protocol::evidence::MessageSide::Response => evidence
            .response
            .context("native response evidence is unavailable")?
            .project(),
    }
}
