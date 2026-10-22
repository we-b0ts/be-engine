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
            crate::policy_evidence::verify_case_clock(witness, &report)?;
            let (source, target) =
                crate::policy_evidence::read(&private, witness, Path::new(directory))?;
            let Some(resource) = &witness.metadata.resource else {
                continue;
            };
            if !source_events.contains_key(directory) {
                let path = Path::new(directory).join("dependencies.jsonl");
                let size = fs::metadata(&path)?.len();
                let events = if size <= 16 * 1024 * 1024
                    && source_bytes.saturating_add(size) <= SOURCE_CACHE_LIMIT
                {
                    source_bytes += size;
                    BufReader::new(fs::File::open(path)?)
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
            let identity_present = if resource.protocol == Protocol::Http {
                witness.metadata.source.exchange_id.is_some()
            } else {
                witness.metadata.source.connection_id.is_some()
                    && witness.metadata.source.sequence.is_some()
            };
            let event = source_events[directory].iter().find(|event| {
                super::super::preflight::dependency::protocol(event) == Some(resource.protocol)
                    && if let Some(id) = &witness.metadata.source.exchange_id {
                        event["id"] == *id
                    } else {
                        event["connection_id"].as_str()
                            == witness.metadata.source.connection_id.as_deref()
                            && (if resource.protocol == Protocol::Mysql {
                                event["query_sequence"].as_u64()
                            } else {
                                event["sequence"].as_u64()
                            }) == witness.metadata.source.sequence
                    }
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
            let independent = identity_present
                && witness.metadata.target_role == TargetRole::IndependentTargetObservation;
            if witness
                .metadata
                .resource
                .as_ref()
                .is_some_and(|r| r.protocol == Protocol::Mysql)
            {
                drafts.sql_entry(
                    event,
                    &source,
                    target.as_deref().filter(|_| independent),
                    witness,
                    state,
                    schemas,
                )?;
                continue;
            }
            let values = super::super::preflight::dependency::values(
                witness.metadata.surface,
                event,
                &source,
            );
            let Ok(values) = values else {
                continue;
            };
            let actual = if independent {
                target.as_ref().and_then(|target| {
                    super::super::preflight::dependency::values(
                        witness.metadata.surface,
                        event,
                        target,
                    )
                    .ok()
                })
            } else {
                None
            };
            for (index, (key, value)) in values.into_iter().enumerate() {
                let Some(key) = std::str::from_utf8(&key).ok() else {
                    continue;
                };
                let mut base = json!({"surface":witness.metadata.surface,"match":{"api":state.api,
                    "resource":witness.metadata.resource,"operation":witness.metadata.operation},"slot":witness.metadata.slot});
                if witness
                    .metadata
                    .resource
                    .as_ref()
                    .is_some_and(|r| r.protocol == Protocol::Http)
                {
                    base["match"]["path"] = json!(
                        event["uri"]
                            .as_str()
                            .and_then(|uri| uri.parse::<hyper::Uri>().ok())
                            .map(|uri| uri.path().to_owned())
                            .unwrap_or_default()
                    );
                } else {
                    base["match"]["key"] = json!({"exact":key});
                }
                drafts.observe(
                    &value,
                    actual
                        .as_ref()
                        .and_then(|a| a.get(index))
                        .map(|(_, v)| v.as_slice()),
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
