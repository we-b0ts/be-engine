//! Finite, source-proven Redis reads shared within one completed recording run.
use super::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
#[cfg(test)]
mod tests;

pub(super) use super::request_identity::target_fingerprint;

fn recorded_fingerprint(record: &RecordedExchange, args: &[Vec<u8>]) -> String {
    target_fingerprint(
        &TargetKey {
            host: normalize_host(&record.native.target_host),
            port: record.native.target_port,
        },
        record.native.resp_version,
        record.native.database,
        record.native.username.as_deref(),
        &record.native.command,
        args,
    )
}

/// Prove an unmatched target read has exact, safe sibling evidence.
pub(crate) fn verify_candidate(
    source: &Path,
    report_path: &Path,
    selector: &shared_read::RedisSharedReadSelector,
) -> Result<Value> {
    selector.validate()?;
    exact_read(selector)?;
    let report_bytes = fs::read(report_path)?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    ensure!(
        report["finalized"] == true,
        "Redis cross-case requires finalized Replay evidence"
    );
    let unmatched = report["redis"]["unmatched"]
        .as_array()
        .context("Redis cross-case requires unmatched Redis report evidence")?;
    let requests = unmatched
        .iter()
        .filter_map(|item| {
            let case_id = item["case_id"].as_str()?;
            let fingerprint = item["request_fingerprint"].as_str()?;
            (item["target"]["host"].as_str().is_some_and(|host| {
                selector
                    .host
                    .as_ref()
                    .is_none_or(|selected| normalize_host(host) == normalize_host(selected))
            }) && item["target"]["port"].as_u64().is_some_and(|port| {
                selector
                    .port
                    .is_none_or(|selected| port == u64::from(selected))
            }) && item["command"]
                .as_str()
                .is_some_and(|command| command.eq_ignore_ascii_case(&selector.read.command)))
            .then_some((case_id, fingerprint))
        })
        .collect::<Vec<_>>();
    ensure!(
        !requests.is_empty(),
        "Redis cross-case requires a current unmatched target read with request identity"
    );
    let (root, files) = crate::replay::recording_evidence::files(source)?;
    let mut selected = 0usize;
    let mut candidate = None;
    let mut digest = Sha256::new();
    for file in files {
        let origin = crate::replay::recording_evidence::case_id(&file)?;
        let index = crate::dependency_index::load_file(&file)?;
        let lane_counts = lane_counts(&index)?;
        let key = selector_key(selector)?;
        let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
        let mut selected_lanes = BTreeMap::<Uuid, usize>::new();
        let mut selected_identities = BTreeSet::new();
        for entry in index
            .redis
            .iter()
            .filter(|entry| key.as_ref().is_none_or(|key| entry.key == *key))
        {
            let bytes = reader.read(&file, &index.stamp, &entry.location)?;
            let raw = std::str::from_utf8(&bytes)?.trim_end_matches(['\r', '\n']);
            let line = entry.location.line - 1;
            let Some(record) = decode_exchange(raw.as_bytes())? else {
                continue;
            };
            let args = record
                .native
                .args
                .iter()
                .map(RecordedCapture::decode)
                .collect::<Result<Vec<_>>>()?;
            if !selector.matches(&record, &args) {
                continue;
            }
            shareable(&record, selector)?;
            ensure!(
                selected_identities.insert((record.native.connection_id, record.native.sequence)),
                "duplicate Redis cross-case exchange identity"
            );
            selected += 1;
            *selected_lanes
                .entry(record.native.connection_id)
                .or_default() += 1;
            digest.update(file.strip_prefix(&root)?.as_os_str().as_encoded_bytes());
            digest.update((line as u64).to_be_bytes());
            digest.update(Sha256::digest(raw.as_bytes()));
            if requests.iter().any(|(consumer, fingerprint)| {
                *consumer != origin && *fingerprint == recorded_fingerprint(&record, &args)
            }) {
                candidate = Some(
                    json!({"origin_case_id":origin,"source_file":file.strip_prefix(&root)?.to_string_lossy(),"source_line":line+1}),
                );
            }
        }
        for (lane, selected_count) in selected_lanes {
            ensure!(
                lane_counts.get(&lane) == Some(&selected_count),
                "Redis cross-case cannot split a recorded connection lane"
            );
        }
    }
    ensure!(
        selected > 0,
        "Redis cross-case requires selected read evidence in the completed recording run"
    );
    let candidate = candidate
        .context("no exact Redis cross-case candidate for the current unmatched target read")?;
    Ok(json!({
        "candidate": candidate,
        "recording_revision": format!("{:x}", digest.finalize()),
        "replay_revision": format!("{:x}", Sha256::digest(report_bytes)),
        "matching_exchanges": selected,
        "does_not_prove": "Source cache ownership and expiry semantics require source evidence; fresh Replay must confirm the target call and finite consumption."
    }))
}

pub(crate) fn exact_read(selector: &shared_read::RedisSharedReadSelector) -> Result<()> {
    use super::key_selector::RedisValueKeySelector;
    ensure!(
        matches!(selector.read.key, RedisValueKeySelector::Exact { .. })
            && selector
                .read
                .hash_field
                .as_ref()
                .is_none_or(|field| matches!(field, RedisValueKeySelector::Exact { .. })),
        "Redis cross-case scope requires exact key and hash field"
    );
    Ok(())
}

fn shareable(
    record: &RecordedExchange,
    _selector: &shared_read::RedisSharedReadSelector,
) -> Result<()> {
    ensure!(
        record.run_owner_kind().is_none()
            && record.native.cache_snapshot_rule.is_none()
            && !record.native.cache_snapshot_hit,
        "Redis cross-case requires an ordinary case-owned read"
    );
    ensure!(
        record.native.replay_safe
            && !record.native.session_setup
            && record.native.outcome == DependencyExchangeOutcome::Response
            && record.native.response_kind == "bulk_string"
            && !record.native.response.truncated
            && record.native.args.iter().all(|arg| !arg.truncated),
        "Redis sharing requires a complete successful ordinary bulk read"
    );
    ensure!(
        crate::policy::runtime::redis_bulk_payload(&record.native.response.decode()?)?.is_some(),
        "Redis sharing requires one complete bulk response"
    );
    Ok(())
}

pub(crate) fn load(
    state: &mut RedisReplayState,
    root: &Path,
    policy_path: Option<&Path>,
    cases: &BTreeMap<String, crate::replay::ReplayCase>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
) -> Result<()> {
    let Some(path) = policy_path else {
        return Ok(());
    };
    let rules = crate::policy::runtime::redis_cross_case_rules(path)?;
    if rules.is_empty() {
        return Ok(());
    }
    for (_, selector) in &rules {
        exact_read(selector)?;
    }
    let (_, files) = crate::replay::recording_evidence::files(root)?;
    let mut selected_identities = BTreeSet::new();

    // The selected cases were loaded normally. Reclassify only selected reads,
    // retaining the origin case for reporting and excluding them from its gate.
    for index in 0..state.exchanges.len() {
        let exchange = &state.exchanges[index];
        if exchange.source != ReplaySource::Case {
            continue;
        }
        let Some((rule_id, selector)) = rules
            .iter()
            .find(|(_, selector)| selector.matches(&exchange.record, &exchange.args))
        else {
            continue;
        };
        shareable(&exchange.record, selector)?;
        ensure!(
            selected_identities.insert((
                exchange.case_id.clone(),
                exchange.record.native.connection_id,
                exchange.record.native.sequence,
            )),
            "duplicate Redis cross-case exchange identity"
        );
        ensure!(
            state
                .exchanges
                .iter()
                .filter(|other| other.case_id == exchange.case_id
                    && other.record.native.connection_id == exchange.record.native.connection_id)
                .all(|other| rules
                    .iter()
                    .any(|(_, selector)| selector.matches(&other.record, &other.args))),
            "Redis cross-case cannot split a recorded connection lane"
        );
        let exchange = &mut state.exchanges[index];
        exchange.source = ReplaySource::Startup;
        exchange.shared_rule_id = Some(rule_id.clone());
    }

    for file in files {
        let origin = crate::replay::recording_evidence::case_id(&file)?;
        if cases.contains_key(&origin) {
            continue;
        }
        let index = crate::dependency_index::load_file(&file)?;
        let lane_counts = lane_counts(&index)?;
        let mut keys = rules
            .iter()
            .map(|(_, s)| selector_key(s))
            .collect::<Result<BTreeSet<_>>>()?;
        let any_scope = keys.remove(&None);
        let keys = keys.into_iter().flatten().collect::<BTreeSet<_>>();
        let mut reader = crate::dependency_index::RecordReader::new(16 * 1024 * 1024);
        let mut selected = Vec::new();
        for entry in index
            .redis
            .iter()
            .filter(|entry| any_scope || keys.contains(&entry.key))
        {
            let raw = reader.read(&file, &index.stamp, &entry.location)?;
            let Some(record) = decode_exchange(&raw)? else {
                continue;
            };
            let args = record
                .native
                .args
                .iter()
                .map(RecordedCapture::decode)
                .collect::<Result<Vec<_>>>()?;
            if let Some((rule_id, selector)) = rules
                .iter()
                .find(|(_, selector)| selector.matches(&record, &args))
            {
                shareable(&record, selector)?;
                ensure!(
                    selected_identities.insert((
                        Some(origin.clone()),
                        record.native.connection_id,
                        record.native.sequence,
                    )),
                    "duplicate Redis cross-case exchange identity"
                );
                selected.push((rule_id.clone(), record));
            }
        }
        if !selected.is_empty() {
            state.shared_source_directories.insert(
                origin.clone(),
                file.parent()
                    .context("shared Source directory is absent")?
                    .to_owned(),
            );
        }
        let mut selected_lanes = BTreeMap::<Uuid, usize>::new();
        for (_, record) in &selected {
            *selected_lanes
                .entry(record.native.connection_id)
                .or_default() += 1;
        }
        for (rule_id, record) in selected {
            ensure!(
                lane_counts.get(&record.native.connection_id)
                    == selected_lanes.get(&record.native.connection_id),
                "Redis cross-case cannot split a recorded connection lane"
            );
            state.register_exchange(
                record,
                ReplaySource::Startup,
                Some(&origin),
                targets,
                process_owned_dependencies,
            )?;
            state
                .exchanges
                .last_mut()
                .expect("registered Redis read")
                .shared_rule_id = Some(rule_id);
        }
    }
    // A persistent rule authorizes only the reads present in this run. Missing
    // reads create no inventory; refreshes remain separate, single-use entries.
    // Keep ordinary inventory order and order shared reads by capture time,
    // independent of case UUIDs or which cases were selected for Replay.
    state.exchanges.sort_by_key(|exchange| {
        (
            exchange.shared_rule_id.is_some(),
            exchange
                .shared_rule_id
                .as_ref()
                .and(exchange.record.native.timestamp),
        )
    });
    state.case_exchange_index = CaseExchangeIndex::default();
    for (index, exchange) in state.exchanges.iter().enumerate() {
        state
            .case_exchange_index
            .register(exchange.source, exchange.case_id.as_deref(), index);
    }
    Ok(())
}

fn selector_key(selector: &shared_read::RedisSharedReadSelector) -> Result<Option<String>> {
    use super::key_selector::RedisValueKeySelector;
    let RedisValueKeySelector::Exact { value } = &selector.read.key else {
        anyhow::bail!("cross-case requires exact key");
    };
    let (Some(host), Some(port), Some(database)) =
        (&selector.host, selector.port, selector.read.database)
    else {
        return Ok(None);
    };
    let mut args = vec![value.as_bytes().to_vec()];
    if let Some(RedisValueKeySelector::Exact { value }) = &selector.read.hash_field {
        args.push(value.as_bytes().to_vec());
    }
    Ok(Some(crate::dependency_index::redis_key(
        host,
        port,
        database,
        &selector.read.command,
        &args,
    )))
}

fn lane_counts(index: &crate::dependency_index::FileIndex) -> Result<BTreeMap<Uuid, usize>> {
    index
        .redis_lanes
        .iter()
        .map(|(id, count)| Ok((id.parse()?, *count)))
        .collect()
}

fn decode_exchange(raw: &[u8]) -> Result<Option<RecordedExchange>> {
    #[derive(Deserialize)]
    struct EventTag<'a> {
        #[serde(borrow)]
        event_type: &'a str,
    }
    // The Redis index includes both exchanges and asynchronous inputs. Read
    // only the discriminator; don't allocate a push's captured payload or
    // invent a request sequence for an input owned by the Pub/Sub executor.
    let tag: EventTag<'_> = serde_json::from_slice(raw).context("invalid Redis evidence tag")?;
    match tag.event_type {
        "redis_pub_sub_push" => Ok(None),
        "redis_exchange" => serde_json::from_slice(raw)
            .map(Some)
            .context("invalid Redis exchange evidence"),
        _ => anyhow::bail!("Redis cross-case index contains an unexpected event type"),
    }
}
