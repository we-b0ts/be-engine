//! Finite, source-proven Redis reads shared within one completed recording run.
use super::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

fn hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

pub(in crate::replay::redis) fn target_fingerprint(
    target: &TargetKey,
    resp_version: u8,
    database: i64,
    username: Option<&str>,
    command: &str,
    args: &[Vec<u8>],
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"traffic-e2e-redis-cross-case-v1\0");
    hash_field(&mut digest, normalize_host(&target.host).as_bytes());
    digest.update(target.port.to_be_bytes());
    digest.update([resp_version]);
    digest.update(database.to_be_bytes());
    let user = normalize_optional(username).unwrap_or_default();
    hash_field(&mut digest, user.as_bytes());
    hash_field(&mut digest, command.to_ascii_uppercase().as_bytes());
    digest.update((args.len() as u64).to_be_bytes());
    for arg in args {
        hash_field(&mut digest, arg);
    }
    format!("{:x}", digest.finalize())
}

fn recorded_fingerprint(record: &RecordedExchange, args: &[Vec<u8>]) -> String {
    target_fingerprint(
        &TargetKey {
            host: normalize_host(&record.target_host),
            port: record.target_port,
        },
        record.resp_version,
        record.database,
        record.username.as_deref(),
        &record.command,
        args,
    )
}

/// Prove an unmatched target read has exact, safe sibling evidence.
pub(in crate::replay) fn verify_candidate(
    source: &Path,
    report_path: &Path,
    selector: &time_shift::RedisTimeShiftSelector,
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
            (item["target"]["host"]
                .as_str()
                .is_some_and(|host| normalize_host(host) == normalize_host(&selector.host))
                && item["target"]["port"].as_u64() == Some(u64::from(selector.port))
                && item["command"]
                    .as_str()
                    .is_some_and(|command| command.eq_ignore_ascii_case(&selector.read.command)))
            .then_some((case_id, fingerprint))
        })
        .collect::<Vec<_>>();
    ensure!(
        !requests.is_empty(),
        "Redis cross-case requires a current unmatched target read with request identity"
    );
    let (root, files) = super::super::recording_evidence::files(source)?;
    let mut selected = 0usize;
    let mut candidate = None;
    let mut digest = Sha256::new();
    for file in files {
        let origin = super::super::recording_evidence::case_id(&file)?;
        let mut lane_counts = BTreeMap::<Uuid, usize>::new();
        let mut selected_lanes = BTreeMap::<Uuid, usize>::new();
        let mut selected_identities = BTreeSet::new();
        for (line, raw) in BufReader::new(fs::File::open(&file)?).lines().enumerate() {
            let raw = raw?;
            if !raw.contains("redis_exchange") {
                continue;
            }
            let value: Value =
                serde_json::from_str(&raw).context("invalid dependency evidence JSON")?;
            if value["event_type"] != "redis_exchange" {
                continue;
            }
            let record: RecordedExchange =
                serde_json::from_value(value).context("invalid Redis exchange evidence")?;
            *lane_counts.entry(record.connection_id).or_default() += 1;
            let args = record
                .args
                .iter()
                .map(RecordedCapture::decode)
                .collect::<Result<Vec<_>>>()?;
            if !selector.matches(&record, &args) {
                continue;
            }
            shareable(&record, selector)?;
            ensure!(
                selected_identities.insert((record.connection_id, record.sequence)),
                "duplicate Redis cross-case exchange identity"
            );
            selected += 1;
            *selected_lanes.entry(record.connection_id).or_default() += 1;
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

pub(in crate::replay) fn exact_read(selector: &time_shift::RedisTimeShiftSelector) -> Result<()> {
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
    selector: &time_shift::RedisTimeShiftSelector,
) -> Result<()> {
    ensure!(
        record.global_dependency_reason.is_none()
            && record.cache_snapshot_rule.is_none()
            && !record.cache_snapshot_hit,
        "Redis cross-case requires an ordinary case-owned read"
    );
    time_shift::ResponseShift::prepare(record, &[("cross-case".into(), selector.read.clone())])?;
    Ok(())
}

pub(in crate::replay) fn load(
    state: &mut RedisReplayState,
    root: &Path,
    policy_path: Option<&Path>,
    cases: &BTreeMap<String, super::super::ReplayCase>,
    targets: &mut BTreeMap<TargetKey, ReplayTarget>,
    process_owned_dependencies: &[crate::BackgroundDependencyRuleConfig],
) -> Result<()> {
    let Some(path) = policy_path else {
        return Ok(());
    };
    let rules = super::super::policy::redis_cross_case_rules(path)?;
    if rules.is_empty() {
        return Ok(());
    }
    for (_, selector) in &rules {
        exact_read(selector)?;
    }
    let (_, files) = super::super::recording_evidence::files(root)?;
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
                exchange.record.connection_id,
                exchange.record.sequence,
            )),
            "duplicate Redis cross-case exchange identity"
        );
        ensure!(
            state
                .exchanges
                .iter()
                .filter(|other| other.case_id == exchange.case_id
                    && other.record.connection_id == exchange.record.connection_id)
                .all(|other| rules
                    .iter()
                    .any(|(_, selector)| selector.matches(&other.record, &other.args))),
            "Redis cross-case cannot split a recorded connection lane"
        );
        let exchange = &mut state.exchanges[index];
        exchange.source = ReplaySource::Global;
        exchange.shared_rule_id = Some(rule_id.clone());
    }

    for file in files {
        let origin = super::super::recording_evidence::case_id(&file)?;
        if cases.contains_key(&origin) {
            continue;
        }
        let mut lane_counts = BTreeMap::<Uuid, usize>::new();
        let mut selected = Vec::new();
        for raw in BufReader::new(fs::File::open(&file)?).lines() {
            let raw = raw?;
            if !raw.contains("redis_exchange") {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(&raw).context("invalid dependency evidence JSON")?;
            if value["event_type"] != "redis_exchange" {
                continue;
            }
            let record: RecordedExchange =
                serde_json::from_value(value).context("invalid Redis exchange evidence")?;
            *lane_counts.entry(record.connection_id).or_default() += 1;
            let args = record
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
                        record.connection_id,
                        record.sequence,
                    )),
                    "duplicate Redis cross-case exchange identity"
                );
                selected.push((rule_id.clone(), record));
            }
        }
        let mut selected_lanes = BTreeMap::<Uuid, usize>::new();
        for (_, record) in &selected {
            *selected_lanes.entry(record.connection_id).or_default() += 1;
        }
        for (rule_id, record) in selected {
            ensure!(
                lane_counts.get(&record.connection_id) == selected_lanes.get(&record.connection_id),
                "Redis cross-case cannot split a recorded connection lane"
            );
            state.register_exchange(
                record,
                ReplaySource::Global,
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
                .and(exchange.record.timestamp),
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
