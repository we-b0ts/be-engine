//! Complete wire-ordered transactions inherit only source-proven API ownership.
mod scan;
mod tail;
use super::{
    OriginIndex,
    evidence::{EvidenceFile, OriginWitness, case_id, timestamp},
    request,
};
use crate::{
    config::{BackgroundDependencyRuleConfig, MysqlBackgroundSelector},
    dependency_index::RecordReader,
};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

struct Exchange {
    case: String,
    file: usize,
    key: String,
    wire_key: Option<String>,
    sha: String,
    command: String,
    wire_command: String,
    before: Option<u16>,
    after: Option<u16>,
    complete: bool,
    time: Option<chrono::DateTime<chrono::Utc>>,
    origin: Option<OriginWitness>,
    members: BTreeSet<String>,
}

fn member_matches(selector: &MysqlBackgroundSelector, e: &Value) -> bool {
    selector.matches_query(
        e["target_host"].as_str(),
        e["target_port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok()),
        e["database"].as_str(),
        e["username"].as_str(),
        e["command"].as_str().unwrap_or_default(),
        e["sql"].as_str(),
    )
}

pub(super) fn associate(
    files: &[EvidenceFile],
    rules: &[BackgroundDependencyRuleConfig],
    index: &mut OriginIndex,
) -> Result<()> {
    let owners: BTreeMap<_, _> = rules
        .iter()
        .filter_map(|r| match r {
            BackgroundDependencyRuleConfig::Mysql {
                name,
                include_transaction_boundaries: true,
                ..
            } => Some((name.clone(), r)),
            _ => None,
        })
        .collect();
    if owners.is_empty() {
        return Ok(());
    }
    let candidates = scan::candidates(files, index)?;
    let mut fingerprints = BTreeMap::<String, usize>::new();
    let mut reader = RecordReader::new(8 * 1024 * 1024);
    let mut connections = BTreeMap::<String, BTreeMap<u64, Exchange>>::new();
    let mut ambiguous_connections = BTreeSet::new();
    // A fingerprint-only summary is usable only if every duplicate is proven.
    let mut boundaries = BTreeMap::<String, Vec<Option<OriginWitness>>>::new();
    let mut invalid = BTreeSet::new();
    for (file_index, file) in files.iter().enumerate() {
        let case = case_id(&file.path)?;
        for record in file.index.mysql.iter().flatten() {
            if !owners.values().any(|r| matches!(r, BackgroundDependencyRuleConfig::Mysql {selector,..}
                if record.summary["target_host"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(&selector.target_host))
                    && record.summary["target_port"].as_u64()==Some(u64::from(selector.target_port))
                    && record.summary["database"]==selector.database && record.summary["username"]==selector.username)) { continue; }
            if let Some(key) = crate::config::api_trigger::mysql::key(&case, &record.summary) {
                *fingerprints.entry(key).or_default() += 1;
            }
            if !scan::selected(&record.summary, &candidates) {
                continue;
            }
            if record.location.length > 64 * 1024 * 1024 {
                if let Some(key) = crate::config::api_trigger::mysql::key(&case, &record.summary) {
                    invalid.insert(key);
                }
                continue;
            }
            let bytes = reader.read(&file.path, &file.index.stamp, &record.location)?;
            let event: Value = serde_json::from_slice(&bytes)?;
            let Some(key) = crate::config::api_trigger::mysql::key(&case, &event) else {
                continue;
            };
            let sql_text = event["sql"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .trim_end_matches(';')
                .trim();
            let sql = if sql_text.len() <= 32 {
                sql_text.to_ascii_lowercase()
            } else {
                "statement".into()
            };
            let terminal = matches!(sql.as_str(), "commit" | "rollback");
            if terminal {
                boundaries.entry(key.clone()).or_default().push(None);
            }
            let members: BTreeSet<String> = owners
                .iter()
                .filter_map(|(name, rule)| {
                    let BackgroundDependencyRuleConfig::Mysql {
                        transaction_members,
                        ..
                    } = rule
                    else {
                        return None;
                    };
                    transaction_members
                        .iter()
                        .any(|s| member_matches(s, &event))
                        .then_some(name.clone())
                })
                .collect();
            let origin = index.witness(&case, &event).cloned();
            if !members.is_empty() && origin.is_none() {
                boundaries.entry(key.clone()).or_default().push(None);
            }
            let Some(connection) = event["connection_id"].as_str() else {
                continue;
            };
            let Some(sequence) = event["query_sequence"].as_u64() else {
                ambiguous_connections.insert(connection.to_owned());
                continue;
            };

            let complete = if terminal || matches!(sql.as_str(), "begin" | "start transaction") {
                event["command"] == "COM_QUERY"
                    && event["outcome"] == "response"
                    && event["response"]["status"] == "ok"
                    && event["parse_warnings"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
            } else {
                crate::config::api_trigger::mysql::complete(&event)
            };
            let exchange = Exchange {
                case: case.clone(),
                file: file_index,
                wire_key: crate::config::api_trigger::mysql::wire_key(&case, &event),
                key,
                sha: record.location.sha256.clone(),
                command: sql,
                wire_command: event["command"].as_str().unwrap_or_default().into(),
                before: event["server_status_before"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok()),
                after: event["response"]["server_status"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok()),
                complete,
                time: timestamp(&event),
                origin,
                members,
            };
            ensure!(
                connections.len() < 100_000,
                "transaction connection inventory exceeds limit"
            );
            if connections
                .entry(connection.into())
                .or_default()
                .insert(sequence, exchange)
                .is_some()
            {
                ambiguous_connections.insert(connection.into());
            }
        }
    }
    for (connection, events) in &connections {
        if ambiguous_connections.contains(connection) {
            continue;
        }
        let mut group = Vec::new();
        let mut known_start = false;
        let mut previous: Option<(u64, u16)> = None;
        let mut cleanup: Option<OriginWitness> = None;
        for (&seq, event) in events {
            let consecutive = previous.is_some_and(|(p, after)| {
                p.checked_add(1) == Some(seq)
                    && event
                        .before
                        .is_some_and(|before| before & 0x200b == after & 0x200b)
            });
            let terminal = matches!(event.command.as_str(), "commit" | "rollback");
            if !consecutive {
                group.clear();
                known_start = false;
                cleanup = None;
            }
            if event.before.is_some_and(|s| s & 0x2009 == 0)
                && event.after.is_some_and(|s| s & 0x2009 == 1)
            {
                group.clear();
                cleanup = None;
                group.push(event);
                known_start = true;
            } else if !group.is_empty() || event.before.is_some_and(|s| s & 0x2009 == 1) {
                group.push(event);
            }
            if terminal && !group.is_empty() {
                let proof = if known_start {
                    prove(&group, files, &owners)
                } else {
                    tail::prove(&group, files, &owners)
                };
                if let Some(origin) = proof {
                    add_boundary(
                        event,
                        &origin,
                        files,
                        &mut boundaries,
                        &mut index.wire_witnesses,
                    );
                    for member in &group {
                        if member.origin.is_none() && member.members.contains(&origin.rule) {
                            add_boundary(
                                member,
                                &origin,
                                files,
                                &mut boundaries,
                                &mut index.wire_witnesses,
                            );
                        }
                    }
                    cleanup = Some(origin);
                } else {
                    index.ambiguous_transactions += 1;
                    cleanup = None;
                }
                group.clear();
                known_start = false;
            } else if event.command == "rollback"
                && consecutive
                && event.before.is_some_and(|s| s & 0x2009 == 0)
                && event.after.is_some_and(|s| s & 0x2009 == 0)
                && event.complete
            {
                if let Some(origin) = cleanup.take()
                    && independent(event, &origin, files, &owners)
                {
                    add_boundary(
                        event,
                        &origin,
                        files,
                        &mut boundaries,
                        &mut index.wire_witnesses,
                    );
                }
            } else if !terminal {
                cleanup = None;
            }
            previous = event.after.map(|after| (seq, after));
        }
    }
    for (key, proofs) in boundaries {
        if invalid.contains(&key) || proofs.iter().any(Option::is_none) {
            continue;
        }
        let mut proofs = proofs.into_iter().flatten();
        let Some(mut first) = proofs.next() else {
            continue;
        };
        let mut compatible = true;
        for proof in proofs {
            if proof.trigger_case_id != first.trigger_case_id
                || proof.trigger_api != first.trigger_api
            {
                compatible = false;
                break;
            }
            first.exchanges += 1;
        }
        if compatible && fingerprints.get(&key) == Some(&first.exchanges) {
            ensure!(
                index.witnesses.insert(key, first).is_none(),
                "transaction proof overlaps a query rule"
            );
        } else {
            index.ambiguous_transactions += 1;
        }
    }
    index.source_bytes += reader.source_bytes;
    Ok(())
}

fn prove(
    group: &[&Exchange],
    files: &[EvidenceFile],
    owners: &BTreeMap<String, &BackgroundDependencyRuleConfig>,
) -> Option<OriginWitness> {
    let end = group.last()?;
    if !matches!(end.command.as_str(), "commit" | "rollback") || end.after? & 0x2009 != 0 {
        return None;
    }
    let anchors: Vec<_> = group.iter().filter_map(|e| e.origin.as_ref()).collect();
    let owner = anchors.iter().find(|w| owners.contains_key(&w.rule))?;
    if anchors
        .iter()
        .any(|w| w.trigger_case_id != owner.trigger_case_id || w.trigger_api != owner.trigger_api)
    {
        return None;
    }
    if group.iter().any(|e| {
        !e.complete
            || e.before.is_none_or(|f| f & 0x2008 != 0)
            || e.after.is_none_or(|f| f & 0x2008 != 0)
            || !independent(e, owner, files, owners)
            || (e.origin.is_none()
                && !e.members.contains(&owner.rule)
                && !matches!(
                    e.command.as_str(),
                    "begin" | "start transaction" | "commit" | "rollback"
                ))
    }) {
        return None;
    }
    Some((*owner).clone())
}

fn independent(
    event: &Exchange,
    origin: &OriginWitness,
    files: &[EvidenceFile],
    owners: &BTreeMap<String, &BackgroundDependencyRuleConfig>,
) -> bool {
    let Some(rule) = owners.get(&origin.rule) else {
        return false;
    };
    let source = rule.trigger_source().expect("transaction API origin");
    let request = &files[event.file].request;
    let path = request.uri.split('?').next().unwrap_or_default();
    event.case != origin.trigger_case_id
        && path != source.path
        && !path.starts_with(&format!("{}/", source.path))
        && !request::references(request, &origin.captured_identity)
        && event.time.is_some_and(|t| t >= origin.captured_at)
}

fn add_boundary(
    event: &Exchange,
    origin: &OriginWitness,
    files: &[EvidenceFile],
    boundaries: &mut BTreeMap<String, Vec<Option<OriginWitness>>>,
    wire_witnesses: &mut BTreeMap<String, OriginWitness>,
) {
    let mut proof = origin.clone();
    proof.command = event.wire_command.clone();
    proof.dependencies_path = files[event.file].path.clone();
    proof.dependency_sha256 = event.sha.clone();
    proof.exchanges = 1;
    if let Some(key) = &event.wire_key {
        wire_witnesses.insert(key.clone(), proof.clone());
    }
    if let Some(slot) = boundaries
        .get_mut(&event.key)
        .and_then(|v| v.iter_mut().find(|p| p.is_none()))
    {
        *slot = Some(proof);
    }
}
