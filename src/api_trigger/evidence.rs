//! Verify INSERT origins and direct foreign-case Redis references in immutable evidence.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use super::{redis_args, request};
use crate::mysql::sql::Token;
use crate::{
    config::{ApiTriggerCapture, BackgroundDependencyRuleConfig},
    dependency_index::{FileIndex, RecordReader},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct OriginWitness {
    pub rule: String,
    pub trigger_case_id: String,
    pub trigger_api: String,
    pub binding: String,
    pub dependency_sha256: String,
    pub dependencies_path: PathBuf,
    pub target_host: String,
    pub target_port: u16,
    pub command: String,
    pub exchanges: usize,
    pub captured_at: DateTime<Utc>,
    pub captured_identity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OriginIndex {
    pub witnesses: BTreeMap<String, OriginWitness>,
    pub wire_witnesses: BTreeMap<String, OriginWitness>,
    pub selector_rejections: BTreeMap<String, BTreeMap<String, String>>,
    pub evidence_fingerprint: String,
    pub triggers: usize,
    pub ambiguous_triggers: usize,
    pub ambiguous_references: usize,
    pub ambiguous_transactions: usize,
    #[serde(skip)]
    pub cache_reused: bool,
    #[serde(skip)]
    pub source_bytes: u64,
}

impl OriginIndex {
    pub(crate) fn witness(&self, case_id: &str, event: &Value) -> Option<&OriginWitness> {
        let witness = if let Some(key) = crate::config::api_trigger::mysql::wire_key(case_id, event)
        {
            self.wire_witnesses.get(&key)?
        } else {
            self.witnesses.get(&key(case_id, event)?)?
        };
        if event["status"]
            .as_str()
            .is_some_and(|s| !matches!(s, "resultset" | "ok"))
            && event["sql_summary"].is_object()
        {
            return None;
        }
        let host = event["target_host"]
            .as_str()
            .or_else(|| event["target"]["host"].as_str())?;
        let port = event["target_port"]
            .as_u64()
            .or_else(|| event["target"]["port"].as_u64())?;
        (host.eq_ignore_ascii_case(&witness.target_host)
            && port == u64::from(witness.target_port)
            && event["command"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(&witness.command)))
        .then_some(witness)
    }
}

pub(super) struct EvidenceFile {
    pub path: PathBuf,
    pub request: request::RequestFacts,
    pub index: FileIndex,
}

#[derive(Clone)]
struct Origin {
    identity: String,
    case_id: String,
    captured_at: DateTime<Utc>,
}

pub(super) fn build(
    files: &[EvidenceFile],
    rules: &[BackgroundDependencyRuleConfig],
) -> Result<OriginIndex> {
    let mut index = OriginIndex::default();
    let mut reader = RecordReader::new(8 * 1024 * 1024);
    let mut sources = BTreeMap::<String, BTreeMap<String, Origin>>::new();
    let mut states = Vec::new();
    for rule in rules.iter().filter(|r| r.trigger_source().is_some()) {
        let source = rule.trigger_source().expect("selected origin");
        let source_key = serde_json::to_string(source)?;
        let origins = if let Some(origins) = sources.get(&source_key) {
            origins.clone()
        } else {
            let mut captured = BTreeMap::<String, Vec<Origin>>::new();
            for file in files
                .iter()
                .filter(|f| request::matches(source, &f.request))
            {
                let values = capture_file(&file.path, source.binding().1, &mut index.source_bytes)?;
                if values.len() != 1 {
                    index.ambiguous_triggers += 1;
                    continue;
                }
                let (identity, captured_at) = values.into_iter().next().expect("one capture");
                if file
                    .request
                    .started_at
                    .is_none_or(|start| captured_at < start)
                {
                    index.ambiguous_triggers += 1;
                    continue;
                }
                ensure!(
                    captured.len() < 4096,
                    "API trigger origin inventory exceeds 4096 identities per rule"
                );
                captured.entry(identity.clone()).or_default().push(Origin {
                    identity,
                    case_id: case_id(&file.path)?,
                    captured_at,
                });
            }
            index.ambiguous_triggers += captured.values().filter(|v| v.len() != 1).count();
            let origins: BTreeMap<_, _> = captured
                .into_iter()
                .filter_map(|(id, mut values)| (values.len() == 1).then(|| (id, values.remove(0))))
                .collect();
            sources.insert(source_key, origins.clone());
            origins
        };
        index.triggers += origins.len();
        let identity_hashes = origins
            .keys()
            .map(|s| {
                super::cache::digest(
                    crate::mysql::sql::number(s)
                        .expect("integer identity")
                        .as_bytes(),
                )
            })
            .collect();
        let mysql_template_len = match rule {
            BackgroundDependencyRuleConfig::Mysql { selector, .. } => {
                selector.api_template().map(|t| t.len())
            }
            _ => None,
        };
        states.push(RuleOrigins {
            rule,
            mysql_template_len,
            origins,
            identity_hashes,
            invalid: BTreeSet::new(),
        });
    }
    // Read and decode each candidate once, regardless of how many rules share a source.
    for file in files {
        let victim = case_id(&file.path)?;
        let path = file.request.uri.split('?').next().unwrap_or_default();
        let eligible = |state: &&mut RuleOrigins<'_>| {
            let source = state.rule.trigger_source().expect("API source");
            !state.origins.is_empty()
                && path != source.path
                && !path.starts_with(&format!("{}/", source.path))
        };
        for record in file.index.mysql.iter().flatten() {
            let candidates: Vec<_> = states
                .iter_mut()
                .filter(eligible)
                .filter(|state| mysql_candidate(state, &record.summary))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            if record.location.length > 64 * 1024 * 1024 {
                if let Some(key) = crate::config::api_trigger::mysql::key(&victim, &record.summary)
                {
                    for state in candidates {
                        state.invalid.insert(key.clone());
                    }
                }
                continue;
            }
            let raw = reader.read(&file.path, &file.index.stamp, &record.location)?;
            let event: Value = serde_json::from_slice(&raw)?;
            for state in candidates {
                observe(
                    state.rule,
                    &state.origins,
                    file,
                    &victim,
                    &event,
                    record.location.sha256.clone(),
                    &mut index,
                    &mut state.invalid,
                )?;
            }
        }
        for record in &file.index.redis {
            let candidates: Vec<_> = states
                .iter_mut()
                .filter(eligible)
                .filter(|s| matches!(s.rule, BackgroundDependencyRuleConfig::Redis { .. }))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let raw = reader.read(&file.path, &file.index.stamp, &record.location)?;
            let event: Value = serde_json::from_slice(&raw)?;
            for state in candidates {
                observe(
                    state.rule,
                    &state.origins,
                    file,
                    &victim,
                    &event,
                    record.location.sha256.clone(),
                    &mut index,
                    &mut state.invalid,
                )?;
            }
        }
    }
    for state in states {
        for key in state.invalid {
            index.witnesses.remove(&key);
            index.wire_witnesses.remove(&key);
        }
    }
    super::redis_script::associate(files, rules, &mut index)?;
    super::mysql_transaction::associate(files, rules, &mut index)?;
    index.source_bytes += reader.source_bytes;
    Ok(index)
}

struct RuleOrigins<'a> {
    rule: &'a BackgroundDependencyRuleConfig,
    mysql_template_len: Option<usize>,
    origins: BTreeMap<String, Origin>,
    identity_hashes: BTreeSet<String>,
    invalid: BTreeSet<String>,
}

fn mysql_candidate(state: &RuleOrigins<'_>, meta: &Value) -> bool {
    let BackgroundDependencyRuleConfig::Mysql { selector, .. } = state.rule else {
        return false;
    };
    meta["target_host"]
        .as_str()
        .is_some_and(|h| h.eq_ignore_ascii_case(&selector.target_host))
        && meta["target_port"].as_u64() == Some(u64::from(selector.target_port))
        && meta["database"] == selector.database
        && meta["username"] == selector.username
        && meta["integer_hashes"].as_array().is_none_or(|hashes| {
            hashes.iter().any(|h| {
                h.as_str()
                    .is_some_and(|h| state.identity_hashes.contains(h))
            })
        })
        && meta["sql_token_count"]
            .as_u64()
            .is_none_or(|n| state.mysql_template_len.is_none_or(|len| n == len as u64))
}

#[allow(clippy::too_many_arguments)]
fn observe(
    rule: &BackgroundDependencyRuleConfig,
    origins: &BTreeMap<String, Origin>,
    file: &EvidenceFile,
    victim: &str,
    event: &Value,
    sha: String,
    index: &mut OriginIndex,
    invalid: &mut BTreeSet<String>,
) -> Result<()> {
    let mysql = matches!(rule, BackgroundDependencyRuleConfig::Mysql { .. });
    let identity = if mysql {
        crate::config::api_trigger::mysql::identity(rule, event)
    } else {
        redis_args(event).and_then(|args| {
            let port = event["target_port"]
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            let command = event["command"].as_str().unwrap_or_default();
            if let BackgroundDependencyRuleConfig::Redis {
                script: Some(script),
                ports,
                command: selected,
                ..
            } = rule
                && ports.contains(&port)
                && selected.eq_ignore_ascii_case(command)
                && let Err(reason) = script.check_identity(&args)
                && let Some(key) = key(victim, event)
                && index
                    .selector_rejections
                    .values()
                    .map(BTreeMap::len)
                    .sum::<usize>()
                    < 100_000
            {
                index
                    .selector_rejections
                    .entry(rule.name().into())
                    .or_default()
                    .insert(key, reason.to_string());
            }
            crate::config::api_trigger::redis_identity(rule, port, command, &args)
        })
    };
    let Some(identity) = identity else {
        return Ok(());
    };
    let Some(origin) = origins.get(&identity) else {
        return Ok(());
    };
    let event_key = if mysql {
        crate::config::api_trigger::mysql::key(victim, event)
    } else {
        key(victim, event)
    };
    let Some(key) = event_key else {
        return Ok(());
    };
    if victim == origin.case_id {
        return Ok(());
    }
    if timestamp(event).is_none_or(|time| time < origin.captured_at)
        || request::references(&file.request, &origin.identity)
        || (mysql && !crate::config::api_trigger::mysql::complete(event))
    {
        index.ambiguous_references += 1;
        invalid.insert(key);
        if mysql && let Some(key) = crate::config::api_trigger::mysql::wire_key(victim, event) {
            invalid.insert(key);
        }
        return Ok(());
    }
    let source = rule.trigger_source().expect("API origin");
    let witness = OriginWitness {
        rule: rule.name().into(),
        trigger_case_id: origin.case_id.clone(),
        trigger_api: format!("{} {}", source.method, source.path),
        binding: source.binding().0.into(),
        dependency_sha256: sha,
        dependencies_path: file.path.clone(),
        target_host: event["target_host"]
            .as_str()
            .context("dependency host missing")?
            .into(),
        target_port: u16::try_from(
            event["target_port"]
                .as_u64()
                .context("dependency port missing")?,
        )?,
        captured_at: origin.captured_at,
        captured_identity: origin.identity.clone(),
        command: event["command"]
            .as_str()
            .context("dependency command missing")?
            .into(),
        exchanges: 1,
    };
    ensure!(
        index.witnesses.len() < 100_000,
        "API trigger witness inventory exceeds limit"
    );
    if mysql && let Some(wire_key) = crate::config::api_trigger::mysql::wire_key(victim, event) {
        ensure!(
            index.wire_witnesses.len() < 100_000,
            "MySQL wire origin inventory exceeds limit"
        );
        ensure!(
            index
                .wire_witnesses
                .insert(wire_key, witness.clone())
                .is_none(),
            "duplicate MySQL wire origin"
        );
    }
    if let Some(existing) = index.witnesses.get_mut(&key) {
        ensure!(
            mysql
                && existing.rule == witness.rule
                && existing.trigger_case_id == witness.trigger_case_id,
            "API-triggered rules have ambiguous overlapping dependency ownership"
        );
        existing.exchanges += 1;
    } else {
        index.witnesses.insert(key, witness);
    }
    Ok(())
}

fn capture_file(
    path: &Path,
    capture: &ApiTriggerCapture,
    bytes_read: &mut u64,
) -> Result<Vec<(String, DateTime<Utc>)>> {
    let mut captures = Vec::new();
    let file = BufReader::new(File::open(path)?);
    for raw in file.split(b'\n') {
        let raw = raw?;
        *bytes_read += raw.len() as u64;
        ensure!(
            raw.len() <= 64 * 1024 * 1024,
            "API trigger dependency record exceeds limit"
        );
        if raw.is_empty() {
            continue;
        }
        let event: Value = serde_json::from_slice(&raw)?;
        if let Some(identity) = capture_identity(capture, &event)
            && let Some(time) = timestamp(&event)
        {
            captures.push((identity, time));
        }
        ensure!(
            captures.len() <= 256,
            "API trigger capture selector matches too many INSERTs"
        );
    }
    Ok(captures)
}

pub(super) fn capture_identity(capture: &ApiTriggerCapture, event: &Value) -> Option<String> {
    if event["event_type"] != "mysql_exchange"
        || event["command"] != "COM_QUERY"
        || !event["target_host"]
            .as_str()?
            .eq_ignore_ascii_case(&capture.target_host)
        || event["target_port"].as_u64()? != u64::from(capture.target_port)
        || event["database"] != capture.database
        || event["username"] != capture.username
        || event["outcome"] != "response"
        || event["response"]["status"] != "ok"
        || event["response"]["affected_rows"].as_u64()? != 1
        || !event["parse_warnings"].as_array()?.is_empty()
    {
        return None;
    }
    let (table, row) = crate::mysql::sql::insert::row(event["sql"].as_str()?)?;
    let tables = crate::config::mysql_tables::TableMatcher::new(
        &capture.tables,
        &capture.table_patterns,
        None,
    )
    .ok()?;
    if !tables.matches(&table)
        || !capture.row_match.iter().all(|(column, expected)| {
            row.get(column)
                .is_some_and(|value| scalar_matches(value, expected))
        })
    {
        return None;
    }
    let Token::Number(identity) = row.get(&capture.column)? else {
        return None;
    };
    crate::mysql::sql::positive_integer(identity)
}

fn scalar_matches(token: &Token, expected: &Value) -> bool {
    match token {
        Token::Number(n) if expected.is_number() => {
            crate::mysql::sql::number(&expected.to_string()).as_ref() == Some(n)
        }
        Token::Bytes(bytes) => expected.as_str().is_some_and(|s| s.as_bytes() == bytes),
        _ => false,
    }
}

pub(super) fn timestamp(event: &Value) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(event["timestamp"].as_str()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub(super) fn case_id(path: &Path) -> Result<String> {
    Ok(path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .context("missing trigger case identity")?
        .into())
}

pub(super) fn key(case: &str, event: &Value) -> Option<String> {
    if event["event_type"] == "mysql_exchange" || event["sql_summary"].is_object() {
        return crate::config::api_trigger::mysql::summary_key(case, event);
    }
    let connection = event["connection_id"].as_str()?;
    let sequence = event["sequence"].as_u64()?;
    Some(format!("{case}/{connection}/{sequence}"))
}
