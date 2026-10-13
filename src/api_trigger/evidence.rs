//! Verify INSERT origins and direct foreign-case Redis references in immutable evidence.
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OriginIndex {
    pub witnesses: BTreeMap<String, OriginWitness>,
    pub evidence_fingerprint: String,
    pub triggers: usize,
    pub ambiguous_triggers: usize,
    pub ambiguous_references: usize,
    #[serde(skip)]
    pub cache_reused: bool,
    #[serde(skip)]
    pub source_bytes: u64,
}

impl OriginIndex {
    pub(crate) fn witness(&self, case_id: &str, event: &Value) -> Option<&OriginWitness> {
        let witness = self.witnesses.get(&key(case_id, event)?)?;
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
    for rule in rules.iter().filter(|r| r.trigger_source().is_some()) {
        let source = rule.trigger_source().expect("selected origin");
        let (binding, capture) = source.binding();
        let mut origins: BTreeMap<String, Vec<Origin>> = BTreeMap::new();
        for file in files
            .iter()
            .filter(|file| request::matches(source, &file.request))
        {
            let captured = capture_file(&file.path, capture, &mut index.source_bytes)?;
            // A broad INSERT selector matching multiple rows is never an origin proof.
            if captured.len() != 1 {
                index.ambiguous_triggers += 1;
                continue;
            }
            let (identity, captured_at) = captured.into_iter().next().expect("one capture");
            let Some(started_at) = file.request.started_at else {
                index.ambiguous_triggers += 1;
                continue;
            };
            if captured_at < started_at {
                index.ambiguous_triggers += 1;
                continue;
            }
            ensure!(
                origins.len() < 4096,
                "API trigger origin inventory exceeds 4096 identities per rule"
            );
            origins.entry(identity.clone()).or_default().push(Origin {
                identity,
                case_id: case_id(&file.path)?,
                captured_at,
            });
        }
        index.ambiguous_triggers += origins.values().filter(|v| v.len() != 1).count();
        let origins: BTreeMap<_, _> = origins
            .into_iter()
            .filter_map(|(id, mut values)| (values.len() == 1).then(|| (id, values.remove(0))))
            .collect();
        index.triggers += origins.len();
        for file in files {
            let victim = case_id(&file.path)?;
            let path = file
                .request
                .uri
                .as_str()
                .split('?')
                .next()
                .unwrap_or_default();
            // Preserve the trigger API and its resource polling/cancellation routes.
            if path == source.path || path.starts_with(&format!("{}/", source.path)) {
                continue;
            }
            for record in &file.index.redis {
                let bytes = reader.read(&file.path, &file.index.stamp, &record.location)?;
                let event: Value = serde_json::from_slice(&bytes)?;
                let Some(args) = redis_args(&event) else {
                    continue;
                };
                let Some(identity) = crate::config::api_trigger::redis_identity(
                    rule,
                    event["target_port"]
                        .as_u64()
                        .and_then(|v| u16::try_from(v).ok())
                        .unwrap_or(0),
                    event["command"].as_str().unwrap_or_default(),
                    &args,
                ) else {
                    continue;
                };
                let Some(origin) = origins.get(&identity) else {
                    continue;
                };
                if victim == origin.case_id {
                    continue;
                }
                if timestamp(&event).is_none_or(|time| time < origin.captured_at)
                    || request::references(&file.request, &origin.identity)
                {
                    index.ambiguous_references += 1;
                    continue;
                }
                let witness = OriginWitness {
                    rule: rule.name().into(),
                    trigger_case_id: origin.case_id.clone(),
                    trigger_api: format!("{} {}", source.method, source.path),
                    binding: binding.into(),
                    dependency_sha256: record.location.sha256.clone(),
                    dependencies_path: file.path.clone(),
                    target_host: event["target_host"]
                        .as_str()
                        .context("Redis host missing")?
                        .into(),
                    target_port: u16::try_from(
                        event["target_port"]
                            .as_u64()
                            .context("Redis port missing")?,
                    )?,
                    command: event["command"]
                        .as_str()
                        .context("Redis command missing")?
                        .into(),
                };
                ensure!(
                    index.witnesses.len() < 100_000,
                    "API trigger witness inventory exceeds limit"
                );
                if let Some(key) = key(&victim, &event) {
                    ensure!(
                        index.witnesses.insert(key, witness).is_none(),
                        "API-triggered rules have ambiguous overlapping dependency ownership"
                    );
                }
            }
        }
    }
    index.source_bytes += reader.source_bytes;
    Ok(index)
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
        || !capture
            .row_match
            .iter()
            .all(|(column, expected)| row.get(column).and_then(scalar).as_ref() == Some(expected))
    {
        return None;
    }
    let Token::Number(identity) = row.get(&capture.column)? else {
        return None;
    };
    identity
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && n.to_string() == *identity)?;
    Some(identity.clone())
}

fn scalar(token: &Token) -> Option<Value> {
    match token {
        Token::Number(number) => serde_json::from_str(number).ok(),
        Token::Bytes(bytes) => String::from_utf8(bytes.clone()).ok().map(Value::String),
        _ => None,
    }
}

fn timestamp(event: &Value) -> Option<DateTime<Utc>> {
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

fn key(case: &str, event: &Value) -> Option<String> {
    let connection = event["connection_id"].as_str()?;
    let sequence = event["sequence"].as_u64()?;
    Some(format!("{case}/{connection}/{sequence}"))
}
