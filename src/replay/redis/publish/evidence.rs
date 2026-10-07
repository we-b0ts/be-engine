//! Bounded UUID-only witnesses; no message bodies or identity values are published.
use super::*;
use crate::replay::ReplaySource;
use crate::replay::command_matching::CommandExchangeScope;
use crate::replay::redis::{
    RecordedCapture, RedisReplayState, TargetConnection, TargetKey, normalize_optional,
};
use anyhow::Context;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in crate::replay) struct PublishEvidence {
    candidates: Vec<Candidate>,
    omitted_candidates: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Candidate {
    case_id: String,
    selector: RedisPublishSelector,
    recorded_exchange_fingerprint: String,
    target_uuid_fingerprint: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fingerprint(record: &RecordedExchange) -> String {
    digest(&serde_json::to_vec(record).expect("record serialization"))
}

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn capture_publish_candidates(
        &mut self,
        case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        actual: &[Vec<u8>],
    ) {
        if !command.eq_ignore_ascii_case("PUBLISH") || actual.len() != 2 {
            return;
        }
        for exchange in &self.exchanges {
            let record = &exchange.record;
            if !exchange.is_available()
                || exchange.source != ReplaySource::Case
                || case_id.is_none()
                || exchange.case_id.as_deref() != case_id
                || !self
                    .connection_scopes
                    .matches(exchange, case_id, connection)
                || !super::super::target_matches(target, &record.target_host, record.target_port)
                || record.resp_version != resp_version
                || record.database != database
                || normalize_optional(username) != normalize_optional(record.username.as_deref())
                || !record.command.eq_ignore_ascii_case(command)
                || record.response_kind != "integer"
                || record.outcome != crate::DependencyExchangeOutcome::Response
                || exchange.args.len() != 2
                || exchange.args[0] != actual[0]
                || self
                    .publish_rules
                    .rules
                    .iter()
                    .any(|rule| rule.selector.matches(record, &exchange.args))
            {
                continue;
            }
            let Some(channel) = std::str::from_utf8(&exchange.args[0])
                .ok()
                .filter(|s| !s.is_empty() && s.len() <= 1024)
            else {
                continue;
            };
            for uuid_index in 0..spans(&exchange.args[1]).map_or(0, |spans| spans.len()) {
                let Some(selected) = pair(&exchange.args[1], &actual[1], &[uuid_index]) else {
                    continue;
                };
                let (source, target) = &selected[0];
                if source == target {
                    continue;
                }
                let candidate = Candidate {
                    case_id: case_id.expect("checked active case").into(),
                    selector: RedisPublishSelector {
                        host: record.target_host.clone(),
                        port: record.target_port,
                        channel: channel.into(),
                        uuid_index: Some(uuid_index),
                        uuid_field: None,
                    },
                    recorded_exchange_fingerprint: fingerprint(record),
                    target_uuid_fingerprint: digest(target),
                };
                if self.publish_evidence.candidates.contains(&candidate) {
                    continue;
                }
                if self.publish_evidence.candidates.len() == 64 {
                    self.publish_evidence.omitted_candidates += 1;
                } else {
                    self.publish_evidence.candidates.push(candidate);
                }
            }
        }
    }
}

pub(crate) fn discover(report_path: &Path) -> Result<Value> {
    let bytes = fs::read(report_path)?;
    let report: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        report["finalized"] == true,
        "Redis PUBLISH requires finalized Replay evidence"
    );
    let missing = report["redis"]["publish"].is_null();
    let evidence: PublishEvidence = if missing {
        PublishEvidence::default()
    } else {
        serde_json::from_value(report["redis"]["publish"].clone())?
    };
    Ok(
        json!({"candidates":evidence.candidates, "omitted_candidates":evidence.omitted_candidates,
        "requires_fresh_replay":missing, "replay_revision":digest(&bytes),
        "does_not_prove":"A UUID-only difference does not prove a random publisher identity. Trace the selected UUID position and its lifetime in source; plan/apply and fresh Replay remain required."}),
    )
}

pub(crate) fn verify(
    source: &Path,
    report_path: &Path,
    selector: &RedisPublishSelector,
) -> Result<Value> {
    selector.validate()?;
    let evidence = discover(report_path)?;
    ensure!(
        evidence["omitted_candidates"] == 0,
        "Redis PUBLISH candidates are bounded; narrow and rerun Replay"
    );
    let candidates: Vec<Candidate> = serde_json::from_value(evidence["candidates"].clone())?;
    let candidates = candidates
        .into_iter()
        .filter(|c| {
            c.selector.host.eq_ignore_ascii_case(&selector.host)
                && c.selector.port == selector.port
                && c.selector.channel == selector.channel
                && selector
                    .uuid_index
                    .is_none_or(|index| c.selector.uuid_index == Some(index))
        })
        .collect::<Vec<_>>();
    ensure!(
        !candidates.is_empty(),
        "no Redis PUBLISH UUID candidate for this selector; old reports require fresh Replay"
    );
    let (root, files) = crate::replay::recording_evidence::files(source)?;
    let mut fingerprints = BTreeMap::new();
    let mut revision = Sha256::new();
    let mut matched = 0;
    for file in files {
        let case_id = crate::replay::recording_evidence::case_id(&file)?;
        ensure!(
            fs::metadata(&file)?.len() <= 256 * 1024 * 1024,
            "Redis PUBLISH evidence file exceeds 256 MiB"
        );
        for (line, raw) in BufReader::new(fs::File::open(&file)?).lines().enumerate() {
            let raw = raw?;
            if raw.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&raw)?;
            if value["event_type"] != "redis_exchange" {
                continue;
            }
            let record: RecordedExchange = serde_json::from_value(value)?;
            let args = record
                .args
                .iter()
                .map(RecordedCapture::decode)
                .collect::<Result<Vec<_>>>()?;
            if !selector.matches(&record, &args) {
                continue;
            }
            let position = selector
                .position(&args[1])
                .context("recorded PUBLISH has no unambiguous UUID v4 at selected location")?;
            revision.update(file.strip_prefix(&root)?.as_os_str().as_encoded_bytes());
            revision.update((line as u64).to_be_bytes());
            revision.update(Sha256::digest(raw.as_bytes()));
            fingerprints.insert((case_id.clone(), fingerprint(&record)), position);
            matched += 1;
            ensure!(
                matched <= 4096,
                "Redis PUBLISH exceeds 4096 selected exchanges; narrow the channel"
            );
        }
    }
    let mut selected_candidates = Vec::new();
    for candidate in candidates {
        let position = fingerprints
            .get(&(
                candidate.case_id.clone(),
                candidate.recorded_exchange_fingerprint.clone(),
            ))
            .context("Redis PUBLISH source evidence changed or is missing")?;
        if candidate.selector.uuid_index == Some(*position) {
            selected_candidates.push(candidate);
        }
    }
    ensure!(
        !selected_candidates.is_empty(),
        "no Redis PUBLISH witness differs at the selected UUID field"
    );
    Ok(
        json!({"candidates":selected_candidates,"recording_root":root,"recording_revision":format!("{:x}",revision.finalize()),
        "replay_revision":evidence["replay_revision"],"matching_exchanges":matched}),
    )
}
