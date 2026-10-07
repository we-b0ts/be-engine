//! Token-only mismatch witnesses and immutable source-reference verification.
use super::*;
use crate::replay::command_matching::CommandExchangeScope;
use crate::replay::redis::{RecordedCapture, RedisReplayState, TargetConnection, TargetKey};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
};
const MAX_CANDIDATES: usize = 64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(in crate::replay) struct LockEvidence {
    candidates: Vec<Candidate>,
    omitted_candidates: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Candidate {
    case_id: String,
    command: String,
    selector: RedisLockSelector,
    recorded_exchange_fingerprint: String,
    target_token_fingerprint: String,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fingerprint(record: &RecordedExchange) -> String {
    digest(&serde_json::to_vec(record).expect("record serialization"))
}
impl LockEvidence {
    pub(in crate::replay::redis) fn observe(
        &mut self,
        exchange: &ReplayExchange,
        actual: &[Vec<u8>],
        exchanges: &[ReplayExchange],
        configured: &LockTokens,
    ) {
        if exchange.source != ReplaySource::Case
            || configured.selected.contains_key(&exchange_id(exchange))
        {
            return;
        }
        let Some((key_index, token_index)) = positions(&exchange.record.command, &exchange.args)
        else {
            return;
        };
        if exchange.args.len() != actual.len()
            || exchange.args[token_index] == actual[token_index]
            || !bounded_token(&actual[token_index])
            || exchange
                .args
                .iter()
                .zip(actual)
                .enumerate()
                .any(|(i, (a, b))| i != token_index && a != b)
        {
            return;
        }
        let Some(key) = std::str::from_utf8(&exchange.args[key_index])
            .ok()
            .filter(|key| !key.is_empty() && key.len() <= 1024)
        else {
            return;
        };
        let selector = RedisLockSelector {
            host: exchange.record.target_host.clone(),
            port: exchange.record.target_port,
            key: RedisValueKeySelector::Exact { value: key.into() },
        };
        // A script argument is a candidate only when it references a preceding source SET token.
        if token_index != 1
            && !LockTokens::prepare(
                exchanges,
                &[LockTokenRule {
                    id: "candidate".into(),
                    selector: selector.clone(),
                }],
            )
            .selected
            .contains_key(&exchange_id(exchange))
        {
            return;
        }
        let Some(case_id) = &exchange.case_id else {
            return;
        };
        let candidate = Candidate {
            case_id: case_id.clone(),
            command: exchange.record.command.clone(),
            selector,
            recorded_exchange_fingerprint: fingerprint(&exchange.record),
            target_token_fingerprint: digest(&actual[token_index]),
        };
        if self.candidates.contains(&candidate) {
            return;
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            self.omitted_candidates += 1;
        } else {
            self.candidates.push(candidate);
        }
    }
}

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::replay::redis) fn capture_lock_candidates(
        &mut self,
        case_id: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) {
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
                || record.response_kind == "error"
                || record.outcome != crate::DependencyExchangeOutcome::Response
            {
                continue;
            }
            self.lock_evidence
                .observe(exchange, args, &self.exchanges, &self.lock_tokens);
        }
    }
}

pub(crate) fn discover(report_path: &Path) -> Result<Value> {
    #[derive(Deserialize)]
    struct Report {
        finalized: bool,
        #[serde(default)]
        redis: RedisReport,
    }
    #[derive(Default, Deserialize)]
    struct RedisReport {
        lock_tokens: Option<LockEvidence>,
    }
    let bytes = fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    ensure!(
        report.finalized,
        "Redis lock requires finalized Replay evidence"
    );
    let unavailable = report.redis.lock_tokens.is_none();
    let evidence = report.redis.lock_tokens.unwrap_or_default();
    Ok(
        json!({"candidates": evidence.candidates, "omitted_candidates": evidence.omitted_candidates,
        "requires_fresh_replay": unavailable, "replay_revision":digest(&bytes),
        "does_not_prove":"Token-only differences do not prove lock semantics. Trace SET NX and the script/conditional deletion in source; a source-proven rule and fresh Replay are required."}),
    )
}

pub(crate) fn verify(
    source: &Path,
    report_path: &Path,
    selector: &RedisLockSelector,
) -> Result<Value> {
    selector.validate()?;
    let evidence = discover(report_path)?;
    ensure!(
        evidence["omitted_candidates"] == 0,
        "Redis lock candidates are bounded; narrow and rerun Replay"
    );
    let candidates: Vec<Candidate> = serde_json::from_value(evidence["candidates"].clone())?;
    let candidates = candidates.into_iter().filter(|c| normalize_host(&c.selector.host) == normalize_host(&selector.host)
        && c.selector.port == selector.port && matches!(&c.selector.key, RedisValueKeySelector::Exact {value} if selector.key.matches(value.as_bytes())))
        .collect::<Vec<_>>();
    ensure!(
        !candidates.is_empty(),
        "no Redis lock candidate for this host, port and key; old reports require fresh Replay"
    );
    let (root, files) = crate::replay::recording_evidence::files(source)?;
    let mut state = RedisReplayState::default();
    let mut targets = BTreeMap::new();
    let mut revision = Sha256::new();
    let mut fingerprints = BTreeMap::new();
    for file in files {
        let case_id = crate::replay::recording_evidence::case_id(&file)?;
        ensure!(
            fs::metadata(&file)?.len() <= 256 * 1024 * 1024,
            "Redis lock evidence file exceeds 256 MiB"
        );
        for (line, raw) in BufReader::new(fs::File::open(&file)?).lines().enumerate() {
            let raw = raw?;
            if raw.trim().is_empty() {
                continue;
            }
            let value: Value =
                serde_json::from_str(&raw).context("invalid dependency evidence JSON")?;
            if value["event_type"] != "redis_exchange" {
                continue;
            }
            let record: RecordedExchange = serde_json::from_value(value)?;
            let args = record
                .args
                .iter()
                .map(RecordedCapture::decode)
                .collect::<Result<Vec<_>>>()?;
            let Some((key_index, _)) = positions(&record.command, &args) else {
                continue;
            };
            if !selector.matches(&record, &args[key_index]) {
                continue;
            }
            let location = file.strip_prefix(&root)?;
            revision.update(location.as_os_str().as_encoded_bytes());
            revision.update((line as u64).to_be_bytes());
            revision.update(Sha256::digest(raw.as_bytes()));
            let index = state.exchanges.len();
            fingerprints.insert((case_id.clone(), fingerprint(&record)), index);
            state.register_exchange(
                record,
                ReplaySource::Case,
                Some(&case_id),
                &mut targets,
                &[],
            )?;
            ensure!(
                state.exchanges.len() <= 4096,
                "Redis lock exceeds 4096 selected exchanges; narrow the key selector"
            );
        }
    }
    let prepared = LockTokens::prepare(
        &state.exchanges,
        &[LockTokenRule {
            id: "planned".into(),
            selector: selector.clone(),
        }],
    );
    let acquisitions = prepared
        .selected
        .values()
        .filter(|selected| selected.token_index != 1)
        .map(|selected| selected.acquisition)
        .collect::<std::collections::BTreeSet<_>>();
    for candidate in &candidates {
        let index = fingerprints
            .get(&(
                candidate.case_id.clone(),
                candidate.recorded_exchange_fingerprint.clone(),
            ))
            .context("Redis lock source evidence changed or is missing")?;
        let selected = prepared
            .selected
            .get(&exchange_id(&state.exchanges[*index]))
            .context("Redis lock source no longer contains the selected reference")?;
        ensure!(
            acquisitions.contains(&selected.acquisition),
            "Redis lock requires a same-case SET and token reference in the recording"
        );
    }
    Ok(json!({"candidates":candidates,"recording_root":root,
        "recording_revision":format!("{:x}",revision.finalize()), "replay_revision":evidence["replay_revision"],
        "matching_exchanges":state.exchanges.len(),"references":prepared.pair_count(),
        "does_not_prove":"Source proof must establish random ownership tokens and conditional release; this evidence does not interpret Lua or validate contention/expiry."}))
}
