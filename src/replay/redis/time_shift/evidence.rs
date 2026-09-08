//! Source-selected time-shift evidence. No heuristic discovery or expiry claims.
use super::super::RecordedExchange;
use super::{RedisTimeShiftSelector, ResponseShift};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Deserialize)]
struct Report {
    finalized: bool,
    #[serde(default)]
    redis: RedisReport,
}
#[derive(Default, Deserialize)]
struct RedisReport {
    #[serde(default)]
    matched: Vec<Matched>,
}
#[derive(Deserialize)]
struct Matched {
    case_id: Option<String>,
    connection_id: uuid::Uuid,
    sequence: u64,
}

pub(crate) fn verify(
    source: &Path,
    report_path: &Path,
    selector: &RedisTimeShiftSelector,
) -> Result<Value> {
    selector.validate()?;
    let report_bytes = fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&report_bytes)?;
    ensure!(
        report.finalized,
        "Redis time-shift requires finalized Replay evidence"
    );
    let (root, mut files) = crate::replay::recording_evidence::files(source)?;
    let global = root.join("global-dependencies.jsonl");
    if global.is_file() {
        ensure!(
            !fs::symlink_metadata(&global)?.file_type().is_symlink(),
            "linked Redis evidence is unsupported"
        );
        files.push(global);
    }
    let mut digest = Sha256::new();
    let mut count = 0_usize;
    let mut matched_count = 0;
    let mut examples = Vec::new();
    for file in files {
        let global = file
            .file_name()
            .is_some_and(|s| s == "global-dependencies.jsonl");
        let case_id = if global {
            None
        } else {
            Some(crate::replay::recording_evidence::case_id(&file)?)
        };
        // A complete selected capture must fit the supported response bound.
        ensure!(
            fs::metadata(&file)?.len() <= 256 * 1024 * 1024,
            "Redis time-shift evidence file exceeds 256 MiB"
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
            let record: RecordedExchange =
                serde_json::from_value(value).context("invalid Redis exchange evidence")?;
            let args = record
                .args
                .iter()
                .map(|a| a.decode())
                .collect::<Result<Vec<_>>>()?;
            if !selector.matches(&record, &args) {
                continue;
            }
            ResponseShift::prepare(&record, &[("planned".into(), selector.read.clone())])?;
            let matched = report.redis.matched.iter().any(|m| {
                m.case_id == case_id
                    && m.connection_id == record.connection_id
                    && m.sequence == record.sequence
            });
            count += 1;
            ensure!(
                count <= 4096,
                "Redis time-shift exceeds 4096 matching exchanges; narrow the selector"
            );
            matched_count += usize::from(matched);
            let location = file.strip_prefix(&root)?.to_string_lossy();
            digest.update(location.as_bytes());
            digest.update((line as u64).to_le_bytes());
            digest.update(Sha256::digest(raw.as_bytes()));
            if examples.len() < 20 {
                examples.push(json!({"case_id":case_id, "file":location, "line":line+1,
                    "recorded_at":record.timestamp, "matched_in_attempt":matched}));
            }
        }
    }
    ensure!(
        matched_count > 0,
        "Redis time-shift requires a selected response actually matched in the current API attempt; inspect earlier cases, or run fresh Replay"
    );
    Ok(json!({
        "recording_root":root, "recording_revision":format!("{:x}", digest.finalize()),
        "replay_revision":format!("{:x}", Sha256::digest(report_bytes)),
        "matching_exchanges":count, "matched_in_attempt":matched_count,
        "examples":examples, "omitted_examples":count.saturating_sub(20),
        "does_not_prove":"Selected integer fields do not prove expiry or cache semantics; source proof and fresh Replay are required."
    }))
}
