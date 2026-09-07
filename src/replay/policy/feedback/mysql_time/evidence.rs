//! Correlate SQL time slots with finalized replay and immutable write evidence.
use super::*;
use crate::replay::policy::matcher::mysql_values::{time_value, values};
use crate::replay::policy::value::parse_time;
use serde_json::Value;

fn identity(s: &MysqlTimeSelector, event: &Value, recorded: bool) -> bool {
    let host = if recorded {
        event["target_host"].as_str()
    } else {
        event["target"]["host"].as_str()
    };
    let port = if recorded {
        event["target_port"].as_u64()
    } else {
        event["target"]["port"].as_u64()
    };
    host.is_some_and(|host| host.eq_ignore_ascii_case(&s.target_host))
        && port == Some(u64::from(s.target_port))
        && event["database"] == s.database
        && event["username"] == s.username
        && matches!(
            event["command"].as_str(),
            Some("COM_QUERY" | "COM_STMT_EXECUTE")
        )
}

fn event_values(s: &MysqlTimeSelector, event: &Value) -> Option<Vec<crate::mysql::sql::Token>> {
    let params: Option<Vec<crate::replay::RecordedMysqlValue>> =
        serde_json::from_value(event.get("params").cloned().unwrap_or(Value::Null)).ok()?;
    values(&s.sql, event["sql"].as_str(), params.as_deref()).ok()
}

pub(super) fn validate(feedback: &MysqlTimeRuleFeedback, time: &TimeRule) -> Result<String> {
    let report: Value = serde_json::from_slice(&super::super::read_published_report(
        &feedback.replay_report_path,
        "MySQL time replay report",
    )?)?;
    ensure!(
        report["finalized"] == true,
        "SQL time rule requires finalized replay evidence"
    );
    let s = &feedback.selector;
    let start = report["started_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .context("replay evidence has no start time")?;
    let finish = report["finalized_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .context("replay evidence has no finalization time")?;
    let offset = crate::replay::policy::config::parse_duration(&time.offset)?;
    let tolerance = crate::replay::policy::config::parse_duration(&time.tolerance)?;
    ensure!(
        finish >= start,
        "replay evidence finalization precedes its start"
    );
    for actual in report["unmatched_queries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| identity(s, event, false))
    {
        let Some(actual_values) = event_values(s, actual) else {
            continue;
        };
        let Some(case) = report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["case_id"] == actual["case_id"])
        else {
            continue;
        };
        let Some(case_dir) = case["case_dir"].as_str() else {
            continue;
        };
        let case_dir = super::super::resolve_published_report_path(std::path::Path::new(case_dir));
        let request: Value = serde_json::from_slice(&fs::read(case_dir.join("request.json"))?)?;
        let (method, path) = crate::replay::policy::response::parse_api(&feedback.api)?;
        if request["method"].as_str() != Some(method)
            || !crate::replay::policy::pattern::path_pattern_matches(
                path,
                &crate::replay::policy::pattern::uri_path(
                    request["uri"].as_str().unwrap_or_default(),
                ),
            )
        {
            continue;
        }
        let bytes = super::super::read_published_report(
            &case_dir.join("dependencies.jsonl"),
            "MySQL semantic dependencies",
        )?;
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let event: Value = serde_json::from_slice(line)?;
            if event["event_type"] != "mysql_exchange" || !identity(s, &event, true) {
                continue;
            }
            let Some(source) = event_values(s, &event) else {
                continue;
            };
            if source.len() != actual_values.len()
                || source
                    .iter()
                    .zip(&actual_values)
                    .enumerate()
                    .any(|(i, (a, b))| i != s.value_index && a != b)
            {
                continue;
            }
            if !event["parse_warnings"]
                .as_array()
                .is_some_and(Vec::is_empty)
                || !matches!(event["response"]["status"].as_str(), Some("ok" | "error"))
            {
                continue;
            }
            let Ok(source_time) = time_value(&source[s.value_index]) else {
                continue;
            };
            let Ok(actual_time) = time_value(&actual_values[s.value_index]) else {
                continue;
            };
            if source_time == actual_time
                || std::mem::discriminant(&source_time) != std::mem::discriminant(&actual_time)
                || parse_time(&source_time, time).is_err()
            {
                continue;
            }
            let Ok(actual_time) = parse_time(&actual_time, time) else {
                continue;
            };
            let actual_millis = actual_time.timestamp_millis();
            if actual_millis
                < start
                    .timestamp_millis()
                    .saturating_add(offset)
                    .saturating_sub(tolerance)
                || actual_millis
                    > finish
                        .timestamp_millis()
                        .saturating_add(offset)
                        .saturating_add(tolerance)
            {
                continue;
            }
            return actual["case_id"]
                .as_str()
                .map(str::to_owned)
                .context("SQL time evidence has no case id");
        }
    }
    anyhow::bail!(
        "SQL time rule requires a matching recorded write and unmatched target write differing only in the selected current-time slot"
    )
}
