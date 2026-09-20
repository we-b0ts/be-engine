//! Correlate SQL time slots with finalized replay and immutable write evidence.
use super::*;
use crate::replay::policy::config::MysqlTimeValueRule;
use crate::replay::policy::matcher::mysql_values::{selected_times, values};
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
    (s.target_host.is_empty()
        || (host.is_some_and(|host| host.eq_ignore_ascii_case(&s.target_host))
            && port == Some(u64::from(s.target_port))))
        && event["database"] == s.database
        && (s.username.is_empty() || event["username"] == s.username)
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

pub(super) fn validate(
    feedback: &MysqlTimeRuleFeedback,
    sql_values: &BTreeMap<usize, MysqlTimeValueRule>,
) -> Result<String> {
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
            // An unscoped rule still requires proof from the same actual
            // database connection identity, never from an unrelated endpoint.
            if !event["target_host"].as_str().is_some_and(|host| {
                actual["target"]["host"]
                    .as_str()
                    .is_some_and(|other| host.eq_ignore_ascii_case(other))
            }) || event["target_port"].as_u64().is_none()
                || event["target_port"] != actual["target"]["port"]
                || event["username"].as_str().is_none()
                || event["username"] != actual["username"]
            {
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
                    .any(|(i, (a, b))| !sql_values.contains_key(&i) && a != b)
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
            let mut validated = 0;
            for (index, selected) in sql_values {
                let Ok(times) = selected_times(&source[*index], &actual_values[*index], selected)
                else {
                    validated = 0;
                    break;
                };
                for selected in times {
                    if selected.source == selected.target
                        || parse_time(&selected.source, &selected.rule).is_err()
                    {
                        validated = 0;
                        break;
                    }
                    let Ok(actual_time) = parse_time(&selected.target, &selected.rule) else {
                        validated = 0;
                        break;
                    };
                    let offset =
                        crate::replay::policy::config::parse_duration(&selected.rule.offset)?;
                    let tolerance =
                        crate::replay::policy::config::parse_duration(&selected.rule.tolerance)?;
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
                        validated = 0;
                        break;
                    }
                    validated += 1;
                }
                if validated == 0 {
                    break;
                }
            }
            let expected = sql_values
                .values()
                .map(|selected| match selected {
                    MysqlTimeValueRule::Scalar(_) => 1,
                    MysqlTimeValueRule::Json(fields) => fields.len(),
                })
                .sum::<usize>();
            if validated != expected {
                continue;
            }
            return actual["case_id"]
                .as_str()
                .map(str::to_owned)
                .context("SQL time evidence has no case id");
        }
    }
    anyhow::bail!(
        "SQL time rule requires a matching recorded write and unmatched target write differing only in all selected current-time locations"
    )
}
