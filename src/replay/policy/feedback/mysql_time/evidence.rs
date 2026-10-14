//! Correlate SQL time slots with finalized replay and immutable SQL evidence.
use super::*;
use crate::replay::policy::config::MysqlTimeValueRule;
use crate::replay::policy::matcher::mysql_values::{
    selected_times, template_values, validate_selected_time,
};
use crate::replay::policy::sql_template::{SqlValueTemplate, bounded_statement_tokens};
use serde_json::Value;

fn complete_response(event: &Value) -> bool {
    if !event["parse_warnings"]
        .as_array()
        .is_some_and(Vec::is_empty)
        || event
            .get("outcome")
            .is_some_and(|outcome| outcome != "response")
    {
        return false;
    }
    match event["response"]["status"].as_str() {
        Some("ok" | "error") => true,
        Some("resultset") => {
            if !event["response"]["rows"].is_array() {
                return false;
            }
            let Ok(response) = serde_json::from_value::<crate::replay::mysql::RecordedMysqlResponse>(
                event["response"].clone(),
            ) else {
                return false;
            };
            !response.rows_truncated
                && !response.columns.is_empty()
                && response
                    .rows
                    .iter()
                    .all(|row| row.len() == response.columns.len())
        }
        _ => false,
    }
}

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
    let template = SqlValueTemplate::new(
        &s.sql,
        &s.tables,
        &s.table_patterns,
        s.table_series.as_ref(),
    )
    .ok()?;
    template_values(&template, event["sql"].as_str(), params.as_deref()).ok()
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
    let template = SqlValueTemplate::new(
        &s.sql,
        &s.tables,
        &s.table_patterns,
        s.table_series.as_ref(),
    )?;
    let loaded = load_replay_policy(&feedback.policy_path)?;
    if !loaded.document.dynamic_values.is_empty() {
        ensure!(
            report["replay_policy"]["fingerprint"] == loaded.fingerprint,
            "dynamic SQL time evidence uses a different policy"
        );
    }
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
        let request_times = crate::replay::assertion::RequestTimes {
            source: request["timestamp"].as_str().and_then(|s| s.parse().ok()),
            target: case["target_request_started_at"]
                .as_str()
                .and_then(|s| s.parse().ok()),
        };
        ensure!(
            request_times.source.is_some() && request_times.target.is_some(),
            "SQL time evidence requires source and target request timestamps; replay the case with the current engine"
        );
        let target_request = request_times.target.expect("validated request timestamp");
        ensure!(
            target_request >= start && target_request <= finish,
            "SQL time target request timestamp is outside the replay interval"
        );
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
            // A template covers several physical tables, never a source/target
            // routing difference within the same exchange.
            let binding = |event: &Value| {
                bounded_statement_tokens(event["sql"].as_str()?)
                    .and_then(|tokens| template.bind(&tokens))
            };
            if binding(&event) != binding(actual) {
                continue;
            }
            let (source, actual_values) = if loaded.document.dynamic_values.is_empty() {
                (source, actual_values.clone())
            } else {
                let aliases = crate::replay::policy::dynamic_values::from_report(
                    &loaded.document.dynamic_values,
                    &report,
                    actual["case_id"]
                        .as_str()
                        .context("dynamic SQL time evidence has no case")?,
                    &crate::replay::policy::pattern::uri_path(
                        request["uri"].as_str().unwrap_or_default(),
                    ),
                    &bytes,
                    &source,
                    &actual_values,
                )?;
                let source_params: Option<Vec<crate::replay::RecordedMysqlValue>> =
                    serde_json::from_value(event.get("params").cloned().unwrap_or(Value::Null))?;
                let actual_params: Option<Vec<crate::replay::RecordedMysqlValue>> =
                    serde_json::from_value(actual.get("params").cloned().unwrap_or(Value::Null))?;
                let identity = crate::replay::ReplaySessionIdentity {
                    target: Some(crate::replay::TargetKey {
                        host: event["target_host"].as_str().unwrap_or_default().into(),
                        port: event["target_port"]
                            .as_u64()
                            .and_then(|port| u16::try_from(port).ok())
                            .unwrap_or_default(),
                    }),
                    database: Some(s.database.clone()),
                    username: event["username"].as_str().map(str::to_owned),
                };
                let normalized =
                    aliases.mysql(&crate::replay::policy::matcher::MysqlPolicyContext {
                        case_id: actual["case_id"].as_str(),
                        identity: &identity,
                        command: actual["command"].as_str().unwrap_or_default(),
                        recorded_sql: event["sql"].as_str(),
                        sql: actual["sql"].as_str(),
                        recorded: source_params.as_deref(),
                        actual: actual_params.as_deref(),
                    });
                match normalized {
                    Some(Ok(normalized)) => {
                        let Ok(source) = template_values(
                            &template,
                            normalized.source_sql.as_deref(),
                            normalized.source_params.as_deref(),
                        ) else {
                            continue;
                        };
                        let Ok(actual) = template_values(
                            &template,
                            normalized.actual_sql.as_deref(),
                            normalized.actual_params.as_deref(),
                        ) else {
                            continue;
                        };
                        (source, actual)
                    }
                    Some(Err(_)) => continue,
                    None => (source, actual_values.clone()),
                }
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
            if !complete_response(&event) {
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
                        || validate_selected_time(&selected, request_times).is_err()
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
        "SQL time rule requires a matching complete recorded statement and unmatched target statement differing only in all selected current-time locations"
    )
}
