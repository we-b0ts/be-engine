//! Verify capture requests and header observations against immutable file witnesses.
use super::*;
use crate::mysql::sql::Token;
use crate::replay::policy::{
    dynamic_values::{DynamicValueCapture, DynamicValueRule},
    matcher::mysql_values::{template_pair_values, template_values},
    pattern::{path_pattern_matches, uri_path},
};
use serde_json::Value;

pub(super) type Witnesses = Vec<(PathBuf, String)>;
pub(super) fn read(path: PathBuf, witnesses: &mut Witnesses) -> Result<Vec<u8>> {
    let bytes = super::super::read_published_report(&path, "generated value evidence")?;
    witnesses.push((path, fingerprint(&bytes)));
    Ok(bytes)
}

pub(super) fn dynamic(
    rule: &DynamicValueRule,
    report_path: &std::path::Path,
    policy_fingerprint: &str,
    mysql_time: Option<&super::mysql_time::JointEvidence<'_>>,
) -> Result<Witnesses> {
    let mut witnesses = Vec::new();
    let report: Value = serde_json::from_slice(&read(report_path.into(), &mut witnesses)?)?;
    ensure!(
        report["finalized"] == true,
        "dynamic value planning requires finalized replay evidence"
    );
    crate::replay::ReplayEvidencePolicyFreshness::new(
        report["replay_policy"]["fingerprint"].as_str(),
        policy_fingerprint,
    )
    .ensure_current("dynamic value replay evidence")?;
    let DynamicValueCapture::Mysql {
        target,
        database,
        value_index,
        json_pointer,
        ..
    } = &rule.capture
    else {
        return super::request_evidence::validate(rule, &report, witnesses);
    };
    let template = rule.capture.mysql_template()?;
    for actual in report["unmatched_queries"].as_array().into_iter().flatten() {
        if !matches!(
            actual["command"].as_str(),
            Some("COM_QUERY" | "COM_STMT_EXECUTE")
        ) {
            continue;
        }
        if actual["target"]["host"]
            .as_str()
            .is_none_or(|host| !host.eq_ignore_ascii_case(&target.host))
            || actual["target"]["port"] != target.port
            || actual["database"] != *database
        {
            continue;
        }
        let actual_params: Option<Vec<crate::replay::RecordedMysqlValue>> =
            serde_json::from_value(actual.get("params").cloned().unwrap_or(Value::Null))?;
        if template_values(&template, actual["sql"].as_str(), actual_params.as_deref()).is_err() {
            continue;
        }
        let Some(case) = report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| case["case_id"] == actual["case_id"])
        else {
            continue;
        };
        let case_dir = PathBuf::from(
            case["case_dir"]
                .as_str()
                .context("dynamic evidence case directory is absent")?,
        );
        let request: Value =
            serde_json::from_slice(&read(case_dir.join("request.json"), &mut witnesses)?)?;
        if rule
            .when
            .as_ref()
            .is_some_and(|condition| !condition.matches_request(&request))
            || !path_pattern_matches(
                &rule.api,
                &uri_path(request["uri"].as_str().unwrap_or_default()),
            )
        {
            continue;
        }
        let dependencies = read(case_dir.join("dependencies.jsonl"), &mut witnesses)?;
        for line in dependencies
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let source: Value = serde_json::from_slice(line)?;
            if source["event_type"] != "mysql_exchange"
                || source["target_host"]
                    .as_str()
                    .is_none_or(|host| !host.eq_ignore_ascii_case(&target.host))
                || source["target_port"] != target.port
                || source["database"] != *database
                || source["username"] != actual["username"]
            {
                continue;
            }
            if !matches!(
                source["command"].as_str(),
                Some("COM_QUERY" | "COM_STMT_EXECUTE")
            ) || !source["parse_warnings"]
                .as_array()
                .is_some_and(Vec::is_empty)
                || source
                    .get("outcome")
                    .is_some_and(|outcome| outcome != "response")
            {
                continue;
            }
            if !complete_response(&source) {
                continue;
            }
            let params: Option<Vec<crate::replay::RecordedMysqlValue>> =
                serde_json::from_value(source.get("params").cloned().unwrap_or(Value::Null))?;
            let Ok((source_values, actual_values)) = template_pair_values(
                &template,
                source["sql"].as_str(),
                params.as_deref(),
                actual["sql"].as_str(),
                actual_params.as_deref(),
            ) else {
                continue;
            };
            if let Some(time) = mysql_time {
                if !time.validate_witness(
                    &report,
                    case,
                    &request,
                    &dependencies,
                    &source,
                    actual,
                )? {
                    continue;
                }
            } else if source_values.len() != actual_values.len()
                || source_values
                    .iter()
                    .zip(&actual_values)
                    .enumerate()
                    .any(|(index, (source, actual))| index != *value_index && source != actual)
            {
                continue;
            }
            let (Token::Bytes(source_bytes), Token::Bytes(target_bytes)) =
                (&source_values[*value_index], &actual_values[*value_index])
            else {
                continue;
            };
            let (source_value, target_value) = if let Some(pointer) = json_pointer {
                let mut source_json = crate::replay::json_order::parse(source_bytes)
                    .context("dynamic capture JSON has duplicate members or is incomplete")?;
                let mut target_json = crate::replay::json_order::parse(target_bytes)
                    .context("dynamic capture JSON has duplicate members or is incomplete")?;
                let source_value = source_json
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .context("source dynamic capture is not a string")?
                    .to_owned();
                let target_value = target_json
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .context("target dynamic capture is not a string")?
                    .to_owned();
                *source_json.pointer_mut(pointer).expect("selected pointer") = Value::Null;
                *target_json.pointer_mut(pointer).expect("selected pointer") = Value::Null;
                if mysql_time.is_none() && source_json != target_json {
                    continue;
                }
                (source_value, target_value)
            } else {
                (
                    crate::replay::policy::dynamic_values::capture_string(source_bytes, None)?,
                    crate::replay::policy::dynamic_values::capture_string(target_bytes, None)?,
                )
            };
            if source_value == target_value {
                continue;
            }
            rule.validate_value(&source_value)?;
            rule.validate_value(&target_value)?;
            ensure!(
                matches!(
                    source["response"]["status"].as_str(),
                    Some("ok" | "error" | "resultset")
                ),
                "dynamic capture response is unavailable"
            );
            return Ok(witnesses);
        }
    }
    anyhow::bail!("no same-case source/target capture differs only at the selected dynamic value")
}

fn complete_response(event: &Value) -> bool {
    match event["response"]["status"].as_str() {
        Some("ok" | "error") => true,
        Some("resultset") => {
            let Ok(response) = serde_json::from_value::<crate::replay::mysql::RecordedMysqlResponse>(
                event["response"].clone(),
            ) else {
                return false;
            };
            event["response"]["rows"].is_array()
                && !response.rows_truncated
                && !response.columns.is_empty()
                && response
                    .rows
                    .iter()
                    .all(|row| row.len() == response.columns.len())
        }
        _ => false,
    }
}
