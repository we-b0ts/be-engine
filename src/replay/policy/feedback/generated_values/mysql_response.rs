//! Plan source-proven MySQL result timestamps from matched, immutable exchanges.
use super::*;
use crate::replay::mysql::time_shift::shift_response;
use crate::replay::policy::{
    config::mysql_response::validate_rule,
    config::{DependencyProtocol, ReplayDependencyRule, validate_document},
    pattern::{path_pattern_matches, uri_path},
    sql_template::SqlValueTemplate,
};
use serde_json::Value;

pub(super) fn plan(
    feedback: DependencyRequestRuleFeedback,
    rule: ReplayDependencyRule,
) -> Result<GeneratedValueRulePlan> {
    validate_rule(&rule)?;
    let original = fs::read_to_string(&feedback.policy_path)?;
    let mut loaded = load_replay_policy(&feedback.policy_path)?;
    let mut proposed = loaded.document.clone();
    proposed.dependency_rules = vec![rule.clone()];
    validate_document(&proposed)?;
    let mut witnesses = Vec::new();
    let report: Value =
        serde_json::from_slice(&evidence::read(feedback.replay_report, &mut witnesses)?)?;
    ensure!(
        report["finalized"] == true && report["complete"] == true,
        "MySQL response time shift requires complete finalized Replay"
    );
    crate::replay::ReplayEvidencePolicyFreshness::new(
        report["replay_policy"]["fingerprint"].as_str(),
        &loaded.fingerprint,
    )
    .ensure_current("MySQL response time shift")?;
    let mysql = rule.mysql.as_ref().expect("validated MySQL rule");
    let scope = rule.case_selector.as_ref().expect("validated API scope");
    let fields = mysql
        .response_time_shift
        .iter()
        .map(|(column, field)| Ok((column.clone(), field.preserved_values()?)))
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let template = SqlValueTemplate::new(
        &mysql.sql,
        &mysql.tables,
        &mysql.table_patterns,
        mysql.table_series.as_ref(),
    )?;
    let mut matching_cases = 0;
    for case in report["cases"].as_array().into_iter().flatten() {
        let matched = report["matched_queries"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|event| {
                event["case_id"] == case["case_id"]
                    && event["source"] == "case"
                    && event["target"]["host"]
                        .as_str()
                        .zip(rule.target.host.as_deref())
                        .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
                    && event["target"]["port"].as_u64() == rule.target.port.map(u64::from)
                    && event["database"].as_str() == mysql.database.as_deref()
                    && event["sql"]
                        .as_str()
                        .is_some_and(|sql| template.matches(sql))
            });
        if !matched {
            continue;
        }
        let dir = PathBuf::from(
            case["case_dir"]
                .as_str()
                .context("Replay case has no directory")?,
        );
        let request: Value =
            serde_json::from_slice(&evidence::read(dir.join("request.json"), &mut witnesses)?)?;
        if request["method"] != scope.method
            || !request["uri"]
                .as_str()
                .is_some_and(|uri| path_pattern_matches(&scope.path, &uri_path(uri)))
        {
            continue;
        }
        let source = request["timestamp"]
            .as_str()
            .and_then(|text| text.parse().ok())
            .context("MySQL response shift evidence has no source request timestamp")?;
        ensure!(
            case["target_request_started_at"]
                .as_str()
                .is_some_and(|text| text.parse::<chrono::DateTime<chrono::Utc>>().is_ok()),
            "MySQL response shift evidence needs a fresh request_begin anchor"
        );
        let bytes = evidence::read(dir.join("dependencies.jsonl"), &mut witnesses)?;
        let mut found = false;
        for line in std::str::from_utf8(&bytes)?
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let event: Value = serde_json::from_str(line)?;
            if event["event_type"] != "mysql_exchange"
                || event["target_host"]
                    .as_str()
                    .zip(rule.target.host.as_deref())
                    .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
                || event["target_port"].as_u64() != rule.target.port.map(u64::from)
                || event["database"].as_str() != mysql.database.as_deref()
                || mysql
                    .username
                    .as_ref()
                    .is_some_and(|name| event["username"] != *name)
                || !event["sql"]
                    .as_str()
                    .is_some_and(|sql| template.matches(sql))
            {
                continue;
            }
            let record: crate::replay::mysql::RecordedMysqlExchange =
                serde_json::from_value(event)?;
            ensure!(
                record.parse_warnings.is_empty()
                    && record.outcome == crate::DependencyExchangeOutcome::Response,
                "MySQL response shift requires complete semantic evidence"
            );
            shift_response(
                &record.response,
                &fields,
                crate::replay::assertion::RequestTimes {
                    source: Some(source),
                    target: Some(source),
                },
            )?;
            found = true;
        }
        if found {
            matching_cases += 1;
        }
    }
    ensure!(
        matching_cases > 0,
        "no matched same-case MySQL resultset proves the selected time columns"
    );
    if let Some(existing) = loaded
        .document
        .dependency_rules
        .iter()
        .find(|existing| existing.id == rule.id)
    {
        ensure!(
            serde_json::to_value(existing)? == serde_json::to_value(&rule)?,
            "dependency rule id already has a different definition"
        );
    } else {
        loaded.document.dependency_rules.push(rule.clone());
    }
    validate_document(&loaded.document)?;
    let updated = replace_dependency_rules(&original, &loaded.document)?;
    Ok(GeneratedValueRulePlan {
        policy_path: feedback.policy_path,
        original: original.clone(),
        updated: updated.clone(),
        witnesses,
        key_witnesses: vec![],
        report: GeneratedValueRuleReport {
            kind: "mysql_response_time_shift".into(),
            api: format!("{} {}", scope.method, scope.path),
            policy_fingerprint: loaded.fingerprint,
            matching_cases,
            selected_difference_cases: matching_cases,
            added_rule_ids: vec![rule.id],
            changed: original != updated,
            applied: false,
            requires_fresh_replay: true,
            diff: render_dependency_rules(&loaded.document)?,
        },
    })
}

pub(super) fn is_rule(rule: &ReplayDependencyRule) -> bool {
    rule.protocol == DependencyProtocol::Mysql
        && rule
            .mysql
            .as_ref()
            .is_some_and(|mysql| !mysql.response_time_shift.is_empty())
}

#[cfg(test)]
mod tests;
