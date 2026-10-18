//! Joint identity/time planning reuses the ordinary capture and SQL time contracts.
use super::*;
use crate::mysql::sql::Token;
mod overlap;
use crate::replay::policy::{
    config::{ReplayDependencyRule, ReplayPolicyDocument},
    dynamic_values::{DynamicValueCapture, from_report},
    matcher::{MysqlPolicyContext, mysql_selectors::MysqlSelectors, mysql_values},
};
pub(super) use overlap::validate as validate_time_overlaps;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueMysqlTimeRule {
    pub id: String,
    pub time_values: Vec<crate::MysqlTimeValueSelector>,
    pub source_evidence: String,
}

impl DynamicValueMysqlTimeRule {
    pub(in crate::replay::policy) fn proposed(
        &self,
        identity: &DynamicValueRule,
    ) -> Result<ReplayDependencyRule> {
        let DynamicValueCapture::Mysql {
            target,
            database,
            sql,
            tables,
            table_patterns,
            table_series,
            value_index,
            json_pointer,
        } = &identity.capture
        else {
            anyhow::bail!("a MySQL time companion requires a MySQL dynamic capture");
        };
        ensure!(
            self.id != identity.id,
            "identity and time rules require distinct ids"
        );
        ensure!(
            self.time_values.iter().all(|time| {
                time.value_index != *value_index
                    || match (json_pointer, &time.json_pointer) {
                        (Some(identity), Some(time)) => {
                            !crate::replay::policy::response_locations_overlap(identity, time)
                        }
                        _ => false,
                    }
            }),
            "identity and time selections overlap"
        );
        crate::config::process_owned_dependencies::validate_source_evidence(&self.source_evidence)?;
        let mut rule = super::super::mysql_time::proposed_rule(
            &self.id,
            &crate::MysqlTimeSelector {
                target_host: target.host.clone(),
                target_port: target.port,
                database: database.clone(),
                username: String::new(),
                sql: sql.clone(),
                tables: tables.clone(),
                table_patterns: table_patterns.clone(),
                table_series: table_series.clone(),
                time_values: self.time_values.clone(),
            },
        )?;
        rule.target.host = Some(target.host.clone());
        rule.target.port = Some(target.port);
        rule.when = identity.when.clone();
        for value in rule
            .mysql
            .as_mut()
            .expect("MySQL time selector")
            .sql_values
            .values_mut()
        {
            match value {
                crate::replay::policy::config::MysqlTimeValueRule::Scalar(field) => {
                    field.source_evidence = self.source_evidence.clone();
                }
                crate::replay::policy::config::MysqlTimeValueRule::Json(fields) => {
                    for field in fields.values_mut() {
                        field.source_evidence = self.source_evidence.clone();
                    }
                }
            }
        }
        Ok(rule)
    }
}

pub(super) struct JointEvidence<'a> {
    identity: &'a DynamicValueRule,
    time: &'a ReplayDependencyRule,
    dynamic_rules: &'a [DynamicValueRule],
    dependency_rules: &'a [ReplayDependencyRule],
    selectors: MysqlSelectors,
}

impl<'a> JointEvidence<'a> {
    pub(super) fn new(
        identity: &'a DynamicValueRule,
        time: &'a ReplayDependencyRule,
        document: &'a ReplayPolicyDocument,
    ) -> Result<Self> {
        Ok(Self {
            identity,
            time,
            dynamic_rules: &document.dynamic_values,
            dependency_rules: &document.dependency_rules,
            selectors: MysqlSelectors::new(&document.dependency_rules)?,
        })
    }
    pub(super) fn validate_witness(
        &self,
        report: &Value,
        _case: &Value,
        request: &Value,
        dependencies: &[u8],
        source_event: &Value,
        actual_event: &Value,
    ) -> Result<bool> {
        let DynamicValueCapture::Mysql {
            target,
            database,
            value_index,
            json_pointer,
            ..
        } = &self.identity.capture
        else {
            anyhow::bail!("a MySQL time companion requires a MySQL dynamic capture");
        };
        let case_id = actual_event["case_id"]
            .as_str()
            .context("joint SQL evidence has no case id")?;
        let source_params: Option<Vec<crate::replay::RecordedMysqlValue>> =
            serde_json::from_value(source_event.get("params").cloned().unwrap_or(Value::Null))?;
        let actual_params: Option<Vec<crate::replay::RecordedMysqlValue>> =
            serde_json::from_value(actual_event.get("params").cloned().unwrap_or(Value::Null))?;
        let template = self.identity.capture.mysql_template()?;
        let (mut source, mut actual) = mysql_values::template_pair_values(
            &template,
            source_event["sql"].as_str(),
            source_params.as_deref(),
            actual_event["sql"].as_str(),
            actual_params.as_deref(),
        )
        .map_err(anyhow::Error::msg)?;
        // Restore only committed, immutable identity proofs. A new proposal
        // cannot overwrite an earlier binding or collapse two source values.
        let aliases = from_report(
            self.dynamic_rules,
            report,
            case_id,
            request,
            dependencies,
            &source,
            &actual,
        )?;
        let session = crate::replay::ReplaySessionIdentity {
            target: Some(crate::replay::TargetKey {
                host: target.host.clone(),
                port: target.port,
            }),
            database: Some(database.clone()),
            username: actual_event["username"].as_str().map(str::to_owned),
        };
        let Some(Ok(normalized)) = aliases.mysql(&MysqlPolicyContext {
            request_times: Default::default(),
            case_id: Some(case_id),
            identity: &session,
            command: actual_event["command"].as_str().unwrap_or_default(),
            recorded_sql: source_event["sql"].as_str(),
            sql: actual_event["sql"].as_str(),
            recorded: source_params.as_deref(),
            actual: actual_params.as_deref(),
        }) else {
            return Ok(false);
        };
        for rule in self.dependency_rules.iter().filter(|rule| {
            rule.mysql
                .as_ref()
                .is_some_and(|mysql| !mysql.params.is_empty())
        }) {
            if rule
                .when
                .as_ref()
                .is_some_and(|condition| !condition.matches_request(request))
            {
                continue;
            }
            if rule.case_selector.as_ref().is_some_and(|scope| {
                request["method"].as_str() != Some(scope.method.as_str())
                    || !crate::replay::policy::pattern::path_pattern_matches(
                        &scope.path,
                        &crate::replay::policy::pattern::uri_path(
                            request["uri"].as_str().unwrap_or_default(),
                        ),
                    )
            }) {
                continue;
            }
            if self.selectors.matches(
                rule,
                &session,
                actual_event["command"].as_str().unwrap_or_default(),
                normalized.actual_sql.as_deref(),
            ) && self
                .selectors
                .matches_sql(rule, normalized.source_sql.as_deref())
            {
                return Ok(false);
            }
        }
        // Identity normalization is limited to its declared capture location.
        // Automatic reference replacement must not excuse another changed slot
        // in the very exchange used to authorize the new contract.
        if let Some(pointer) = json_pointer {
            for values in [&mut source, &mut actual] {
                let Token::Bytes(bytes) = &values[*value_index] else {
                    return Ok(false);
                };
                let mut json = crate::replay::json_order::parse(bytes)
                    .context("joint identity JSON is incomplete")?;
                let field = json
                    .pointer_mut(pointer)
                    .context("joint identity pointer is absent")?;
                ensure!(field.is_string(), "joint identity must be a JSON string");
                *field = Value::Null;
                values[*value_index] = Token::Bytes(serde_json::to_vec(&json)?);
            }
        } else {
            actual[*value_index] = source[*value_index].clone();
        }
        let selected = &self
            .time
            .mysql
            .as_ref()
            .context("joint time selector is absent")?
            .sql_values;
        if source.len() != actual.len()
            || source
                .iter()
                .zip(&actual)
                .enumerate()
                .any(|(index, (source, actual))| !selected.contains_key(&index) && source != actual)
        {
            return Ok(false);
        }
        let times = request_times(report, source_event, actual_event)?;
        for (index, time) in selected {
            let Ok(selected_times) =
                mysql_values::selected_times(&source[*index], &actual[*index], time)
            else {
                return Ok(false);
            };
            if selected_times.iter().any(|selected| {
                selected.source == selected.target
                    || mysql_values::validate_selected_time(selected, times).is_err()
            }) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn request_times(
    report: &Value,
    source_event: &Value,
    actual_event: &Value,
) -> Result<crate::replay::assertion::RequestTimes> {
    let parse = |value: &Value| {
        value
            .as_str()
            .and_then(|text| text.parse::<chrono::DateTime<chrono::Utc>>().ok())
    };
    let source = crate::replay::recording_evidence::dependency_started_at(source_event)
        .context("joint SQL evidence requires a source dependency request timestamp")?;
    let target = parse(&actual_event["request_started_at"])
        .context("joint SQL evidence requires a target dependency request timestamp")?;
    let start =
        parse(&report["started_at"]).context("joint SQL evidence has no Replay start timestamp")?;
    let finish = parse(&report["finalized_at"])
        .context("joint SQL evidence has no Replay finish timestamp")?;
    ensure!(
        start <= target && target <= finish,
        "joint SQL request timestamp is outside the Replay interval"
    );
    Ok(crate::replay::assertion::RequestTimes {
        source: Some(source),
        target: Some(target),
    })
}

#[cfg(test)]
mod tests;
