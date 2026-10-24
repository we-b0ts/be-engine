//! SQL text/prepared values and result cells keep their native physical owner.
use super::*;
use crate::replay::policy::MysqlPolicyContext;
use crate::replay::{RecordedMysqlExchange, ReplaySessionIdentity};

pub(super) fn validate(
    runtime: &mut ReplayPolicyRuntime,
    case: &NativeSourceCase<'_>,
    event: &Value,
    coverage: &mut super::coverage::Coverage,
) -> Result<()> {
    let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    let Some(source) = crate::replay::identity_from_exchange(&record) else {
        return Ok(());
    };
    let identity = ReplaySessionIdentity {
        target: Some(source.target),
        database: source.database,
        username: source.username,
    };
    let clock = started(event)?.context("Source SQL request clock missing")?;
    let context = MysqlPolicyContext {
        request_times: crate::replay::assertion::RequestTimes {
            source: Some(clock),
            target: Some(clock),
        },
        case_id: Some(case.id),
        identity: &identity,
        command: &record.command,
        recorded_sql: record.sql.as_deref(),
        sql: record.sql.as_deref(),
        recorded: record.params.as_deref(),
        actual: record.params.as_deref(),
    };
    let response_rules = runtime
        .request_contracts
        .compiled_rules()
        .into_iter()
        .flat_map(|policy| &policy.native)
        .filter(|compiled| matches!(compiled.rule.effect, NativeEffect::MysqlValues(_)))
        .filter(|compiled| {
            NativeScopeGuard::from_rule(&compiled.rule).matches_case(
                case.request["method"].as_str().unwrap_or_default(),
                &super::super::super::pattern::uri_path(
                    case.request["uri"].as_str().unwrap_or_default(),
                ),
                super::super::super::case_condition::request_body(case.request).as_ref(),
            )
        })
        .map(|compiled| {
            super::super::super::matcher::mysql_native::witness_matches(event, compiled)
        })
        .collect::<Result<Vec<_>>>()?;
    let selected = response_rules.into_iter().any(|matches| matches)
        || runtime.dynamic_values.mysql(&context).is_some();
    if !selected {
        return Ok(());
    }
    ensure!(
        record.outcome == crate::DependencyExchangeOutcome::Response
            && record.parse_warnings.is_empty(),
        "Source SQL native evidence has an incomplete outcome"
    );
    ensure!(
        !record.response.rows_truncated,
        "Source SQL native result is truncated"
    );
    if record.response.status == "resultset" {
        ensure!(
            crate::config::process_owned_dependencies::mysql::evidence::complete_response(event),
            "Source SQL native result has incomplete immutable row metadata"
        );
    }
    coverage.references(runtime.dynamic_values.source_mysql_references(&context)?);
    if let Some(normalized) = runtime.dynamic_values.mysql(&context) {
        let normalized = normalized?;
        ensure!(
            normalized.source_sql == normalized.actual_sql
                && normalized.source_params == normalized.actual_params,
            "Source SQL identity self validation changed fields"
        );
        runtime.dynamic_values.commit(case.id, normalized.decision);
    }
    if let Some(decision) = runtime.request_contracts.preview_mysql_values(
        Some(case.id),
        &identity,
        &record,
        &record.command,
        record.sql.as_deref(),
        record.params.as_deref(),
        clock,
        runtime,
    ) {
        runtime.commit(Some(case.id), decision.map_err(anyhow::Error::msg)?)?;
    }
    let (response, ids) = runtime.shift_mysql_response(
        Some(case.id),
        &identity,
        &record,
        &record.response,
        crate::replay::mysql::contracts::source_started(&record),
    )?;
    ensure!(
        serde_json::to_value(&response)? == serde_json::to_value(&record.response)?,
        "Source SQL response self translation changed values"
    );
    for id in &ids {
        let compiled = runtime
            .request_contracts
            .compiled_rules()
            .and_then(|policy| policy.native.iter().find(|rule| &rule.rule.id == id))
            .context("Source SQL response lost its native owner")?;
        let NativeEffect::MysqlValues(effect) = &compiled.rule.effect else {
            continue;
        };
        for (name, field) in &effect.response_time {
            let index = crate::replay::mysql::time_shift::column_index(&record.response, name)?;
            let mut positive = false;
            for row in &record.response.rows {
                let cell = row
                    .get(index)
                    .context("Source SQL result row is incomplete")?;
                if cell.kind == "null" {
                    continue;
                }
                let value = crate::replay::mysql_value_bytes(cell)?;
                let value = std::str::from_utf8(&value)?;
                crate::replay::mysql::time_shift::parse_datetime(value)?;
                if !field
                    .contract
                    .preserve_values
                    .iter()
                    .any(|preserved| preserved == value)
                {
                    positive = true;
                }
            }
            if positive {
                coverage.column(id, name);
            }
        }
    }
    runtime.commit_mysql_response_shift(&ids);
    if let Some(prepared) = runtime.dynamic_values.prepare_mysql_identity_delivery(
        Some(case.id),
        &identity,
        &record,
        &record.response,
    )? {
        let delivered = prepared.render(&record.response)?;
        ensure!(
            delivered == record.response,
            "Source SQL identity self delivery changed fields"
        );
        prepared.commit(&runtime.dynamic_values, &delivered)?;
    }
    Ok(())
}
