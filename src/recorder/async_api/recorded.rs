//! Reuse completion semantics against immutable semantic JSONL inventories.
use super::*;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Capture {
    encoding: String,
    data: String,
    truncated: bool,
    original_len: usize,
    stored_len: usize,
}
impl Capture {
    fn capture(&self) -> Result<BodyCapture> {
        let encoding = match self.encoding.as_str() {
            "utf8" => "utf8",
            "base64" => "base64",
            _ => anyhow::bail!("unsupported recorded async resource encoding"),
        };
        Ok(BodyCapture {
            encoding,
            data: self.data.clone(),
            truncated: self.truncated,
            original_len: self.original_len,
            stored_len: self.stored_len,
        })
    }
}

#[derive(Deserialize)]
struct Parameter {
    kind: String,
    value: Option<Value>,
    raw: Option<Capture>,
}
impl Parameter {
    fn parameter(&self) -> Result<MysqlValue> {
        Ok(MysqlValue {
            kind: self.kind.clone(),
            value: self.value.clone(),
            raw: self.raw.as_ref().map(Capture::capture).transpose()?,
        })
    }
}

#[derive(Deserialize)]
struct Mysql {
    command: String,
    sql: Option<String>,
    params: Option<Vec<Parameter>>,
    database: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    response: MysqlResponse,
    outcome: DependencyExchangeOutcome,
}
#[derive(Deserialize)]
struct MysqlResponse {
    status: String,
    error_code: Option<u16>,
}

#[derive(Deserialize)]
struct Redis {
    id: uuid::Uuid,
    command: String,
    args: Vec<Capture>,
    target_host: String,
    target_port: u16,
    database: i64,
    response_kind: String,
    outcome: DependencyExchangeOutcome,
}

impl AsyncScope {
    pub(crate) fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>> {
        let (index, kind) = match event["event_type"].as_str() {
            Some("dependency_connect_failure") => {
                return Ok(Some(signal(
                    AsyncEndReason::DependencyFailure,
                    None,
                    "dependency_connect_failure",
                )));
            }
            Some("mysql_exchange") => {
                let event: Mysql = serde_json::from_value(event.clone())
                    .context("invalid recorded async MySQL exchange")?;
                if failed_outcome(event.outcome)
                    || event.response.error_code.is_some()
                    || event.response.status == "error"
                {
                    return Ok(Some(signal(
                        AsyncEndReason::DependencyFailure,
                        None,
                        "mysql_exchange",
                    )));
                }
                if event.outcome != DependencyExchangeOutcome::Response {
                    return Ok(None);
                }
                let params = event
                    .params
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(Parameter::parameter)
                    .collect::<Result<Vec<_>>>()?;
                let index = self.rule.end.iter().position(|end| match end {
                    AsyncEnd::Mysql(end) => {
                        matches!(event.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
                            && end
                                .database
                                .as_deref()
                                .is_none_or(|db| event.database.as_deref() == Some(db))
                            && endpoint_matches(
                                &end.endpoint,
                                event.target_host.as_deref(),
                                event.target_port,
                            )
                            && event
                                .sql
                                .as_deref()
                                .is_some_and(|sql| sql_matches(&end.sql, sql, &params))
                    }
                    _ => false,
                });
                (index, "mysql_exchange")
            }
            Some("redis_exchange") => {
                let event: Redis = serde_json::from_value(event.clone())
                    .context("invalid recorded async Redis exchange")?;
                if failed_outcome(event.outcome)
                    || matches!(event.response_kind.as_str(), "error" | "blob_error")
                {
                    return Ok(Some(signal(
                        AsyncEndReason::DependencyFailure,
                        None,
                        "redis_exchange",
                    )));
                }
                if event.outcome != DependencyExchangeOutcome::Response {
                    return Ok(None);
                }
                let args = event
                    .args
                    .iter()
                    .map(Capture::capture)
                    .collect::<Result<Vec<_>>>()?;
                let keys = if let Some(args) = args.iter().map(decode).collect::<Option<Vec<_>>>() {
                    crate::redis::key_slots::key_indices(
                        &event.command.to_ascii_uppercase(),
                        &args,
                    )?
                    .into_iter()
                    .map(|index| args[index].clone())
                    .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let index = self
                    .rule
                    .end
                    .iter()
                    .enumerate()
                    .find_map(|(index, end)| match end {
                        AsyncEnd::Redis(end)
                            if event.command.eq_ignore_ascii_case(&end.operation)
                                && end.database.is_none_or(|db| event.database == db)
                                && endpoint_matches(
                                    &end.endpoint,
                                    Some(&event.target_host),
                                    Some(event.target_port),
                                )
                                && keys.iter().any(|key| key_matches(&end.key, key))
                                && self.redis_occurrence(
                                    index,
                                    end,
                                    event.id,
                                    (&event.target_host, event.target_port, event.database),
                                    keys.clone(),
                                ) =>
                        {
                            Some(index)
                        }
                        _ => None,
                    });
                (index, "redis_exchange")
            }
            Some("http_exchange") => {
                let outcome: DependencyExchangeOutcome =
                    serde_json::from_value(event["outcome"].clone())
                        .context("invalid recorded HTTP outcome")?;
                let failed = !matches!(
                    outcome,
                    DependencyExchangeOutcome::Response | DependencyExchangeOutcome::NoResponse
                ) || !event["error"].is_null()
                    || event["response_status"]
                        .as_u64()
                        .is_some_and(|status| status >= 400);
                return Ok(failed
                    .then(|| signal(AsyncEndReason::DependencyFailure, None, "http_exchange")));
            }
            _ => return Ok(None),
        };
        Ok(index.map(|index| signal(AsyncEndReason::Resource, Some(index), kind)))
    }
}

fn signal(
    end_reason: AsyncEndReason,
    resource_index: Option<usize>,
    event_type: &'static str,
) -> AsyncSignal {
    AsyncSignal {
        end_reason,
        resource_index,
        event_type: Some(event_type),
    }
}
