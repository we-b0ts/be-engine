//! Reuse completion semantics against immutable semantic JSONL inventories.
use super::*;
use crate::recorder::MysqlValue;
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
    connection_id: uuid::Uuid,
    query_sequence: u64,
    server_status_before: Option<u16>,
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
    server_status: Option<u16>,
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

impl ResourceScope {
    pub(crate) fn observe_recorded(&self, event: &Value) -> Result<Option<AsyncSignal>> {
        let (indexes, kind) = match event["event_type"].as_str() {
            Some("dependency_connect_failure") => {
                return Ok(None);
            }
            Some("mysql_exchange") => {
                let event: Mysql = serde_json::from_value(event.clone())
                    .context("invalid recorded async MySQL exchange")?;
                if event.outcome != DependencyExchangeOutcome::Response
                    || event.response.error_code.is_some()
                    || event.response.status == "error"
                {
                    self.progress
                        .lock()
                        .expect("async progress poisoned")
                        .mysql
                        .observe(
                            transaction::Facts {
                                connection_id: event.connection_id,
                                sequence: event.query_sequence,
                                before: event.server_status_before,
                                after: event.response.server_status,
                                tokens: None,
                                successful: false,
                            },
                            0,
                        );
                    return Ok(None);
                }
                let params = event
                    .params
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(Parameter::parameter)
                    .collect::<Result<Vec<_>>>()?;
                let actual_sql = OnceCell::new();
                let indexes = self
                    .rule
                    .end
                    .iter()
                    .enumerate()
                    .filter_map(|(index, end)| {
                        (match end {
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
                                    && actual_sql
                                        .get_or_init(|| {
                                            templates::actual_sql(event.sql.as_deref()?, &params)
                                        })
                                        .as_deref()
                                        .is_some_and(|actual| {
                                            self.templates.sql_matches(index, actual)
                                        })
                            }
                            _ => false,
                        })
                        .then_some(index)
                    })
                    .fold(0, |mask, index| mask | (1_u32 << index));
                let indexes = {
                    let mut progress = self.progress.lock().expect("async progress poisoned");
                    let tokens = progress
                        .mysql
                        .needs_tokens(event.connection_id, indexes)
                        .then(|| {
                            actual_sql
                                .get_or_init(|| {
                                    templates::actual_sql(event.sql.as_deref()?, &params)
                                })
                                .as_deref()
                        })
                        .flatten();
                    progress.mysql.observe(
                        transaction::Facts {
                            connection_id: event.connection_id,
                            sequence: event.query_sequence,
                            before: event.server_status_before,
                            after: event.response.server_status,
                            tokens,
                            successful: true,
                        },
                        indexes,
                    )
                };
                return Ok(self.complete(indexes, "mysql_exchange"));
            }
            Some("redis_exchange") => {
                let reply = self
                    .rule
                    .end
                    .iter()
                    .any(|end| matches!(end, AsyncEnd::Redis(_) | AsyncEnd::RedisPublish(_)))
                    .then(|| response_evidence(event))
                    .flatten();
                let event: Redis = serde_json::from_value(event.clone())
                    .context("invalid recorded async Redis exchange")?;
                if event.outcome != DependencyExchangeOutcome::Response
                    || matches!(event.response_kind.as_str(), "error" | "blob_error")
                {
                    return Ok(None);
                }
                let args = event
                    .args
                    .iter()
                    .map(Capture::capture)
                    .collect::<Result<Vec<_>>>()?;
                let cached = redis_event::Event::new(redis_event::Exchange {
                    command: &event.command,
                    args: &args,
                    target_host: &event.target_host,
                    target_port: event.target_port,
                    database: event.database,
                    response_kind: &event.response_kind,
                    resp_version: reply.as_ref().map(|(_, _, version)| *version),
                    response: reply.as_ref().map(|(body, _, _)| body),
                    outcome: event.outcome,
                    parse_warnings: reply.as_ref().map(|(_, warnings, _)| warnings.as_slice()),
                });
                let indexes = self
                    .rule
                    .end
                    .iter()
                    .enumerate()
                    .filter_map(|(index, end)| match end {
                        AsyncEnd::Redis(end)
                            if cached.matches_key(end, index, &self.templates)
                                && self.redis_occurrence(
                                    index,
                                    end,
                                    event.id,
                                    (&event.target_host, event.target_port, event.database),
                                    cached.keys().unwrap_or_default(),
                                ) =>
                        {
                            Some(index)
                        }
                        AsyncEnd::RedisPublish(end) if publish::matches(end, &cached) => {
                            Some(index)
                        }
                        _ => None,
                    })
                    .fold(0, |mask, index| mask | (1_u32 << index));
                (indexes, "redis_exchange")
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
                if failed {
                    return Ok(None);
                }
                let indexes = self
                    .rule
                    .end
                    .iter()
                    .enumerate()
                    .filter_map(|(index, end)| {
                        (match end {
                            AsyncEnd::Http(end) => {
                                outcome == DependencyExchangeOutcome::Response
                                    && http_terminal(
                                        end,
                                        event["method"].as_str().unwrap_or_default(),
                                        event["uri"].as_str().unwrap_or_default(),
                                        event["authority"].as_str(),
                                        event["scheme"].as_str().unwrap_or_default(),
                                        event["response_status"]
                                            .as_u64()
                                            .and_then(|value| value.try_into().ok()),
                                    )
                            }
                            _ => false,
                        })
                        .then_some(index)
                    })
                    .fold(0, |mask, index| mask | (1_u32 << index));
                (indexes, "http_exchange")
            }
            _ => return Ok(None),
        };
        Ok(self.complete(indexes, kind))
    }
}

fn response_evidence(event: &Value) -> Option<(BodyCapture, Vec<String>, u8)> {
    let response: Capture = serde_json::from_value(event.get("response")?.clone()).ok()?;
    let warnings = serde_json::from_value(event.get("parse_warnings")?.clone()).ok()?;
    let version = event.get("resp_version")?.as_u64()?.try_into().ok()?;
    Some((response.capture().ok()?, warnings, version))
}
