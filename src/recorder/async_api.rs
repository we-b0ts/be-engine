//! Source-selected asynchronous API completion, independent of traffic ownership.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::DependencyExchangeOutcome;
use crate::mysql::sql::{self, Token};
use crate::policy::{AsyncApiRule, AsyncEnd, Endpoint};
use crate::recorder::{BodyCapture, MysqlValue, RecorderEvent};
mod recorded;
mod selection;
mod transaction;
pub(crate) use selection::AsyncScope;

#[derive(Debug, Clone)]
struct ResourceScope {
    rule: AsyncApiRule,
    progress: Arc<Mutex<RedisProgress>>,
}

#[derive(Debug, Default)]
struct RedisProgress {
    resources: BTreeMap<RedisResource, BTreeSet<uuid::Uuid>>,
    observations: usize,
    mysql: transaction::Transactions,
}

const MAX_OCCURRENCE_OBSERVATIONS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RedisResource {
    selector: usize,
    host: String,
    port: u16,
    database: i64,
    key_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AsyncEndReason {
    Resource,
    DependencyFailure,
    Timeout,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AsyncSignal {
    pub(crate) end_reason: AsyncEndReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) event_type: Option<&'static str>,
}

impl ResourceScope {
    pub(crate) fn observe(&self, event: &RecorderEvent) -> Option<AsyncSignal> {
        // Reuse the exact metadata exemption applied to the semantic inventory.
        // Optional CLIENT SETINFO errors cannot end the business observation.
        if matches!(event, RecorderEvent::RedisExchange(exchange)
            if super::summary::is_client_library_info_exchange(exchange))
        {
            return None;
        }
        if failed(event) {
            return Some(AsyncSignal {
                end_reason: AsyncEndReason::DependencyFailure,
                resource_index: None,
                event_type: Some(event.kind()),
            });
        }
        let signal = self
            .rule
            .end
            .iter()
            .enumerate()
            .find_map(|(index, end)| {
                (terminal(end, event) && self.occurrence_reached(index, end, event))
                    .then_some(index)
            })
            .map(|index| AsyncSignal {
                end_reason: AsyncEndReason::Resource,
                resource_index: Some(index),
                event_type: Some(event.kind()),
            });
        if let RecorderEvent::MysqlExchange(event) = event {
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
                        sql: event.sql.as_deref(),
                        successful: event.outcome == DependencyExchangeOutcome::Response
                            && event.response.error_code.is_none()
                            && event.parse_warnings.is_empty(),
                    },
                    signal,
                )
        } else {
            signal
        }
    }

    fn occurrence_reached(&self, index: usize, end: &AsyncEnd, event: &RecorderEvent) -> bool {
        let (AsyncEnd::Redis(end), RecorderEvent::RedisExchange(event)) = (end, event) else {
            return true;
        };
        if end.occurrence == 1 {
            return true;
        }
        self.redis_occurrence(
            index,
            end,
            event.id,
            (&event.target_host, event.target_port, event.database),
            redis_keys(event),
        )
    }

    fn redis_occurrence(
        &self,
        index: usize,
        end: &crate::policy::AsyncRedisEnd,
        id: uuid::Uuid,
        (host, port, database): (&str, u16, i64),
        keys: Vec<Vec<u8>>,
    ) -> bool {
        if end.occurrence == 1 {
            return true;
        }
        let mut progress = self
            .progress
            .lock()
            .expect("async resource progress poisoned");
        // Keep a bounded observation inventory. An untracked resource remains
        // unfinished and uses the same common deadline, never a guessed end.
        keys.into_iter()
            .filter(|key| key_matches(&end.key, key))
            .any(|key| {
                let resource = RedisResource {
                    selector: index,
                    host: host.to_ascii_lowercase(),
                    port,
                    database,
                    key_digest: Sha256::digest(&key).into(),
                };
                if let Some(observed) = progress.resources.get(&resource) {
                    if observed.len() >= end.occurrence {
                        return true;
                    }
                    if observed.contains(&id) {
                        return false;
                    }
                }
                // Bound the total set entries, including a multi-key command
                // touching many resources. Digests avoid retaining large keys.
                if progress.observations >= MAX_OCCURRENCE_OBSERVATIONS {
                    return false;
                }
                progress.observations += 1;
                let observed = progress.resources.entry(resource).or_default();
                observed.insert(id);
                observed.len() >= end.occurrence
            })
    }
}

fn endpoint_matches(endpoint: &Option<Endpoint>, host: Option<&str>, port: Option<u16>) -> bool {
    endpoint.as_ref().is_none_or(|endpoint| {
        host.is_some_and(|host| endpoint.host.eq_ignore_ascii_case(host))
            && port == Some(endpoint.port)
    })
}

fn terminal(end: &AsyncEnd, event: &RecorderEvent) -> bool {
    match (end, event) {
        (AsyncEnd::Mysql(end), RecorderEvent::MysqlExchange(event)) => {
            event.outcome == DependencyExchangeOutcome::Response
                && event.response.error_code.is_none()
                && event.response.status != "error"
                && matches!(event.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE")
                && end
                    .database
                    .as_deref()
                    .is_none_or(|database| event.database.as_deref() == Some(database))
                && endpoint_matches(
                    &end.endpoint,
                    event.target_host.as_deref(),
                    event.target_port,
                )
                && event.sql.as_deref().is_some_and(|actual| {
                    sql_matches(
                        &end.sql,
                        actual,
                        event.params.as_deref().unwrap_or_default(),
                    )
                })
        }
        (AsyncEnd::Redis(end), RecorderEvent::RedisExchange(event)) => {
            event.outcome == DependencyExchangeOutcome::Response
                && !matches!(event.response_kind.as_str(), "error" | "blob_error")
                && end
                    .database
                    .is_none_or(|database| event.database == database)
                && endpoint_matches(
                    &end.endpoint,
                    Some(&event.target_host),
                    Some(event.target_port),
                )
                && event.command.eq_ignore_ascii_case(&end.operation)
                && redis_keys(event)
                    .iter()
                    .any(|key| key_matches(&end.key, key))
        }
        (AsyncEnd::Http(end), RecorderEvent::HttpExchange(event)) => {
            event.outcome == DependencyExchangeOutcome::Response
                && event.error.is_none()
                && http_terminal(
                    end,
                    &event.method,
                    &event.uri,
                    event.authority.as_deref(),
                    &event.scheme,
                    event.response_status,
                )
        }
        _ => false,
    }
}

fn http_terminal(
    end: &crate::policy::AsyncHttpEnd,
    method: &str,
    uri: &str,
    authority: Option<&str>,
    scheme: &str,
    status: Option<u16>,
) -> bool {
    let Some(status) = status.filter(|status| (200..=299).contains(status)) else {
        return false;
    };
    let Ok(uri) = uri.parse::<hyper::Uri>() else {
        return false;
    };
    let Some(authority) = authority.or_else(|| uri.authority().map(|value| value.as_str())) else {
        return false;
    };
    let Ok(authority) = authority.parse::<hyper::http::uri::Authority>() else {
        return false;
    };
    let port = authority.port_u16().unwrap_or(
        if scheme.contains("https") || uri.scheme_str() == Some("https") {
            443
        } else {
            80
        },
    );
    method == end.method
        && uri.path() == end.path
        && end.endpoint.host.eq_ignore_ascii_case(
            authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']'),
        )
        && end.endpoint.port == port
        && (end.status_codes.is_empty() || end.status_codes.contains(&status))
}

fn redis_keys(event: &crate::recorder::RedisExchangeEvent) -> Vec<Vec<u8>> {
    let Some(arguments) = event.args.iter().map(decode).collect::<Option<Vec<_>>>() else {
        return Vec::new();
    };
    crate::redis::key_slots::key_indices(&event.command.to_ascii_uppercase(), &arguments)
        .unwrap_or_default()
        .into_iter()
        .map(|index| arguments[index].clone())
        .collect()
}

fn key_matches(pattern: &str, key: &[u8]) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            key.len() >= prefix.len() + suffix.len()
                && key.starts_with(prefix.as_bytes())
                && key.ends_with(suffix.as_bytes())
        }
        None => pattern.as_bytes() == key,
    }
}

fn decode(capture: &BodyCapture) -> Option<Vec<u8>> {
    if capture.truncated {
        return None;
    }
    match capture.encoding {
        "utf8" => Some(capture.data.as_bytes().to_vec()),
        "base64" => STANDARD.decode(capture.data.as_bytes()).ok(),
        _ => None,
    }
}

fn sql_matches(pattern: &str, actual: &str, parameters: &[MysqlValue]) -> bool {
    let (Some(pattern), Some(mut actual)) = (
        sql::bounds::statement(pattern),
        sql::bounds::statement(actual),
    ) else {
        return false;
    };
    let mut parameters = parameters.iter();
    for token in &mut actual {
        if *token == Token::Placeholder {
            let Some(value) = parameters.next().and_then(bound_value) else {
                return false;
            };
            *token = value;
        }
    }
    parameters.next().is_none()
        && pattern.len() == actual.len()
        && pattern.iter().zip(&actual).all(|(expected, actual)| {
            expected == actual || *expected == Token::Placeholder && actual.is_value()
        })
}

fn bound_value(value: &MysqlValue) -> Option<Token> {
    match value.kind.as_str() {
        "null" => Some(Token::Null),
        "integer" | "float" | "decimal" => {
            let value = value.value.as_ref()?;
            let text = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string());
            sql::number(&text).map(Token::Number)
        }
        "boolean" | "bool" => value
            .value
            .as_ref()?
            .as_bool()
            .map(|value| Token::Number(u8::from(value).to_string())),
        "string" | "bytes" | "binary" | "date" | "datetime" | "time" | "json" => {
            let bytes = if let Some(raw) = &value.raw {
                decode(raw)?
            } else {
                value.value.as_ref()?.as_str()?.as_bytes().to_vec()
            };
            Some(Token::Bytes(bytes))
        }
        _ => None,
    }
}

fn failed(event: &RecorderEvent) -> bool {
    !crate::recorder::ledger::event::terminal(event).1
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod http_tests;
