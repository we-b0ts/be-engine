//! Source-selected asynchronous API completion, independent of traffic ownership.
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::DependencyExchangeOutcome;
use crate::mysql::sql::Token;
use crate::policy::{AsyncApiRule, AsyncEnd, Endpoint};
use crate::recorder::{BodyCapture, RecorderEvent};
mod publish;
mod recorded;
mod redis_event;
mod response;
mod selection;
mod templates;
mod transaction;
pub(crate) use selection::AsyncScope;

#[derive(Debug, Clone)]
struct ResourceScope {
    rule: AsyncApiRule,
    progress: Arc<Mutex<ResourceProgress>>,
    templates: templates::Templates,
}

#[derive(Debug, Default)]
struct ResourceProgress {
    resources: BTreeMap<RedisResource, BTreeSet<uuid::Uuid>>,
    observations: usize,
    mysql: transaction::Transactions,
    completed: u32,
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
    Stopped,
    Idle,
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
    fn new(rule: AsyncApiRule) -> Self {
        let templates = templates::Templates::new(&rule);
        Self {
            rule,
            templates,
            progress: Default::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn observe(&self, event: &RecorderEvent) -> Option<AsyncSignal> {
        self.observe_cached(
            event,
            redis_event::Event::from_event(event).as_ref(),
            &OnceCell::new(),
        )
    }

    fn observe_cached(
        &self,
        event: &RecorderEvent,
        redis: Option<&redis_event::Event<'_>>,
        actual_sql: &OnceCell<Option<Vec<Token>>>,
    ) -> Option<AsyncSignal> {
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
        let indexes = self
            .rule
            .end
            .iter()
            .enumerate()
            .filter_map(|(index, end)| {
                (terminal(index, end, event, redis, actual_sql, &self.templates)
                    && self.occurrence_reached(index, end, event, redis))
                .then_some(index)
            })
            .fold(0, |mask, index| mask | (1_u32 << index));
        let indexes = if let RecorderEvent::MysqlExchange(event) = event {
            let mut progress = self.progress.lock().expect("async progress poisoned");
            let tokens = progress
                .mysql
                .needs_tokens(event.connection_id, indexes)
                .then(|| {
                    actual_sql
                        .get_or_init(|| {
                            templates::actual_sql(
                                event.sql.as_deref()?,
                                event.params.as_deref().unwrap_or_default(),
                            )
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
                    successful: event.outcome == DependencyExchangeOutcome::Response
                        && event.response.error_code.is_none()
                        && event.parse_warnings.is_empty(),
                },
                indexes,
            )
        } else {
            indexes
        };
        self.complete(indexes, event.kind())
    }

    fn complete(&self, indexes: u32, event_type: &'static str) -> Option<AsyncSignal> {
        if indexes == 0 {
            return None;
        }
        let index = indexes.trailing_zeros() as usize;
        self.progress
            .lock()
            .expect("async progress poisoned")
            .completed |= indexes;
        Some(AsyncSignal {
            end_reason: AsyncEndReason::Resource,
            resource_index: Some(index),
            event_type: Some(event_type),
        })
    }

    fn all_ends_matched(&self) -> bool {
        !self.rule.end.is_empty()
            && self
                .progress
                .lock()
                .expect("async progress poisoned")
                .completed
                .count_ones() as usize
                == self.rule.end.len()
    }

    fn occurrence_reached(
        &self,
        index: usize,
        end: &AsyncEnd,
        event: &RecorderEvent,
        redis: Option<&redis_event::Event<'_>>,
    ) -> bool {
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
            redis.and_then(redis_event::Event::keys).unwrap_or_default(),
        )
    }

    fn redis_occurrence(
        &self,
        index: usize,
        end: &crate::policy::AsyncRedisEnd,
        id: uuid::Uuid,
        (host, port, database): (&str, u16, i64),
        keys: &[Vec<u8>],
    ) -> bool {
        if end.occurrence == 1 {
            return true;
        }
        let mut progress = self
            .progress
            .lock()
            .expect("async resource progress poisoned");
        // Keep a bounded observation inventory. An untracked resource cannot
        // prove completion; only a real end or the recording boundary closes it.
        keys.iter()
            .filter(|key| self.templates.key_matches(index, key))
            .any(|key| {
                let resource = RedisResource {
                    selector: index,
                    host: host.to_ascii_lowercase(),
                    port,
                    database,
                    key_digest: Sha256::digest(key).into(),
                };
                if progress
                    .resources
                    .get(&resource)
                    .is_some_and(|observed| observed.contains(&id))
                {
                    return false;
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

fn terminal(
    index: usize,
    end: &AsyncEnd,
    event: &RecorderEvent,
    redis: Option<&redis_event::Event<'_>>,
    actual_sql: &OnceCell<Option<Vec<Token>>>,
    templates: &templates::Templates,
) -> bool {
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
                && actual_sql
                    .get_or_init(|| {
                        templates::actual_sql(
                            event.sql.as_deref()?,
                            event.params.as_deref().unwrap_or_default(),
                        )
                    })
                    .as_deref()
                    .is_some_and(|actual| templates.sql_matches(index, actual))
        }
        (AsyncEnd::Redis(end), RecorderEvent::RedisExchange(_)) => {
            redis.is_some_and(|cached| cached.matches_key(end, index, templates))
        }
        (AsyncEnd::RedisPublish(end), RecorderEvent::RedisExchange(_)) => {
            redis.is_some_and(|cached| publish::matches(end, cached))
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

fn failed(event: &RecorderEvent) -> bool {
    !event.capture_complete()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod http_tests;
