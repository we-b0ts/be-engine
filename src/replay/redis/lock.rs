//! Case-local nonce substitution preserving recorded lock-token equality.
use super::key_selector::RedisValueKeySelector;
use super::{RecordedExchange, ReplayExchange, ReplaySource, normalize_host, normalize_optional};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) mod evidence;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedisLockSelector {
    pub host: String,
    pub port: u16,
    pub key: RedisValueKeySelector,
}
impl RedisLockSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty() && self.host.len() <= 253 && self.port > 0,
            "Redis lock requires a bounded host and nonzero port"
        );
        self.key.validate()
    }
    pub(super) fn matches(&self, record: &RecordedExchange, key: &[u8]) -> bool {
        normalize_host(&self.host) == normalize_host(&record.target_host)
            && self.port == record.target_port
            && self.key.matches(key)
    }
}

#[derive(Debug, Clone)]
pub(in crate::replay) struct LockTokenRule {
    pub id: String,
    pub selector: RedisLockSelector,
}

type ExchangeId = (Option<String>, uuid::Uuid, u64);
fn exchange_id(exchange: &ReplayExchange) -> ExchangeId {
    (
        exchange.case_id.clone(),
        exchange.record.connection_id,
        exchange.record.sequence,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Resource {
    case_id: Option<String>,
    host: String,
    port: u16,
    database: i64,
    username: Option<String>,
    key: Vec<u8>,
}
fn resource(exchange: &ReplayExchange, key: &[u8]) -> Resource {
    Resource {
        case_id: exchange.case_id.clone(),
        host: normalize_host(&exchange.record.target_host),
        port: exchange.record.target_port,
        database: exchange.record.database,
        username: normalize_optional(exchange.record.username.as_deref()),
        key: key.to_vec(),
    }
}
#[derive(Debug, Clone)]
struct Selected {
    rule_id: String,
    token_index: usize,
    acquisition: usize,
    resource: Resource,
}
#[derive(Debug, Default)]
pub(super) struct LockTokens {
    selected: BTreeMap<ExchangeId, Selected>,
    bindings: BTreeMap<usize, Vec<u8>>,
}

pub(super) fn bounded_token(token: &[u8]) -> bool {
    !token.is_empty() && token.len() <= 1024
}

/// Return key/value positions only for the supported single-key command shapes.
pub(super) fn positions(command: &str, args: &[Vec<u8>]) -> Option<(usize, usize)> {
    if command.eq_ignore_ascii_case("SET") && args.len() == 5 {
        let (expiry, ttl) = if args[2].eq_ignore_ascii_case(b"NX") {
            (&args[3], &args[4])
        } else if args[4].eq_ignore_ascii_case(b"NX") {
            (&args[2], &args[3])
        } else {
            return None;
        };
        if (expiry.eq_ignore_ascii_case(b"PX") || expiry.eq_ignore_ascii_case(b"EX"))
            && std::str::from_utf8(ttl).ok()?.parse::<u64>().ok()? > 0
            && bounded_token(&args[1])
        {
            return Some((0, 1));
        }
    } else if (command.eq_ignore_ascii_case("EVALSHA") || command.eq_ignore_ascii_case("EVAL"))
        && args.len() == 4
        && args[1] == b"1"
        && bounded_token(&args[3])
    {
        return Some((2, 3));
    } else if command.eq_ignore_ascii_case("DELEX")
        && args.len() == 3
        && args[1].eq_ignore_ascii_case(b"IFEQ")
        && bounded_token(&args[2])
    {
        return Some((0, 2));
    }
    None
}

impl LockTokens {
    pub(super) fn prepare(exchanges: &[ReplayExchange], rules: &[LockTokenRule]) -> Self {
        let mut result = Self::default();
        for rule in rules {
            let mut values = BTreeMap::new();
            for (index, exchange) in exchanges.iter().enumerate() {
                if exchange.source != ReplaySource::Case {
                    continue;
                }
                let Some((key_index, token_index)) =
                    positions(&exchange.record.command, &exchange.args)
                else {
                    continue;
                };
                if !rule
                    .selector
                    .matches(&exchange.record, &exchange.args[key_index])
                {
                    continue;
                }
                let resource = resource(exchange, &exchange.args[key_index]);
                let key = (resource.clone(), exchange.args[token_index].clone());
                let acquisition = if exchange.record.command.eq_ignore_ascii_case("SET") {
                    *values.entry(key).or_insert(index)
                } else {
                    let Some(prior) = values.get(&key) else {
                        continue;
                    };
                    *prior
                };
                result.selected.insert(
                    exchange_id(exchange),
                    Selected {
                        rule_id: rule.id.clone(),
                        token_index,
                        acquisition,
                        resource,
                    },
                );
            }
        }
        result
    }
    pub(super) fn arguments_match(
        &self,
        exchange: &ReplayExchange,
        exchanges: &[ReplayExchange],
        actual: &[Vec<u8>],
    ) -> Option<bool> {
        let selected = self.selected.get(&exchange_id(exchange))?;
        if exchange.args.len() != actual.len()
            || !bounded_token(&actual[selected.token_index])
            || exchange
                .args
                .iter()
                .zip(actual)
                .enumerate()
                .any(|(i, (a, b))| i != selected.token_index && a != b)
        {
            return Some(false);
        }
        let producer = exchange.record.command.eq_ignore_ascii_case("SET");
        if let Some(value) = self.bindings.get(&selected.acquisition) {
            return Some(
                value == &actual[selected.token_index]
                    && (producer || exchanges[selected.acquisition].status.is_consumed()),
            );
        }
        // Distinct source nonces must not collapse into a reused target nonce.
        Some(
            producer
                && !self.selected.values().any(|other| {
                    other.resource == selected.resource
                        && other.acquisition != selected.acquisition
                        && self.bindings.get(&other.acquisition)
                            == Some(&actual[selected.token_index])
                }),
        )
    }
    pub(super) fn claim(&mut self, exchange: &ReplayExchange, actual: &[Vec<u8>]) -> Vec<String> {
        let Some(selected) = self.selected.get(&exchange_id(exchange)) else {
            return Vec::new();
        };
        if exchange.record.command.eq_ignore_ascii_case("SET") {
            self.bindings
                .entry(selected.acquisition)
                .or_insert_with(|| actual[selected.token_index].clone());
        }
        vec![selected.rule_id.clone()]
    }
    pub(super) fn pair_count(&self) -> usize {
        self.selected
            .values()
            .filter(|selected| selected.token_index != 1)
            .count()
    }
}

#[cfg(test)]
mod tests;
