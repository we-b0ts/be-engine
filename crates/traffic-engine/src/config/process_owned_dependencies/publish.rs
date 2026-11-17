//! Outgoing process-owned Redis publications with exact channels and bounded message conditions.
use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::native::RedisPublishPredicate;
use crate::protocols::recording::events::RedisExchangeEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub ports: Vec<u16>,
    pub channels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub when_message: BTreeMap<String, RedisPublishPredicate>,
}

impl Selector {
    pub(super) fn validate(&self, name: &str) -> Result<()> {
        super::validate_redis_ports(name, &self.ports)?;
        super::validate_exact_redis_keys(name, "PUBLISH", &self.channels)?;
        ensure!(
            self.channels
                .iter()
                .all(|channel| !channel.contains('*') && !channel.chars().any(char::is_control)),
            "process Redis PUBLISH channels require exact names without wildcards or controls"
        );
        ensure!(
            self.when_message.len() <= 32,
            "process Redis PUBLISH supports at most 32 message conditions"
        );
        for (pointer, predicate) in &self.when_message {
            crate::policy::validate_pointer(pointer, false)?;
            match predicate {
                RedisPublishPredicate::Equals { equals } => {
                    ensure!(
                        equals.to_string().len() <= 4096,
                        "Redis PUBLISH equals condition exceeds bounds"
                    );
                }
                RedisPublishPredicate::Prefix { prefix } => {
                    ensure!(
                        !prefix.is_empty() && prefix.len() <= 1024,
                        "Redis PUBLISH prefix condition requires 1..1024 bytes"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn matches(&self, port: u16, command: &str, args: &[Vec<u8>]) -> bool {
        let [channel, payload] = args else {
            return false;
        };
        if !command.eq_ignore_ascii_case("PUBLISH")
            || !self.ports.contains(&port)
            || !super::matches_exact_redis_key(channel, &self.channels)
        {
            return false;
        }
        if self.when_message.is_empty() {
            return true;
        }
        crate::json_value::parse(payload).is_some_and(|message| {
            self.when_message.iter().all(|(pointer, condition)| {
                let actual = message.pointer(pointer);
                match condition {
                    RedisPublishPredicate::Equals { equals } => actual == Some(equals),
                    RedisPublishPredicate::Prefix { prefix } => actual
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.starts_with(prefix)),
                }
            })
        })
    }

    pub fn matches_recorded_request(&self, event: &Value) -> bool {
        if event["event_type"] != "redis_exchange"
            || event["session_setup"] == true
            || event["replay_safe"] != true
            || !event["command"]
                .as_str()
                .is_some_and(|command| command.eq_ignore_ascii_case("PUBLISH"))
        {
            return false;
        }
        let Some(port) = event["target_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
        else {
            return false;
        };
        self.ports.contains(&port)
            && event["args"]
                .as_array()
                .and_then(|args| {
                    args.iter()
                        .map(super::pubsub::capture)
                        .collect::<Option<Vec<_>>>()
                })
                .is_some_and(|args| self.matches(port, "PUBLISH", &args))
    }
}

pub(super) fn successful_exchange(exchange: &RedisExchangeEvent) -> bool {
    exchange.command.eq_ignore_ascii_case("PUBLISH")
        && exchange.outcome == crate::DependencyExchangeOutcome::Response
        && exchange.response_kind == "integer"
        && exchange.parse_warnings.is_empty()
        && exchange.cache_snapshot_rule.is_none()
        && !exchange.cache_snapshot_hit
        && super::decode_capture(&exchange.response).is_some_and(|raw| {
            raw.len() == exchange.response.stored_len
                && raw.len() == exchange.response.original_len
                && successful_reply(&raw)
        })
}

pub(crate) fn successful_record(event: &Value) -> bool {
    event["outcome"] == "response"
        && event["response_kind"] == "integer"
        && event["parse_warnings"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && event["cache_snapshot_rule"].is_null()
        && event["cache_snapshot_hit"] != true
        && super::pubsub::capture(&event["response"]).is_some_and(|raw| successful_reply(&raw))
}

fn successful_reply(raw: &[u8]) -> bool {
    matches!(
        redis_protocol::resp2::decode::decode(raw),
        Ok(Some((redis_protocol::resp2::types::OwnedFrame::Integer(count), length)))
            if count >= 0 && length == raw.len()
    )
}
