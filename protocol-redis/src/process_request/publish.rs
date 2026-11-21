//! Process publishers select exact channels and bounded message predicates.
use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_contract::MAX_VALUE_BYTES;
use traffic_model::DependencyExchangeOutcome;
use traffic_protocol::evidence::FiniteProcessRequest;

use crate::events::RedisExchangeEvent;

use super::{EVENT_TYPES, capture_bytes, is_finite_response, recorded_args, recorded_port};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSelector {
    pub ports: Vec<u16>,
    pub channels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub when_message: BTreeMap<String, RedisPublishPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RedisPublishPredicate {
    Equals { equals: Value },
    Prefix { prefix: String },
}

impl PublishSelector {
    pub fn validate(&self, name: &str) -> Result<()> {
        let mut ports = HashSet::new();
        ensure!(
            (1..=64).contains(&self.ports.len())
                && self
                    .ports
                    .iter()
                    .all(|port| *port != 0 && ports.insert(port)),
            "process Redis PUBLISH rule {name:?} requires 1..64 unique nonzero ports"
        );
        let mut channels = HashSet::new();
        ensure!(
            (1..=4096).contains(&self.channels.len())
                && self.channels.iter().all(|channel| {
                    !channel.is_empty()
                        && channel == channel.trim()
                        && channel.len() <= 512
                        && !channel.contains('*')
                        && !channel.chars().any(char::is_control)
                        && channels.insert(channel)
                }),
            "process Redis PUBLISH rule {name:?} requires unique bounded exact channels without wildcards or controls"
        );
        ensure!(
            self.when_message.len() <= 32,
            "process Redis PUBLISH supports at most 32 message conditions"
        );
        for (pointer, predicate) in &self.when_message {
            traffic_contract::path::validate_pointer(pointer, false)?;
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

    pub fn matches(&self, port: u16, command: &str, args: &[Vec<u8>]) -> bool {
        let [channel, payload] = args else {
            return false;
        };
        command.eq_ignore_ascii_case("PUBLISH")
            && self.ports.contains(&port)
            && self.matches_message(channel, payload)
    }

    fn matches_message(&self, channel: &[u8], payload: &[u8]) -> bool {
        self.channels.iter().any(|key| key.as_bytes() == channel)
            && (self.when_message.is_empty()
                || traffic_codec_json::parse(payload).is_some_and(|message| {
                    self.when_message.iter().all(|(pointer, condition)| {
                        let actual = message.pointer(pointer);
                        match condition {
                            RedisPublishPredicate::Equals { equals } => actual == Some(equals),
                            RedisPublishPredicate::Prefix { prefix } => actual
                                .and_then(Value::as_str)
                                .is_some_and(|value| value.starts_with(prefix)),
                        }
                    })
                }))
    }

    pub fn matches_exchange(&self, exchange: &RedisExchangeEvent) -> bool {
        if exchange.session_setup
            || !exchange.replay_safe
            || !exchange.command.eq_ignore_ascii_case("PUBLISH")
            || !self.ports.contains(&exchange.target_port)
            || exchange.outcome != DependencyExchangeOutcome::Response
            || exchange.response_kind != "integer"
            || !exchange.parse_warnings.is_empty()
            || exchange.cache_snapshot_rule.is_some()
            || exchange.cache_snapshot_hit
        {
            return false;
        }
        let [channel, payload] = exchange.args.as_slice() else {
            return false;
        };
        let complete = crate::capture::response::complete;
        complete(channel)
            .zip(complete(payload))
            .is_some_and(|(channel, payload)| self.matches_message(&channel, &payload))
            && complete(&exchange.response).is_some_and(|reply| successful_reply(&reply))
    }
}

impl FiniteProcessRequest for PublishSelector {
    fn event_types(&self) -> &'static [&'static str] {
        EVENT_TYPES
    }

    fn matches_request(&self, event: &Value) -> bool {
        let (Some(port), Some([channel, payload])) =
            (recorded_port(event), recorded_args(event, "PUBLISH"))
        else {
            return false;
        };
        self.ports.contains(&port)
            && bounded_capture(channel)
                .zip(bounded_capture(payload))
                .is_some_and(|(channel, payload)| self.matches_message(&channel, &payload))
    }

    fn matches_evidence(&self, event: &Value) -> Result<bool> {
        Ok(self.matches_request(event)
            && is_finite_response(event)
            && event["response_kind"] == "integer"
            && event["parse_warnings"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && bounded_capture(&event["response"]).is_some_and(|reply| successful_reply(&reply)))
    }
}

fn bounded_capture(capture: &Value) -> Option<std::borrow::Cow<'_, [u8]>> {
    if capture["data"].as_str()?.len() > 2 * MAX_VALUE_BYTES {
        return None;
    }
    capture_bytes(capture).filter(|bytes| bytes.len() <= MAX_VALUE_BYTES)
}

fn successful_reply(raw: &[u8]) -> bool {
    matches!(
        redis_protocol::resp2::decode::decode(raw),
        Ok(Some((redis_protocol::resp2::types::OwnedFrame::Integer(count), length)))
            if count >= 0 && length == raw.len()
    )
}
