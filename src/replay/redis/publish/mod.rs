//! Explicit UUID identities in PUBLISH payloads, without interpreting codecs.
//! Preview never binds identities; only a selected, ordered exchange claims one.
use super::{RecordedExchange, ReplayExchange};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Range};
use uuid::Uuid;

pub(crate) mod evidence;
pub(in crate::replay) mod json;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_UUIDS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisPublishSelector {
    pub host: String,
    pub port: u16,
    pub channel: String,
    /// Zero-based position among complete ASCII UUID v4 values in the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid_index: Option<usize>,
    /// Exact ASCII field marker immediately preceding the textual UUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid_field: Option<String>,
}

impl RedisPublishSelector {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty() && self.port != 0,
            "Redis PUBLISH requires host and port"
        );
        ensure!(
            !self.channel.is_empty() && self.channel.len() <= 1024,
            "Redis PUBLISH requires an exact channel of 1..1024 bytes"
        );
        ensure!(
            self.uuid_index.is_some() != self.uuid_field.is_some(),
            "Redis PUBLISH requires exactly one UUID index or field marker"
        );
        if let Some(index) = self.uuid_index {
            ensure!(
                index < MAX_UUIDS,
                "Redis PUBLISH UUID index must be below {MAX_UUIDS}"
            );
        }
        if let Some(field) = &self.uuid_field {
            ensure!(
                !field.is_empty() && field.len() <= 64 && field.bytes().all(word_byte),
                "Redis PUBLISH UUID field must be an ASCII identifier of 1..64 bytes"
            );
        }
        Ok(())
    }
    fn position(&self, payload: &[u8]) -> Option<usize> {
        let spans = spans(payload)?;
        if let Some(index) = self.uuid_index {
            return spans.get(index).map(|_| index);
        }
        let field = self.uuid_field.as_ref()?.as_bytes();
        let mut markers = payload
            .windows(field.len())
            .enumerate()
            .filter(|(index, bytes)| {
                *bytes == field
                    && (*index == 0 || !word_byte(payload[index - 1]))
                    && payload
                        .get(index + field.len())
                        .is_none_or(|byte| !word_byte(*byte))
            });
        let (start, _) = markers.next()?;
        if markers.next().is_some() {
            return None;
        }
        let end = start + field.len();
        spans.iter().position(|span| {
            span.start >= end
                && span.start - end <= 8
                && payload[end..span.start]
                    .iter()
                    .all(|byte| !word_byte(*byte))
        })
    }
    fn matches(&self, record: &RecordedExchange, args: &[Vec<u8>]) -> bool {
        record.command.eq_ignore_ascii_case("PUBLISH")
            && self.host.eq_ignore_ascii_case(&record.target_host)
            && self.port == record.target_port
            && args.len() == 2
            && args[0] == self.channel.as_bytes()
    }
}
fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[derive(Debug)]
pub(in crate::replay) struct PublishRule {
    pub id: String,
    pub selector: RedisPublishSelector,
}

// Scan complete textual UUIDs only. Fixed byte lengths preserve framing in
// binary serializers; arbitrary bytes, embedded fragments and other UUID
// versions are never exempted. Every unselected byte remains exact.
fn spans(payload: &[u8]) -> Option<Vec<Range<usize>>> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let mut spans = Vec::new();
    let mut start = 0;
    while start < payload.len() {
        if !payload[start].is_ascii_hexdigit() {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < payload.len() && (payload[end].is_ascii_hexdigit() || payload[end] == b'-') {
            end += 1;
        }
        let bytes = &payload[start..end];
        if matches!(bytes.len(), 32 | 36)
            && std::str::from_utf8(bytes)
                .ok()
                .and_then(|s| Uuid::parse_str(s).ok())
                .is_some_and(|id| {
                    id.get_version() == Some(uuid::Version::Random)
                        && id.get_variant() == uuid::Variant::RFC4122
                })
        {
            spans.push(start..end);
            if spans.len() > MAX_UUIDS {
                return None;
            }
        }
        start = end;
    }
    Some(spans)
}

fn pair(source: &[u8], target: &[u8], indices: &[usize]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let source_spans = spans(source)?;
    let target_spans = spans(target)?;
    if source_spans.len() != target_spans.len() || source.len() != target.len() {
        return None;
    }
    let mut selected = Vec::new();
    let mut previous = 0;
    for index in indices {
        let a = source_spans.get(*index)?;
        let b = target_spans.get(*index)?;
        if a != b || source.get(previous..a.start)? != target.get(previous..b.start)? {
            return None;
        }
        selected.push((source[a.clone()].to_vec(), target[b.clone()].to_vec()));
        previous = a.end;
    }
    if source.get(previous..)? != target.get(previous..)? {
        return None;
    }
    Some(selected)
}

type BindingKey = (String, i64, Option<String>, Vec<u8>);
struct SelectedIdentity<'a> {
    rule: &'a PublishRule,
    source: Vec<u8>,
    target: Vec<u8>,
}
#[derive(Debug, Default)]
pub(in crate::replay) struct PublishRules {
    rules: Vec<PublishRule>,
    bindings: BTreeMap<BindingKey, Vec<u8>>,
}

impl PublishRules {
    pub(in crate::replay) fn configure(&mut self, rules: Vec<PublishRule>) {
        self.rules = rules;
    }

    fn selection<'a>(
        &'a self,
        exchange: &ReplayExchange,
        actual: &[Vec<u8>],
    ) -> Option<Vec<SelectedIdentity<'a>>> {
        let rules = self
            .rules
            .iter()
            .filter(|rule| rule.selector.matches(&exchange.record, &exchange.args))
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return None;
        }
        if actual.len() != 2 || actual[0] != exchange.args[0] {
            return Some(Vec::new());
        }
        let Some(mut rules) = rules
            .into_iter()
            .map(|rule| {
                rule.selector
                    .position(&exchange.args[1])
                    .map(|position| (position, rule))
            })
            .collect::<Option<Vec<_>>>()
        else {
            return Some(Vec::new());
        };
        rules.sort_by_key(|(position, _)| *position);
        let Some(pairs) = pair(
            &exchange.args[1],
            &actual[1],
            &rules
                .iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
        ) else {
            return Some(Vec::new());
        };
        let mut selected = Vec::new();
        for ((_, rule), (source, target)) in rules.into_iter().zip(pairs) {
            let key = self.key(exchange, rule, &source);
            if self
                .bindings
                .get(&key)
                .is_some_and(|bound| bound != &target)
                || self.bindings.iter().any(|(other, bound)| {
                    other.0 == key.0
                        && other.1 == key.1
                        && other.2 == key.2
                        && other.3 != key.3
                        && bound == &target
                })
            {
                return Some(Vec::new());
            }
            selected.push(SelectedIdentity {
                rule,
                source,
                target,
            });
        }
        Some(selected)
    }
    fn key(&self, exchange: &ReplayExchange, rule: &PublishRule, source: &[u8]) -> BindingKey {
        (
            rule.id.clone(),
            exchange.record.database,
            exchange.record.username.clone(),
            source.to_vec(),
        )
    }
    pub(in crate::replay::redis) fn arguments_match(
        &self,
        exchange: &ReplayExchange,
        actual: &[Vec<u8>],
    ) -> Option<bool> {
        self.selection(exchange, actual)
            .map(|selected| !selected.is_empty())
    }
    pub(in crate::replay::redis) fn claim(
        &mut self,
        exchange: &ReplayExchange,
        actual: &[Vec<u8>],
    ) -> Vec<String> {
        let selected = self
            .selection(exchange, actual)
            .unwrap_or_default()
            .into_iter()
            .map(|selected| {
                (
                    self.key(exchange, selected.rule, &selected.source),
                    selected.target,
                    selected.rule.id.clone(),
                )
            })
            .collect::<Vec<_>>();
        let mut ids = Vec::new();
        for (key, target, id) in selected {
            self.bindings.insert(key, target);
            ids.push(id);
        }
        ids
    }
}

#[cfg(test)]
mod tests;
