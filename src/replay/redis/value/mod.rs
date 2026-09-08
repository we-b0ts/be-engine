//! Redis string-write value decoding and explicit collection normalization.
use super::ReplayExchange;
use crate::replay::assertion::protobuf;
use serde_json::Value;
pub(crate) mod evidence;
use super::json;
mod selector;
pub use selector::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};

const MAX_VALUE_BYTES: usize = 1024 * 1024;
#[derive(Debug, Clone)]
pub(in crate::replay) struct ValueRule {
    pub id: String,
    pub selector: RedisUnorderedSelector,
}

/// Only whole string writes: substring writes and collection-member bytes keep exact identity.
pub(super) fn value_index(command: &str, args: &[Vec<u8>]) -> Option<usize> {
    match command.to_ascii_uppercase().as_str() {
        "SET" if args.len() >= 2 => Some(1),
        "SETNX" if args.len() == 2 => Some(1),
        "SETEX" | "PSETEX" if args.len() == 3 => Some(2),
        _ => None,
    }
}
pub(super) fn paired_values<'a>(
    command: &str,
    expected: &'a [Vec<u8>],
    actual: &'a [Vec<u8>],
) -> Option<(&'a [u8], &'a [u8])> {
    let index = value_index(command, expected)?;
    if expected.len() != actual.len()
        || expected
            .iter()
            .zip(actual)
            .enumerate()
            .any(|(i, (a, b))| i != index && a != b)
    {
        return None;
    }
    let (a, b) = (expected[index].as_slice(), actual[index].as_slice());
    (a.len() <= MAX_VALUE_BYTES && b.len() <= MAX_VALUE_BYTES).then_some((a, b))
}

pub(super) fn compare(expected: &[u8], actual: &[u8], fields: &[RedisUnorderedField]) -> bool {
    if expected == actual {
        return true;
    }
    let parsed = (json::parse(expected), json::parse(actual));
    if parsed.0.is_some() != parsed.1.is_some() {
        return false;
    }
    if let (Some(mut a), Some(mut b)) = parsed {
        for field in fields {
            if let RedisUnorderedField::Json { pointer } = field {
                normalize_json(&mut a, &mut b, pointer);
            }
        }
        return a == b;
    }
    let paths = fields
        .iter()
        .filter_map(RedisUnorderedField::protobuf_rule)
        .collect::<Vec<_>>();
    protobuf::compare_protobuf(expected, actual, &paths, &[]).unwrap_or(false)
}
pub(super) fn normalize_json(a: &mut Value, b: &mut Value, pointer: &str) {
    if pointer.is_empty() {
        if let (Value::Array(a), Value::Array(b)) = (a, b) {
            a.sort_by_cached_key(crate::replay::json_order::canonical_json);
            b.sort_by_cached_key(crate::replay::json_order::canonical_json);
        }
    } else {
        crate::replay::json_order::normalize_arrays(a, b, pointer);
    }
}

pub(super) fn arguments_match(
    exchange: &ReplayExchange,
    actual: &[Vec<u8>],
    rules: &[ValueRule],
) -> bool {
    if exchange.args == actual {
        return true;
    }
    let Some((a, b)) = paired_values(&exchange.record.command, &exchange.args, actual) else {
        return false;
    };
    let fields = matching_rules(exchange, rules)
        .map(|r| r.selector.field.clone())
        .collect::<Vec<_>>();
    compare(a, b, &fields)
}
fn matching_rules<'a>(
    exchange: &'a ReplayExchange,
    rules: &'a [ValueRule],
) -> impl Iterator<Item = &'a ValueRule> {
    rules.iter().filter(|r| {
        exchange.args.first().is_some_and(|key| {
            r.selector.matches(
                &exchange.record.target_host,
                exchange.record.target_port,
                key,
            )
        })
    })
}
pub(super) fn used_rules(
    exchange: &ReplayExchange,
    actual: &[Vec<u8>],
    rules: &[ValueRule],
) -> Vec<String> {
    let Some((a, b)) = paired_values(&exchange.record.command, &exchange.args, actual) else {
        return Vec::new();
    };
    let matching = matching_rules(exchange, rules).collect::<Vec<_>>();
    matching
        .iter()
        .filter(|r| {
            let others = matching
                .iter()
                .filter(|o| o.id != r.id)
                .map(|o| o.selector.field.clone())
                .collect::<Vec<_>>();
            !compare(a, b, &others)
        })
        .map(|r| r.id.clone())
        .collect()
}
#[cfg(test)]
mod tests;
