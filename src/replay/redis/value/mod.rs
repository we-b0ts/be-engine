//! Redis string-write value decoding and explicit collection normalization.
use super::ReplayExchange;
use serde_json::Value;
pub(crate) mod evidence;
use super::json;
mod selector;
pub use selector::{RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector};

use crate::value_limits::MAX_VALUE_BYTES;
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

/// Guessed JSON keeps strict logical equality. Unknown bytes never acquire a
/// protobuf decoder, unordered permission or resource-scoped value rule.
pub(super) fn arguments_match(exchange: &ReplayExchange, actual: &[Vec<u8>]) -> bool {
    if exchange.args == actual {
        return true;
    }
    let Some((source, target)) = paired_values(&exchange.record.command, &exchange.args, actual)
    else {
        return false;
    };
    match (json::parse(source), json::parse(target)) {
        (Some(source), Some(target)) => source == target,
        _ => source == target,
    }
}
#[cfg(test)]
mod tests;
