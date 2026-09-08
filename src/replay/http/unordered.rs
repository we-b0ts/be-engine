//! Explicit unordered JSON arrays in outbound HTTP dependency requests.
use super::identity::canonical_json;
use super::*;
use crate::replay::policy::{
    response_pointer_matches, select_json_pointers, validate_json_pointer,
};
use anyhow::ensure;

pub(crate) mod evidence;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpUnorderedSelector {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub pointer: String,
}

impl HttpUnorderedSelector {
    pub(crate) fn validate(&self) -> Result<()> {
        self.endpoint().validate()?;
        validate_json_pointer(&self.pointer)
    }

    fn endpoint(&self) -> super::selector::HttpDependencySelector {
        super::selector::HttpDependencySelector {
            host: self.host.clone(),
            port: self.port,
            method: self.method.clone(),
            path: self.path.clone(),
        }
    }

    fn selects(&self, candidate: &Self) -> bool {
        self.host.eq_ignore_ascii_case(&candidate.host)
            && self.port == candidate.port
            && self.method.eq_ignore_ascii_case(&candidate.method)
            && self.path == candidate.path
            && response_pointer_matches(&self.pointer, &candidate.pointer)
    }
}

/// Sort only the selected array. Nested arrays retain their own ordering.
pub(in crate::replay) fn normalize_arrays(
    expected: &mut Value,
    actual: &mut Value,
    pattern: &str,
) -> bool {
    for pointer in select_json_pointers(pattern, expected, actual) {
        let (Some(Value::Array(left)), Some(Value::Array(right))) =
            (expected.pointer_mut(&pointer), actual.pointer_mut(&pointer))
        else {
            continue;
        };
        left.sort_by_cached_key(canonical_json);
        right.sort_by_cached_key(canonical_json);
    }
    expected == actual
}

/// Discover individual order-only locations without making them active rules.
fn order_paths(expected: &Value, actual: &Value, pointer: &str, paths: &mut Vec<String>) {
    if paths.len() >= 64 || pointer.matches('/').count() > 32 || expected == actual {
        return;
    }
    match (expected, actual) {
        (Value::Array(left), Value::Array(right)) if left.len() == right.len() => {
            let mut left = left.clone();
            let mut right = right.clone();
            left.sort_by_cached_key(canonical_json);
            right.sort_by_cached_key(canonical_json);
            if left == right && !pointer.is_empty() {
                paths.push(pointer.to_string());
            } else {
                // Positional child paths remain meaningful only in the original array order.
                for (index, (left, right)) in expected
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(actual.as_array().unwrap())
                    .enumerate()
                {
                    order_paths(left, right, &format!("{pointer}/{index}"), paths);
                }
            }
        }
        (Value::Object(left), Value::Object(right)) => {
            for (key, left) in left {
                if let Some(right) = right.get(key) {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    order_paths(left, right, &format!("{pointer}/{key}"), paths);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
