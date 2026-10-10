//! JSON object identity and explicit array-order normalization for dependency values.
pub(in crate::replay) use crate::json_value::parse;
use crate::replay::policy::select_json_pointers;
use serde_json::Value;
use std::collections::BTreeMap;

pub(in crate::replay) fn canonical_json(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), ordered(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).expect("JSON is serializable")
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
pub(in crate::replay) fn order_paths(
    expected: &Value,
    actual: &Value,
    pointer: &str,
    paths: &mut Vec<String>,
) {
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
