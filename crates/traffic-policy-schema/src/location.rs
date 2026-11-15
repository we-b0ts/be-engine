use anyhow::{Result, ensure};
use serde_json::Value;

pub fn validate_json_pointer(pointer: &str) -> Result<()> {
    ensure!(
        pointer.starts_with('/') && pointer.len() > 1,
        "response field must use a non-root JSON Pointer: {pointer:?}"
    );
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            ensure!(
                bytes
                    .get(index + 1)
                    .is_some_and(|byte| matches!(byte, b'0' | b'1')),
                "JSON Pointer contains an invalid '~' escape: {pointer:?}"
            );
            index += 1;
        }
        index += 1;
    }
    Ok(())
}

/// Match a concrete evidence location. Numeric tokens are potential array indexes;
/// actual array types are enforced when selecting values during comparison.
pub fn response_pointer_matches(pattern: &str, pointer: &str) -> bool {
    pattern.split('/').count() == pointer.split('/').count()
        && pattern
            .split('/')
            .zip(pointer.split('/'))
            .all(|(pattern, token)| pattern == token || (pattern == "*" && is_array_index(token)))
}

pub fn response_locations_overlap(left: &str, right: &str) -> bool {
    left.split('/').zip(right.split('/')).all(|(left, right)| {
        left == right
            || (left == "*" && is_array_index(right))
            || (right == "*" && is_array_index(left))
    })
}

fn is_array_index(token: &str) -> bool {
    token == "0"
        || (!token.starts_with('0')
            && !token.is_empty()
            && token.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Resolve a rule against both response bodies. A whole `*` segment expands
/// arrays only; object keys (including a literal `*`) retain exact lookup.
/// Missing values are left to the structural comparator.
pub fn select_json_pointers(pattern: &str, expected: &Value, actual: &Value) -> Vec<String> {
    let mut selected = Vec::new();
    select_segments(
        &pattern.split('/').skip(1).collect::<Vec<_>>(),
        expected,
        actual,
        String::new(),
        &mut selected,
    );
    selected
}

fn select_segments(
    segments: &[&str],
    expected: &Value,
    actual: &Value,
    pointer: String,
    selected: &mut Vec<String>,
) {
    let Some((segment, remaining)) = segments.split_first() else {
        selected.push(pointer);
        return;
    };
    if *segment == "*"
        && let (Value::Array(expected), Value::Array(actual)) = (expected, actual)
    {
        for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
            select_segments(
                remaining,
                expected,
                actual,
                format!("{pointer}/{index}"),
                selected,
            );
        }
    } else {
        let child = format!("/{segment}");
        if let (Some(expected), Some(actual)) = (expected.pointer(&child), actual.pointer(&child)) {
            select_segments(
                remaining,
                expected,
                actual,
                format!("{pointer}{child}"),
                selected,
            );
        }
    }
}

#[cfg(test)]
mod tests;
