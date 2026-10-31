//! Standard textual timestamps are Source-selected value semantics, not guesses.
use anyhow::{Result, ensure};
use serde_json::Value;

use crate::policy::{
    ClockScope, FieldContract, TimeAnchor, TimePolicy, TimeRelation, TimestampFormat,
};

pub(crate) const RULE_ID: &str = "builtin.time";
const MAX_NODES: usize = 16_384;
const MAX_DEPTH: usize = 128;
const MAX_FIELDS: usize = 4096;

/// Numeric epochs require authored semantics. A standard string fixes its
/// grammar independently of any differing Target value or available clock.
pub(crate) fn contract(source: &Value, settings: &TimePolicy) -> Option<FieldContract> {
    let text = source.as_str()?;
    let format = classify(text)?;
    let utc_offset = matches!(
        format,
        TimestampFormat::Iso8601Naive
            | TimestampFormat::SqlDatetime
            | TimestampFormat::CalendarDate
    )
    .then(|| settings.default_utc_offset.clone());
    let contract = FieldContract::Time {
        format,
        relation: TimeRelation::PreserveOffset,
        anchor: TimeAnchor::Observation,
        utc_offset,
        clock_group: None,
        clock_scope: ClockScope::default(),
    };
    super::super::json::parse_time_value(source, &contract.time()?).ok()?;
    Some(contract)
}

fn classify(text: &str) -> Option<TimestampFormat> {
    let bytes = text.as_bytes();
    if !(10..=35).contains(&bytes.len())
        || !bytes[..10]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                _ => byte.is_ascii_digit(),
            })
    {
        return None;
    }
    if bytes.len() == 10 {
        return Some(TimestampFormat::CalendarDate);
    }
    if bytes.len() < 19
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || !bytes[11..19]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                2 | 5 => *byte == b':',
                _ => byte.is_ascii_digit(),
            })
    {
        return None;
    }
    let zoned = bytes.last().is_some_and(|byte| matches!(byte, b'Z' | b'z'))
        || bytes.len() >= 25
            && matches!(bytes[bytes.len() - 6], b'+' | b'-')
            && bytes[bytes.len() - 3] == b':';
    if zoned {
        if !matches!(bytes[10], b'T' | b't') {
            return None;
        }
        let end = bytes.len()
            - if matches!(bytes[bytes.len() - 1], b'Z' | b'z') {
                1
            } else {
                6
            };
        if !fraction(&bytes[19..end]) {
            return None;
        }
        Some(TimestampFormat::Rfc3339)
    } else if fraction(&bytes[19..]) {
        match bytes[10] {
            b'T' => Some(TimestampFormat::Iso8601Naive),
            b' ' => Some(TimestampFormat::SqlDatetime),
            _ => None,
        }
    } else {
        None
    }
}

fn fraction(bytes: &[u8]) -> bool {
    bytes.is_empty()
        || (2..=10).contains(&bytes.len())
            && bytes[0] == b'.'
            && bytes[1..].iter().all(u8::is_ascii_digit)
}

pub(crate) fn fields(
    source: &Value,
    settings: &TimePolicy,
) -> Result<Vec<(String, FieldContract)>> {
    let mut output = Vec::new();
    let mut remaining = MAX_NODES;
    let mut pointer = String::new();
    let complete = visit(
        source,
        settings,
        &mut pointer,
        0,
        &mut remaining,
        &mut output,
    )?;
    ensure!(
        complete || output.is_empty(),
        "automatic timestamp scan exceeds its bounded Source inventory"
    );
    Ok(output)
}

fn visit(
    source: &Value,
    settings: &TimePolicy,
    pointer: &mut String,
    depth: usize,
    remaining: &mut usize,
    output: &mut Vec<(String, FieldContract)>,
) -> Result<bool> {
    if depth > MAX_DEPTH || *remaining == 0 {
        return Ok(false);
    }
    *remaining -= 1;
    match source {
        Value::Object(values) => {
            for (key, value) in values {
                if key == "\0protobuf" {
                    continue;
                }
                if !needs_visit(value) {
                    continue;
                }
                let before = pointer.len();
                pointer.push('/');
                for character in key.chars() {
                    match character {
                        '~' => pointer.push_str("~0"),
                        '/' => pointer.push_str("~1"),
                        character => pointer.push(character),
                    }
                }
                let complete = visit(value, settings, pointer, depth + 1, remaining, output)?;
                pointer.truncate(before);
                if !complete {
                    return Ok(false);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if !needs_visit(value) {
                    continue;
                }
                let before = pointer.len();
                pointer.push('/');
                use std::fmt::Write as _;
                write!(pointer, "{index}").expect("writing a String is infallible");
                let complete = visit(value, settings, pointer, depth + 1, remaining, output)?;
                pointer.truncate(before);
                if !complete {
                    return Ok(false);
                }
            }
        }
        Value::String(_) => {
            if let Some(contract) = contract(source, settings) {
                ensure!(
                    output.len() < MAX_FIELDS,
                    "automatic timestamp leaf inventory exceeds its bound"
                );
                output.push((pointer.clone(), contract));
            }
        }
        _ => {}
    }
    Ok(true)
}

fn needs_visit(value: &Value) -> bool {
    value.is_object()
        || value.is_array()
        || value
            .as_str()
            .is_some_and(|value| classify(value).is_some())
}

/// Generalize only Source array coordinates. Numeric object member names keep
/// their exact JSON Pointer spelling and cannot become wildcard permissions.
pub(crate) fn pointer_pattern(source: &Value, pointer: &str) -> String {
    let mut parent = Some(source);
    let mut pattern = String::with_capacity(pointer.len());
    for part in pointer.split('/').skip(1) {
        pattern.push('/');
        if parent.is_some_and(Value::is_array) {
            pattern.push('*');
            parent = parent.and_then(|array| {
                part.parse::<usize>()
                    .ok()
                    .and_then(|index| array.get(index))
            });
        } else {
            pattern.push_str(part);
            let key = if part.contains('~') {
                std::borrow::Cow::Owned(part.replace("~1", "/").replace("~0", "~"))
            } else {
                std::borrow::Cow::Borrowed(part)
            };
            parent = parent.and_then(|object| object.get(key.as_ref()));
        }
    }
    pattern
}

#[cfg(test)]
mod tests;
