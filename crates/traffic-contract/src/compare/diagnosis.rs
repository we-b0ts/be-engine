//! Shared read-only JSON/byte difference projection. Contract evaluation stays
//! with the ordinary comparator; this walk only locates original value changes.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

const PAGE_SIZE: usize = 20;
const NODE_LIMIT: usize = 1_000_000;
const DEPTH_LIMIT: usize = 128;

pub fn at_pointer(source: &[u8], target: &[u8], pointer: &str) -> Value {
    match (parse(source), parse(target)) {
        (Some(source), Some(target)) => {
            let source = source.pointer(pointer);
            let target = target.pointer(pointer);
            let mut result = json!({"pointer":pointer,"source":preview(source),"target":preview(target),
                "origin":"original_body_values_at_runtime_failure_pointer"});
            if let (Some(Value::String(source)), Some(Value::String(target))) = (source, target)
                && source != target
            {
                result["string_difference"] = byte_difference(source.as_bytes(), target.as_bytes());
            }
            result
        }
        _ => {
            json!({"pointer":pointer,"presence":"unavailable","reason":"original_body_is_not_json"})
        }
    }
}

pub fn differences(source: &[u8], target: &[u8], offset: usize) -> Value {
    let mut walk = Walk {
        offset,
        found: 0,
        nodes: 0,
        complete: true,
        values: Vec::new(),
    };
    let codec = match (parse(source), parse(target)) {
        (Some(source), Some(target)) => {
            walk.visit(Some(&source), Some(&target), "", 0);
            "json"
        }
        _ => {
            if source != target {
                walk.found = 1;
                if offset == 0 {
                    walk.values
                        .push(json!({"pointer":"", "kind":"bytes_mismatch",
                        "bytes":byte_difference(source, target)}));
                }
            }
            "bytes"
        }
    };
    json!({"codec":codec, "offset":offset, "page_size":PAGE_SIZE,
        "analysis_complete":walk.complete, "nodes_examined":walk.nodes,
        "node_limit":NODE_LIMIT, "differences_found":walk.found,
        "total_differences":walk.complete.then_some(walk.found),
        "returned_differences":walk.values.len(), "differences":walk.values,
        "next_offset":(offset.saturating_add(PAGE_SIZE) < walk.found)
            .then_some(offset.saturating_add(PAGE_SIZE))})
}

fn parse(bytes: &[u8]) -> Option<Value> {
    crate::json::parse_with_limit(bytes, 64 * 1024 * 1024)
}

struct Walk {
    offset: usize,
    found: usize,
    nodes: usize,
    complete: bool,
    values: Vec<Value>,
}

impl Walk {
    fn emit(&mut self, pointer: &str, kind: &str, source: Option<&Value>, target: Option<&Value>) {
        if self.found >= self.offset && self.values.len() < PAGE_SIZE {
            let mut value = json!({"pointer":pointer,"kind":kind,
                "source":preview(source),"target":preview(target)});
            if let (Some(Value::String(a)), Some(Value::String(b))) = (source, target) {
                value["string_difference"] = byte_difference(a.as_bytes(), b.as_bytes());
            }
            self.values.push(value);
        }
        self.found += 1;
    }

    fn visit(
        &mut self,
        source: Option<&Value>,
        target: Option<&Value>,
        pointer: &str,
        depth: usize,
    ) {
        if !self.complete {
            return;
        }
        if self.nodes == NODE_LIMIT || depth > DEPTH_LIMIT {
            self.complete = false;
            return;
        }
        self.nodes += 1;
        if source == target {
            return;
        }
        match (source, target) {
            (None, Some(_)) => self.emit(pointer, "unexpected_target", source, target),
            (Some(_), None) => self.emit(pointer, "missing_target", source, target),
            (Some(Value::Object(a)), Some(Value::Object(b))) => {
                for key in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
                    let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                    self.visit(a.get(key), b.get(key), &child, depth + 1);
                    if !self.complete {
                        break;
                    }
                }
            }
            (Some(Value::Array(a)), Some(Value::Array(b))) => {
                if a.len() != b.len() {
                    self.emit(pointer, "array_length_mismatch", source, target);
                } else if order_only(a, b) {
                    self.emit(pointer, "array_order_mismatch", source, target);
                }
                for index in 0..a.len().max(b.len()) {
                    self.visit(
                        a.get(index),
                        b.get(index),
                        &format!("{pointer}/{index}"),
                        depth + 1,
                    );
                    if !self.complete {
                        break;
                    }
                }
            }
            (Some(a), Some(b)) => self.emit(
                pointer,
                if kind(a) == kind(b) {
                    "value_mismatch"
                } else {
                    "type_mismatch"
                },
                source,
                target,
            ),
            _ => {}
        }
    }
}

fn order_only(source: &[Value], target: &[Value]) -> bool {
    // This hint is bounded independently of complete indexed array comparison.
    if source.len() > 1024 {
        return false;
    }
    let counts = |items: &[Value]| -> Option<BTreeMap<String, usize>> {
        let mut bytes = 0;
        let mut counts = BTreeMap::new();
        for value in items {
            let value = value.to_string();
            bytes += value.len();
            if bytes > 1024 * 1024 {
                return None;
            }
            *counts.entry(value).or_default() += 1;
        }
        Some(counts)
    };
    counts(source).is_some_and(|a| counts(target).is_some_and(|b| a == b))
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn preview(value: Option<&Value>) -> Value {
    let Some(value) = value else {
        return json!({"presence":"missing"});
    };
    let mut result = json!({"presence":"present", "type":kind(value)});
    match value {
        Value::Array(items) => result["length"] = json!(items.len()),
        Value::Object(items) => result["length"] = json!(items.len()),
        Value::String(text) if text.len() > 512 => {
            result["byte_length"] = json!(text.len());
            result["preview"] = context(text.as_bytes(), 0);
            result["truncated"] = json!(true);
        }
        _ => result["value"] = value.clone(),
    }
    result
}

pub(super) fn byte_difference(source: &[u8], target: &[u8]) -> Value {
    let start = source
        .iter()
        .zip(target)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = source[start..]
        .iter()
        .rev()
        .zip(target[start..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    json!({"first_different_byte":start,
        "source_range":{"start":start,"end":source.len()-suffix},
        "target_range":{"start":start,"end":target.len()-suffix},
        "source_context":context(source, start), "target_context":context(target, start)})
}

fn context(bytes: &[u8], offset: usize) -> Value {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let mut start = offset.saturating_sub(64);
    let mut end = offset.saturating_add(128).min(bytes.len());
    if let Ok(text) = std::str::from_utf8(bytes) {
        while !text.is_char_boundary(start) {
            start -= 1;
        }
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        json!({"offset":start,"encoding":"utf8","data":&text[start..end]})
    } else {
        json!({"offset":start,"encoding":"base64","data":STANDARD.encode(&bytes[start..end])})
    }
}

#[cfg(test)]
mod tests;
