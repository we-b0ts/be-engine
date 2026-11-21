//! Bounded differences over codec-projected logical values and original byte ranges.
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};
use traffic_value::Value;
const PAGE_SIZE: usize = 20;
const NODE_LIMIT: usize = 1_000_000;
const DEPTH_LIMIT: usize = 128;

pub fn at_pointer(source: &Value, target: &Value, pointer: &str) -> Json {
    let source = source.pointer(pointer);
    let target = target.pointer(pointer);
    let mut result = json!({"pointer":pointer,"source":preview(source),"target":preview(target),
        "origin":"original_body_values_at_runtime_failure_pointer"});
    if let (Some(Value::String(source)), Some(Value::String(target))) = (source, target)
        && source != target
    {
        result["string_difference"] = byte_difference(source.as_bytes(), target.as_bytes());
    }
    if let (Some(Value::Bytes(source)), Some(Value::Bytes(target))) = (source, target)
        && source != target
    {
        result["bytes"] = byte_difference(source, target);
    }
    result
}

pub fn differences(source: &Value, target: &Value, codec: &str, offset: usize) -> Json {
    if let (Value::Bytes(source), Value::Bytes(target)) = (source, target) {
        return byte_differences(source, target, codec, offset);
    }
    let mut walk = Walk::new(offset);
    walk.visit(Some(source), Some(target), "", 0);
    report(codec, walk)
}

pub fn byte_differences(source: &[u8], target: &[u8], codec: &str, offset: usize) -> Json {
    let mut walk = Walk::new(offset);
    if source != target {
        walk.found = 1;
        if offset == 0 {
            walk.values
                .push(json!({"pointer":"", "kind":"bytes_mismatch",
                "bytes":byte_difference(source, target)}));
        }
    }
    report(codec, walk)
}

fn report(codec: &str, walk: Walk) -> Json {
    json!({"codec":codec, "offset":walk.offset, "page_size":PAGE_SIZE,
        "analysis_complete":walk.complete, "nodes_examined":walk.nodes,
        "node_limit":NODE_LIMIT, "differences_found":walk.found,
        "total_differences":walk.complete.then_some(walk.found),
        "returned_differences":walk.values.len(), "differences":walk.values,
        "next_offset":(walk.offset.saturating_add(PAGE_SIZE) < walk.found)
            .then_some(walk.offset.saturating_add(PAGE_SIZE))})
}
struct Walk {
    offset: usize,
    found: usize,
    nodes: usize,
    complete: bool,
    values: Vec<Json>,
}

impl Walk {
    fn new(offset: usize) -> Self {
        Self {
            offset,
            found: 0,
            nodes: 0,
            complete: true,
            values: Vec::new(),
        }
    }

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
            (Some(Value::Bytes(a)), Some(Value::Bytes(b))) => {
                self.emit(pointer, "bytes_mismatch", source, target);
                if let Some(value) = self
                    .values
                    .last_mut()
                    .filter(|value| value["pointer"] == pointer)
                {
                    value["bytes"] = byte_difference(a, b);
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
    let mut remaining: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    let mut bytes = 0;
    for value in target {
        let Ok(key) = serde_json::to_string(value) else {
            return false;
        };
        bytes += key.len();
        if bytes > 1024 * 1024 {
            return false;
        }
        remaining.entry(key).or_default().push(value);
    }
    bytes = 0;
    for value in source {
        let Ok(key) = serde_json::to_string(value) else {
            return false;
        };
        bytes += key.len();
        if bytes > 1024 * 1024 {
            return false;
        }
        let Some(candidates) = remaining.get_mut(&key) else {
            return false;
        };
        // The serialized key is only a partition. Native bytes, arrays and
        // numeric categories can share that spelling and still differ.
        let Some(index) = candidates.iter().position(|candidate| *candidate == value) else {
            return false;
        };
        candidates.swap_remove(index);
    }
    true
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Bytes(_) => "bytes",
    }
}

fn preview(value: Option<&Value>) -> Json {
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
        Value::Bytes(bytes) => {
            result["byte_length"] = json!(bytes.len());
            result["preview"] = context(bytes, 0);
        }
        Value::Number(number) => {
            result["value"] = serde_json::to_value(number).expect("logical numbers serialize");
            result["representation"] = match number {
                traffic_value::Number::Signed(_) => "signed",
                traffic_value::Number::Unsigned(_) => "unsigned",
                traffic_value::Number::Float(_) => "float",
            }
            .into();
        }
        _ => result["value"] = serde_json::to_value(value).expect("logical values serialize"),
    }
    result
}

pub fn byte_difference(source: &[u8], target: &[u8]) -> Json {
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

fn context(bytes: &[u8], offset: usize) -> Json {
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
