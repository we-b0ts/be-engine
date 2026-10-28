//! Source request predicates for dependency contracts; retain only matching rule IDs at runtime.
use anyhow::{Result, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseCondition {
    pub request_body_json: BTreeMap<String, JsonCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "JsonConditionDocument", into = "JsonConditionDocument")]
pub enum JsonCondition {
    Equals(Value),
    NotEquals(Value),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum JsonConditionDocument {
    Equals { equals: Value },
    NotEquals { not_equals: Value },
}

impl From<JsonConditionDocument> for JsonCondition {
    fn from(value: JsonConditionDocument) -> Self {
        match value {
            JsonConditionDocument::Equals { equals } => Self::Equals(equals),
            JsonConditionDocument::NotEquals { not_equals } => Self::NotEquals(not_equals),
        }
    }
}

impl From<JsonCondition> for JsonConditionDocument {
    fn from(value: JsonCondition) -> Self {
        match value {
            JsonCondition::Equals(equals) => Self::Equals { equals },
            JsonCondition::NotEquals(not_equals) => Self::NotEquals { not_equals },
        }
    }
}

impl CaseCondition {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16).contains(&self.request_body_json.len()),
            "request body conditions require 1..16 fields"
        );
        for (pointer, condition) in &self.request_body_json {
            super::response::validate_json_pointer(pointer)?;
            ensure!(
                !pointer.is_empty() && !pointer.split('/').any(|part| part == "*"),
                "request body conditions require exact non-root JSON pointers"
            );
            let value = condition.value();
            ensure!(
                value.is_boolean()
                    || value.is_number()
                    || value.as_str().is_some_and(|s| s.len() <= 1024),
                "request body conditions require non-null scalar values"
            );
        }
        Ok(())
    }

    pub(crate) fn matches_request(&self, request: &Value) -> bool {
        let Some(body) = request_body(request) else {
            return false;
        };
        self.matches_body(&body)
    }

    fn matches_body(&self, body: &Value) -> bool {
        self.request_body_json.iter().all(|(pointer, condition)| {
            body.pointer(pointer).is_some_and(|actual| {
                let expected = condition.value();
                let same_type = actual.is_string() && expected.is_string()
                    || actual.is_number() && expected.is_number()
                    || actual.is_boolean() && expected.is_boolean();
                same_type
                    && match condition {
                        JsonCondition::Equals(_) => actual == expected,
                        JsonCondition::NotEquals(_) => actual != expected,
                    }
            })
        })
    }
}

/// Parse each Source body once, then discard it after projecting the eligible IDs.
pub(in crate::replay::policy) fn matching_rule_ids<'a>(
    request: &Value,
    rules: impl Iterator<Item = (&'a str, &'a CaseCondition)>,
) -> BTreeSet<String> {
    let mut rules = rules.peekable();
    if rules.peek().is_none() {
        return BTreeSet::new();
    }
    let Some(body) = request_body(request) else {
        return BTreeSet::new();
    };
    rules
        .filter(|(_, condition)| condition.matches_body(&body))
        .map(|(id, _)| id.into())
        .collect()
}

impl JsonCondition {
    fn value(&self) -> &Value {
        match self {
            Self::Equals(value) | Self::NotEquals(value) => value,
        }
    }
}

/// Absence, malformed JSON and type mismatches never satisfy either operator.
pub(in crate::replay) fn request_body(request: &Value) -> Option<Value> {
    let body = &request["body"];
    if body.get("truncated").is_some_and(|v| v != false)
        || body.get("decode_error").is_some_and(|v| !v.is_null())
    {
        return None;
    }
    let data = body["data"].as_str()?;
    if data.len() > crate::value_limits::MAX_VALUE_BYTES.div_ceil(3) * 4 {
        return None;
    }
    let bytes = match body["encoding"].as_str()? {
        "utf8" => data.as_bytes().to_vec(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(data)
            .ok()?,
        _ => return None,
    };
    crate::json_value::parse(&bytes)
}

/// Only prove disjointness from a shared exact pointer; otherwise stay conservative.
pub(in crate::replay::policy) fn overlaps(
    left: Option<&CaseCondition>,
    right: Option<&CaseCondition>,
) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return true;
    };
    !left.request_body_json.iter().any(|(pointer, a)| {
        let Some(b) = right.request_body_json.get(pointer) else {
            return false;
        };
        match (a, b) {
            (JsonCondition::Equals(a), JsonCondition::Equals(b)) => a != b,
            (JsonCondition::Equals(a), JsonCondition::NotEquals(b))
            | (JsonCondition::NotEquals(b), JsonCondition::Equals(a)) => a == b,
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests;
