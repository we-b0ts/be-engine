use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::joined_string;
use super::model::{JsonJoinedStringCandidate, ResponseDifference, ResponseDifferenceKind};
use super::time;
use traffic_contract::compare::AnchorClocks;
use traffic_policy_schema::response::{ResponseField, ResponseRuleKind, select_json_pointers};

pub fn compare_json(
    policies: &traffic_policy::PolicyRegistry,
    expected: &Value,
    actual: &Value,
    fields: &[ResponseField],
    clocks: AnchorClocks,
    jwt: &mut dyn JwtVerifier,
) -> (Vec<ResponseField>, JsonComparison) {
    let mut report = JsonComparison::default();
    let mut selected = BTreeMap::new();
    let mut applicable = Vec::new();
    for field in fields {
        let pointers = select_json_pointers(&field.pointer, expected, actual);
        if !pointers.is_empty() {
            applicable.push(field.clone());
        }
        for pointer in pointers {
            if let Some(rule) = &field.jwt {
                for companion in rule.companion_pointers() {
                    selected.insert(
                        traffic_policy_schema::response::ResponseJwtRule::concrete_pointer(
                            companion, &pointer,
                        ),
                        field,
                    );
                }
            }
            selected.insert(pointer, field);
        }
    }
    Comparator {
        policies,
        fields: &selected,
        clocks,
        jwt,
    }
    .compare_value("", expected, actual, &mut report);
    for ids in [
        &mut report.applied_generated_rule_ids,
        &mut report.applied_unordered_rule_ids,
        &mut report.applied_unordered_joined_string_rule_ids,
    ] {
        let mut seen = BTreeSet::new();
        ids.retain(|id| seen.insert(id.clone()));
    }
    (applicable, report)
}

struct Comparator<'a> {
    policies: &'a traffic_policy::PolicyRegistry,
    fields: &'a BTreeMap<String, &'a ResponseField>,
    clocks: AnchorClocks,
    jwt: &'a mut dyn JwtVerifier,
}
impl Comparator<'_> {
    fn compare_value(
        &mut self,
        pointer: &str,
        expected: &Value,
        actual: &Value,
        report: &mut JsonComparison,
    ) {
        if let Some(field) = self.fields.get(pointer) {
            match field.kind {
                ResponseRuleKind::Jwt => match self.jwt.compare(field, pointer, self.clocks.case) {
                    Ok(()) => report.applied_generated_rule_ids.push(field.id.clone()),
                    Err(kind) => report.differences.push(difference(
                        pointer,
                        kind,
                        Some(expected),
                        Some(actual),
                    )),
                },
                ResponseRuleKind::Timestamp | ResponseRuleKind::Duration => {
                    match time::compare(
                        self.policies,
                        field.time.expect("validated time rule"),
                        expected,
                        actual,
                        self.clocks.observation(),
                    ) {
                        Ok(()) => report.applied_generated_rule_ids.push(field.id.clone()),
                        Err(kind) => report.differences.push(difference(
                            pointer,
                            kind,
                            Some(expected),
                            Some(actual),
                        )),
                    }
                }
                kind if kind.is_generated() => {
                    if scalar_kind(expected).is_some()
                        && scalar_kind(expected) == scalar_kind(actual)
                    {
                        report.applied_generated_rule_ids.push(field.id.clone());
                    } else {
                        report.differences.push(difference(
                            pointer,
                            ResponseDifferenceKind::GeneratedFieldNotScalar,
                            Some(expected),
                            Some(actual),
                        ));
                    }
                }
                ResponseRuleKind::Unordered => match (expected, actual) {
                    (Value::Array(expected), Value::Array(actual))
                        if unordered_arrays_equal(self.policies, expected, actual) =>
                    {
                        report.applied_unordered_rule_ids.push(field.id.clone());
                    }
                    (Value::Array(_), Value::Array(_)) => {
                        report.differences.push(difference(
                            pointer,
                            ResponseDifferenceKind::UnorderedArrayContentMismatch,
                            Some(expected),
                            Some(actual),
                        ));
                    }
                    _ => {
                        report.differences.push(difference(
                            pointer,
                            ResponseDifferenceKind::UnorderedFieldNotArray,
                            Some(expected),
                            Some(actual),
                        ));
                    }
                },
                ResponseRuleKind::UnorderedJoinedString => match (expected, actual) {
                    (Value::String(expected), Value::String(actual))
                        if joined_string::equal(
                            self.policies,
                            expected,
                            actual,
                            field
                                .separator
                                .as_deref()
                                .expect("joined-string response field has a separator"),
                        ) =>
                    {
                        report
                            .applied_unordered_joined_string_rule_ids
                            .push(field.id.clone());
                    }
                    (Value::String(_), Value::String(_)) => {
                        report.differences.push(difference(
                            pointer,
                            ResponseDifferenceKind::UnorderedJoinedStringContentMismatch,
                            Some(expected),
                            Some(actual),
                        ));
                    }
                    _ => {
                        report.differences.push(difference(
                            pointer,
                            ResponseDifferenceKind::UnorderedJoinedStringFieldNotString,
                            Some(expected),
                            Some(actual),
                        ));
                    }
                },
                _ => unreachable!("all response rule kinds are covered"),
            }
            return;
        }
        match (expected, actual) {
            (Value::Object(expected), Value::Object(actual)) => {
                let keys = expected
                    .keys()
                    .chain(actual.keys())
                    .collect::<BTreeSet<_>>();
                for key in keys {
                    let child = child_pointer(pointer, key);
                    match (expected.get(key), actual.get(key)) {
                        (Some(expected), Some(actual)) => {
                            self.compare_value(&child, expected, actual, report)
                        }
                        (Some(expected), None) => report.differences.push(difference(
                            &child,
                            ResponseDifferenceKind::MissingActual,
                            Some(expected),
                            None,
                        )),
                        (None, Some(actual)) => report.differences.push(difference(
                            &child,
                            ResponseDifferenceKind::UnexpectedActual,
                            None,
                            Some(actual),
                        )),
                        (None, None) => unreachable!(),
                    }
                }
            }
            (Value::Array(expected), Value::Array(actual)) => {
                if expected != actual && unordered_arrays_equal(self.policies, expected, actual) {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::ArrayOrderMismatch,
                        Some(&Value::Array(expected.clone())),
                        Some(&Value::Array(actual.clone())),
                    ));
                    return;
                }
                if expected.len() != actual.len() {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::ArrayLengthMismatch,
                        Some(&Value::Array(expected.clone())),
                        Some(&Value::Array(actual.clone())),
                    ));
                }
                for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                    self.compare_value(
                        &child_pointer(pointer, &index.to_string()),
                        expected,
                        actual,
                        report,
                    );
                }
            }
            _ if json_kind(expected) != json_kind(actual) => report.differences.push(difference(
                pointer,
                ResponseDifferenceKind::TypeMismatch,
                Some(expected),
                Some(actual),
            )),
            (Value::String(expected), Value::String(actual)) if expected != actual => {
                report.unordered_joined_string_candidates.extend(
                    joined_string::matching_discovery_separators(self.policies, expected, actual)
                        .into_iter()
                        .map(|separator| JsonJoinedStringCandidate {
                            pointer: pointer.to_string(),
                            separator,
                        }),
                );
                report.differences.push(difference(
                    pointer,
                    ResponseDifferenceKind::ValueMismatch,
                    Some(&Value::String(expected.clone())),
                    Some(&Value::String(actual.clone())),
                ));
            }
            _ if expected != actual => report.differences.push(difference(
                pointer,
                ResponseDifferenceKind::ValueMismatch,
                Some(expected),
                Some(actual),
            )),
            _ => {}
        }
    }
}

fn unordered_arrays_equal(
    policies: &traffic_policy::PolicyRegistry,
    expected: &[Value],
    actual: &[Value],
) -> bool {
    let compare = || -> anyhow::Result<bool> {
        let policy = policies.prepare("unordered", &traffic_value::Value::Null)?;
        Ok(policy
            .evaluate(
                &traffic_policy::ValuePair {
                    source: &serde_json::from_value(Value::Array(expected.to_vec()))?,
                    target: &serde_json::from_value(Value::Array(actual.to_vec()))?,
                    source_path: "",
                    target_path: "",
                },
                &mut (),
            )?
            .passed())
    };
    compare().unwrap_or(false)
}

fn difference(
    pointer: &str,
    kind: ResponseDifferenceKind,
    expected: Option<&Value>,
    actual: Option<&Value>,
) -> ResponseDifference {
    ResponseDifference {
        pointer: pointer.to_string(),
        kind,
        expected_type: expected.map(json_kind).map(str::to_string),
        actual_type: actual.map(json_kind).map(str::to_string),
        expected_status: None,
        actual_status: None,
    }
}

fn child_pointer(parent: &str, token: &str) -> String {
    let token = token.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{token}")
}

fn scalar_kind(value: &Value) -> Option<&'static str> {
    match value {
        Value::Bool(_) => Some("boolean"),
        Value::Number(_) => Some("number"),
        Value::String(_) => Some("string"),
        _ => None,
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[derive(Default)]
pub struct JsonComparison {
    pub differences: Vec<ResponseDifference>,
    pub applied_generated_rule_ids: Vec<String>,
    pub applied_unordered_rule_ids: Vec<String>,
    pub applied_unordered_joined_string_rule_ids: Vec<String>,
    pub unordered_joined_string_candidates: Vec<JsonJoinedStringCandidate>,
}
pub trait JwtVerifier {
    fn compare(
        &mut self,
        field: &ResponseField,
        pointer: &str,
        times: crate::time::RequestTimes,
    ) -> Result<(), ResponseDifferenceKind>;
}
