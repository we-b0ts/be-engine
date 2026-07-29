use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::model::{ResponseAssertionCaseReport, ResponseDifference, ResponseDifferenceKind};
use crate::replay::policy::{ResponseField, ResponseRuleKind};

pub(super) fn compare_json(
    expected: &Value,
    actual: &Value,
    fields: &[ResponseField],
    report: &mut ResponseAssertionCaseReport,
) {
    let fields = fields
        .iter()
        .map(|field| (field.pointer.as_str(), field))
        .collect::<BTreeMap<_, _>>();
    compare_value("", expected, actual, &fields, report);
}

fn compare_value(
    pointer: &str,
    expected: &Value,
    actual: &Value,
    fields: &BTreeMap<&str, &ResponseField>,
    report: &mut ResponseAssertionCaseReport,
) {
    if let Some(field) = fields.get(pointer) {
        match field.kind {
            ResponseRuleKind::Dynamic => {
                if scalar_kind(expected).is_some() && scalar_kind(expected) == scalar_kind(actual) {
                    report.applied_dynamic_rule_ids.push(field.id.clone());
                } else {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::DynamicFieldNotScalar,
                        Some(expected),
                        Some(actual),
                    ));
                }
            }
            ResponseRuleKind::Unordered => match (expected, actual) {
                (Value::Array(expected), Value::Array(actual))
                    if unordered_arrays_equal(expected, actual) =>
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
            ResponseRuleKind::Counter => match (expected, actual) {
                (Value::Number(_), Value::Number(_)) => {
                    report.applied_counter_rule_ids.push(field.id.clone());
                }
                (Value::String(expected), Value::String(actual))
                    if expected.is_empty() == actual.is_empty() =>
                {
                    report.applied_counter_rule_ids.push(field.id.clone());
                }
                _ if json_kind(expected) != json_kind(actual) => {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::TypeMismatch,
                        Some(expected),
                        Some(actual),
                    ));
                }
                (Value::String(_), Value::String(_)) => {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::ValueMismatch,
                        Some(expected),
                        Some(actual),
                    ));
                }
                _ => {
                    report.differences.push(difference(
                        pointer,
                        ResponseDifferenceKind::CounterFieldUnsupportedType,
                        Some(expected),
                        Some(actual),
                    ));
                }
            },
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
                        compare_value(&child, expected, actual, fields, report)
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
            if expected != actual && unordered_arrays_equal(expected, actual) {
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
                compare_value(
                    &child_pointer(pointer, &index.to_string()),
                    expected,
                    actual,
                    fields,
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
        _ if expected != actual => report.differences.push(difference(
            pointer,
            ResponseDifferenceKind::ValueMismatch,
            Some(expected),
            Some(actual),
        )),
        _ => {}
    }
}

fn unordered_arrays_equal(expected: &[Value], actual: &[Value]) -> bool {
    if expected == actual {
        return true;
    }
    if expected.len() != actual.len() {
        return false;
    }
    let mut matched = vec![false; actual.len()];
    expected.iter().all(|expected| {
        actual
            .iter()
            .enumerate()
            .find(|(index, actual)| !matched[*index] && expected == *actual)
            .is_some_and(|(index, _)| {
                matched[index] = true;
                true
            })
    })
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
