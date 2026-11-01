use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::joined_string;
use super::model::{
    JsonJoinedStringCandidate, ResponseAssertionCaseReport, ResponseDifference,
    ResponseDifferenceKind,
};
use super::time;
use crate::replay::policy::{ResponseField, ResponseRuleKind, select_json_pointers};
use crate::value_contract::json::AnchorClocks;

pub(super) fn compare_json(
    expected: &Value,
    actual: &Value,
    fields: &[ResponseField],
    report: &mut ResponseAssertionCaseReport,
    clocks: AnchorClocks,
) -> Vec<ResponseField> {
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
                        crate::replay::policy::ResponseJwtRule::concrete_pointer(
                            companion, &pointer,
                        ),
                        field,
                    );
                }
            }
            selected.insert(pointer, field);
        }
    }
    let mut jwt = super::jwt::JwtComparison::load(
        fields,
        std::path::Path::new(&report.policy_path),
        std::path::Path::new(&report.request_path),
        expected,
        actual,
    );
    compare_value("", expected, actual, &selected, report, clocks, &mut jwt);
    for ids in [
        &mut report.applied_generated_rule_ids,
        &mut report.applied_unordered_rule_ids,
        &mut report.applied_unordered_joined_string_rule_ids,
    ] {
        let mut seen = BTreeSet::new();
        ids.retain(|id| seen.insert(id.clone()));
    }
    applicable
}

fn compare_value(
    pointer: &str,
    expected: &Value,
    actual: &Value,
    fields: &BTreeMap<String, &ResponseField>,
    report: &mut ResponseAssertionCaseReport,
    clocks: AnchorClocks,
    jwt: &mut super::jwt::JwtComparison<'_>,
) {
    if let Some(field) = fields.get(pointer) {
        match field.kind {
            ResponseRuleKind::Jwt => match jwt.compare(field, pointer, clocks.case) {
                Ok(()) => report.applied_generated_rule_ids.push(field.id.clone()),
                Err(kind) => {
                    report
                        .differences
                        .push(difference(pointer, kind, Some(expected), Some(actual)))
                }
            },
            ResponseRuleKind::Timestamp | ResponseRuleKind::Duration => {
                match time::compare(
                    field.time.expect("validated time rule"),
                    expected,
                    actual,
                    clocks.observation(),
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
                if scalar_kind(expected).is_some() && scalar_kind(expected) == scalar_kind(actual) {
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
            ResponseRuleKind::UnorderedJoinedString => match (expected, actual) {
                (Value::String(expected), Value::String(actual))
                    if joined_string::equal(
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
                        compare_value(&child, expected, actual, fields, report, clocks, jwt)
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
                    clocks,
                    jwt,
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
                joined_string::matching_discovery_separators(expected, actual)
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
