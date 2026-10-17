use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use super::model::{ResponseAssertionCaseReport, ResponseDifference, ResponseDifferenceKind};
use crate::http::response_headers::{STANDARD_RESPONSE_HEADERS, X_REQUEST_ID};
use crate::recorder::HeaderMapSnapshot;
pub(in crate::replay) mod date;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderJwtCandidate {
    pub header: String,
    pub jwt_candidate: bool,
}

pub(super) fn compare_with_rules(
    expected: Option<&HeaderMapSnapshot>,
    actual: Option<&HeaderMapSnapshot>,
    expected_request: Option<&HeaderMapSnapshot>,
    actual_request: Option<&HeaderMapSnapshot>,
    rules: &crate::replay::policy::response_headers::ResponseHeaderRules,
    times: super::time::RequestTimes,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    compare_standard_headers(expected, actual, expected_request, actual_request, report)?;
    let matching = rules
        .iter()
        .filter(|(api, _)| crate::replay::policy::response_headers::matches(api, &report.path))
        .collect::<Vec<_>>();
    for (api, entries) in matching {
        let mut by_header = std::collections::BTreeMap::<String, Vec<_>>::new();
        for rule in entries {
            by_header
                .entry(rule.header.to_ascii_lowercase())
                .or_default()
                .push(rule.clone());
        }
        for (header, selected) in by_header {
            let ids = selected.iter().map(|rule| rule.id(api)).collect::<Vec<_>>();
            let values = expected
                .and_then(|headers| headers.get(&header))
                .zip(actual.and_then(|headers| headers.get(&header)));
            let valid = values.is_some_and(|(source, target)| {
                !source
                    .iter()
                    .chain(target)
                    .any(|value| value == "<redacted>")
                    && date::compare(source, target, &selected, times).unwrap_or(false)
            });
            if valid {
                report
                    .differences
                    .retain(|difference| difference.pointer != format!("$headers/{header}"));
                report.applied_header_rule_ids.extend(ids);
            } else {
                report.unused_applicable_header_rule_ids.extend(ids);
                if !report
                    .differences
                    .iter()
                    .any(|difference| difference.pointer == format!("$headers/{header}"))
                {
                    report.differences.push(ResponseDifference::header(
                        &header,
                        ResponseDifferenceKind::HeaderValueMismatch,
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn compare_standard_headers(
    expected: Option<&HeaderMapSnapshot>,
    actual: Option<&HeaderMapSnapshot>,
    expected_request: Option<&HeaderMapSnapshot>,
    actual_request: Option<&HeaderMapSnapshot>,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let (Some(expected), Some(actual)) = (expected, actual) else {
        // Older response artifacts did not retain headers. Their header
        // evidence is unavailable, so preserve their existing body/status
        // verdict instead of treating unavailable evidence as an empty map.
        return Ok(());
    };
    for name in STANDARD_RESPONSE_HEADERS {
        if name == X_REQUEST_ID {
            compare_x_request_id(expected, actual, expected_request, actual_request, report)?;
            continue;
        }
        let expected_values = expected.get(name);
        let actual_values = actual.get(name);
        match (expected_values, actual_values) {
            (None, None) => {}
            (Some(values), None) => {
                ensure_values_available(name, values, "expected")?;
                report.differences.push(ResponseDifference::header(
                    name,
                    ResponseDifferenceKind::HeaderMissingActual,
                ));
            }
            (None, Some(values)) => {
                ensure_values_available(name, values, "actual")?;
                report.differences.push(ResponseDifference::header(
                    name,
                    ResponseDifferenceKind::HeaderUnexpectedActual,
                ));
            }
            (Some(expected), Some(actual)) => {
                ensure_values_available(name, expected, "expected")?;
                ensure_values_available(name, actual, "actual")?;
                if canonical_values(name, expected) != canonical_values(name, actual) {
                    if expected
                        .iter()
                        .chain(actual)
                        .any(|value| crate::ResponseJwtRule::is_candidate(value))
                    {
                        report.header_jwt_candidates.push(HeaderJwtCandidate {
                            header: name.into(),
                            jwt_candidate: true,
                        });
                    }
                    report
                        .header_date_candidates
                        .extend(date::candidates(name, expected, actual));
                    report.differences.push(ResponseDifference::header(
                        name,
                        ResponseDifferenceKind::HeaderValueMismatch,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn compare_x_request_id(
    expected: &HeaderMapSnapshot,
    actual: &HeaderMapSnapshot,
    expected_request: Option<&HeaderMapSnapshot>,
    actual_request: Option<&HeaderMapSnapshot>,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let Some(expected_response_values) = expected.get(X_REQUEST_ID) else {
        // A target may introduce its own request ID even when the source does
        // not expose one. This contract is intentionally source-positive.
        return Ok(());
    };
    ensure_values_available(X_REQUEST_ID, expected_response_values, "expected")?;
    let Some(actual_response_values) = actual.get(X_REQUEST_ID) else {
        report.differences.push(ResponseDifference::header(
            X_REQUEST_ID,
            ResponseDifferenceKind::HeaderMissingActual,
        ));
        return Ok(());
    };
    ensure_values_available(X_REQUEST_ID, actual_response_values, "actual")?;

    let Some(expected_request) = expected_request else {
        return Ok(());
    };
    let source_echoes_request = match expected_request.get(X_REQUEST_ID) {
        Some(values) if request_values_available(values) => {
            canonical_scalar(expected_response_values) == canonical_scalar(values)
        }
        Some(_) => return Ok(()),
        None => false,
    };
    let matches = if source_echoes_request {
        let Some(actual_request) = actual_request else {
            return Ok(());
        };
        actual_request.get(X_REQUEST_ID).is_some_and(|values| {
            request_values_available(values)
                && canonical_scalar(actual_response_values) == canonical_scalar(values)
        })
    } else {
        canonical_lengths(expected_response_values) == canonical_lengths(actual_response_values)
    };
    if !matches {
        report.differences.push(ResponseDifference::header(
            X_REQUEST_ID,
            ResponseDifferenceKind::HeaderValueMismatch,
        ));
    }
    Ok(())
}

fn ensure_values_available(name: &str, values: &[String], side: &str) -> Result<()> {
    ensure!(
        !values.iter().any(|value| value == "<redacted>"),
        "{side} response header {name:?} is redacted and unavailable for standard comparison"
    );
    Ok(())
}

fn request_values_available(values: &[String]) -> bool {
    values
        .iter()
        .all(|value| value != "<redacted>" && !value.starts_with("traffic-e2e:enc:"))
}

fn canonical_lengths(values: &[String]) -> Vec<usize> {
    let mut lengths = values
        .iter()
        .map(|value| value.trim().len())
        .collect::<Vec<_>>();
    lengths.sort_unstable();
    lengths
}

fn canonical_values(name: &str, values: &[String]) -> Vec<String> {
    match name {
        "access-control-allow-headers"
        | "access-control-allow-methods"
        | "access-control-expose-headers"
        | "allow"
        | "vary" => canonical_token_set(values),
        "access-control-max-age" => canonical_delta_seconds(values),
        "cache-control" => canonical_cache_control(values),
        "content-disposition" | "content-type" => canonical_parameterized(values),
        "www-authenticate" => canonical_authenticate(values),
        _ => canonical_scalar(values),
    }
}

fn canonical_token_set(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| split_quoted(value, ','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical_delta_seconds(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| {
            let value = value.trim();
            value
                .parse::<u64>()
                .map_or_else(|_| value.to_string(), |seconds| seconds.to_string())
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn canonical_scalar(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn canonical_parameterized(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| {
            let mut parts = split_quoted(value, ';').into_iter();
            let main = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let mut parameters = parts
                .filter_map(|part| normalize_parameter(&part))
                .collect::<Vec<_>>();
            parameters.sort();
            if parameters.is_empty() {
                main
            } else {
                format!("{main};{}", parameters.join(";"))
            }
        })
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn normalize_parameter(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let Some((name, value)) = value.split_once('=') else {
        return Some(value.to_ascii_lowercase());
    };
    let name = name.trim().to_ascii_lowercase();
    let mut value = unquote(value.trim());
    if name == "charset" {
        value.make_ascii_lowercase();
    }
    Some(format!("{name}={value}"))
}

fn canonical_cache_control(values: &[String]) -> Vec<String> {
    let mut directives = values
        .iter()
        .flat_map(|value| split_quoted(value, ','))
        .filter_map(|directive| normalize_cache_directive(&directive))
        .collect::<Vec<_>>();
    directives.sort();
    directives
}

fn normalize_cache_directive(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let Some((name, value)) = value.split_once('=') else {
        return Some(value.to_ascii_lowercase());
    };
    let name = name.trim().to_ascii_lowercase();
    let value = unquote(value.trim());
    let value = value
        .parse::<u64>()
        .map_or(value.clone(), |number| number.to_string());
    Some(format!("{name}={value}"))
}

fn canonical_authenticate(values: &[String]) -> Vec<String> {
    let mut challenges = Vec::new();
    for value in values {
        let mut current: Option<(String, Vec<String>)> = None;
        for fragment in split_quoted(value, ',') {
            let fragment = fragment.trim();
            if fragment.is_empty() {
                continue;
            }
            if starts_auth_parameter(fragment)
                && let Some((_, parts)) = current.as_mut()
            {
                parts.push(fragment.to_string());
                continue;
            }
            if let Some(challenge) = current.take() {
                challenges.push(normalize_challenge(challenge));
            }
            let split = fragment.find(char::is_whitespace).unwrap_or(fragment.len());
            let scheme = fragment[..split].to_ascii_lowercase();
            let remainder = fragment[split..].trim();
            let parts = if remainder.is_empty() {
                Vec::new()
            } else {
                vec![remainder.to_string()]
            };
            current = Some((scheme, parts));
        }
        if let Some(challenge) = current {
            challenges.push(normalize_challenge(challenge));
        }
    }
    challenges.sort();
    challenges
}

fn starts_auth_parameter(value: &str) -> bool {
    let value = value.trim_start();
    let token_end = value
        .find(|character: char| character.is_whitespace() || character == '=')
        .unwrap_or(value.len());
    let Some(value) = value[token_end..].trim_start().strip_prefix('=') else {
        return false;
    };
    let value = value.trim_start();
    !value.is_empty() && !value.starts_with('=')
}

fn normalize_challenge((scheme, parts): (String, Vec<String>)) -> String {
    if parts.is_empty() {
        return scheme;
    }
    if parts.iter().all(|part| starts_auth_parameter(part)) {
        let mut parts = parts
            .iter()
            .filter_map(|part| normalize_parameter(part))
            .collect::<Vec<_>>();
        parts.sort();
        return format!("{scheme} {}", parts.join(","));
    }
    format!(
        "{scheme} {}",
        parts
            .iter()
            .map(|part| part.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn unquote(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return value.to_string();
    };
    let mut output = String::new();
    let mut escaped = false;
    for character in inner.chars() {
        if escaped {
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            output.push(character);
        }
    }
    if escaped {
        output.push('\\');
    }
    output
}

fn split_quoted(value: &str, delimiter: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            character if character == delimiter && !quoted => {
                parts.push(value[start..index].to_string());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].to_string());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_header_set_is_stable() {
        assert_eq!(STANDARD_RESPONSE_HEADERS.len(), 14);
        assert!(STANDARD_RESPONSE_HEADERS.is_sorted());
    }

    #[test]
    fn normalizes_list_parameter_and_directive_headers() {
        assert_eq!(
            canonical_values("vary", &["Origin, Accept-Encoding".into(), "origin".into()]),
            canonical_values("vary", &["accept-encoding, ORIGIN".into()])
        );
        assert_eq!(
            canonical_values(
                "content-type",
                &["Application/JSON; Charset=\"UTF-8\"; profile=v1".into()]
            ),
            canonical_values(
                "content-type",
                &["application/json;profile=v1;charset=utf-8".into()]
            )
        );
        assert_eq!(
            canonical_values("cache-control", &["max-age=060, private".into()]),
            canonical_values("cache-control", &["PRIVATE, MAX-AGE=60".into()])
        );
    }

    #[test]
    fn normalizes_auth_scheme_and_parameter_order() {
        assert_eq!(
            canonical_values(
                "www-authenticate",
                &["Bearer realm=\"api\", charset=\"UTF-8\"".into()]
            ),
            canonical_values(
                "www-authenticate",
                &["bearer charset=UTF-8, realm=api".into()]
            )
        );
        assert_ne!(
            canonical_values("www-authenticate", &["Basic abc==".into()]),
            canonical_values("www-authenticate", &["basic ABC==".into()])
        );
    }

    #[test]
    fn reports_presence_and_semantic_value_differences() {
        let mut expected = HeaderMapSnapshot::new();
        expected.insert("content-type".into(), vec!["application/json".into()]);
        expected.insert("vary".into(), vec!["Origin".into()]);
        let mut actual = HeaderMapSnapshot::new();
        actual.insert("vary".into(), vec!["Accept-Encoding".into()]);
        actual.insert("location".into(), vec!["/next".into()]);
        let mut report = ResponseAssertionCaseReport::new(
            "case".into(),
            "GET".into(),
            "/".into(),
            super::super::model::ResponseGatewayProtocol::Http,
            "request".into(),
            "policy".into(),
            "policy-fingerprint".into(),
            "expected".into(),
            "expected-fingerprint".into(),
            "actual".into(),
            "actual-fingerprint".into(),
        );

        compare_standard_headers(Some(&expected), Some(&actual), None, None, &mut report).unwrap();

        assert_eq!(report.differences.len(), 3);
        assert_eq!(
            report.differences[0].kind,
            ResponseDifferenceKind::HeaderMissingActual
        );
        assert_eq!(report.differences[0].pointer, "$headers/content-type");
        assert_eq!(
            report.differences[1].kind,
            ResponseDifferenceKind::HeaderUnexpectedActual
        );
        assert_eq!(report.differences[1].pointer, "$headers/location");
        assert_eq!(
            report.differences[2].kind,
            ResponseDifferenceKind::HeaderValueMismatch
        );
        assert_eq!(report.differences[2].pointer, "$headers/vary");
    }

    #[test]
    fn skips_unavailable_legacy_headers_and_rejects_redacted_values() {
        let mut report = ResponseAssertionCaseReport::new(
            "case".into(),
            "GET".into(),
            "/".into(),
            super::super::model::ResponseGatewayProtocol::Http,
            "request".into(),
            "policy".into(),
            "policy-fingerprint".into(),
            "expected".into(),
            "expected-fingerprint".into(),
            "actual".into(),
            "actual-fingerprint".into(),
        );
        compare_standard_headers(
            None,
            Some(&HeaderMapSnapshot::new()),
            None,
            None,
            &mut report,
        )
        .unwrap();
        assert!(report.differences.is_empty());

        let expected =
            HeaderMapSnapshot::from([("www-authenticate".into(), vec!["<redacted>".into()])]);
        assert!(
            compare_standard_headers(
                Some(&expected),
                Some(&HeaderMapSnapshot::new()),
                None,
                None,
                &mut report
            )
            .unwrap_err()
            .to_string()
            .contains("redacted")
        );
    }

    #[test]
    fn x_request_id_is_source_positive_and_preserves_echo_behavior() {
        let expected_response = HeaderMapSnapshot::new();
        let actual_response =
            HeaderMapSnapshot::from([(X_REQUEST_ID.into(), vec!["target-generated".into()])]);
        let mut report = new_report();
        compare_standard_headers(
            Some(&expected_response),
            Some(&actual_response),
            Some(&HeaderMapSnapshot::new()),
            Some(&HeaderMapSnapshot::new()),
            &mut report,
        )
        .unwrap();
        assert!(report.differences.is_empty());

        let expected_response = x_request_id("source-request-id");
        let expected_request = x_request_id("source-request-id");
        let actual_response = x_request_id("target-request-id");
        let actual_request = x_request_id("target-request-id");
        compare_standard_headers(
            Some(&expected_response),
            Some(&actual_response),
            Some(&expected_request),
            Some(&actual_request),
            &mut report,
        )
        .unwrap();
        assert!(report.differences.is_empty());

        let wrong_actual_response = x_request_id("not-the-target-id");
        compare_standard_headers(
            Some(&expected_response),
            Some(&wrong_actual_response),
            Some(&expected_request),
            Some(&actual_request),
            &mut report,
        )
        .unwrap();
        assert_eq!(
            report.differences.last().unwrap().kind,
            ResponseDifferenceKind::HeaderValueMismatch
        );
    }

    #[test]
    fn x_request_id_generated_values_compare_trimmed_byte_lengths() {
        let expected_response = x_request_id("source-generated-01");
        let expected_request = x_request_id("incoming-id");
        let mut report = new_report();
        compare_standard_headers(
            Some(&expected_response),
            Some(&x_request_id("target-generated-99")),
            Some(&expected_request),
            Some(&x_request_id("another-incoming-id")),
            &mut report,
        )
        .unwrap();
        assert!(report.differences.is_empty());

        compare_standard_headers(
            Some(&expected_response),
            Some(&x_request_id("short")),
            Some(&expected_request),
            Some(&x_request_id("another-incoming-id")),
            &mut report,
        )
        .unwrap();
        assert_eq!(
            report.differences.last().unwrap().kind,
            ResponseDifferenceKind::HeaderValueMismatch
        );

        let mut missing_report = new_report();
        compare_standard_headers(
            Some(&expected_response),
            Some(&HeaderMapSnapshot::new()),
            Some(&expected_request),
            Some(&HeaderMapSnapshot::new()),
            &mut missing_report,
        )
        .unwrap();
        assert_eq!(
            missing_report.differences[0].kind,
            ResponseDifferenceKind::HeaderMissingActual
        );
    }

    fn x_request_id(value: &str) -> HeaderMapSnapshot {
        HeaderMapSnapshot::from([(X_REQUEST_ID.into(), vec![value.into()])])
    }

    fn new_report() -> ResponseAssertionCaseReport {
        ResponseAssertionCaseReport::new(
            "case".into(),
            "GET".into(),
            "/".into(),
            super::super::model::ResponseGatewayProtocol::Http,
            "request".into(),
            "policy".into(),
            "policy-fingerprint".into(),
            "expected".into(),
            "expected-fingerprint".into(),
            "actual".into(),
            "actual-fingerprint".into(),
        )
    }
}
