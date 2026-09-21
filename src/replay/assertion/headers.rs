use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use super::model::{ResponseAssertionCaseReport, ResponseDifference, ResponseDifferenceKind};
use crate::http::response_headers::STANDARD_RESPONSE_HEADERS;
use crate::recorder::HeaderMapSnapshot;

pub(super) fn compare_standard_headers(
    expected: Option<&HeaderMapSnapshot>,
    actual: Option<&HeaderMapSnapshot>,
    report: &mut ResponseAssertionCaseReport,
) -> Result<()> {
    let (Some(expected), Some(actual)) = (expected, actual) else {
        // Older response artifacts did not retain headers. Their header
        // evidence is unavailable, so preserve their existing body/status
        // verdict instead of treating unavailable evidence as an empty map.
        return Ok(());
    };
    for name in STANDARD_RESPONSE_HEADERS {
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

fn ensure_values_available(name: &str, values: &[String], side: &str) -> Result<()> {
    ensure!(
        !values.iter().any(|value| value == "<redacted>"),
        "{side} response header {name:?} is redacted and unavailable for standard comparison"
    );
    Ok(())
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
        assert_eq!(STANDARD_RESPONSE_HEADERS.len(), 13);
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

        compare_standard_headers(Some(&expected), Some(&actual), &mut report).unwrap();

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
        compare_standard_headers(None, Some(&HeaderMapSnapshot::new()), &mut report).unwrap();
        assert!(report.differences.is_empty());

        let expected =
            HeaderMapSnapshot::from([("www-authenticate".into(), vec!["<redacted>".into()])]);
        assert!(
            compare_standard_headers(
                Some(&expected),
                Some(&HeaderMapSnapshot::new()),
                &mut report
            )
            .unwrap_err()
            .to_string()
            .contains("redacted")
        );
    }
}
