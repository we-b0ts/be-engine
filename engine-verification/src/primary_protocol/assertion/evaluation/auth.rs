//! Optional authentication comparison for primary responses.
use serde_json::Value;
use traffic_contract::compare::{AnchorClocks, LeafObservations};
use traffic_policy_value::auth::{Carrier, Matcher};

use crate::protocols::recording::events::HeaderMapSnapshot;

use super::{ResponseAssertionCaseReport, ResponseDifference, ResponseDifferenceKind};

pub(super) fn body_matches(
    matcher: &Matcher,
    source: Value,
    target: &[u8],
    clocks: AnchorClocks,
) -> bool {
    fn plausible(matcher: &Matcher, value: &Value) -> bool {
        match value {
            Value::String(value) => matcher.may_recognize_value(value),
            Value::Array(values) => values.iter().any(|value| plausible(matcher, value)),
            Value::Object(values) => values.values().any(|value| plausible(matcher, value)),
            _ => false,
        }
    }

    if !plausible(matcher, &source) {
        return false;
    }
    let Some(target) = crate::json_value::parse(target) else {
        return false;
    };
    let (Ok(source), Ok(target)) = (
        serde_json::from_value(source),
        serde_json::from_value(target),
    ) else {
        return false;
    };
    !matcher
        .matching_string_paths(&source, &target, clocks)
        .is_empty()
}

pub(super) fn compare_headers(
    source: Option<&HeaderMapSnapshot>,
    target: Option<&HeaderMapSnapshot>,
    report: &mut ResponseAssertionCaseReport,
    is_declared: impl Fn(&str, &str) -> bool,
    recognizes_authorization: impl Fn(&str) -> bool,
    compare: impl Fn(&str, &str, Carrier) -> Option<LeafObservations>,
) {
    let (Some(source), Some(target)) = (source, target) else {
        return;
    };
    for (name, carrier) in [
        ("authorization", Carrier::Authorization),
        ("location", Carrier::Value),
    ] {
        if is_declared(name, &report.path) {
            continue;
        }
        let value_mismatch = |difference: &ResponseDifference| {
            difference.pointer.strip_prefix("$headers/") == Some(name)
                && difference.kind == ResponseDifferenceKind::HeaderValueMismatch
        };
        if name == "location" && !report.differences.iter().any(value_mismatch) {
            continue;
        }
        let source = header_values(source, name);
        let target = header_values(target, name);
        // Older standalone Target artifacts only contain standard response
        // headers. Compare Authorization when both snapshots supply evidence.
        if source.clone().next().is_none()
            || target.clone().next().is_none()
            || source.clone().eq(target.clone())
            || source.clone().any(is_protected)
        {
            continue;
        }
        // Authorization is outside the standard response headers. Only an
        // authenticated Source value can establish an inferred comparison.
        if name == "authorization" && !source.clone().any(&recognizes_authorization) {
            continue;
        }
        let matched = single(source)
            .zip(single(target))
            .and_then(|(source, target)| {
                if is_protected(target) || (name == "location" && !source.contains('?')) {
                    return None;
                }
                compare(source, target, carrier)
            });
        if let Some(observations) = matched {
            report
                .differences
                .retain(|difference| !value_mismatch(difference));
            report.identity_pairs.extend(observations.identities);
        } else if name == "authorization" {
            report.differences.push(ResponseDifference::header(
                name,
                ResponseDifferenceKind::HeaderValueMismatch,
            ));
        }
    }
}

fn header_values<'a>(
    headers: &'a HeaderMapSnapshot,
    name: &'static str,
) -> impl Iterator<Item = &'a str> + Clone {
    headers
        .iter()
        .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
        .flat_map(|(_, values)| values.iter().map(String::as_str))
}

fn single<'a>(mut values: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn is_protected(value: &str) -> bool {
    value == "<redacted>" || value.starts_with("traffic-e2e:enc:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primary_protocol::assertion::ResponseGatewayProtocol;

    #[test]
    fn inferred_body_comparison_requires_a_matching_credential() {
        let source_url = |date: &str, signature: char| {
            let signature = signature.to_string().repeat(64);
            format!(
                "/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date={date}T010000Z&X-Amz-Credential=access%2F{date}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature={signature}"
            )
        };
        let source = serde_json::json!({"content": source_url("20261126", 'a')});
        let target = serde_json::json!({"content": source_url("20261127", 'b')});
        let times = traffic_contract::time::ClockPair {
            source: Some("2026-11-26T01:00:00Z".parse().unwrap()),
            target: Some("2026-11-27T01:00:00Z".parse().unwrap()),
        };
        let clocks = AnchorClocks::for_response(times, times);
        let matcher = Matcher::default();
        assert!(body_matches(
            &matcher,
            source.clone(),
            &serde_json::to_vec(&target).unwrap(),
            clocks,
        ));
        assert!(!body_matches(
            &matcher,
            source,
            br#"{"content":"http://example.com/?credentials=unknown"}"#,
            clocks,
        ));
    }

    fn report() -> ResponseAssertionCaseReport {
        ResponseAssertionCaseReport::new(
            "case".into(),
            "GET".into(),
            "/redirect".into(),
            ResponseGatewayProtocol::Http,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
    }

    #[test]
    fn applies_only_to_single_unclaimed_header_values() {
        let source = HeaderMapSnapshot::from([
            ("authorization".into(), vec!["Bearer old".into()]),
            ("location".into(), vec!["/login?state=old".into()]),
        ]);
        let target = HeaderMapSnapshot::from([
            ("authorization".into(), vec!["Bearer new".into()]),
            ("location".into(), vec!["/login?state=new".into()]),
        ]);
        let mut report = report();
        report.differences.push(ResponseDifference::header(
            "location",
            ResponseDifferenceKind::HeaderValueMismatch,
        ));
        compare_headers(
            Some(&source),
            Some(&target),
            &mut report,
            |name, path| name == "location" && path == "/redirect",
            |value| value == "Bearer old",
            |source, target, carrier| {
                assert!(matches!(carrier, Carrier::Authorization));
                assert_eq!((source, target), ("Bearer old", "Bearer new"));
                Some(LeafObservations::default())
            },
        );
        assert_eq!(report.differences[0].pointer, "$headers/location");
        assert_eq!(report.differences.len(), 1);

        let mut duplicated = target.clone();
        duplicated.insert("Authorization".into(), vec!["Bearer again".into()]);
        compare_headers(
            Some(&source),
            Some(&duplicated),
            &mut report,
            |_, _| false,
            |value| value == "Bearer old",
            |source, target, carrier| {
                assert!(matches!(carrier, Carrier::Value));
                assert_eq!((source, target), ("/login?state=old", "/login?state=new"));
                Some(LeafObservations::default())
            },
        );
        assert_eq!(report.differences[0].pointer, "$headers/authorization");
        assert_eq!(report.differences.len(), 1);
    }

    #[test]
    fn older_standalone_target_capture_does_not_invent_authorization_evidence() {
        let source = HeaderMapSnapshot::from([("authorization".into(), vec!["Bearer a".into()])]);
        let target = HeaderMapSnapshot::new();
        let mut report = report();
        compare_headers(
            Some(&source),
            Some(&target),
            &mut report,
            |_, _| false,
            |_| panic!("missing capture must not invoke recognition"),
            |_, _, _| panic!("missing capture must not invoke matcher"),
        );
        assert!(report.differences.is_empty());
    }

    #[test]
    fn a_target_placeholder_cannot_waive_a_captured_authorization_mismatch() {
        let source = HeaderMapSnapshot::from([("authorization".into(), vec!["Bearer a".into()])]);
        let target = HeaderMapSnapshot::from([("authorization".into(), vec!["<redacted>".into()])]);
        let mut report = report();
        compare_headers(
            Some(&source),
            Some(&target),
            &mut report,
            |_, _| false,
            |value| value == "Bearer a",
            |_, _, _| panic!("protected values must not invoke matcher"),
        );
        assert_eq!(report.differences[0].pointer, "$headers/authorization");
    }

    #[test]
    fn unrecognized_authorization_does_not_add_a_standard_header_mismatch() {
        let source = HeaderMapSnapshot::from([("authorization".into(), vec!["opaque-a".into()])]);
        let target = HeaderMapSnapshot::from([("authorization".into(), vec!["opaque-b".into()])]);
        let mut report = report();
        compare_headers(
            Some(&source),
            Some(&target),
            &mut report,
            |_, _| false,
            |_| false,
            |_, _, _| panic!("unrecognized Authorization must not invoke matcher"),
        );
        assert!(report.differences.is_empty());
    }
}
