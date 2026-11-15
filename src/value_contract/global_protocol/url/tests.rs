use super::*;
use crate::policy::CompiledJsonPolicy;
use crate::value_contract::{global, json::AnchorClocks, time::ClockPair};
use serde_json::{Value, json};

const A: &str = "11111111-1111-4111-8111-111111111111";
const X: &str = "22222222-2222-4222-8222-222222222222";

fn plan() -> CompiledJsonPolicy {
    crate::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /authorize_url: {kind: url, formats: [url]}
    /session_id: {kind: identity, formats: [uuid]}
    /a~1b: {kind: identity, formats: [uuid]}
    /stamp: {kind: time, formats: [rfc3339]}
"#,
    )
    .unwrap()
    .global_json
    .unwrap()
}

#[test]
fn url_query_identities_join_root_fields_even_when_the_url_is_unchanged() {
    let source = json!({"session_id":A,"authorize_url":format!("https://auth.test/authorize?session_id={A}&keep=x%20y#fixed")});
    let good = json!({"session_id":X,"authorize_url":format!("https://auth.test/authorize?session_id={X}&keep=x%20y#fixed")});
    let compare = |target: &Value| {
        global::compare_logical(&source, target, &plan(), &[], Default::default()).unwrap()
    };
    assert!(compare(&good).passed());
    assert_eq!(compare(&good).identity_pairs().len(), 1);
    let mut inconsistent = good.clone();
    inconsistent["authorize_url"] = source["authorize_url"].clone();
    assert!(!compare(&inconsistent).passed());
    for altered in [
        good["authorize_url"]
            .as_str()
            .unwrap()
            .replace("auth.test", "other.test"),
        good["authorize_url"]
            .as_str()
            .unwrap()
            .replace("/authorize?", "/other?"),
        good["authorize_url"]
            .as_str()
            .unwrap()
            .replace("keep=x%20y", "keep=x+y"),
        good["authorize_url"]
            .as_str()
            .unwrap()
            .replace("#fixed", "#changed"),
        format!("https://auth.test/authorize?keep=x%20y&session_id={X}#fixed"),
        format!("https://auth.test/authorize?session_id={X}&session_id={X}&keep=x%20y#fixed"),
        format!("https://auth.test/authorize?%73ession_id={X}&keep=x%20y#fixed"),
    ] {
        let mut target = good.clone();
        target["authorize_url"] = altered.into();
        assert!(!compare(&target).passed());
    }
}

#[test]
fn url_query_uses_decoded_pointer_names_and_existing_time_formats() {
    let source = json!({"a/b":A,"authorize_url":format!("https://auth.test/authorize?a%2Fb={A}&stamp=1970-01-01T00%3A16%3A40Z")});
    let target = json!({"a/b":X,"authorize_url":format!("https://auth.test/authorize?a%2Fb={X}&stamp=1970-01-01T00%3A33%3A20Z")});
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: chrono::DateTime::from_timestamp(1000, 0),
            target: chrono::DateTime::from_timestamp(2000, 0),
        },
        ..Default::default()
    };
    let compared = global::compare_logical(&source, &target, &plan(), &[], clocks).unwrap();
    assert!(compared.passed(), "{:?}", compared.differences);
    assert_eq!(compared.time_validations.values().sum::<usize>(), 1);
    let document = Document::parse(&source["authorize_url"]).unwrap();
    let mut logical = document.logical.clone();
    logical["a/b"] = X.into();
    let rebuilt = document.rebuild(&logical).unwrap();
    assert!(rebuilt.starts_with(&format!("https://auth.test/authorize?a%2Fb={X}&stamp=")));
    assert!(rebuilt.ends_with("1970-01-01T00%3A16%3A40Z"));
}

#[test]
fn unknown_source_urls_remain_exact_and_known_urls_cannot_change_protocol() {
    for source in [
        "opaque",
        "https://auth.test/?x=1&x=2",
        "https://auth.test/?x=%zz",
        "https://auth.test/?x=%FF",
    ] {
        let before = json!({"authorize_url":source});
        assert!(
            global::compare_logical(&before, &before, &plan(), &[], Default::default())
                .unwrap()
                .passed()
        );
        assert!(
            !global::compare_logical(
                &before,
                &json!({"authorize_url":"https://auth.test/?x=3"}),
                &plan(),
                &[],
                Default::default()
            )
            .unwrap()
            .passed()
        );
    }
    let source = json!({"authorize_url":format!("https://auth.test/?session_id={A}")});
    for changed in [
        json!(null),
        json!(7),
        json!(format!("wss://auth.test/?session_id={X}")),
    ] {
        assert!(
            !global::compare_logical(
                &source,
                &json!({"authorize_url":changed}),
                &plan(),
                &[],
                Default::default()
            )
            .unwrap()
            .passed()
        );
    }
}
