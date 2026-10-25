use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

const FIELDS: &str = r#"
  /session_id: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}
  /url:
    kind: template
    formats:
      - template: 'wss://vnc.example/sessions/{session_id}?ticket={ticket}'
        fields:
          session_id: {prefix: vnc-, base64url: 24}
          ticket: {base64url: 43}
"#;

fn plan() -> CompiledJsonPolicy {
    serde_yaml::from_str::<crate::policy::JsonPolicy>(&format!("fields:{FIELDS}"))
        .unwrap()
        .compile()
        .unwrap()
}

fn value(session: u8, ticket: u8) -> Value {
    let session = format!("vnc-{}", URL_SAFE_NO_PAD.encode([session; 18]));
    let ticket = URL_SAFE_NO_PAD.encode([ticket; 32]);
    json!({"session_id": session, "url": format!("wss://vnc.example/sessions/{session}?ticket={ticket}"), "strict": true})
}

fn compare(source: &Value, target: &Value) -> crate::value_contract::json::Comparison {
    crate::value_contract::global::compare_logical(source, target, &plan(), &[], Default::default())
        .unwrap()
}

#[test]
fn global_template_preserves_complete_session_identity_and_static_url_parts() {
    let source = value(1, 3);
    let target = value(2, 4);
    let comparison = compare(&source, &target);
    assert!(comparison.passed(), "{:?}", comparison.differences);
    assert_eq!(comparison.identity_pairs().len(), 2);
    let encoded = serde_json::to_string(&source["session_id"]).unwrap();
    assert!(
        comparison
            .identity_pairs()
            .iter()
            .any(|pair| pair.source == encoded)
    );
    let url = target["url"].as_str().unwrap();
    for changed in [
        url.replace("vnc.example", "other.example"),
        url.replace("/sessions/", "/other/"),
        url.replace("?ticket=", "?other="),
        url.replace("wss:", "https:"),
        url.replace(
            target["session_id"].as_str().unwrap(),
            source["session_id"].as_str().unwrap(),
        ),
        format!("{url}&extra=true"),
    ] {
        let mut changed_target = target.clone();
        changed_target["url"] = changed.into();
        assert!(!compare(&source, &changed_target).passed());
    }
    let mut changed = target;
    changed["strict"] = false.into();
    assert!(!compare(&source, &changed).passed());
}

#[test]
fn unmatched_source_urls_remain_exact_and_target_cannot_select_a_template() {
    for source in [
        json!("https://elsewhere/path"),
        json!(null),
        json!(17),
        json!({"nested": true}),
    ] {
        let source = json!({"url": source});
        assert!(compare(&source, &source).passed());
        assert!(!compare(&source, &json!({"url": value(2, 4)["url"]})).passed());
    }
    let source = json!({"url": "https://elsewhere/path"});
    assert!(!compare(&source, &json!({"url": "https://elsewhere/changed"})).passed());
    assert!(!compare(&json!({}), &source).passed());
    assert!(!compare(&source, &json!({})).passed());
}

#[test]
fn recognized_source_template_never_falls_back_for_invalid_tokens_or_layout() {
    let source = value(1, 3);
    let url = source["url"].as_str().unwrap();
    for changed in [
        url.replace("?ticket=", "?bad="),
        url.replace("vnc-", "other-"),
        format!("{url}="),
        format!("{url}?ticket=duplicate"),
        // Forty-three base64url characters must encode exactly 32 bytes,
        // including canonical zero pad bits in the final character.
        format!(
            "{}?ticket={}",
            url.split_once("?ticket=").unwrap().0,
            "B".repeat(43)
        ),
    ] {
        let malformed = json!({"url": changed});
        assert!(!compare(&malformed, &malformed).passed());
        assert!(!compare(&source, &malformed).passed());
    }
}

#[test]
fn template_identity_uses_complete_prefixes_and_string_types() {
    let source = value(1, 3);
    let target = value(2, 4);
    let mut comparison = compare(&source, &target);
    let standalone = crate::value_contract::global::compare_logical(
        &json!({"session_id": source["session_id"]}),
        &json!({"session_id": format!("vnc-{}", URL_SAFE_NO_PAD.encode([5;18]))}),
        &plan(),
        &[],
        Default::default(),
    )
    .unwrap();
    comparison.merge_and_validate(standalone);
    assert!(!comparison.passed());

    let numeric: crate::policy::JsonPolicy = serde_yaml::from_str(
        "fields:\n  /id: {kind: identity, formats: [decimal]}\n  /url: {kind: template, formats: [{template: 'item:{id}', fields: {id: decimal}}]}\n",
    ).unwrap();
    let numeric = numeric.compile().unwrap();
    for (source, target, passed) in [
        (
            json!({"id": 11, "url": "item:11"}),
            json!({"id": 22, "url": "item:33"}),
            true,
        ),
        (
            json!({"id": "11", "url": "item:11"}),
            json!({"id": "22", "url": "item:33"}),
            false,
        ),
    ] {
        assert_eq!(
            crate::value_contract::global::compare_logical(
                &source,
                &target,
                &numeric,
                &[],
                Default::default()
            )
            .unwrap()
            .passed(),
            passed
        );
    }
}

#[test]
fn ambiguous_source_layouts_reject_without_trying_target_or_reordering_formats() {
    let raw = FIELDS.replace("          ticket: {base64url: 43}", "          ticket: {base64url: 43}\n      - template: 'wss://vnc.example/{path}?ticket={ticket}'\n        fields:\n          path: string\n          ticket: {base64url: 43}");
    let mut plan = serde_yaml::from_str::<crate::policy::JsonPolicy>(&format!("fields:{raw}"))
        .unwrap()
        .compile()
        .unwrap();
    let source = value(1, 3);
    for _ in 0..2 {
        let compared = crate::value_contract::global::compare_logical(
            &source,
            &source,
            &plan,
            &[],
            Default::default(),
        )
        .unwrap();
        assert!(!compared.passed());
        let GlobalField::Template { formats } = plan.fields.get_mut("/url").unwrap() else {
            unreachable!()
        };
        formats.reverse();
    }
}
