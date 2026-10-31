//! Template delivery uses ordinary private case correspondence proposals.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;

fn owner() -> RequestContracts {
    let compiled = crate::policy::parse_and_compile_policy(
        r#"
format: traffic-policy/v3
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}
    /url:
      kind: template
      formats:
        - template: 'wss://vnc.example/sessions/{session_id}?ticket={ticket}'
          fields:
            session_id: {prefix: vnc-, base64url: 24}
            ticket: {base64url: 43}
"#,
    )
    .unwrap();
    let mut owner = RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(compiled))).unwrap();
    owner
}

fn session(byte: u8) -> String {
    format!("vnc-{}", URL_SAFE_NO_PAD.encode([byte; 18]))
}

fn url(session: &str) -> String {
    format!(
        "wss://vnc.example/sessions/{session}?ticket={}",
        URL_SAFE_NO_PAD.encode([3; 32])
    )
}

#[test]
fn template_only_delivery_reuses_complete_accepted_session_without_early_publication() {
    let owner = owner();
    let source_session = session(1);
    let target_session = session(2);
    let before = json!({"session_id": source_session});
    let after = json!({"session_id": target_session});
    let compared = owner
        .compare_global_value(
            before.to_string().as_bytes(),
            after.to_string().as_bytes(),
            &[],
            Default::default(),
        )
        .unwrap();
    owner
        .commit_identity(owner.identity_decision("case", &compared).unwrap())
        .unwrap();

    let source = json!({"url": url(&source_session), "stable": true});
    let prepared = crate::replay::contract_value::Delivery::prepare_global(
        source.to_string().as_bytes(),
        owner.global_json().unwrap(),
        Default::default(),
    )
    .unwrap();
    assert!(
        prepared.has_identities(),
        "template-only payloads still have deliverable identities"
    );
    let (bytes, decision) = prepared
        .render_with_identities(Utc::now(), &owner, "case")
        .unwrap();
    let actual: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(actual, json!({"url": url(&target_session), "stable": true}));
    let ticket = json!(URL_SAFE_NO_PAD.encode([3; 32]));
    assert!(
        !owner
            .knows_identity_value("case", &ticket, &ticket)
            .unwrap()
    );
    owner.commit_identity(decision).unwrap();
    assert!(
        owner
            .knows_identity_value("case", &ticket, &ticket)
            .unwrap()
    );
    let (again, _) = prepared
        .render_with_identities(Utc::now(), &owner, "case")
        .unwrap();
    assert_eq!(bytes, again);

    let wrong = owner
        .compare_global_value(
            source.to_string().as_bytes(),
            source.to_string().as_bytes(),
            &[],
            Default::default(),
        )
        .unwrap();
    assert!(wrong.passed());
    assert!(
        owner.identity_decision("case", &wrong).is_err(),
        "equal URLs cannot ignore an accepted session mapping"
    );
    let (isolated, _) = prepared
        .render_with_identities(Utc::now(), &owner, "other-case")
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&isolated).unwrap(), source);
}

#[test]
fn malformed_matched_template_cannot_be_prepared_even_when_bytes_equal() {
    let owner = owner();
    for source in [
        json!({"url":"wss://vnc.example/sessions/invalid?ticket=invalid"}),
        json!({"url":format!("{}=", url(&session(1)))}),
    ] {
        assert!(
            crate::replay::contract_value::Delivery::prepare_global(
                source.to_string().as_bytes(),
                owner.global_json().unwrap(),
                Default::default(),
            )
            .is_err()
        );
        assert!(!owner.has_identities("case"));
    }
}
