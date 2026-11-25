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
    /created_at: {kind: time, formats: [unix_seconds]}
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
    let prepared = crate::value_contract::response_delivery::Delivery::prepare_global(
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
            crate::value_contract::response_delivery::Delivery::prepare_global(
                source.to_string().as_bytes(),
                owner.global_json().unwrap(),
                Default::default(),
            )
            .is_err()
        );
        assert!(!owner.has_identities("case"));
    }
}

#[test]
fn native_json_projection_uses_the_global_template_rule_and_shared_delivery_store() {
    native_template_delivery("case", true);
}

#[test]
fn session_native_template_delivery_reuses_the_registered_identity_scope() {
    native_template_delivery("session", false);
}

#[test]
fn prefetch_reuses_only_committed_session_identities() {
    use crate::replay::policy::ValueRuleHost;

    let owner = owner();
    ValueRuleHost::configure_session_identities(&owner, "session", 60_000).unwrap();
    let source_session = session(1);
    let target_session = session(2);
    let source = json!({"session_id":source_session,"url":url(&source_session)});
    let global = owner.global_json().unwrap();
    let fields = global.identity_fields(&source).unwrap();
    assert!(
        owner
            .prefetch_root_identities(&source, &fields)
            .unwrap()
            .is_none()
    );

    let pair = crate::value_contract::identities::IdentityPair {
        source: json!(source_session).to_string(),
        target: json!(target_session).to_string(),
    };
    owner
        .commit_identity(
            owner
                .preview_run_identity_pairs("session", &[pair])
                .unwrap(),
        )
        .unwrap();
    let cached = owner
        .prefetch_root_identities(&source, &fields)
        .unwrap()
        .unwrap();
    let mut delivered = Cow::Borrowed(&source);
    owner
        .translate_resolved_identities_cow("session", &source, &mut delivered, global, cached)
        .unwrap();
    assert_eq!(
        delivered.as_ref(),
        &json!({"session_id":target_session,"url":url(&target_session)})
    );
    let ticket = json!(URL_SAFE_NO_PAD.encode([3; 32]));
    assert!(
        !owner
            .knows_identity_value("session", &ticket, &ticket)
            .unwrap()
    );
}

#[test]
fn unchanged_identity_delivery_stays_borrowed() {
    use crate::replay::policy::ValueRuleHost;

    let owner = owner();
    let source_session = session(1);
    let source = json!({"session_id":source_session,"url":url(&source_session),"stable":true});
    let mut delivered = Cow::Borrowed(&source);
    ValueRuleHost::translate_delivery_document(
        &owner,
        "case",
        &source,
        &mut delivered,
        Default::default(),
    )
    .unwrap();
    assert!(matches!(delivered, Cow::Borrowed(value) if std::ptr::eq(value, &source)));
}

fn native_template_delivery(scope: &str, case_owned: bool) {
    use crate::replay::policy::ValueRuleHost;
    use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};

    struct Message(Value);
    impl ProtocolMessage for Message {
        fn project(&self) -> Result<ProjectedMessage> {
            Ok(ProjectedMessage {
                structure: json!({"document": true}),
                values: std::collections::BTreeMap::from([(
                    "payload".into(),
                    ProjectedValue::json(self.0.to_string()),
                )]),
            })
        }
        fn locate(&self, _: &Value) -> Result<Vec<String>> {
            anyhow::bail!("global fields already have native physical locations")
        }
        fn evidence(&self, _: &Value) -> Result<Value> {
            Ok(self.0.clone())
        }
    }

    let owner = owner();
    if !case_owned {
        ValueRuleHost::configure_session_identities(&owner, scope, 60_000).unwrap();
    }
    let source_session = session(1);
    let target_session = session(2);
    let source = Message(json!({"session_id":source_session}));
    let target = Message(json!({"session_id":target_session}));
    let policy = owner.document_policy(Default::default());
    let request =
        crate::value_extensions::prepare_message_with_policy(&source, &[], policy).unwrap();
    let comparison = request
        .compare(
            &target,
            Default::default(),
            &crate::value_contract::json::PolicyMetadata,
        )
        .unwrap();
    assert!(comparison.passed());
    let identity = ValueRuleHost::preview_identity_pairs(
        &owner,
        scope,
        &comparison.identity_pairs(),
        case_owned,
    )
    .unwrap();
    let response = Message(
        json!({"session_id":source_session,"url":url(&source_session),"stable":true,"created_at":1010}),
    );
    let clocks = crate::value_contract::json::AnchorClocks::for_request(
        Default::default(),
        crate::value_contract::time::ClockPair {
            source: DateTime::from_timestamp(1000, 0),
            target: DateTime::from_timestamp(2000, 0),
        },
        Default::default(),
    );
    let policy = owner.document_policy(clocks);
    let mut prepared =
        crate::value_extensions::prepare_message_with_policy(&response, &[], policy).unwrap();
    if !case_owned {
        prepared.prepare_delivery().unwrap();
    }
    ValueRuleHost::commit_comparison(&owner, comparison, identity).unwrap();

    let rendered = prepared
        .render_delivery_with_prepared_documents(
            clocks,
            &crate::value_contract::json::PolicyMetadata,
            &Default::default(),
            &Default::default(),
            |selected| {
                ValueRuleHost::identity_deliveries(&owner, scope, selected)
                    .map(|(values, _)| values)
            },
            |source, delivered, delivery| {
                assert!(matches!(delivered, Cow::Borrowed(_)));
                if case_owned {
                    assert!(delivery.is_none());
                    ValueRuleHost::translate_delivery_document(
                        &owner, scope, source, delivered, clocks,
                    )?;
                } else {
                    assert!(delivery.unwrap().apply(scope, source, delivered, clocks)?);
                }
                assert!(matches!(delivered, Cow::Owned(_)));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&rendered.values["payload"]).unwrap(),
        json!({"session_id":target_session,"url":url(&target_session),"stable":true,"created_at":2010})
    );
    let ticket = json!(URL_SAFE_NO_PAD.encode([3; 32]));
    assert!(!owner.knows_identity_value(scope, &ticket, &ticket).unwrap());
    let identity = ValueRuleHost::preview_identity_pairs(
        &owner,
        scope,
        &rendered.comparison.identity_pairs(),
        case_owned,
    )
    .unwrap();
    ValueRuleHost::commit_comparison(&owner, rendered.comparison, identity).unwrap();
    assert!(owner.knows_identity_value(scope, &ticket, &ticket).unwrap());
}
