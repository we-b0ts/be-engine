use super::*;
use crate::replay::policy::ValueRuleHost;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{borrow::Cow, collections::BTreeMap};
use traffic_contract::{identity::IdentityPair, time::ClockPair};
use traffic_policy_value::PreparedMessage;
use traffic_protocol::message::{ProjectedMessage, ProjectedValue, ProtocolMessage};

fn owner() -> RequestContracts {
    let configured = crate::policy::parse_and_compile_policy(
        r#"
format: traffic-policy/v3
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: id-, hex: 4}]}
    /created_at: {kind: time, formats: [unix_seconds]}
    /link:
      kind: template
      formats:
        - template: 'wss://example.test/session/{session_id}'
          fields:
            session_id: {prefix: id-, hex: 4}
    /url: {kind: url, formats: [url]}
"#,
    )
    .unwrap();
    let mut owner = RequestContracts::default();
    owner
        .configure_compiled(Some(Arc::new(configured)))
        .unwrap();
    owner.configure_session_identities("session", 4096).unwrap();
    owner
}

struct Body(&'static [u8]);

impl ProtocolMessage for Body {
    fn project(&self) -> Result<ProjectedMessage> {
        Ok(ProjectedMessage {
            structure: Value::Null,
            values: BTreeMap::from([("payload".into(), ProjectedValue::bytes(self.0))]),
        })
    }

    fn locate(&self, _: &Value) -> Result<Vec<String>> {
        Ok(vec!["payload".into()])
    }

    fn evidence(&self, _: &Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

fn clock(target: i64) -> AnchorClocks {
    let observation: ClockPair = ClockPair {
        source: DateTime::<Utc>::from_timestamp(1000, 0),
        target: DateTime::<Utc>::from_timestamp(target, 0),
    };
    AnchorClocks {
        observation: Some(observation),
        ..Default::default()
    }
}

fn prepare(owner: &RequestContracts, body: &'static [u8]) -> PreparedMessage {
    let mut message = crate::value_extensions::prepare_message_with_policy(
        &Body(body),
        &[],
        owner.document_policy(clock(1000)),
    )
    .unwrap();
    message.prepare_delivery().unwrap();
    message
}

#[test]
fn prefetched_identity_and_template_match_live_delivery() {
    let owner = owner();
    commit_identity(&owner, "id-aaaa", "id-bbbb");
    let message = prepare(
        &owner,
        br#"{ "session_id": "id-aaaa", "link": "wss://example.test/session/id-aaaa" }"#,
    );
    let mut source_comparison = message.compare_source(clock(1000), owner.metadata());
    let prefetched = message
        .prefetch_delivery(
            "session",
            clock(1000),
            owner.metadata(),
            &mut source_comparison,
        )
        .unwrap()
        .unwrap();
    assert!(prefetched.guards.iter().all(|guard| guard.is_current()));
    let prefetched = prefetched.rendered;
    let live = message
        .render_delivery_with_prepared_documents(
            clock(2000),
            owner.metadata(),
            &Default::default(),
            &BTreeMap::new(),
            |_| Ok(vec![]),
            |source, delivered, preparation| {
                assert!(matches!(delivered, Cow::Borrowed(_)));
                assert!(
                    preparation
                        .unwrap()
                        .apply("session", source, delivered, clock(2000))?
                );
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(prefetched.values, live.values);
    assert_eq!(
        serde_json::from_slice::<Value>(&prefetched.values["payload"]).unwrap(),
        json!({"session_id":"id-bbbb", "link":"wss://example.test/session/id-bbbb"})
    );
    assert_eq!(
        prefetched.comparison.identity_pairs(),
        live.comparison.identity_pairs()
    );
    assert_eq!(prefetched.comparison.evaluated, live.comparison.evaluated);
}

fn commit_identity(owner: &RequestContracts, source: &str, target: &str) {
    let decision = owner
        .preview_run_identity_pairs(
            "session",
            &[IdentityPair {
                source: json!(source).to_string(),
                target: json!(target).to_string(),
            }],
        )
        .unwrap();
    owner.commit_identity(decision).unwrap();
}

#[test]
fn unrelated_identity_commits_keep_prefetched_template_current() {
    let owner = owner();
    let original = br#"{ "session_id":"id-aaaa", "link":"wss://example.test/session/id-bbbb" }"#;
    let message = prepare(&owner, original);
    let mut source_comparison = message.compare_source(clock(1000), owner.metadata());
    let evaluated = source_comparison.evaluated.clone();
    let prefetched = message
        .prefetch_delivery(
            "session",
            clock(1000),
            owner.metadata(),
            &mut source_comparison,
        )
        .unwrap()
        .unwrap();
    assert_eq!(prefetched.rendered.values["payload"].as_ref(), original);
    assert_eq!(prefetched.rendered.comparison.evaluated, evaluated);
    assert!(source_comparison.evaluated.is_empty());
    assert_eq!(prefetched.guards.len(), 1);
    let guard = &prefetched.guards[0];
    assert!(guard.is_current());
    commit_identity(&owner, "id-cccc", "id-dddd");
    assert!(guard.is_current());
    commit_identity(&owner, "id-bbbb", "id-eeee");
    assert!(!guard.is_current());
}

#[test]
fn prefetch_defers_clock_sensitive_document_rules() {
    let owner = owner();
    for body in [
        br#"{"created_at":1010}"#.as_slice(),
        br#"{"observed_at":"2024-02-15T12:34:56Z"}"#.as_slice(),
        br#"{"url":"https://example.test/path?created_at=1010"}"#.as_slice(),
    ] {
        let message = prepare(&owner, body);
        let mut comparison = message.compare_source(clock(1000), owner.metadata());
        assert!(comparison.passed(), "{:?}", comparison.differences);
        assert!(
            message
                .prefetch_delivery("session", clock(1000), owner.metadata(), &mut comparison)
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn prepared_json_reuses_native_matches_with_the_same_comparison_results() {
    let document = GlobalDocumentPolicy::new(owner(), clock(1000));
    let source = serde_json::from_value(json!({
        "session_id": "id-aaaa",
        "created_at": 1010,
        "link": "wss://example.test/session/id-aaaa",
        "url": "https://example.test/path?session_id=id-aaaa"
    }))
    .unwrap();
    let projection = LogicalProjection::new(&source).unwrap();
    let scanned = document.prepare_projected_source(&projection).unwrap();
    let matched = document.prepare_json_source(&projection).unwrap();
    assert_eq!(scanned.paths, matched.paths);
    let scanned = scanned.comparison.unwrap();
    let matched = matched.comparison.unwrap();
    assert_eq!(scanned.clock_independent(), matched.clock_independent());
    for (link, passes) in [
        ("wss://example.test/session/id-bbbb", true),
        ("wss://example.test/session/corrupt", false),
    ] {
        let target = serde_json::from_value(json!({
            "session_id": "id-bbbb",
            "created_at": 2010,
            "link": link,
            "url": "https://example.test/path?session_id=id-bbbb"
        }))
        .unwrap();
        let expected = scanned
            .compare_projected(&projection, &target, &[], clock(2000))
            .unwrap();
        let actual = matched
            .compare_projected(&projection, &target, &[], clock(2000))
            .unwrap();
        assert_eq!(actual.passed(), passes, "{:?}", actual.differences);
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(actual.identity_pairs(), expected.identity_pairs());
    }
}
