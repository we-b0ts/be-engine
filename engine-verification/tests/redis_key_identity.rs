use std::sync::Arc;

use bytes::Bytes;
use traffic_engine_verification::{
    policy::runtime::RequestContracts, value_contract::json::PolicyMetadata,
};
use traffic_policy_value::{PreparedMessage, host::ValueRuleHost};
use traffic_protocol_redis::message::RequestMessage;

const SOURCE: &str = "vnc-AAAAAAAAAAAAAAAAAAAAAAAA";
const TARGET: &str = "vnc-BBBBBBBBBBBBBBBBBBBBBBBB";
const OTHER: &str = "vnc-CCCCCCCCCCCCCCCCCCCCCCCC";

fn contracts() -> RequestContracts {
    let policy = traffic_engine_policy::policy::parse_and_compile_policy(
        r#"format: traffic-policy/v3
json:
  fields:
    /session_id: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}
redis:
  keys:
    'vnc_session:*':
      key_format: {kind: identity, formats: [{prefix: vnc-, base64url: 24}]}
"#,
    )
    .unwrap();
    let mut contracts = RequestContracts::default();
    contracts
        .configure_compiled(Some(Arc::new(policy)))
        .unwrap();
    contracts
        .configure_session_identities("session", 10)
        .unwrap();
    contracts
}

fn request(command: &str, args: &[&str]) -> RequestMessage {
    RequestMessage {
        command: command.into(),
        args: args
            .iter()
            .map(|value| Bytes::copy_from_slice(value.as_bytes()))
            .collect(),
        resp_version: 2,
        database: 0,
        username: None,
    }
}

fn set(key_id: &str, value_id: &str, ttl: &str) -> RequestMessage {
    request(
        "SET",
        &[
            &format!("vnc_session:{key_id}"),
            &format!(r#"{{"session_id":"{value_id}"}}"#),
            "EX",
            ttl,
        ],
    )
}

fn prepare(contracts: &RequestContracts, source: &RequestMessage) -> PreparedMessage {
    PreparedMessage::compile_with_policy(
        source,
        &contracts.additional_request_bindings(source).unwrap(),
        contracts.document_policy(Default::default()),
        traffic_extensions::codecs(),
    )
    .unwrap()
}

#[test]
fn redis_key_and_json_value_share_the_complete_session_identity() {
    let contracts = contracts();
    let prepared = prepare(&contracts, &set(SOURCE, SOURCE, "3600"));
    let compare = |target: &RequestMessage| {
        prepared
            .compare(target, Default::default(), &PolicyMetadata)
            .unwrap()
    };

    assert!(!compare(&set(TARGET, OTHER, "3600")).passed());
    assert!(!compare(&set(TARGET, TARGET, "60")).passed());
    assert!(!compare(&set("vnc-short", "vnc-short", "3600")).passed());
    let mut wrong_prefix = set(TARGET, TARGET, "3600");
    wrong_prefix.args[0] = format!("other:{TARGET}").into();
    assert!(!compare(&wrong_prefix).passed());

    let accepted = compare(&set(TARGET, TARGET, "3600"));
    assert!(accepted.passed(), "{:?}", accepted.differences);
    let pairs = accepted.identity_pairs();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].source, format!(r#""{SOURCE}""#));
    assert_eq!(pairs[0].target, format!(r#""{TARGET}""#));
    let decision = contracts
        .preview_run_identity_pairs("session", &pairs)
        .unwrap();
    contracts.commit_comparison(accepted, decision).unwrap();

    let prepared = prepare(
        &contracts,
        &request("GET", &[&format!("vnc_session:{SOURCE}")]),
    );
    for (id, expected) in [(TARGET, true), (OTHER, false)] {
        let actual = request("GET", &[&format!("vnc_session:{id}")]);
        let compared = prepared
            .compare(&actual, Default::default(), &PolicyMetadata)
            .unwrap();
        assert!(compared.passed());
        assert_eq!(
            contracts
                .preview_run_identity_pairs("session", &compared.identity_pairs())
                .is_ok(),
            expected
        );
    }
}

#[test]
fn key_format_only_applies_to_matching_physical_slots() {
    let contracts = contracts();
    let key = format!("vnc_session:{SOURCE}");
    let source = request("DEL", &[&key, "static:key"]);
    let selected = contracts.additional_request_bindings(&source).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].selector["index"], 0);
    for source in [
        request("PUBLISH", &[&key, &key]),
        request("SET", &["static:key", &key]),
        request("GET", &["vnc_session:short"]),
    ] {
        assert!(
            contracts
                .additional_request_bindings(&source)
                .unwrap()
                .is_empty()
        );
    }
}
