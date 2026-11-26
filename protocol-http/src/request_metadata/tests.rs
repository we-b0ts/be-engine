use super::*;
use bytes::Bytes;
use serde_json::json;
use std::collections::BTreeMap;

const TRACE: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const PATH: &str = "/connection/open";
const BODY: &str = r#"{"address":"192.0.2.12","topics":["a","b"],"secret":"example"}"#;

fn rule() -> RequestMetadataRule {
    RequestMetadataRule {
        host: "gateway.example".into(),
        method: "POST".into(),
        path: PATH.into(),
        json_ipv4: vec!["/address".into()],
    }
}

fn endpoint() -> Endpoint {
    Endpoint {
        host: "gateway.example".into(),
        port: 443,
    }
}

fn record() -> Value {
    json!({
        "scheme":"fake_ip_https",
        "response_status":200,
        "response_headers":{"content-encoding":["gzip"]}
    })
}

fn message() -> RequestMessage {
    RequestMessage {
        method: "POST".into(),
        uri: PATH.into(),
        headers: BTreeMap::from([
            ("host".into(), vec!["gateway.example".into()]),
            ("content-type".into(), vec!["application/json".into()]),
            ("accept".into(), vec!["application/json".into()]),
            ("accept-encoding".into(), vec!["gzip".into()]),
            ("user-agent".into(), vec!["an-sdk".into()]),
            ("x-business".into(), vec!["value".into()]),
        ]),
        body: Bytes::from_static(BODY.as_bytes()),
    }
}

fn source_message(record: &Value) -> Arc<dyn ProtocolMessage> {
    let mut source = message();
    source.body = Bytes::from_static(
        br#"{"secret": "example", "address": "192.0.2.23", "topics": ["a", "b"]}"#,
    );
    source
        .headers
        .insert("traceparent".into(), vec![TRACE.into()]);
    source
        .headers
        .insert("accept-encoding".into(), vec!["gzip, deflate, br".into()]);
    request(&[rule()], &endpoint(), Arc::new(source), Some(record)).unwrap()
}

fn target_matches(source: &dyn ProtocolMessage, target: RequestMessage) -> bool {
    let target = request(
        &[rule()],
        &endpoint(),
        tls_target_request(Arc::new(target)),
        None,
    )
    .unwrap();
    let target = target
        .exact_request_alternative()
        .unwrap_or(target.as_ref());
    let source = source.project().unwrap();
    let target = target.project().unwrap();
    source.structure == target.structure
        && source.values.len() == target.values.len()
        && source.values.iter().all(|(path, value)| {
            target
                .values
                .get(path)
                .is_some_and(|target| value.bytes == target.bytes)
        })
}

#[test]
fn compares_only_declared_metadata_for_finite_compatible_http() {
    let source = source_message(&record());
    assert!(target_matches(source.as_ref(), message()));

    for (name, value) in [
        ("host", "elsewhere.example"),
        ("accept", "text/plain"),
        ("content-type", "application/octet-stream"),
        ("content-digest", "sha-256=:value:"),
        ("x-business", "changed"),
        ("user-agent", "other-sdk"),
    ] {
        let mut target = message();
        target.headers.insert(name.into(), vec![value.into()]);
        assert!(!target_matches(source.as_ref(), target), "{name}");
    }
    for body in [
        BODY.replace("192.0.2.12", "2001:db8::1"),
        BODY.replace("192.0.2.12", "0.0.0.0"),
        BODY.replace("\"a\",\"b\"", "\"b\",\"a\""),
        BODY.replace("example", "other"),
        BODY.replace("\"address\"", "\"other\""),
        BODY.replace("\"address\"", "\"address\":\"192.0.2.1\",\"address\""),
    ] {
        let mut target = message();
        target.body = Bytes::from(body);
        assert!(!target_matches(source.as_ref(), target));
    }
    let mut target = message();
    target.uri = "/different".into();
    assert!(!target_matches(source.as_ref(), target));
    let mut target = message();
    target.method = "GET".into();
    assert!(!target_matches(source.as_ref(), target));
}

#[test]
fn scoped_metadata_matching_uses_the_protocol_header_projection() {
    for response_headers in [
        json!({}),
        json!({"content-encoding":["br"],"vary":["accept-encoding"]}),
    ] {
        let mut record = record();
        record["response_headers"] = response_headers;
        let source = source_message(&record);
        let mut target = message();
        target.headers.remove("accept-encoding");
        assert!(target_matches(source.as_ref(), target));
        let mut target = message();
        target
            .headers
            .insert("accept-encoding".into(), vec!["gzip;q=0, br".into()]);
        target.headers.insert(
            "traceparent".into(),
            vec!["00-0123456789abcdef0123456789abcdef-123456789abcdef0-01".into()],
        );
        assert!(target_matches(source.as_ref(), target));
    }
}

#[test]
fn retains_exact_comparison_without_finite_representation_evidence() {
    assert!(
        request(&[rule()], &endpoint(), Arc::new(message()), None)
            .unwrap()
            .exact_request_alternative()
            .is_none()
    );
    for (path, value) in [("/response_status", json!(400)), ("/scheme", json!("http"))] {
        let mut record = record();
        *record.pointer_mut(path).unwrap() = value;
        let source = source_message(&record);
        assert!(!target_matches(source.as_ref(), message()), "{path}");
    }
    let mut streamed = record();
    streamed["response_stream"] = json!({"complete":true});
    assert!(!target_matches(
        source_message(&streamed).as_ref(),
        message()
    ));
}

#[test]
fn validates_one_exact_scope_and_an_exact_pointer() {
    validate_rules(&[rule()]).unwrap();
    assert!(validate_rules(&[rule(), rule()]).is_err());
    let mut invalid = rule();
    invalid.path = "/*".into();
    assert!(validate_rules(&[invalid]).is_err());
    let mut invalid = rule();
    invalid.json_ipv4 = vec!["/addresses/*".into()];
    assert!(validate_rules(&[invalid]).is_err());
    let mut invalid = rule();
    invalid.json_ipv4.clear();
    assert!(validate_rules(&[invalid]).is_err());
}

#[test]
fn native_inventory_considers_the_scoped_form_before_selecting_the_exchange() {
    use traffic_model::recording::ProtocolRef;
    use traffic_protocol::{
        ProtocolId,
        connection::{RecordedExchange, RecordedInput},
    };
    use traffic_replay::{
        ReplaySource,
        exchange::{ExchangeInventory, ExchangeRules, MatchContext, Selection, SourceContext},
    };

    let protocol = ProtocolId::new("http");
    let endpoint = endpoint();
    let mut inventory: ExchangeInventory = ExchangeInventory::default();
    inventory
        .register(
            protocol,
            RecordedExchange {
                reference: ProtocolRef::exchange("http", uuid::Uuid::new_v4()),
                endpoint: endpoint.clone(),
                lane: None,
                response_delay: std::time::Duration::ZERO,
                input: RecordedInput::Request(source_message(&record())),
                response: Arc::new(crate::message::ResponseMessage {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: Bytes::new(),
                    head_request: false,
                }),
            },
            SourceContext {
                source: ReplaySource::Startup,
                case_id: None,
                position: 0,
                capture: None,
            },
            ExchangeRules::default(),
        )
        .unwrap();
    inventory.seal();

    let select = |target: RequestMessage| {
        let target = request(
            &[rule()],
            &endpoint,
            tls_target_request(Arc::new(target)),
            None,
        )
        .unwrap();
        inventory
            .select(
                MatchContext {
                    protocol,
                    endpoint: &endpoint,
                    active_case: None,
                    request: target.as_ref(),
                    session: None,
                    lane: None,
                    request_session: None,
                    metadata: &(),
                },
                |_| (),
                |_, _| Ok(()),
            )
            .unwrap()
    };
    assert!(matches!(select(message()), Selection::Matched(_)));
    let mut changed = message();
    changed.body = Bytes::from(BODY.replace("example", "other"));
    assert!(matches!(select(changed), Selection::NotFound));
}
