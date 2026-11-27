use super::*;
use chrono::{TimeZone, Utc};
use traffic_contract::time::ClockPair;
use traffic_protocol::connection::Endpoint;
use traffic_protocol_http::{message::RequestMessage, request_sigv4};

const HOST: &str = "s3.hj4.1.intra.weibo.com:9100";
const URI: &str = "/wegent-archives?location=";
const SOURCE_DATE: &str = "20261126T025500Z";
const TARGET_DATE: &str = "20261127T031000Z";

fn request(date: &str) -> RequestMessage {
    RequestMessage {
        method: "GET".into(),
        uri: URI.into(),
        headers: [
            ("host".into(), vec![HOST.into()]),
            ("x-amz-date".into(), vec![date.into()]),
        ]
        .into(),
        body: Default::default(),
    }
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: ClockPair {
            source: Utc.with_ymd_and_hms(2026, 11, 26, 2, 55, 1).single(),
            target: Utc.with_ymd_and_hms(2026, 11, 27, 3, 10, 1).single(),
        },
        ..Default::default()
    }
}

#[test]
fn signing_date_is_independent_of_authorization() {
    let source = request(SOURCE_DATE);
    let clocks = clocks();
    let binding = binding(&source, clocks, &[]).unwrap().unwrap();
    let prepared = crate::value_extensions::prepare_message(&source, &[binding]).unwrap();
    let contracts = crate::value_extensions::strict_values();
    let compare = |target: &RequestMessage| {
        prepared
            .compare(target, clocks, contracts.metadata())
            .unwrap()
            .passed()
    };
    assert!(compare(&request(TARGET_DATE)));
    assert!(!compare(&request(SOURCE_DATE)));
    assert!(!compare(&request("20261127T032000Z")));
    assert!(!compare(&request("20261131T031000Z")));
    let mut missing = request(TARGET_DATE);
    missing.headers.remove("x-amz-date");
    assert!(!compare(&missing));
    let mut repeated = request(TARGET_DATE);
    repeated
        .headers
        .get_mut("x-amz-date")
        .unwrap()
        .push(TARGET_DATE.into());
    assert!(!compare(&repeated));
}

#[test]
fn bucket_location_matches_both_the_signing_date_and_sigv4_structure() {
    let rules = serde_json::from_value::<Vec<request_sigv4::SigV4RequestRule>>(json!([{
        "host": HOST,
        "method": "GET",
        "path": "/wegent-archives",
        "query": "location=",
        "authorization": {"kind": "aws_sigv4"}
    }]))
    .unwrap();
    let endpoint = Endpoint {
        host: "s3.hj4.1.intra.weibo.com".into(),
        port: 9100,
    };
    let signed = |date: &str, credential_date: &str, signature: &str| {
        let mut message = request(date);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential=test-key/{credential_date}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={signature}"
        );
        message
            .headers
            .insert("authorization".into(), vec![authorization]);
        message
    };
    let source = request_sigv4::request(
        &rules,
        &endpoint,
        Arc::new(signed(SOURCE_DATE, "20261126", &"a".repeat(64))),
        Some(&json!({"scheme":"fake_ip_http", "response_status":200})),
    )
    .unwrap();
    let clocks = clocks();
    let binding = binding(source.as_ref(), clocks, &[]).unwrap().unwrap();
    let prepared = crate::value_extensions::prepare_message(source.as_ref(), &[binding]).unwrap();
    let contracts = crate::value_extensions::strict_values();
    let compare = |target: RequestMessage| {
        let target = request_sigv4::request(&rules, &endpoint, Arc::new(target), None).unwrap();
        prepared
            .compare(target.as_ref(), clocks, contracts.metadata())
            .unwrap()
            .passed()
    };
    let mut valid = signed(TARGET_DATE, "20261127", &"b".repeat(64));
    valid.headers.insert("accept".into(), vec!["*/*".into()]);
    assert!(compare(valid));
    assert!(!compare(signed(TARGET_DATE, "20261126", &"b".repeat(64))));
    assert!(!compare(signed(
        "20261127T032000Z",
        "20261127",
        &"b".repeat(64)
    )));
    let mut wrong_query = signed(TARGET_DATE, "20261127", &"b".repeat(64));
    wrong_query.uri = "/wegent-archives?location".into();
    assert!(!compare(wrong_query));
}
