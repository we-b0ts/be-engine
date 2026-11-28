use super::*;
use crate::message::RequestMessage;
use bytes::Bytes;
use serde_json::json;
use std::collections::BTreeMap;

const HOST: &str = "s3.test:9100";
const PATH: &str = "/wegent-archives";
const URI: &str = "/wegent-archives?location=";
const HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";
const SOURCE_DATE: &str = "20261126T025500Z";
const TARGET_DATE: &str = "20261127T031000Z";

fn rule(query: Option<&str>) -> SigV4RequestRule {
    SigV4RequestRule {
        host: HOST.into(),
        method: Some("GET".into()),
        path: Some(PATH.into()),
        query: query.map(str::to_owned),
        authorization: SigV4Authorization::AwsSigv4 {},
    }
}

fn endpoint() -> Endpoint {
    Endpoint {
        host: "s3.test".into(),
        port: 9100,
    }
}

fn authorization(key: &str, scope: &str, headers: &str, signature: char) -> String {
    let signature = signature.to_string().repeat(64);
    format!("{ALGORITHM} Credential={key}/{scope}, SignedHeaders={headers}, Signature={signature}")
}

fn signed_request(date: &str, signature: char) -> RequestMessage {
    RequestMessage {
        method: "GET".into(),
        uri: URI.into(),
        headers: BTreeMap::from([
            ("Host".into(), vec![HOST.into()]),
            ("X-Amz-Date".into(), vec![date.into()]),
            (
                "X-Amz-Content-Sha256".into(),
                vec!["UNSIGNED-PAYLOAD".into()],
            ),
            (
                "Authorization".into(),
                vec![authorization(
                    "EXAMPLEACCESSKEY",
                    &format!("{}/us-east-1/s3/aws4_request", &date[..8]),
                    HEADERS,
                    signature,
                )],
            ),
        ]),
        body: Bytes::new(),
    }
}

fn project(message: RequestMessage, source: bool) -> Arc<dyn ProtocolMessage> {
    let record = json!({"scheme": "fake_ip_http", "response_status": 200});
    request(
        &[rule(Some("location="))],
        &endpoint(),
        Arc::new(message),
        source.then_some(&record),
    )
    .unwrap()
}

fn applies(request: &dyn ProtocolMessage) -> bool {
    request.as_any().is_some_and(|raw| raw.is::<SigV4Request>())
}

#[test]
fn signed_bucket_location_compares_scope_and_preserves_the_date_binding() {
    let source = project(signed_request(SOURCE_DATE, 'a'), true);
    let mut target = signed_request(TARGET_DATE, 'b');
    target.headers.insert("Accept".into(), vec!["*/*".into()]);
    let raw = target.headers["Authorization"][0].clone();
    let target = project(target, false);

    assert!(applies(source.as_ref()));
    assert!(applies(target.as_ref()));
    assert_eq!(amz_date(source.as_ref()), Some(SOURCE_DATE));
    assert_eq!(amz_date(target.as_ref()), Some(TARGET_DATE));
    let selector = json!({"kind": "header", "name": "x-amz-date"});
    assert_eq!(source.locate(&selector).unwrap(), ["/headers/x-amz-date/0"]);

    let source_projection = source.project().unwrap();
    let target_projection = target.project().unwrap();
    assert_eq!(source_projection.structure, target_projection.structure);
    assert_eq!(
        source_projection.values.keys().collect::<Vec<_>>(),
        target_projection.values.keys().collect::<Vec<_>>()
    );
    for (location, source_value) in source_projection.values {
        let target_value = &target_projection.values[&location];
        assert_eq!(
            source_value.matches(target_value),
            location != "/headers/x-amz-date/0",
            "{location}"
        );
    }

    assert_eq!(target_projection.values[AUTHORIZATION_LOCATION].bytes, raw);
    let raw_target = target
        .exact_request_alternative()
        .unwrap()
        .project()
        .unwrap();
    let source_authorization = &source.project().unwrap().values[AUTHORIZATION_LOCATION];
    assert!(!source_authorization.matches(&raw_target.values[AUTHORIZATION_LOCATION]));
    assert!(source.exact_request_alternative().is_none());
}

#[test]
fn invalid_signature_headers_stay_in_the_ordinary_exact_projection() {
    let original = signed_request(SOURCE_DATE, 'a').headers["Authorization"][0].clone();
    for altered in [
        original.replace("20261126/", "20261127/"),
        original.replace("/s3/aws4_request", "/s3/wrong"),
        original.replace("aws4_request", "aws4_request/extra"),
        original.replace(&"a".repeat(64), &"A".repeat(64)),
        original.replace(&"a".repeat(64), "0000"),
        original.replace(HEADERS, "host;x-amz-date;x-amz-content-sha256"),
        original.replace(HEADERS, "host;x-amz-date;x-other"),
        original.replace(HEADERS, "host;x-amz-date;x-amz-date"),
        original.replace(HEADERS, "host;x-amz-content-sha256"),
        format!("{original}, Unknown=bad"),
    ] {
        let mut message = signed_request(SOURCE_DATE, 'a');
        message
            .headers
            .insert("Authorization".into(), vec![altered]);
        assert!(!applies(project(message, false).as_ref()));
    }
    for name in ["authorization", "x-amz-date"] {
        let mut message = signed_request(SOURCE_DATE, 'a');
        message
            .headers
            .insert(name.into(), vec!["duplicate".into()]);
        assert!(!applies(project(message, false).as_ref()));
    }
    let mut message = signed_request(SOURCE_DATE, 'a');
    message
        .headers
        .insert("X-Amz-Date".into(), vec!["20261126T256000Z".into()]);
    assert!(amz_date(&message).is_none());
    assert!(!applies(project(message, true).as_ref()));
}

#[test]
fn signer_scope_and_signed_transport_header_values_remain_distinct() {
    let mut source = signed_request(SOURCE_DATE, 'a');
    source.headers.insert("Accept".into(), vec!["*/*".into()]);
    source.headers.insert(
        "Authorization".into(),
        vec![authorization(
            "EXAMPLEACCESSKEY",
            "20261126/us-east-1/s3/aws4_request",
            &format!("accept;{HEADERS}"),
            'a',
        )],
    );
    let source = project(source, true);
    let expected = source.project().unwrap();
    assert_eq!(expected.values["/headers/accept/0"].bytes, "*/*");
    assert_eq!(
        source
            .locate(&json!({"kind":"header", "name":"Accept"}))
            .unwrap(),
        ["/headers/accept/0"]
    );
    for (key, scope, signed) in [
        (
            "OTHEREXAMPLEKEY",
            "20261127/us-east-1/s3/aws4_request",
            format!("accept;{HEADERS}"),
        ),
        (
            "EXAMPLEACCESSKEY",
            "20261127/us-west-1/s3/aws4_request",
            format!("accept;{HEADERS}"),
        ),
        (
            "EXAMPLEACCESSKEY",
            "20261127/us-east-1/other/aws4_request",
            format!("accept;{HEADERS}"),
        ),
        (
            "EXAMPLEACCESSKEY",
            "20261127/us-east-1/s3/aws4_request",
            HEADERS.into(),
        ),
    ] {
        let mut target = signed_request(TARGET_DATE, 'b');
        target.headers.insert("Accept".into(), vec!["*/*".into()]);
        target.headers.insert(
            "Authorization".into(),
            vec![authorization(key, scope, &signed, 'b')],
        );
        let target = project(target, false);
        assert!(applies(target.as_ref()));
        assert!(
            !expected.values[AUTHORIZATION_LOCATION]
                .matches(&target.project().unwrap().values[AUTHORIZATION_LOCATION])
        );
    }
}

#[test]
fn route_matches_exact_endpoint_method_path_and_query_spelling() {
    for (uri, query, applies_rule) in [
        (URI, Some("location="), true),
        (URI, Some("location"), false),
        ("/wegent-archives?location", Some("location="), false),
        ("/archives?location=", Some("location="), false),
        (PATH, None, true),
        (PATH, Some(""), false),
        ("/wegent-archives?", Some(""), true),
        ("/wegent-archives?", None, false),
    ] {
        let rules = [rule(query)];
        validate_rules(&rules).unwrap();
        let mut message = signed_request(SOURCE_DATE, 'a');
        message.uri = uri.into();
        let projected = request(&rules, &endpoint(), Arc::new(message), None).unwrap();
        assert_eq!(
            applies(projected.as_ref()),
            applies_rule,
            "{uri}, {query:?}"
        );
    }
    let mut message = signed_request(SOURCE_DATE, 'a');
    message.method = "HEAD".into();
    assert!(!applies(project(message, false).as_ref()));
    let mut endpoint = endpoint();
    endpoint.port = 9200;
    let projected = request(
        &[rule(Some("location="))],
        &endpoint,
        Arc::new(signed_request(SOURCE_DATE, 'a')),
        None,
    )
    .unwrap();
    assert!(!applies(projected.as_ref()));
    assert!(validate_rules(&[rule(None), rule(None)]).is_err());
}

#[test]
fn endpoint_scope_selects_each_signed_request_with_its_full_route() {
    let host_only = json!({"host": HOST, "authorization": {"kind": "aws_sigv4"}});
    let rule: SigV4RequestRule = serde_json::from_value(host_only.clone()).unwrap();
    assert_eq!(serde_json::to_value(&rule).unwrap(), host_only);
    validate_rules(std::slice::from_ref(&rule)).unwrap();
    for (method, uri) in [
        ("GET", URI),
        ("HEAD", PATH),
        (
            "HEAD",
            "/wegent-archives/workspace-archives/task/archive.tar.gz",
        ),
    ] {
        let mut raw = signed_request(SOURCE_DATE, 'a');
        raw.method = method.into();
        raw.uri = uri.into();
        let original = raw.project().unwrap();
        let selected = request(
            std::slice::from_ref(&rule),
            &endpoint(),
            Arc::new(raw),
            None,
        )
        .unwrap();
        assert!(applies(selected.as_ref()), "{method} {uri}");

        let projected = selected.project().unwrap();
        assert_eq!(projected.structure["method"], original.structure["method"]);
        assert_eq!(projected.structure["uri"], original.structure["uri"]);
        for (location, value) in original.values {
            if location != "/headers/authorization/0" {
                assert_eq!(projected.values[&location].bytes, value.bytes, "{location}");
            }
        }
    }
    let mut unsigned = signed_request(SOURCE_DATE, 'a');
    unsigned.headers.remove("Authorization");
    let unsigned = request(
        std::slice::from_ref(&rule),
        &endpoint(),
        Arc::new(unsigned),
        None,
    )
    .unwrap();
    assert!(!applies(unsigned.as_ref()));

    let mut other_endpoint = endpoint();
    other_endpoint.port = 9200;
    let unselected = request(
        &[rule],
        &other_endpoint,
        Arc::new(signed_request(SOURCE_DATE, 'a')),
        None,
    )
    .unwrap();
    assert!(!applies(unselected.as_ref()));
}

#[test]
fn endpoint_scope_and_complete_routes_can_coexist() {
    let host_only = SigV4RequestRule {
        method: None,
        path: None,
        ..rule(None)
    };
    validate_rules(&[host_only.clone(), rule(None)]).unwrap();
    assert!(validate_rules(&[host_only.clone(), host_only.clone()]).is_err());

    for (method, path, query) in [
        (Some("GET"), None, None),
        (None, Some(PATH), None),
        (None, None, Some("location=")),
        (Some("GET"), None, Some("location=")),
        (None, Some(PATH), Some("location=")),
    ] {
        let partial = SigV4RequestRule {
            method: method.map(str::to_owned),
            path: path.map(str::to_owned),
            query: query.map(str::to_owned),
            ..host_only.clone()
        };
        assert!(validate_rules(&[partial]).is_err());
    }
}

#[test]
fn authorization_policy_has_a_closed_discriminator() {
    let expected = json!({"kind":"aws_sigv4"});
    assert_eq!(
        serde_json::to_value(SigV4Authorization::AwsSigv4 {}).unwrap(),
        expected
    );
    assert!(
        serde_json::from_value::<SigV4Authorization>(json!({
            "kind": "aws_sigv4", "verify": false
        }))
        .is_err()
    );
}

#[test]
fn valid_date_is_available_without_sigv4_and_through_tls() {
    let mut request = signed_request(SOURCE_DATE, 'a');
    request.headers.remove("Authorization");
    assert_eq!(amz_date(&request), Some(SOURCE_DATE));
    assert!(!applies(project(request, false).as_ref()));

    let tls =
        crate::request_metadata::tls_target_request(Arc::new(signed_request(TARGET_DATE, 'b')));
    let target = super::request(&[rule(Some("location="))], &endpoint(), tls, None).unwrap();
    assert!(applies(target.as_ref()));
    assert_eq!(amz_date(target.as_ref()), Some(TARGET_DATE));
}
