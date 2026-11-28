use std::sync::Arc;

use serde_json::json;
use traffic_engine_policy::policy::parse_and_compile_policy;
use traffic_engine_verification::policy::runtime::RequestContracts;
use traffic_policy_value::{PreparedMessage, host::ValueRuleHost};
use traffic_protocol::{ProtocolId, connection::Endpoint};
use traffic_protocol_http::message::RequestMessage;

const HOST: &str = "s3.hj4.1.intra.weibo.com";

fn request(method: &str, uri: &str, signature: char) -> RequestMessage {
    let signature = signature.to_string().repeat(64);
    RequestMessage {
        method: method.into(),
        uri: uri.into(),
        headers: [
            ("host".into(), vec![format!("{HOST}:9100")]),
            ("x-amz-date".into(), vec!["20261126T025500Z".into()]),
            ("authorization".into(), vec![format!("AWS4-HMAC-SHA256 Credential=test-key/20261126/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={signature}")]),
        ].into(),
        body: Default::default(),
    }
}

#[test]
fn compiled_policy_matches_sigv4_only_on_the_declared_http_request() -> anyhow::Result<()> {
    let compiled = parse_and_compile_policy(
        r#"format: traffic-policy/v3
http:
  requests:
    - host: s3.hj4.1.intra.weibo.com:9100
      method: GET
      path: /wegent-archives
      query: 'location='
      authorization: {kind: aws_sigv4}
"#,
    )?;
    let mut contracts = RequestContracts::default();
    contracts.configure_compiled(Some(Arc::new(compiled)))?;
    let protocol = ProtocolId::new("http");
    let endpoint = Endpoint {
        host: HOST.into(),
        port: 9100,
    };
    let record = json!({"scheme": "fake_ip_http", "response_status": 200});

    for (uri, matches) in [
        ("/wegent-archives?location=", true),
        ("/wegent-archives?location", false),
    ] {
        let source = contracts.native_request_projection(
            protocol,
            &endpoint,
            Arc::new(request("GET", uri, 'a')),
            Some(&record),
        )?;
        let target = contracts.native_request_projection(
            protocol,
            &endpoint,
            Arc::new(request("GET", uri, 'b')),
            None,
        )?;
        let prepared =
            PreparedMessage::compile(source.as_ref(), &[], traffic_extensions::codecs())?;
        assert_eq!(
            prepared
                .compare(target.as_ref(), Default::default(), contracts.metadata())?
                .passed(),
            matches,
            "{uri}"
        );
    }
    Ok(())
}

#[test]
fn endpoint_sigv4_applies_to_each_recorded_route_and_preserves_its_request() -> anyhow::Result<()> {
    let compiled = parse_and_compile_policy(
        r#"format: traffic-policy/v3
http:
  requests:
    - host: s3.hj4.1.intra.weibo.com:9100
      authorization: {kind: aws_sigv4}
"#,
    )?;
    let mut contracts = RequestContracts::default();
    contracts.configure_compiled(Some(Arc::new(compiled)))?;
    let protocol = ProtocolId::new("http");
    let endpoint = Endpoint {
        host: HOST.into(),
        port: 9100,
    };
    let other_endpoint = Endpoint {
        host: HOST.into(),
        port: 9101,
    };
    let record = json!({"scheme": "fake_ip_http"});

    for (method, uri) in [
        ("GET", "/wegent-archives?location="),
        ("HEAD", "/wegent-archives"),
        (
            "HEAD",
            "/wegent-archives/workspace-archives/465918052421380/archive.tar.gz",
        ),
    ] {
        let source = contracts.native_request_projection(
            protocol,
            &endpoint,
            Arc::new(request(method, uri, 'a')),
            Some(&record),
        )?;
        let prepared =
            PreparedMessage::compile(source.as_ref(), &[], traffic_extensions::codecs())?;
        let compare = |endpoint: &Endpoint, method: &str, uri: &str| -> anyhow::Result<bool> {
            let target = contracts.native_request_projection(
                protocol,
                endpoint,
                Arc::new(request(method, uri, 'b')),
                None,
            )?;
            Ok(prepared
                .compare(target.as_ref(), Default::default(), contracts.metadata())?
                .passed())
        };
        assert!(compare(&endpoint, method, uri)?);
        assert!(!compare(&other_endpoint, method, uri)?);
        assert!(!compare(&endpoint, "PUT", uri)?);
        assert!(!compare(
            &endpoint,
            method,
            &uri.replace("wegent-archives", "other-archives")
        )?);
        assert!(!compare(
            &endpoint,
            method,
            &format!("{uri}{}x=1", if uri.contains('?') { "&" } else { "?" })
        )?);
    }
    Ok(())
}

#[test]
fn sigv4_is_automatic_when_policy_omits_the_rule() -> anyhow::Result<()> {
    let policy = parse_and_compile_policy(
        "format: traffic-policy/v3\nhttp:\n  headers:\n    x-amz-date: {kind: time, formats: [amz_date]}\n",
    )?;
    let mut explicit_http = RequestContracts::default();
    explicit_http.configure_compiled(Some(Arc::new(policy)))?;
    let hosts: [Arc<dyn ValueRuleHost>; 3] = [
        traffic_engine_replay::value_extensions::strict_values(),
        Arc::new(RequestContracts::default()),
        Arc::new(explicit_http),
    ];
    let endpoint = Endpoint {
        host: HOST.into(),
        port: 9100,
    };
    let record = json!({"scheme": "fake_ip_http"});
    let uri = "/wegent-archives?location=";

    for contracts in hosts {
        let project = |message, source| {
            contracts.native_request_projection(
                ProtocolId::new("http"),
                &endpoint,
                Arc::new(message),
                source,
            )
        };
        let source = project(request("GET", uri, 'a'), Some(&record))?;
        let prepared =
            PreparedMessage::compile(source.as_ref(), &[], traffic_extensions::codecs())?;
        let compare = |target| -> anyhow::Result<bool> {
            let target = project(target, None)?;
            Ok(prepared
                .compare(target.as_ref(), Default::default(), contracts.metadata())?
                .passed())
        };

        assert!(compare(request("GET", uri, 'a'))?);
        assert!(compare(request("GET", uri, 'b'))?);
        assert!(!compare(request("GET", uri, 'z'))?);
        assert!(!compare(request("HEAD", uri, 'b'))?);
        assert!(!compare(request("GET", "/other?location=", 'b'))?);
        assert!(!compare(request(
            "GET",
            "/wegent-archives?location=else",
            'b'
        ))?);

        let mut missing = request("GET", uri, 'b');
        missing.headers.remove("authorization");
        assert!(!compare(missing)?);

        let mut other_key = request("GET", uri, 'b');
        let authorization = &mut other_key.headers.get_mut("authorization").unwrap()[0];
        *authorization = authorization.replace("test-key", "other-key");
        assert!(!compare(other_key)?);

        let mut malformed = request("GET", uri, 'z');
        let exact = project(request("GET", uri, 'z'), Some(&record))?;
        let prepared = PreparedMessage::compile(exact.as_ref(), &[], traffic_extensions::codecs())?;
        let exact_target = project(request("GET", uri, 'z'), None)?;
        assert!(
            prepared
                .compare(
                    exact_target.as_ref(),
                    Default::default(),
                    contracts.metadata()
                )?
                .passed()
        );

        malformed
            .headers
            .insert("authorization".into(), vec!["Bearer example".into()]);
        assert!(!compare(malformed)?);
    }
    Ok(())
}
