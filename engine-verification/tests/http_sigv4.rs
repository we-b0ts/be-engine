use std::sync::Arc;

use serde_json::json;
use traffic_engine_policy::policy::parse_and_compile_policy;
use traffic_engine_verification::policy::runtime::RequestContracts;
use traffic_policy_value::{PreparedMessage, host::ValueRuleHost};
use traffic_protocol::{ProtocolId, connection::Endpoint};
use traffic_protocol_http::message::RequestMessage;

const HOST: &str = "s3.hj4.1.intra.weibo.com";

fn request(uri: &str, signature: char) -> RequestMessage {
    let signature = signature.to_string().repeat(64);
    RequestMessage {
        method: "GET".into(),
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
            Arc::new(request(uri, 'a')),
            Some(&record),
        )?;
        let target = contracts.native_request_projection(
            protocol,
            &endpoint,
            Arc::new(request(uri, 'b')),
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
