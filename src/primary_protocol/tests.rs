use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn context<'a>(
    request: &'a Path,
    session: &'a Path,
    http: &'a str,
    motan: Option<&'a str>,
) -> CaseExecutionContext<'a> {
    CaseExecutionContext {
        case_id: "00000000-0000-0000-0000-000000000123",
        session_path: session,
        request_path: request,
        request_rules: Arc::new(crate::request_rules::RequestRuleRuntime::with_test_keys(
            vec![],
        )),
        dependency_failure: None,
        settings: ExecutionSettings {
            http_origin: http,
            motan_upstream: motan,
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 1024,
            motan_limits: motan_protocol::Limits::default(),
            socketio_timing: Default::default(),
        },
        deadline: tokio::time::Instant::now() + Duration::from_secs(2),
    }
}

#[tokio::test]
async fn http_static_adapter_executes_real_input_and_retains_independent_clocks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.extend_from_slice(&byte);
        }
        assert!(head.starts_with(b"GET /api/42 HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 201 Created\r\nContent-Length: 6\r\nConnection: close\r\n\r\nactual",
            )
            .await
            .unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let request_path = temp.path().join("request.json");
    let session = temp.path().join("session.json");
    std::fs::write(
        temp.path().join("expected-response.json"),
        "NEVER_EXECUTE_EXPECTED",
    )
    .unwrap();
    let bytes = serde_json::to_vec(&json!({"method":"GET","uri":"/api/42","api_pattern":"/api/{id}","timestamp":"2020-01-01T00:00:00Z","headers":{},"body":{"encoding":"utf8","data":"","truncated":false}})).unwrap();
    let input = PrimaryProtocol::from_recorded(&bytes).unwrap();
    let output = input
        .execute(&context(&request_path, &session, &origin, None))
        .await
        .unwrap();
    let artifact = output.artifact(&temp.path().join("actual.json")).unwrap();
    assert_eq!(artifact["status"], 201);
    assert_eq!(artifact["body"]["data"], "actual");
    assert_eq!(
        artifact["primary"]["api"],
        json!({"protocol":"http","method":"GET","route":"/api/{id}"})
    );
    assert_eq!(
        artifact["primary"]["clocks"]["case"]["source"],
        "2020-01-01T00:00:00Z"
    );
    assert_ne!(
        artifact["primary"]["clocks"]["case"]["target"],
        artifact["primary"]["clocks"]["case"]["source"]
    );
    server.await.unwrap();
}

fn motan2_request() -> Vec<u8> {
    let mut metadata = motan_protocol::Metadata::new();
    metadata.insert(motan_protocol::META_GROUP, "contract-group");
    metadata.insert(motan_protocol::META_PATH, "example.EchoService");
    metadata.insert(motan_protocol::META_METHOD, "echo");
    metadata.insert(motan_protocol::META_METHOD_DESC, "java.lang.String");
    motan_protocol::FrameBuilder::request(91)
        .metadata(metadata)
        .serialization(0)
        .encode()
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn motan_versions_use_real_wire_and_typed_identity_without_expected_evidence() {
    for (version, raw) in [
        (
            "motan1",
            include_bytes!("../../tests/fixtures/motan/motan1-request.bin").to_vec(),
        ),
        ("motan2", motan2_request()),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let original = raw.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0; original.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, original);
            let mut response = Vec::new();
            motan_protocol::encode_empty_response(
                motan_protocol::parse_frame_ref(&received, motan_protocol::Limits::default())
                    .unwrap(),
                &mut response,
                motan_protocol::Limits::default(),
            )
            .unwrap();
            stream.write_all(&response).await.unwrap();
            response
        });
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("request.json");
        let session = temp.path().join("session.json");
        std::fs::write(
            temp.path().join("expected-response.json"),
            "NEVER_EXECUTE_EXPECTED",
        )
        .unwrap();
        let bytes = serde_json::to_vec(&json!({"method":"MOTAN","uri":"/rpc/echo","protocol_version":version,"timestamp":"2020-01-01T00:00:00Z","frame":{"encoding":"base64","data":STANDARD.encode(raw),"truncated":false}})).unwrap();
        let input = PrimaryProtocol::from_recorded(&bytes).unwrap();
        assert!(matches!(
            input.api(),
            ApiIdentity::Motan {
                interface: Some(_),
                ..
            }
        ));
        let output = input
            .execute(&context(
                &path,
                &session,
                "http://127.0.0.1:1",
                Some(&address),
            ))
            .await
            .unwrap();
        let PrimaryObservation::Motan { response_frame, .. } = &output.observation else {
            panic!("native Motan output required")
        };
        assert_eq!(*response_frame, server.await.unwrap());
        assert_eq!(
            output.artifact(&temp.path().join("actual.json")).unwrap()["primary"]["api"]["protocol"],
            "motan"
        );
    }
}

#[test]
fn native_version_and_primary_role_cannot_be_guessed_from_a_payload() {
    let raw = motan2_request();
    let bytes = serde_json::to_vec(&json!({"method":"MOTAN","uri":"/rpc/echo","protocol_version":"motan1","frame":{"encoding":"base64","data":STANDARD.encode(raw),"truncated":false}})).unwrap();
    assert!(PrimaryProtocol::from_recorded(&bytes).is_err());
    assert!(
        contract(ProtocolKind::Mysql)
            .validate_version(NativeProtocolVersion::MysqlClassic)
            .is_err()
    );
}

#[test]
fn an_http_method_named_motan_does_not_declare_a_native_rpc_input() {
    let bytes = serde_json::to_vec(&json!({"method":"MOTAN","uri":"/api/echo"})).unwrap();
    let input = PrimaryProtocol::from_recorded(&bytes).unwrap();
    assert_eq!(input.kind(), ProtocolKind::Http);
    assert_eq!(
        input.api(),
        &ApiIdentity::Http {
            method: "MOTAN".into(),
            route: "/api/echo".into()
        }
    );
}

#[test]
fn partial_native_declarations_and_invalid_native_frames_are_rejected() {
    let raw = motan2_request();
    let complete = json!({"method":"MOTAN","uri":"/rpc/echo","protocol_version":"motan2","frame":{"encoding":"base64","data":STANDARD.encode(raw),"truncated":false}});
    let bytes = serde_json::to_vec(&complete).unwrap();
    assert_eq!(
        PrimaryProtocol::from_recorded(&bytes).unwrap().kind(),
        ProtocolKind::Motan
    );
    for missing in ["protocol_version", "frame"] {
        let mut partial = complete.clone();
        partial.as_object_mut().unwrap().remove(missing);
        assert!(PrimaryProtocol::from_recorded(&serde_json::to_vec(&partial).unwrap()).is_err());
    }
    let mut invalid = complete;
    invalid["frame"]["data"] = STANDARD.encode(b"MOTAN is also a valid HTTP method").into();
    assert!(PrimaryProtocol::from_recorded(&serde_json::to_vec(&invalid).unwrap()).is_err());
}
