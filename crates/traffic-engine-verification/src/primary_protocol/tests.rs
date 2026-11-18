use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn context<'a>(request: &'a Path, session: &'a Path, http: &'a str) -> CaseExecutionContext<'a> {
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
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 1024,
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
            .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 6\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let body_released_at = chrono::Utc::now();
        stream.write_all(b"actual").await.unwrap();
        body_released_at
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
        .execute(&context(&request_path, &session, &origin))
        .await
        .unwrap();
    let artifact = output.artifact().unwrap();
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
    let completed_at: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(artifact["response_completed_at"].clone()).unwrap();
    assert!(completed_at >= server.await.unwrap());
    assert!(completed_at > output.clocks.target_request_started_at);
    assert!(completed_at <= chrono::Utc::now());
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
    assert!(PrimaryProtocol::from_recorded(&bytes).is_err());
    for missing in ["protocol_version", "frame"] {
        let mut partial = complete.clone();
        partial.as_object_mut().unwrap().remove(missing);
        assert!(PrimaryProtocol::from_recorded(&serde_json::to_vec(&partial).unwrap()).is_err());
    }
    let mut invalid = complete;
    invalid["frame"]["data"] = STANDARD.encode(b"MOTAN is also a valid HTTP method").into();
    assert!(PrimaryProtocol::from_recorded(&serde_json::to_vec(&invalid).unwrap()).is_err());
}
