use super::*;
use crate::interaction::model::{InputTranscript, Protocol};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

#[tokio::test]
async fn publication_encrypts_only_configured_headers_across_interaction_protocols() {
    for protocol in [
        Protocol::SocketIo,
        Protocol::WebSocket,
        Protocol::Sse,
        Protocol::Ndjson,
        Protocol::RawStream,
    ] {
        for encrypted in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let local = temp.path().join(".traffic-e2e/local");
            let mut recorder = Recorder::new(local.join("artifacts/recordings"))
                .await
                .unwrap();
            if encrypted {
                let key = std::env::var(crate::request_headers::ENCRYPTION_KEY_ENV)
                    .map(|value| STANDARD.decode(value).unwrap().try_into().unwrap())
                    .unwrap_or([7; 32]);
                let key_path = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
                std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
                std::fs::write(key_path, STANDARD.encode(key)).unwrap();
                recorder.request_header_capture =
                    crate::request_headers::RequestHeaderCapture::with_key(
                        &["Authorization".into()],
                        &[],
                        &key,
                    );
            }
            let headers = hyper::HeaderMap::from_iter([
                (
                    hyper::header::AUTHORIZATION,
                    "Bearer header-secret".parse().unwrap(),
                ),
                (
                    hyper::header::COOKIE,
                    "session=visible-cookie".parse().unwrap(),
                ),
            ]);
            let mut input = request();
            input.uri = "/socket.io/?token=visible-query".into();
            input.headers = recorder.capture_request_headers(&headers).unwrap();
            input.body = capture_case_body(b"visible request body", 1024, 1024, None);
            let mut program = InputTranscript::new(protocol, Default::default());
            program.actions = serde_json::from_value(json!([
                {"sequence":1,"offset_ms":0,"action":{"kind":"message","message":{"kind":"text","data":"visible input"}}},
                {"sequence":2,"offset_ms":1,"action":{"kind":"upgrade","uri":"/socket.io/?sid=visible-sid","headers":input.headers}},
                {"sequence":3,"offset_ms":2,"action":{"kind":"close","code":1000,"reason":"visible client close"}}
            ])).unwrap();
            input.interaction = Some(program);
            let mut response = json_response(b"duplicate stream body");
            response
                .headers
                .as_mut()
                .unwrap()
                .insert("set-cookie".into(), vec!["visible=response-cookie".into()]);
            let observation = json!({"version":1,"protocol":protocol,"events":[
                {"sequence":1,"offset_ms":1,"heartbeat":false,"message":{"kind":"text","data":"visible output"}},
                {"sequence":2,"offset_ms":2,"heartbeat":false,"message":{"kind":"binary","data":"AP8="}}
            ],"end":{"reason":"client_close","offset_ms":3,"clean":true,"pending":[],
                "partial_message":{"kind":"binary","data":"AP8="},
                "close":{"code":1000,"reason":"visible server close"}}});
            response.interaction = Some(serde_json::from_value(observation.clone()).unwrap());
            let case = CaseContext {
                id: Uuid::new_v4(),
                rule_name: "plaintext".into(),
                uri_group: None,
            };
            let original = serde_json::to_value(&input).unwrap();
            finalize_http_case(&recorder, &case, input, response, None)
                .await
                .unwrap();
            let request_path = recorder.case_dir(&case).join("request.json");
            let stored: Value =
                serde_json::from_slice(&std::fs::read(&request_path).unwrap()).unwrap();
            assert_eq!(stored, original);
            assert_eq!(
                stored["headers"]["authorization"][0]
                    .as_str()
                    .unwrap()
                    .starts_with("traffic-e2e:enc:"),
                encrypted
            );
            assert_eq!(stored["headers"]["cookie"][0], "session=visible-cookie");
            assert_eq!(stored["uri"], "/socket.io/?token=visible-query");
            assert_eq!(stored["body"]["data"], "visible request body");
            assert!(stored.get("private_headers").is_none());
            assert_eq!(
                crate::request_headers::has_encrypted_request_headers(&stored),
                encrypted
            );
            let decoded: Value = serde_json::from_slice(
                &crate::request_headers::load_request_file(&request_path).unwrap(),
            )
            .unwrap();
            assert_eq!(
                decoded["headers"]["authorization"][0],
                "Bearer header-secret"
            );
            assert_eq!(
                decoded["interaction"]["actions"][1]["action"]["headers"]["authorization"][0],
                "Bearer header-secret"
            );
            let expected: Value = serde_json::from_slice(
                &std::fs::read(recorder.case_dir(&case).join("expected-response.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(expected["interaction"], observation);
            assert_eq!(
                expected["headers"]["set-cookie"][0],
                "visible=response-cookie"
            );
            assert!(expected.get("private_interaction_output").is_none());
            assert_eq!(expected["body"]["data"], "");
        }
    }
}
