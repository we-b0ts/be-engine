use super::*;
use chrono::Utc;
use serde_json::json;

#[test]
fn target_interaction_artifacts_keep_plaintext_events_and_headers_without_a_key() {
    for protocol in ["socket_io", "web_socket", "sse", "ndjson", "raw_stream"] {
        let observation = json!({"version":1,"protocol":protocol,"events":[
            {"sequence":1,"offset_ms":1,"heartbeat":false,"message":{"kind":"text","data":"readable target event"}},
            {"sequence":2,"offset_ms":2,"heartbeat":false,"message":{"kind":"binary","data":"AP8="}}
        ],"end":{"reason":"client_close","offset_ms":3,"clean":true,"pending":[],
            "partial_message":{"kind":"binary","data":"AP8="},
            "close":{"code":1000,"reason":"readable close"}}});
        let now = Utc::now();
        let output = PrimaryOutput {
            api: ApiIdentity::Http {
                method: "GET".into(),
                route: "/socket.io/".into(),
            },
            clocks: CaseClock {
                source_request_started_at: Some(now),
                target_request_started_at: now,
            },
            response_completed_at: Some(now),
            observation: PrimaryObservation::Http(Box::new(
                crate::recorded_request::RecordedHttpResponse {
                    interaction_started_at: Some(now),
                    request_sent_at: now,
                    response_completed_at: now,
                    request_rules: Vec::new(),
                    request_headers: Default::default(),
                    status: hyper::StatusCode::OK,
                    headers: HeaderMapSnapshot::from([(
                        "set-cookie".into(),
                        vec!["readable-cookie".into()],
                    )]),
                    body: bytes::Bytes::from_static(b"duplicate body"),
                    sse_observation: None,
                    interaction: Some(serde_json::from_value(observation.clone()).unwrap()),
                },
            )),
        };
        let artifact = output.artifact().unwrap();
        assert_eq!(artifact["interaction"], observation);
        assert_eq!(artifact["headers"]["set-cookie"][0], "readable-cookie");
        assert!(artifact.get("private_interaction_output").is_none());
        assert_eq!(artifact["body"]["data"], "");
    }
}
