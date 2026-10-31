use super::*;
use crate::interaction::model::{
    EndObservation, InputTranscript, OutputObservation, TRANSCRIPT_VERSION,
};
use crate::interaction::policy::InteractionPolicy;
use serde_json::json;
use uuid::Uuid;

async fn files(root: &Path, protocol: Protocol) -> Vec<RecordedReference> {
    let input = InputTranscript::new(protocol, InteractionPolicy::default());
    let output = OutputObservation {
        version: TRANSCRIPT_VERSION,
        protocol,
        events: vec![],
        end: EndObservation {
            reason: EndReason::ClientClose,
            offset_ms: 400,
            pending: vec![3],
            clean: true,
            partial_message: None,
            close: None,
        },
    };
    tokio::fs::write(
        root.join("request.json"),
        json!({"interaction":input}).to_string(),
    )
    .await
    .unwrap();
    tokio::fs::write(root.join("expected-response.json"),
        json!({"duration_ms":500,"interaction":output,"status":101,"body":{"data":"oracle-not-a-target-input"}}).to_string())
        .await.unwrap();
    let connection = Uuid::new_v4();
    let exchange = json!({"event_type":"redis_exchange", "connection_id":connection,"sequence":16});
    tokio::fs::write(root.join("dependencies.jsonl"), format!("{exchange}\n"))
        .await
        .unwrap();
    vec![RecordedReference::Redis {
        connection_id: connection,
        sequence: 16,
    }]
}

#[tokio::test]
async fn clean_native_interactions_retain_original_case_refs_without_a_sidecar() {
    for protocol in [Protocol::SocketIo, Protocol::WebSocket] {
        let temp = tempfile::tempdir().unwrap();
        let references = files(temp.path(), protocol).await;
        let original = tokio::fs::read(temp.path().join("dependencies.jsonl"))
            .await
            .unwrap();
        let tail = from_complete_source(temp.path(), Duration::from_millis(100))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail.request_timeout_ms, 600);
        assert_eq!(tail.interaction_post_input_ms, Some(500));
        assert_eq!(tail.references, references);
        assert!(!tail.source_stop_required);
        assert!(tail.cleanup_refs.is_empty());
        assert_eq!(
            tokio::fs::read(temp.path().join("dependencies.jsonl"))
                .await
                .unwrap(),
            original
        );
        assert!(
            !temp
                .path()
                .join("dependency-tail-observation.json")
                .exists()
        );
    }
}

#[tokio::test]
async fn redis_protocol_observations_do_not_become_interaction_business_tails() {
    let temp = tempfile::tempdir().unwrap();
    let references = files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("dependencies.jsonl");
    let original = tokio::fs::read_to_string(&path).await.unwrap();
    let control = json!({
        "event_type":"redis_exchange", "command":"CLIENT",
        "capture":{"semantic_required":false}
    });
    tokio::fs::write(&path, format!("{control}\n{original}"))
        .await
        .unwrap();
    let tail = from_complete_source(temp.path(), Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail.references, references);
}

#[tokio::test]
async fn source_post_input_allowance_uses_offsets_without_reading_message_bodies() {
    let temp = tempfile::tempdir().unwrap();
    files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("request.json");
    let mut request: Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    request["interaction"]["actions"] = json!([
        {"offset_ms":10,"action":{"kind":"message","message":{"data":"private-ignored"}}},
        {"offset_ms":400,"action":{"kind":"close"}}
    ]);
    tokio::fs::write(&path, request.to_string()).await.unwrap();
    let tail = from_complete_source(temp.path(), Duration::from_millis(100))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail.interaction_post_input_ms, Some(100));
    assert_eq!(tail.request_timeout_ms, 600);
    for offsets in [[400, 10], [10, 501]] {
        request["interaction"]["actions"][0]["offset_ms"] = offsets[0].into();
        request["interaction"]["actions"][1]["offset_ms"] = offsets[1].into();
        tokio::fs::write(&path, request.to_string()).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_millis(100))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn a_client_transport_end_retains_its_finite_cleanup_inventory_and_allowance() {
    for protocol in [Protocol::SocketIo, Protocol::WebSocket] {
        let temp = tempfile::tempdir().unwrap();
        let references = files(temp.path(), protocol).await;
        let path = temp.path().join("request.json");
        let mut request: Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        request["interaction"]["actions"] = json!([
            {"offset_ms":10,"action":{"kind":"message","message":{"data":"unread"}}},
            {"offset_ms":400,"action":{"kind":"transport_end","end":"reset"}}
        ]);
        tokio::fs::write(&path, request.to_string()).await.unwrap();
        let path = temp.path().join("expected-response.json");
        let mut response: Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        response["interaction"]["end"]["reason"] = "client_transport_end".into();
        tokio::fs::write(&path, response.to_string()).await.unwrap();
        let metadata = from_complete_source(temp.path(), Duration::from_millis(100))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(metadata.references, references);
        assert_eq!(metadata.interaction_post_input_ms, Some(100));
        assert_eq!(metadata.request_timeout_ms, 600);
        // A bare normal-looking end reason cannot invent a terminating input.
        request["interaction"]["actions"][1]["action"] = json!({"kind":"close"});
        tokio::fs::write(temp.path().join("request.json"), request.to_string())
            .await
            .unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_millis(100))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn incomplete_or_non_session_sources_do_not_prove_an_interaction_tail() {
    let temp = tempfile::tempdir().unwrap();
    files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("expected-response.json");
    let original: Value = serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    for (field, value) in [
        ("clean", json!(false)),
        ("reason", json!("cleanup_timeout")),
    ] {
        let mut response = original.clone();
        response["interaction"]["end"][field] = value;
        tokio::fs::write(&path, response.to_string()).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_secs(1))
                .await
                .unwrap()
                .is_none()
        );
    }
    files(temp.path(), Protocol::Sse).await;
    assert!(
        from_complete_source(temp.path(), Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
    tokio::fs::write(
        temp.path().join("request.json"),
        json!({"interaction":{"protocol":"socket_io"}}).to_string(),
    )
    .await
    .unwrap();
    assert!(
        from_complete_source(temp.path(), Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn malformed_or_incomplete_reference_inventories_fail_before_admission() {
    let temp = tempfile::tempdir().unwrap();
    files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("dependencies.jsonl");
    let original = tokio::fs::read_to_string(&path).await.unwrap();
    for contents in [
        format!("{original}{original}"),
        "{bad-json".into(),
        json!({"event_type":"redis_exchange","sequence":16}).to_string(),
    ] {
        tokio::fs::write(&path, contents).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
    tokio::fs::remove_file(&path).await.unwrap();
    assert!(
        from_complete_source(temp.path(), Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unsupported_legacy_footprints_do_not_claim_a_partial_tail_or_change_admission() {
    let temp = tempfile::tempdir().unwrap();
    files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("dependencies.jsonl");
    for event in [
        json!({"event_type":"redis_exchange","connection_id":Uuid::new_v4(),"sequence":16,"lifecycle_cleanup":true}),
        json!({"event_type":"kafka_produce"}),
    ] {
        tokio::fs::write(&path, event.to_string()).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_secs(1))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn original_protocol_identity_and_elapsed_time_are_validated() {
    let temp = tempfile::tempdir().unwrap();
    files(temp.path(), Protocol::SocketIo).await;
    let path = temp.path().join("expected-response.json");
    let original: Value = serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
    for value in [json!("web_socket"), json!("raw_stream")] {
        let mut response = original.clone();
        response["interaction"]["protocol"] = value;
        tokio::fs::write(&path, response.to_string()).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
    for value in [json!(-1), json!("500"), json!(1.5)] {
        let mut response = original.clone();
        response["duration_ms"] = value;
        tokio::fs::write(&path, response.to_string()).await.unwrap();
        assert!(
            from_complete_source(temp.path(), Duration::from_secs(1))
                .await
                .is_err()
        );
    }
}
