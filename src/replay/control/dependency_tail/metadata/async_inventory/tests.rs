use super::*;
use serde_json::json;

#[tokio::test]
async fn source_response_selects_the_proven_http_end_without_requiring_background() {
    let temp = tempfile::tempdir().unwrap();
    let rules = BTreeMap::from([("POST /jobs".into(), serde_json::from_value(json!([
        {"when_response":{"/status":"in_progress"},"end":[{"redis":{"operation":"DEL","key":"done:*","occurrence":2}}]},
        {"when_response":{"/status":"queued"},"end":[{"http":{"method":"POST","endpoint":"executor.test:80","path":"/submit"}}]}
    ])).unwrap())]);
    tokio::fs::write(
        temp.path().join("request.json"),
        json!({
            "method":"POST","uri":"/jobs","body":{"encoding":"utf8","data":"{}","truncated":false}
        })
        .to_string(),
    )
    .await
    .unwrap();
    let response = |status| {
        json!({
            "status":200,"body":{"encoding":"utf8","data":json!({"status":status}).to_string(),"truncated":false}
        })
    };
    tokio::fs::write(
        temp.path().join("expected-response.json"),
        response("queued").to_string(),
    )
    .await
    .unwrap();
    let exchange_id = uuid::Uuid::new_v4();
    let mut event = json!({
        "event_type":"http_exchange","id":exchange_id,"outcome":"response",
        "method":"POST","uri":"/submit","authority":"executor.test","scheme":"http","response_status":202
    });
    tokio::fs::write(temp.path().join("dependencies.jsonl"), event.to_string())
        .await
        .unwrap();
    let metadata = from_complete_source(temp.path(), &rules, Duration::from_secs(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        metadata.references,
        [RecordedReference::Http { exchange_id }]
    );
    assert!(!metadata.source_stop_required);
    event["uri"] = json!("/unrelated");
    tokio::fs::write(temp.path().join("dependencies.jsonl"), event.to_string())
        .await
        .unwrap();
    let error = from_complete_source(temp.path(), &rules, Duration::from_secs(2))
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("no proven completion"));
    tokio::fs::write(
        temp.path().join("expected-response.json"),
        response("completed").to_string(),
    )
    .await
    .unwrap();
    assert!(
        from_complete_source(temp.path(), &rules, Duration::from_secs(2))
            .await
            .unwrap()
            .is_none()
    );
}
