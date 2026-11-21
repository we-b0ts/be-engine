use super::*;
use serde_json::json;

#[tokio::test]
async fn source_response_selects_the_proven_http_end_without_requiring_background() {
    let temp = tempfile::tempdir().unwrap();
    let rules: BTreeMap<String, crate::policy::AsyncApiRules> = BTreeMap::from([("POST /jobs".into(), serde_json::from_value(json!([
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
    let metadata = from_complete_source(
        temp.path(),
        &rules.clone().into(),
        Duration::from_secs(2),
        crate::protocols::default_providers().evidence(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        metadata.references,
        [RecordedReference::exchange("http", exchange_id)]
    );
    assert!(!metadata.source_stop_required);
    event["uri"] = json!("/unrelated");
    tokio::fs::write(temp.path().join("dependencies.jsonl"), event.to_string())
        .await
        .unwrap();
    let error = from_complete_source(
        temp.path(),
        &rules.clone().into(),
        Duration::from_secs(2),
        crate::protocols::default_providers().evidence(),
    )
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
        from_complete_source(
            temp.path(),
            &rules.clone().into(),
            Duration::from_secs(2),
            crate::protocols::default_providers().evidence()
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[test]
fn end_only_source_inventory_requires_every_native_intermediate_effect() {
    use traffic_protocol::DependencyProvider;

    let rules: BTreeMap<String, crate::policy::AsyncApiRules> = BTreeMap::from([(
        "POST /jobs".into(),
        serde_json::from_value(json!([
            {"end":[{"http":{"method":"POST","endpoint":"executor.test:80","path":"/done"}}]}
        ]))
        .unwrap(),
    )]);
    let scope = crate::recorder::async_api::AsyncScope::for_primary(
        &rules,
        &"POST".parse().unwrap(),
        &"/jobs".parse().unwrap(),
        b"{}",
    )
    .unwrap();
    assert!(scope.select_response(Some(&json!({}))).0);
    let connection = uuid::Uuid::new_v4();
    let end = uuid::Uuid::new_v4();
    let intermediate = |ordinal| {
        json!({
            "event_type":traffic_protocol_fixture::EVENT,"channel":connection,"ordinal":ordinal,
            "peer":{"address":"native.test","port":7001},"input":[],"reply":[],
            "latency_micros":0,"wire_complete":true
        })
    };
    let rows = vec![
        intermediate(1),
        intermediate(2),
        json!({"event_type":"control_observation","capture":{"semantic_required":false}}),
        intermediate(3),
        json!({"event_type":"http_exchange","id":end,"outcome":"response","method":"POST","uri":"/done","authority":"executor.test","scheme":"http","response_status":200}),
    ];
    let mut evidence = crate::protocols::default_providers().evidence().clone();
    evidence
        .register(
            traffic_protocol_fixture::NAME,
            traffic_protocol_fixture::Provider.evidence().unwrap(),
        )
        .unwrap();
    let raw = rows
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    let (refs, stop) = complete_inventory(&scope, raw.as_bytes(), &evidence).unwrap();
    assert_eq!(
        refs.len(),
        4,
        "one declared end does not replace the actual variable dependency inventory"
    );
    assert!(!stop);
    for ordinal in 1..=3 {
        let reference = RecordedReference::new(
            traffic_protocol_fixture::NAME,
            json!({"channel":connection,"ordinal":ordinal}),
        )
        .unwrap();
        assert!(refs.contains(&reference));
    }
    assert!(refs.contains(&RecordedReference::exchange("http", end)));
    let mut incomplete = rows;
    incomplete[3].as_object_mut().unwrap().remove("ordinal");
    let incomplete = incomplete
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    assert!(
        complete_inventory(&scope, incomplete.as_bytes(), &evidence).is_err(),
        "a missing native effect identity must keep the inventory incomplete"
    );
}
