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

#[test]
fn end_only_source_inventory_requires_every_native_intermediate_effect() {
    let rules = BTreeMap::from([(
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
    let rows = vec![
        json!({"event_type":"memcached_exchange","connection_id":connection,"sequence":1}),
        json!({"event_type":"motan_exchange","connection_id":connection,"sequence":2,"heartbeat":false}),
        json!({"event_type":"motan_exchange","heartbeat":true}),
        json!({"event_type":"kafka_produce","connection_id":connection,"request_sequence":3,"sequence":31}),
        json!({"event_type":"kafka_produce","connection_id":connection,"request_sequence":3,"sequence":32}),
        json!({"event_type":"kafka_fetch","connection_id":connection,"sequence":4}),
        json!({"event_type":"kafka_delivery","connection_id":connection,"fetch_sequence":4,"sequence":41}),
        json!({"event_type":"redis_pub_sub_push","rpc_request":{"connection_id":connection,"sequence":5}}),
        json!({"event_type":"http_exchange","id":end,"outcome":"response","method":"POST","uri":"/done","authority":"executor.test","scheme":"http","response_status":200}),
    ];
    let raw = rows
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    let (refs, stop) = complete_inventory(&scope, raw.as_bytes()).unwrap();
    assert_eq!(
        refs.len(),
        8,
        "one declared end does not replace the actual variable dependency inventory"
    );
    assert!(!stop);
    for reference in [
        RecordedReference::Memcached {
            connection_id: connection,
            sequence: 1,
        },
        RecordedReference::Motan {
            connection_id: connection,
            sequence: 2,
        },
        RecordedReference::KafkaProduce {
            connection_id: connection,
            sequence: 31,
        },
        RecordedReference::KafkaProduce {
            connection_id: connection,
            sequence: 32,
        },
        RecordedReference::KafkaFetch {
            connection_id: connection,
            sequence: 4,
        },
        RecordedReference::KafkaDelivery {
            connection_id: connection,
            sequence: 41,
        },
        RecordedReference::RedisRpcPush {
            connection_id: connection,
            sequence: 5,
        },
        RecordedReference::Http { exchange_id: end },
    ] {
        assert!(refs.contains(&reference));
    }
    let mut incomplete = rows;
    incomplete[3].as_object_mut().unwrap().remove("sequence");
    let incomplete = incomplete
        .iter()
        .map(|row| format!("{row}\n"))
        .collect::<String>();
    assert!(
        complete_inventory(&scope, incomplete.as_bytes()).is_err(),
        "native request sequence cannot stand in for a missing effect identity"
    );
}
